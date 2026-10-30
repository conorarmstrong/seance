//! TCC — Transparency, Consent & Control (`TCC.db`).
//!
//! TCC records which app was granted or denied access to a protected resource
//! (camera, microphone, screen recording, full-disk access, automation, …) and
//! why. It lives at `/Library/Application Support/com.apple.TCC/TCC.db` (system)
//! and `~/Library/Application Support/com.apple.TCC/TCC.db` (per-user). This
//! answers "what was this app allowed to touch, and did the user consent?".
//!
//! The `access` table schema changed at Big Sur (11): the legacy `allowed`
//! (0/1) + `prompt_count` columns were replaced by `auth_value`, `auth_reason`
//! and `auth_version`. Both are handled; the raw integers are always preserved
//! alongside the decoded label, because published decodings vary slightly and a
//! forensic record must not hide the value it interpreted.

use anyhow::{Context, Result};
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{probe_table, Presence, TempDb};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{basename_lower, staged_looks_like_sqlite, to_rfc3339, MAX_DB_BYTES};

/// Emits one `Permission` record per TCC access-table row.
pub struct TccParser;

fn is_tcc_db(name: &str) -> bool {
    basename_lower(name) == "tcc.db"
}

/// `auth_value` (Big Sur+): whether access is granted. Raw value is always kept.
fn auth_value_label(v: i64) -> &'static str {
    match v {
        0 => "denied",
        1 => "unknown",
        2 => "allowed",
        3 => "limited",
        _ => "other",
    }
}

/// `auth_reason` (Big Sur+): why the grant exists.
fn auth_reason_label(v: i64) -> &'static str {
    match v {
        1 => "error",
        2 => "user_consent",
        3 => "user_set",
        4 => "system_set",
        5 => "service_policy",
        6 => "mdm_policy",
        7 => "override_policy",
        8 => "missing_usage_string",
        9 => "prompt_timeout",
        10 => "preflight_unknown",
        11 => "entitled",
        12 => "app_type_policy",
        _ => "unspecified",
    }
}

/// `client_type`: how the `client` column identifies the app.
fn client_type_label(v: i64) -> &'static str {
    match v {
        0 => "bundle_id",
        1 => "absolute_path",
        _ => "other",
    }
}

impl ForensicsModule for TccParser {
    fn id(&self) -> &str {
        "macos.tcc"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !is_tcc_db(name) {
            return Ok(Vec::new());
        }
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let temp = TempDb::spill(ds.as_ref(), "tcc", MAX_DB_BYTES)
            .map_err(|e| ModuleError::ParsingError(format!("spill failed: {e}")))?;

        let result = (|| -> Result<Vec<Artifact>> {
            if !staged_looks_like_sqlite(temp.path()) {
                return Ok(Vec::new());
            }
            let conn = temp.open().context("open TCC database")?;
            match probe_table(&conn, "access") {
                Presence::Present => {}
                Presence::Absent => return Ok(Vec::new()),
                Presence::Undetermined(why) => anyhow::bail!("schema unreadable: {why}"),
            }
            parse_access(&conn, artifact.case_id, artifact.id)
        })();

        match result {
            Ok(mut artifacts) => {
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                info!("TccParser: {} grants from {name}", artifacts.len());
                Ok(artifacts)
            }
            Err(e) => {
                warn!("TccParser failed on {name}: {e}");
                Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "Permission",
                        "subtype": "tcc",
                        "file_name": name,
                        "status": "ParseFailed",
                        "error": e.to_string(),
                        "content_incomplete": true,
                        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    }),
                )
                .with_parent(artifact.id)])
            }
        }
    }
}

/// Which columns the `access` table has (varies by macOS version).
fn columns(conn: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn.prepare("PRAGMA table_info(access)")?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<std::collections::HashSet<String>>>()?;
    Ok(cols)
}

fn parse_access(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Result<Vec<Artifact>> {
    let cols = columns(conn)?;
    let modern = cols.contains("auth_value");
    let has_last_modified = cols.contains("last_modified");

    // Build a SELECT that works on both schemas; missing columns are read as NULL.
    let grant_col = if modern { "auth_value" } else { "allowed" };
    let reason_col = if modern { "auth_reason" } else { "NULL" };
    let lm_col = if has_last_modified {
        "last_modified"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT service, client, client_type, {grant_col}, {reason_col}, {lm_col} FROM access"
    );

    let mut stmt = conn.prepare(&sql).context("prepare access query")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?, // service
                row.get::<_, Option<String>>(1)?, // client
                row.get::<_, Option<i64>>(2)?,    // client_type
                row.get::<_, Option<i64>>(3)?,    // auth_value / allowed
                row.get::<_, Option<i64>>(4)?,    // auth_reason (or NULL)
                row.get::<_, Option<i64>>(5)?,    // last_modified (or NULL)
            ))
        })
        .context("query access")?;

    let mut out = Vec::new();
    for row in rows {
        let (service, client, client_type, grant, reason, last_modified) =
            row.context("read access row")?;

        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("Permission"));
        meta.insert("subtype".into(), json!("tcc"));
        meta.insert("service".into(), json!(service));
        meta.insert("client".into(), json!(client));
        meta.insert("client_type".into(), json!(client_type));
        if let Some(ct) = client_type {
            meta.insert("client_type_label".into(), json!(client_type_label(ct)));
        }
        meta.insert(
            "schema".into(),
            json!(if modern { "auth_value" } else { "allowed" }),
        );

        // Grant: raw value always kept; label depends on the schema.
        meta.insert("auth_value".into(), json!(grant));
        let granted = match grant {
            Some(g) => {
                let label = if modern {
                    auth_value_label(g)
                } else if g == 1 {
                    "allowed"
                } else {
                    "denied"
                };
                meta.insert("auth_value_label".into(), json!(label));
                label == "allowed" || label == "limited"
            }
            None => false,
        };
        meta.insert("granted".into(), json!(granted));

        if let Some(r) = reason {
            meta.insert("auth_reason".into(), json!(r));
            meta.insert("auth_reason_label".into(), json!(auth_reason_label(r)));
        }
        if let Some(lm) = last_modified {
            meta.insert("timestamp".into(), json!(lm));
            if let Some(rfc) = to_rfc3339(lm) {
                meta.insert("timestamp_rfc3339".into(), json!(rfc));
            }
        }

        let svc = service.as_deref().unwrap_or("(unknown service)");
        let who = client.as_deref().unwrap_or("(unknown client)");
        let verb = if granted { "granted" } else { "denied" };
        meta.insert("name".into(), json!(format!("{who} {verb} {svc}")));

        out.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta.into())
                .with_parent(parent_id)
                .with_subtype("tcc"),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    fn build_tcc(modern: bool, rows: &[(&str, &str, i64, i64, i64, i64)]) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("tcc_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("TCC.db");
        {
            let conn = Connection::open(&path).unwrap();
            if modern {
                conn.execute_batch(
                    "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER,
                        auth_value INTEGER, auth_reason INTEGER, auth_version INTEGER,
                        last_modified INTEGER);",
                )
                .unwrap();
                for (service, client, ctype, auth_value, auth_reason, lm) in rows {
                    conn.execute(
                        "INSERT INTO access (service,client,client_type,auth_value,auth_reason,auth_version,last_modified)
                         VALUES (?1,?2,?3,?4,?5,1,?6)",
                        rusqlite::params![service, client, ctype, auth_value, auth_reason, lm],
                    )
                    .unwrap();
                }
            } else {
                conn.execute_batch(
                    "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER,
                        allowed INTEGER, prompt_count INTEGER, last_modified INTEGER);",
                )
                .unwrap();
                for (service, client, ctype, allowed, _reason, lm) in rows {
                    conn.execute(
                        "INSERT INTO access (service,client,client_type,allowed,prompt_count,last_modified)
                         VALUES (?1,?2,?3,?4,1,?5)",
                        rusqlite::params![service, client, ctype, allowed, lm],
                    )
                    .unwrap();
                }
            }
        }
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    fn run(bytes: Vec<u8>) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            json!({ "name": "TCC.db" }),
        );
        TccParser.process(&art).unwrap()
    }

    #[test]
    fn decodes_modern_schema_grants() {
        let db = build_tcc(
            true,
            &[
                ("kTCCServiceCamera", "com.zoom.xos", 0, 2, 2, 1_600_000_000),
                (
                    "kTCCServiceMicrophone",
                    "/usr/bin/evil",
                    1,
                    0,
                    4,
                    1_600_000_001,
                ),
            ],
        );
        let out = run(db);
        assert_eq!(out.len(), 2);
        let cam = out
            .iter()
            .find(|a| a.metadata["service"] == json!("kTCCServiceCamera"))
            .unwrap();
        assert_eq!(cam.metadata["auth_value"], json!(2));
        assert_eq!(cam.metadata["auth_value_label"], json!("allowed"));
        assert_eq!(cam.metadata["granted"], json!(true));
        assert_eq!(cam.metadata["auth_reason_label"], json!("user_consent"));
        assert_eq!(cam.metadata["client_type_label"], json!("bundle_id"));
        assert_eq!(cam.metadata["timestamp"], json!(1_600_000_000));

        let mic = out
            .iter()
            .find(|a| a.metadata["service"] == json!("kTCCServiceMicrophone"))
            .unwrap();
        assert_eq!(mic.metadata["auth_value_label"], json!("denied"));
        assert_eq!(mic.metadata["granted"], json!(false));
        assert_eq!(mic.metadata["client_type_label"], json!("absolute_path"));
        assert_eq!(mic.metadata["auth_reason_label"], json!("system_set"));
    }

    #[test]
    fn decodes_legacy_allowed_schema() {
        let db = build_tcc(
            false,
            &[(
                "kTCCServiceAccessibility",
                "com.foo.bar",
                0,
                1,
                0,
                1_500_000_000,
            )],
        );
        let out = run(db);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["schema"], json!("allowed"));
        assert_eq!(out[0].metadata["auth_value_label"], json!("allowed"));
        assert_eq!(out[0].metadata["granted"], json!(true));
    }

    #[test]
    fn ignores_non_tcc_names() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(vec![0u8; 16]))),
            json!({ "name": "chat.db" }),
        );
        assert!(TccParser.process(&art).unwrap().is_empty());
    }
}
