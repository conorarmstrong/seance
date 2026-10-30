//! Download quarantine — `com.apple.LaunchServices.QuarantineEventsV2`.
//!
//! When LaunchServices downloads a file it records where it came from in a
//! per-user SQLite database at
//! `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`. It is
//! the canonical answer to "where did this file come from?": the downloading
//! app, the direct data URL, and the referring page, each timestamped. The
//! generic SQLite dump would surface the rows; this decodes the column meanings
//! and the Cocoa timestamp so they read as provenance.
//!
//! Table `LSQuarantineEvent`:
//!
//! | Column | Meaning |
//! |---|---|
//! | `LSQuarantineEventIdentifier` | event UUID |
//! | `LSQuarantineTimeStamp` | CFAbsoluteTime (REAL) of the download |
//! | `LSQuarantineAgentName` | app that downloaded it (e.g. `Safari`) |
//! | `LSQuarantineAgentBundleIdentifier` | that app's bundle id |
//! | `LSQuarantineDataURLString` | the direct download URL |
//! | `LSQuarantineOriginURLString` | the page that linked to it |
//! | `LSQuarantineSenderName` / `LSQuarantineSenderAddress` | for mail/AirDrop |

use anyhow::{Context, Result};
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{probe_columns, probe_table, Presence, TempDb};
use serde_json::json;
use std::collections::HashSet;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    basename_lower, cfabsolute_to_unix_parts, staged_looks_like_sqlite, to_rfc3339_nanos, unix_ns,
    MAX_DB_BYTES,
};

/// Emits one `Download` record per quarantine event.
pub struct QuarantineParser;

/// Filename match: the DB is `com.apple.LaunchServices.QuarantineEventsV2`, but
/// copies are often renamed, so match the stable `quarantineeventsv2` tail.
fn is_quarantine_db(name: &str) -> bool {
    basename_lower(name).contains("quarantineeventsv2")
}

impl ForensicsModule for QuarantineParser {
    fn id(&self) -> &str {
        "macos.quarantine"
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
        if !is_quarantine_db(name) {
            return Ok(Vec::new());
        }
        let Some(data_source) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let temp = TempDb::spill(data_source.as_ref(), "quarantine", MAX_DB_BYTES)
            .map_err(|e| ModuleError::ParsingError(format!("spill failed: {e}")))?;

        let result = (|| -> Result<Vec<Artifact>> {
            if !staged_looks_like_sqlite(temp.path()) {
                return Ok(Vec::new()); // not a SQLite DB: not ours, stay silent
            }
            let conn = temp.open().context("open quarantine database")?;
            match probe_table(&conn, "LSQuarantineEvent") {
                Presence::Present => {}
                Presence::Absent => return Ok(Vec::new()),
                Presence::Undetermined(why) => {
                    anyhow::bail!("schema catalogue unreadable: {why}")
                }
            }
            parse_events(&conn, artifact.case_id, artifact.id)
        })();

        match result {
            Ok(mut artifacts) => {
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                info!("QuarantineParser: {} events from {name}", artifacts.len());
                Ok(artifacts)
            }
            Err(e) => {
                warn!("QuarantineParser failed on {name}: {e}");
                Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "Download",
                        "subtype": "quarantine",
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

/// Every column this parser knows how to read, in SELECT order.
const COLUMNS: [&str; 8] = [
    "LSQuarantineEventIdentifier",
    "LSQuarantineTimeStamp",
    "LSQuarantineAgentName",
    "LSQuarantineAgentBundleIdentifier",
    "LSQuarantineDataURLString",
    "LSQuarantineOriginURLString",
    "LSQuarantineSenderName",
    "LSQuarantineSenderAddress",
];

/// `name` when the table really has that column, else the literal `NULL` so the
/// row still selects.
///
/// Naming a column the schema does not have fails the whole statement, and this
/// parser answers a failed statement with one ParseFailed record — so a single
/// column of drift, in either direction, would cost every download's
/// provenance. `probe_columns` lower-cases what it returns.
fn column_or_null(cols: &HashSet<String>, name: &'static str) -> &'static str {
    if cols.contains(&name.to_ascii_lowercase()) {
        name
    } else {
        "NULL"
    }
}

fn parse_events(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Result<Vec<Artifact>> {
    // Column set varies by macOS version; select only what this table actually
    // has. An unreadable column list is NOT "the column is absent": that would
    // substitute NULL for the download URL and present the result as complete.
    let cols = probe_columns(conn, "LSQuarantineEvent")
        .map_err(|why| anyhow::anyhow!("LSQuarantineEvent column list unreadable: {why}"))?;
    let selected: Vec<&'static str> = COLUMNS
        .iter()
        .copied()
        .map(|name| column_or_null(&cols, name))
        .collect();
    let absent: Vec<&'static str> = COLUMNS
        .iter()
        .copied()
        .zip(selected.iter())
        .filter(|(_, picked)| **picked == "NULL")
        .map(|(name, _)| name)
        .collect();

    // The timestamp, the downloading app and the URLs are what makes a row
    // provenance. With none of them present this is some other table wearing
    // the name, and a record of nothing but nulls would be worse than saying so.
    if selected[1..6].iter().all(|picked| *picked == "NULL") {
        anyhow::bail!(
            "LSQuarantineEvent has none of the provenance columns this parser reads (missing: {})",
            absent.join(", ")
        );
    }

    // ORDER BY a column that does not exist is the same statement failure the
    // probe exists to avoid, so it goes only when the timestamp is really there.
    let order = if selected[1] == "NULL" {
        String::new()
    } else {
        format!(" ORDER BY {} DESC", selected[1])
    };
    let sql = format!(
        "SELECT {} FROM LSQuarantineEvent{order}",
        selected.join(", ")
    );

    let mut stmt = conn
        .prepare(&sql)
        .context("prepare LSQuarantineEvent query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?, // identifier
                row.get::<_, Option<f64>>(1)?,    // timestamp (CFAbsoluteTime)
                row.get::<_, Option<String>>(2)?, // agent name
                row.get::<_, Option<String>>(3)?, // agent bundle id
                row.get::<_, Option<String>>(4)?, // data URL
                row.get::<_, Option<String>>(5)?, // origin URL
                row.get::<_, Option<String>>(6)?, // sender name
                row.get::<_, Option<String>>(7)?, // sender address
            ))
        })
        .context("query LSQuarantineEvent")?;

    let mut out = Vec::new();
    for row in rows {
        let (id, ts_cf, agent, bundle, data_url, origin_url, sender, sender_addr) =
            row.context("read quarantine row")?;

        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("Download"));
        meta.insert("subtype".into(), json!("quarantine"));
        meta.insert("event_identifier".into(), json!(id));
        meta.insert("agent_name".into(), json!(agent));
        meta.insert("agent_bundle_id".into(), json!(bundle));
        meta.insert("data_url".into(), json!(data_url));
        meta.insert("origin_url".into(), json!(origin_url));
        meta.insert("sender_name".into(), json!(sender));
        meta.insert("sender_address".into(), json!(sender_addr));
        // A null read from a column that is not in the schema means "this macOS
        // never recorded it", which is not the same claim as "recorded empty".
        if !absent.is_empty() {
            meta.insert("schema_absent_columns".into(), json!(absent));
        }

        if let Some((unix, nanos)) = ts_cf.and_then(cfabsolute_to_unix_parts) {
            meta.insert("timestamp".into(), json!(unix));
            if let Some(ns) = unix_ns(unix, nanos) {
                meta.insert("timestamp_ns".into(), json!(ns));
            }
            if let Some(r) = to_rfc3339_nanos(unix, nanos) {
                meta.insert("timestamp_rfc3339".into(), json!(r));
            }
        }

        // A human summary: what was downloaded, by what, from where.
        let what = data_url
            .as_deref()
            .or(origin_url.as_deref())
            .unwrap_or("(unknown source)");
        let by = agent.as_deref().unwrap_or("unknown app");
        meta.insert("name".into(), json!(format!("Downloaded via {by}: {what}")));

        out.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta.into())
                .with_parent(parent_id)
                .with_subtype("quarantine"),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CF_EPOCH_OFFSET;
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    /// Build a real QuarantineEventsV2 SQLite database with known rows, so the
    /// test asserts the parser against the documented schema (ground truth), not
    /// against its own output.
    fn build_quarantine_db(rows: &[(f64, &str, &str, &str)]) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("qtn_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("QuarantineEventsV2");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE LSQuarantineEvent (
                    LSQuarantineEventIdentifier TEXT PRIMARY KEY,
                    LSQuarantineTimeStamp REAL,
                    LSQuarantineAgentName TEXT,
                    LSQuarantineAgentBundleIdentifier TEXT,
                    LSQuarantineDataURLString TEXT,
                    LSQuarantineOriginURLString TEXT,
                    LSQuarantineSenderName TEXT,
                    LSQuarantineSenderAddress TEXT );",
            )
            .unwrap();
            for (i, (ts, agent, data_url, origin_url)) in rows.iter().enumerate() {
                conn.execute(
                    "INSERT INTO LSQuarantineEvent VALUES (?1,?2,?3,?4,?5,?6,NULL,NULL)",
                    rusqlite::params![
                        format!("id-{i}"),
                        ts,
                        agent,
                        "com.apple.Safari",
                        data_url,
                        origin_url
                    ],
                )
                .unwrap();
            }
        }
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    /// A QuarantineEventsV2 whose `LSQuarantineEvent` table has exactly the
    /// columns in `create_columns` — the shape a schema other than the one this
    /// parser was written against presents.
    fn build_quarantine_db_schema(create_columns: &str, insert: &str) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("qtn_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("QuarantineEventsV2");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE LSQuarantineEvent ({create_columns}); {insert}"
            ))
            .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            json!({ "name": name }),
        );
        QuarantineParser.process(&art).unwrap()
    }

    #[test]
    fn parses_quarantine_events_with_provenance_and_time() {
        // CFAbsoluteTime 700000000.0 == 2023-03-08T20:26:40Z (Cocoa epoch + offset).
        let db = build_quarantine_db(&[(
            700_000_000.0,
            "Safari",
            "https://example.com/malware.dmg",
            "https://example.com/downloads",
        )]);
        let out = run(db, "com.apple.LaunchServices.QuarantineEventsV2");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["type"], json!("Download"));
        assert_eq!(m["agent_name"], json!("Safari"));
        assert_eq!(m["data_url"], json!("https://example.com/malware.dmg"));
        assert_eq!(m["origin_url"], json!("https://example.com/downloads"));
        assert_eq!(m["timestamp"], json!(700_000_000 + CF_EPOCH_OFFSET));
        assert_eq!(
            m["timestamp_rfc3339"].as_str().unwrap(),
            "2023-03-08T20:26:40+00:00"
        );
    }

    #[test]
    fn newest_event_is_first() {
        let db = build_quarantine_db(&[
            (100.0, "Chrome", "https://a/old.zip", "https://a"),
            (900.0, "Safari", "https://b/new.zip", "https://b"),
        ]);
        let out = run(db, "QuarantineEventsV2");
        assert_eq!(out[0].metadata["data_url"], json!("https://b/new.zip"));
        assert_eq!(out[1].metadata["data_url"], json!("https://a/old.zip"));
    }

    #[test]
    fn ignores_unrelated_files() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(vec![0u8; 32]))),
            json!({ "name": "History.db" }),
        );
        assert!(QuarantineParser.process(&art).unwrap().is_empty());
    }

    #[test]
    fn a_matching_name_that_is_not_sqlite_stays_silent() {
        let out = run(b"not a database".to_vec(), "QuarantineEventsV2");
        assert!(out.is_empty());
    }

    /// A schema without the sender columns must still yield the download
    /// provenance it does carry. Naming every column in the SELECT made one
    /// column of drift fail the statement, and the whole database then produced
    /// a single ParseFailed record instead of its downloads.
    #[test]
    fn a_schema_without_the_sender_columns_still_yields_download_provenance() {
        let db = build_quarantine_db_schema(
            "LSQuarantineEventIdentifier TEXT PRIMARY KEY, LSQuarantineTimeStamp REAL, \
             LSQuarantineAgentName TEXT, LSQuarantineDataURLString TEXT",
            "INSERT INTO LSQuarantineEvent \
             VALUES ('id-0', 700000000.0, 'Safari', 'https://example.com/x.dmg');",
        );
        let out = run(db, "com.apple.LaunchServices.QuarantineEventsV2");
        assert_eq!(
            out.len(),
            1,
            "the download must survive the missing columns"
        );
        let m = &out[0].metadata;
        assert_ne!(m["status"], json!("ParseFailed"));
        assert_eq!(m["agent_name"], json!("Safari"));
        assert_eq!(m["data_url"], json!("https://example.com/x.dmg"));
        // The sender columns were never in this schema; a bare null would read
        // as "recorded empty", so the record names them as absent.
        assert_eq!(
            m["schema_absent_columns"],
            json!([
                "LSQuarantineAgentBundleIdentifier",
                "LSQuarantineOriginURLString",
                "LSQuarantineSenderName",
                "LSQuarantineSenderAddress"
            ])
        );
    }

    /// A table wearing the name but carrying none of the provenance columns is
    /// not silently emitted as rows of nulls.
    #[test]
    fn a_table_without_any_provenance_column_is_reported_not_emptied() {
        let db = build_quarantine_db_schema(
            "LSQuarantineEventIdentifier TEXT, SomethingElse TEXT",
            "INSERT INTO LSQuarantineEvent VALUES ('id-0', 'x');",
        );
        let out = run(db, "QuarantineEventsV2");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["status"], json!("ParseFailed"));
        assert_eq!(out[0].metadata["content_incomplete"], json!(true));
    }

    /// CFAbsoluteTime is a REAL column: two downloads inside the same second
    /// order arbitrarily once the fraction is cast away.
    #[test]
    fn a_fractional_download_time_keeps_its_sub_second_precision() {
        let db = build_quarantine_db(&[(
            700_000_000.25,
            "Safari",
            "https://example.com/a.dmg",
            "https://example.com",
        )]);
        let out = run(db, "QuarantineEventsV2");
        let m = &out[0].metadata;
        assert_eq!(m["timestamp"], json!(700_000_000 + CF_EPOCH_OFFSET));
        assert_eq!(
            m["timestamp_ns"],
            json!((700_000_000 + CF_EPOCH_OFFSET) * 1_000_000_000 + 250_000_000)
        );
        assert_eq!(
            m["timestamp_rfc3339"].as_str().unwrap(),
            "2023-03-08T20:26:40.250+00:00"
        );
    }
}
