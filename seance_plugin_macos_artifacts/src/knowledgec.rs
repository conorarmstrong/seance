//! knowledgeC — the macOS/iOS activity timeline (`knowledgeC.db`).
//!
//! CoreDuet's `knowledgeC.db` records a stream of activity events in its
//! `ZOBJECT` table: app usage and focus, device lock/unlock, backlight, Now
//! Playing, Safari history, and more. `/app/usage` rows are the headline — which
//! app was foreground, from when to when — but every stream is emitted so the
//! timeline is complete. Timestamps are CFAbsoluteTime; durations are
//! `ZENDDATE - ZSTARTDATE`.
//!
//! Locations: macOS `~/Library/Application Support/Knowledge/knowledgeC.db` and
//! `/private/var/db/CoreDuet/Knowledge/knowledgeC.db`; iOS carries the same file.

use anyhow::{Context, Result};
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{cap_marker, probe_table, CapCounter, Presence, TempDb};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    basename_lower, cfabsolute_to_unix_parts, staged_looks_like_sqlite, to_rfc3339_nanos, unix_ns,
    MAX_DB_BYTES,
};

/// Cap on emitted activity rows. knowledgeC can hold millions; the oldest are
/// dropped first (walk is newest-first) and the truncation is reported.
const ROW_CAP: usize = 500_000;

/// The record type of this reader's own statements about what it could not
/// read — the cap marker and the parse failure. `*ParseStatus` is the name
/// the record census files under "What could not be read"; `Activity`, which
/// they used to carry, filed them with the rows (HUNT-179).
const PARSE_STATUS_TYPE: &str = "KnowledgeCParseStatus";

/// Emits one `Activity` record per `ZOBJECT` row (plus a `KnowledgeCParseStatus`
/// marker if capped).
pub struct KnowledgeCParser;

fn is_knowledgec(name: &str) -> bool {
    basename_lower(name) == "knowledgec.db"
}

impl ForensicsModule for KnowledgeCParser {
    fn id(&self) -> &str {
        "macos.knowledgec"
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
        if !is_knowledgec(name) {
            return Ok(Vec::new());
        }
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let temp = TempDb::spill(ds.as_ref(), "knowledgec", MAX_DB_BYTES)
            .map_err(|e| ModuleError::ParsingError(format!("spill failed: {e}")))?;

        let result = (|| -> Result<Vec<Artifact>> {
            if !staged_looks_like_sqlite(temp.path()) {
                return Ok(Vec::new());
            }
            let conn = temp.open().context("open knowledgeC database")?;
            match probe_table(&conn, "ZOBJECT") {
                Presence::Present => {}
                Presence::Absent => return Ok(Vec::new()),
                Presence::Undetermined(why) => anyhow::bail!("schema unreadable: {why}"),
            }
            parse_objects(&conn, artifact.case_id, artifact.id, ROW_CAP)
        })();

        match result {
            Ok(mut artifacts) => {
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                info!(
                    "KnowledgeCParser: {} activity rows from {name}",
                    artifacts.len()
                );
                Ok(artifacts)
            }
            Err(e) => {
                warn!("KnowledgeCParser failed on {name}: {e}");
                Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": PARSE_STATUS_TYPE,
                        "subtype": "parse_incomplete",
                        "file_name": name,
                        "status": "ParseFailed",
                        "error": e.to_string(),
                        "content_incomplete": true,
                        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                        "content_incomplete_detail": format!(
                            "{name} could not be read ({e}); none of its activity was extracted"
                        ),
                    }),
                )
                .with_parent(artifact.id)])
            }
        }
    }
}

fn parse_objects(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    row_cap: usize,
) -> Result<Vec<Artifact>> {
    let mut cap = CapCounter::new(row_cap);
    let mut stmt = conn
        .prepare(
            "SELECT ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE, ZVALUEINTEGER \
             FROM ZOBJECT ORDER BY ZSTARTDATE DESC LIMIT ?1",
        )
        .context("prepare ZOBJECT query")?;

    let mut rows = stmt.query([cap.limit()]).context("query ZOBJECT")?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().context("read ZOBJECT row")? {
        if !cap.admit() {
            break; // probe row: we are over the cap
        }
        let stream: Option<String> = row.get(0)?;
        let value: Option<String> = row.get(1)?;
        let start_cf: Option<f64> = row.get(2)?;
        let end_cf: Option<f64> = row.get(3)?;
        let value_int: Option<i64> = row.get(4)?;

        let start = start_cf.and_then(cfabsolute_to_unix_parts);
        let end = end_cf.and_then(cfabsolute_to_unix_parts);
        let duration = match (start_cf, end_cf) {
            (Some(s), Some(e)) if e >= s => Some((e - s) as i64),
            _ => None,
        };

        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("Activity"));
        meta.insert("subtype".into(), json!("knowledgec"));
        meta.insert("stream".into(), json!(stream));
        meta.insert("value".into(), json!(value));
        meta.insert("value_integer".into(), json!(value_int));
        meta.insert("start".into(), json!(start.map(|(secs, _)| secs)));
        meta.insert("end".into(), json!(end.map(|(secs, _)| secs)));
        meta.insert("duration_seconds".into(), json!(duration));
        // Sub-second precision alongside the whole seconds: activity bounds are
        // REAL columns, and two events inside the same second order arbitrarily
        // without it.
        if let Some(ns) = start.and_then(|(secs, nanos)| unix_ns(secs, nanos)) {
            meta.insert("start_ns".into(), json!(ns));
        }
        if let Some(ns) = end.and_then(|(secs, nanos)| unix_ns(secs, nanos)) {
            meta.insert("end_ns".into(), json!(ns));
        }
        if let Some(r) = start.and_then(|(secs, nanos)| to_rfc3339_nanos(secs, nanos)) {
            meta.insert("start_rfc3339".into(), json!(r));
        }
        if let Some(r) = end.and_then(|(secs, nanos)| to_rfc3339_nanos(secs, nanos)) {
            meta.insert("end_rfc3339".into(), json!(r));
        }

        let stream_label = stream.as_deref().unwrap_or("(stream?)");
        let v = value.as_deref().unwrap_or("");
        let dur = duration.map(|d| format!(" for {d}s")).unwrap_or_default();
        meta.insert("name".into(), json!(format!("{stream_label}: {v}{dur}")));

        out.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta.into())
                .with_parent(parent_id)
                .with_subtype("knowledgec"),
        );
    }

    if cap.truncated() {
        // A type of its own, not the data records' `Activity`: a capped read
        // filed as one more activity is a shortfall nobody is shown (HUNT-179).
        out.push(cap_marker(
            case_id,
            parent_id,
            PARSE_STATUS_TYPE,
            "ZOBJECT",
            &cap,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CF_EPOCH_OFFSET;
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    fn build_knowledgec(rows: &[(&str, &str, f64, f64)]) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("kc_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("knowledgeC.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT,
                    ZVALUESTRING TEXT, ZSTARTDATE REAL, ZENDDATE REAL, ZVALUEINTEGER INTEGER);",
            )
            .unwrap();
            for (stream, value, start, end) in rows {
                conn.execute(
                    "INSERT INTO ZOBJECT (ZSTREAMNAME,ZVALUESTRING,ZSTARTDATE,ZENDDATE) VALUES (?1,?2,?3,?4)",
                    rusqlite::params![stream, value, start, end],
                )
                .unwrap();
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
            json!({ "name": "knowledgeC.db" }),
        );
        KnowledgeCParser.process(&art).unwrap()
    }

    #[test]
    fn parses_app_usage_with_duration_and_time() {
        // start 700000000 CFAbs -> 2023-03-08T20:26:40Z; 3600s of usage.
        let db = build_knowledgec(&[(
            "/app/usage",
            "com.apple.Safari",
            700_000_000.0,
            700_003_600.0,
        )]);
        let out = run(db);
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["stream"], json!("/app/usage"));
        assert_eq!(m["value"], json!("com.apple.Safari"));
        assert_eq!(m["duration_seconds"], json!(3600));
        assert_eq!(
            m["start_rfc3339"].as_str().unwrap(),
            "2023-03-08T20:26:40+00:00"
        );
    }

    #[test]
    fn newest_activity_first() {
        let db = build_knowledgec(&[
            ("/app/usage", "old.app", 100.0, 200.0),
            ("/app/usage", "new.app", 900.0, 1000.0),
        ]);
        let out = run(db);
        assert_eq!(out[0].metadata["value"], json!("new.app"));
        assert_eq!(out[1].metadata["value"], json!("old.app"));
    }

    /// ZSTARTDATE/ZENDDATE are REAL columns. Casting the fraction away merged
    /// app-focus events that happened a fifth of a second apart.
    #[test]
    fn fractional_activity_bounds_keep_their_sub_second_precision() {
        let db = build_knowledgec(&[(
            "/app/usage",
            "com.apple.Safari",
            700_000_000.25,
            700_000_001.75,
        )]);
        let out = run(db);
        let m = &out[0].metadata;
        assert_eq!(m["start"], json!(700_000_000 + CF_EPOCH_OFFSET));
        assert_eq!(
            m["start_ns"],
            json!((700_000_000 + CF_EPOCH_OFFSET) * 1_000_000_000 + 250_000_000)
        );
        assert_eq!(
            m["end_ns"],
            json!((700_000_001 + CF_EPOCH_OFFSET) * 1_000_000_000 + 750_000_000)
        );
        assert_eq!(
            m["start_rfc3339"].as_str().unwrap(),
            "2023-03-08T20:26:40.250+00:00"
        );
    }

    #[test]
    fn ignores_non_knowledgec() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(vec![0u8; 16]))),
            json!({ "name": "TCC.db" }),
        );
        assert!(KnowledgeCParser.process(&art).unwrap().is_empty());
    }

    /// HUNT-179. The cap marker reused the data records' type `Activity`, so a
    /// capped read was filed with the activity it failed to finish.
    #[test]
    fn the_cap_marker_is_typed_as_a_parse_status_not_as_activity() {
        let db = build_knowledgec(&[
            ("/app/usage", "a.app", 100.0, 200.0),
            ("/app/usage", "b.app", 300.0, 400.0),
            ("/app/usage", "c.app", 500.0, 600.0),
        ]);
        let dir = std::env::temp_dir().join(format!("kccap_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("knowledgeC.db");
        std::fs::write(&path, db).unwrap();
        let conn = Connection::open(&path).unwrap();
        let out = parse_objects(&conn, Uuid::new_v4(), Uuid::new_v4(), 1).unwrap();
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
        let marker = out
            .iter()
            .find(|a| a.metadata["status"] == "CapReached")
            .expect("a cap of one over three rows leaves a marker");
        assert_ne!(
            marker.metadata["type"],
            json!("Activity"),
            "the cap marker was filed as an activity"
        );
        assert_eq!(marker.metadata["type"], json!("KnowledgeCParseStatus"));
        assert_eq!(marker.metadata["subtype"], json!("parse_incomplete"));
    }

    /// The same defect on the failure path: a `knowledgeC.db` whose `ZOBJECT`
    /// cannot be queried was filed as one more `Activity`.
    #[test]
    fn a_failed_read_is_typed_as_a_parse_status_not_as_activity() {
        let dir = std::env::temp_dir().join(format!("kcbad_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("knowledgeC.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY);")
                .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let out = run(bytes);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].metadata["status"], json!("ParseFailed"));
        assert_eq!(out[0].metadata["type"], json!("KnowledgeCParseStatus"));
    }
}
