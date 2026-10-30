//! Timeline exports must stream (bounded memory), not build the whole payload
//! in RAM and pretty-print it. We can't assert peak memory in-process, but we
//! assert the two observable consequences of the streaming rewrite: the JSON is
//! emitted compactly (array elements start immediately, no pretty indentation)
//! and the export is complete and correctly ordered.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    orchestrator::{CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const N: i64 = 250;

async fn setup() -> (axum::Router, Uuid) {
    let (app, case_id, _db, _ids) = setup_with_db().await;
    (app, case_id)
}

/// Same fixture, but hands back the DB handle and the event artifact ids so a
/// test can tag events and assert the export honours the tagged-only filter.
async fn setup_with_db() -> (axum::Router, Uuid, Arc<SqliteConnection>, Vec<Uuid>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Stream Case", "examiner").await.unwrap();

    let mut ids = Vec::new();
    for i in 0..N {
        let e = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_700_000_000 + i,
                "timestamp_desc": "File Created",
                "source_module": "plugin.ntfs.mft_parser",
                "short_desc": format!("event {i}"),
                "full_details": format!("{{\"filename\": \"file_{i}.txt\"}}"),
            }),
        );
        ids.push(e.id);
        db.record_artifact(&e).await.unwrap();
    }

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: None,
        ingestion_service: orchestrator.ingestion_service(),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: EvidenceRootPolicy::unrestricted(),
        cancellation: CancellationHandle::new(),
    };
    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: String::new(),
        enabled: false,
    };
    (
        router_with_auth(app_state, Some(auth_config)),
        case_id,
        db,
        ids,
    )
}

async fn get_body(app: &axum::Router, uri: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, bytes.to_vec())
}

/// The `events` array of a streamed timeline JSON document.
fn timeline_events(body: &[u8]) -> Vec<serde_json::Value> {
    let doc: serde_json::Value = serde_json::from_slice(body).expect("valid JSON document");
    doc["events"].as_array().expect("events array").clone()
}

#[tokio::test]
async fn timeline_json_export_streams_compact_and_complete() {
    let (app, case) = setup().await;
    let (status, body) =
        get_body(&app, &format!("/api/v1/cases/{case}/timeline/export/json")).await;
    assert_eq!(status, StatusCode::OK);

    let text = String::from_utf8(body).unwrap();
    // Streamed/compact output: no pretty-printing, the events array opens
    // straight onto the first object.
    assert!(
        text.contains(",\"events\":[{") || text.contains(",\"events\":[]"),
        "export must be compact-streamed"
    );

    let doc: serde_json::Value = serde_json::from_str(&text).expect("valid JSON document");
    assert_eq!(doc["export"], "timeline");
    assert_eq!(doc["population"]["matching_events"], N);
    assert!(doc["timezone"].as_str().unwrap().contains("UTC"));
    assert_eq!(doc["completeness"]["complete"], true);
    assert_eq!(doc["completeness"]["rows"], N);
    let arr = doc["events"].as_array().expect("events array");
    assert_eq!(arr.len() as i64, N, "every event must be exported");
    assert!(
        arr[0]["timestamp_iso8601_utc"]
            .as_str()
            .unwrap()
            .ends_with("+00:00"),
        "the ISO rendering sits beside the raw epoch"
    );
    assert!(arr[0].get("timestamp_subsec_nanos").is_some());

    // Ordered timestamp DESC: first element is the newest.
    assert_eq!(
        arr[0]["timestamp"].as_i64().unwrap(),
        1_700_000_000 + (N - 1)
    );
    assert_eq!(
        arr[(N - 1) as usize]["timestamp"].as_i64().unwrap(),
        1_700_000_000
    );
}

#[tokio::test]
async fn timeline_csv_export_streams_complete() {
    let (app, case) = setup().await;
    let (status, body) = get_body(&app, &format!("/api/v1/cases/{case}/timeline/export/csv")).await;
    assert_eq!(status, StatusCode::OK);

    let text = String::from_utf8(body).unwrap();
    let (preamble, data): (Vec<&str>, Vec<&str>) = text.lines().partition(|l| l.starts_with("# "));
    assert!(
        preamble.iter().any(|l| l.starts_with("# timezone,")),
        "the file states its timezone convention"
    );
    // Preamble lines are padded to the table's column count (CR-033 #7), so
    // the population line is matched by its prefix.
    assert!(
        preamble
            .iter()
            .any(|l| l.starts_with(&format!("# matching_events,{N},"))),
        "the file states its population"
    );
    // Padded to the table's width. Counted on the lines with no quoted value,
    // since a quoted value may itself carry commas.
    let columns = data[0].split(',').count();
    assert!(
        preamble
            .iter()
            .filter(|l| !l.contains('"'))
            .all(|l| l.split(',').count() == columns),
        "every preamble line carries the table's column count: {preamble:?}"
    );
    let header = data[0];
    assert!(header.starts_with("Timestamp,"), "CSV header present");
    assert!(header.contains("Timestamp (ISO-8601 UTC)"), "{header}");
    assert!(header.contains("Source UTC Offset Seconds"), "{header}");
    // Header + N rows + verdict row (test data has no embedded newlines).
    assert_eq!(
        data.len() as i64,
        N + 2,
        "all rows present, plus the verdict"
    );
    assert!(
        data.last().unwrap().contains("### END OF EXPORT ###")
            && data.last().unwrap().contains("COMPLETE"),
        "the last row is the verdict"
    );
}

/// The two streamed exports end with a verdict row that says the walk reached
/// the end, and the CSV's population line agrees with its row count.
#[tokio::test]
async fn the_timeline_exports_state_their_population_and_verdict_in_the_file() {
    let (app, case) = setup().await;
    let (_, body) = get_body(&app, &format!("/api/v1/cases/{case}/timeline/export/csv")).await;
    let text = String::from_utf8(body).unwrap();
    let rows = text
        .lines()
        .filter(|l| {
            !l.starts_with("# ")
                && !l.starts_with("Timestamp,")
                && !l.contains("### END OF EXPORT ###")
        })
        .count() as i64;
    assert_eq!(rows, N);
    assert!(text.contains(&format!("# matching_events,{N},")));
    assert!(
        text.contains(&format!("This file holds all {N} of {N} events")),
        "{text}"
    );

    let (_, body) = get_body(&app, &format!("/api/v1/cases/{case}/timeline/export/json")).await;
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["completeness"]["walk_reached_end"], true);
    assert_eq!(doc["completeness"]["stopped_because"], "exhausted");
}

// ── BUG-231: exports must apply the same filters the list/UI applies ─────────

#[tokio::test]
async fn timeline_export_honours_tagged_only_and_column_filters() {
    let (app, case, db, ids) = setup_with_db().await;

    // Tag exactly two events; "tagged only" must export those two and no more.
    db.create_timeline_tag(case, ids[3], Some("examiner"), Some("note"))
        .await
        .unwrap();
    db.create_timeline_tag(case, ids[7], Some("examiner"), None)
        .await
        .unwrap();

    let (status, body) = get_body(
        &app,
        &format!("/api/v1/cases/{case}/timeline/export/json?tagged_only=true"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = timeline_events(&body);
    assert_eq!(arr.len(), 2, "tagged_only must not export untagged events");

    // The CSV sibling applies the same filter.
    let (status, body) = get_body(
        &app,
        &format!("/api/v1/cases/{case}/timeline/export/csv?tagged_only=true"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).unwrap();
    let data = text.lines().filter(|l| !l.starts_with("# ")).count();
    assert_eq!(data, 4, "header + 2 tagged rows + verdict");

    // Column filters too: filename matches exactly one event (file_11.txt).
    let (status, body) = get_body(
        &app,
        &format!("/api/v1/cases/{case}/timeline/export/json?filter_filename=file_11."),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = timeline_events(&body);
    assert_eq!(arr.len(), 1, "filename filter must scope the export");

    // An event-type filter that matches nothing exports nothing.
    let (status, body) = get_body(
        &app,
        &format!("/api/v1/cases/{case}/timeline/export/json?filter_event_type=Registry"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = timeline_events(&body);
    assert!(arr.is_empty(), "event-type filter must scope the export");
}

// ── The mactime body file: a FILE export beside the event exports ────────────

/// The body file is one row per `FileEntry`, so the fixture's timeline events
/// are not in it; these files are.
async fn setup_with_files() -> (axum::Router, Uuid, Vec<Uuid>) {
    let (app, case, db, _events) = setup_with_db().await;
    let mut ids = Vec::new();
    let files = [
        json!({
            "name": "passwd",
            "path": "/etc/passwd",
            "size": 1234,
            "inode": 17,
            "mode": 0o100644,
            "uid": 0,
            "gid": 0,
            "created": "2024-01-15T12:30:00Z",
            "modified": "2024-01-15T12:30:00Z",
            "accessed": "2024-02-01T00:00:00Z",
            "changed": "2024-01-15T12:31:00Z",
            "is_directory": false,
        }),
        json!({
            "name": "gone.txt",
            "path": "\\Users\\x\\gone.txt",
            "size": 9,
            "record_number": 4096,
            "mft_modified": "2024-01-15T12:30:00Z",
            "created": "2024-01-15T12:30:00Z",
            "deleted": true,
        }),
        // A file with no timestamps at all: still a row, all times 0.
        json!({ "name": "undated", "path": "/undated|pipe" }),
    ];
    for m in files {
        let a = Artifact::new(case, ArtifactType::FileEntry, None, m);
        ids.push(a.id);
        db.record_artifact(&a).await.unwrap();
    }
    (app, case, ids)
}

#[tokio::test]
async fn body_file_export_is_one_row_per_file_entry_with_a_preamble_and_verdict() {
    let (app, case, _ids) = setup_with_files().await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{case}/timeline/export/body"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-disposition"],
        format!("attachment; filename=\"body_{case}.txt\"")
    );
    assert_eq!(resp.headers()["x-export-total"], "3");
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();

    let (comments, rows): (Vec<&str>, Vec<&str>) = text.lines().partition(|l| l.starts_with('#'));
    // The N timeline events are events, not files: none of them is a row.
    assert_eq!(rows.len(), 3, "one row per FileEntry: {rows:?}");
    assert!(
        rows.iter().all(|r| r.matches('|').count() == 10),
        "eleven pipe-delimited fields per row: {rows:?}"
    );
    // The full mapping, including the mode string and the NTFS keys.
    assert!(
        rows.contains(
            &"|/etc/passwd|17|r/rrw-r--r--|0|0|1234|1706745600|1705321800|1705321860|1705321800"
        ),
        "{rows:?}"
    );
    assert!(
        rows.iter().any(|r| r
            .starts_with("|\\Users\\x\\gone.txt (deleted)|4096||0|0|9|0|0|1705321800|1705321800")),
        "{rows:?}"
    );
    // The pipe in the name cannot add a field; times absent are 0, not guessed.
    assert!(
        rows.contains(&"|/undated pipe|0||0|0|0|0|0|0|0"),
        "{rows:?}"
    );

    // Preamble: population, columns, timezone, how to read; verdict last.
    assert!(comments.contains(&"# file_entries: 3"), "{comments:?}");
    assert!(comments
        .iter()
        .any(|l| l.starts_with("# columns: MD5|name|inode|")));
    assert!(comments.iter().any(|l| l.starts_with("# timezone: ")));
    assert!(comments.iter().any(|l| l.starts_with("# how_to_read: ")));
    let last = text.lines().last().unwrap();
    assert!(
        last.starts_with("# ### END OF EXPORT ### VERDICT: COMPLETE"),
        "the last line is the verdict: {last}"
    );
    assert!(last.contains("all 3 of 3"), "{last}");
    // mactime's reader skips '#' lines and nothing else: no row may begin
    // with one, or the reader would drop a file silently.
    assert!(rows.iter().all(|r| !r.starts_with('#')));
}

/// §3.7, through the real production path end to end: a real router, a real
/// (in-memory) database, the real `stream_export_timeline` query, and the
/// returned bytes opened as a real SQLite file — not `insert_timeline_sqlite_row`
/// called directly with a hand-built event.
///
/// A code-review pass on 2026-09-18 caught two defects this route's own unit
/// tests could not: (1) `DEVICE_OFFSET` read `TimelineEventResponse::dynamic_fields`,
/// which `stream_export_timeline` never populates, so every real export shipped
/// it permanently NULL; and (2) the finished file was read into a `Vec<u8>`
/// before responding, undoing the bounded-memory point of building it to a
/// temp file in the first place. This test exercises the real query path for
/// (1) and, for (2), asserts the response is actually a streamed body (no
/// `Content-Length` header — the marker `Body::from_stream` produces and
/// `Body::from(bytes)` does not) rather than re-implementing a memory-usage
/// assertion no in-process test can make honestly.
#[tokio::test]
async fn timeline_sqlite_export_streams_and_carries_a_real_device_offset() {
    let (app, case_id, db, _ids) = setup_with_db().await;

    // One more event, carrying a device-position key in `full_details` the
    // way a real disk-forensics module would -- this is the one path
    // `device_offset_from_full_details` is meant to read.
    let offset_event = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": 1_700_000_500,
            "timestamp_desc": "MFT Entry Modified",
            "source_module": "plugin.ntfs.mft_parser",
            "short_desc": "\\evidence\\offset-carrying-file.txt",
            "full_details": json!({
                "filename": "offset-carrying-file.txt",
                "byte_offset": 786_432i64,
            })
            .to_string(),
        }),
    );
    db.record_artifact(&offset_event).await.unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{case_id}/timeline/export/sqlite"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/vnd.sqlite3"
    );
    // `Body::from_stream` produces a chunked/streamed body with no
    // Content-Length; `Body::from(bytes)` (the defect this test pins) sets
    // one because the whole payload is already in memory as one `Vec<u8>`.
    assert!(
        resp.headers().get("content-length").is_none(),
        "a streamed export must not carry a Content-Length: {:?}",
        resp.headers()
    );
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();

    // Real bytes, opened as a real SQLite file — not trusted as "probably
    // fine because the route returned 200".
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), &body).unwrap();
    let conn = rusqlite::Connection::open(tmp.path()).unwrap();

    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM timeline", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        total,
        N + 1,
        "the offset-carrying event must be exported too"
    );

    let offset: i64 = conn
        .query_row(
            "SELECT \"DEVICE_OFFSET\" FROM timeline WHERE \"ACTION\" = ?1",
            ["MFT Entry Modified"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        offset, 786_432,
        "DEVICE_OFFSET must be read from the real stream_export_timeline path, \
         not left NULL"
    );

    let null_offsets: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM timeline WHERE \"DEVICE_OFFSET\" IS NOT NULL AND \"ACTION\" != ?1",
            ["MFT Entry Modified"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        null_offsets, 0,
        "an event with no offset key must not be given a fabricated one"
    );

    let (rows_written, complete): (i64, i64) = conn
        .query_row("SELECT rows_written, complete FROM export_meta", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(rows_written, N + 1);
    assert_eq!(complete, 1);
}

#[tokio::test]
async fn body_file_export_of_a_case_with_no_files_is_a_whole_empty_file() {
    let (app, case) = setup().await;
    let (status, body) =
        get_body(&app, &format!("/api/v1/cases/{case}/timeline/export/body")).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).unwrap();
    assert!(text.lines().all(|l| l.starts_with('#')), "no rows: {text}");
    assert!(text.contains("# file_entries: 0\n"));
    assert!(text
        .lines()
        .last()
        .unwrap()
        .contains("VERDICT: COMPLETE. This file holds all 0 of 0"));
}

/// §5.12: a body file of timeline events (memory events included), the
/// `timeliner --create-bodyfile` parity the file-list body file does not give.
/// One row per event, the time in the column its kind names, the request's
/// filters honoured, and a verdict line that counts events.
#[tokio::test]
async fn timeline_events_export_as_a_body_file_with_a_verdict() {
    let (app, case) = setup().await;
    let (status, body) = get_body(
        &app,
        &format!("/api/v1/cases/{case}/timeline/export/body_events"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).unwrap();
    let rows: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(rows.len() as i64, N, "one row per event");
    assert!(
        rows[0].contains("[plugin.ntfs.mft_parser] event ") && rows[0].contains("File Created"),
        "{}",
        rows[0]
    );
    assert!(
        rows.iter().all(|r| r.matches('|').count() == 10),
        "eleven fields on every row"
    );
    // 'File Created' is a creation time: crtime is the last field.
    assert!(rows[0].rsplit('|').next().unwrap().parse::<i64>().unwrap() >= 1_700_000_000);
    let last = text.lines().last().unwrap();
    assert!(
        last.starts_with("# ### END OF EXPORT ### VERDICT: COMPLETE")
            && last.contains(&format!("{N} of {N} timeline events")),
        "{last}"
    );

    // A filter that matches nothing is complete and empty, not an error.
    let (status, body) = get_body(
        &app,
        &format!("/api/v1/cases/{case}/timeline/export/body_events?search=zzz-no-such-event"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).unwrap();
    assert!(text.lines().filter(|l| !l.starts_with('#')).count() == 0);
    assert!(text.contains("VERDICT: COMPLETE"), "{text}");
}
