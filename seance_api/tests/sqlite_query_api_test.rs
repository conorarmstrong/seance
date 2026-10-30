//! `POST /api/v1/cases/:id/sqlite/query` (ROADMAP §1.3): one read-only SQL
//! statement over the STAGED COPY of a database artifact.
//!
//! The contract the frontend's `SqliteQueryApi.ts` encodes, driven through
//! the real router: the evidence file is never opened for writing, one
//! statement only, nothing that writes or attaches, a row ceiling that is
//! reported when it bites, a timeout that is reported when it fires, blobs
//! summarised rather than inlined, and the staging's own incompleteness
//! carried onto the answer.

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
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

struct Harness {
    app: axum::Router,
    db: Arc<SqliteConnection>,
    case_id: Uuid,
    _dir: tempfile::TempDir,
    dir: std::path::PathBuf,
}

async fn setup() -> Harness {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("SQL Query Case", "examiner").await.unwrap();

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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    Harness {
        app: router_with_auth(app_state, Some(auth_config)),
        db,
        case_id,
        _dir: dir,
        dir: path,
    }
}

/// A small Chrome-History-shaped database on disk. Rollback-journal mode, so
/// there is no `-wal` to stage and the staging reports it whole.
fn write_history_db(path: &std::path::Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, \
                            favicon BLOB, big INTEGER);
         INSERT INTO urls VALUES (1, 'https://example.test/', 'Example', 3, X'0102030405', 9007199254740993);
         INSERT INTO urls VALUES (2, 'https://other.test/', NULL, 1, NULL, 42);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);",
    )
    .unwrap();
    let mut insert = conn
        .prepare("INSERT INTO visits (url, visit_time) VALUES (?1, ?2)")
        .unwrap();
    for i in 0..1_500i64 {
        insert
            .execute([1 + (i % 2), 13_000_000_000_000_000 + i])
            .unwrap();
    }
    drop(insert);
    conn.close().unwrap();
}

/// Record `path` as a file the directory walker listed, the way a
/// folder-sourced case holds a browser profile.
async fn record_file(h: &Harness, name: &str, path: &std::path::Path) -> Uuid {
    let file = Artifact::new(
        h.case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": name,
            "path": format!("/Users/alice/Library/Application Support/Google/Chrome/Default/{name}"),
            "source_path": path.to_str().unwrap(),
            "size": std::fs::metadata(path).unwrap().len(),
        }),
    );
    h.db.record_artifact(&file).await.unwrap();
    file.id
}

async fn history_artifact(h: &Harness) -> (Uuid, std::path::PathBuf) {
    let path = h.dir.join("History");
    write_history_db(&path);
    let id = record_file(h, "History", &path).await;
    (id, path)
}

async fn query(h: &Harness, body: Value) -> (StatusCode, Value) {
    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/sqlite/query", h.case_id))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "{status}: not JSON ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, value)
}

fn sha256_of(path: &std::path::Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    format!("{:x}", Sha256::digest(bytes))
}

async fn audit_actions(h: &Harness) -> Vec<Value> {
    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/audit_log", h.case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let log: Value = serde_json::from_slice(&bytes).unwrap();
    log["events"].as_array().cloned().unwrap_or_default()
}

#[tokio::test]
async fn a_select_answers_with_the_attested_contract() {
    let h = setup().await;
    let (artifact, _) = history_artifact(&h).await;
    let (status, body) = query(
        &h,
        json!({
            "artifact_id": artifact,
            "sql": "SELECT id, url, title, visit_count FROM urls ORDER BY id",
            "max_rows": 1000
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(
        body["columns"],
        json!(["id", "url", "title", "visit_count"])
    );
    assert_eq!(
        body["rows"],
        json!([
            [1, "https://example.test/", "Example", 3],
            [2, "https://other.test/", null, 1]
        ])
    );
    assert_eq!(body["row_count"], 2);
    assert_eq!(body["row_cap"], 1000);
    assert_eq!(body["capped"], false);
    assert_eq!(body["timeout_ms"], 10_000);
    assert!(body["elapsed_ms"].is_u64(), "{body}");
    // The attestations a screen may print "read-only over the staged copy" from.
    assert_eq!(body["read_only"], true);
    assert_eq!(body["source"], "staged_copy");
    assert_eq!(body["artifact_id"], artifact.to_string());
    assert_eq!(body["database"], "History");
    assert_eq!(body["content_incomplete"], Value::Null);
    assert_eq!(body["wal_incomplete"], Value::Null);
}

#[tokio::test]
async fn the_row_cap_is_reported_and_capped_is_true_only_past_it() {
    let h = setup().await;
    let (artifact, _) = history_artifact(&h).await;

    // 1,500 rows exist; asking for 100 gets 100 and the fact that more exist.
    let (status, body) = query(
        &h,
        json!({ "artifact_id": artifact, "sql": "SELECT id FROM visits", "max_rows": 100 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["row_cap"], 100);
    assert_eq!(body["row_count"], 100);
    assert_eq!(body["rows"].as_array().unwrap().len(), 100);
    assert_eq!(body["capped"], true);

    // Exactly the cap: 1,500 rows under a cap of 1,500 is not capped, because
    // the server looked for a 1,501st and found none.
    let (_, body) = query(
        &h,
        json!({ "artifact_id": artifact, "sql": "SELECT id FROM visits", "max_rows": 1500 }),
    )
    .await;
    assert_eq!(body["row_count"], 1500);
    assert_eq!(body["capped"], false);

    // The server's own ceiling: a client asking for more gets the ceiling, and
    // the answer says which applied.
    let (_, body) = query(
        &h,
        json!({ "artifact_id": artifact, "sql": "SELECT 1", "max_rows": 1_000_000 }),
    )
    .await;
    assert_eq!(body["row_cap"], 10_000);

    // No ceiling asked for: the default applies and is stated.
    let (_, body) = query(&h, json!({ "artifact_id": artifact, "sql": "SELECT 1" })).await;
    assert_eq!(body["row_cap"], 1000);
}

#[tokio::test]
async fn more_than_one_statement_is_refused() {
    let h = setup().await;
    let (artifact, _) = history_artifact(&h).await;
    for sql in [
        "SELECT 1; SELECT 2",
        "SELECT 1; DELETE FROM urls",
        "SELECT 1; -- x\n SELECT 2",
    ] {
        let (status, body) = query(&h, json!({ "artifact_id": artifact, "sql": sql })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{sql}: {body}");
        assert_eq!(
            body["error"]["code"], "sql_not_single_statement",
            "{sql}: {body}"
        );
    }
    // A trailing semicolon alone is one statement.
    let (status, body) = query(&h, json!({ "artifact_id": artifact, "sql": "SELECT 1;" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn anything_that_writes_attaches_or_sets_a_pragma_is_refused() {
    let h = setup().await;
    let (artifact, path) = history_artifact(&h).await;
    let before = sha256_of(&path);
    let other = h.dir.join("other.db");
    for sql in [
        "DELETE FROM urls",
        "INSERT INTO urls (url) VALUES ('x')",
        "UPDATE urls SET title = 'x'",
        "DROP TABLE urls",
        "CREATE TABLE t (x)",
        "PRAGMA journal_mode=DELETE",
        "PRAGMA user_version = 7",
        &format!("ATTACH DATABASE '{}' AS other", other.display()),
        "DETACH DATABASE main",
        "VACUUM",
        "BEGIN",
    ] {
        let (status, body) = query(&h, json!({ "artifact_id": artifact, "sql": sql })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{sql}: {body}");
        assert_eq!(body["error"]["code"], "sql_not_readonly", "{sql}: {body}");
    }
    assert!(!other.exists(), "ATTACH must not create a database file");
    assert_eq!(sha256_of(&path), before, "the evidence file is untouched");
}

#[tokio::test]
async fn only_a_select_or_with_is_run_whatever_sqlite_would_say_about_it() {
    let h = setup().await;
    let (artifact, _) = history_artifact(&h).await;
    // The contract names the refusal by the statement's form, not by whether
    // SQLite got as far as authorising it: a DELETE on a table that does not
    // exist is still not a SELECT, and a PRAGMA read is not one either.
    for sql in [
        "DELETE FROM no_such_table",
        "PRAGMA table_info(urls)",
        "EXPLAIN SELECT 1",
        "VALUES (1, 2)",
    ] {
        let (status, body) = query(&h, json!({ "artifact_id": artifact, "sql": sql })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{sql}: {body}");
        assert_eq!(body["error"]["code"], "sql_not_readonly", "{sql}: {body}");
    }
    // Leading comments and case do not change what the statement is.
    for sql in [
        "-- the visits\nselect count(*) FROM visits",
        "/* block */ WITH v AS (SELECT 1 AS x) SELECT x FROM v",
        "  \n\tSELECT 1",
    ] {
        let (status, body) = query(&h, json!({ "artifact_id": artifact, "sql": sql })).await;
        assert_eq!(status, StatusCode::OK, "{sql}: {body}");
    }
}

#[tokio::test]
async fn a_statement_sqlite_rejects_is_a_400_with_its_message() {
    let h = setup().await;
    let (artifact, _) = history_artifact(&h).await;
    let (status, body) = query(
        &h,
        json!({ "artifact_id": artifact, "sql": "SELECT nope FROM no_such_table" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "sql_error");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no such table"),
        "{body}"
    );

    let (status, body) = query(&h, json!({ "artifact_id": artifact, "sql": "   " })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "sql_error");
}

#[tokio::test]
async fn a_runaway_statement_is_interrupted_and_reported_as_a_timeout() {
    let h = setup().await;
    let (artifact, _) = history_artifact(&h).await;
    let started = std::time::Instant::now();
    let (status, body) = query(
        &h,
        json!({
            "artifact_id": artifact,
            "sql": "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) \
                    SELECT count(*) FROM r",
            "timeout_ms": 300
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "sql_timeout", "{body}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(8),
        "the statement was interrupted, not run to exhaustion"
    );
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("300"),
        "the timeout that applied is named: {message}"
    );
}

#[tokio::test]
async fn blobs_are_summarised_and_big_integers_are_strings() {
    let h = setup().await;
    let (artifact, _) = history_artifact(&h).await;
    let (status, body) = query(
        &h,
        json!({ "artifact_id": artifact, "sql": "SELECT favicon, big, 1.5 AS f FROM urls ORDER BY id" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"][0][0], json!({ "blob": true, "size": 5 }));
    assert_eq!(body["rows"][1][0], Value::Null);
    // 2^53 + 1 cannot survive a JavaScript number; it travels as a string.
    assert_eq!(body["rows"][0][1], "9007199254740993");
    assert_eq!(body["rows"][1][1], 42);
    assert_eq!(body["rows"][0][2], 1.5);
}

#[tokio::test]
async fn an_artifact_that_is_not_a_sqlite_database_is_a_404() {
    let h = setup().await;
    let text = h.dir.join("notes.txt");
    std::fs::write(&text, b"just some text, not a database\n").unwrap();
    let artifact = record_file(&h, "notes.txt", &text).await;
    let (status, body) = query(&h, json!({ "artifact_id": artifact, "sql": "SELECT 1" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "not_a_sqlite_database");

    // An artifact the case does not hold, and one in another case, look the same.
    let (status, body) = query(
        &h,
        json!({ "artifact_id": Uuid::new_v4(), "sql": "SELECT 1" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "not_a_sqlite_database");

    let other_case = h.db.create_case("Other", "examiner").await.unwrap();
    let path = h.dir.join("History");
    write_history_db(&path);
    let foreign = Artifact::new(
        other_case,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "History", "source_path": path.to_str().unwrap() }),
    );
    h.db.record_artifact(&foreign).await.unwrap();
    let (status, body) = query(&h, json!({ "artifact_id": foreign.id, "sql": "SELECT 1" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "not_a_sqlite_database");
}

/// A database whose recorded extent is longer than the bytes the evidence
/// can deliver: the staging is a prefix, and the answer says so rather than
/// presenting a subset of the tables as the whole database.
#[tokio::test]
async fn a_short_staging_is_carried_onto_the_answer() {
    let h = setup().await;
    let path = h.dir.join("History");
    write_history_db(&path);
    let db_len = std::fs::metadata(&path).unwrap().len();
    let declared = db_len + 8192;

    let root = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({ "name": "profile.raw", "source_path": path.to_str().unwrap() }),
    );
    let part = Artifact::new(
        h.case_id,
        ArtifactType::Partition,
        None,
        json!({ "name": "p0", "offset_bytes": 0, "size_bytes": declared }),
    )
    .with_parent(root.id);
    let fs = Artifact::new(
        h.case_id,
        ArtifactType::FileSystem,
        None,
        json!({ "filesystem_type": "NTFS", "subtype": "ntfs", "offset_bytes": 0, "size_bytes": declared }),
    )
    .with_parent(part.id);
    let file = Artifact::new(
        h.case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "History",
            "size": declared,
            "data_runs": [[0, declared]],
            "data_runs_complete": true,
        }),
    )
    .with_parent(fs.id);
    for a in [&root, &part, &fs, &file] {
        h.db.record_artifact(a).await.unwrap();
    }

    let (status, body) = query(
        &h,
        json!({ "artifact_id": file.id, "sql": "SELECT count(*) FROM urls" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"], json!([[2]]));
    assert_eq!(body["content_incomplete"], "short_read", "{body}");
}

#[tokio::test]
async fn the_evidence_file_is_byte_identical_after_a_run_and_the_run_is_audited() {
    let h = setup().await;
    let (artifact, path) = history_artifact(&h).await;
    let before = sha256_of(&path);
    let (status, _) = query(
        &h,
        json!({ "artifact_id": artifact, "sql": "SELECT count(*) FROM visits" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sha256_of(&path), before);
    assert!(
        !path.with_file_name("History-journal").exists()
            && !path.with_file_name("History-wal").exists(),
        "no journal or WAL appears beside the evidence file"
    );

    let events = audit_actions(&h).await;
    let run = events
        .iter()
        .find(|e| e["action"] == "sqlite_query_executed")
        .unwrap_or_else(|| panic!("a query over evidence is accounted for: {events:?}"));
    assert_eq!(run["resource_id"], artifact.to_string());
    let details = run["details"].as_str().unwrap();
    assert!(details.contains("SELECT count(*) FROM visits"), "{details}");
    assert!(details.contains("rows: 1"), "{details}");
    assert!(details.contains("capped: false"), "{details}");
}
