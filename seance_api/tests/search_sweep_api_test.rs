//! `POST /api/v1/cases/:id/search/sweep` (ROADMAP §1.2): the case-wide byte
//! sweep, driven through the real router.
//!
//! What the route is held to: every object of the case that carries bytes is
//! offered to `seance_search::sweep` with its region named by TYPE (live,
//! recovered, unallocated, raw), so a hit in a carved or deleted file is never
//! read as a hit in a live one; an object whose bytes cannot be resolved is a
//! listed read failure, never a silent "no hits"; slack is not claimed (the
//! response shows `slack: 0` offered); raw images are offered only when the
//! scope names `raw`; the bounds that applied are echoed as numbers; a hit cap
//! yields a cursor that resumes without re-reporting; a bad pattern is a 400
//! naming the fault; a directory root carries no bytes whatever its type;
//! and every call that reaches the handler is audited, the refused ones
//! included.

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
    let case_id = db.create_case("Sweep Case", "examiner").await.unwrap();

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

/// A file the directory walker listed, with `extra` metadata merged in.
async fn record_file(h: &Harness, name: &str, bytes: &[u8], extra: Value) -> Uuid {
    let path = h.dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    let mut md = json!({
        "name": name,
        "path": format!("/evidence/{name}"),
        "source_path": path.to_str().unwrap(),
        "size": bytes.len(),
    });
    if let Some(obj) = extra.as_object() {
        for (k, v) in obj {
            md[k] = v.clone();
        }
    }
    let file = Artifact::new(h.case_id, ArtifactType::FileEntry, None, md);
    h.db.record_artifact(&file).await.unwrap();
    file.id
}

/// A raw image on disk, and an unallocated window `[offset, offset+len)` of
/// it. Returns `(raw id, unallocated id)`.
async fn record_image_with_unallocated(
    h: &Harness,
    name: &str,
    bytes: &[u8],
    offset: u64,
    len: u64,
) -> (Uuid, Uuid) {
    let path = h.dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    let raw = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": name,
            "source_path": path.to_str().unwrap(),
            "size": bytes.len(),
        }),
    );
    h.db.record_artifact(&raw).await.unwrap();
    let unalloc = Artifact::new(
        h.case_id,
        ArtifactType::UnallocatedSpace,
        None,
        json!({
            "name": "Unallocated 1",
            "offset_bytes": offset,
            "size_bytes": len,
        }),
    )
    .with_parent(raw.id);
    h.db.record_artifact(&unalloc).await.unwrap();
    (raw.id, unalloc.id)
}

async fn sweep(h: &Harness, body: Value) -> (StatusCode, Value) {
    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/search/sweep", h.case_id))
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

fn hits_for(body: &Value, artifact: Uuid) -> Vec<&Value> {
    body["hits"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["artifact_id"] == json!(artifact))
        .collect()
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

#[tokio::test]
async fn every_object_with_bytes_is_offered_under_its_region_and_hits_say_which() {
    let h = setup().await;
    // Live: the pattern once in UTF-8.
    let live = record_file(&h, "notes.txt", b"the needle is here", json!({})).await;
    // Recovered: a carved file (carving_source set) holding the UTF-16LE form.
    let mut carved = b"xx".to_vec();
    carved.extend(utf16le("needle"));
    carved.extend(b"yy");
    let recovered = record_file(
        &h,
        "carved_0000beef.bin",
        &carved,
        json!({ "carved": true, "carving_source": "slack" }),
    )
    .await;
    // Recovered: a deleted file the filesystem parser reconstructed.
    let deleted = record_file(&h, "gone.txt", b"needle", json!({ "deleted": true })).await;
    // Unallocated: a window of a raw image, the pattern inside the window
    // and once again outside it (which a live-only or unallocated-only
    // sweep must NOT find, because it is the raw image's, not the window's).
    let mut image = vec![0u8; 4096];
    image[100..106].copy_from_slice(b"needle");
    image[3000..3006].copy_from_slice(b"needle");
    let (raw, unalloc) = record_image_with_unallocated(&h, "disk.raw", &image, 0, 1024).await;
    // No bytes of their own: never offered.
    let record = Artifact::new(
        h.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({ "name": "needle record", "text": "needle" }),
    )
    .with_parent(live);
    h.db.record_artifact(&record).await.unwrap();

    let (status, body) = sweep(
        &h,
        json!({ "patterns": [{ "kind": "text", "value": "needle" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Regions by TYPE on every hit.
    let live_hits = hits_for(&body, live);
    assert_eq!(live_hits.len(), 1, "{body}");
    assert_eq!(live_hits[0]["region"], "live");
    assert_eq!(live_hits[0]["offset"], 4);
    assert_eq!(live_hits[0]["path"], "/evidence/notes.txt");
    let recovered_hits = hits_for(&body, recovered);
    assert_eq!(recovered_hits.len(), 1, "{body}");
    assert_eq!(recovered_hits[0]["region"], "recovered");
    assert!(
        recovered_hits[0]["encodings"]
            .as_array()
            .unwrap()
            .contains(&json!("utf-16le")),
        "{body}"
    );
    let deleted_hits = hits_for(&body, deleted);
    assert_eq!(deleted_hits.len(), 1, "{body}");
    assert_eq!(deleted_hits[0]["region"], "recovered");
    let unalloc_hits = hits_for(&body, unalloc);
    assert_eq!(unalloc_hits.len(), 1, "{body}");
    assert_eq!(unalloc_hits[0]["region"], "unallocated");
    assert_eq!(unalloc_hits[0]["offset"], 100);
    // The whole image was offered as raw (the default scope admits raw), and
    // both occurrences are found there, attributed by offset only.
    let raw_hits = hits_for(&body, raw);
    assert_eq!(raw_hits.len(), 2, "{body}");
    assert!(raw_hits.iter().all(|h| h["region"] == "raw"));
    // The parsed record's text is not evidence bytes.
    assert!(hits_for(&body, record.id).is_empty(), "{body}");

    // What was on offer, per region, and what was not: slack is not claimed.
    let offered = &body["objects_offered_by_region"];
    assert_eq!(offered["live"], 1, "{body}");
    assert_eq!(offered["recovered"], 2, "{body}");
    assert_eq!(offered["unallocated"], 1, "{body}");
    assert_eq!(offered["raw"], 1, "{body}");
    assert_eq!(offered["slack"], 0, "{body}");
    assert_eq!(body["objects_offered"], 5, "{body}");
    assert_eq!(body["objects_searched"], 5, "{body}");
    assert_eq!(body["complete"], true, "{body}");
    assert_eq!(body["next_cursor"], Value::Null, "{body}");
    assert_eq!(body["read_failures"], json!([]), "{body}");
    let scope_statement = body["scope_statement"].as_str().unwrap();
    assert!(scope_statement.contains("slack: 0"), "{scope_statement}");
    assert!(
        body["slack_statement"]
            .as_str()
            .unwrap()
            .contains("no slack"),
        "{body}"
    );
    // The hits are grouped as well as listed, and both counts are there.
    assert_eq!(
        body["grouping"]["hit_count"],
        body["hits"].as_array().unwrap().len()
    );
    assert!(body["grouping"]["group_count"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn a_raw_image_is_offered_only_when_the_scope_names_raw() {
    let h = setup().await;
    let mut image = vec![0u8; 2048];
    image[10..16].copy_from_slice(b"needle");
    let (raw, unalloc) = record_image_with_unallocated(&h, "disk.raw", &image, 1024, 1024).await;

    let (status, body) = sweep(
        &h,
        json!({
            "patterns": [{ "kind": "text", "value": "needle" }],
            "scope": { "regions": ["live", "unallocated"] }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(hits_for(&body, raw).is_empty(), "{body}");
    assert!(
        hits_for(&body, unalloc).is_empty(),
        "the pattern is outside the window: {body}"
    );
    // The image was not offered at all, and the answer says raw was not
    // searched, so "no hits" cannot be read as "not in the image".
    assert_eq!(body["objects_offered_by_region"]["raw"], 0, "{body}");
    assert_eq!(
        body["objects_offered_by_region"]["unallocated"], 1,
        "{body}"
    );
    assert!(
        body["regions_not_searched"]
            .as_array()
            .unwrap()
            .contains(&json!("raw")),
        "{body}"
    );
    assert!(
        body["scope_statement"]
            .as_str()
            .unwrap()
            .contains("NOT searched: slack, recovered, raw"),
        "{body}"
    );
}

#[tokio::test]
async fn an_object_whose_bytes_cannot_be_resolved_is_a_listed_read_failure() {
    let h = setup().await;
    let found = record_file(&h, "a.txt", b"needle", json!({})).await;
    // A file entry with a size but no location the resolver can read.
    let orphan = Artifact::new(
        h.case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "orphan.bin", "path": "/evidence/orphan.bin", "size": 512 }),
    );
    h.db.record_artifact(&orphan).await.unwrap();

    let (status, body) = sweep(
        &h,
        json!({ "patterns": [{ "kind": "bytes", "value": "6e 65 65 64 6c 65" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(hits_for(&body, found).len(), 1, "{body}");
    let failures = body["read_failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1, "{body}");
    assert_eq!(failures[0]["artifact_id"], json!(orphan.id));
    assert!(
        failures[0]["error"]
            .as_str()
            .unwrap()
            .contains("no source_path"),
        "{body}"
    );
    assert_eq!(
        body["complete"], false,
        "a failed object is not a complete sweep: {body}"
    );
    assert_eq!(body["objects_offered"], 2, "{body}");
}

#[tokio::test]
async fn a_bad_pattern_set_is_a_400_naming_the_fault() {
    let h = setup().await;
    record_file(&h, "a.txt", b"needle", json!({})).await;

    let (status, body) = sweep(&h, json!({ "patterns": [] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "INVALID_REQUEST");

    let (status, body) = sweep(
        &h,
        json!({ "patterns": [{ "kind": "bytes", "value": "zz" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]["message"].as_str().unwrap().contains("zz"),
        "the refusal names the bad hex: {body}"
    );

    // An unknown code page is not a 400: it is reported as absent, never
    // approximated, and the sweep runs without it.
    let (status, body) = sweep(
        &h,
        json!({
            "patterns": [{ "kind": "text", "value": "needle" }],
            "codepages": ["windows-1252", "no-such-codepage"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["codepages_absent"],
        json!(["no-such-codepage"]),
        "{body}"
    );
    assert_eq!(
        body["codepages_resolved"][0]["name"], "windows-1252",
        "{body}"
    );
}

#[tokio::test]
async fn bounds_are_clamped_and_echoed_and_a_hit_cap_resumes_without_repeating() {
    let h = setup().await;
    // Three files, four hits each, ids in a known order.
    let mut ids = Vec::new();
    for name in ["a.txt", "b.txt", "c.txt"] {
        ids.push(record_file(&h, name, b"needle needle needle needle", json!({})).await);
    }

    let (status, body) = sweep(
        &h,
        json!({
            "patterns": [{ "kind": "text", "value": "needle" }],
            "bounds": { "max_hits": 5, "max_bytes": 1u64 << 40 }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["max_hits"], 5, "{body}");
    assert_eq!(body["hit_cap_reached"], true, "{body}");
    assert_eq!(body["complete"], false, "{body}");
    // max_bytes is clamped to the route's per-request ceiling and the
    // clamped number is the one echoed.
    let max_bytes = body["max_bytes"].as_u64().unwrap();
    assert!(max_bytes < (1u64 << 40), "{body}");
    assert_eq!(body["max_bytes_ceiling"], max_bytes, "{body}");
    let first: Vec<(Value, u64)> = body["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hit| (hit["artifact_id"].clone(), hit["offset"].as_u64().unwrap()))
        .collect();
    assert!(first.len() >= 5, "{body}");
    let cursor = body["next_cursor"].clone();
    assert!(cursor.is_object(), "{body}");

    // Resume from the cursor: the rest, and nothing already reported.
    let (status, second) = sweep(
        &h,
        json!({
            "patterns": [{ "kind": "text", "value": "needle" }],
            "bounds": { "max_hits": 100 },
            "resume": cursor
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["complete"], true, "{second}");
    let rest: Vec<(Value, u64)> = second["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hit| (hit["artifact_id"].clone(), hit["offset"].as_u64().unwrap()))
        .collect();
    for hit in &rest {
        assert!(!first.contains(hit), "re-reported: {hit:?}");
    }
    assert_eq!(first.len() + rest.len(), 12, "{body}\n{second}");
    // The resumed call pages from the cursor's object, so nothing before it
    // was pulled from the store.
    let skipped = second["objects_skipped_by_cursor"].as_u64().unwrap();
    let offered = second["objects_offered"].as_u64().unwrap();
    assert!(offered <= 3 && skipped <= 1, "{second}");

    // A cursor naming an object the case does not hold is refused, not
    // silently restarted.
    let (status, body) = sweep(
        &h,
        json!({
            "patterns": [{ "kind": "text", "value": "needle" }],
            "resume": { "artifact_id": Uuid::new_v4(), "offset": 0 }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("resume cursor"),
        "{body}"
    );

    // max_hits above the route's ceiling is clamped and the clamp echoed.
    let (status, body) = sweep(
        &h,
        json!({
            "patterns": [{ "kind": "text", "value": "needle" }],
            "bounds": { "max_hits": 1_000_000 }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["max_hits"], 10_000, "{body}");
}

#[tokio::test]
async fn every_sweep_is_audited_with_its_patterns_and_outcome() {
    let h = setup().await;
    record_file(&h, "a.txt", b"needle", json!({})).await;
    let (status, _) = sweep(
        &h,
        json!({ "patterns": [{ "kind": "text", "value": "needle" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let events = audit_actions(&h).await;
    let sweeps: Vec<&Value> = events
        .iter()
        .filter(|e| e["action"] == "search_sweep_executed")
        .collect();
    assert_eq!(sweeps.len(), 1, "{events:?}");
    let details = sweeps[0]["details"].as_str().unwrap();
    assert!(details.contains("hits: 1"), "{details}");
    assert!(details.contains("complete: true"), "{details}");
    assert!(details.contains("text:needle"), "{details}");
}

#[tokio::test]
async fn a_directory_root_carries_no_bytes_whatever_its_type() {
    // A directory ingest (API and CLI alike) records its root as RawEvidence
    // with `is_directory` and no `source_path`. It carries no bytes of its
    // own, so it is counted in `objects_without_bytes`, never offered — not
    // classified `raw`, resolved, failed and listed under `read_failures`,
    // which would make every default-scope sweep of such a case incomplete.
    let h = setup().await;
    let root = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "seized-folder",
            "path": h.dir.to_str().unwrap(),
            "is_directory": true,
        }),
    );
    h.db.record_artifact(&root).await.unwrap();
    let file = record_file(&h, "a.txt", b"needle", json!({})).await;

    for scope in [
        json!({}),
        json!({ "regions": ["live", "recovered", "unallocated", "raw"] }),
    ] {
        let (status, body) = sweep(
            &h,
            json!({
                "patterns": [{ "kind": "text", "value": "needle" }],
                "scope": scope
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["complete"], true, "{body}");
        assert_eq!(body["read_failures"], json!([]), "{body}");
        assert_eq!(body["objects_without_bytes"], 1, "{body}");
        assert_eq!(body["raw_objects_not_offered"], 0, "{body}");
        assert_eq!(body["objects_offered"], 1, "{body}");
        assert_eq!(hits_for(&body, file).len(), 1, "{body}");
        assert!(hits_for(&body, root.id).is_empty(), "{body}");
    }
}

#[tokio::test]
async fn a_refused_call_is_audited_whatever_refused_it() {
    // Every call leaves a `search_sweep_executed` record: one refused for a
    // pattern set that does not compile, one refused for a scope that does
    // not compile, and one refused for a resume cursor the case does not
    // hold, each with `outcome: refused` or `failed` naming the fault.
    let h = setup().await;
    record_file(&h, "a.txt", b"needle", json!({})).await;

    let (status, body) = sweep(
        &h,
        json!({ "patterns": [{ "kind": "bytes", "value": "zz" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = sweep(
        &h,
        json!({
            "patterns": [{ "kind": "text", "value": "needle" }],
            "scope": { "path_glob": "[" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("path_glob"),
        "{body}"
    );

    let (status, body) = sweep(
        &h,
        json!({
            "patterns": [{ "kind": "text", "value": "needle" }],
            "scope": { "regions": [] }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = sweep(
        &h,
        json!({
            "patterns": [{ "kind": "text", "value": "needle" }],
            "resume": { "artifact_id": Uuid::new_v4(), "offset": 0 }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let events = audit_actions(&h).await;
    let details: Vec<&str> = events
        .iter()
        .filter(|e| e["action"] == "search_sweep_executed")
        .map(|e| e["details"].as_str().unwrap())
        .collect();
    assert_eq!(details.len(), 4, "{events:?}");
    let refused_for = |what: &str| {
        details
            .iter()
            .any(|d| d.starts_with("outcome: refused (") && d.contains(what))
    };
    assert!(refused_for("patterns:"), "{details:?}");
    assert!(
        refused_for("scope: path_glob does not parse"),
        "{details:?}"
    );
    assert!(
        refused_for("scope: scope admits no region kind"),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|d| d.starts_with("outcome: failed (") && d.contains("resume cursor")),
        "{details:?}"
    );
    assert!(
        details.iter().all(|d| d.contains("patterns: [")),
        "every record names its patterns: {details:?}"
    );
}

/// HUNT-124: a file-slack region the NTFS/FAT/exFAT parsers publish is offered
/// to the sweep as `slack`, a hit in it says so, and the slack statement says
/// what "slack" covers rather than that none was offered.
#[tokio::test]
async fn a_file_slack_region_is_offered_as_slack_and_the_statement_says_what_slack_covers() {
    let h = setup().await;
    let mut image = vec![0u8; 4096];
    // The pattern inside the slack window [1000, 1024) and once outside it.
    image[1010..1016].copy_from_slice(b"needle");
    image[3000..3006].copy_from_slice(b"needle");
    let path = h.dir.join("vol.raw");
    std::fs::write(&path, &image).unwrap();
    let raw = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({ "name": "vol.raw", "source_path": path.to_str().unwrap(), "size": 4096 }),
    );
    h.db.record_artifact(&raw).await.unwrap();
    let slack = Artifact::new(
        h.case_id,
        ArtifactType::SlackSpace,
        None,
        json!({
            "name": "Slack of host.doc",
            "offset_bytes": 1000,
            "size_bytes": 24,
            "source": "file_slack",
            "parent_file": "host.doc",
        }),
    )
    .with_parent(raw.id);
    h.db.record_artifact(&slack).await.unwrap();

    let (status, body) = sweep(
        &h,
        json!({ "patterns": [{ "kind": "text", "value": "needle" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let slack_hits = hits_for(&body, slack.id);
    assert_eq!(slack_hits.len(), 1, "{body}");
    assert_eq!(slack_hits[0]["region"], "slack");
    assert_eq!(slack_hits[0]["offset"], 10);
    assert_eq!(body["objects_offered_by_region"]["slack"], 1, "{body}");
    let statement = body["slack_statement"].as_str().unwrap();
    assert!(statement.contains("file-slack regions"), "{statement}");
    assert!(statement.contains("no other file system"), "{statement}");
}
