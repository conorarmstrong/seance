//! The per-case search-index display-name repair.
//!
//! LIVE-022 taught every new document to carry the name of the thing it
//! describes, but cases indexed before that fix still show the literal word
//! "ParsedRecord" in every result row, and re-ingesting the evidence was the
//! only way to change it. This endpoint repairs the documents a case already
//! has in the index. It does not — and these tests hold it to this — discover
//! artifacts that were never indexed at all.

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

/// Build the router around a real (empty) Tantivy index and hand the same
/// `SearchService` back, so a test can seed documents the router will repair.
/// The index directory is deliberately leaked for the test's lifetime, as
/// `report_export_test` does, because the service outlives the `TempDir` guard.
async fn setup() -> (
    axum::Router,
    Arc<SqliteConnection>,
    Uuid,
    Arc<seance_search::SearchService>,
) {
    let index_dir = tempfile::tempdir().unwrap();
    let service =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    std::mem::forget(index_dir);
    let (app, db, case_id) = setup_with_index(Some(service.clone())).await;
    (app, db, case_id, service)
}

async fn setup_with_index(
    search_service: Option<Arc<seance_search::SearchService>>,
) -> (axum::Router, Arc<SqliteConnection>, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Search Reindex Case", "examiner")
        .await
        .unwrap();

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service,
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
    (router_with_auth(app_state, Some(auth_config)), db, case_id)
}

async fn post_reindex(
    app: &axum::Router,
    case_id: Uuid,
    query: &str,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/search/reindex{}", case_id, query))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

async fn audit_actions(db: &SqliteConnection, case_id: Uuid) -> Vec<String> {
    db.get_audit_log(case_id, 100, 0)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|row| row["action"].as_str().map(str::to_string))
        .collect()
}

/// Poll the case's audit log until the repair reports an outcome, and return
/// that event. The audit log is the operation's record of completion; there is
/// no job row, because `ad_hoc_jobs.target_artifact_id` is a foreign key into
/// `artifacts` and this operation has no artifact to point at.
async fn await_repair_outcome(db: &SqliteConnection, case_id: Uuid) -> serde_json::Value {
    for _ in 0..300 {
        let event = db
            .get_audit_log(case_id, 100, 0)
            .await
            .unwrap()
            .into_iter()
            .find(|row| {
                row["action"] == "search_index_repair_completed"
                    || row["action"] == "search_index_repair_failed"
            });
        if let Some(event) = event {
            return event;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the repair never recorded an outcome");
}

/// Record an artifact and put it in the search index, so a test can assert what
/// the endpoint does to a case that actually has documents.
///
/// Note what this cannot set up: every document the public indexing path writes
/// already carries a correct display name, so the rename itself is exercised
/// in-crate in `seance_search`, where a pre-fix document can be constructed.
/// What these tests hold is the endpoint's contract — authorization, the audit
/// record, the guard, and the promise that a repair never costs the case a
/// search hit.
async fn index_artifact(
    service: &seance_search::SearchService,
    db: &SqliteConnection,
    case_id: Uuid,
    metadata: serde_json::Value,
) -> Uuid {
    let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, metadata);
    db.record_artifact(&artifact).await.unwrap();
    service.add_artifact_to_index(&artifact).await.unwrap();
    service.commit().await.unwrap();
    artifact.id
}

#[tokio::test]
async fn search_reindex_starts_a_repair_and_audits_the_request_before_touching_anything() {
    let (app, db, case_id, service) = setup().await;
    index_artifact(
        &service,
        &db,
        case_id,
        json!({ "name": "notes.txt", "path": "/evidence/notes.txt" }),
    )
    .await;

    let (status, body) = post_reindex(&app, case_id, "").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "running");
    assert!(
        body["repair_id"].as_str().is_some(),
        "the response must name the repair it started: {body}"
    );

    let outcome = await_repair_outcome(&db, case_id).await;
    assert_eq!(
        outcome["action"], "search_index_repair_completed",
        "a repair over a healthy case must finish, not fail: {outcome}"
    );

    let actions = audit_actions(&db, case_id).await;
    assert!(
        actions.iter().any(|a| a == "search_index_repair_requested"),
        "the request must be audited before any document is touched: {actions:?}"
    );

    // The case must still be searchable afterwards. A repair that emptied the
    // index would be strictly worse than the stale names it was fixing.
    assert_eq!(
        service
            .search(case_id, "notes.txt", 10)
            .await
            .unwrap()
            .len(),
        1,
        "the repaired case must still answer the searches it answered before"
    );
}

/// The audit trail has to say what the operation could not do, not only what it
/// did. A repair walks the documents that are in the index; artifacts that were
/// never indexed stay unsearchable and only re-ingest changes that.
#[tokio::test]
async fn the_completion_audit_says_what_a_repair_does_not_cover() {
    let (app, db, case_id, _service) = setup().await;

    let (status, _body) = post_reindex(&app, case_id, "").await;
    assert_eq!(status, StatusCode::OK);
    let outcome = await_repair_outcome(&db, case_id).await;

    let details = outcome["details"]
        .as_str()
        .expect("the outcome event must carry details");
    assert!(
        details.contains("never indexed"),
        "the record must disclose what the repair cannot reach: {details}"
    );
    assert!(
        details.contains("renamed"),
        "and must quote what it actually changed: {details}"
    );
    assert!(
        details.contains("indexed document"),
        "and must count against the documents that are in the INDEX, not the \
         artifacts in the case: {details}"
    );

    // The same disclosure has to be on the record written before anything is
    // touched, not only on the one written afterwards. An audit trail is read a
    // row at a time.
    let requested = db
        .get_audit_log(case_id, 100, 0)
        .await
        .unwrap()
        .into_iter()
        .find(|row| row["action"] == "search_index_repair_requested")
        .expect("the request must be audited");
    assert!(
        requested["details"]
            .as_str()
            .is_some_and(|d| d.contains("never indexed")),
        "the request record must carry the scope note too: {requested}"
    );
}

#[tokio::test]
async fn search_reindex_reports_unavailable_when_no_index_is_configured() {
    let (app, db, case_id) = setup_with_index(None).await;

    // The detail ("Search service not available") is deliberately replaced with
    // a correlation id before it reaches the client, as every
    // `InternalServerError` is; it is in the server log under that id.
    let (status, body) = post_reindex(&app, case_id, "").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");

    // Nothing was started, so nothing may claim to have been repaired.
    let actions = audit_actions(&db, case_id).await;
    assert!(
        !actions.iter().any(|a| a.starts_with("search_index_repair")),
        "a refused request must not leave a repair in the audit trail: {actions:?}"
    );
}

#[tokio::test]
async fn a_second_reindex_is_refused_while_one_is_still_running() {
    let (app, db, case_id, _service) = setup().await;

    // Stand an unfinished request in the audit log directly: that is what the
    // guard reads, and a real first request over a small case finishes far too
    // fast to race against reliably.
    db.record_audit_event(
        Some(case_id),
        "examiner",
        "search_index_repair_requested",
        Some("case"),
        Some(case_id),
        Some("repair in progress"),
    )
    .await
    .unwrap();

    let (status, body) = post_reindex(&app, case_id, "").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a second repair over the same case must be refused: {body}"
    );
    assert!(
        body.to_string().contains("already running"),
        "and must say why: {body}"
    );
}

/// A request whose outcome was never recorded — a server killed mid-repair —
/// must not lock the case out of ever being repaired again.
#[tokio::test]
async fn an_abandoned_repair_can_be_overridden_rather_than_wedging_the_case() {
    let (app, db, case_id, _service) = setup().await;
    db.record_audit_event(
        Some(case_id),
        "examiner",
        "search_index_repair_requested",
        Some("case"),
        Some(case_id),
        Some("repair that never reported an outcome"),
    )
    .await
    .unwrap();

    let (refused, _) = post_reindex(&app, case_id, "").await;
    assert_eq!(refused, StatusCode::BAD_REQUEST);

    let (forced, body) = post_reindex(&app, case_id, "?force=true").await;
    assert_eq!(forced, StatusCode::OK, "body: {body}");
    await_repair_outcome(&db, case_id).await;
}

/// A repair scoped to one case must not disturb another case's documents. The
/// crate-level wipe (`rebuild_index`) is global and repopulates nothing; if it
/// were ever wired to this route, this is what would catch it.
#[tokio::test]
async fn reindexing_one_case_leaves_another_cases_search_results_intact() {
    let (app, db, case_id, service) = setup().await;
    let other_case = db.create_case("Bystander Case", "examiner").await.unwrap();

    index_artifact(&service, &db, case_id, json!({ "name": "target_doc.txt" })).await;
    index_artifact(
        &service,
        &db,
        other_case,
        json!({ "name": "bystander_doc.txt" }),
    )
    .await;

    let (status, _body) = post_reindex(&app, case_id, "").await;
    assert_eq!(status, StatusCode::OK);
    await_repair_outcome(&db, case_id).await;

    assert_eq!(
        service
            .search(other_case, "bystander_doc", 10)
            .await
            .unwrap()
            .len(),
        1,
        "another case's documents must survive this case's repair"
    );
    assert_eq!(
        service
            .search(case_id, "target_doc", 10)
            .await
            .unwrap()
            .len(),
        1,
        "and the repaired case must stay searchable"
    );
}
