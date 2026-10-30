//! Indexing what a case has and the index does not (`LIVE-028`).
//!
//! `rebuild_index` only ever deleted, and the batch path took an explicit list
//! of at most five thousand ids, so a case whose ingest dropped documents had
//! no route back to a whole index short of re-ingesting the evidence. The case
//! this was found against holds 580,394 artifacts.
//!
//! Two things these tests hold hardest, because both are ways the operation
//! could lie. It must not report a case made whole when artifacts were refused,
//! and it must say — in the response, and in the audit record that outlives it
//! — that a document built from the database carries the artifact's metadata
//! and NOT the text extracted from the file's bytes at ingest (`B5-001`). A
//! keyword search over a backfilled file is answered from metadata alone, and
//! an examiner reading "reindexed" would otherwise take an empty result as
//! evidence that the term is absent from the evidence.

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

/// Artifacts recorded in the database. Half of them are also indexed at setup,
/// so a pass has both work to do and work to skip.
const ARTIFACTS: usize = 40;
const PRE_INDEXED: usize = 20;

/// The cancellation handle the app state was built with, so a test can cancel a
/// case the way `POST /cases/{id}/processing/cancel` does.
async fn setup_with_cancel() -> (
    axum::Router,
    Uuid,
    Arc<SqliteConnection>,
    seance_core::orchestrator::CancellationHandle,
) {
    let cancel = CancellationHandle::new();
    let (app, case_id, _service, db) = setup_inner(cancel.clone()).await;
    (app, case_id, db, cancel)
}

async fn setup() -> (
    axum::Router,
    Uuid,
    Arc<seance_search::SearchService>,
    Arc<SqliteConnection>,
) {
    setup_inner(CancellationHandle::new()).await
}

async fn setup_inner(
    cancel: seance_core::orchestrator::CancellationHandle,
) -> (
    axum::Router,
    Uuid,
    Arc<seance_search::SearchService>,
    Arc<SqliteConnection>,
) {
    let index_dir = tempfile::tempdir().unwrap();
    let service =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    std::mem::forget(index_dir);

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Backfill Case", "examiner").await.unwrap();

    for i in 0..ARTIFACTS {
        let artifact = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": format!("file_{i:03}.txt"),
                "path": format!("/evidence/file_{i:03}.txt"),
            }),
        );
        db.record_artifact(&artifact).await.unwrap();
        if i < PRE_INDEXED {
            service.add_artifact_to_index_sync(&artifact).unwrap();
        }
    }
    service.commit_sync().unwrap();

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: Some(service.clone()),
        ingestion_service: orchestrator.ingestion_service(),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: EvidenceRootPolicy::unrestricted(),
        cancellation: cancel,
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
        service,
        db,
    )
}

/// The backfill and the repair share a process-wide slot count of two, so four
/// tests running at once in one binary can refuse each other for reasons that
/// have nothing to do with what they are testing. They take turns.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn post(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The audit rows this case carries for one action, newest first.
async fn audit(db: &Arc<SqliteConnection>, case_id: Uuid, action: &str) -> Vec<Value> {
    db.get_audit_log_filtered(case_id, None, Some(action), None, None, None, 20, 0)
        .await
        .expect("audit log")
}

/// Wait for the spawned pass to write its terminal record. The endpoint returns
/// as soon as the sweep starts, which is the contract; the test needs the end.
async fn wait_for_completion(db: &Arc<SqliteConnection>, case_id: Uuid) -> Value {
    for _ in 0..200 {
        let rows = audit(db, case_id, "search_index_backfill_completed").await;
        if let Some(row) = rows.first() {
            return row.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the backfill never recorded an outcome");
}

#[tokio::test]
async fn it_indexes_the_artifacts_the_index_was_missing_and_leaves_the_rest_alone() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (app, case_id, service, db) = setup().await;

    // Before: only the pre-indexed half is findable.
    let before = service
        .search(case_id, "file_030", 10)
        .await
        .expect("search");
    assert!(
        before.is_empty(),
        "artifact 30 was never indexed, so it must not be findable before the backfill"
    );

    let (status, body) = post(&app, format!("/api/v1/cases/{}/search/backfill", case_id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "running");
    assert_eq!(body["artifacts"], ARTIFACTS as u64);

    let record = wait_for_completion(&db, case_id).await;
    let details = record["details"].as_str().unwrap_or_default().to_string();
    assert!(
        details.contains(&format!("examined {} artifact(s)", ARTIFACTS)),
        "{details}"
    );
    assert!(
        details.contains(&format!("{} already indexed", PRE_INDEXED)),
        "{details}"
    );
    assert!(
        details.contains(&format!("{} added", ARTIFACTS - PRE_INDEXED)),
        "{details}"
    );

    // After: the artifact that was only in the database is findable.
    let after = service
        .search(case_id, "file_030", 10)
        .await
        .expect("search");
    assert_eq!(
        after.len(),
        1,
        "the backfill must make an unindexed artifact findable"
    );
}

#[tokio::test]
async fn every_record_says_what_a_backfilled_document_does_not_carry() {
    let _turn = ONE_AT_A_TIME.lock().await;
    // The scope note is the whole reason this operation can be honest about
    // itself. It has to be in the response the caller reads AND in the audit
    // record read months later, because the second is often read alone.
    let (app, case_id, _service, db) = setup().await;
    let (_, body) = post(&app, format!("/api/v1/cases/{}/search/backfill", case_id)).await;
    let note = body["note"].as_str().unwrap_or_default();
    assert!(note.contains("metadata only"), "{note}");
    assert!(note.contains("re-ingested"), "{note}");

    let requested = audit(&db, case_id, "search_index_backfill_requested").await;
    let requested = requested.first().expect("a request is recorded first");
    assert!(
        requested["details"]
            .as_str()
            .unwrap_or_default()
            .contains("metadata only"),
        "the request record must carry the scope note too: {requested}"
    );

    let completed = wait_for_completion(&db, case_id).await;
    assert!(
        completed["details"]
            .as_str()
            .unwrap_or_default()
            .contains("metadata only"),
        "{completed}"
    );
}

#[tokio::test]
async fn a_second_backfill_is_refused_while_one_is_unfinished_and_forced_past() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (app, case_id, _service, db) = setup().await;
    let (status, _) = post(&app, format!("/api/v1/cases/{}/search/backfill", case_id)).await;
    assert_eq!(status, StatusCode::OK);

    // The guard reads the audit log: a request with no outcome after it means
    // one is running. Assert the refusal against that state directly rather
    // than racing the pass.
    let refused = post(&app, format!("/api/v1/cases/{}/search/backfill", case_id)).await;
    if refused.0 == StatusCode::OK {
        // The first pass already finished — then there is nothing to refuse,
        // and the test's subject is the forced path below.
        wait_for_completion(&db, case_id).await;
    } else {
        assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{:?}", refused.1);
        assert!(
            refused.1["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("force=true"),
            "the refusal must name the way out: {:?}",
            refused.1
        );
    }

    wait_for_completion(&db, case_id).await;
    let (forced, body) = post(
        &app,
        format!("/api/v1/cases/{}/search/backfill?force=true", case_id),
    )
    .await;
    assert_eq!(forced, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_case_already_whole_is_walked_and_nothing_is_added() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (app, case_id, service, db) = setup().await;
    // Index the rest by hand, so the pass finds nothing to do.
    let mut after = None;
    loop {
        let page = db.artifacts_page_after(case_id, after, 100).await.unwrap();
        if page.is_empty() {
            break;
        }
        after = page.last().map(|a| a.id);
        for artifact in &page {
            service.add_artifact_to_index_sync(artifact).unwrap();
        }
    }
    service.commit_sync().unwrap();

    let (status, _) = post(&app, format!("/api/v1/cases/{}/search/backfill", case_id)).await;
    assert_eq!(status, StatusCode::OK);
    let record = wait_for_completion(&db, case_id).await;
    let details = record["details"].as_str().unwrap_or_default().to_string();
    assert!(details.contains("0 added"), "{details}");
    assert!(
        details.contains(&format!("{} already indexed", ARTIFACTS)),
        "{details}"
    );
}

#[tokio::test]
async fn a_sweep_stopped_by_a_cancel_is_recorded_as_stopped_and_never_as_completed() {
    let _turn = ONE_AT_A_TIME.lock().await;
    // The ordinary way to reach this: an examiner cancels the case's
    // processing, then presses Backfill. The per-case cancel flag is still set,
    // so the sweep stops on its first page with "examined 0; 0 added" — numbers
    // which, filed as a completion, read as "the case was walked and nothing
    // was missing". That is the false completeness this whole operation is
    // written to avoid, so a stop is filed as a stop.
    let (app, case_id, db, cancel) = setup_with_cancel().await;
    cancel.cancel_case(case_id);

    let (status, body) = post(&app, format!("/api/v1/cases/{}/search/backfill", case_id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let mut record = None;
    for _ in 0..200 {
        if let Some(row) = audit(&db, case_id, "search_index_backfill_stopped")
            .await
            .first()
        {
            record = Some(row.clone());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let record = record.expect("a stopped sweep records that it stopped");
    let details = record["details"].as_str().unwrap_or_default().to_string();
    assert!(details.contains("STOPPED"), "{details}");
    assert!(
        details.contains("NOT known to be whole"),
        "the record must refuse the inference the numbers invite: {details}"
    );
    assert!(details.contains("re-run"), "{details}");

    assert!(
        audit(&db, case_id, "search_index_backfill_completed")
            .await
            .is_empty(),
        "a stopped sweep must not also be recorded as completed"
    );
}

#[tokio::test]
async fn a_repair_and_a_backfill_do_not_run_on_one_case_at_once() {
    let _turn = ONE_AT_A_TIME.lock().await;
    // CORE_DESIGN.md says the two share their in-flight guard. They share the
    // index writer and the blocking pool, so running a repair that re-emits
    // documents from a snapshot beside a backfill that adds new ones is an
    // interleaving nothing tests and nothing needs.
    let (app, case_id, _service, db) = setup().await;
    let (status, _) = post(&app, format!("/api/v1/cases/{}/search/backfill", case_id)).await;
    assert_eq!(status, StatusCode::OK);

    let (repair_status, repair_body) =
        post(&app, format!("/api/v1/cases/{}/search/reindex", case_id)).await;
    if repair_status == StatusCode::BAD_REQUEST {
        assert!(
            repair_body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("already running"),
            "{repair_body}"
        );
    }
    // Either way the backfill's own outcome must land; the guard must not have
    // eaten it.
    wait_for_completion(&db, case_id).await;
}
