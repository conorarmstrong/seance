//! The search-index repair is bounded process-wide, not only per case.
//!
//! `?force=true` exists so a server killed mid-repair cannot wedge a case out of
//! ever being repaired again, and that has to stay. What it must not be is a
//! work generator: every accepted request spawns a pass that ends in
//! `spawn_blocking`, each holding a searcher snapshot and feeding the one global
//! index writer every case shares. Looped by an authenticated caller, that parks
//! blocking-pool threads until nothing else in the process can take one, and
//! pins deleted index segments on disk while it does.
//!
//! These tests live in their own binary rather than beside the other reindex
//! tests, and deliberately so: the limiter is process-wide, so a test that holds
//! every slot would refuse the repairs those tests are waiting on. One binary
//! per integration test file is what keeps the two apart.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::{
    db::DatabaseConnection,
    orchestrator::{CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

/// The limiter these tests exercise is one process-wide object, so they take
/// turns with it: two tests each holding every slot would refuse each other.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The index directory is leaked for the test's lifetime, as the sibling
/// reindex tests do, because the service outlives the `TempDir` guard.
async fn setup() -> (axum::Router, Arc<SqliteConnection>, Uuid) {
    let index_dir = tempfile::tempdir().unwrap();
    let service =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    std::mem::forget(index_dir);

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Reindex Limiter Case", "examiner")
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
        search_service: Some(service),
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

/// **The defect.** With every repair slot taken, a further forced request used
/// to be accepted and spawned anyway; the guard it bypasses is per case, and
/// nothing at all counted the passes already running.
#[tokio::test]
async fn a_forced_repair_is_refused_when_every_repair_slot_is_taken() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let (app, _db, case_id) = setup().await;

    // Hold every slot, which is what a run of already-accepted repairs looks
    // like from here — and which the endpoint could not previously see at all.
    let mut held = Vec::new();
    for _ in 0..seance_api::SEARCH_REPAIR_MAX_CONCURRENT {
        held.push(
            seance_api::SEARCH_REPAIR_SLOTS
                .try_acquire()
                .expect("a slot is free before the cap is reached"),
        );
    }

    let (status, body) = post_reindex(&app, case_id, "?force=true").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a forced repair with no slot free must be refused, not spawned: {body}"
    );
    assert!(
        body.to_string().contains("repair"),
        "and must say what was refused and that it can be retried: {body}"
    );

    drop(held);
}

/// A refusal must leave nothing behind. `search_index_repair_requested` with no
/// outcome beside it is exactly what the per-case in-flight guard reads as "a
/// repair is running", so a refusal that audited a request would wedge the case
/// out of unforced repairs — turning a rate limit into a lasting lockout.
#[tokio::test]
async fn a_refused_repair_leaves_no_unfinished_request_in_the_audit_log() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let (app, db, case_id) = setup().await;

    let mut held = Vec::new();
    for _ in 0..seance_api::SEARCH_REPAIR_MAX_CONCURRENT {
        held.push(
            seance_api::SEARCH_REPAIR_SLOTS
                .try_acquire()
                .expect("a slot is free before the cap is reached"),
        );
    }
    let (status, _) = post_reindex(&app, case_id, "?force=true").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    assert!(
        !audit_actions(&db, case_id)
            .await
            .iter()
            .any(|action| action == "search_index_repair_requested"),
        "a repair that never started must not be recorded as requested: {:?}",
        audit_actions(&db, case_id).await
    );

    drop(held);
}

/// And the bound must be a bound, not a ban: a slot freed by a finished repair
/// admits the next one. `force` is the escape hatch for a server killed
/// mid-repair, and it has to keep working.
#[tokio::test]
async fn a_freed_slot_admits_the_next_forced_repair() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let (app, db, case_id) = setup().await;

    let mut held = Vec::new();
    for _ in 0..seance_api::SEARCH_REPAIR_MAX_CONCURRENT {
        held.push(
            seance_api::SEARCH_REPAIR_SLOTS
                .try_acquire()
                .expect("a slot is free before the cap is reached"),
        );
    }
    let (refused, _) = post_reindex(&app, case_id, "?force=true").await;
    assert_eq!(refused, StatusCode::SERVICE_UNAVAILABLE);
    drop(held);

    let (accepted, body) = post_reindex(&app, case_id, "?force=true").await;
    assert_eq!(
        accepted,
        StatusCode::OK,
        "a free slot must admit the repair: {body}"
    );

    // And the slot has to come back when the repair is over, or the cap decays
    // into a ban after a few hundred repairs.
    for _ in 0..600 {
        let done = audit_actions(&db, case_id).await.iter().any(|action| {
            action == "search_index_repair_completed" || action == "search_index_repair_failed"
        });
        if done {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    for _ in 0..600 {
        if seance_api::SEARCH_REPAIR_SLOTS.available_permits()
            == seance_api::SEARCH_REPAIR_MAX_CONCURRENT
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the repair finished without returning its slot; the cap would decay into a ban");
}
