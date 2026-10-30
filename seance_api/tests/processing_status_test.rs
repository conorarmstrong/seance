//! `GET /api/v1/status` — the per-case census beside the process-wide count.
//!
//! The complaint (BUG-027 / BUG-043 / B2-115): one `active_tasks` number for
//! the whole process, so a client with case A open could not tell whether the
//! work still outstanding was its own or case B's. The orchestrator has kept a
//! per-case census since HUNT-019; these tests pin that the route serves it,
//! and that a server assembled without it says so rather than answering "no
//! cases have work".
//!
//! Every number asserted here is hand-derived from the setup: the process-wide
//! count is incremented the way the orchestrator's own callers do it (once per
//! queued artifact, plus one held guard for pre-queue ingest), so the sums can
//! be re-counted from the test body.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Extension,
};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy, ProcessingCensus};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    orchestrator::{ActiveTaskGuard, CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup() -> (AppState, Orchestrator) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
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
    (app_state, orchestrator)
}

fn no_auth() -> AuthConfig {
    AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: String::new(),
        enabled: false,
    }
}

async fn get_status(app: axum::Router) -> Value {
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Queue one artifact for `case_id` the way the orchestrator's own producers
/// do: count it process-wide, then hand it to the queue (which counts it for
/// its case).
fn queue_for(orchestrator: &Orchestrator, case_id: Uuid) {
    orchestrator.active_tasks().fetch_add(1, Ordering::SeqCst);
    orchestrator
        .task_queue()
        .push(Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({}),
        ))
        .unwrap_or_else(|_| panic!("queue is open"));
}

#[tokio::test]
async fn status_reports_each_cases_outstanding_work_keyed_by_case_id() {
    let (state, orchestrator) = setup().await;
    let case_a = Uuid::new_v4();
    let case_b = Uuid::new_v4();
    let case_settled = Uuid::new_v4();

    // Case A: three queued. Case B: one queued. A third case queued one and
    // had it taken by a worker and finished, so it holds nothing now.
    for _ in 0..3 {
        queue_for(&orchestrator, case_a);
    }
    queue_for(&orchestrator, case_b);
    queue_for(&orchestrator, case_settled);
    let census = orchestrator.case_census();
    census.dequeued(case_settled);
    orchestrator.active_tasks().fetch_sub(1, Ordering::SeqCst);

    // Pre-queue ingest work — hashing an image before its first artifact
    // exists — is counted process-wide but belongs to no case the census can
    // name. Held for the duration of the request.
    let _ingest = ActiveTaskGuard::new(orchestrator.active_tasks());

    let app = router_with_auth(state, Some(no_auth()))
        .layer(Extension(ProcessingCensus(orchestrator.case_census())));
    let body = get_status(app).await;

    assert_eq!(
        body["active_tasks"], 5,
        "3 (A) + 1 (B) + 1 (pre-queue ingest)"
    );
    assert_eq!(
        body["scope"], "process",
        "`scope` still names what `active_tasks` counts: the frontend draws no \
         conclusion from any other value"
    );

    let cases = body["cases"]
        .as_object()
        .expect("per-case breakdown keyed by case id");
    assert_eq!(cases[&case_a.to_string()]["active_tasks"], 3);
    assert_eq!(cases[&case_b.to_string()]["active_tasks"], 1);
    assert!(
        !cases.contains_key(&case_settled.to_string()),
        "a case holding no queued or in-flight artifact is absent, not zero"
    );
    assert_eq!(cases.len(), 2);

    assert_eq!(
        body["unattributed_tasks"], 1,
        "the process-wide count the census could not attribute to a case"
    );
    assert!(
        body.get("cases_unavailable").is_none(),
        "the census was served, so no unavailability reason is given"
    );
}

#[tokio::test]
async fn status_with_no_outstanding_work_reports_an_empty_case_map() {
    let (state, orchestrator) = setup().await;
    let app = router_with_auth(state, Some(no_auth()))
        .layer(Extension(ProcessingCensus(orchestrator.case_census())));
    let body = get_status(app).await;

    assert_eq!(body["active_tasks"], 0);
    assert_eq!(body["scope"], "process");
    assert_eq!(body["cases"], json!({}));
    assert_eq!(body["unattributed_tasks"], 0);
}

#[tokio::test]
async fn a_server_assembled_without_the_census_says_so_rather_than_reporting_no_cases() {
    let (state, orchestrator) = setup().await;
    let case_a = Uuid::new_v4();
    queue_for(&orchestrator, case_a);

    // No `ProcessingCensus` extension: only the process-wide count is known.
    let app = router_with_auth(state, Some(no_auth()));
    let body = get_status(app).await;

    assert_eq!(body["active_tasks"], 1);
    assert_eq!(body["scope"], "process");
    assert!(
        body["cases"].is_null(),
        "could not look must not read as no cases: got {}",
        body["cases"]
    );
    assert!(body["unattributed_tasks"].is_null());
    let reason = body["cases_unavailable"]
        .as_str()
        .expect("a reason the per-case breakdown is missing");
    assert!(
        reason.contains("census"),
        "the reason names what is missing: {reason}"
    );
}
