//! CR-047: `FilterCondition::validate` must be enforced where a filter enters
//! (save) and where a stored one is read back (grid, apply).
//!
//! SYNTHETIC: the filters here are `Not` chains built in the test. A filter
//! nested past the evaluator's limit evaluates to `false` for every row, so
//! unvalidated it would open an empty grid for a population the examiner never
//! asked to be empty.

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

async fn setup() -> (axum::Router, Arc<SqliteConnection>, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Depth Case", "examiner").await.unwrap();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "a.jpg", "size": 5}),
    );
    db.record_artifact(&artifact).await.unwrap();

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
    (router_with_auth(app_state, Some(auth_config)), db, case_id)
}

/// A `Not` chain `levels` deep around one simple condition. The limit is 32.
fn not_chain(levels: usize) -> Value {
    let mut f = json!({"type": "simple", "field": "size", "operator": "gt", "value": 1});
    for _ in 0..levels {
        f = json!({"type": "not", "condition": f});
    }
    f
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn post_filter(app: &axum::Router, case_id: Uuid, filter: Value) -> (StatusCode, Value) {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/api/v1/cases/{case_id}/filters"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"name": "deep", "filter": filter}).to_string(),
            ))
            .unwrap(),
    )
    .await
}

async fn get(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    send(
        app,
        Request::builder().uri(uri).body(Body::empty()).unwrap(),
    )
    .await
}

#[tokio::test]
async fn saving_a_filter_nested_past_the_limit_is_refused() {
    let (app, _db, case_id) = setup().await;
    let (status, body) = post_filter(&app, case_id, not_chain(33)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(body.to_string().contains("33"), "names the depth: {body}");
}

#[tokio::test]
async fn saving_a_filter_at_the_limit_is_accepted() {
    let (app, _db, case_id) = setup().await;
    let (status, body) = post_filter(&app, case_id, not_chain(32)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn a_stored_filter_past_the_limit_is_refused_by_the_grid_and_by_apply() {
    let (app, db, case_id) = setup().await;
    let id = Uuid::new_v4();
    db.save_filter(
        id,
        Some(case_id),
        "stored deep",
        "",
        &not_chain(33).to_string(),
        false,
    )
    .await
    .unwrap();

    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/files?filter_id={id}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "grid body: {body}");

    let (status, body) = get(&app, format!("/api/v1/cases/{case_id}/filters/{id}/apply")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "apply body: {body}");
}
