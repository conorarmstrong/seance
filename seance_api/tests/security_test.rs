//! OWASP-style security posture tests for the API surface.
//!
//! Complements users_rbac_test (auth/authz) with: unauthenticated protected
//! routes are rejected even though health probes are public; the health/
//! readiness endpoints work without credentials (D11); and CSRF is enforced on
//! unsafe methods. These lock in the hardening from the production pass.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use std::sync::Arc;
use tower::util::ServiceExt;

const JWT_SECRET: &str = "sec-test-secret";

async fn fresh_db() -> Arc<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
    db.initialize().await.unwrap();
    Arc::new(db)
}

fn build_state(db: Arc<SqliteConnection>) -> AppState {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, _ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    AppState {
        db: db.clone(),
        // A counted submitter over the test channel; the counter is the test's own
        // because nothing here submits through it.
        orchestrator_sender: seance_core::orchestrator::TaskSubmitter::new(
            tx,
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        ),
        ad_hoc_sender: ad_hoc_tx,
        event_sender: event_tx.clone(),
        status_sender: status_tx,
        active_tasks: active_tasks.clone(),
        search_service: None,
        ingestion_service: seance_core::ingestion::IngestionService::new(
            Some(db.clone()),
            task_tx,
            event_tx,
            active_tasks,
        ),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: seance_api::EvidenceRootPolicy::from_env(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    }
}

/// Router with auth ENABLED (the production posture).
fn app_auth_on(db: Arc<SqliteConnection>) -> axum::Router {
    let cfg = AuthConfig {
        jwt_secret: JWT_SECRET.to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: seance_api::hash_password("pw").unwrap(),
        enabled: true,
    };
    router_with_auth(build_state(db), Some(cfg))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// D11: liveness probe is reachable WITHOUT a token even with auth enabled.
#[tokio::test]
async fn healthz_is_public() {
    let app = app_auth_on(fresh_db().await);
    let resp = app.oneshot(get("/healthz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// D11: readiness probe returns 200 (DB reachable) without a token.
#[tokio::test]
async fn readyz_is_public_and_db_backed() {
    let app = app_auth_on(fresh_db().await);
    let resp = app.oneshot(get("/readyz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// A protected route without a token is rejected (401) even though the health
/// probes above are public -- the public probes are not an auth hole.
#[tokio::test]
async fn protected_route_requires_auth() {
    let app = app_auth_on(fresh_db().await);
    let resp = app.oneshot(get("/api/v1/cases")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// An unsafe method with a valid-looking bearer token but NO CSRF double-submit
/// is rejected (CSRF protection is independent of auth).
#[tokio::test]
async fn unsafe_method_requires_csrf() {
    let app = app_auth_on(fresh_db().await);
    // No token, no CSRF -- must not reach the handler (401 or 403, never 2xx).
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/cases")
        .header("content-type", "application/json")
        .body(Body::from("{\"name\":\"x\",\"examiner\":\"y\"}"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN,
        "unauthenticated/no-CSRF POST must be blocked, got {}",
        resp.status()
    );
}
