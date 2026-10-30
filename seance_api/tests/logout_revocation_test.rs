//! Logout ends the session it is called on (SEC-001).
//!
//! A JWT is self-contained, so before `revoked_tokens` existed a logout
//! cleared the browser cookie and nothing else: a captured Bearer token kept
//! working for the rest of its 24 h, and an action taken with it would have
//! been attributed to an examiner who had signed out. These tests pin that a
//! logged-out token is refused, that the refusal survives a restart of the
//! auth state (the DB is the record, not memory), and that logging out one
//! session leaves the same user's other sessions alone.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::Value;
use std::sync::Arc;
use tower::util::ServiceExt;

const JWT_SECRET: &str = "logout-revocation-test-secret";
const CSRF_TOKEN: &str = "logout-revocation-csrf";

async fn fresh_db() -> Arc<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
    db.initialize().await.unwrap();
    Arc::new(db)
}

fn make_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: JWT_SECRET.to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: seance_api::hash_password("bootstrap-admin-pw").unwrap(),
        enabled: true,
    }
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

/// A router over `db`, plus the config that minted its tokens. Building a
/// second router over the same DB is the test's "restart": fresh in-memory
/// state, same durable record.
fn build_app(db: Arc<SqliteConnection>) -> (axum::Router, AuthConfig) {
    let cfg = make_config();
    let app = router_with_auth(build_state(db), Some(cfg.clone()));
    (app, cfg)
}

async fn seed_examiner(db: &SqliteConnection) {
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
}

fn logout(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("authorization", format!("Bearer {}", token))
        .header("x-csrf-token", CSRF_TOKEN)
        .header("cookie", format!("seance_csrf={}", CSRF_TOKEN))
        .body(Body::empty())
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn a_token_is_rejected_after_its_session_logs_out() {
    let db = fresh_db().await;
    seed_examiner(&db).await;
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    // Control: the session works before logout.
    let before = app
        .clone()
        .oneshot(get("/api/v1/cases", &token))
        .await
        .unwrap();
    assert_eq!(before.status(), StatusCode::OK);

    let out = app.clone().oneshot(logout(&token)).await.unwrap();
    assert_eq!(out.status(), StatusCode::OK);

    // The same token, still inside its 24 h, is refused with the auth error
    // shape every other rejection uses.
    let after = app
        .clone()
        .oneshot(get("/api/v1/cases", &token))
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "a logged-out token must not keep working"
    );
    let err = body_json(after).await;
    assert_eq!(err["error"]["code"], "SESSION_REVOKED");
    assert!(err["error"]["message"].is_string());

    // /auth/me agrees with the protected routes.
    let me = app.oneshot(get("/api/v1/auth/me", &token)).await.unwrap();
    assert_eq!(me.status(), StatusCode::OK);
    assert_eq!(body_json(me).await["authenticated"], false);
}

#[tokio::test]
async fn a_revoked_token_stays_rejected_across_a_restart_of_the_auth_state() {
    let db = fresh_db().await;
    seed_examiner(&db).await;
    let (app, cfg) = build_app(db.clone());
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let out = app.oneshot(logout(&token)).await.unwrap();
    assert_eq!(out.status(), StatusCode::OK);
    drop(cfg);

    // "Restart": a brand-new router with no in-memory state, over the same
    // database. If revocation lived only in memory the token would come back.
    let (restarted, _) = build_app(db);
    let after = restarted
        .oneshot(get("/api/v1/cases", &token))
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "a restart must not resurrect a logged-out session"
    );
    assert_eq!(body_json(after).await["error"]["code"], "SESSION_REVOKED");
}

#[tokio::test]
async fn logging_out_one_session_does_not_end_another() {
    let db = fresh_db().await;
    seed_examiner(&db).await;
    let (app, cfg) = build_app(db);
    let (workstation, _) = cfg.generate_token("erin", "examiner").unwrap();
    let (laptop, _) = cfg.generate_token("erin", "examiner").unwrap();
    assert_ne!(workstation, laptop, "each login must mint its own jti");

    let out = app.clone().oneshot(logout(&workstation)).await.unwrap();
    assert_eq!(out.status(), StatusCode::OK);

    let dead = app
        .clone()
        .oneshot(get("/api/v1/cases", &workstation))
        .await
        .unwrap();
    assert_eq!(dead.status(), StatusCode::UNAUTHORIZED);

    let alive = app.oneshot(get("/api/v1/cases", &laptop)).await.unwrap();
    assert_eq!(
        alive.status(),
        StatusCode::OK,
        "revocation is per token, not per user"
    );
}

#[tokio::test]
async fn a_token_without_a_jti_cannot_be_used_because_it_could_never_be_logged_out() {
    use jsonwebtoken::{encode, EncodingKey, Header};

    let db = fresh_db().await;
    seed_examiner(&db).await;
    let (app, _) = build_app(db);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // A pre-SEC-001 token: valid signature, no `jti`.
    let legacy = encode(
        &Header::default(),
        &serde_json::json!({
            "sub": "erin", "exp": now + 3600, "iat": now, "role": "examiner"
        }),
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap();

    let resp = app.oneshot(get("/api/v1/cases", &legacy)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["error"]["code"], "SESSION_REVOKED");
}
