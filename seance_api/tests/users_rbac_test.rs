//! Integration tests for multi-user authentication + role-based access control.
//!
//! Covers: DB-backed login (success/wrong-password/deactivated), JWT role
//! propagation, the admin-only user-management endpoints (403 for non-admins),
//! admin bootstrap seeding, and per-user audit attribution.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

const JWT_SECRET: &str = "rbac-test-secret";
const CSRF_TOKEN: &str = "rbac-csrf";

/// Fresh in-memory DB with migrations applied.
async fn fresh_db() -> Arc<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
    db.initialize().await.unwrap();
    Arc::new(db)
}

/// AuthConfig sharing a fixed secret so tests can mint their own tokens.
fn make_config(enabled: bool) -> AuthConfig {
    AuthConfig {
        jwt_secret: JWT_SECRET.to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: seance_api::hash_password("bootstrap-admin-pw").unwrap(),
        enabled,
    }
}

/// Build an AppState around a shared DB. Orchestrator channels are unused.
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

/// Build the full router (auth ENABLED) around a shared DB, returning the
/// config too so tests can mint tokens with the same secret.
fn build_app(db: Arc<SqliteConnection>) -> (axum::Router, AuthConfig) {
    let cfg = make_config(true);
    let app = router_with_auth(build_state(db), Some(cfg.clone()));
    (app, cfg)
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// POST to the login endpoint. Login is public but still behind CSRF, so we
/// supply a matching double-submit cookie+header pair.
fn login_request(username: &str, password: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .header("x-csrf-token", CSRF_TOKEN)
        .header("cookie", format!("seance_csrf={}", CSRF_TOKEN))
        .body(Body::from(
            json!({ "username": username, "password": password }).to_string(),
        ))
        .unwrap()
}

/// Authenticated POST: Bearer token for auth + CSRF double-submit pair.
fn authed_post(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .header("x-csrf-token", CSRF_TOKEN)
        .header("cookie", format!("seance_csrf={}", CSRF_TOKEN))
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Authenticated GET: Bearer token (safe method needs no CSRF).
fn authed_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
}

// ============================================================
//  Login flow (DB-backed credential validation)
// ============================================================

#[tokio::test]
async fn login_succeeds_and_issues_token_with_role() {
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let (app, _cfg) = build_app(db);

    let resp = app
        .oneshot(login_request("erin", "examinerpw1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp).await;
    assert_eq!(body["username"].as_str().unwrap(), "erin");
    assert_eq!(body["role"].as_str().unwrap(), "examiner");
    assert!(
        !body["token"].as_str().unwrap().is_empty(),
        "must issue a JWT"
    );
}

#[tokio::test]
async fn login_wrong_password_fails() {
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let (app, _cfg) = build_app(db);

    let resp = app
        .oneshot(login_request("erin", "not-the-password"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn deactivated_user_cannot_login() {
    let db = fresh_db().await;
    let id = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    db.set_user_active(id, false).await.unwrap();
    let (app, _cfg) = build_app(db);

    let resp = app
        .oneshot(login_request("erin", "examinerpw1"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a deactivated user must not be able to log in"
    );
}

// ============================================================
//  Role guard on user-management endpoints
// ============================================================

#[tokio::test]
async fn non_admin_token_is_rejected_by_user_management() {
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("pw").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let (app, cfg) = build_app(db);

    // Mint an examiner token directly (valid signature, examiner role).
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let resp = app
        .oneshot(authed_get("/api/v1/users", &token))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "examiner must not reach the admin-only user list"
    );
}

#[tokio::test]
async fn admin_can_create_and_list_users() {
    let db = fresh_db().await;
    db.create_user(
        "root",
        &seance_api::hash_password("rootpw1234").unwrap(),
        "admin",
    )
    .await
    .unwrap();
    let (app, cfg) = build_app(db.clone());
    let (admin_token, _) = cfg.generate_token("root", "admin").unwrap();

    // Create an examiner via the endpoint.
    let create = app
        .clone()
        .oneshot(authed_post(
            "/api/v1/users",
            &admin_token,
            json!({ "username": "dave", "password": "davepw12345", "role": "examiner" }),
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let created = body_json(create).await;
    assert_eq!(created["username"].as_str().unwrap(), "dave");
    assert_eq!(created["role"].as_str().unwrap(), "examiner");
    assert!(
        created.get("password_hash").is_none(),
        "must never leak the hash"
    );

    // The new examiner can now log in and gets the examiner role.
    let login = app
        .clone()
        .oneshot(login_request("dave", "davepw12345"))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(body_json(login).await["role"].as_str().unwrap(), "examiner");

    // List shows both users.
    let list = app
        .oneshot(authed_get("/api/v1/users", &admin_token))
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let users = body_json(list).await;
    let names: Vec<&str> = users
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"root"));
    assert!(names.contains(&"dave"));
}

#[tokio::test]
async fn admin_can_deactivate_user_via_endpoint() {
    let db = fresh_db().await;
    db.create_user(
        "root",
        &seance_api::hash_password("rootpw1234").unwrap(),
        "admin",
    )
    .await
    .unwrap();
    let target = db
        .create_user(
            "dave",
            &seance_api::hash_password("davepw12345").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let (app, cfg) = build_app(db.clone());
    let (admin_token, _) = cfg.generate_token("root", "admin").unwrap();

    let resp = app
        .clone()
        .oneshot(authed_post(
            &format!("/api/v1/users/{}/deactivate", target),
            &admin_token,
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Deactivated user can no longer log in.
    let login = app
        .oneshot(login_request("dave", "davepw12345"))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn user_can_change_own_password() {
    let db = fresh_db().await;
    let dave = db
        .create_user(
            "dave",
            &seance_api::hash_password("davepw12345").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let (app, cfg) = build_app(db.clone());
    let (dave_token, _) = cfg.generate_token("dave", "examiner").unwrap();

    // A self-service change without the current password is refused, so a
    // stolen session cannot take the account over (BUG-194).
    let no_current = app
        .clone()
        .oneshot(authed_post(
            &format!("/api/v1/users/{}/password", dave),
            &dave_token,
            json!({ "password": "newdavepw123" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        no_current.status(),
        StatusCode::FORBIDDEN,
        "changing your own password must require the current one"
    );

    // A wrong current password is refused too.
    let wrong_current = app
        .clone()
        .oneshot(authed_post(
            &format!("/api/v1/users/{}/password", dave),
            &dave_token,
            json!({ "password": "newdavepw123", "current_password": "not-my-password" }),
        ))
        .await
        .unwrap();
    assert_eq!(wrong_current.status(), StatusCode::FORBIDDEN);

    // Non-admin changes their OWN password with the correct current one: allowed.
    let resp = app
        .clone()
        .oneshot(authed_post(
            &format!("/api/v1/users/{}/password", dave),
            &dave_token,
            json!({ "password": "newdavepw123", "current_password": "davepw12345" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Old password no longer works; new one does.
    let old = app
        .clone()
        .oneshot(login_request("dave", "davepw12345"))
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
    let new = app
        .oneshot(login_request("dave", "newdavepw123"))
        .await
        .unwrap();
    assert_eq!(new.status(), StatusCode::OK);
}

#[tokio::test]
async fn non_admin_cannot_change_another_users_password() {
    let db = fresh_db().await;
    db.create_user(
        "dave",
        &seance_api::hash_password("davepw12345").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let victim = db
        .create_user(
            "root",
            &seance_api::hash_password("rootpw1234").unwrap(),
            "admin",
        )
        .await
        .unwrap();
    let (app, cfg) = build_app(db);
    let (dave_token, _) = cfg.generate_token("dave", "examiner").unwrap();

    let resp = app
        .oneshot(authed_post(
            &format!("/api/v1/users/{}/password", victim),
            &dave_token,
            json!({ "password": "hijacked-pw-1" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "a non-admin must not change another user's password"
    );
}

// ============================================================
//  Admin bootstrap
// ============================================================

#[tokio::test]
async fn bootstrap_seeds_exactly_one_admin_when_empty() {
    let db = fresh_db().await;
    let cfg = make_config(true);

    assert_eq!(db.count_users().await.unwrap(), 0);

    // Idempotent: two calls still yield exactly one admin.
    seance_api::bootstrap_admin(&db, &cfg, true).await.unwrap();
    seance_api::bootstrap_admin(&db, &cfg, true).await.unwrap();

    assert_eq!(db.count_users().await.unwrap(), 1);
    let seeded = db.get_user_by_username("admin").await.unwrap().unwrap();
    assert_eq!(seeded.role, "admin");
    assert!(seeded.active);
}

/// A config with NO env admin password, so bootstrap uses the loopback default.
fn config_without_admin_password() -> AuthConfig {
    AuthConfig {
        jwt_secret: JWT_SECRET.to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: String::new(),
        enabled: true,
    }
}

#[tokio::test]
async fn loopback_bootstrap_seeds_seance_default_requiring_change() {
    let db = fresh_db().await;
    let cfg = config_without_admin_password();
    seance_api::bootstrap_admin(&db, &cfg, true).await.unwrap();

    let admin = db.get_user_by_username("admin").await.unwrap().unwrap();
    assert!(
        admin.must_change_password,
        "a default-seeded admin must be flagged to change its password"
    );

    let app = router_with_auth(build_state(db), Some(cfg));
    let resp = app.oneshot(login_request("admin", "seance")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the default password must log in"
    );
    let body = body_json(resp).await;
    assert_eq!(
        body["must_change_password"].as_bool(),
        Some(true),
        "login with the default must signal a required change"
    );
}

#[tokio::test]
async fn must_change_token_is_confined_to_password_change() {
    let db = fresh_db().await;
    let cfg = config_without_admin_password();
    seance_api::bootstrap_admin(&db, &cfg, true).await.unwrap();
    let admin_id = db.get_user_by_username("admin").await.unwrap().unwrap().id;
    let app = router_with_auth(build_state(db.clone()), Some(cfg));

    // Log in with the default → a must-change token.
    let login = app
        .clone()
        .oneshot(login_request("admin", "seance"))
        .await
        .unwrap();
    let token = body_json(login).await["token"]
        .as_str()
        .unwrap()
        .to_string();

    // Any case route is blocked until the password is rotated.
    let blocked = app
        .clone()
        .oneshot(authed_get("/api/v1/cases", &token))
        .await
        .unwrap();
    assert_eq!(
        blocked.status(),
        StatusCode::FORBIDDEN,
        "a must-change token must not reach case data"
    );

    // The change-password endpoint IS reachable with the same token.
    let changed = app
        .clone()
        .oneshot(authed_post(
            &format!("/api/v1/users/{}/password", admin_id),
            &token,
            json!({ "password": "a-strong-new-password" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        changed.status(),
        StatusCode::OK,
        "a must-change token may change its own password"
    );

    // After rotating, a fresh login clears the flag and has full access.
    let relogin = app
        .clone()
        .oneshot(login_request("admin", "a-strong-new-password"))
        .await
        .unwrap();
    let body = body_json(relogin).await;
    assert_eq!(body["must_change_password"].as_bool(), Some(false));
    let new_token = body["token"].as_str().unwrap().to_string();
    let allowed = app
        .oneshot(authed_get("/api/v1/cases", &new_token))
        .await
        .unwrap();
    assert_ne!(
        allowed.status(),
        StatusCode::FORBIDDEN,
        "the rotated credential must have full access"
    );
}

// ============================================================
//  Per-user audit attribution
// ============================================================

#[tokio::test]
async fn audit_events_record_the_actual_logged_in_username() {
    let db = fresh_db().await;
    db.create_user(
        "alice",
        &seance_api::hash_password("pw").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let (app, cfg) = build_app(db.clone());

    // Mint a token for a real examiner identity and create a case as them.
    let (token, _) = cfg.generate_token("alice", "examiner").unwrap();
    let resp = app
        .oneshot(authed_post(
            "/api/v1/cases",
            &token,
            json!({ "name": "Alice Case", "examiner_name": "Alice" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let case_id: Uuid = body_json(resp).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // The audit trail must attribute the action to alice, not a hardcoded user.
    let events = db.get_audit_log(case_id, 50, 0).await.unwrap();
    assert!(
        events.iter().any(|e| e["user_id"].as_str() == Some("alice")
            && e["action"].as_str() == Some("case_created")),
        "expected a case_created audit event attributed to 'alice'; got {:?}",
        events
    );
}
