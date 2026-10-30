//! Integration tests for per-case access control (multi-user v1.0).
//!
//! Covers, with auth ENABLED: examiner denied a case they hold no grant on,
//! admin bypass, creator auto-owner grant, case-list filtering, the
//! grant/list/revoke endpoints (owner-or-admin authorization), and the
//! admin-only role-change / user-delete endpoints.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

const JWT_SECRET: &str = "case-access-test-secret";
const CSRF_TOKEN: &str = "case-access-csrf";

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

fn build_app(db: Arc<SqliteConnection>) -> (axum::Router, AuthConfig) {
    let cfg = make_config();
    let app = router_with_auth(build_state(db), Some(cfg.clone()));
    (app, cfg)
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn authed_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
}

/// Authenticated request carrying an optional JSON body plus the CSRF
/// double-submit pair (required for unsafe methods).
fn authed(method: &str, uri: &str, token: &str, body: Option<Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .header("x-csrf-token", CSRF_TOKEN)
        .header("cookie", format!("seance_csrf={}", CSRF_TOKEN));
    match body {
        Some(v) => builder
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// Create a case directly in the DB and return its id (no owner grant), so we
/// can test the "examiner has no grant" path deterministically.
async fn seed_case(db: &SqliteConnection) -> Uuid {
    db.create_case_with_metadata(Some("Seed".to_string()), None, Some("Ex".to_string()))
        .await
        .unwrap()
}

/// Seed a plain artifact directly into a case; returns its id.
async fn seed_artifact(db: &SqliteConnection, case_id: Uuid, name: &str) -> Uuid {
    let art = Artifact::new(
        case_id,
        ArtifactType::Container,
        None,
        json!({ "name": name }),
    );
    let id = art.id;
    db.record_artifact(&art).await.unwrap();
    id
}

/// Seed a timeline-event artifact into a case; returns its (event) id.
async fn seed_timeline_event(db: &SqliteConnection, case_id: Uuid) -> Uuid {
    let art = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": 1234567890i64,
            "timestamp_desc": "Created",
            "source_module": "test.module",
            "short_desc": "secret event",
            "full_details": "{}",
        }),
    );
    let id = art.id;
    db.record_artifact(&art).await.unwrap();
    id
}

// ============================================================
//  Cross-case IDOR: bookmark / timeline-tag creation must gate the
//  caller-supplied sub-resource id against the path case.
// ============================================================

#[tokio::test]
async fn bookmark_rejects_cross_case_artifact_and_allows_own() {
    let db = fresh_db().await;
    let uid = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let case_a = seed_case(&db).await;
    db.grant_case_access(case_a, uid, "read_write", None)
        .await
        .unwrap();
    // A case erin holds NO grant on, containing a secret artifact.
    let case_b = seed_case(&db).await;
    let foreign = seed_artifact(&db, case_b, "case-b-secret.e01").await;
    let own = seed_artifact(&db, case_a, "case-a.e01").await;

    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    // Cross-case artifact id: must be rejected so its name/type never gets
    // stored under case A nor surfaced through the bookmark list.
    let leak = app
        .clone()
        .oneshot(authed(
            "POST",
            &format!("/api/v1/cases/{}/bookmarks", case_a),
            &token,
            Some(json!({ "artifact_id": foreign })),
        ))
        .await
        .unwrap();
    assert_eq!(
        leak.status(),
        StatusCode::NOT_FOUND,
        "bookmarking a foreign case's artifact must 404, not leak its metadata"
    );

    // Control: an artifact that IS in case A remains bookmarkable.
    let ok = app
        .oneshot(authed(
            "POST",
            &format!("/api/v1/cases/{}/bookmarks", case_a),
            &token,
            Some(json!({ "artifact_id": own })),
        ))
        .await
        .unwrap();
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "an in-case artifact must still be bookmarkable"
    );
}

#[tokio::test]
async fn timeline_tag_rejects_cross_case_event() {
    let db = fresh_db().await;
    let uid = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let case_a = seed_case(&db).await;
    db.grant_case_access(case_a, uid, "read_write", None)
        .await
        .unwrap();
    let case_b = seed_case(&db).await;
    let foreign_event = seed_timeline_event(&db, case_b).await;

    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let leak = app
        .oneshot(authed(
            "POST",
            &format!("/api/v1/cases/{}/timeline/tags/{}", case_a, foreign_event),
            &token,
            Some(json!({ "event_id": foreign_event, "note": "x" })),
        ))
        .await
        .unwrap();
    assert_eq!(
        leak.status(),
        StatusCode::NOT_FOUND,
        "tagging a foreign case's timeline event must 404"
    );
}

// ============================================================
//  Enforcement on get_case
// ============================================================

#[tokio::test]
async fn examiner_without_grant_is_denied_case() {
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let case = seed_case(&db).await;
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let resp = app
        .oneshot(authed_get(&format!("/api/v1/cases/{}", case), &token))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "an examiner with no grant must not read the case"
    );
}

#[tokio::test]
async fn middleware_guards_non_self_guarded_case_routes() {
    // The audit_log handler does NOT itself call require_case_access; the
    // router-level case_access_middleware must still deny an ungranted examiner.
    // This is the guarantee that closes the ~100-handler enforcement gap.
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let case = seed_case(&db).await;
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let resp = app
        .oneshot(authed_get(
            &format!("/api/v1/cases/{}/audit_log", case),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "middleware must guard case data routes even when the handler does not self-guard"
    );
}

#[tokio::test]
async fn middleware_allows_granted_examiner_on_case_routes() {
    let db = fresh_db().await;
    let uid = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let case = seed_case(&db).await;
    db.grant_case_access(case, uid, "read_write", None)
        .await
        .unwrap();
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let resp = app
        .oneshot(authed_get(
            &format!("/api/v1/cases/{}/audit_log", case),
            &token,
        ))
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a granted examiner must pass the access middleware"
    );
}

#[tokio::test]
async fn read_only_grantee_can_read_but_not_mutate() {
    let db = fresh_db().await;
    let uid = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let case = seed_case(&db).await;
    db.grant_case_access(case, uid, "read_only", None)
        .await
        .unwrap();
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    // A safe GET is permitted by the read_only grant.
    let read = app
        .clone()
        .oneshot(authed_get(
            &format!("/api/v1/cases/{}/filters", case),
            &token,
        ))
        .await
        .unwrap();
    assert_ne!(
        read.status(),
        StatusCode::FORBIDDEN,
        "read_only may read case data"
    );

    // An unsafe POST is denied for a read_only grantee (middleware, before the
    // handler even sees the body).
    let write = app
        .oneshot(authed(
            "POST",
            &format!("/api/v1/cases/{}/filters", case),
            &token,
            Some(serde_json::json!({ "name": "x" })),
        ))
        .await
        .unwrap();
    assert_eq!(
        write.status(),
        StatusCode::FORBIDDEN,
        "read_only cannot mutate case data"
    );
}

#[tokio::test]
async fn read_write_grantee_may_mutate() {
    let db = fresh_db().await;
    let uid = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let case = seed_case(&db).await;
    db.grant_case_access(case, uid, "read_write", None)
        .await
        .unwrap();
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    // The access middleware must let a read_write grantee through to the handler
    // (the handler may still reject a bad body, but not with 403).
    let write = app
        .oneshot(authed(
            "POST",
            &format!("/api/v1/cases/{}/filters", case),
            &token,
            Some(serde_json::json!({ "name": "x" })),
        ))
        .await
        .unwrap();
    assert_ne!(
        write.status(),
        StatusCode::FORBIDDEN,
        "read_write grantee may mutate"
    );
}

#[tokio::test]
async fn cannot_delete_or_demote_last_admin() {
    let db = fresh_db().await;
    let admin_id = db
        .create_user(
            "root",
            &seance_api::hash_password("rootpw12345").unwrap(),
            "admin",
        )
        .await
        .unwrap();
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("root", "admin").unwrap();

    // Deleting the only admin is refused.
    let del = app
        .clone()
        .oneshot(authed(
            "DELETE",
            &format!("/api/v1/users/{}", admin_id),
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(
        del.status(),
        StatusCode::BAD_REQUEST,
        "last admin cannot be deleted"
    );

    // Demoting the only admin is refused.
    let demote = app
        .oneshot(authed(
            "PUT",
            &format!("/api/v1/users/{}/role", admin_id),
            &token,
            Some(serde_json::json!({ "role": "examiner" })),
        ))
        .await
        .unwrap();
    assert_eq!(
        demote.status(),
        StatusCode::BAD_REQUEST,
        "last admin cannot be demoted"
    );
}

#[tokio::test]
async fn admin_can_read_any_case() {
    let db = fresh_db().await;
    db.create_user(
        "root",
        &seance_api::hash_password("rootpw12345").unwrap(),
        "admin",
    )
    .await
    .unwrap();
    let case = seed_case(&db).await;
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("root", "admin").unwrap();

    let resp = app
        .oneshot(authed_get(&format!("/api/v1/cases/{}", case), &token))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "admins bypass per-case access"
    );
}

#[tokio::test]
async fn creating_a_case_grants_creator_owner() {
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    // Create as erin.
    let created = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/v1/cases",
            &token,
            Some(json!({ "name": "Erin Case" })),
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let case_id: Uuid = body_json(created).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // Erin was auto-granted owner, so she can read it back.
    let get = app
        .clone()
        .oneshot(authed_get(&format!("/api/v1/cases/{}", case_id), &token))
        .await
        .unwrap();
    assert_eq!(
        get.status(),
        StatusCode::OK,
        "creator must retain access to their case"
    );

    // ...and it shows up in her filtered case list.
    let list = app
        .oneshot(authed_get("/api/v1/cases", &token))
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let listed = body_json(list).await;
    let ids: Vec<String> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&case_id.to_string()));
}

#[tokio::test]
async fn case_list_is_filtered_for_examiners() {
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    // Two cases exist that erin has NO grant on.
    seed_case(&db).await;
    seed_case(&db).await;
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let list = app
        .oneshot(authed_get("/api/v1/cases", &token))
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let cases = body_json(list).await;
    assert_eq!(
        cases.as_array().unwrap().len(),
        0,
        "an examiner sees only cases they are granted access to"
    );
}

// ============================================================
//  Grant / list / revoke endpoints
// ============================================================

#[tokio::test]
async fn owner_can_grant_and_revoke_access() {
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let dana = db
        .create_user(
            "dana",
            &seance_api::hash_password("examinerpw2").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let (app, cfg) = build_app(db);
    let (erin_token, _) = cfg.generate_token("erin", "examiner").unwrap();
    let (dana_token, _) = cfg.generate_token("dana", "examiner").unwrap();

    // Erin creates a case (becomes owner).
    let created = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/v1/cases",
            &erin_token,
            Some(json!({ "name": "Shared" })),
        ))
        .await
        .unwrap();
    let case_id: Uuid = body_json(created).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // Dana cannot read it yet.
    let denied = app
        .clone()
        .oneshot(authed_get(
            &format!("/api/v1/cases/{}", case_id),
            &dana_token,
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    // Erin (owner) grants dana read_write.
    let grant = app
        .clone()
        .oneshot(authed(
            "POST",
            &format!("/api/v1/cases/{}/access", case_id),
            &erin_token,
            Some(json!({ "user_id": dana, "access_level": "read_write" })),
        ))
        .await
        .unwrap();
    assert_eq!(grant.status(), StatusCode::OK);

    // Now dana can read the case.
    let allowed = app
        .clone()
        .oneshot(authed_get(
            &format!("/api/v1/cases/{}", case_id),
            &dana_token,
        ))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);

    // The access list shows both erin (owner) and dana (read_write).
    let list = app
        .clone()
        .oneshot(authed_get(
            &format!("/api/v1/cases/{}/access", case_id),
            &erin_token,
        ))
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let grants = body_json(list).await;
    assert_eq!(grants.as_array().unwrap().len(), 2);

    // Erin revokes dana.
    let revoke = app
        .clone()
        .oneshot(authed(
            "DELETE",
            &format!("/api/v1/cases/{}/access/{}", case_id, dana),
            &erin_token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::NO_CONTENT);

    // Dana is denied again.
    let denied_again = app
        .oneshot(authed_get(
            &format!("/api/v1/cases/{}", case_id),
            &dana_token,
        ))
        .await
        .unwrap();
    assert_eq!(denied_again.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn non_owner_examiner_cannot_grant_access() {
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let dana = db
        .create_user(
            "dana",
            &seance_api::hash_password("examinerpw2").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let (app, cfg) = build_app(db);
    let (erin_token, _) = cfg.generate_token("erin", "examiner").unwrap();
    let (dana_token, _) = cfg.generate_token("dana", "examiner").unwrap();

    // Erin creates and owns a case; dana gets read_write (not owner).
    let created = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/v1/cases",
            &erin_token,
            Some(json!({ "name": "Shared" })),
        ))
        .await
        .unwrap();
    let case_id: Uuid = body_json(created).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let _ = app
        .clone()
        .oneshot(authed(
            "POST",
            &format!("/api/v1/cases/{}/access", case_id),
            &erin_token,
            Some(json!({ "user_id": dana, "access_level": "read_write" })),
        ))
        .await
        .unwrap();

    // dana holds read_write but NOT owner: she may not grant to others.
    let grant = app
        .oneshot(authed(
            "POST",
            &format!("/api/v1/cases/{}/access", case_id),
            &dana_token,
            Some(json!({ "user_id": dana, "access_level": "owner" })),
        ))
        .await
        .unwrap();
    assert_eq!(
        grant.status(),
        StatusCode::FORBIDDEN,
        "only owners or admins may manage case access"
    );
}

// ============================================================
//  User role-change / delete endpoints (admin only)
// ============================================================

#[tokio::test]
async fn admin_can_change_role_and_delete_user() {
    let db = fresh_db().await;
    db.create_user(
        "root",
        &seance_api::hash_password("rootpw12345").unwrap(),
        "admin",
    )
    .await
    .unwrap();
    let dave = db
        .create_user(
            "dave",
            &seance_api::hash_password("davepw12345").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let (app, cfg) = build_app(db.clone());
    let (admin_token, _) = cfg.generate_token("root", "admin").unwrap();

    // Promote dave to admin.
    let promote = app
        .clone()
        .oneshot(authed(
            "PUT",
            &format!("/api/v1/users/{}/role", dave),
            &admin_token,
            Some(json!({ "role": "admin" })),
        ))
        .await
        .unwrap();
    assert_eq!(promote.status(), StatusCode::OK);
    assert_eq!(body_json(promote).await["role"].as_str().unwrap(), "admin");

    // Delete dave.
    let delete = app
        .oneshot(authed(
            "DELETE",
            &format!("/api/v1/users/{}", dave),
            &admin_token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    assert!(db.get_user_by_id(dave).await.unwrap().is_none());
}

#[tokio::test]
async fn examiner_cannot_change_role_or_delete_user() {
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let dave = db
        .create_user(
            "dave",
            &seance_api::hash_password("davepw12345").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let (app, cfg) = build_app(db);
    let (erin_token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let role = app
        .clone()
        .oneshot(authed(
            "PUT",
            &format!("/api/v1/users/{}/role", dave),
            &erin_token,
            Some(json!({ "role": "admin" })),
        ))
        .await
        .unwrap();
    assert_eq!(role.status(), StatusCode::FORBIDDEN);

    let del = app
        .oneshot(authed(
            "DELETE",
            &format!("/api/v1/users/{}", dave),
            &erin_token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::FORBIDDEN);
}

// ============================================================
//  Default case scoping
// ============================================================

#[tokio::test]
async fn default_case_returns_callers_accessible_case() {
    // Erin owns `mine`; an unrelated case `other` also exists (created by
    // someone else, no grant to erin). default_case must return the case from
    // her accessible set — never the inaccessible one, regardless of which is
    // more recent in the global list.
    let db = fresh_db().await;
    let uid = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let mine = seed_case(&db).await;
    db.grant_case_access(mine, uid, "owner", None)
        .await
        .unwrap();
    let other = seed_case(&db).await;
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let resp = app
        .oneshot(authed_get("/api/v1/cases/default_case", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let case = body_json(resp).await;
    let id: Uuid = case["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(id, mine, "default_case must return the caller's case");
    assert_ne!(id, other, "default_case must not leak an inaccessible case");
}

#[tokio::test]
async fn default_case_creates_and_grants_ownership_when_none_accessible() {
    // Only an inaccessible case exists: default_case must NOT hand it out.
    // It creates a fresh default case and grants the caller owner access
    // (mirroring create_case), so the caller can read it back and a repeat
    // call returns the same case instead of creating another.
    let db = fresh_db().await;
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let other = seed_case(&db).await;
    let (app, cfg) = build_app(db);
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let resp = app
        .clone()
        .oneshot(authed_get("/api/v1/cases/default_case", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let case = body_json(resp).await;
    let id: Uuid = case["id"].as_str().unwrap().parse().unwrap();
    assert_ne!(
        id, other,
        "default_case must not return a case the caller cannot access"
    );
    assert_eq!(case["name"].as_str().unwrap(), "Default Case");

    // The owner grant: erin can read the new case directly (the access
    // middleware would 403 her otherwise).
    let get = app
        .clone()
        .oneshot(authed_get(&format!("/api/v1/cases/{}", id), &token))
        .await
        .unwrap();
    assert_eq!(
        get.status(),
        StatusCode::OK,
        "creator must own the freshly created default case"
    );

    // A second call finds the now-accessible case and returns it unchanged.
    let again = app
        .oneshot(authed_get("/api/v1/cases/default_case", &token))
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::OK);
    let second = body_json(again).await;
    assert_eq!(second["id"].as_str().unwrap(), id.to_string());
}
