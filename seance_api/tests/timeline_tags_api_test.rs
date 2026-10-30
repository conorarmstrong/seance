use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    models::CreateTagRequest,
    models::UpdateTagRequest,
};
use seance_db::SqliteConnection;
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

/// Helper to setup test app with in-memory database
async fn setup_test_app() -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();

    let case_id = db
        .create_case("API Test Case", "Test Examiner")
        .await
        .unwrap();

    // Create test orchestrator components (minimal for API testing)
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, _ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let app_state = AppState {
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
    };

    // Use auth-disabled config for tests
    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: "".to_string(),
        enabled: false,
    };
    let app = router_with_auth(app_state, Some(auth_config));
    (app, case_id, db)
}

/// Records a timeline event as an artifact whose id equals `event_id`. The tag
/// handlers scope a tag to an existing event (stored as an artifact with the
/// same id), so a tag target must exist before it can be created.
async fn record_event(db: &SqliteConnection, case_id: Uuid, event_id: Uuid) {
    let mut event = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        serde_json::json!({
            "timestamp": 1_700_000_000,
            "timestamp_desc": "Test Event",
            "source_module": "test",
            "short_desc": "tag target",
            "full_details": "{}",
        }),
    );
    event.id = event_id;
    db.record_artifact(&event).await.unwrap();
}

#[tokio::test]
async fn test_create_tag_api() {
    let (app, case_id, db) = setup_test_app().await;
    let event_id = Uuid::new_v4();
    record_event(&db, case_id, event_id).await;

    let payload = CreateTagRequest {
        event_id,
        note: Some("Test note from API".to_string()),
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{}/timeline/tags/{}",
                    case_id, event_id
                ))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_delete_tag_api() {
    let (app, case_id, db) = setup_test_app().await;

    // First create a tag
    let event_id = Uuid::new_v4();
    record_event(&db, case_id, event_id).await;
    let create_payload = CreateTagRequest {
        event_id,
        note: None,
    };

    let _create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{}/timeline/tags/{}",
                    case_id, event_id
                ))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&create_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Then delete it
    let delete_response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/cases/{}/timeline/tags/{}",
                    case_id, event_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(delete_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_update_tag_note_api() {
    let (app, case_id, db) = setup_test_app().await;

    // Create a tag first
    let event_id = Uuid::new_v4();
    record_event(&db, case_id, event_id).await;
    let create_payload = CreateTagRequest {
        event_id,
        note: Some("Original note".to_string()),
    };

    let _create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{}/timeline/tags/{}",
                    case_id, event_id
                ))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&create_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Update the note
    let update_payload = UpdateTagRequest {
        note: "Updated note from API".to_string(),
    };

    let update_response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/api/v1/cases/{}/timeline/tags/{}",
                    case_id, event_id
                ))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(update_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_tags_api() {
    let (app, case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/timeline/tags", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_delete_nonexistent_tag() {
    let (app, case_id, _db) = setup_test_app().await;
    let event_id = Uuid::new_v4(); // Tag doesn't exist

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/cases/{}/timeline/tags/{}",
                    case_id, event_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_invalid_uuid_returns_bad_request() {
    let (app, _case_id, _db) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/cases/invalid-uuid/timeline/tags")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
