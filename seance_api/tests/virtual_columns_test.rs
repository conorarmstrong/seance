use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;

async fn setup_test_app() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();

    let case_id = db
        .create_case("Virtual Columns Test", "Test Examiner")
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
    (app, case_id)
}

#[tokio::test]
async fn test_get_default_virtual_columns() {
    let (app, case_id) = setup_test_app().await;

    let request = Request::builder()
        .uri(format!("/api/v1/cases/{}/virtual_columns", case_id))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    let virtual_columns = json["virtual_columns"].as_array().unwrap();
    assert!(
        virtual_columns.len() >= 5,
        "Should have at least 5 default virtual columns"
    );

    // Verify Resource Path column exists
    let resource_path = virtual_columns
        .iter()
        .find(|vc| vc["id"] == "vc_resource_path")
        .expect("Resource Path virtual column should exist");

    assert_eq!(resource_path["name"], "Resource Path");
    assert_eq!(resource_path["built_in"], true);
    assert!(!resource_path["sources"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_create_custom_virtual_column() {
    let (app, case_id) = setup_test_app().await;

    let new_column = json!({
        "id": "vc_custom_test",
        "name": "Test Column",
        "description": "A test virtual column",
        "type": "string",
        "sources": [
            {
                "path": "$.test_field",
                "artifact_types": []
            }
        ],
        "default_visible": false,
        "built_in": false
    });

    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/cases/{}/virtual_columns", case_id))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&new_column).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(json["id"], "vc_custom_test");
    assert_eq!(json["name"], "Test Column");
    assert_eq!(json["built_in"], false);
}

#[tokio::test]
async fn test_create_virtual_column_validation() {
    let (app, case_id) = setup_test_app().await;

    // Test: Empty name
    let invalid_column = json!({
        "id": "vc_test",
        "name": "",
        "description": "Test",
        "type": "string",
        "sources": [{"path": "$.test", "artifact_types": []}],
        "default_visible": false,
        "built_in": false
    });

    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/cases/{}/virtual_columns", case_id))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&invalid_column).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_virtual_column_no_sources() {
    let (app, case_id) = setup_test_app().await;

    // Test: No sources
    let invalid_column = json!({
        "id": "vc_test",
        "name": "Test",
        "description": "Test",
        "type": "string",
        "sources": [],
        "default_visible": false,
        "built_in": false
    });

    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/cases/{}/virtual_columns", case_id))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&invalid_column).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_virtual_column_invalid_json_path() {
    let (app, case_id) = setup_test_app().await;

    // Test: Invalid JSON path (doesn't start with $)
    let invalid_column = json!({
        "id": "vc_test",
        "name": "Test",
        "description": "Test",
        "type": "string",
        "sources": [{"path": "invalid_path", "artifact_types": []}],
        "default_visible": false,
        "built_in": false
    });

    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/cases/{}/virtual_columns", case_id))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&invalid_column).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_cannot_create_builtin_virtual_column() {
    let (app, case_id) = setup_test_app().await;

    // Test: Cannot create built-in columns
    let builtin_column = json!({
        "id": "vc_test",
        "name": "Test",
        "description": "Test",
        "type": "string",
        "sources": [{"path": "$.test", "artifact_types": []}],
        "default_visible": false,
        "built_in": true
    });

    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/cases/{}/virtual_columns", case_id))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&builtin_column).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_virtual_column() {
    let (app, case_id) = setup_test_app().await;

    // First create a custom column
    let new_column = json!({
        "id": "vc_custom_update_test",
        "name": "Original Name",
        "description": "Original description",
        "type": "string",
        "sources": [{"path": "$.test", "artifact_types": []}],
        "default_visible": false,
        "built_in": false
    });

    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/cases/{}/virtual_columns", case_id))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&new_column).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now update it
    let updated_column = json!({
        "id": "vc_custom_update_test",
        "name": "Updated Name",
        "description": "Updated description",
        "type": "string",
        "sources": [{"path": "$.test", "artifact_types": []}],
        "default_visible": true,
        "built_in": false
    });

    let request = Request::builder()
        .method("PUT")
        .uri(format!(
            "/api/v1/cases/{}/virtual_columns/vc_custom_update_test",
            case_id
        ))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&updated_column).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(json["name"], "Updated Name");
    assert_eq!(json["description"], "Updated description");
    assert_eq!(json["default_visible"], true);
}

#[tokio::test]
async fn test_cannot_update_builtin_virtual_column() {
    let (app, case_id) = setup_test_app().await;

    // Try to update a built-in column
    let updated_column = json!({
        "id": "vc_resource_path",
        "name": "Modified Resource Path",
        "description": "Modified",
        "type": "string",
        "sources": [{"path": "$.test", "artifact_types": []}],
        "default_visible": true,
        "built_in": true
    });

    let request = Request::builder()
        .method("PUT")
        .uri(format!(
            "/api/v1/cases/{}/virtual_columns/vc_resource_path",
            case_id
        ))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&updated_column).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_delete_custom_virtual_column() {
    let (app, case_id) = setup_test_app().await;

    // First create a custom column
    let new_column = json!({
        "id": "vc_custom_delete_test",
        "name": "To Be Deleted",
        "description": "This will be deleted",
        "type": "string",
        "sources": [{"path": "$.test", "artifact_types": []}],
        "default_visible": false,
        "built_in": false
    });

    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/cases/{}/virtual_columns", case_id))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&new_column).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now delete it
    let request = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/api/v1/cases/{}/virtual_columns/vc_custom_delete_test",
            case_id
        ))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_cannot_delete_builtin_virtual_column() {
    let (app, case_id) = setup_test_app().await;

    // Try to delete a built-in column
    let request = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/api/v1/cases/{}/virtual_columns/vc_resource_path",
            case_id
        ))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
