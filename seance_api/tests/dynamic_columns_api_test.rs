use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

/// Helper to setup test app with in-memory database
async fn setup_test_app() -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();

    let case_id = db
        .create_case("Dynamic Columns Test", "Test Examiner")
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

/// Helper to create a test artifact with timeline event
async fn create_test_event(db: &Arc<SqliteConnection>, case_id: Uuid, full_details: &str) -> Uuid {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::TimelineEvent,
        metadata: serde_json::json!({
            "timestamp": 1234567890i64,
            "timestamp_desc": "Test Event",
            "source_module": "TestModule",
            "short_desc": "Test description",
            "full_details": full_details,
        }),
        data: None,
    };

    let event_id = artifact.id;
    db.record_artifact(&artifact).await.unwrap();
    event_id
}

#[tokio::test]
async fn test_dynamic_columns_query_parameter() {
    let (app, case_id, db) = setup_test_app().await;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/cases/{}/timeline?columns=$.filename,$.file_size",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Check that events array exists
    let events = response_json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);

    // Check that dynamic_fields exists and has the requested fields
    let dynamic_fields = events[0]["dynamic_fields"].as_object().unwrap();
    assert_eq!(
        dynamic_fields.get("filename").unwrap().as_str().unwrap(),
        "test.txt"
    );
    assert_eq!(
        dynamic_fields.get("file_size").unwrap().as_i64().unwrap(),
        1024
    );
}

#[tokio::test]
async fn test_no_dynamic_columns_parameter() {
    let (app, case_id, db) = setup_test_app().await;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/timeline", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let events = response_json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);

    // Without columns parameter, dynamic_fields should not be present
    assert!(events[0].get("dynamic_fields").is_none());
}

#[tokio::test]
async fn test_dynamic_columns_with_single_field() {
    let (app, case_id, db) = setup_test_app().await;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/cases/{}/timeline?columns=$.filename",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let events = response_json["events"].as_array().unwrap();
    let dynamic_fields = events[0]["dynamic_fields"].as_object().unwrap();

    // Should only have the requested field
    assert_eq!(dynamic_fields.len(), 1);
    assert!(dynamic_fields.contains_key("filename"));
    assert!(!dynamic_fields.contains_key("file_size"));
}

#[tokio::test]
async fn test_dynamic_columns_with_whitespace() {
    let (app, case_id, db) = setup_test_app().await;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await;

    // Test with whitespace in query parameter (URL encoded)
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/cases/{}/timeline?columns=$.filename,%20$.file_size",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let events = response_json["events"].as_array().unwrap();
    let dynamic_fields = events[0]["dynamic_fields"].as_object().unwrap();

    // Whitespace should be trimmed
    assert_eq!(dynamic_fields.len(), 2);
    assert!(dynamic_fields.contains_key("filename"));
    assert!(dynamic_fields.contains_key("file_size"));
}

#[tokio::test]
async fn test_dynamic_columns_with_filters() {
    let (app, case_id, db) = setup_test_app().await;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await;
    create_test_event(
        &db,
        case_id,
        r#"{"filename": "other.txt", "file_size": 2048}"#,
    )
    .await;

    // Combine dynamic columns with filename filter
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/cases/{}/timeline?columns=$.filename,$.file_size&filter_filename=test",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let events = response_json["events"].as_array().unwrap();
    // Should only get the filtered event
    assert_eq!(events.len(), 1);

    let dynamic_fields = events[0]["dynamic_fields"].as_object().unwrap();
    assert_eq!(
        dynamic_fields.get("filename").unwrap().as_str().unwrap(),
        "test.txt"
    );
}

#[tokio::test]
async fn test_dynamic_columns_multiple_events() {
    let (app, case_id, db) = setup_test_app().await;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "file1.txt", "file_size": 100}"#,
    )
    .await;
    create_test_event(
        &db,
        case_id,
        r#"{"filename": "file2.txt", "file_size": 200}"#,
    )
    .await;
    create_test_event(&db, case_id, r#"{"filename": "file3.txt"}"#).await; // Missing file_size

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/cases/{}/timeline?columns=$.filename,$.file_size",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let events = response_json["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);

    // Events share a timestamp, so their order is id-dependent; match by
    // filename instead of position.
    let by_filename = |name: &str| {
        events
            .iter()
            .map(|e| e["dynamic_fields"].as_object().unwrap())
            .find(|f| f["filename"] == name)
            .unwrap_or_else(|| panic!("no event with filename {name}"))
    };

    assert_eq!(by_filename("file1.txt").len(), 2);
    assert_eq!(by_filename("file2.txt").len(), 2);

    // file3 is missing file_size, so only filename is present
    let dynamic3 = by_filename("file3.txt");
    assert_eq!(dynamic3.len(), 1);
}

#[tokio::test]
async fn test_dynamic_columns_missing_field() {
    let (app, case_id, db) = setup_test_app().await;

    create_test_event(&db, case_id, r#"{"filename": "test.txt"}"#).await;

    // Request a field that doesn't exist
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/cases/{}/timeline?columns=$.filename,$.nonexistent",
                    case_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let events = response_json["events"].as_array().unwrap();
    let dynamic_fields = events[0]["dynamic_fields"].as_object().unwrap();

    // Should only have the field that exists
    assert_eq!(dynamic_fields.len(), 1);
    assert!(dynamic_fields.contains_key("filename"));
    assert!(!dynamic_fields.contains_key("nonexistent"));
}
