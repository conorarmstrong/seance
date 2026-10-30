use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

/// Helper to setup test app with in-memory database
async fn setup_test_app() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();

    let case_id = db
        .create_case("Schema Test Case", "Test Examiner")
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

/// Helper to create a test artifact with timeline event
async fn create_test_event(db: &Arc<SqliteConnection>, case_id: Uuid, full_details: &str) -> Uuid {
    use seance_core::artifact::{Artifact, ArtifactType};

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
async fn test_get_schema_empty_case() {
    let (app, case_id) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/timeline/schema", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let schema: seance_core::models::TimelineSchema = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(schema.available_fields.len(), 0);
}

#[tokio::test]
async fn test_get_schema_with_events() {
    let (_app, _case_id) = setup_test_app().await;

    // Get DB from app to create test data
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Schema Test", "Examiner").await.unwrap();

    // Create events with different JSON schemas
    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test.txt", "file_size": 1024}"#,
    )
    .await;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test2.txt", "file_size": 2048, "is_hidden": true}"#,
    )
    .await;

    create_test_event(
        &db,
        case_id,
        r#"{"filename": "test3.txt", "permissions": "rwxr-xr-x"}"#,
    )
    .await;

    // Recreate app with populated DB
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

    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: "".to_string(),
        enabled: false,
    };
    let app = router_with_auth(app_state, Some(auth_config));

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/timeline/schema", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let schema: seance_core::models::TimelineSchema = serde_json::from_slice(&body_bytes).unwrap();

    // Should have discovered all unique fields
    assert!(schema.available_fields.len() >= 4); // filename, file_size, is_hidden, permissions

    // Verify filename field (should appear in all 3 events)
    let filename_field = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.filename")
        .expect("filename field should exist");
    assert_eq!(filename_field.field_type, "string");
    assert_eq!(filename_field.frequency, 3);

    // Verify file_size field (appears in 2 events)
    let file_size_field = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.file_size")
        .expect("file_size field should exist");
    assert_eq!(file_size_field.field_type, "number");
    assert_eq!(file_size_field.frequency, 2);

    // Verify is_hidden field (appears in 1 event)
    let is_hidden_field = schema
        .available_fields
        .iter()
        .find(|f| f.path == "$.is_hidden")
        .expect("is_hidden field should exist");
    assert_eq!(is_hidden_field.field_type, "boolean");
    assert_eq!(is_hidden_field.frequency, 1);
}

#[tokio::test]
async fn test_get_schema_sorted_by_frequency() {
    let (_app, _case_id) = setup_test_app().await;

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Schema Test", "Examiner").await.unwrap();

    // Create events where some fields appear more frequently than others
    for i in 0..5 {
        create_test_event(
            &db,
            case_id,
            &format!(r#"{{"common_field": "value{}", "rare_field": "rare"}}"#, i),
        )
        .await;
    }

    create_test_event(&db, case_id, r#"{"common_field": "value6"}"#).await;
    create_test_event(&db, case_id, r#"{"common_field": "value7"}"#).await;

    // Recreate app with populated DB
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

    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: "".to_string(),
        enabled: false,
    };
    let app = router_with_auth(app_state, Some(auth_config));

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/timeline/schema", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let schema: seance_core::models::TimelineSchema = serde_json::from_slice(&body_bytes).unwrap();

    // common_field should be first (appears 7 times)
    assert_eq!(schema.available_fields[0].path, "$.common_field");
    assert_eq!(schema.available_fields[0].frequency, 7);

    // rare_field should be second (appears 5 times)
    assert_eq!(schema.available_fields[1].path, "$.rare_field");
    assert_eq!(schema.available_fields[1].frequency, 5);
}

#[tokio::test]
async fn test_invalid_case_id_returns_bad_request() {
    let (app, _case_id) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/cases/invalid-uuid/timeline/schema")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
