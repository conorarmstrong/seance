use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig, CreateProfileRequest};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use tower::{Service, ServiceExt};
use uuid::Uuid;

/// Helper to setup test app with in-memory database
async fn setup_test_app() -> (axum::Router, Arc<SqliteConnection>, Uuid) {
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
    (app, db, case_id)
}

async fn create_test_artifact(db: &SqliteConnection, case_id: Uuid) -> Uuid {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::FileEntry,
        data: None,
        metadata: json!({"name": "test_file"}),
    };
    db.record_artifact(&artifact).await.unwrap();
    artifact.id
}

// === Profile API Tests ===

#[tokio::test]
async fn test_create_profile_api() {
    let (app, _db, case_id) = setup_test_app().await;

    let payload = CreateProfileRequest {
        name: "Test Profile".to_string(),
        description: "Test description".to_string(),
        enabled_modules: vec!["plugin.ntfs.mft_parser".to_string()],
        disabled_modules: vec![],
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/profiles", case_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_profiles_api() {
    let (app, _db, case_id) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/profiles", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_active_profile_none() {
    let (app, _db, case_id) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/profiles/active", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_create_and_activate_profile_api() {
    let (mut app, _db, case_id) = setup_test_app().await;

    // Create profile
    let create_payload = CreateProfileRequest {
        name: "Activation Test".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec![],
        disabled_modules: vec![],
    };

    let create_response = app
        .call(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/profiles", case_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&create_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(create_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let profile_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let profile_id = profile_response["id"].as_str().unwrap();

    // Activate profile
    let activate_response = app
        .call(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{}/profiles/{}/activate",
                    case_id, profile_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(activate_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_delete_profile_api() {
    let (mut app, _db, case_id) = setup_test_app().await;

    // Create profile first
    let create_payload = CreateProfileRequest {
        name: "Delete Test".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec![],
        disabled_modules: vec![],
    };

    let create_response = app
        .call(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/profiles", case_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&create_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let profile_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let profile_id = profile_response["id"].as_str().unwrap();

    // Delete profile
    let delete_response = app
        .call(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/cases/{}/profiles/{}", case_id, profile_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
}

// === Ad-Hoc Execution API Tests ===

#[tokio::test]
async fn test_run_module_on_artifact_api() {
    let (_app, db, case_id) = setup_test_app().await;

    // Create artifact using the shared DB
    let artifact_id = create_test_artifact(&db, case_id).await;

    // Create ad-hoc request directly (API test for this would require keeping receiver alive)
    let request = seance_core::profile::AdHocRequest::new(
        case_id,
        "plugin.ntfs.mft_parser".to_string(),
        artifact_id,
    );
    let job = seance_core::profile::AdHocJob::new(&request);

    // Verify job can be created successfully
    let result = db.create_job(&job).await;
    assert!(result.is_ok());

    // Verify job was created
    let retrieved = db.get_job(job.id).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().module_id, "plugin.ntfs.mft_parser");
}

#[tokio::test]
async fn test_list_jobs_api() {
    let (app, _db, case_id) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/jobs", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // The job list is a capped-listing envelope, not a bare array (B8-030).
    // Asserting only the status let the shape change underneath this test
    // without it noticing; an examiner reads this list to answer "was this
    // analysis ever run", so a listing that stopped at its ceiling must say so
    // rather than read as "nothing was run".
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["items"].as_array().is_some_and(|a| a.is_empty()),
        "jobs travel under `items`"
    );
    assert_eq!(body["truncated"], serde_json::json!(false));
    assert_eq!(body["has_more"], serde_json::json!(false));
    assert_eq!(body["count_is_lower_bound"], serde_json::json!(false));
    assert_eq!(body["undecodable"], serde_json::json!(0));
    assert!(body.get("limit").is_some(), "the applied ceiling is named");
    assert!(body.get("offset").is_some());
}

#[tokio::test]
async fn test_list_jobs_capped_page_reports_has_more() {
    // Two jobs ran; the page shows one. An examiner reads this list to answer
    // "was this module ever run against this evidence", so a capped page that
    // reported itself complete would answer "no" for every job past the
    // ceiling. `has_more` is the only thing separating the two answers.
    let (app, db, case_id) = setup_test_app().await;
    let artifact_id = create_test_artifact(&db, case_id).await;

    for module in ["plugin.ntfs.mft_parser", "plugin.registry.parser"] {
        let request =
            seance_core::profile::AdHocRequest::new(case_id, module.to_string(), artifact_id);
        let job = seance_core::profile::AdHocJob::new(&request);
        db.create_job(&job).await.unwrap();
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/jobs?limit=1", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let page_one = body["items"].as_array().expect("jobs travel under `items`");
    assert_eq!(page_one.len(), 1);
    // Capped, under every name a client reads it by.
    assert_eq!(body["has_more"], serde_json::json!(true));
    assert_eq!(body["truncated"], serde_json::json!(true));
    assert_eq!(body["count_is_lower_bound"], serde_json::json!(true));
    // Capped is not damaged: both rows decoded, so paging recovers the missing
    // one and the reason must not claim otherwise.
    assert_eq!(body["undecodable"], serde_json::json!(0));
    assert_eq!(body["inventory_incomplete"], serde_json::json!(true));
    assert_eq!(
        body["inventory_incomplete_reason"],
        serde_json::json!("capped")
    );
    assert_eq!(body["limit"], serde_json::json!(1));

    // The withheld job is genuinely reachable, and it is the other one.
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/jobs?limit=1&offset=1", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let rest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let page_two = rest["items"].as_array().unwrap();
    assert_eq!(page_two.len(), 1);
    assert_eq!(rest["has_more"], serde_json::json!(false));
    assert_eq!(rest["offset"], serde_json::json!(1));
    assert_ne!(
        page_one[0]["id"].as_str().unwrap(),
        page_two[0]["id"].as_str().unwrap(),
        "the second page must hold the job the first one withheld"
    );
}

#[tokio::test]
async fn test_get_job_not_found() {
    let (app, _db, case_id) = setup_test_app().await;
    let fake_job_id = Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/jobs/{}", case_id, fake_job_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_profile_workflow_e2e() {
    let (mut app, _db, case_id) = setup_test_app().await;

    // 1. List profiles (should be empty)
    let list_response = app
        .call(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/profiles", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(list_response.status(), StatusCode::OK);

    // 2. Create a profile
    let create_payload = CreateProfileRequest {
        name: "E2E Test Profile".to_string(),
        description: "End-to-end test".to_string(),
        enabled_modules: vec!["plugin.ntfs.mft_parser".to_string()],
        disabled_modules: vec![],
    };

    let create_response = app
        .call(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/profiles", case_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&create_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(create_response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let profile: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let profile_id = profile["id"].as_str().unwrap();

    // 3. Activate the profile
    let activate_response = app
        .call(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{}/profiles/{}/activate",
                    case_id, profile_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(activate_response.status(), StatusCode::OK);

    // 4. Get active profile (should return our profile)
    let active_response = app
        .call(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/cases/{}/profiles/active", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(active_response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(active_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let active_profile: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(active_profile["id"].as_str().unwrap(), profile_id);

    // 5. Delete the profile
    let delete_response = app
        .call(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/cases/{}/profiles/{}", case_id, profile_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
}

/// A request the runner will not take leaves its job FAILED, not queued for
/// ever (HUNT-045).
///
/// The job row is written before the request is handed to the runner. When the
/// runner is gone — its channel closed — the handler returned 500 and the row
/// stayed `queued`: a job in the list that nothing would ever move. Built with
/// the ad-hoc receiver dropped, so every send is refused.
#[tokio::test]
async fn a_request_the_runner_refuses_leaves_its_job_failed_not_queued() {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Refused Case", "Test Examiner")
        .await
        .unwrap();
    // Content that resolves: a root evidence file on disk, and a child whose
    // bytes are carried inline (NTFS resident data), so the handler gets past
    // content resolution to the send.
    let evidence = std::env::temp_dir().join(format!("seance_adhoc_{}.bin", Uuid::new_v4()));
    std::fs::write(&evidence, b"evidence").unwrap();
    let root = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::RawEvidence,
        data: None,
        metadata: json!({
            "name": "evidence.bin",
            "source_path": evidence.to_string_lossy(),
        }),
    };
    db.record_artifact(&root).await.unwrap();
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: Some(root.id),
        artifact_type: ArtifactType::FileEntry,
        data: None,
        metadata: json!({
            "name": "resident.txt",
            "size": 5,
            "resident_data_b64": "aGVsbG8=",
        }),
    };
    db.record_artifact(&artifact).await.unwrap();

    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    drop(ad_hoc_rx);
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let app_state = AppState {
        db: db.clone(),
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
        evidence_roots: seance_api::EvidenceRootPolicy::unrestricted(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };
    let app = router_with_auth(
        app_state,
        Some(AuthConfig {
            jwt_secret: "test-secret".to_string(),
            admin_username: "admin".to_string(),
            admin_password_hash: "".to_string(),
            enabled: false,
        }),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{}/artifacts/{}/run_module",
                    case_id, artifact.id
                ))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "module_id": "plugin.ntfs.mft_parser" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let run_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        String::from_utf8_lossy(&run_body)
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/jobs", case_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("\"failed\"") && !text.contains("\"queued\""),
        "the refused job must be listed as failed, never left queued: {text}"
    );
    assert!(
        text.contains("did not accept the request"),
        "and carry the reason: {text}"
    );
    let _ = std::fs::remove_file(&evidence);
}
