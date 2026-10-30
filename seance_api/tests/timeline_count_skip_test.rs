//! The timeline endpoint runs a full filtered COUNT(*) for pagination, but the
//! total only changes when the filters change, not when paging. `count=false`
//! lets the client skip that COUNT while paging and reuse the total it fetched
//! on page 1 / filter change. When skipped the server returns -1 for
//! total_count/total_pages (the "reuse your cached total" sentinel) and infers
//! has_next from whether the page came back full.

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

async fn setup_test_app() -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Count Skip", "Examiner").await.unwrap();

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
    (app, case_id, db)
}

async fn add_event(db: &Arc<SqliteConnection>, case_id: Uuid, ts: i64) {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::TimelineEvent,
        metadata: serde_json::json!({
            "timestamp": ts,
            "timestamp_desc": "Test Event",
            "source_module": "TestModule",
            "short_desc": "desc",
            "full_details": "{}",
        }),
        data: None,
    };
    db.record_artifact(&artifact).await.unwrap();
}

async fn get_json(app: &axum::Router, uri: String) -> serde_json::Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn default_request_computes_total_count() {
    let (app, case_id, db) = setup_test_app().await;
    for ts in 0..3 {
        add_event(&db, case_id, 1000 + ts).await;
    }

    let json = get_json(&app, format!("/api/v1/cases/{}/timeline", case_id)).await;
    let pg = &json["pagination"];
    assert_eq!(json["events"].as_array().unwrap().len(), 3);
    assert_eq!(pg["total_count"].as_i64().unwrap(), 3);
    assert_eq!(pg["total_pages"].as_i64().unwrap(), 1);
}

#[tokio::test]
async fn count_false_skips_the_count_and_returns_the_sentinel() {
    let (app, case_id, db) = setup_test_app().await;
    for ts in 0..3 {
        add_event(&db, case_id, 1000 + ts).await;
    }

    let json = get_json(
        &app,
        format!("/api/v1/cases/{}/timeline?count=false", case_id),
    )
    .await;
    let pg = &json["pagination"];
    // Rows still come back; only the COUNT is skipped.
    assert_eq!(json["events"].as_array().unwrap().len(), 3);
    assert_eq!(
        pg["total_count"].as_i64().unwrap(),
        -1,
        "count=false must not compute a total"
    );
    assert_eq!(pg["total_pages"].as_i64().unwrap(), -1);
    // A short (non-full) page implies no next page even without a total.
    assert!(!pg["has_next"].as_bool().unwrap());
}

#[tokio::test]
async fn count_false_infers_has_next_from_a_full_page() {
    let (app, case_id, db) = setup_test_app().await;
    for ts in 0..5 {
        add_event(&db, case_id, 1000 + ts).await;
    }

    // page_size=2 with 5 events: page 1 comes back full (2 rows) -> more pages.
    let json = get_json(
        &app,
        format!(
            "/api/v1/cases/{}/timeline?count=false&page=1&page_size=2",
            case_id
        ),
    )
    .await;
    let pg = &json["pagination"];
    assert_eq!(json["events"].as_array().unwrap().len(), 2);
    assert_eq!(pg["total_count"].as_i64().unwrap(), -1);
    assert!(
        pg["has_next"].as_bool().unwrap(),
        "a full page must infer a next page when the count is skipped"
    );
}
