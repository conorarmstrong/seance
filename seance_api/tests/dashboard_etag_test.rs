//! The case-stats (dashboard aggregate) endpoint attaches a strong ETag and
//! honours If-None-Match: an unchanged case yields 304 (no body re-sent), and a
//! fresh ingest changes the ETag so the next conditional request is a 200.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

async fn setup() -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("ETag", "Examiner").await.unwrap();

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
        evidence_roots: seance_api::EvidenceRootPolicy::unrestricted(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };
    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: "".to_string(),
        enabled: false,
    };
    (router_with_auth(app_state, Some(auth_config)), case_id, db)
}

async fn add_file(db: &Arc<SqliteConnection>, case: Uuid, name: &str) {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id: case,
        parent_id: None,
        artifact_type: ArtifactType::FileEntry,
        data: None,
        metadata: json!({ "name": name }),
    };
    db.record_artifact(&artifact).await.unwrap();
}

fn stats_req(case: Uuid, if_none_match: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(format!("/api/v1/cases/{}/stats", case));
    if let Some(etag) = if_none_match {
        b = b.header(header::IF_NONE_MATCH, etag);
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn stats_etag_yields_304_until_data_changes() {
    let (app, case, db) = setup().await;
    add_file(&db, case, "a.txt").await;

    // First fetch: 200 with an ETag.
    let r1 = app.clone().oneshot(stats_req(case, None)).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let etag = r1
        .headers()
        .get(header::ETAG)
        .expect("stats response carries an ETag")
        .to_str()
        .unwrap()
        .to_string();

    // Same data + matching If-None-Match: 304, empty body.
    let r2 = app
        .clone()
        .oneshot(stats_req(case, Some(&etag)))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::NOT_MODIFIED);
    let body = axum::body::to_bytes(r2.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(body.is_empty(), "304 must not re-send the body");

    // Ingest changes the counts, so the stale ETag no longer matches: 200 fresh.
    add_file(&db, case, "b.txt").await;
    let r3 = app
        .clone()
        .oneshot(stats_req(case, Some(&etag)))
        .await
        .unwrap();
    assert_eq!(r3.status(), StatusCode::OK);
    let new_etag = r3
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(new_etag, etag, "a fresh ingest must change the ETag");
}
