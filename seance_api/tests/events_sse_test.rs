//! Integration tests for per-case scoping of the SSE event stream
//! (`GET /api/v1/events`).
//!
//! The stream must never leak artifact or processing metadata across case
//! boundaries: an examiner only receives events for cases they hold a
//! `case_access` grant on; admins receive the unfiltered stream.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use futures::StreamExt;
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::orchestrator::OrchestratorEvent;
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

const JWT_SECRET: &str = "sse-scope-test-secret";

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

fn authed_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
}

async fn seed_case(db: &SqliteConnection, name: &str) -> Uuid {
    db.create_case_with_metadata(Some(name.to_string()), None, Some("Ex".to_string()))
        .await
        .unwrap()
}

/// Reads SSE body chunks until EVERY needle has been observed (or
/// the timeout elapses). Use when the awaited events arrive on separate broadcast
/// channels (event_sender vs status_sender) whose SSE-select! interleaving order
/// is nondeterministic, so keying on a single marker would race the others.
async fn collect_body_until_all<S>(
    stream: &mut S,
    needles: &[&str],
    timeout: std::time::Duration,
) -> String
where
    S: futures::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin,
{
    let mut acc = String::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Ok(bytes))) => {
                acc.push_str(&String::from_utf8_lossy(&bytes));
                if needles.iter().all(|n| acc.contains(n)) {
                    break;
                }
            }
            _ => break,
        }
    }
    acc
}

#[tokio::test]
async fn sse_examiner_receives_only_accessible_case_events() {
    let db = fresh_db().await;
    let uid = db
        .create_user(
            "erin",
            &seance_api::hash_password("examinerpw1").unwrap(),
            "examiner",
        )
        .await
        .unwrap();
    let visible_case = seed_case(&db, "Visible").await;
    let hidden_case = seed_case(&db, "Hidden").await;
    db.grant_case_access(visible_case, uid, "read_write", None)
        .await
        .unwrap();

    let state = build_state(db.clone());
    let event_tx = state.event_sender.clone();
    let status_tx = state.status_sender.clone();
    let cfg = make_config();
    let app = router_with_auth(state, Some(cfg.clone()));
    let (token, _) = cfg.generate_token("erin", "examiner").unwrap();

    let resp = app
        .oneshot(authed_get("/api/v1/events", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body().into_data_stream();

    // Artifact events: low-volume types are forwarded immediately as full JSON.
    let hidden_artifact = Artifact::new(
        hidden_case,
        ArtifactType::Container,
        None,
        json!({"name": "hidden.e01"}),
    );
    let visible_artifact = Artifact::new(
        visible_case,
        ArtifactType::Container,
        None,
        json!({"name": "visible.e01"}),
    );
    let hidden_artifact_id = hidden_artifact.id;
    let visible_artifact_id = visible_artifact.id;
    event_tx.send(hidden_artifact).unwrap();
    event_tx.send(visible_artifact).unwrap();

    // Orchestrator events scoped by case_id: only the visible case passes.
    let hidden_ingest = Uuid::new_v4();
    let visible_ingest = Uuid::new_v4();
    status_tx
        .send(OrchestratorEvent::IngestCompleted {
            case_id: hidden_case,
            artifact_id: hidden_ingest,
        })
        .unwrap();
    status_tx
        .send(OrchestratorEvent::IngestCompleted {
            case_id: visible_case,
            artifact_id: visible_ingest,
        })
        .unwrap();

    // ModuleProgress with no case scope must be withheld (fail closed); a
    // scoped one for the visible case passes.
    let unscoped_progress = Uuid::new_v4();
    let scoped_progress = Uuid::new_v4();
    status_tx
        .send(OrchestratorEvent::ModuleProgress {
            case_id: None,
            module_id: "plugin.test".to_string(),
            artifact_id: unscoped_progress,
            units_done: 1,
            units_total: Some(2),
            unit: "bytes".to_string(),
        })
        .unwrap();
    status_tx
        .send(OrchestratorEvent::ModuleProgress {
            case_id: Some(visible_case),
            module_id: "plugin.test".to_string(),
            artifact_id: scoped_progress,
            units_done: 2,
            units_total: Some(2),
            unit: "bytes".to_string(),
        })
        .unwrap();

    // The artifact (event_sender), the ingest, and the module_progress
    // (status_sender) arrive on two separate broadcast channels the SSE select!
    // interleaves nondeterministically, and artifacts are additionally released
    // on a 500ms flush. Collect until ALL expected markers appear rather than
    // keying on one and racing the others.
    let received = collect_body_until_all(
        &mut body,
        &[
            &visible_artifact_id.to_string(),
            &visible_ingest.to_string(),
            &scoped_progress.to_string(),
        ],
        std::time::Duration::from_secs(5),
    )
    .await;

    assert!(
        received.contains(&visible_artifact_id.to_string()),
        "accessible artifact must be delivered; got: {}",
        received
    );
    assert!(
        received.contains(&visible_ingest.to_string()),
        "accessible ingest_completed must be delivered; got: {}",
        received
    );
    assert!(
        received.contains(&scoped_progress.to_string()),
        "case-scoped module_progress must be delivered; got: {}",
        received
    );
    assert!(
        !received.contains(&hidden_artifact_id.to_string()),
        "artifact from an inaccessible case must be dropped; got: {}",
        received
    );
    assert!(
        !received.contains(&hidden_ingest.to_string()),
        "ingest_completed for an inaccessible case must be dropped; got: {}",
        received
    );
    assert!(
        !received.contains(&unscoped_progress.to_string()),
        "unscoped module_progress must be dropped for non-admins; got: {}",
        received
    );
}

#[tokio::test]
async fn sse_admin_receives_unfiltered_stream() {
    let db = fresh_db().await;
    db.create_user(
        "root",
        &seance_api::hash_password("rootpw12345").unwrap(),
        "admin",
    )
    .await
    .unwrap();
    // No grants exist for this case at all; an admin still sees its events.
    let hidden_case = seed_case(&db, "Hidden").await;

    let state = build_state(db.clone());
    let event_tx = state.event_sender.clone();
    let status_tx = state.status_sender.clone();
    let cfg = make_config();
    let app = router_with_auth(state, Some(cfg.clone()));
    let (token, _) = cfg.generate_token("root", "admin").unwrap();

    let resp = app
        .oneshot(authed_get("/api/v1/events", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body().into_data_stream();

    let hidden_artifact = Artifact::new(
        hidden_case,
        ArtifactType::Container,
        None,
        json!({"name": "hidden.e01"}),
    );
    let hidden_artifact_id = hidden_artifact.id;
    event_tx.send(hidden_artifact).unwrap();

    let hidden_ingest = Uuid::new_v4();
    status_tx
        .send(OrchestratorEvent::IngestCompleted {
            case_id: hidden_case,
            artifact_id: hidden_ingest,
        })
        .unwrap();

    // The artifact (event_sender) and the ingest (status_sender) arrive on two
    // separate broadcast channels that the SSE select! interleaves in a
    // nondeterministic order. Collect until BOTH have been observed rather than
    // keying on one marker and racing the other.
    let received = collect_body_until_all(
        &mut body,
        &[&hidden_artifact_id.to_string(), &hidden_ingest.to_string()],
        std::time::Duration::from_secs(5),
    )
    .await;

    assert!(
        received.contains(&hidden_artifact_id.to_string()),
        "admin must receive artifacts from every case; got: {}",
        received
    );
    assert!(
        received.contains(&hidden_ingest.to_string()),
        "admin must receive status events from every case; got: {}",
        received
    );
}

#[tokio::test]
async fn sse_requires_authentication() {
    let db = fresh_db().await;
    let cfg = make_config();
    let app = router_with_auth(build_state(db), Some(cfg));

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "the event stream must sit behind auth like every other case-data route"
    );
}
