//! Regression: an ad-hoc module run against a *directory* artifact must run.
//!
//! An iOS backup, a mobile extraction and an unpacked file-system export are
//! ingested as a folder: the root artifact records `is_directory` and a `path`,
//! and the module that handles it walks that tree itself. It has no bytes, so
//! the content resolver cannot open it — and the ad-hoc run, which resolves
//! content for every target, refused every such run with "the physical evidence
//! file cannot be located". That made the interactive unlock unreachable: a
//! backup that ingested locked could never be handed its password (HUNT-087).

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

struct Harness {
    app: axum::Router,
    db: Arc<SqliteConnection>,
    case_id: Uuid,
    /// Held so the ad-hoc channel stays open for the duration of the test.
    ad_hoc_rx: tokio::sync::mpsc::Receiver<seance_core::profile::AdHocRequest>,
}

async fn harness() -> Harness {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Directory Run", "Examiner").await.unwrap();

    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: seance_core::orchestrator::TaskSubmitter::new(
            tx,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );
    Harness {
        app,
        db,
        case_id,
        ad_hoc_rx,
    }
}

async fn record_directory_artifact(h: &Harness, path: &std::path::Path) -> Uuid {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id: h.case_id,
        parent_id: None,
        artifact_type: ArtifactType::RawEvidence,
        data: None,
        metadata: json!({
            "name": "00008030-001259123E50802E",
            "path": path.to_string_lossy(),
            "is_directory": true,
        }),
    };
    h.db.record_artifact(&artifact).await.unwrap();
    artifact.id
}

async fn run_module(
    h: &axum::Router,
    case_id: Uuid,
    artifact_id: Uuid,
) -> (StatusCode, serde_json::Value) {
    run_module_with(
        h,
        case_id,
        artifact_id,
        json!({ "module_id": "plugin.mobile.ios_backup" }),
    )
    .await
}

async fn run_module_with(
    h: &axum::Router,
    case_id: Uuid,
    artifact_id: Uuid,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = h
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{case_id}/artifacts/{artifact_id}/run_module"
                ))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn directory_artifact_runs_instead_of_being_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Manifest.plist"), b"stub").unwrap();

    let mut h = harness().await;
    let artifact_id = record_directory_artifact(&h, dir.path()).await;

    let (status, body) = run_module(&h.app, h.case_id, artifact_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        body["status"], "failed",
        "a directory target must not be refused for having no file to open: {body}"
    );

    // The run reached the orchestrator with no data source — the module reads
    // the folder itself. (A password for it goes to the credential route,
    // which resolves a directory target the same way: SEC-204.)
    let request = h
        .ad_hoc_rx
        .try_recv()
        .expect("the run was queued for the orchestrator");
    assert_eq!(request.module_id, "plugin.mobile.ios_backup");
    assert!(
        request.data_source.is_none(),
        "a directory has no bytes to hand the module"
    );
}

#[tokio::test]
async fn directory_that_has_moved_away_is_refused_not_treated_as_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let h = harness().await;
    let artifact_id = record_directory_artifact(&h, &path).await;
    drop(dir); // the evidence is no longer where the case says it is

    let (status, body) = run_module(&h.app, h.case_id, artifact_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["status"], "failed",
        "evidence that has moved must be reported, not run against nothing: {body}"
    );
}

/// SEC-204. `run_module`'s `secrets` map carried a password as a plain
/// `String`, merged it into the artifact's metadata, never zeroed it and never
/// audited what it did. It is retired: a run that still sends one is refused,
/// told where the secret goes now, and the secret is not echoed.
#[tokio::test]
async fn run_module_with_secrets_is_refused_and_names_the_credential_route() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Manifest.plist"), b"stub").unwrap();
    let mut h = harness().await;
    let artifact_id = record_directory_artifact(&h, dir.path()).await;

    let (status, body) = run_module_with(
        &h.app,
        h.case_id,
        artifact_id,
        json!({
            "module_id": "plugin.mobile.ios_backup",
            "secrets": {"ios_backup_password": "MyPassword123"},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let text = body.to_string();
    assert!(text.contains("/credential"), "{text}");
    assert!(!text.contains("MyPassword123"), "{text}");
    assert!(
        h.ad_hoc_rx.try_recv().is_err(),
        "a refused run must not reach the orchestrator"
    );
    assert!(h.db.list_jobs(h.case_id).await.unwrap().is_empty());
}
