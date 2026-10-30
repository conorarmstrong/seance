//! A module run on a record resolves through to the evidence it was made from.
//!
//! HUNT-103. After `seance fetch-symbols` the product tells the examiner to
//! "re-run the memory analysis". There are two artifacts they could aim at and
//! neither worked: the `MemoryImage` **record** was refused for having "no
//! recorded content location" — it is a statement about the image, not a file —
//! and the raw evidence underneath is declined by the memory module, which does
//! not subscribe to it. The one action the product asks for was impossible
//! from the API.

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
    #[allow(dead_code)]
    ad_hoc_rx: tokio::sync::mpsc::Receiver<seance_core::profile::AdHocRequest>,
}

async fn harness() -> Harness {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Through parent", "Examiner").await.unwrap();

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

async fn run_module(
    app: &axum::Router,
    case_id: Uuid,
    artifact_id: Uuid,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/cases/{case_id}/artifacts/{artifact_id}/run_module"
                ))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"module_id": "plugin.memory.windows"}).to_string(),
                ))
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
async fn a_record_with_no_bytes_of_its_own_is_run_against_its_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("memdump.mem");
    std::fs::write(&image, vec![7u8; 4096]).unwrap();

    let h = harness().await;
    let evidence = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "memdump.mem",
            "path": image.to_string_lossy(),
            "source_path": image.to_string_lossy(),
        }),
    );
    h.db.record_artifact(&evidence).await.unwrap();

    // The record the memory stages actually analyse. It describes the image; it
    // holds none of it.
    let record = Artifact::new(
        h.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({"type": "MemoryImage", "name": "Memory image (raw)"}),
    )
    .with_parent(evidence.id);
    h.db.record_artifact(&record).await.unwrap();

    let (status, body) = run_module(&h.app, h.case_id, record.id).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        body["status"], "failed",
        "a re-run on the memory record must reach the image it describes: {body}"
    );
}

/// The fallback must not become a way to serve the wrong bytes: a record whose
/// own content IS locatable is still resolved from its own location.
#[tokio::test]
async fn a_record_that_has_its_own_bytes_is_not_read_through_its_parent() {
    let dir = tempfile::tempdir().unwrap();
    let parent_file = dir.path().join("container.bin");
    std::fs::write(&parent_file, vec![1u8; 4096]).unwrap();
    let own_file = dir.path().join("own.bin");
    std::fs::write(&own_file, b"the record's own bytes").unwrap();

    let h = harness().await;
    let parent = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "container.bin",
            "path": parent_file.to_string_lossy(),
            "source_path": parent_file.to_string_lossy(),
        }),
    );
    h.db.record_artifact(&parent).await.unwrap();

    let record = Artifact::new(
        h.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "SomeRecord",
            "name": "own.bin",
            "source_path": own_file.to_string_lossy(),
        }),
    )
    .with_parent(parent.id);
    h.db.record_artifact(&record).await.unwrap();

    let resolved = seance_api::content_resolver::resolve_artifact_content_through_parent(
        &h.db,
        &seance_api::EvidenceRootPolicy::unrestricted(),
        h.case_id,
        record.id,
    )
    .await
    .expect("the record names its own file");
    assert_eq!(resolved.size, b"the record's own bytes".len() as u64);
}
