use async_trait::async_trait;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::{Orchestrator, OrchestratorEvent},
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

// Mock module that always fails
struct FailingModule {
    id: String,
}

impl FailingModule {
    fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

#[async_trait]
impl ForensicsModule for FailingModule {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, _artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Err(ModuleError::ParsingError(
            "Simulated module error".to_string(),
        ))
    }
}

// Mock module that panics (should be caught)
#[allow(dead_code)]
struct PanickingModule {
    id: String,
}

impl PanickingModule {
    #[allow(dead_code)]
    fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

#[async_trait]
impl ForensicsModule for PanickingModule {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, _artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        panic!("Module panic!");
    }
}

async fn setup_test_orchestrator() -> (Orchestrator, Arc<SqliteConnection>, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();

    let case_id = db.create_case("Test Case", "Test Examiner").await.unwrap();

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);

    (orchestrator, db, case_id)
}

/// A module returning `Err` must surface as a `ModuleError` event and leave
/// the run able to finish: the task is settled and the orchestrator idle-exits.
#[tokio::test]
async fn test_module_error_handling() {
    let mut orchestrator = Orchestrator::new(None, 100).with_exit_on_idle(true);
    orchestrator.register_module(Arc::new(FailingModule::new("failing.module")));

    let mut status_rx = orchestrator.status_sender().subscribe();
    let sender = orchestrator.task_submitter();
    let active_tasks = orchestrator.active_tasks();

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "test.txt"}),
    );
    let artifact_id = artifact.id;

    // The submitter counts the task itself; counting again would leave one
    // that never completes and idle-exit would never fire.
    sender.send(artifact).unwrap();

    let run_handle = tokio::spawn(orchestrator.run());
    tokio::time::timeout(std::time::Duration::from_secs(20), run_handle)
        .await
        .expect("orchestrator must idle-exit despite a module error")
        .expect("orchestrator run task must not panic");

    assert_eq!(
        active_tasks.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "active_tasks must return to zero after a module error"
    );

    let mut saw_module_error = false;
    while let Ok(event) = status_rx.try_recv() {
        if let OrchestratorEvent::ModuleError {
            module_id,
            artifact_id: aid,
            ..
        } = event
        {
            if module_id == "failing.module" && aid == artifact_id {
                saw_module_error = true;
            }
        }
    }
    assert!(
        saw_module_error,
        "a module error must surface as a ModuleError event"
    );
}

#[tokio::test]
async fn test_invalid_artifact_handling() {
    let (orchestrator, _db, _case_id) = setup_test_orchestrator().await;

    // Try to submit an artifact with invalid data
    // For now, the orchestrator accepts any artifact
    // This test documents current behavior
    let artifact = Artifact::new(
        Uuid::nil(), // Invalid case_id
        ArtifactType::FileEntry,
        None,
        json!({}), // Empty metadata
    );

    let sender = orchestrator.task_submitter();
    let result = sender.send(artifact);

    // Currently accepts any artifact
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_closed_channel_handling() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    let sender = orchestrator.task_submitter();

    // Drop the orchestrator, closing the channel
    drop(orchestrator);

    // Try to send to closed channel
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "test.txt"}),
    );

    let result = sender.send(artifact);

    // Should fail because channel is closed
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ad_hoc_with_invalid_module_id() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    // Try to submit ad-hoc request for non-existent module
    let artifact_id = Uuid::new_v4();
    let request = seance_core::profile::AdHocRequest::new(
        case_id,
        "nonexistent.module".to_string(),
        artifact_id,
    );

    let sender = orchestrator.ad_hoc_submitter();
    let result = sender.send(request).await;

    // Should successfully queue (validation happens during processing)
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_ad_hoc_closed_channel() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    let sender = orchestrator.ad_hoc_submitter();

    // Drop orchestrator
    drop(orchestrator);

    let artifact_id = Uuid::new_v4();
    let request =
        seance_core::profile::AdHocRequest::new(case_id, "test.module".to_string(), artifact_id);

    let result = sender.send(request).await;

    // Should fail because channel is closed
    assert!(result.is_err());
}

#[tokio::test]
async fn test_database_connection_error() {
    // Test orchestrator without database
    let orchestrator = Orchestrator::new(None, 100);

    // Should still work, but without persistence
    assert!(!orchestrator.ad_hoc_submitter().is_closed());
    assert!(!orchestrator.task_submitter().is_closed());
}

#[tokio::test]
async fn test_duplicate_module_registration() {
    let (mut orchestrator, _db, _case_id) = setup_test_orchestrator().await;

    // Register same module twice
    orchestrator.register_module(Arc::new(FailingModule::new("test.module")));
    orchestrator.register_module(Arc::new(FailingModule::new("test.module")));

    // Should handle gracefully (likely overwrites or ignores)
    // This test documents current behavior
}

#[tokio::test]
async fn test_empty_artifact_metadata() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    // Create artifact with empty metadata
    let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({}));

    let sender = orchestrator.task_submitter();
    let result = sender.send(artifact);

    // Should accept empty metadata
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_large_metadata_handling() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    // Create artifact with large metadata
    let large_value = "x".repeat(10000);
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"large_field": large_value}),
    );

    let sender = orchestrator.task_submitter();
    let result = sender.send(artifact);

    // Should handle large metadata
    assert!(result.is_ok());
}

/// H1: a panicking module must not kill the worker or leak the active_tasks
/// count. The orchestrator must still idle-exit and a ModuleError event must
/// be emitted for the panic.
#[tokio::test]
async fn test_panicking_module_emits_error_and_allows_idle_exit() {
    let mut orchestrator = Orchestrator::new(None, 100)
        .with_worker_count(2)
        .with_exit_on_idle(true);
    orchestrator.register_module(Arc::new(PanickingModule::new("panicking.module")));

    let mut status_rx = orchestrator.status_sender().subscribe();
    let sender = orchestrator.task_submitter();
    let active_tasks = orchestrator.active_tasks();

    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "boom.bin"}),
    );
    let artifact_id = artifact.id;

    // The submitter counts the task itself (HUNT-043); counting here as well
    // would leave one that never completes and idle-exit would never fire.
    sender.send(artifact).unwrap();

    // The run() future must complete via idle-exit (10s idle timeout) even
    // though the module panicked. A leaked active_tasks count or a dead
    // worker would keep this pending until the 20s timeout.
    let run_handle = tokio::spawn(orchestrator.run());
    tokio::time::timeout(std::time::Duration::from_secs(20), run_handle)
        .await
        .expect("orchestrator must idle-exit despite module panic")
        .expect("orchestrator run task must not panic");

    assert_eq!(
        active_tasks.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "active_tasks must be decremented even when the module panics"
    );

    let mut saw_module_error = false;
    while let Ok(event) = status_rx.try_recv() {
        if let OrchestratorEvent::ModuleError {
            module_id,
            artifact_id: aid,
            error,
            ..
        } = event
        {
            if module_id == "panicking.module" && aid == artifact_id && error.contains("panicked") {
                saw_module_error = true;
            }
        }
    }
    assert!(
        saw_module_error,
        "a module panic must surface as a ModuleError event"
    );
}
