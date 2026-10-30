use async_trait::async_trait;
use seance_core::{
    artifact::Artifact,
    artifact::ArtifactType,
    db::DatabaseConnection,
    module::{ForensicsModule, ModuleError},
    orchestrator::Orchestrator,
    profile::{AdHocRequest, IngestionProfile},
};
use seance_db::SqliteConnection;
use std::sync::Arc;
use uuid::Uuid;

// Mock module for testing
struct MockModule {
    id: String,
}

impl MockModule {
    fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

#[async_trait]
impl ForensicsModule for MockModule {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> seance_core::module::InputCapability {
        seance_core::module::InputCapability::Stream
    }

    fn process(&self, _artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(vec![])
    }
}

async fn setup_test_orchestrator() -> (Orchestrator, Arc<SqliteConnection>, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();

    let case_id = db.create_case("Test Case", "Test Examiner").await.unwrap();

    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100);
    orchestrator.register_module(Arc::new(MockModule::new("test.module.1")));
    orchestrator.register_module(Arc::new(MockModule::new("test.module.2")));
    orchestrator.register_module(Arc::new(MockModule::new("test.module.3")));

    (orchestrator, db, case_id)
}

#[tokio::test]
async fn test_orchestrator_creation() {
    let (orchestrator, _db, _case_id) = setup_test_orchestrator().await;

    // Verify orchestrator can be created with database
    assert!(!orchestrator.ad_hoc_submitter().is_closed());
}

#[tokio::test]
async fn test_set_profile() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    // Create a profile
    let profile = IngestionProfile {
        id: Uuid::new_v4(),
        case_id,
        name: "Test Profile".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec!["test.module.1".to_string()],
        disabled_modules: vec![],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    // Should not panic
    orchestrator.set_profile(case_id, Some(profile)).await;
}

#[tokio::test]
async fn test_clear_profile() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    // Set a profile first
    let profile = IngestionProfile {
        id: Uuid::new_v4(),
        case_id,
        name: "Test Profile".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec!["test.module.1".to_string()],
        disabled_modules: vec![],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    orchestrator.set_profile(case_id, Some(profile)).await;

    // Clear it
    orchestrator.set_profile(case_id, None).await;
}

#[tokio::test]
async fn test_profile_isolation_by_case() {
    let (orchestrator, db, case1_id) = setup_test_orchestrator().await;

    // Create second case
    let case2_id = db
        .create_case("Test Case 2", "Test Examiner")
        .await
        .unwrap();

    // Set different profiles for each case
    let profile1 = IngestionProfile {
        id: Uuid::new_v4(),
        case_id: case1_id,
        name: "Profile 1".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec!["test.module.1".to_string()],
        disabled_modules: vec![],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    let profile2 = IngestionProfile {
        id: Uuid::new_v4(),
        case_id: case2_id,
        name: "Profile 2".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec!["test.module.2".to_string()],
        disabled_modules: vec![],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    // Should not panic when setting profiles for multiple cases
    orchestrator.set_profile(case1_id, Some(profile1)).await;
    orchestrator.set_profile(case2_id, Some(profile2)).await;
}

#[tokio::test]
async fn test_profile_update() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    // Set initial profile
    let profile1 = IngestionProfile {
        id: Uuid::new_v4(),
        case_id,
        name: "Profile 1".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec!["test.module.1".to_string()],
        disabled_modules: vec![],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    orchestrator.set_profile(case_id, Some(profile1)).await;

    // Update to new profile
    let profile2 = IngestionProfile {
        id: Uuid::new_v4(),
        case_id,
        name: "Profile 2".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec!["test.module.2".to_string()],
        disabled_modules: vec![],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    orchestrator.set_profile(case_id, Some(profile2)).await;
}

#[tokio::test]
async fn test_profile_lazy_loading_from_db() {
    let (_orchestrator, db, case_id) = setup_test_orchestrator().await;

    // Create and store a profile in the database
    let profile = IngestionProfile {
        id: Uuid::new_v4(),
        case_id,
        name: "DB Profile".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec!["test.module.1".to_string()],
        disabled_modules: vec![],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    db.create_profile(&profile).await.unwrap();
    db.set_active_profile(case_id, profile.id).await.unwrap();

    // Profile is in DB and can be loaded when needed by orchestrator
    let loaded_profile = db.get_active_profile(case_id).await.unwrap();
    assert!(loaded_profile.is_some());
    assert_eq!(loaded_profile.unwrap().id, profile.id);
}

// === Ad-Hoc Execution Tests ===

#[tokio::test]
async fn test_ad_hoc_submitter() {
    let (orchestrator, _db, _case_id) = setup_test_orchestrator().await;

    // Verify ad-hoc submitter is available
    let sender = orchestrator.ad_hoc_submitter();
    assert!(!sender.is_closed());
}

#[tokio::test]
async fn test_ad_hoc_request_submission() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    let artifact_id = Uuid::new_v4();
    let request = AdHocRequest::new(case_id, "test.module.1".to_string(), artifact_id);

    // Should be able to send ad-hoc request
    let sender = orchestrator.ad_hoc_submitter();
    let result = sender.send(request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_multiple_ad_hoc_requests() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    let sender = orchestrator.ad_hoc_submitter();

    // Send multiple requests
    for i in 0..5 {
        let artifact_id = Uuid::new_v4();
        let request = AdHocRequest::new(case_id, format!("test.module.{}", i % 3 + 1), artifact_id);
        assert!(sender.send(request).await.is_ok());
    }
}

#[tokio::test]
async fn test_register_module() {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();

    let mut orchestrator = Orchestrator::new(Some(db), 100);

    // Register modules
    orchestrator.register_module(Arc::new(MockModule::new("module.1")));
    orchestrator.register_module(Arc::new(MockModule::new("module.2")));

    // Orchestrator should accept modules without error
}

#[tokio::test]
async fn test_profile_with_disabled_modules() {
    let (orchestrator, _db, case_id) = setup_test_orchestrator().await;

    // Create a profile with disabled modules
    let profile = IngestionProfile {
        id: Uuid::new_v4(),
        case_id,
        name: "Disabled Test".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec![], // Empty = all modules
        disabled_modules: vec!["test.module.2".to_string()],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    orchestrator.set_profile(case_id, Some(profile)).await;
}
