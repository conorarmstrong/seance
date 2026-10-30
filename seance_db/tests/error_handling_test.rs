use seance_core::db::DatabaseConnection;
use seance_core::profile::IngestionProfile;
use seance_db::SqliteConnection;
use uuid::Uuid;

async fn setup_test_db() -> SqliteConnection {
    let conn = SqliteConnection::new("sqlite::memory:").await.unwrap();
    conn.initialize().await.unwrap();
    conn
}

#[tokio::test]
async fn test_get_nonexistent_case() {
    let db = setup_test_db().await;

    let result = db.get_case(Uuid::new_v4()).await;

    // Should return error for nonexistent case
    assert!(result.is_err());
}

#[tokio::test]
async fn test_delete_nonexistent_case() {
    let db = setup_test_db().await;

    let result = db.delete_case(Uuid::new_v4()).await;

    // Deleting a case that does not exist is a loud error, not a silent no-op.
    assert!(result.is_err());
}

#[tokio::test]
async fn test_create_profile_with_invalid_case_id() {
    let db = setup_test_db().await;

    let profile = IngestionProfile {
        id: Uuid::new_v4(),
        case_id: Uuid::new_v4(), // Non-existent case
        name: "Test Profile".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec![],
        disabled_modules: vec![],
        is_active: false,
        created_at: chrono::Utc::now().timestamp(),
    };

    let result = db.create_profile(&profile).await;

    // Should fail due to foreign key constraint
    assert!(result.is_err());
}

#[tokio::test]
async fn test_set_active_profile_nonexistent() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();
    let result = db.set_active_profile(case_id, Uuid::new_v4()).await;

    // BUG-232: activating a profile that does not exist must FAIL rather than
    // report success after clearing whatever was active.
    assert!(result.is_err());
}

#[tokio::test]
async fn test_create_job_with_invalid_case_id() {
    let db = setup_test_db().await;

    let job = seance_core::profile::AdHocJob {
        id: Uuid::new_v4(),
        case_id: Uuid::new_v4(), // Non-existent case
        target_artifact_id: Uuid::new_v4(),
        module_id: "test.module".to_string(),
        status: seance_core::profile::JobStatus::Pending,
        created_at: chrono::Utc::now().timestamp(),
        artifacts_produced: 0,
        completed_at: None,
        error_message: None,
    };

    let result = db.create_job(&job).await;

    // Should fail due to foreign key constraint
    assert!(result.is_err());
}

#[tokio::test]
async fn test_update_job_nonexistent() {
    let db = setup_test_db().await;

    let job = seance_core::profile::AdHocJob {
        id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        target_artifact_id: Uuid::new_v4(),
        module_id: "test.module".to_string(),
        status: seance_core::profile::JobStatus::Running,
        created_at: chrono::Utc::now().timestamp(),
        artifacts_produced: 0,
        completed_at: None,
        error_message: None,
    };

    let result = db.update_job(&job).await;

    // An update that touched no row must be reported, not swallowed.
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_artifact_nonexistent() {
    let db = setup_test_db().await;

    let result = db.get_artifact(Uuid::new_v4()).await;

    // A missing artifact is a defined "not found", not an error.
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_duplicate_case_creation() {
    let db = setup_test_db().await;

    // Create two cases with same name
    let case1 = db.create_case("Duplicate Name", "Examiner").await.unwrap();
    let case2 = db.create_case("Duplicate Name", "Examiner").await.unwrap();

    // Should succeed - names don't have uniqueness constraint
    assert_ne!(case1, case2);
}

#[tokio::test]
async fn test_create_case_with_empty_name() {
    let db = setup_test_db().await;

    // No validation at this layer: an empty name is stored and round-trips.
    let id = db.create_case("", "Examiner").await.unwrap();
    assert_eq!(db.get_case(id).await.unwrap().name, "");
}

#[tokio::test]
async fn test_create_case_with_very_long_name() {
    let db = setup_test_db().await;

    let long_name = "x".repeat(10000);
    let id = db.create_case(&long_name, "Examiner").await.unwrap();

    // Stored in full, not truncated.
    assert_eq!(db.get_case(id).await.unwrap().name, long_name);
}

#[tokio::test]
async fn test_profile_cascade_delete() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    let profile = IngestionProfile {
        id: Uuid::new_v4(),
        case_id,
        name: "Test Profile".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec![],
        disabled_modules: vec![],
        is_active: false,
        created_at: chrono::Utc::now().timestamp(),
    };

    db.create_profile(&profile).await.unwrap();

    // Delete the case
    db.delete_case(case_id).await.unwrap();

    // Profile should be cascade deleted
    let profiles = db.list_profiles(case_id).await.unwrap();
    assert!(profiles.is_empty());
}

#[tokio::test]
async fn test_job_cascade_delete() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    // Create artifact first
    let artifact = seance_core::artifact::Artifact::new(
        case_id,
        seance_core::artifact::ArtifactType::FileEntry,
        None,
        serde_json::json!({"name": "test.txt"}),
    );
    db.record_artifact(&artifact).await.unwrap();

    let job = seance_core::profile::AdHocJob {
        id: Uuid::new_v4(),
        case_id,
        target_artifact_id: artifact.id,
        module_id: "test.module".to_string(),
        status: seance_core::profile::JobStatus::Pending,
        created_at: chrono::Utc::now().timestamp(),
        artifacts_produced: 0,
        completed_at: None,
        error_message: None,
    };

    db.create_job(&job).await.unwrap();

    // Delete the case
    db.delete_case(case_id).await.unwrap();

    // Jobs should be cascade deleted
    let jobs = db.list_jobs(case_id).await.unwrap();
    assert!(jobs.is_empty());
}

#[tokio::test]
async fn test_invalid_job_status_transition() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    let artifact = seance_core::artifact::Artifact::new(
        case_id,
        seance_core::artifact::ArtifactType::FileEntry,
        None,
        serde_json::json!({"name": "test.txt"}),
    );
    db.record_artifact(&artifact).await.unwrap();

    let job_id = Uuid::new_v4();
    let mut job = seance_core::profile::AdHocJob {
        id: job_id,
        case_id,
        target_artifact_id: artifact.id,
        module_id: "test.module".to_string(),
        status: seance_core::profile::JobStatus::Pending,
        created_at: chrono::Utc::now().timestamp(),
        artifacts_produced: 0,
        completed_at: None,
        error_message: None,
    };

    db.create_job(&job).await.unwrap();

    // Try various status transitions - all should succeed
    job.status = seance_core::profile::JobStatus::Running;
    db.update_job(&job).await.unwrap();

    job.status = seance_core::profile::JobStatus::Complete;
    db.update_job(&job).await.unwrap();

    // Even "backwards" transitions should succeed (no state machine enforcement at DB level)
    job.status = seance_core::profile::JobStatus::Pending;
    db.update_job(&job).await.unwrap();
}

#[tokio::test]
async fn test_multiple_active_profiles_per_case() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    let profile1 = IngestionProfile {
        id: Uuid::new_v4(),
        case_id,
        name: "Profile 1".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec![],
        disabled_modules: vec![],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    let profile2 = IngestionProfile {
        id: Uuid::new_v4(),
        case_id,
        name: "Profile 2".to_string(),
        description: "Test".to_string(),
        enabled_modules: vec![],
        disabled_modules: vec![],
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    db.create_profile(&profile1).await.unwrap();
    db.create_profile(&profile2).await.unwrap();

    // Database allows multiple active profiles (no constraint)
    // Application logic handles which one to use
    let profiles = db.list_profiles(case_id).await.unwrap();
    assert_eq!(profiles.len(), 2);
}
