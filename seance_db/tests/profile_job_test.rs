use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::profile::{AdHocJob, AdHocRequest, IngestionProfile, JobStatus};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

async fn setup_test_db() -> Arc<SqliteConnection> {
    let db_url = "sqlite::memory:".to_string();
    let conn = Arc::new(SqliteConnection::new(&db_url).await.unwrap());
    conn.initialize().await.unwrap();
    conn
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

#[tokio::test]
async fn test_create_profile() {
    let db = setup_test_db().await;
    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();
    let profile = IngestionProfile::triage(case_id);

    let result = db.create_profile(&profile).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_active_profile_none_exists() {
    let db = setup_test_db().await;
    let case_id = Uuid::new_v4();

    let result = db.get_active_profile(case_id).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_create_and_activate_profile() {
    let db = setup_test_db().await;

    // Create case first
    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    let mut profile = IngestionProfile::triage(case_id);
    profile.is_active = false;

    db.create_profile(&profile).await.unwrap();

    // Activate it
    db.set_active_profile(case_id, profile.id).await.unwrap();

    // Verify it's active
    let active = db.get_active_profile(case_id).await.unwrap();
    assert!(active.is_some());
    assert_eq!(active.unwrap().id, profile.id);
}

#[tokio::test]
async fn test_set_active_profile_deactivates_previous() {
    let db = setup_test_db().await;

    // Create case
    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    // Create two profiles
    let mut profile1 = IngestionProfile::triage(case_id);
    profile1.is_active = false;
    let mut profile2 = IngestionProfile::deep(case_id);
    profile2.is_active = false;

    db.create_profile(&profile1).await.unwrap();
    db.create_profile(&profile2).await.unwrap();

    // Activate first
    db.set_active_profile(case_id, profile1.id).await.unwrap();
    let active = db.get_active_profile(case_id).await.unwrap().unwrap();
    assert_eq!(active.id, profile1.id);

    // Activate second (should deactivate first)
    db.set_active_profile(case_id, profile2.id).await.unwrap();
    let active = db.get_active_profile(case_id).await.unwrap().unwrap();
    assert_eq!(active.id, profile2.id);
}

/// BUG-232: a failed activation (unknown id, or a profile owned by another
/// case) must leave the previously active profile in place. Clearing it drops
/// the case to "no profile", which the orchestrator reads as "run everything".
#[tokio::test]
async fn test_failed_activation_preserves_active_profile() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();
    let other_case = db.create_case("Other Case", "Examiner").await.unwrap();

    let mut profile = IngestionProfile::triage(case_id);
    profile.is_active = false;
    db.create_profile(&profile).await.unwrap();
    db.set_active_profile(case_id, profile.id).await.unwrap();

    // Unknown profile id.
    assert!(db
        .set_active_profile(case_id, Uuid::new_v4())
        .await
        .is_err());
    let active = db.get_active_profile(case_id).await.unwrap();
    assert_eq!(active.map(|p| p.id), Some(profile.id));

    // Profile that belongs to a different case.
    let mut foreign = IngestionProfile::deep(other_case);
    foreign.is_active = false;
    db.create_profile(&foreign).await.unwrap();
    assert!(db.set_active_profile(case_id, foreign.id).await.is_err());
    let active = db.get_active_profile(case_id).await.unwrap();
    assert_eq!(active.map(|p| p.id), Some(profile.id));
}

#[tokio::test]
async fn test_list_profiles_empty() {
    let db = setup_test_db().await;
    let case_id = Uuid::new_v4();

    let profiles = db.list_profiles(case_id).await.unwrap();
    assert_eq!(profiles.len(), 0);
}

#[tokio::test]
async fn test_list_profiles_multiple() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    let profile1 = IngestionProfile::triage(case_id);
    let profile2 = IngestionProfile::deep(case_id);

    db.create_profile(&profile1).await.unwrap();
    db.create_profile(&profile2).await.unwrap();

    let profiles = db.list_profiles(case_id).await.unwrap();
    assert_eq!(profiles.len(), 2);

    let ids: Vec<Uuid> = profiles.iter().map(|p| p.id).collect();
    assert!(ids.contains(&profile1.id));
    assert!(ids.contains(&profile2.id));
}

#[tokio::test]
async fn test_list_profiles_isolated_by_case() {
    let db = setup_test_db().await;

    let case1_id = db.create_case("Case 1", "Examiner").await.unwrap();
    let case2_id = db.create_case("Case 2", "Examiner").await.unwrap();

    let profile1 = IngestionProfile::triage(case1_id);
    let profile2 = IngestionProfile::deep(case2_id);

    db.create_profile(&profile1).await.unwrap();
    db.create_profile(&profile2).await.unwrap();

    // Case 1 should only see its profile
    let case1_profiles = db.list_profiles(case1_id).await.unwrap();
    assert_eq!(case1_profiles.len(), 1);
    assert_eq!(case1_profiles[0].id, profile1.id);

    // Case 2 should only see its profile
    let case2_profiles = db.list_profiles(case2_id).await.unwrap();
    assert_eq!(case2_profiles.len(), 1);
    assert_eq!(case2_profiles[0].id, profile2.id);
}

#[tokio::test]
async fn test_delete_profile() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    let profile = IngestionProfile::triage(case_id);
    db.create_profile(&profile).await.unwrap();

    // Verify it exists
    let profiles = db.list_profiles(case_id).await.unwrap();
    assert_eq!(profiles.len(), 1);

    // Delete it
    db.delete_profile(profile.id).await.unwrap();

    // Verify it's gone
    let profiles = db.list_profiles(case_id).await.unwrap();
    assert_eq!(profiles.len(), 0);
}

#[tokio::test]
async fn test_delete_active_profile() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    let mut profile = IngestionProfile::triage(case_id);
    profile.is_active = false;
    db.create_profile(&profile).await.unwrap();
    db.set_active_profile(case_id, profile.id).await.unwrap();

    // Delete the active profile
    db.delete_profile(profile.id).await.unwrap();

    // Verify no active profile
    let active = db.get_active_profile(case_id).await.unwrap();
    assert!(active.is_none());
}

#[tokio::test]
async fn test_profile_cascade_delete_with_case() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    let profile = IngestionProfile::triage(case_id);
    db.create_profile(&profile).await.unwrap();

    let other_case = db.create_case("Other Case", "Examiner").await.unwrap();
    let other_profile = IngestionProfile::triage(other_case);
    db.create_profile(&other_profile).await.unwrap();

    // Delete the case (should cascade to its profiles only)
    db.delete_case(case_id).await.unwrap();

    assert!(db.list_profiles(case_id).await.unwrap().is_empty());
    let kept = db.list_profiles(other_case).await.unwrap();
    assert!(kept.iter().any(|p| p.id == other_profile.id));
}

#[tokio::test]
async fn test_profile_serialization_roundtrip() {
    let db = setup_test_db().await;

    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();

    let mut original = IngestionProfile::triage(case_id);
    original.enabled_modules.push("custom.module".to_string());
    original
        .disabled_modules
        .push("disabled.module".to_string());

    db.create_profile(&original).await.unwrap();

    let profiles = db.list_profiles(case_id).await.unwrap();
    let retrieved = &profiles[0];

    assert_eq!(retrieved.id, original.id);
    assert_eq!(retrieved.name, original.name);
    assert_eq!(retrieved.enabled_modules, original.enabled_modules);
    assert_eq!(retrieved.disabled_modules, original.disabled_modules);
}

// === Ad-Hoc Job Tests ===

#[tokio::test]
async fn test_create_job() {
    let db = setup_test_db().await;
    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();
    let artifact_id = create_test_artifact(&db, case_id).await;

    let request = AdHocRequest::new(case_id, "plugin.ntfs.mft_parser".to_string(), artifact_id);
    let job = AdHocJob::new(&request);

    let result = db.create_job(&job).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_job() {
    let db = setup_test_db().await;
    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();
    let artifact_id = create_test_artifact(&db, case_id).await;

    let request = AdHocRequest::new(case_id, "plugin.ntfs.mft_parser".to_string(), artifact_id);
    let job = AdHocJob::new(&request);

    db.create_job(&job).await.unwrap();

    let retrieved = db.get_job(job.id).await.unwrap();
    assert!(retrieved.is_some());

    let retrieved_job = retrieved.unwrap();
    assert_eq!(retrieved_job.id, job.id);
    assert_eq!(retrieved_job.module_id, job.module_id);
    assert_eq!(retrieved_job.status, JobStatus::Pending);
}

#[tokio::test]
async fn test_get_nonexistent_job() {
    let db = setup_test_db().await;
    let fake_id = Uuid::new_v4();

    let result = db.get_job(fake_id).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_job_status() {
    let db = setup_test_db().await;
    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();
    let artifact_id = create_test_artifact(&db, case_id).await;

    let request = AdHocRequest::new(case_id, "plugin.ntfs.mft_parser".to_string(), artifact_id);
    let mut job = AdHocJob::new(&request);

    db.create_job(&job).await.unwrap();

    // Update to Running
    job.status = JobStatus::Running;
    db.update_job(&job).await.unwrap();

    let retrieved = db.get_job(job.id).await.unwrap().unwrap();
    assert_eq!(retrieved.status, JobStatus::Running);

    // Update to Complete
    job.status = JobStatus::Complete;
    job.artifacts_produced = 10;
    job.completed_at = Some(chrono::Utc::now().timestamp());
    db.update_job(&job).await.unwrap();

    let retrieved = db.get_job(job.id).await.unwrap().unwrap();
    assert_eq!(retrieved.status, JobStatus::Complete);
    assert_eq!(retrieved.artifacts_produced, 10);
    assert!(retrieved.completed_at.is_some());
}

#[tokio::test]
async fn test_update_job_with_error() {
    let db = setup_test_db().await;
    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();
    let artifact_id = create_test_artifact(&db, case_id).await;

    let request = AdHocRequest::new(case_id, "plugin.ntfs.mft_parser".to_string(), artifact_id);
    let mut job = AdHocJob::new(&request);

    db.create_job(&job).await.unwrap();

    job.status = JobStatus::Failed;
    job.error_message = Some("Test error message".to_string());
    job.completed_at = Some(chrono::Utc::now().timestamp());

    db.update_job(&job).await.unwrap();

    let retrieved = db.get_job(job.id).await.unwrap().unwrap();
    assert_eq!(retrieved.status, JobStatus::Failed);
    assert_eq!(
        retrieved.error_message.as_deref(),
        Some("Test error message")
    );
}

#[tokio::test]
async fn test_list_jobs_empty() {
    let db = setup_test_db().await;
    let case_id = Uuid::new_v4();

    let jobs = db.list_jobs(case_id).await.unwrap();
    assert_eq!(jobs.len(), 0);
}

#[tokio::test]
async fn test_list_jobs_multiple() {
    let db = setup_test_db().await;
    let case_id = db.create_case("Test Case", "Examiner").await.unwrap();
    let artifact_id = create_test_artifact(&db, case_id).await;

    let request1 = AdHocRequest::new(case_id, "module1".to_string(), artifact_id);
    let request2 = AdHocRequest::new(case_id, "module2".to_string(), artifact_id);

    let job1 = AdHocJob::new(&request1);
    let job2 = AdHocJob::new(&request2);

    db.create_job(&job1).await.unwrap();
    db.create_job(&job2).await.unwrap();

    let jobs = db.list_jobs(case_id).await.unwrap();
    assert_eq!(jobs.len(), 2);

    let ids: Vec<Uuid> = jobs.iter().map(|j| j.id).collect();
    assert!(ids.contains(&job1.id));
    assert!(ids.contains(&job2.id));
}

#[tokio::test]
async fn test_list_jobs_isolated_by_case() {
    let db = setup_test_db().await;
    let case1_id = db.create_case("Case 1", "Examiner").await.unwrap();
    let case2_id = db.create_case("Case 2", "Examiner").await.unwrap();
    let artifact1_id = create_test_artifact(&db, case1_id).await;
    let artifact2_id = create_test_artifact(&db, case2_id).await;

    let request1 = AdHocRequest::new(case1_id, "module1".to_string(), artifact1_id);
    let request2 = AdHocRequest::new(case2_id, "module2".to_string(), artifact2_id);

    let job1 = AdHocJob::new(&request1);
    let job2 = AdHocJob::new(&request2);

    db.create_job(&job1).await.unwrap();
    db.create_job(&job2).await.unwrap();

    // Case 1 should only see its job
    let case1_jobs = db.list_jobs(case1_id).await.unwrap();
    assert_eq!(case1_jobs.len(), 1);
    assert_eq!(case1_jobs[0].id, job1.id);

    // Case 2 should only see its job
    let case2_jobs = db.list_jobs(case2_id).await.unwrap();
    assert_eq!(case2_jobs.len(), 1);
    assert_eq!(case2_jobs[0].id, job2.id);
}

#[tokio::test]
async fn test_job_status_persistence() {
    let db = setup_test_db().await;

    for status in [
        JobStatus::Pending,
        JobStatus::Running,
        JobStatus::Complete,
        JobStatus::Failed,
    ] {
        let case_id = db.create_case("Test Case", "Examiner").await.unwrap();
        let artifact_id = create_test_artifact(&db, case_id).await;
        let request = AdHocRequest::new(case_id, "module".to_string(), artifact_id);
        let mut job = AdHocJob::new(&request);
        job.status = status.clone();

        db.create_job(&job).await.unwrap();

        let retrieved = db.get_job(job.id).await.unwrap().unwrap();
        assert_eq!(retrieved.status, status);
    }
}
