use seance_core::profile::{AdHocJob, AdHocRequest, IngestionProfile, JobStatus};
use uuid::Uuid;

#[test]
fn test_triage_profile_creation() {
    let case_id = Uuid::new_v4();
    let profile = IngestionProfile::triage(case_id);

    assert_eq!(profile.case_id, case_id);
    assert_eq!(profile.name, "triage");
    assert!(!profile.is_active); // New profiles are not active by default
    assert!(!profile.enabled_modules.is_empty());
    assert!(profile.disabled_modules.is_empty());

    // Triage should enable essential modules
    assert!(profile
        .enabled_modules
        .contains(&"plugin.ntfs.mft_parser".to_string()));
    assert!(profile
        .enabled_modules
        .contains(&"plugin.ntfs.usnjrnl_parser".to_string()));
}

#[test]
fn test_deep_profile_creation() {
    let case_id = Uuid::new_v4();
    let profile = IngestionProfile::deep(case_id);

    assert_eq!(profile.case_id, case_id);
    assert_eq!(profile.name, "deep");
    assert!(!profile.is_active);
    assert!(profile.enabled_modules.is_empty()); // Deep enables all by default
    assert!(profile.disabled_modules.is_empty());
}

#[test]
fn test_custom_profile_creation() {
    let case_id = Uuid::new_v4();
    let profile = IngestionProfile::new(
        case_id,
        "Custom Profile".to_string(),
        "My custom profile".to_string(),
    );

    assert_eq!(profile.case_id, case_id);
    assert_eq!(profile.name, "Custom Profile");
    assert_eq!(profile.description, "My custom profile");
    assert!(!profile.is_active);
    assert!(profile.enabled_modules.is_empty());
    assert!(profile.disabled_modules.is_empty());
}

#[test]
fn test_profile_should_run_module_with_enabled_list() {
    let case_id = Uuid::new_v4();
    let profile = IngestionProfile::triage(case_id);

    // Triage has specific enabled modules
    assert!(profile.should_run_module("plugin.ntfs.mft_parser"));
    assert!(profile.should_run_module("plugin.ntfs.usnjrnl_parser"));

    // Modules not in enabled list should not run
    assert!(!profile.should_run_module("plugin.ntfs.logfile_parser"));
    assert!(!profile.should_run_module("unknown_module"));
}

#[test]
fn test_profile_should_run_module_with_disabled_list() {
    let case_id = Uuid::new_v4();
    let mut profile =
        IngestionProfile::new(case_id, "Custom".to_string(), "Test profile".to_string());

    // Empty enabled list means all modules run except disabled
    profile.disabled_modules = vec!["plugin.ntfs.logfile_parser".to_string()];

    assert!(profile.should_run_module("plugin.ntfs.mft_parser"));
    assert!(!profile.should_run_module("plugin.ntfs.logfile_parser"));
    assert!(profile.should_run_module("any_other_module"));
}

#[test]
fn test_profile_should_run_module_both_lists() {
    let case_id = Uuid::new_v4();
    let mut profile =
        IngestionProfile::new(case_id, "Custom".to_string(), "Test profile".to_string());

    profile.enabled_modules = vec!["plugin.ntfs.mft_parser".to_string()];
    profile.disabled_modules = vec!["plugin.ntfs.mft_parser".to_string()];

    // Disabled takes precedence over enabled
    assert!(!profile.should_run_module("plugin.ntfs.mft_parser"));
}

#[test]
fn test_profile_empty_enabled_list_runs_all() {
    let case_id = Uuid::new_v4();
    let profile = IngestionProfile::new(
        case_id,
        "All Modules".to_string(),
        "Run everything".to_string(),
    );

    // Empty enabled list means run all modules
    assert!(profile.should_run_module("plugin.ntfs.mft_parser"));
    assert!(profile.should_run_module("plugin.ntfs.logfile_parser"));
    assert!(profile.should_run_module("any_module"));
}

#[test]
fn test_ad_hoc_request_creation() {
    let case_id = Uuid::new_v4();
    let artifact_id = Uuid::new_v4();
    let module_id = "plugin.ntfs.mft_parser".to_string();

    let request = AdHocRequest::new(case_id, module_id.clone(), artifact_id);

    assert_eq!(request.case_id, case_id);
    assert_eq!(request.module_id, module_id);
    assert_eq!(request.artifact_id, artifact_id);
    assert_ne!(request.job_id, Uuid::nil()); // Should generate a job ID
}

#[test]
fn test_ad_hoc_job_creation() {
    let request = AdHocRequest::new(
        Uuid::new_v4(),
        "plugin.ntfs.mft_parser".to_string(),
        Uuid::new_v4(),
    );

    let job = AdHocJob::new(&request);

    assert_eq!(job.id, request.job_id);
    assert_eq!(job.case_id, request.case_id);
    assert_eq!(job.module_id, request.module_id);
    assert_eq!(job.target_artifact_id, request.artifact_id);
    assert_eq!(job.status, JobStatus::Pending);
    assert_eq!(job.artifacts_produced, 0);
    assert!(job.error_message.is_none());
    assert!(job.completed_at.is_none());
    assert!(job.created_at > 0);
}

#[test]
fn test_job_status_display() {
    assert_eq!(JobStatus::Pending.to_string(), "pending");
    assert_eq!(JobStatus::Running.to_string(), "running");
    assert_eq!(JobStatus::Complete.to_string(), "complete");
    assert_eq!(JobStatus::Failed.to_string(), "failed");
}

#[test]
fn test_profile_serialization() {
    let case_id = Uuid::new_v4();
    let profile = IngestionProfile::triage(case_id);

    // Test that profile can be serialized to JSON
    let json = serde_json::to_string(&profile).unwrap();
    assert!(json.contains("triage"));
    assert!(json.contains("plugin.ntfs.mft_parser"));

    // Test deserialization
    let deserialized: IngestionProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, profile.name);
    assert_eq!(deserialized.case_id, profile.case_id);
    assert_eq!(deserialized.enabled_modules, profile.enabled_modules);
}

#[test]
fn test_ad_hoc_request_serialization() {
    let request = AdHocRequest::new(
        Uuid::new_v4(),
        "plugin.ntfs.mft_parser".to_string(),
        Uuid::new_v4(),
    );

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: AdHocRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.job_id, request.job_id);
    assert_eq!(deserialized.module_id, request.module_id);
    assert_eq!(deserialized.case_id, request.case_id);
    assert_eq!(deserialized.artifact_id, request.artifact_id);
}

#[test]
fn test_job_status_serialization() {
    let statuses = vec![
        JobStatus::Pending,
        JobStatus::Running,
        JobStatus::Complete,
        JobStatus::Failed,
    ];

    for status in statuses {
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: JobStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, status);
    }
}
