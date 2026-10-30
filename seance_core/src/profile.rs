//! Ingestion profiles for controlling which modules run during analysis.
//!
//! Profiles allow users to select between different analysis modes:
//! - **Triage**: Fast, essential modules only (registry, EVTX, prefetch, etc.)
//! - **Deep**: Comprehensive analysis with all modules enabled
//! - **Custom**: User-defined module selection
//!
//! Profiles are stored per-case and can be changed during investigation.

use crate::data_source::DataSource;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// An ingestion profile that controls which modules execute during analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionProfile {
    /// Unique identifier for this profile
    pub id: Uuid,

    /// Associated case ID (profiles are case-specific)
    pub case_id: Uuid,

    /// Profile name (e.g., "triage", "deep", "custom")
    pub name: String,

    /// Human-readable description
    pub description: String,

    /// List of module IDs to enable (empty = all modules)
    pub enabled_modules: Vec<String>,

    /// List of module IDs to explicitly disable
    pub disabled_modules: Vec<String>,

    /// Whether this profile is currently active for the case
    pub is_active: bool,

    /// Creation timestamp (Unix epoch seconds)
    pub created_at: i64,
}

impl IngestionProfile {
    /// Creates a new custom profile
    pub fn new(case_id: Uuid, name: String, description: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            case_id,
            name,
            description,
            enabled_modules: Vec::new(),
            disabled_modules: Vec::new(),
            is_active: false,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Creates a "triage" profile with fast, essential modules only
    pub fn triage(case_id: Uuid) -> Self {
        let mut profile = Self::new(
            case_id,
            "triage".to_string(),
            "Fast triage mode - essential artifacts only".to_string(),
        );

        // Triage focuses on user activity, execution history, and logs.
        // IDs must match the exact `ForensicsModule::id()` strings; a mismatch
        // silently disables the module under this profile.
        profile.enabled_modules = vec![
            // Evidence containers (triage must still open E01/AFF4/virtual disks)
            "container.e01_reader".to_string(),
            "container.aff4_reader".to_string(),
            "container.vhd_reader".to_string(),
            "container.vmdk_reader".to_string(),
            "container.qcow2_reader".to_string(),
            // File system basics
            "plugin.disk.partition_parser".to_string(),
            "plugin.disk.filesystem_detector".to_string(),
            // NTFS essentials
            "plugin.ntfs.mft_parser".to_string(),
            "plugin.ntfs.usnjrnl_parser".to_string(),
            // Windows artifacts
            "plugin.windows.registry_parser".to_string(),
            "plugin.windows.evtx_parser".to_string(),
            "plugin.windows.prefetch_parser".to_string(),
            // Timeline indexing
            "plugin.search.indexer".to_string(),
        ];

        profile
    }

    /// Creates a "deep" profile with all modules enabled
    pub fn deep(case_id: Uuid) -> Self {
        let mut profile = Self::new(
            case_id,
            "deep".to_string(),
            "Deep analysis - all modules enabled".to_string(),
        );

        // Empty enabled_modules = run all modules
        profile.enabled_modules = Vec::new();

        profile
    }

    /// Checks if a module should run under this profile
    pub fn should_run_module(&self, module_id: &str) -> bool {
        // If explicitly disabled, don't run
        if self.disabled_modules.contains(&module_id.to_string()) {
            return false;
        }

        // If enabled list is empty, run all modules (except disabled)
        if self.enabled_modules.is_empty() {
            return true;
        }

        // Otherwise, only run if explicitly enabled
        self.enabled_modules.contains(&module_id.to_string())
    }
}

/// A record of a module execution against an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingLogEntry {
    pub id: i64,
    pub case_id: Uuid,
    pub artifact_id: Uuid,
    pub module_id: String,
    pub status: String,
    pub artifacts_produced: usize,
    pub error_message: Option<String>,
    pub duration_ms: u64,
    pub created_at: i64,
}

/// A request to execute a specific module on specific artifacts (ad-hoc execution)
///
/// `Debug` is written by hand: a derived one printed every value in the old
/// `secrets` map, so any `{:?}` of a request carrying a passphrase put it in a
/// log line. That map is gone (`SEC-204`); the credential prints redacted.
#[derive(Clone, Serialize, Deserialize)]
pub struct AdHocRequest {
    /// Unique job identifier
    pub job_id: Uuid,

    /// Module ID to execute
    pub module_id: String,

    /// Artifact ID to process
    pub artifact_id: Uuid,

    /// Associated case
    pub case_id: Uuid,

    /// Data source for the target artifact, resolved by the caller.
    ///
    /// Artifacts loaded from the database carry no in-memory `DataSource`, so
    /// an ad-hoc module (e.g. the opt-in deep carver) would otherwise have
    /// nothing to read and silently produce nothing. The API resolves the
    /// source via its content resolver and attaches it here; the orchestrator
    /// stamps it onto the fetched artifact before running the module. In-process
    /// only — skipped by serde.
    #[serde(skip)]
    pub data_source: Option<Arc<dyn DataSource>>,

    /// An examiner-supplied credential for this artifact and this run only
    /// (`HUNT-120`): a BitLocker or LUKS volume, a 7z archive, the Signal for
    /// iOS store, an iOS backup, a Signal Android backup. It is the only way a
    /// secret reaches an ad-hoc run (`SEC-204` retired the plain-string
    /// `secrets` map, which was merged into the artifact's metadata, never
    /// zeroed and never audited for its outcome). It is never merged into the
    /// artifact's metadata; the orchestrator makes it visible to the module for the one
    /// `process` call through [`crate::credential::scoped`], reads back what
    /// the module did with it, and drops it — zeroing the value — as soon as
    /// the module returns. In-process only and skipped by serde.
    #[serde(skip)]
    pub credential: Option<Arc<crate::credential::RunCredential>>,
}

impl std::fmt::Debug for AdHocRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdHocRequest")
            .field("job_id", &self.job_id)
            .field("module_id", &self.module_id)
            .field("artifact_id", &self.artifact_id)
            .field("case_id", &self.case_id)
            .field("data_source", &self.data_source.is_some())
            .field("credential", &self.credential)
            .finish()
    }
}

impl AdHocRequest {
    pub fn new(case_id: Uuid, module_id: String, artifact_id: Uuid) -> Self {
        Self {
            job_id: Uuid::new_v4(),
            case_id,
            module_id,
            artifact_id,
            data_source: None,
            credential: None,
        }
    }

    /// Attach the resolved data source for the target artifact.
    pub fn with_data_source(mut self, source: Arc<dyn DataSource>) -> Self {
        self.data_source = Some(source);
        self
    }

    /// Attach an examiner-supplied credential bound to this request's target.
    pub fn with_credential(mut self, credential: Arc<crate::credential::RunCredential>) -> Self {
        self.credential = Some(credential);
        self
    }
}

/// Status of an ad-hoc execution job
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    /// Job is queued but not yet started
    Pending,

    /// Job is currently executing
    Running,

    /// Job completed successfully
    Complete,

    /// Job failed with an error
    Failed,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobStatus::Pending => write!(f, "pending"),
            JobStatus::Running => write!(f, "running"),
            JobStatus::Complete => write!(f, "complete"),
            JobStatus::Failed => write!(f, "failed"),
        }
    }
}

/// One run of processing a root exhibit, from the moment it was queued to the
/// moment the orchestrator went idle for its case — or the moment a later
/// start found it never had (HUNT-113).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestRun {
    pub id: Uuid,
    pub case_id: Uuid,
    /// The root artifact whose subtree this run produced.
    pub source_artifact_id: Uuid,
    /// The source path or declared name, for the examiner reading the row.
    pub source_label: String,
    /// Unix seconds when the exhibit was queued.
    pub started_at: i64,
    /// Unix seconds when the row was closed; `None` while running.
    pub finished_at: Option<i64>,
    /// `running`, `completed`, `cancelled` or `interrupted`.
    pub status: String,
    /// The source's subtree size when the row was closed. For an interrupted
    /// run, what had been recorded before the process stopped.
    pub artifacts_recorded: Option<i64>,
    /// Why the run ended the way it did, when that needs saying.
    pub detail: Option<String>,
}

impl IngestRun {
    pub const RUNNING: &'static str = "running";
    pub const COMPLETED: &'static str = "completed";
    pub const CANCELLED: &'static str = "cancelled";
    pub const INTERRUPTED: &'static str = "interrupted";
}

/// Record of an ad-hoc execution job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdHocJob {
    /// Job identifier
    pub id: Uuid,

    /// Associated case
    pub case_id: Uuid,

    /// Module that was/is being executed
    pub module_id: String,

    /// Target artifact
    pub target_artifact_id: Uuid,

    /// Current status
    pub status: JobStatus,

    /// Number of artifacts produced
    pub artifacts_produced: usize,

    /// Error message if failed
    pub error_message: Option<String>,

    /// Creation timestamp
    pub created_at: i64,

    /// Completion timestamp
    pub completed_at: Option<i64>,
}

impl AdHocJob {
    pub fn new(request: &AdHocRequest) -> Self {
        Self {
            id: request.job_id,
            case_id: request.case_id,
            module_id: request.module_id.clone(),
            target_artifact_id: request.artifact_id,
            status: JobStatus::Pending,
            artifacts_produced: 0,
            error_message: None,
            created_at: chrono::Utc::now().timestamp(),
            completed_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_triage_profile_filters_modules() {
        let case_id = Uuid::new_v4();
        let profile = IngestionProfile::triage(case_id);

        // Should run enabled modules
        assert!(profile.should_run_module("plugin.ntfs.mft_parser"));
        assert!(profile.should_run_module("plugin.windows.evtx_parser"));

        // Should not run modules not in the enabled list
        assert!(!profile.should_run_module("plugin.ext4.extent_parser"));
    }

    /// Regression: triage profile IDs must match the exact module id() strings
    /// implemented across the workspace (e.g. "plugin.disk.partition_parser",
    /// not "plugin.partition_parser"). A mismatched ID silently disables the
    /// module so triage ingests parse no partitions.
    #[test]
    fn test_triage_profile_uses_real_module_ids() {
        let profile = IngestionProfile::triage(Uuid::new_v4());

        let expected = [
            "container.e01_reader",
            "container.aff4_reader",
            "container.vhd_reader",
            "container.vmdk_reader",
            "container.qcow2_reader",
            "plugin.disk.partition_parser",
            "plugin.disk.filesystem_detector",
            "plugin.ntfs.mft_parser",
            "plugin.ntfs.usnjrnl_parser",
            "plugin.windows.registry_parser",
            "plugin.windows.evtx_parser",
            "plugin.windows.prefetch_parser",
            "plugin.search.indexer",
        ];
        for id in expected {
            assert!(
                profile.should_run_module(id),
                "triage profile must enable '{}'",
                id
            );
        }

        // The old, incorrect IDs must be gone
        assert!(!profile.should_run_module("plugin.partition_parser"));
        assert!(!profile.should_run_module("plugin.filesystem_detector"));
        assert!(!profile.should_run_module("plugin.search.timeline_indexer"));
    }

    #[test]
    fn test_deep_profile_runs_all_modules() {
        let case_id = Uuid::new_v4();
        let profile = IngestionProfile::deep(case_id);

        // Should run any module (empty enabled list)
        assert!(profile.should_run_module("plugin.ntfs.mft_parser"));
        assert!(profile.should_run_module("plugin.ext4.extent_parser"));
        assert!(profile.should_run_module("plugin.any.random_module"));
    }

    #[test]
    fn test_disabled_modules_override() {
        let case_id = Uuid::new_v4();
        let mut profile = IngestionProfile::deep(case_id);

        // Disable a specific module
        profile
            .disabled_modules
            .push("plugin.ntfs.mft_parser".to_string());

        // Should not run disabled module even in deep mode
        assert!(!profile.should_run_module("plugin.ntfs.mft_parser"));
        assert!(profile.should_run_module("plugin.windows.evtx_parser"));
    }

    /// A derived `Debug` printed every value in the old `secrets` map; a
    /// request carrying a credential must format without its value.
    #[test]
    fn an_ad_hoc_request_formats_without_its_secrets() {
        let target = Uuid::new_v4();
        let request = AdHocRequest::new(Uuid::new_v4(), "m".into(), target).with_credential(
            std::sync::Arc::new(crate::credential::RunCredential::new(
                target,
                crate::credential::CredentialKind::LuksPassphrase,
                "hunter2-luks".into(),
                "erin",
            )),
        );
        let shown = format!("{request:?}");
        assert!(!shown.contains("hunter2-luks"), "{shown}");
        assert!(shown.contains("luks_passphrase"), "{shown}");
    }
}
