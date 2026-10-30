use crate::artifact::Artifact;
use crate::profile::{AdHocJob, IngestRun, IngestionProfile, ProcessingLogEntry};
use anyhow::Result;
use async_trait::async_trait;
use uuid::Uuid;

/// One aggregated processing-log group: everything one module did in one status
/// across a whole case. Produced by
/// [`DatabaseConnection::get_processing_log_for_case`] and rendered as the tool
/// provenance section of the court report.
///
/// Lives here rather than in the SQLite backend because it is the trait's
/// return type: a backend that cannot produce these must fail rather than be
/// unable to name them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CaseProcessingLogEntry {
    pub module_id: String,
    pub status: String,
    /// Individual per-artifact runs folded into this group.
    pub runs: i64,
    pub artifacts_produced: i64,
    /// Summed wall-clock across the group; `None` only if every row was NULL.
    pub duration_ms: Option<i64>,
    /// One representative error from the group, or `None` when it recorded
    /// none. `error_count` says how many rows carried one.
    pub error_message: Option<String>,
    pub error_count: i64,
}

/// One row of the processing log, as the writer hands it to the backend.
///
/// The log is the run's provenance: which module touched which artifact, and
/// whether it succeeded, skipped, errored or never ran. Most of it is the same
/// sentence over and over — "this module ran over this artifact and produced
/// nothing" — which cost 98.5% of 23.4 million rows on one case and 27 rows per
/// artifact on another (HUNT-074). A row may therefore carry that sentence for
/// MANY modules at once, in [`ProcessingLogRow::zero_yield`], instead of one row
/// each. Nothing is lost: each module keeps its own duration, and the read paths
/// expand the list back into one entry per module.
#[derive(Debug, Clone)]
pub struct ProcessingLogRow {
    pub case_id: Uuid,
    pub artifact_id: Uuid,
    /// The module this row is about. Empty when the row is a `zero_yield` fold,
    /// which is about several.
    pub module_id: String,
    pub status: String,
    pub artifacts_produced: usize,
    pub error_message: Option<String>,
    pub duration_ms: u64,
    /// Modules that ran over this artifact and produced nothing, with how long
    /// each took. `None` for an ordinary single-module row.
    pub zero_yield: Option<Vec<(String, u64)>>,
}

impl ProcessingLogRow {
    /// An ordinary row about one module.
    pub fn single(
        case_id: Uuid,
        artifact_id: Uuid,
        module_id: String,
        status: String,
        artifacts_produced: usize,
        error_message: Option<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            case_id,
            artifact_id,
            module_id,
            status,
            artifacts_produced,
            error_message,
            duration_ms,
            zero_yield: None,
        }
    }

    /// The folded modules, or nothing when this is an ordinary row.
    pub fn zero_yield_modules(&self) -> Vec<(String, u64)> {
        self.zero_yield.clone().unwrap_or_default()
    }

    /// The folded list as the JSON the column stores, or `None`.
    pub fn zero_yield_json(&self) -> Option<String> {
        let modules = self.zero_yield.as_ref()?;
        let value: Vec<serde_json::Value> = modules
            .iter()
            .map(|(module_id, duration_ms)| {
                serde_json::json!({"module_id": module_id, "duration_ms": duration_ms})
            })
            .collect();
        serde_json::to_string(&value).ok()
    }
}

// async_trait stamps #[must_use] on every method whose future is already
// must_use; clippy 1.99 flags that, and the macro output is not ours to edit.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait DatabaseConnection: Send + Sync + 'static {
    async fn initialize(&self) -> Result<()>;
    async fn create_case(&self, name: &str, examiner: &str) -> Result<Uuid>;
    async fn record_artifact(&self, artifact: &Artifact) -> Result<()>;
    async fn get_artifact(&self, artifact_id: Uuid) -> Result<Option<Artifact>>;

    // Batch operations for performance
    async fn record_artifacts_batch(&self, artifacts: &[Artifact]) -> Result<()> {
        // Default implementation: fall back to individual inserts
        for artifact in artifacts {
            self.record_artifact(artifact).await?;
        }
        Ok(())
    }

    // Profile management
    async fn create_profile(&self, profile: &IngestionProfile) -> Result<()>;
    async fn get_active_profile(&self, case_id: Uuid) -> Result<Option<IngestionProfile>>;
    async fn list_profiles(&self, case_id: Uuid) -> Result<Vec<IngestionProfile>>;
    async fn set_active_profile(&self, case_id: Uuid, profile_id: Uuid) -> Result<()>;
    async fn delete_profile(&self, profile_id: Uuid) -> Result<()>;

    // Ad-hoc job management
    async fn create_job(&self, job: &AdHocJob) -> Result<()>;
    async fn update_job(&self, job: &AdHocJob) -> Result<()>;
    async fn get_job(&self, job_id: Uuid) -> Result<Option<AdHocJob>>;
    async fn list_jobs(&self, case_id: Uuid) -> Result<Vec<AdHocJob>>;

    /// Mark every job that was still `pending` or `running` when a process
    /// stopped as failed, with `reason` as its error message, and return the
    /// jobs so marked. Only jobs created at or before `created_at_or_before`
    /// (a Unix timestamp in seconds) are touched: the caller passes the moment
    /// it started, so a job it accepted itself is never swept.
    ///
    /// Ad-hoc jobs live in an in-memory queue and are not resumed across a
    /// restart, so a row still `running` after one describes work nobody is
    /// doing. The orchestrator calls this once when it starts, before it accepts
    /// work. The default refuses rather than pretending: a backend that cannot
    /// sweep leaves the stale rows visible and the caller says so in its log.
    async fn fail_interrupted_jobs(
        &self,
        created_at_or_before: i64,
        reason: &str,
    ) -> Result<Vec<AdHocJob>> {
        let _ = (created_at_or_before, reason);
        Err(anyhow::anyhow!(
            "this database backend cannot sweep interrupted jobs; a job left pending or \
             running by a stopped process would keep that status"
        ))
    }

    /// Record that processing of a root exhibit has started (HUNT-113).
    ///
    /// Written when the exhibit is queued, so that a process which stops
    /// before the walk ends leaves a row with no `finished_at` for the next
    /// start to find. The default keeps lightweight backends compiling; a
    /// backend that records nothing cannot see an interruption either, which
    /// [`Self::mark_interrupted_ingest_runs`] refuses to hide.
    async fn start_ingest_run(&self, _run: &IngestRun) -> Result<()> {
        Ok(())
    }

    /// Close every `running` ingest run of `case_id` with `status`
    /// (`completed` or `cancelled`). Returns the runs closed. No count is
    /// stored: the artifact writer may still be flushing, so a closed run's
    /// count is taken at read time by [`Self::list_ingest_runs`].
    async fn finish_ingest_runs_for_case(
        &self,
        _case_id: Uuid,
        _status: &str,
        _finished_at: i64,
    ) -> Result<Vec<IngestRun>> {
        Ok(Vec::new())
    }

    /// Mark every ingest run still `running` and started strictly before
    /// `started_before` as `interrupted`: it was queued by a process that has
    /// stopped, and nothing will finish it. Strictly before, with one-second
    /// timestamps: an ingest accepted in the same second this process started
    /// is this process's own, and a process cannot die and restart inside one
    /// second. Each returned run carries the
    /// source's subtree count as recorded before it stopped. The orchestrator
    /// calls this once at start, before accepting work. The default refuses
    /// rather than pretending, for the reason `fail_interrupted_jobs` gives.
    async fn mark_interrupted_ingest_runs(
        &self,
        started_before: i64,
        detail: &str,
    ) -> Result<Vec<IngestRun>> {
        let _ = (started_before, detail);
        Err(anyhow::anyhow!(
            "this database backend cannot sweep interrupted ingest runs; an exhibit whose \
             processing a stopped process never finished would read as complete"
        ))
    }

    /// Every ingest run of `case_id`, newest first. A closed run that stored
    /// no count (completed, cancelled) reports its source's subtree size as it
    /// stands now.
    async fn list_ingest_runs(&self, _case_id: Uuid) -> Result<Vec<IngestRun>> {
        Ok(Vec::new())
    }

    /// Mark every record of `record_type` with `status` under `parent_id` as
    /// superseded by `by_artifact`, returning how many were marked.
    ///
    /// A later run can answer an earlier refusal: a password opens a backup that
    /// was recorded as unreadable, a symbol pack arrives after a memory pass
    /// gave up. The earlier record stays — it is evidence that the refusal
    /// happened — but it stops counting as missing data.
    ///
    /// The default refuses rather than pretending: a backend that cannot mark
    /// would leave two contradictory statements standing with nothing saying
    /// which is current, and the caller must be able to say so.
    async fn mark_records_superseded(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        record_type: &str,
        field: &str,
        status: &str,
        by_artifact: Uuid,
    ) -> Result<u64> {
        let _ = (case_id, parent_id, record_type, field, status, by_artifact);
        Err(anyhow::anyhow!(
            "this database backend cannot mark a record superseded; an earlier statement a \
             later run answered would keep counting as missing data"
        ))
    }

    /// Mark the records a previous run of `module_id` left under `parent_id` as
    /// superseded by this run, returning how many were marked.
    ///
    /// Re-running a parser is an ordinary act of examination — a splitter is
    /// fixed, a password arrives, a symbol pack is fetched — and before this the
    /// second run's records simply landed beside the first run's with nothing
    /// saying which run wrote either. `match_field` / `match_value` select what
    /// this module wrote: a record `type` for parsed records, `source_module`
    /// for timeline events. `run_started_at` is the RFC 3339 stamp taken before
    /// the run, so only records that predate it are marked.
    ///
    /// The earlier records are kept: that the first run said what it said is
    /// part of the examination's history.
    ///
    /// The default refuses rather than pretending: a backend that cannot mark
    /// would leave two runs' answers standing with nothing saying which is
    /// current, and the caller must be able to say so.
    #[allow(clippy::too_many_arguments)]
    async fn supersede_records_from_an_earlier_run(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        match_field: &str,
        match_value: &str,
        run_started_at: &str,
        by_artifact: Uuid,
        module_id: &str,
    ) -> Result<u64> {
        let _ = (
            case_id,
            parent_id,
            match_field,
            match_value,
            run_started_at,
            by_artifact,
            module_id,
        );
        Err(anyhow::anyhow!(
            "this database backend cannot mark a record superseded; an earlier run's answer would stand beside this one with nothing saying which is current"
        ))
    }

    // Processing log
    async fn record_processing_log(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        module_id: &str,
        status: &str,
        artifacts_produced: usize,
        error_message: Option<&str>,
        duration_ms: u64,
    ) -> Result<()>;

    async fn record_processing_log_batch(&self, entries: &[ProcessingLogRow]) -> Result<()> {
        for entry in entries {
            // A backend with no column for the folded form writes the statement
            // out in full rather than losing it: the row exists to say that
            // these modules ran and produced nothing.
            for (module_id, duration_ms) in entry.zero_yield_modules() {
                self.record_processing_log(
                    entry.case_id,
                    entry.artifact_id,
                    &module_id,
                    "complete",
                    0,
                    None,
                    duration_ms,
                )
                .await?;
            }
            if entry.zero_yield.is_none() {
                self.record_processing_log(
                    entry.case_id,
                    entry.artifact_id,
                    &entry.module_id,
                    &entry.status,
                    entry.artifacts_produced,
                    entry.error_message.as_deref(),
                    entry.duration_ms,
                )
                .await?;
            }
        }
        Ok(())
    }

    // Evidence integrity & audit trail. Default no-ops keep lightweight
    // backends/test doubles compiling; the SQLite backend overrides these.
    #[allow(clippy::too_many_arguments)]
    /// Record one integrity verification.
    ///
    /// `expected_*` are the baseline digests the computed ones were compared
    /// against; SHA-256 is included because it is the ONLY baseline an ordinary
    /// FileEntry has, and leaving it out of the record made the integrity
    /// history unable to show what a check was measured against.
    async fn record_integrity_check(
        &self,
        _case_id: Uuid,
        _artifact_id: Uuid,
        _computed_md5: Option<&str>,
        _computed_sha1: Option<&str>,
        _computed_sha256: Option<&str>,
        _expected_md5: Option<&str>,
        _expected_sha1: Option<&str>,
        _expected_sha256: Option<&str>,
        _status: &str,
        _details: Option<&str>,
    ) -> Result<()> {
        Ok(())
    }

    async fn record_audit_event(
        &self,
        _case_id: Option<Uuid>,
        _user_id: &str,
        _action: &str,
        _resource_type: Option<&str>,
        _resource_id: Option<Uuid>,
        _details: Option<&str>,
    ) -> Result<()> {
        Ok(())
    }

    /// Merge a JSON object into an existing artifact's metadata, in place.
    ///
    /// Used to attach the acquisition baseline (and its integrity state) to an
    /// artifact that was persisted and queued for processing *before* hashing
    /// finished, so parsing can start while the hash runs. Returns the number of
    /// rows updated (0 if the artifact is not persisted). `case_id` scopes the
    /// write so a stray id can never patch another case's evidence. Default
    /// no-op keeps lightweight backends compiling.
    async fn merge_artifact_metadata(
        &self,
        _case_id: Uuid,
        _artifact_id: Uuid,
        _patch: &serde_json::Value,
    ) -> Result<u64> {
        Ok(0)
    }

    /// Apply a computed per-file hash to an existing artifact: set the
    /// md5_hash/sha1_hash/sha256_hash columns and merge the md5/sha1/sha256
    /// keys into its metadata. Called by the orchestrator when a `file_hash`
    /// record is produced. Returns the number of artifact rows updated (0 if
    /// the parent is not yet persisted, so the caller can retry). Default
    /// no-op keeps lightweight backends compiling.
    /// `case_id` scopes the write: the ids come from a worker pipeline, and a
    /// corrupt or cross-case `parent_id` must never be able to write digests
    /// onto another case's evidence.
    async fn apply_file_hash(
        &self,
        _case_id: Uuid,
        _artifact_id: Uuid,
        _md5: &str,
        _sha1: &str,
        _sha256: &str,
    ) -> Result<u64> {
        Ok(0)
    }

    /// Apply a batch of computed per-file hashes to their parents in a single
    /// write path. Entries are `(case_id, artifact_id, md5, sha1, sha256)`.
    /// Returns the parent ids that were NOT applied (0 rows -- the
    /// parent isn't persisted yet), so the caller can retry them. The default
    /// falls back to one `apply_file_hash` per entry; the SQLite backend
    /// overrides this with a single transaction to avoid one autocommit UPDATE
    /// per file (the ingest-time chokepoint for tens of thousands of files).
    async fn apply_file_hashes_batch(
        &self,
        hashes: &[(Uuid, Uuid, String, String, String)],
    ) -> Result<Vec<Uuid>> {
        let mut missed = Vec::new();
        for (case_id, id, md5, sha1, sha256) in hashes {
            if self
                .apply_file_hash(*case_id, *id, md5, sha1, sha256)
                .await?
                == 0
            {
                missed.push(*id);
            }
        }
        Ok(missed)
    }

    /// Record on a parent artifact that its content hash was NOT computed, and
    /// why. Entries are `(case_id, artifact_id, reason)`.
    ///
    /// The hasher emits a `file_hash` record with `hash_skipped: "size"` or
    /// `"short_read"` instead of digests when it refuses or fails to read the
    /// file. Those records used to be dropped: the parent kept empty hash
    /// columns and no marker, so a file too large to hash, or one whose bytes
    /// could not be read, was indistinguishable from an ordinary file that
    /// simply had not been hashed yet — and from one whose digests were
    /// verified. Stamping the standard `content_incomplete` /
    /// `content_incomplete_reason` pair (plus `hash_skipped` for the specific
    /// reason) is what keeps "not hashed, and here is why" from reading as
    /// "hashed, nothing notable".
    ///
    /// Returns the artifact ids that matched no row, so the caller can retry
    /// them once the parent has been flushed. The default is a no-op that
    /// reports every entry as missed rather than claiming a stamp it did not
    /// make.
    async fn mark_file_hashes_skipped_batch(
        &self,
        skips: &[(Uuid, Uuid, String)],
    ) -> Result<Vec<Uuid>> {
        Ok(skips.iter().map(|(_, id, _)| *id).collect())
    }

    async fn get_processing_log_for_artifact(
        &self,
        artifact_id: Uuid,
        limit: Option<usize>,
    ) -> Result<Vec<ProcessingLogEntry>>;

    async fn count_processing_log_for_artifact(&self, artifact_id: Uuid) -> Result<usize>;

    /// Case-scoped tool provenance, aggregated per (module, status).
    ///
    /// Returns `(groups, distinct_group_count)`. `groups` is capped at `limit`;
    /// when `distinct_group_count` exceeds `groups.len()` the caller MUST
    /// disclose the shortfall, because the report section this feeds is the
    /// court's account of which tools touched the evidence and a shortened list
    /// presented as the whole one misstates that.
    ///
    /// This is on the trait, not on one backend, because it is part of what a
    /// case store has to be able to answer. The default does NOT return an
    /// empty log: an empty tool-provenance section reads as "no module ran",
    /// which is a claim about the evidence, and no backend gets to make that
    /// claim by omission. A backend that cannot aggregate its processing log
    /// says so and the export fails.
    async fn get_processing_log_for_case(
        &self,
        _case_id: Uuid,
        _limit: i64,
    ) -> Result<(Vec<CaseProcessingLogEntry>, i64)> {
        Err(anyhow::anyhow!(
            "this database backend cannot aggregate the case processing log; tool provenance \
             would be reported as absent rather than as unavailable"
        ))
    }

    async fn list_jobs_for_artifact(&self, artifact_id: Uuid) -> Result<Vec<AdHocJob>>;
}
