//! Tests for the background artifact writer's retry behavior (C3).
//!
//! A transient DB failure must not silently discard parsed artifacts: the
//! writer retries with backoff, and if a flush still fails the batch is
//! retained and retried on the next flush tick.

use anyhow::{bail, Result};
use async_trait::async_trait;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::Orchestrator,
    profile::{AdHocJob, IngestionProfile, ProcessingLogEntry},
};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// DB double whose batch writes fail a configurable number of times before
/// succeeding, recording everything that is eventually persisted.
struct FlakyDb {
    fail_remaining: AtomicUsize,
    batch_attempts: AtomicUsize,
    stored: Mutex<Vec<Artifact>>,
}

impl FlakyDb {
    fn new(failures: usize) -> Self {
        Self {
            fail_remaining: AtomicUsize::new(failures),
            batch_attempts: AtomicUsize::new(0),
            stored: Mutex::new(Vec::new()),
        }
    }

    fn stored_ids(&self) -> Vec<Uuid> {
        self.stored.lock().unwrap().iter().map(|a| a.id).collect()
    }
}

#[async_trait]
impl DatabaseConnection for FlakyDb {
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
    async fn create_case(&self, _name: &str, _examiner: &str) -> Result<Uuid> {
        Ok(Uuid::new_v4())
    }

    async fn record_artifact(&self, artifact: &Artifact) -> Result<()> {
        self.stored.lock().unwrap().push(artifact.clone());
        Ok(())
    }

    async fn record_artifacts_batch(&self, artifacts: &[Artifact]) -> Result<()> {
        self.batch_attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail_remaining.load(Ordering::SeqCst) > 0 {
            self.fail_remaining.fetch_sub(1, Ordering::SeqCst);
            bail!("simulated transient DB failure");
        }
        self.stored
            .lock()
            .unwrap()
            .extend(artifacts.iter().cloned());
        Ok(())
    }

    async fn get_artifact(&self, _artifact_id: Uuid) -> Result<Option<Artifact>> {
        Ok(None)
    }
    async fn create_profile(&self, _profile: &IngestionProfile) -> Result<()> {
        Ok(())
    }
    async fn get_active_profile(&self, _case_id: Uuid) -> Result<Option<IngestionProfile>> {
        Ok(None)
    }
    async fn list_profiles(&self, _case_id: Uuid) -> Result<Vec<IngestionProfile>> {
        Ok(Vec::new())
    }
    async fn set_active_profile(&self, _case_id: Uuid, _profile_id: Uuid) -> Result<()> {
        Ok(())
    }
    async fn delete_profile(&self, _profile_id: Uuid) -> Result<()> {
        Ok(())
    }
    async fn create_job(&self, _job: &AdHocJob) -> Result<()> {
        Ok(())
    }
    async fn update_job(&self, _job: &AdHocJob) -> Result<()> {
        Ok(())
    }
    async fn get_job(&self, _job_id: Uuid) -> Result<Option<AdHocJob>> {
        Ok(None)
    }
    async fn list_jobs(&self, _case_id: Uuid) -> Result<Vec<AdHocJob>> {
        Ok(Vec::new())
    }

    async fn record_processing_log(
        &self,
        _case_id: Uuid,
        _artifact_id: Uuid,
        _module_id: &str,
        _status: &str,
        _artifacts_produced: usize,
        _error_message: Option<&str>,
        _duration_ms: u64,
    ) -> Result<()> {
        Ok(())
    }

    async fn get_processing_log_for_artifact(
        &self,
        _artifact_id: Uuid,
        _limit: Option<usize>,
    ) -> Result<Vec<ProcessingLogEntry>> {
        Ok(Vec::new())
    }

    async fn count_processing_log_for_artifact(&self, _artifact_id: Uuid) -> Result<usize> {
        Ok(0)
    }
    async fn list_jobs_for_artifact(&self, _artifact_id: Uuid) -> Result<Vec<AdHocJob>> {
        Ok(Vec::new())
    }
}

/// Module producing a fixed number of ParsedRecord artifacts per input.
struct ProducerModule {
    produce_count: usize,
}

impl ForensicsModule for ProducerModule {
    fn id(&self) -> &str {
        "test.producer"
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
    fn process(&self, artifact: &Artifact) -> std::result::Result<Vec<Artifact>, ModuleError> {
        Ok((0..self.produce_count)
            .map(|i| {
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({"index": i}),
                )
                .with_parent(artifact.id)
            })
            .collect())
    }
}

async fn run_with_flaky_db(failures: usize) -> (Arc<FlakyDb>, usize) {
    let db = Arc::new(FlakyDb::new(failures));
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100)
        .with_worker_count(2)
        .with_exit_on_idle(true);
    orchestrator.register_module(Arc::new(ProducerModule { produce_count: 3 }));

    let sender = orchestrator.task_submitter();

    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "in.bin"}),
    );

    // The submitter counts the task itself (HUNT-043).
    sender.send(artifact).unwrap();

    let run_handle = tokio::spawn(orchestrator.run());
    tokio::time::timeout(std::time::Duration::from_secs(20), run_handle)
        .await
        .expect("orchestrator must idle-exit")
        .expect("orchestrator run must not panic");

    let attempts = db.batch_attempts.load(Ordering::SeqCst);
    (db, attempts)
}

/// Transient failures within one flush must be retried with backoff and the
/// batch persisted without loss.
#[tokio::test]
async fn writer_retries_transient_batch_failures() {
    let (db, attempts) = run_with_flaky_db(2).await;

    let stored = db.stored_ids();
    assert_eq!(
        stored.len(),
        3,
        "all 3 produced artifacts must be persisted despite 2 transient failures"
    );
    assert!(
        attempts >= 3,
        "expected at least 3 batch attempts (2 failures + 1 success), got {}",
        attempts
    );
}

/// When one flush exhausts its retries, the batch must be retained and
/// persisted by a later flush tick, not dropped.
#[tokio::test]
async fn writer_retains_batch_across_failed_flush() {
    // 4 failures exhaust one full flush (initial attempt + 3 retries); the
    // batch must survive and be written on a subsequent flush.
    let (db, attempts) = run_with_flaky_db(4).await;

    let stored = db.stored_ids();
    assert_eq!(
        stored.len(),
        3,
        "batch must be retained and persisted after a fully failed flush"
    );
    assert!(
        attempts >= 5,
        "expected at least 5 batch attempts, got {}",
        attempts
    );
}

// --- One unwritable row must not hold back the valid rows beside it --------

/// DB double that refuses, with SQLite's foreign-key error, any batch that
/// contains an artifact marked `orphan` (a row whose case or parent is not in
/// the database), and stores every other batch.
struct OrphanRejectingDb {
    inner: FlakyDb,
}

#[async_trait]
impl DatabaseConnection for OrphanRejectingDb {
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
    async fn create_case(&self, _name: &str, _examiner: &str) -> Result<Uuid> {
        Ok(Uuid::new_v4())
    }
    async fn record_artifact(&self, artifact: &Artifact) -> Result<()> {
        self.record_artifacts_batch(std::slice::from_ref(artifact))
            .await
    }
    async fn record_artifacts_batch(&self, artifacts: &[Artifact]) -> Result<()> {
        self.inner.batch_attempts.fetch_add(1, Ordering::SeqCst);
        if artifacts
            .iter()
            .any(|a| a.metadata.get("orphan") == Some(&json!(true)))
        {
            bail!("(code: 787) FOREIGN KEY constraint failed");
        }
        self.inner
            .stored
            .lock()
            .unwrap()
            .extend(artifacts.iter().cloned());
        Ok(())
    }
    async fn get_artifact(&self, _id: Uuid) -> Result<Option<Artifact>> {
        Ok(None)
    }
    async fn create_profile(&self, _p: &IngestionProfile) -> Result<()> {
        Ok(())
    }
    async fn get_active_profile(&self, _c: Uuid) -> Result<Option<IngestionProfile>> {
        Ok(None)
    }
    async fn list_profiles(&self, _c: Uuid) -> Result<Vec<IngestionProfile>> {
        Ok(Vec::new())
    }
    async fn set_active_profile(&self, _c: Uuid, _p: Uuid) -> Result<()> {
        Ok(())
    }
    async fn delete_profile(&self, _p: Uuid) -> Result<()> {
        Ok(())
    }
    async fn create_job(&self, _j: &AdHocJob) -> Result<()> {
        Ok(())
    }
    async fn update_job(&self, _j: &AdHocJob) -> Result<()> {
        Ok(())
    }
    async fn get_job(&self, _j: Uuid) -> Result<Option<AdHocJob>> {
        Ok(None)
    }
    async fn list_jobs(&self, _c: Uuid) -> Result<Vec<AdHocJob>> {
        Ok(Vec::new())
    }
    async fn record_processing_log(
        &self,
        _case_id: Uuid,
        _artifact_id: Uuid,
        _module_id: &str,
        _status: &str,
        _artifacts_produced: usize,
        _error_message: Option<&str>,
        _duration_ms: u64,
    ) -> Result<()> {
        Ok(())
    }
    async fn get_processing_log_for_artifact(
        &self,
        _a: Uuid,
        _l: Option<usize>,
    ) -> Result<Vec<ProcessingLogEntry>> {
        Ok(Vec::new())
    }
    async fn count_processing_log_for_artifact(&self, _a: Uuid) -> Result<usize> {
        Ok(0)
    }
    async fn list_jobs_for_artifact(&self, _a: Uuid) -> Result<Vec<AdHocJob>> {
        Ok(Vec::new())
    }
}

/// Produces `produce_count` records per input, every third one an orphan.
struct OrphanProducer {
    produce_count: usize,
}

impl ForensicsModule for OrphanProducer {
    fn id(&self) -> &str {
        "test.orphan_producer"
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
    fn process(&self, artifact: &Artifact) -> std::result::Result<Vec<Artifact>, ModuleError> {
        Ok((0..self.produce_count)
            .map(|i| {
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({"index": i, "orphan": i % 3 == 1}),
                )
                .with_parent(artifact.id)
            })
            .collect())
    }
}

/// A batch holding one row the database cannot take (the case was deleted while
/// its ingest was still running, so its rows violate the foreign key) used to
/// fail as a whole, be retained whole, and grow until the writer's cap dropped
/// the oldest rows — which were the **valid** ones of every other case in the
/// same writer. On the NIST CFReDS Data Leakage run that dropped 610,857
/// artifacts, including most of the Windows volume's file entries. The valid
/// rows must be written; only the row that cannot be written may stay behind.
#[tokio::test]
async fn one_unwritable_row_does_not_hold_back_the_valid_rows() {
    let db = Arc::new(OrphanRejectingDb {
        inner: FlakyDb::new(0),
    });
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100)
        .with_worker_count(2)
        .with_exit_on_idle(true);
    orchestrator.register_module(Arc::new(OrphanProducer { produce_count: 9 }));

    let sender = orchestrator.task_submitter();
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "in.bin"}),
    );
    sender.send(artifact).unwrap();

    let run_handle = tokio::spawn(orchestrator.run());
    tokio::time::timeout(std::time::Duration::from_secs(30), run_handle)
        .await
        .expect("orchestrator must idle-exit")
        .expect("orchestrator run must not panic");

    let stored = db.inner.stored.lock().unwrap();
    assert_eq!(
        stored.len(),
        6,
        "the six valid rows of nine must be persisted; the three orphans cannot be"
    );
    assert!(stored
        .iter()
        .all(|a| a.metadata.get("orphan") != Some(&json!(true))));
}
