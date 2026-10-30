//! The orchestrator must apply `file_hash` records to the parent artifact via
//! `apply_file_hash` and drop them: they are neither persisted as visible
//! artifacts nor re-queued (so they cannot loop back into the hasher). Other
//! produced artifacts flow through the writer unchanged.

use anyhow::Result;
use async_trait::async_trait;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::Orchestrator,
    profile::{AdHocJob, IngestionProfile, ProcessingLogEntry},
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const MD5: &str = "5d41402abc4b2a76b9719d911017c592";
const SHA1: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
const SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

/// DB double recording persisted artifacts, apply_file_hash calls, and
/// hash-skipped stamps.
/// One recorded `apply` call: (case, artifact, algorithm, digest, source).
type AppliedHash = (Uuid, Uuid, String, String, String);
/// One recorded `skip`: (case, artifact, why).
type SkippedHash = (Uuid, Uuid, String);

/// One recorded processing-log row: (case, artifact, module, status, error).
type LogRow = (Uuid, Uuid, String, String, Option<String>);

struct HashApplyDb {
    stored: Mutex<Vec<Artifact>>,
    applied: Mutex<Vec<AppliedHash>>,
    skipped: Mutex<Vec<SkippedHash>>,
    log: Mutex<Vec<LogRow>>,
    /// When set, no parent row ever matches: every hash apply and every skip
    /// stamp misses, as when the parent never reaches the database.
    parent_never_lands: bool,
}

impl HashApplyDb {
    fn new() -> Self {
        Self {
            stored: Mutex::new(Vec::new()),
            applied: Mutex::new(Vec::new()),
            skipped: Mutex::new(Vec::new()),
            log: Mutex::new(Vec::new()),
            parent_never_lands: false,
        }
    }

    fn parent_never_lands() -> Self {
        Self {
            parent_never_lands: true,
            ..Self::new()
        }
    }
}

#[async_trait]
impl DatabaseConnection for HashApplyDb {
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
    async fn create_case(&self, _n: &str, _e: &str) -> Result<Uuid> {
        Ok(Uuid::new_v4())
    }

    async fn record_artifact(&self, artifact: &Artifact) -> Result<()> {
        self.stored.lock().unwrap().push(artifact.clone());
        Ok(())
    }

    async fn record_artifacts_batch(&self, artifacts: &[Artifact]) -> Result<()> {
        self.stored
            .lock()
            .unwrap()
            .extend(artifacts.iter().cloned());
        Ok(())
    }

    async fn apply_file_hash(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        md5: &str,
        sha1: &str,
        sha256: &str,
    ) -> Result<u64> {
        if self.parent_never_lands {
            return Ok(0);
        }
        self.applied.lock().unwrap().push((
            case_id,
            artifact_id,
            md5.to_string(),
            sha1.to_string(),
            sha256.to_string(),
        ));
        Ok(1) // report a matched row so the drain considers it applied
    }

    async fn mark_file_hashes_skipped_batch(
        &self,
        skips: &[(Uuid, Uuid, String)],
    ) -> Result<Vec<Uuid>> {
        if self.parent_never_lands {
            return Ok(skips.iter().map(|s| s.1).collect());
        }
        self.skipped.lock().unwrap().extend(skips.iter().cloned());
        Ok(Vec::new()) // every stamp landed
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
        c: Uuid,
        a: Uuid,
        m: &str,
        s: &str,
        _p: usize,
        e: Option<&str>,
        _d: u64,
    ) -> Result<()> {
        self.log
            .lock()
            .unwrap()
            .push((c, a, m.to_string(), s.to_string(), e.map(str::to_string)));
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

/// Emits a `file_hash` record plus one ordinary ParsedRecord per FileEntry,
/// standing in for the real FileHasher (which seance_core cannot depend on).
struct FakeHasher;

impl ForensicsModule for FakeHasher {
    fn id(&self) -> &str {
        "test.hasher"
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
        let hash = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "file_hash", "md5": MD5, "sha1": SHA1, "sha256": SHA256 }),
        )
        .with_parent(artifact.id);
        let other = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "other" }),
        )
        .with_parent(artifact.id);
        Ok(vec![hash, other])
    }
}

#[tokio::test]
async fn orchestrator_applies_and_drops_file_hash_records() {
    let db = Arc::new(HashApplyDb::new());
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100)
        .with_worker_count(2)
        .with_exit_on_idle(true);
    orchestrator.register_module(Arc::new(FakeHasher));

    let sender = orchestrator.task_submitter();

    let case_id = Uuid::new_v4();
    let file_entry = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "f.bin" }),
    );
    let file_entry_id = file_entry.id;

    // The submitter counts the task itself (HUNT-043).
    sender.send(file_entry).unwrap();

    let run_handle = tokio::spawn(orchestrator.run());
    tokio::time::timeout(std::time::Duration::from_secs(20), run_handle)
        .await
        .expect("orchestrator must idle-exit")
        .expect("orchestrator run must not panic");

    // The hash was applied to the parent FileEntry exactly once.
    let applied = db.applied.lock().unwrap();
    assert_eq!(applied.len(), 1, "apply_file_hash must be called once");
    assert_eq!(applied[0].0, case_id, "the write must be case-scoped");
    assert_eq!(applied[0].1, file_entry_id);
    assert_eq!(applied[0].2, MD5);
    assert_eq!(applied[0].3, SHA1);
    assert_eq!(applied[0].4, SHA256);

    // The file_hash record was dropped (never persisted); the ordinary record
    // still flows to the writer.
    let stored = db.stored.lock().unwrap();
    assert!(
        stored
            .iter()
            .all(|a| a.metadata.get("type").and_then(|v| v.as_str()) != Some("file_hash")),
        "file_hash records must not be persisted as artifacts"
    );
    assert!(
        stored
            .iter()
            .any(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("other")),
        "ordinary produced artifacts must still be persisted"
    );
}

/// Stands in for the real hasher refusing an oversized file: a `file_hash`
/// record carrying only `hash_skipped`, no digests.
struct SkippingHasher;

impl ForensicsModule for SkippingHasher {
    fn id(&self) -> &str {
        "test.hasher.skip"
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
        let skipped = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "file_hash", "hash_skipped": "size" }),
        )
        .with_parent(artifact.id);
        Ok(vec![skipped])
    }
}

/// B6-005: a `file_hash` record with no digests used to be silently discarded.
/// The parent kept blank hash columns and no marker, so a file too large (or
/// too broken) to hash presented exactly like a file that had been hashed and
/// matched nothing.
#[tokio::test]
async fn a_skipped_hash_is_recorded_on_the_parent_not_dropped() {
    let db = Arc::new(HashApplyDb::new());
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100)
        .with_worker_count(2)
        .with_exit_on_idle(true);
    orchestrator.register_module(Arc::new(SkippingHasher));

    let sender = orchestrator.task_submitter();

    let case_id = Uuid::new_v4();
    let file_entry = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "huge.bin" }),
    );
    let file_entry_id = file_entry.id;

    // The submitter counts the task itself (HUNT-043).
    sender.send(file_entry).unwrap();

    let run_handle = tokio::spawn(orchestrator.run());
    tokio::time::timeout(std::time::Duration::from_secs(20), run_handle)
        .await
        .expect("orchestrator must idle-exit")
        .expect("orchestrator run must not panic");

    let skipped = db.skipped.lock().unwrap();
    assert_eq!(
        skipped.len(),
        1,
        "the skip reason must reach the parent artifact, not be dropped"
    );
    assert_eq!(skipped[0].0, case_id, "the stamp must be case-scoped");
    assert_eq!(skipped[0].1, file_entry_id);
    assert_eq!(skipped[0].2, "size");

    // No digests exist, so nothing may be claimed as applied.
    assert!(
        db.applied.lock().unwrap().is_empty(),
        "a skipped hash must never present as an applied digest"
    );
}

/// Run one FileEntry through the orchestrator with `module` against a DB on
/// which the parent never lands, and return the processing-log rows written
/// for that parent with status `error`.
async fn run_with_parent_that_never_lands(
    module: Arc<dyn ForensicsModule>,
) -> (Uuid, Uuid, Vec<LogRow>) {
    let db = Arc::new(HashApplyDb::parent_never_lands());
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100)
        .with_worker_count(2)
        .with_exit_on_idle(true);
    orchestrator.register_module(module);
    let sender = orchestrator.task_submitter();
    let case_id = Uuid::new_v4();
    let file_entry = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "evidence.bin" }),
    );
    let file_entry_id = file_entry.id;
    sender.send(file_entry).unwrap();
    let run_handle = tokio::spawn(orchestrator.run());
    tokio::time::timeout(std::time::Duration::from_secs(60), run_handle)
        .await
        .expect("orchestrator must idle-exit")
        .expect("orchestrator run must not panic");
    assert!(db.applied.lock().unwrap().is_empty());
    let rows = db
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.1 == file_entry_id && r.3 == "error")
        .cloned()
        .collect();
    (case_id, file_entry_id, rows)
}

/// HUNT-199: when the apply loop exhausts its attempts, the digests it
/// computed were dropped with only a log line, and the file then looked like
/// one nobody hashed. The loss is written to the case's processing log
/// against the file, carrying the digests, so it is in the case and not only
/// in the server log.
#[tokio::test]
async fn digests_the_apply_loop_gives_up_on_are_recorded_in_the_case() {
    let (case_id, _, rows) = run_with_parent_that_never_lands(Arc::new(FakeHasher)).await;
    assert_eq!(
        rows.len(),
        1,
        "one error row for the lost digests: {rows:?}"
    );
    let (row_case, _, module, _, message) = &rows[0];
    assert_eq!(*row_case, case_id);
    assert_eq!(
        module, "test.hasher",
        "attributed to the module that hashed it"
    );
    let message = message.as_deref().expect("the row says what was lost");
    for digest in [MD5, SHA1, SHA256] {
        assert!(message.contains(digest), "{message}");
    }
    assert!(message.contains("not stored"), "{message}");
}

/// The same for a skip reason: "this file was not hashed, and why" reaches
/// the case even when the parent row it belongs on never does.
#[tokio::test]
async fn a_skip_reason_the_apply_loop_gives_up_on_is_recorded_in_the_case() {
    let (_, _, rows) = run_with_parent_that_never_lands(Arc::new(SkippingHasher)).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].2, "test.hasher.skip");
    let message = rows[0].4.as_deref().expect("message");
    assert!(message.contains("hash_skipped (size)"), "{message}");
}

/// Waits, on its own worker, until the apply loop has given up on `file_id`
/// (the error row is in the processing log), then produces the file's record —
/// the record landing after the loop stopped looking for it. Anything but the
/// trigger passes through untouched.
struct LateFileRecord {
    db: Arc<HashApplyDb>,
    file_id: Uuid,
}

impl ForensicsModule for LateFileRecord {
    fn id(&self) -> &str {
        "test.late_record"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::ParsedRecord]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, artifact: &Artifact) -> std::result::Result<Vec<Artifact>, ModuleError> {
        if artifact.metadata.get("type").and_then(|v| v.as_str()) != Some("late_trigger") {
            return Ok(Vec::new());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            let gave_up = self
                .db
                .log
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.1 == self.file_id && r.3 == "error");
            if gave_up || std::time::Instant::now() > deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let mut record = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "late_file_record", "name": "evidence.bin" }),
        );
        record.id = self.file_id;
        Ok(vec![record])
    }
}

/// HUNT-199 (b): when the file's record reaches the writer only after the
/// apply loop gave up, the digests held for it are written with that record —
/// the hash columns are filled, not left blank beside an error row — and the
/// case says the earlier loss was made good.
#[tokio::test]
async fn digests_given_up_on_are_applied_when_the_files_record_lands_later() {
    let db = Arc::new(HashApplyDb::parent_never_lands());
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100)
        .with_worker_count(2)
        .with_exit_on_idle(true);
    let case_id = Uuid::new_v4();
    let file_entry = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "evidence.bin" }),
    );
    let file_entry_id = file_entry.id;
    orchestrator.register_module(Arc::new(FakeHasher));
    orchestrator.register_module(Arc::new(LateFileRecord {
        db: db.clone(),
        file_id: file_entry_id,
    }));
    let sender = orchestrator.task_submitter();
    sender.send(file_entry).unwrap();
    sender
        .send(Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "late_trigger" }),
        ))
        .unwrap();
    let run_handle = tokio::spawn(orchestrator.run());
    tokio::time::timeout(std::time::Duration::from_secs(150), run_handle)
        .await
        .expect("orchestrator must idle-exit")
        .expect("orchestrator run must not panic");

    let log = db.log.lock().unwrap().clone();
    assert!(
        log.iter().any(|r| r.1 == file_entry_id && r.3 == "error"),
        "the loop must have given up first: {log:?}"
    );
    let stored = db.stored.lock().unwrap();
    let record = stored
        .iter()
        .find(|a| a.id == file_entry_id)
        .expect("the file's record was saved");
    for (key, digest) in [("md5", MD5), ("sha1", SHA1), ("sha256", SHA256)] {
        assert_eq!(
            record.metadata.get(key).and_then(|v| v.as_str()),
            Some(digest),
            "{key} must be written with the late record: {}",
            record.metadata
        );
    }
    assert!(
        log.iter().any(|r| r.1 == file_entry_id
            && r.3 == "complete"
            && r.4.as_deref().is_some_and(|m| m.contains("applied"))),
        "the case must say the digests were applied after all: {log:?}"
    );
}
