//! Tests for cooperative cancellation and progress denominators.
//!
//! Cancelling a running orchestrator must stop dispatching new work, let
//! in-flight module runs finish, emit ProcessingCancelled, and shut down
//! promptly instead of grinding through the remaining queue.

use async_trait::async_trait;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::module::{ForensicsModule, InputCapability, ModuleError};
use seance_core::orchestrator::{Orchestrator, OrchestratorEvent};
use seance_core::profile::{AdHocJob, IngestionProfile, ProcessingLogEntry};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// A module that sleeps synchronously per artifact (simulates a slow parser).
struct SlowModule {
    delay_ms: u64,
}

impl ForensicsModule for SlowModule {
    fn id(&self) -> &str {
        "test.slow"
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
        std::thread::sleep(Duration::from_millis(self.delay_ms));
        Ok(vec![])
    }
}

#[tokio::test]
async fn cancellation_emits_processing_cancelled_and_exits_promptly() {
    let mut orch = Orchestrator::new(None, 100).with_worker_count(1);
    orch.register_module(Arc::new(SlowModule { delay_ms: 300 }));

    let cancel = orch.cancellation_handle();
    let mut status_rx = orch.status_sender().subscribe();
    let case_id = Uuid::new_v4();

    // 20 artifacts x 300ms = 6s of work if run to completion.
    for i in 0..20 {
        orch.ingest_artifact(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": format!("f{}.bin", i)}),
        )
        .await
        .unwrap();
    }

    let run_handle = tokio::spawn(orch.run());

    // Let the first artifact start processing, then cancel.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let cancelled_at = Instant::now();
    cancel.cancel_all();

    // ProcessingCancelled must arrive promptly (in-flight run <= 300ms,
    // remaining queue is drained without dispatching).
    let event = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::ProcessingCancelled {
                    artifacts_processed,
                    ..
                }) => {
                    return artifacts_processed;
                }
                Ok(_) => {}
                Err(e) => panic!("status channel closed before ProcessingCancelled: {}", e),
            }
        }
    })
    .await
    .expect("ProcessingCancelled must be emitted after cancel");

    let elapsed = cancelled_at.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "cancellation must be prompt, took {:?} (would be ~6s uncancelled)",
        elapsed
    );
    // At least the in-flight artifact was processed; far fewer than all 20.
    assert!(
        event < 20,
        "cancel must not process the whole queue, got {}",
        event
    );

    // The orchestrator task itself must terminate cleanly.
    tokio::time::timeout(Duration::from_secs(10), run_handle)
        .await
        .expect("orchestrator run() must exit after cancellation")
        .expect("orchestrator task must not panic");
}

#[tokio::test]
async fn phase_progress_carries_task_denominators() {
    let mut orch = Orchestrator::new(None, 100).with_worker_count(1);
    orch.register_module(Arc::new(SlowModule { delay_ms: 1200 }));

    let cancel = orch.cancellation_handle();
    let mut status_rx = orch.status_sender().subscribe();
    let case_id = Uuid::new_v4();

    for i in 0..4 {
        orch.ingest_artifact(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": format!("f{}.bin", i)}),
        )
        .await
        .unwrap();
    }

    let run_handle = tokio::spawn(orch.run());

    // The 2s progress tick must emit PhaseProgress with a usable denominator.
    // Every PhaseProgress must satisfy the invariants; wait until one shows
    // completed work (the first tick can fire before anything finishes).
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::PhaseProgress { tasks_completed, tasks_total, .. }) => {
                    assert!(
                        tasks_total >= tasks_completed,
                        "denominator must not be smaller than completed ({} < {})",
                        tasks_total,
                        tasks_completed
                    );
                    assert!(
                        tasks_total <= 4,
                        "4 queued tasks producing nothing must never report tasks_total > 4, got {}",
                        tasks_total
                    );
                    if tasks_completed >= 1 {
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => panic!("status channel closed before PhaseProgress: {}", e),
            }
        }
    })
    .await
    .expect("PhaseProgress with completed work must be emitted while busy");

    // Shut the orchestrator down.
    cancel.cancel_all();
    tokio::time::timeout(Duration::from_secs(15), run_handle)
        .await
        .expect("orchestrator run() must exit after cancellation")
        .expect("orchestrator task must not panic");
}

/// PhaseProgress must now carry honest throughput/ETA/discovery signals plus the
/// set of running modules. With a fixed queue that produces nothing, tasks_total
/// stabilizes: the run starts "discovering" (ETA None) and, once stable with a
/// positive rate, reports an ETA. The running SlowModule must appear in
/// active_modules while it is mid-parse.
#[tokio::test]
async fn phase_progress_carries_rate_eta_and_active_modules() {
    let mut orch = Orchestrator::new(None, 256).with_worker_count(1);
    orch.register_module(Arc::new(SlowModule { delay_ms: 1000 }));

    let cancel = orch.cancellation_handle();
    let mut status_rx = orch.status_sender().subscribe();
    let case_id = Uuid::new_v4();

    // 10 x 1000ms serial work => ~10s of ticks (2s cadence) so tasks_total
    // stabilizes and the discovery->stable transition is observable.
    for i in 0..10 {
        orch.ingest_artifact(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": format!("f{}.bin", i)}),
        )
        .await
        .unwrap();
    }

    let run_handle = tokio::spawn(orch.run());

    let mut saw_discovering_true_eta_none = false;
    let mut saw_discovering_false = false;
    let mut saw_eta_some_when_stable = false;
    let mut saw_active_module = false;

    let _ = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::PhaseProgress {
                    rate_per_sec,
                    eta_seconds,
                    discovering,
                    active_modules,
                    tasks_completed,
                    tasks_total,
                    ..
                }) => {
                    assert!(rate_per_sec >= 0.0, "rate must be non-negative");
                    assert!(tasks_total >= tasks_completed);
                    if discovering {
                        assert_eq!(eta_seconds, None, "ETA must be None while discovering");
                        saw_discovering_true_eta_none = true;
                    } else {
                        saw_discovering_false = true;
                        if rate_per_sec > 0.0 && tasks_total > tasks_completed {
                            assert!(
                                eta_seconds.is_some(),
                                "ETA must be Some once stable with a positive rate"
                            );
                            saw_eta_some_when_stable = true;
                        }
                    }
                    if active_modules.iter().any(|m| m == "test.slow") {
                        saw_active_module = true;
                    }
                    if saw_discovering_true_eta_none
                        && saw_discovering_false
                        && saw_eta_some_when_stable
                        && saw_active_module
                    {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    })
    .await;

    cancel.cancel_all();
    let _ = tokio::time::timeout(Duration::from_secs(15), run_handle).await;

    assert!(
        saw_discovering_true_eta_none,
        "expected a discovering=true tick with ETA None"
    );
    assert!(
        saw_discovering_false,
        "discovering must transition to false once tasks_total stabilizes"
    );
    assert!(
        saw_eta_some_when_stable,
        "ETA must become Some once stable with a positive rate"
    );
    assert!(
        saw_active_module,
        "active_modules must report the running module id"
    );
}

// --- Per-case cancel: terminal status, stopped-module records, event order ---

/// Captures the processing-log rows the run produces.
struct LogCapturingDb {
    log: Mutex<Vec<(String, String)>>, // (module_id, status)
}

impl LogCapturingDb {
    fn new() -> Self {
        Self {
            log: Mutex::new(Vec::new()),
        }
    }
    fn rows(&self) -> Vec<(String, String)> {
        self.log.lock().unwrap().clone()
    }
}

#[async_trait]
impl DatabaseConnection for LogCapturingDb {
    async fn initialize(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn create_case(&self, _n: &str, _e: &str) -> anyhow::Result<Uuid> {
        Ok(Uuid::new_v4())
    }
    async fn record_artifact(&self, _a: &Artifact) -> anyhow::Result<()> {
        Ok(())
    }
    async fn get_artifact(&self, _id: Uuid) -> anyhow::Result<Option<Artifact>> {
        Ok(None)
    }
    async fn create_profile(&self, _p: &IngestionProfile) -> anyhow::Result<()> {
        Ok(())
    }
    async fn get_active_profile(&self, _c: Uuid) -> anyhow::Result<Option<IngestionProfile>> {
        Ok(None)
    }
    async fn list_profiles(&self, _c: Uuid) -> anyhow::Result<Vec<IngestionProfile>> {
        Ok(Vec::new())
    }
    async fn set_active_profile(&self, _c: Uuid, _p: Uuid) -> anyhow::Result<()> {
        Ok(())
    }
    async fn delete_profile(&self, _p: Uuid) -> anyhow::Result<()> {
        Ok(())
    }
    async fn create_job(&self, _j: &AdHocJob) -> anyhow::Result<()> {
        Ok(())
    }
    async fn update_job(&self, _j: &AdHocJob) -> anyhow::Result<()> {
        Ok(())
    }
    async fn get_job(&self, _j: Uuid) -> anyhow::Result<Option<AdHocJob>> {
        Ok(None)
    }
    async fn list_jobs(&self, _c: Uuid) -> anyhow::Result<Vec<AdHocJob>> {
        Ok(Vec::new())
    }
    async fn record_processing_log(
        &self,
        _c: Uuid,
        _a: Uuid,
        module_id: &str,
        status: &str,
        _p: usize,
        _e: Option<&str>,
        _d: u64,
    ) -> anyhow::Result<()> {
        self.log
            .lock()
            .unwrap()
            .push((module_id.to_string(), status.to_string()));
        Ok(())
    }
    async fn get_processing_log_for_artifact(
        &self,
        _a: Uuid,
        _l: Option<usize>,
    ) -> anyhow::Result<Vec<ProcessingLogEntry>> {
        Ok(Vec::new())
    }
    async fn count_processing_log_for_artifact(&self, _a: Uuid) -> anyhow::Result<usize> {
        Ok(0)
    }
    async fn list_jobs_for_artifact(&self, _a: Uuid) -> anyhow::Result<Vec<AdHocJob>> {
        Ok(Vec::new())
    }
}

/// Registered after `SlowModule`, so a cancel that lands mid-batch reaches it
/// before it ever runs.
struct NeverReachedModule;

impl ForensicsModule for NeverReachedModule {
    fn id(&self) -> &str {
        "test.never_reached"
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
        Ok(vec![])
    }
}

/// B5-002: `ProcessingCancelled` was emitted from exactly one place — the
/// process-wide shutdown branch. A PER-CASE cancel drained the queue, cleared
/// its own flags, and then the idle branch emitted `ProcessingComplete` because
/// artifacts had been processed. The examiner who pressed cancel was told the
/// run finished.
///
/// B5-026: the modules the cancel stopped left no processing-log row at all, so
/// "stopped before this module ran" and "never scheduled" were the same absence.
///
/// B7-025 / B7-036: `ModuleStarted` was sent on the async side while applying
/// outcomes — immediately before `ModuleCompleted`, after the work was done. The
/// live "Running: ..." view never showed anything and every module looked
/// instantaneous in the audit timeline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_per_case_cancel_ends_as_cancelled_and_records_the_modules_it_stopped() {
    let db = Arc::new(LogCapturingDb::new());
    // exit_on_idle stays false, matching the server: the 2s progress tick is the
    // only terminal-event path.
    let mut orch = Orchestrator::new(Some(db.clone()), 100).with_worker_count(1);
    orch.register_module(Arc::new(SlowModule { delay_ms: 900 }));
    orch.register_module(Arc::new(NeverReachedModule));

    let cancel = orch.cancellation_handle();
    let mut status_rx = orch.status_sender().subscribe();
    let case_id = Uuid::new_v4();

    orch.ingest_artifact(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "image.dd" }),
    )
    .await
    .unwrap();

    let run_handle = tokio::spawn(orch.run());

    // Cancel THIS CASE (not the process) while the slow module is mid-run.
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel_case(case_id);
    });

    let mut started_at: Option<Instant> = None;
    let mut completed_at: Option<Instant> = None;
    let mut saw_complete = false;
    let mut cancelled_for: Option<Option<Uuid>> = None;

    let _ = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::ModuleStarted { module_id, .. }) => {
                    if module_id == "test.slow" && started_at.is_none() {
                        started_at = Some(Instant::now());
                    }
                }
                Ok(OrchestratorEvent::ModuleCompleted { module_id, .. }) => {
                    if module_id == "test.slow" && completed_at.is_none() {
                        completed_at = Some(Instant::now());
                    }
                }
                Ok(OrchestratorEvent::ProcessingComplete { .. }) => {
                    saw_complete = true;
                    return;
                }
                Ok(OrchestratorEvent::ProcessingCancelled { case_id, .. }) => {
                    cancelled_for = Some(case_id);
                    return;
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    })
    .await;

    let _ = canceller.await;
    // Let the processing-log writer flush its 500ms batch.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let rows = db.rows();
    run_handle.abort();

    assert!(
        !saw_complete,
        "a run the examiner cancelled must never be reported as complete"
    );
    assert_eq!(
        cancelled_for,
        Some(Some(case_id)),
        "a per-case cancel must terminate with ProcessingCancelled naming its case"
    );

    // B7-025: Started has to precede the work, not trail it.
    let started = started_at.expect("ModuleStarted must be emitted for a module that ran");
    let completed = completed_at.expect("ModuleCompleted must be emitted for a module that ran");
    let gap = completed.duration_since(started);
    assert!(
        gap >= Duration::from_millis(400),
        "ModuleStarted must be sent when the module starts, not just before its \
         ModuleCompleted; the gap was only {gap:?}"
    );

    // B5-026: the module the cancel stopped must leave a record.
    assert!(
        rows.iter()
            .any(|(m, s)| m == "test.never_reached" && s == "cancelled"),
        "a module stopped by the cancel must be logged as cancelled rather than \
         simply absent; rows were {rows:?}"
    );
    assert!(
        rows.iter()
            .any(|(m, s)| m == "test.slow" && s == "complete"),
        "a module that did run must still record its outcome; rows were {rows:?}"
    );
}

// --- A cancel that drains before any artifact is processed ------------------

/// Records how the ingest run was closed and what the source was stamped with.
struct RunRecordingDb {
    inner: LogCapturingDb,
    source: Uuid,
    closed_as: Mutex<Vec<String>>,
    stamps: Mutex<Vec<(Uuid, serde_json::Value)>>,
}

#[async_trait]
impl DatabaseConnection for RunRecordingDb {
    async fn initialize(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn create_case(&self, n: &str, e: &str) -> anyhow::Result<Uuid> {
        self.inner.create_case(n, e).await
    }
    async fn record_artifact(&self, a: &Artifact) -> anyhow::Result<()> {
        self.inner.record_artifact(a).await
    }
    async fn get_artifact(&self, id: Uuid) -> anyhow::Result<Option<Artifact>> {
        self.inner.get_artifact(id).await
    }
    async fn create_profile(&self, p: &IngestionProfile) -> anyhow::Result<()> {
        self.inner.create_profile(p).await
    }
    async fn get_active_profile(&self, c: Uuid) -> anyhow::Result<Option<IngestionProfile>> {
        self.inner.get_active_profile(c).await
    }
    async fn list_profiles(&self, c: Uuid) -> anyhow::Result<Vec<IngestionProfile>> {
        self.inner.list_profiles(c).await
    }
    async fn set_active_profile(&self, c: Uuid, p: Uuid) -> anyhow::Result<()> {
        self.inner.set_active_profile(c, p).await
    }
    async fn delete_profile(&self, p: Uuid) -> anyhow::Result<()> {
        self.inner.delete_profile(p).await
    }
    async fn create_job(&self, j: &AdHocJob) -> anyhow::Result<()> {
        self.inner.create_job(j).await
    }
    async fn update_job(&self, j: &AdHocJob) -> anyhow::Result<()> {
        self.inner.update_job(j).await
    }
    async fn get_job(&self, j: Uuid) -> anyhow::Result<Option<AdHocJob>> {
        self.inner.get_job(j).await
    }
    async fn list_jobs(&self, c: Uuid) -> anyhow::Result<Vec<AdHocJob>> {
        self.inner.list_jobs(c).await
    }
    async fn record_processing_log(
        &self,
        c: Uuid,
        a: Uuid,
        m: &str,
        s: &str,
        p: usize,
        e: Option<&str>,
        d: u64,
    ) -> anyhow::Result<()> {
        self.inner.record_processing_log(c, a, m, s, p, e, d).await
    }
    async fn get_processing_log_for_artifact(
        &self,
        a: Uuid,
        l: Option<usize>,
    ) -> anyhow::Result<Vec<ProcessingLogEntry>> {
        self.inner.get_processing_log_for_artifact(a, l).await
    }
    async fn count_processing_log_for_artifact(&self, a: Uuid) -> anyhow::Result<usize> {
        self.inner.count_processing_log_for_artifact(a).await
    }
    async fn list_jobs_for_artifact(&self, a: Uuid) -> anyhow::Result<Vec<AdHocJob>> {
        self.inner.list_jobs_for_artifact(a).await
    }
    async fn mark_interrupted_ingest_runs(
        &self,
        _started_before: i64,
        _detail: &str,
    ) -> anyhow::Result<Vec<seance_core::profile::IngestRun>> {
        Ok(Vec::new())
    }
    async fn finish_ingest_runs_for_case(
        &self,
        case_id: Uuid,
        status: &str,
        finished_at: i64,
    ) -> anyhow::Result<Vec<seance_core::profile::IngestRun>> {
        self.closed_as.lock().unwrap().push(status.to_string());
        Ok(vec![seance_core::profile::IngestRun {
            id: Uuid::new_v4(),
            case_id,
            source_artifact_id: self.source,
            source_label: "image.dd".into(),
            started_at: 0,
            finished_at: Some(finished_at),
            status: status.to_string(),
            artifacts_recorded: None,
            detail: None,
        }])
    }
    async fn merge_artifact_metadata(
        &self,
        _case_id: Uuid,
        artifact_id: Uuid,
        patch: &serde_json::Value,
    ) -> anyhow::Result<u64> {
        self.stamps
            .lock()
            .unwrap()
            .push((artifact_id, patch.clone()));
        Ok(1)
    }
}

/// An examiner cancels a case right after submitting it, before any worker has
/// processed an artifact. No progress snapshot exists for the case, and only the
/// memory-stop path used to handle that: the ingest run stayed `running`, the
/// source was never stamped incomplete and no `ProcessingCancelled` was sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_before_any_artifact_is_processed_still_closes_the_run() {
    let source = Uuid::new_v4();
    let db = Arc::new(RunRecordingDb {
        inner: LogCapturingDb::new(),
        source,
        closed_as: Mutex::new(Vec::new()),
        stamps: Mutex::new(Vec::new()),
    });
    let mut orch = Orchestrator::new(Some(db.clone()), 100).with_worker_count(1);
    orch.register_module(Arc::new(SlowModule { delay_ms: 10 }));
    let cancel = orch.cancellation_handle();
    let mut status_rx = orch.status_sender().subscribe();
    let case_id = Uuid::new_v4();

    // Cancelled before the run starts, so the worker takes the early-return
    // cancel path and never records an artifact.
    cancel.cancel_case(case_id);
    orch.ingest_artifact(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "image.dd" }),
    )
    .await
    .unwrap();
    let run_handle = tokio::spawn(orch.run());

    let cancelled_for = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::ProcessingCancelled { case_id, .. }) => return case_id,
                Ok(OrchestratorEvent::ProcessingComplete { .. }) => {
                    panic!("a cancelled run must not be reported complete")
                }
                Ok(_) => {}
                Err(e) => panic!("status channel closed: {e}"),
            }
        }
    })
    .await
    .expect("ProcessingCancelled must be emitted for a cancel that drained early");
    run_handle.abort();

    assert_eq!(cancelled_for, Some(case_id));
    assert!(
        db.closed_as
            .lock()
            .unwrap()
            .iter()
            .any(|s| s == seance_core::profile::IngestRun::CANCELLED),
        "the ingest run must be closed as cancelled"
    );
    let stamps = db.stamps.lock().unwrap();
    assert!(
        stamps.iter().any(|(id, patch)| *id == source
            && patch["inventory_incomplete"] == json!(true)
            && patch["processing_state"] == json!("cancelled")),
        "the source must be stamped incomplete; stamps were {stamps:?}"
    );
}
