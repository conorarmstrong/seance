use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::{
    channel as broadcast_channel, Receiver as BroadcastReceiver, Sender as BroadcastSender,
};
use tokio::sync::mpsc::{
    channel as mpsc_channel, unbounded_channel, Receiver as MpscReceiver, Sender as MpscSender,
    UnboundedReceiver, UnboundedSender,
};
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::artifact::{Artifact, ArtifactType};
use crate::db::DatabaseConnection;
use crate::memory_guard::{self, MemoryGuard, MemoryReader, MemoryStop};
use crate::module::{ExecutionMode, ForensicsModule, ModuleError, ModuleInfo};
use crate::profile::{AdHocRequest, IngestRun, IngestionProfile};
use crate::task_queue::{CaseTaskCensus, TaskQueue, DEFAULT_QUEUE_CAPACITY};
use anyhow::Result;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event_type")]
pub enum OrchestratorEvent {
    ModuleStarted {
        case_id: Uuid,
        module_id: String,
        artifact_type: String,
    },
    ModuleCompleted {
        case_id: Uuid,
        module_id: String,
        artifacts_produced: usize,
        duration_ms: u64,
    },
    ModuleError {
        case_id: Uuid,
        module_id: String,
        /// The artifact that the module failed to process. Surfaced so the
        /// GUI can offer a "re-run this module on this artifact" link in the
        /// processing panel.
        artifact_id: Uuid,
        error: String,
    },
    ProcessingStatus {
        active_tasks: usize,
    },
    /// Emitted when a new artifact type first enters the pipeline
    PhaseStarted {
        case_id: Uuid,
        phase: String,
        artifact_type: String,
    },
    /// Periodic progress update (every 2s while processing)
    PhaseProgress {
        case_id: Uuid,
        artifacts_processed: usize,
        artifacts_by_type: Vec<(String, usize)>,
        /// Tasks fully processed so far (== artifacts_processed)
        tasks_completed: usize,
        /// Known total: completed + currently queued/in-flight. Grows as
        /// modules produce new artifacts; suitable for a progress bar.
        tasks_total: usize,
        /// Completion throughput over a short trailing window, in artifacts/sec.
        rate_per_sec: f64,
        /// Estimated seconds remaining = (tasks_total - tasks_completed) / rate.
        /// `None` while `discovering` (denominator not yet trustworthy) or before
        /// a rate can be measured; render an indeterminate bar in that case.
        eta_seconds: Option<u64>,
        /// `true` while `tasks_total` is still climbing (producers still fanning
        /// out work); `false` once it has held steady for a couple of ticks.
        discovering: bool,
        /// Module ids currently executing, for "Running: ..." UI feedback.
        active_modules: Vec<String>,
    },
    /// Emitted when processing reaches idle (active_tasks == 0)
    ProcessingComplete {
        case_id: Uuid,
        total_artifacts: usize,
        total_duration_ms: u64,
        artifacts_by_type: Vec<(String, usize)>,
    },
    /// Emitted after a cancellation request once in-flight work has drained.
    ProcessingCancelled {
        /// Case whose work was in flight when the drain completed; `None`
        /// when no case context was recorded. Consumers enforcing per-case
        /// access must withhold unscoped events from non-admins (fail closed).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        case_id: Option<Uuid>,
        artifacts_processed: usize,
    },
    /// Fine-grained progress from a single module run (rate-limited ~1/sec).
    ModuleProgress {
        /// Case the artifact belongs to. `None` only from reporters using the
        /// legacy unscoped `report`/`report_now`; consumers enforcing per-case
        /// access must withhold unscoped events from non-admins (fail closed).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        case_id: Option<Uuid>,
        module_id: String,
        artifact_id: Uuid,
        units_done: u64,
        units_total: Option<u64>,
        /// Unit of measure, e.g. "bytes" or "items"
        unit: String,
    },
    /// Progress of acquisition hashing during evidence ingest.
    AcquisitionHashProgress {
        case_id: Uuid,
        source: String,
        bytes_done: u64,
        bytes_total: u64,
        /// Number of files in the EWF segment set when `source` is the first
        /// file of a multi-part E01 image (e.g. 001.E01 .. 001.E18). `None` for
        /// single-file sources; lets the UI show "part of an N-file set".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        segment_count: Option<usize>,
        /// Combined on-disk size of every file in that set, in bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        segment_bytes_total: Option<u64>,
    },
    /// Progress of decoded-media verification hashing — the second full pass
    /// that hashes a container's decoded stream to compare against the hash the
    /// acquisition tool recorded inside it. **Only E01 records such a
    /// baseline**: `seance_container_e01` publishes `stored_md5`/`stored_sha1`
    /// and the pass runs only where they are present, so no AFF4 image is ever
    /// decoded-media verified (the AFF4 reader reads no hash from the turtle
    /// graph). Without this a large image hashed a second time in silence,
    /// which reads as a hang.
    DecodedMediaHashProgress {
        case_id: Uuid,
        artifact_id: Uuid,
        bytes_done: u64,
        /// Total size of the decoded stream, `0` when the source cannot report
        /// one (so a consumer shows an indeterminate rather than a false 100%).
        bytes_total: u64,
    },
    /// A background ingest job finished successfully.
    IngestCompleted {
        case_id: Uuid,
        artifact_id: Uuid,
    },
    /// A background ingest job failed.
    IngestFailed {
        case_id: Uuid,
        artifact_id: Uuid,
        error: String,
    },
}

/// Clonable handle for cooperative cancellation of orchestrator processing.
///
/// Cancelling stops dispatching new work; in-flight module runs finish and
/// their artifact batches are flushed (evidence is never half-written). The
/// orchestrator emits [`OrchestratorEvent::ProcessingCancelled`] once drained.
#[derive(Clone, Debug, Default)]
pub struct CancellationHandle {
    /// Global shutdown (Ctrl-C / SIGTERM): stop dispatching ALL work and let
    /// the orchestrator drain in-flight batches and exit.
    shutting_down: Arc<AtomicBool>,
    /// Case ids explicitly cancelled via the API. Cancels only that case's
    /// in-flight and queued work; the orchestrator keeps serving other cases.
    /// This is what stops a user of case A from halting case B's ingestion.
    cancelled_cases: Arc<std::sync::Mutex<std::collections::HashSet<Uuid>>>,
}

impl CancellationHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Global cancel: stop all processing and shut the orchestrator down. Used
    /// by process-level shutdown signals, never by a per-case request.
    pub fn cancel_all(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    /// Cancel a single case's processing without affecting other cases.
    pub fn cancel_case(&self, case_id: Uuid) {
        self.cancelled_cases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(case_id);
    }

    /// Clear a per-case cancel so future work for `case_id` runs again. Called
    /// when new work is explicitly submitted (fresh ingest), so a cancel drains
    /// the queued batch rather than poisoning the case until the process
    /// restarts. No-op for a case that was never cancelled.
    pub fn clear_case_cancel(&self, case_id: Uuid) {
        self.cancelled_cases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&case_id);
    }

    /// Lift every per-case cancel, and report how many were lifted.
    ///
    /// Only correct to call once the work queue is empty: at that point the
    /// cancel has done its job (every queued artifact for those cases has been
    /// discarded), and keeping the poison would silently drop unrelated later
    /// work. Called by the orchestrator loop when `active_tasks` reaches zero —
    /// never in response to a new job arriving, which is what used to let a
    /// single ad-hoc request resurrect a half-drained cancelled ingest.
    pub fn clear_all_case_cancels(&self) -> usize {
        self.take_all_case_cancels().len()
    }

    /// Lift every per-case cancel and return the case ids that were lifted.
    ///
    /// Same contract as [`Self::clear_all_case_cancels`], but the caller keeps
    /// the identities. The orchestrator needs them because a drained cancel has
    /// to end the run as *cancelled*: once the flags are cleared there is no
    /// other record that the examiner stopped this run, and the idle path would
    /// otherwise report it as a completed one.
    pub fn take_all_case_cancels(&self) -> Vec<Uuid> {
        let mut cancelled = self
            .cancelled_cases
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cancelled.drain().collect()
    }

    /// True while at least one case is under a per-case cancel.
    pub fn has_cancelled_cases(&self) -> bool {
        !self
            .cancelled_cases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// True once a global shutdown has been requested.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// True when processing for `case_id` must stop — either a global shutdown
    /// or an explicit per-case cancel.
    pub fn is_cancelled(&self, case_id: Uuid) -> bool {
        self.is_shutting_down()
            || self
                .cancelled_cases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&case_id)
    }
}

/// Lightweight, clonable progress reporter for long-running module work.
///
/// Emits [`OrchestratorEvent::ModuleProgress`] on the status bus, rate-limited
/// to at most one event per second per reporter. Cheap to clone and safe to
/// call from blocking threads.
#[derive(Clone)]
pub struct ProgressReporter {
    module_id: String,
    sender: BroadcastSender<OrchestratorEvent>,
    last_emit: Arc<std::sync::Mutex<Option<Instant>>>,
    min_interval: Duration,
}

impl ProgressReporter {
    pub fn new(sender: BroadcastSender<OrchestratorEvent>, module_id: impl Into<String>) -> Self {
        Self {
            module_id: module_id.into(),
            sender,
            last_emit: Arc::new(std::sync::Mutex::new(None)),
            min_interval: Duration::from_secs(1),
        }
    }

    /// Rate-limit gate: at most one emission per `min_interval`.
    fn should_emit(&self) -> bool {
        let mut last = self.last_emit.lock().unwrap_or_else(|e| e.into_inner());
        match *last {
            Some(t) if t.elapsed() < self.min_interval => false,
            _ => {
                *last = Some(Instant::now());
                true
            }
        }
    }

    fn emit(
        &self,
        case_id: Option<Uuid>,
        artifact_id: Uuid,
        units_done: u64,
        units_total: Option<u64>,
        unit: &str,
    ) {
        let _ = self.sender.send(OrchestratorEvent::ModuleProgress {
            case_id,
            module_id: self.module_id.clone(),
            artifact_id,
            units_done,
            units_total,
            unit: unit.to_string(),
        });
    }

    /// Report progress, rate-limited to one event per `min_interval`.
    ///
    /// Emits without case scope; retained for callers that predate
    /// case-scoped events. Prefer [`Self::report_for_case`] wherever the case
    /// is known so downstream consumers can enforce per-case access.
    pub fn report(&self, artifact_id: Uuid, units_done: u64, units_total: Option<u64>, unit: &str) {
        if !self.should_emit() {
            return;
        }
        self.emit(None, artifact_id, units_done, units_total, unit);
    }

    /// Case-scoped [`Self::report`].
    pub fn report_for_case(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        units_done: u64,
        units_total: Option<u64>,
        unit: &str,
    ) {
        if !self.should_emit() {
            return;
        }
        self.emit(Some(case_id), artifact_id, units_done, units_total, unit);
    }

    /// Report progress unconditionally (e.g. a final 100% update).
    pub fn report_now(
        &self,
        artifact_id: Uuid,
        units_done: u64,
        units_total: Option<u64>,
        unit: &str,
    ) {
        {
            let mut last = self.last_emit.lock().unwrap_or_else(|e| e.into_inner());
            *last = Some(Instant::now());
        }
        self.emit(None, artifact_id, units_done, units_total, unit);
    }

    /// Case-scoped [`Self::report_now`].
    pub fn report_now_for_case(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        units_done: u64,
        units_total: Option<u64>,
        unit: &str,
    ) {
        {
            let mut last = self.last_emit.lock().unwrap_or_else(|e| e.into_inner());
            *last = Some(Instant::now());
        }
        self.emit(Some(case_id), artifact_id, units_done, units_total, unit);
    }
}

/// Fixed ArtifactType set, ordered to match `type_index`. Lets ProgressTracker
/// key its per-type counters by a stable index into a lock-free atomic array
/// instead of a HashMap<String, _> behind a write-lock.
const TRACKED_TYPES: [ArtifactType; 11] = [
    ArtifactType::Container,
    ArtifactType::RawEvidence,
    ArtifactType::Partition,
    ArtifactType::FileSystem,
    ArtifactType::FileEntry,
    ArtifactType::FileContent,
    ArtifactType::SystemArtifact,
    ArtifactType::ParsedRecord,
    ArtifactType::TimelineEvent,
    ArtifactType::UnallocatedSpace,
    ArtifactType::SlackSpace,
];

/// Stable index of an ArtifactType into `TRACKED_TYPES`. The exhaustive match
/// makes the compiler flag any new variant so the counter array stays in sync.
fn type_index(t: &ArtifactType) -> usize {
    match t {
        ArtifactType::Container => 0,
        ArtifactType::RawEvidence => 1,
        ArtifactType::Partition => 2,
        ArtifactType::FileSystem => 3,
        ArtifactType::FileEntry => 4,
        ArtifactType::FileContent => 5,
        ArtifactType::SystemArtifact => 6,
        ArtifactType::ParsedRecord => 7,
        ArtifactType::TimelineEvent => 8,
        ArtifactType::UnallocatedSpace => 9,
        ArtifactType::SlackSpace => 10,
    }
}

/// Progress counters for ONE case's current run.
///
/// Everything an examiner is shown about "their" ingest is counted here rather
/// than process-wide: two cases can ingest concurrently in one process, and a
/// single shared counter triple stamped with whichever case wrote most recently
/// told the examiner watching case A how much of case B had been processed
/// (BUG-027 / BUG-043 / B2-115).
struct CaseProgress {
    total_processed: AtomicUsize,
    /// Artifacts fully processed (all modules finished). Unlike
    /// total_processed (incremented at start), this excludes in-flight work,
    /// so tasks_total = total_completed + active_tasks never double-counts.
    total_completed: AtomicUsize,
    /// Per-ArtifactType counts, indexed by `type_index`. Lock-free: the ingest
    /// hot path does one atomic increment per artifact instead of taking a
    /// write-lock and allocating the type-name String on every artifact.
    type_counts: [AtomicUsize; TRACKED_TYPES.len()],
    /// Whether each ArtifactType has been seen this run (drives phase-started).
    /// A `swap(true)` returns the prior state, so "is this a new phase" stays a
    /// single lock-free op.
    phases_started: [AtomicBool; TRACKED_TYPES.len()],
    /// When this case's current run started — stamped when the entry is created,
    /// i.e. on its first artifact. The reported duration used to be measured
    /// from orchestrator construction, so a 10-second ingest on a server that
    /// had been up for a quarter of an hour was reported as "complete in 914s"
    /// (LIVE-006). Cleared with the rest of the run by `reset_run`.
    started_at: Instant,
}

impl CaseProgress {
    fn new() -> Self {
        Self {
            total_processed: AtomicUsize::new(0),
            total_completed: AtomicUsize::new(0),
            type_counts: std::array::from_fn(|_| AtomicUsize::new(0)),
            phases_started: std::array::from_fn(|_| AtomicBool::new(false)),
            started_at: Instant::now(),
        }
    }
}

/// One case's progress at a single tick, as reported to that case's watchers.
struct CaseSnapshot {
    case_id: Uuid,
    /// Artifacts that entered processing (includes in-flight work).
    processed: usize,
    /// Artifacts whose modules have all finished.
    completed: usize,
    by_type: Vec<(String, usize)>,
    /// Time since this case's first artifact of the current run.
    elapsed: Duration,
}

struct ProgressTracker {
    /// Per-case counters, created on a case's first artifact of the run. The
    /// per-artifact path takes a read lock (write only for the first artifact
    /// of a case), so workers still don't serialize on the hot path.
    cases: RwLock<HashMap<Uuid, Arc<CaseProgress>>>,
    module_durations: RwLock<HashMap<String, (u64, usize)>>,
    /// In-flight module runs keyed by module id (value = concurrent run count).
    /// Drives `active_modules` on PhaseProgress so the UI can show what is
    /// currently executing during long single-module parses. A std Mutex (not an
    /// async RwLock) so the per-artifact blocking dispatch can update it around
    /// each module run without an await.
    running_modules: StdMutex<HashMap<String, usize>>,
}

impl ProgressTracker {
    fn new() -> Self {
        Self {
            cases: RwLock::new(HashMap::new()),
            module_durations: RwLock::new(HashMap::new()),
            running_modules: StdMutex::new(HashMap::new()),
        }
    }

    /// The counters for `case_id`, creating them (and stamping the case's run
    /// start) on its first artifact of the run.
    async fn case_entry(&self, case_id: Uuid) -> Arc<CaseProgress> {
        {
            let cases = self.cases.read().await;
            if let Some(progress) = cases.get(&case_id) {
                return progress.clone();
            }
        }
        self.cases
            .write()
            .await
            .entry(case_id)
            .or_insert_with(|| Arc::new(CaseProgress::new()))
            .clone()
    }

    /// Mark a module run as started (mirrors a ModuleStarted emission). Sync so
    /// it can be called from inside the per-artifact blocking dispatch.
    fn module_started(&self, module_id: &str) {
        let mut running = self
            .running_modules
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *running.entry(module_id.to_string()).or_insert(0) += 1;
    }

    /// Mark a module run as finished (mirrors a ModuleCompleted/ModuleError
    /// emission). Removes the entry once no runs remain so the map stays small.
    fn module_finished(&self, module_id: &str) {
        let mut running = self
            .running_modules
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(count) = running.get_mut(module_id) {
            *count -= 1;
            if *count == 0 {
                running.remove(module_id);
            }
        }
    }

    /// Distinct module ids currently executing.
    fn active_modules(&self) -> Vec<String> {
        self.running_modules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Record an artifact entering processing, against its own case. Returns
    /// whether this is a new phase **for that case** — case B's first FileEntry
    /// is new to case B even if case A is already deep into its own.
    async fn record_artifact(&self, artifact_type: &ArtifactType, case_id: Uuid) -> bool {
        let progress = self.case_entry(case_id).await;
        progress.total_processed.fetch_add(1, Ordering::Relaxed);
        let idx = type_index(artifact_type);
        progress.type_counts[idx].fetch_add(1, Ordering::Relaxed);

        // New phase iff this type had not been recorded yet this run.
        !progress.phases_started[idx].swap(true, Ordering::Relaxed)
    }

    /// Record an artifact whose modules have all finished, against its case.
    async fn record_completed(&self, case_id: Uuid) {
        self.case_entry(case_id)
            .await
            .total_completed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Clear per-run counters and case attribution so the next ingest wave
    /// starts from zero rather than accumulating across every run since boot.
    /// Called when the orchestrator returns to idle (no active tasks), so no
    /// artifacts are being recorded concurrently.
    async fn reset_run(&self) {
        self.cases.write().await.clear();
        self.module_durations.write().await.clear();
        self.running_modules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Artifacts that entered processing this run, across every case. Only used
    /// where a process-wide "did anything happen" answer is what is wanted.
    async fn total_processed(&self) -> usize {
        self.cases
            .read()
            .await
            .values()
            .map(|c| c.total_processed.load(Ordering::Relaxed))
            .sum()
    }

    /// One snapshot per case that has done work this run, ordered by case id so
    /// the emission order is stable.
    async fn case_snapshots(&self) -> Vec<CaseSnapshot> {
        let cases = self.cases.read().await;
        let mut snapshots: Vec<CaseSnapshot> = cases
            .iter()
            .map(|(case_id, progress)| {
                // Only types actually seen this run are reported (matches the
                // prior HashMap behaviour, which never held zero-count entries).
                let by_type: Vec<(String, usize)> = TRACKED_TYPES
                    .iter()
                    .enumerate()
                    .filter_map(|(i, t)| {
                        let count = progress.type_counts[i].load(Ordering::Relaxed);
                        (count > 0).then(|| (format!("{:?}", t), count))
                    })
                    .collect();
                CaseSnapshot {
                    case_id: *case_id,
                    processed: progress.total_processed.load(Ordering::Relaxed),
                    completed: progress.total_completed.load(Ordering::Relaxed),
                    by_type,
                    elapsed: progress.started_at.elapsed(),
                }
            })
            .collect();
        snapshots.sort_by_key(|s| s.case_id);
        snapshots
    }

    async fn record_module_duration(&self, module_id: &str, duration_ms: u64) {
        let mut durations = self.module_durations.write().await;
        let entry = durations.entry(module_id.to_string()).or_insert((0, 0));
        entry.0 += duration_ms;
        entry.1 += 1;
    }

    async fn module_summary(&self) -> Vec<(String, u64, usize)> {
        let durations = self.module_durations.read().await;
        let mut summary: Vec<_> = durations
            .iter()
            .map(|(k, (total_ms, count))| (k.clone(), *total_ms, *count))
            .collect();
        summary.sort_by_key(|b| std::cmp::Reverse(b.1)); // Sort by total time descending
        summary
    }
}

/// Derived progress statistics for a single progress tick.
struct ProgressStats {
    rate_per_sec: f64,
    discovering: bool,
    eta_seconds: Option<u64>,
}

/// Trailing-window throughput + discovery-state tracker for progress ticks.
///
/// Fed once per progress tick (~every 2s). It keeps a small ring of
/// `(instant, completed count)` samples to derive a completion rate, and tracks
/// whether `tasks_total` has stopped climbing so an ETA can be trusted. While
/// `tasks_total` is still growing (producers fanning out work) it reports
/// `discovering = true` and suppresses the ETA.
struct ThroughputTracker {
    samples: VecDeque<(Instant, usize)>,
    window: Duration,
    stable_threshold: u32,
    prev_total: Option<usize>,
    stable_ticks: u32,
}

impl ThroughputTracker {
    /// Trailing window over which the completion rate is measured.
    const RATE_WINDOW: Duration = Duration::from_secs(10);
    /// Consecutive non-increasing ticks required before `tasks_total` is
    /// considered stable (producers done enqueuing).
    const STABLE_THRESHOLD: u32 = 2;

    fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            window: Self::RATE_WINDOW,
            stable_threshold: Self::STABLE_THRESHOLD,
            prev_total: None,
            stable_ticks: 0,
        }
    }

    /// Record one tick and return the derived stats. `now` is injected rather
    /// than read internally so the derivation is deterministically testable.
    fn observe(&mut self, now: Instant, completed: usize, tasks_total: usize) -> ProgressStats {
        // Trailing-window completion rate from completed-count deltas.
        self.samples.push_back((now, completed));
        while self.samples.len() > 1 && now.duration_since(self.samples[0].0) > self.window {
            self.samples.pop_front();
        }
        let rate_per_sec = match (self.samples.front(), self.samples.back()) {
            (Some(&(t0, c0)), Some(&(t1, c1))) => {
                let span = t1.duration_since(t0).as_secs_f64();
                if span > 0.0 && c1 >= c0 {
                    (c1 - c0) as f64 / span
                } else {
                    0.0
                }
            }
            _ => 0.0,
        };

        // Discovery state: a still-climbing tasks_total means producers are
        // still enqueuing work, so the denominator is not yet trustworthy.
        match self.prev_total {
            Some(prev) if tasks_total > prev => self.stable_ticks = 0,
            Some(_) => self.stable_ticks += 1,
            None => self.stable_ticks = 0,
        }
        self.prev_total = Some(tasks_total);
        let discovering = self.stable_ticks < self.stable_threshold;

        // ETA only once the denominator is stable and a rate exists.
        let eta_seconds = if discovering || rate_per_sec <= 0.0 {
            None
        } else {
            let remaining = tasks_total.saturating_sub(completed);
            Some((remaining as f64 / rate_per_sec).ceil() as u64)
        };

        ProgressStats {
            rate_per_sec,
            discovering,
            eta_seconds,
        }
    }
}

fn phase_name(t: &ArtifactType) -> &'static str {
    match t {
        ArtifactType::Container => "Container Extraction",
        ArtifactType::RawEvidence => "Evidence Loading",
        ArtifactType::Partition => "Partition Detection",
        ArtifactType::FileSystem => "Filesystem Analysis",
        ArtifactType::FileEntry => "File Extraction",
        ArtifactType::FileContent => "Content Processing",
        ArtifactType::SystemArtifact => "Artifact Analysis",
        ArtifactType::ParsedRecord => "Record Parsing",
        ArtifactType::TimelineEvent => "Timeline Generation",
        ArtifactType::UnallocatedSpace => "Unallocated Space Analysis",
        ArtifactType::SlackSpace => "File Slack Analysis",
    }
}

/// Emit one `PhaseProgress` per case that has done work this run, each with a
/// denominator made only of that case's own work.
///
/// The denominator used to be the process-wide `active_tasks` count, which is
/// the total of every case's queued and in-flight work. That is fine for
/// deciding whether the orchestrator is busy and useless as a progress bar: with
/// a second case ingesting, case A's bar was computed against case B's queue
/// depth and case A's ETA was derived from work that was never case A's. The
/// previous mitigation — fall back to `processed` and force `discovering` as
/// soon as two cases appeared — merely swapped a wrong percentage for no
/// percentage, and did nothing at all about the window in which case B has
/// queued work but no snapshot yet, where case A was still shown case B's depth.
///
/// [`CaseTaskCensus`] answers the question the bar actually asks — how much work
/// is outstanding *for this case* — so every case gets a determinate bar and an
/// honest ETA regardless of what else the process is doing.
async fn emit_case_progress(
    progress_tracker: &ProgressTracker,
    census: &CaseTaskCensus,
    throughput: &mut HashMap<Uuid, ThroughputTracker>,
    status_broadcaster: &BroadcastSender<OrchestratorEvent>,
    now: Instant,
) {
    let snapshots = progress_tracker.case_snapshots().await;
    let active_modules = progress_tracker.active_modules();
    for snap in snapshots {
        if snap.processed == 0 {
            continue;
        }
        let completed = snap.completed;
        // Known total for THIS case: what it has finished, plus what of its own
        // is still queued or running.
        let tasks_total = completed + census.active(snap.case_id);
        let tracker = throughput
            .entry(snap.case_id)
            .or_insert_with(ThroughputTracker::new);
        let stats = tracker.observe(now, completed, tasks_total);
        let _ = status_broadcaster.send(OrchestratorEvent::PhaseProgress {
            case_id: snap.case_id,
            artifacts_processed: snap.processed,
            artifacts_by_type: snap.by_type,
            tasks_completed: completed,
            tasks_total,
            rate_per_sec: stats.rate_per_sec,
            eta_seconds: stats.eta_seconds,
            discovering: stats.discovering,
            active_modules: active_modules.clone(),
        });
    }
}

/// Close this case's `running` ingest runs and, when the run did not complete,
/// stamp each source artifact so the case says so (HUNT-113).
///
/// `stop_detail` is set when the governor ended the run for want of memory: the
/// run still closes as cancelled (the vocabulary every screen reads), but each
/// source says why.
async fn close_ingest_runs(
    db: &dyn DatabaseConnection,
    case_id: Uuid,
    cancelled: bool,
    stop_detail: Option<&str>,
) {
    let status = if cancelled {
        IngestRun::CANCELLED
    } else {
        IngestRun::COMPLETED
    };
    let closed = match db
        .finish_ingest_runs_for_case(case_id, status, chrono::Utc::now().timestamp())
        .await
    {
        Ok(closed) => closed,
        Err(e) => {
            warn!(
                "Could not close the ingest runs of case {case_id}: {e}. A run left `running` \
                 will be marked interrupted at the next start."
            );
            return;
        }
    };
    for run in closed {
        if !cancelled {
            // Only `processing_state` is set, never a clear of the
            // `inventory_incomplete` / `content_incomplete` stamps: a run's
            // `source_artifact_id` is always a freshly-created artifact (see
            // `record_ingest_run_start`), so a completing run's source was
            // never stamped by a prior interrupted run, and those keys are
            // shared with the parsers — clearing them here would erase a
            // legitimate parser incompleteness (an encrypted volume, a capped
            // listing) on a source that genuinely is incomplete.
            if let Err(e) = db
                .merge_artifact_metadata(
                    case_id,
                    run.source_artifact_id,
                    &serde_json::json!({ "processing_state": IngestRun::COMPLETED }),
                )
                .await
            {
                warn!(
                    "Could not stamp source {} of case {case_id} as completed: {e}; it will \
                     read as unfinished",
                    run.source_artifact_id
                );
            }
            continue;
        }
        stamp_source_unfinished(
            db,
            case_id,
            run.source_artifact_id,
            IngestRun::CANCELLED,
            stop_detail.unwrap_or(
                "processing of this source was cancelled by the examiner before its walk \
                 ended; what the walk had not reached is absent from this case, not from \
                 the evidence. Re-ingest the source to complete it",
            ),
        )
        .await;
    }
}

/// Mark a source whose processing never finished, in the vocabulary the census,
/// the report and every screen already read: the same `inventory_incomplete`
/// pair a parser writes for a listing it could not complete.
async fn stamp_source_unfinished(
    db: &dyn DatabaseConnection,
    case_id: Uuid,
    source: Uuid,
    state: &str,
    detail: &str,
) {
    let patch = serde_json::json!({
        "processing_state": state,
        "inventory_incomplete": true,
        "inventory_incomplete_reason": "ingest_interrupted",
        "incomplete_detail": detail,
        "content_incomplete": true,
        "content_incomplete_reason": "ingest_interrupted",
    });
    if let Err(e) = db.merge_artifact_metadata(case_id, source, &patch).await {
        warn!("Could not stamp source {source} of case {case_id} as {state}: {e}");
    }
}

/// Emit the terminal event for every case that did work in the run that just
/// went idle, then log the module summary once.
///
/// One event per case, carrying that case's own totals and its own duration:
/// a single event holding process-wide totals stamped with whichever case wrote
/// most recently reported case B's work to case A's examiner, and measured the
/// duration from orchestrator start rather than from the job.
async fn emit_run_terminal_events(
    progress_tracker: &ProgressTracker,
    status_broadcaster: &BroadcastSender<OrchestratorEvent>,
    cancellation: &CancellationHandle,
    drained_cancels: &[Uuid],
    db: Option<&Arc<dyn DatabaseConnection>>,
    memory_guard: &MemoryGuard,
) {
    let mut reported_any = false;
    // A run the memory governor ended. Taken here, once, so the stop is
    // reported against this run and the guard is re-armed for the next.
    let memory_stop: Option<MemoryStop> = memory_guard.take_stop();
    let gs = memory_guard.stats();
    if gs.budget > 0 {
        info!(
            "memory governor: budget {}, peak anonymous {}, peak resident {}, {} pressure \
             transition(s), {}s at high, {}s at critical, {} stop(s)",
            memory_guard::human_bytes(gs.budget),
            memory_guard::human_bytes(gs.peak_anon),
            memory_guard::human_bytes(gs.peak_rss),
            gs.transitions,
            gs.high_ms / 1000,
            gs.critical_ms / 1000,
            gs.stops
        );
    }
    let snapshots = progress_tracker.case_snapshots().await;
    // A cancel (the examiner's, or the memory governor's) that came before a
    // case's first artifact was processed has no snapshot, and would leave its
    // ingest run `running` to be swept as "interrupted" at the next start, with
    // the source unstamped and the UI never told. Close it here; with no stop
    // the default cancel text applies.
    let stop_detail = memory_stop.as_ref().map(|stop| stop.message(0));
    for case_id in drained_cancels {
        if snapshots.iter().any(|s| s.case_id == *case_id) {
            continue;
        }
        if let Some(db) = db {
            close_ingest_runs(db.as_ref(), *case_id, true, stop_detail.as_deref()).await;
        }
        let _ = status_broadcaster.send(OrchestratorEvent::ProcessingCancelled {
            case_id: Some(*case_id),
            artifacts_processed: 0,
        });
        warn!(
            "Processing of case {case_id} was cancelled{} before any artifact was processed; \
             the run is incomplete",
            if memory_stop.is_some() {
                " by the memory limit"
            } else {
                ""
            }
        );
    }
    for snap in snapshots {
        if snap.processed == 0 {
            continue;
        }
        reported_any = true;
        let case_id = snap.case_id;
        let total = snap.processed;
        let duration_ms = snap.elapsed.as_millis() as u64;
        // A run the examiner stopped did not complete, and must never be
        // reported as though it did. `drained_cancels` covers the cancel
        // already lifted by the 200ms tick; `is_cancelled` covers a cancel
        // still in force when this tick wins the race.
        let run_cancelled =
            drained_cancels.contains(&case_id) || cancellation.is_cancelled(case_id);
        // The durable half (HUNT-113): the ingest-run rows for this case are
        // closed now, so the next start finds nothing still `running` for a
        // walk that did in fact end. A cancelled run's sources are stamped
        // incomplete the way an interrupted one's are — the examiner stopped
        // it, and the case must not read as whole.
        if let Some(db) = db {
            let detail = memory_stop
                .as_ref()
                .filter(|_| run_cancelled)
                .map(|stop| stop.message(total));
            close_ingest_runs(db.as_ref(), case_id, run_cancelled, detail.as_deref()).await;
        }
        if run_cancelled {
            let _ = status_broadcaster.send(OrchestratorEvent::ProcessingCancelled {
                case_id: Some(case_id),
                artifacts_processed: total,
            });
            warn!(
                "Processing cancelled for case {} after {} artifacts in {:.1}s; the run is incomplete{}",
                case_id,
                total,
                duration_ms as f64 / 1000.0,
                if memory_stop.is_some() {
                    " (stopped by the memory limit)"
                } else {
                    ""
                }
            );
        } else {
            let _ = status_broadcaster.send(OrchestratorEvent::ProcessingComplete {
                case_id,
                total_artifacts: total,
                total_duration_ms: duration_ms,
                artifacts_by_type: snap.by_type,
            });
            info!(
                "Processing complete for case {}: {} artifacts in {:.1}s",
                case_id,
                total,
                duration_ms as f64 / 1000.0
            );
        }
    }

    if reported_any {
        let module_summary = progress_tracker.module_summary().await;
        if !module_summary.is_empty() {
            info!("=== Module Performance Summary ===");
            for (module_id, total_ms, count) in &module_summary {
                if *count > 0 {
                    info!(
                        "  {:<40} {:>7}ms total  {:>5} calls  {:>7.1}ms avg",
                        module_id,
                        total_ms,
                        count,
                        *total_ms as f64 / *count as f64
                    );
                }
            }
            info!("==================================");
        }
    }
}

/// Internal record sent through the processing log channel.
struct ProcessingLogRecord {
    case_id: Uuid,
    artifact_id: Uuid,
    module_id: String,
    status: String,
    artifacts_produced: usize,
    error_message: Option<String>,
    duration_ms: u64,
    /// Modules that ran over this artifact and produced nothing, folded into
    /// this one row with the time each took (HUNT-074). `None` on every other
    /// record, which is about one module.
    zero_yield: Option<Vec<(String, u64)>>,
}

/// Queue a processing-log row, applying backpressure rather than dropping it.
///
/// The processing log is the run's provenance record: which module touched
/// which artifact, whether it succeeded, skipped, errored or never ran. It is
/// what the court report's completeness section is built from. Every call site
/// used to be `let _ = sender.try_send(..)`, which silently discarded the row
/// whenever the 10k-deep channel was full — exactly when the machine is under
/// the heaviest ingest, and exactly the rows an examiner most needs. A module
/// that ran and errored then reads identically to a module that never ran.
///
/// Awaiting the send turns that hole into a brief stall bounded by the log
/// writer's flush cadence. There is no deadlock: the writer task only awaits
/// database writes and never sends back into this channel. A closed channel
/// (writer gone) is the one unavoidable loss; it is logged at `error` and
/// recorded through [`crate::evidence_loss`].
async fn record_processing_log(
    sender: &MpscSender<ProcessingLogRecord>,
    record: ProcessingLogRecord,
) {
    if let Err(e) = sender.send(record).await {
        let lost = e.0;
        error!(
            "Processing-log writer is gone; lost the '{}' record for module '{}' on artifact {} \
             (case {}). This run's provenance is incomplete.",
            lost.status, lost.module_id, lost.artifact_id, lost.case_id
        );
        crate::evidence_loss::record(
            crate::evidence_loss::LossCause::ProcessingLog,
            1,
            "processing-log writer channel closed",
            std::iter::once(format!(
                "{}:{}:{}",
                lost.module_id, lost.artifact_id, lost.status
            )),
        );
    }
}

/// RAII guard guaranteeing `active_tasks` is decremented on every exit path,
/// including early returns and panics.
///
/// Two distinct users:
///
/// * **In-flight processing** (`adopt_in_flight`, crate-internal) — the count
///   was already incremented by whoever queued the artifact, so the guard owns
///   only the matching decrement, plus the per-case in-flight mark.
/// * **Pre-queue ingest work** ([`ActiveTaskGuard::new`]) — see that
///   constructor. This is what keeps a run that has not yet queued its first
///   artifact from being mistaken for a finished one.
pub struct ActiveTaskGuard {
    active_tasks: Arc<AtomicUsize>,
    /// The case this task belongs to, when it is known. In-flight processing
    /// always knows it (it is stamped on the artifact); the pre-queue phase of
    /// an ingest that has produced no artifact yet does not, and an absent case
    /// stays absent rather than being attributed to a guess.
    case: Option<(CaseTaskCensus, Uuid)>,
}

impl ActiveTaskGuard {
    /// Mark the orchestrator busy for work that happens BEFORE the artifact it
    /// belongs to reaches the task queue, and keep it busy until the guard is
    /// dropped.
    ///
    /// Ingest is not instantaneous. Acquisition hashing (MD5 + SHA-1 + SHA-256
    /// over the whole evidence file), container probing and decompression all
    /// run before `IngestionService::ingest_artifact` sends anything, and on a
    /// real image they take minutes. An orchestrator started with
    /// `with_exit_on_idle(true)` sees an empty queue and a zero task count for
    /// that entire period, so it takes the idle branch, exits, and the ingest
    /// that follows hits a closed channel — "Failed to send artifact to queue",
    /// with nothing examined and no evidence recorded.
    ///
    /// Holding this guard across the pre-queue phase makes the run
    /// *observably* busy for its whole duration, which is the truth: work on
    /// the evidence is in progress. Callers MUST drop it before awaiting the
    /// orchestrator's completion, or the run can never go idle.
    ///
    /// A wrong answer here is not a slow answer — it is an examiner told the
    /// scan finished when nothing was ever parsed.
    pub fn new(active_tasks: Arc<AtomicUsize>) -> Self {
        active_tasks.fetch_add(1, Ordering::SeqCst);
        Self {
            active_tasks,
            case: None,
        }
    }

    /// Take ownership of the decrement for a count already incremented by the
    /// caller that queued the artifact, and mark the artifact as in flight for
    /// its own case. Does NOT increment the process-wide count.
    ///
    /// The per-case half is what lets a progress bar use a denominator made of
    /// this case's work only. The two halves are dropped together, so a case can
    /// never be left holding in-flight work that the process no longer counts.
    fn adopt_in_flight(
        active_tasks: Arc<AtomicUsize>,
        census: CaseTaskCensus,
        case_id: Uuid,
    ) -> Self {
        census.started(case_id);
        Self {
            active_tasks,
            case: Some((census, case_id)),
        }
    }
}

/// The counted way to submit an initial task to the orchestrator.
///
/// Holds the channel the pump drains and the process-wide active-task counter,
/// and increments the counter BEFORE the send, so a task is counted for the
/// whole of its life: in the channel, in the queue, and in a worker. See
/// [`Orchestrator::task_submitter`] for why the bare channel is not handed out.
#[derive(Clone)]
pub struct TaskSubmitter {
    sender: UnboundedSender<Artifact>,
    active_tasks: Arc<AtomicUsize>,
}

impl TaskSubmitter {
    pub fn new(sender: UnboundedSender<Artifact>, active_tasks: Arc<AtomicUsize>) -> Self {
        Self {
            sender,
            active_tasks,
        }
    }

    /// Whether the orchestrator's receiving side has gone away.
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Submit one artifact. The count is taken back if the orchestrator is
    /// gone and the send fails, so a refused submission is not an active task.
    pub fn send(
        &self,
        artifact: Artifact,
    ) -> Result<(), Box<tokio::sync::mpsc::error::SendError<Artifact>>> {
        self.active_tasks.fetch_add(1, Ordering::SeqCst);
        match self.sender.send(artifact) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.active_tasks.fetch_sub(1, Ordering::SeqCst);
                Err(Box::new(e))
            }
        }
    }
}

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        // Per-case first, process-wide second: the idle branch triggers on the
        // process-wide count reaching zero, and it must never observe that with
        // a case still holding work.
        if let Some((census, case_id)) = &self.case {
            census.finished(*case_id);
        }
        self.active_tasks.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Bound the retained processing-log backlog when DB writes keep failing,
/// dropping the oldest rows so a persistent write failure cannot grow the
/// buffer without limit, and recording what was dropped.
///
/// The processing log is the run's provenance record, not disposable telemetry:
/// shedding is a last resort, and it is reported through
/// [`crate::evidence_loss`] so the report does not read a shed module as one
/// that never ran. `last_error` is the write failure that forced the shed.
fn cap_processing_log_backlog(batch: &mut Vec<crate::db::ProcessingLogRow>, last_error: &str) {
    const MAX_BACKLOG: usize = 5000;
    if batch.len() <= MAX_BACKLOG {
        return;
    }
    let drop = batch.len() - MAX_BACKLOG;
    let dropped: Vec<crate::db::ProcessingLogRow> = batch.drain(0..drop).collect();
    error!(
        "EVIDENCE LOSS: processing-log backlog exceeded {}; dropped {} oldest rows ({})",
        MAX_BACKLOG, drop, last_error
    );
    record_processing_log_lost(&dropped, last_error);
}

/// Report processing-log rows that could not be saved. Never fails: it is
/// called from the error path of the write that already did.
fn record_processing_log_lost(rows: &[crate::db::ProcessingLogRow], reason: &str) {
    crate::evidence_loss::record(
        crate::evidence_loss::LossCause::ProcessingLog,
        rows.len(),
        reason,
        rows.iter()
            .map(|r| format!("{}:{}:{}", r.module_id, r.artifact_id, r.status)),
    );
}

/// Write processing-log rows with bounded exponential backoff (3 retries), for
/// the last flush, where there is no next tick to retry on.
async fn write_processing_log_with_retry(
    db: &Arc<dyn DatabaseConnection>,
    batch: &[crate::db::ProcessingLogRow],
) -> Result<()> {
    const MAX_RETRIES: u32 = 3;
    let mut delay = Duration::from_millis(100);
    let mut attempt = 0u32;
    loop {
        match db.record_processing_log_batch(batch).await {
            Ok(()) => return Ok(()),
            Err(e) if attempt >= MAX_RETRIES => return Err(e),
            Err(e) => {
                attempt += 1;
                warn!(
                    "Processing-log write failed (attempt {attempt}/{MAX_RETRIES}), retrying in \
                     {delay:?}: {e:#}"
                );
                time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
}

/// The `ModuleError` a panicking module is reported as.
fn panic_to_module_error(module_id: &str, panic: Box<dyn std::any::Any + Send>) -> ModuleError {
    let msg = panic
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic payload".to_string());
    ModuleError::FatalError(format!("Module '{module_id}' panicked: {msg}"))
}

/// Run a module with panic isolation: a panicking module is converted into a
/// `ModuleError::FatalError` instead of unwinding through the worker task
/// (which would kill the worker and leak the active_tasks count).
fn run_module_isolated(
    module: &Arc<dyn ForensicsModule>,
    artifact: &Artifact,
) -> std::result::Result<Vec<Artifact>, ModuleError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| module.process(artifact)))
        .unwrap_or_else(|panic| Err(panic_to_module_error(module.id(), panic)))
}

/// How many messages may be waiting for the artifact writer before a streaming
/// module's next batch is held back (HUNT-125).
const STREAM_WRITER_BACKLOG_MESSAGES: usize = 4;

/// [`run_module_isolated`] for the batch dispatch: the module is run through
/// [`ForensicsModule::process_streaming`], so a module that produces more than
/// it should hold can hand finished batches to `sink` as it goes (HUNT-125).
fn run_module_streaming(
    module: &Arc<dyn ForensicsModule>,
    artifact: &Artifact,
    sink: &mut dyn FnMut(Vec<Artifact>),
) -> std::result::Result<Vec<Artifact>, ModuleError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        module.process_streaming(artifact, sink)
    }))
    .unwrap_or_else(|panic| Err(panic_to_module_error(module.id(), panic)))
}

/// Keeps [`ProgressTracker::module_started`] and
/// [`ProgressTracker::module_finished`] paired even if the batch dispatch
/// unwinds. Without it, a task that dies mid-batch leaves the module in the
/// live "currently running" set forever, so the UI shows work in flight that
/// nothing will ever complete (B3-006).
struct RunningModuleGuard<'a> {
    tracker: &'a ProgressTracker,
    module_id: &'a str,
}

impl<'a> RunningModuleGuard<'a> {
    fn new(tracker: &'a ProgressTracker, module_id: &'a str) -> Self {
        tracker.module_started(module_id);
        Self { tracker, module_id }
    }
}

impl Drop for RunningModuleGuard<'_> {
    fn drop(&mut self) {
        self.tracker.module_finished(self.module_id);
    }
}

/// Whether the database refused a write over a foreign key, which names rows
/// rather than the batch and does not clear on retry.
fn is_foreign_key_refusal(e: &anyhow::Error) -> bool {
    format!("{e:#}").contains("FOREIGN KEY constraint failed")
}

/// Honour the records in a just-written `batch` that answer an earlier
/// statement: a WhatsApp backup read before the key that opens it is answered
/// later in the same ingest (ROADMAP §5.7). Applied once the batch is written,
/// so an answer and the statement it supersedes may share a batch. An answer
/// written in an earlier flush than its statement finds nothing to mark, and
/// both then stand. Pass only rows that were stored.
async fn apply_batch_supersessions(db: &dyn DatabaseConnection, batch: &[Artifact]) {
    for record in batch
        .iter()
        .filter(|a| a.metadata.get("supersedes_status").is_some())
    {
        apply_supersession(db, record).await;
    }
}

/// Write one artifact batch with bounded exponential backoff (3 retries; none
/// for a foreign-key refusal).
async fn write_batch_with_retry(
    db: &Arc<dyn DatabaseConnection>,
    batch: &[Artifact],
) -> Result<()> {
    const MAX_RETRIES: u32 = 3;
    let mut delay = Duration::from_millis(100);
    let mut attempt = 0u32;
    loop {
        match db.record_artifacts_batch(batch).await {
            Ok(()) => {
                apply_batch_supersessions(db.as_ref(), batch).await;
                return Ok(());
            }
            Err(e) => {
                // A foreign-key refusal is deterministic: retrying cannot
                // change it, and each sleep stalls the writer while the
                // bounded channel back-pressures every worker. Fail at once so
                // the caller isolates the refused rows.
                if attempt >= MAX_RETRIES || is_foreign_key_refusal(&e) {
                    return Err(e);
                }
                attempt += 1;
                warn!(
                    "Artifact batch write failed (attempt {}/{}), retrying in {:?}: {:#}",
                    attempt, MAX_RETRIES, delay, e
                );
                time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
}

/// Report artifacts that will never reach the case database. The log is not
/// enough: a dropped artifact is invisible to the report built from that
/// database, and a report that renders a complete-looking account of an
/// examination that lost evidence is the failure this codebase exists to avoid
/// (BUG-127). `what` says how they were lost; `reason` what the write failed
/// with.
fn record_artifacts_lost(ids: &[Uuid], what: &str, reason: &str) {
    error!(
        "EVIDENCE LOSS: {what}; {} artifacts not persisted: {:?} ({reason})",
        ids.len(),
        ids
    );
    crate::evidence_loss::record(
        crate::evidence_loss::LossCause::NotWritten,
        ids.len(),
        reason,
        ids.iter().map(|id| id.to_string()),
    );
}

/// A foreign-key refusal is the database naming rows, not the batch: a row
/// whose case was deleted mid-ingest (or whose parent is not written yet)
/// cannot be stored, and every valid row beside it can. Write the valid rows
/// and leave only the refused ones in `buffer`, so one bad row no longer holds
/// the whole writer — every case's rows — until the cap drops the oldest, which
/// are the valid ones (the Data Leakage run lost 610,857 artifacts this way).
async fn isolate_refused_rows(
    db: &Arc<dyn DatabaseConnection>,
    buffer: &mut Vec<Artifact>,
    late: &LateHashes,
    late_ids: &[Uuid],
) {
    let refused = write_isolating_refused_rows(db, std::mem::take(buffer)).await;
    warn!(
        "Artifact writer: {} row(s) the database refused with a foreign-key error \
         were kept for the next flush; every other row of the batch was written",
        refused.len()
    );
    *buffer = refused;
    // A late hash whose file row was refused is still owed to that
    // row: settle only the ones that were written.
    let held: std::collections::HashSet<Uuid> = buffer.iter().map(|a| a.id).collect();
    let written: Vec<Uuid> = late_ids
        .iter()
        .copied()
        .filter(|id| !held.contains(id))
        .collect();
    settle_late_hashes(db, late, &written).await;
}

/// Flush the artifact writer buffer. On persistent failure the buffer is
/// retained and retried on the next flush tick; if it grows past `max_pending`
/// the oldest overflow is dropped with a loud error!, so evidence loss is
/// never silent.
async fn flush_artifact_buffer(
    db: &Option<Arc<dyn DatabaseConnection>>,
    buffer: &mut Vec<Artifact>,
    max_pending: usize,
    late: &LateHashes,
) {
    if buffer.is_empty() {
        return;
    }
    let Some(db) = db else {
        buffer.clear();
        return;
    };
    // Hashes the apply loop gave up on travel with their file's record when it
    // is in this batch (HUNT-199). The merge is idempotent, so a failed write
    // that retains the buffer is merged again on the next flush.
    let late_ids = merge_late_hashes(buffer, late);
    match write_batch_with_retry(db, buffer).await {
        Ok(()) => {
            buffer.clear();
            settle_late_hashes(db, late, &late_ids).await;
        }
        Err(e) => {
            warn!("Artifact batch flush failed after retries; retaining {} artifacts for next flush: {}",
                  buffer.len(), e);
            if is_foreign_key_refusal(&e) {
                isolate_refused_rows(db, buffer, late, &late_ids).await;
            }
            if buffer.len() > max_pending {
                let overflow = buffer.len() - max_pending;
                let dropped_ids: Vec<Uuid> = buffer.drain(..overflow).map(|a| a.id).collect();
                record_artifacts_lost(
                    &dropped_ids,
                    &format!("artifact writer buffer exceeded cap of {max_pending}"),
                    &format!("{e:#}"),
                );
            }
        }
    }
}

/// The writer's last flush, at channel close. Retry before giving up; this is
/// the last chance to persist evidence. A foreign-key refusal is isolated as in
/// [`flush_artifact_buffer`] so one refused row does not cost the rest of the
/// buffer, and whatever still cannot be stored is recorded as lost, since there
/// is no next tick to retain it for.
async fn final_flush_artifact_buffer(
    db: &Arc<dyn DatabaseConnection>,
    buffer: &mut Vec<Artifact>,
    late: &LateHashes,
) {
    if buffer.is_empty() {
        return;
    }
    let late_ids = merge_late_hashes(buffer, late);
    match write_batch_with_retry(db, buffer).await {
        Ok(()) => {
            buffer.clear();
            settle_late_hashes(db, late, &late_ids).await;
        }
        Err(e) => {
            if is_foreign_key_refusal(&e) {
                isolate_refused_rows(db, buffer, late, &late_ids).await;
            }
            let ids: Vec<Uuid> = buffer.drain(..).map(|a| a.id).collect();
            if !ids.is_empty() {
                record_artifacts_lost(
                    &ids,
                    "final artifact flush failed after retries",
                    &format!("{e:#}"),
                );
            }
        }
    }
}

/// Write `batch` so that rows the database refuses do not stop the rest.
///
/// Splits the batch in halves until each refused row stands alone, writing every
/// half that goes in; returns the rows that would not, in their original order.
/// A batch with `k` refused rows costs `O(k log n)` writes, and only on the
/// failure path. A sub-batch that fails for any other reason than a foreign-key
/// refusal is returned whole, so a database that is down is not mistaken for a
/// set of bad rows and nothing is thrown away here.
async fn write_isolating_refused_rows(
    db: &Arc<dyn DatabaseConnection>,
    batch: Vec<Artifact>,
) -> Vec<Artifact> {
    let mut refused: Vec<(usize, Artifact)> = Vec::new();
    let mut pending: Vec<(usize, Vec<Artifact>)> = vec![(0, batch)];
    while let Some((offset, chunk)) = pending.pop() {
        if chunk.is_empty() {
            continue;
        }
        match db.record_artifacts_batch(&chunk).await {
            // Only the rows just stored are superseded-over: a refused row was
            // never written, and its answer must not mark anything.
            Ok(()) => apply_batch_supersessions(db.as_ref(), &chunk).await,
            Err(e) if is_foreign_key_refusal(&e) => {
                if chunk.len() == 1 {
                    refused.push((offset, chunk.into_iter().next().unwrap()));
                } else {
                    let mid = chunk.len() / 2;
                    let mut left = chunk;
                    let right = left.split_off(mid);
                    pending.push((offset + mid, right));
                    pending.push((offset, left));
                }
            }
            Err(_) => {
                for (i, a) in chunk.into_iter().enumerate() {
                    refused.push((offset + i, a));
                }
            }
        }
    }
    refused.sort_by_key(|(i, _)| *i);
    refused.into_iter().map(|(_, a)| a).collect()
}

/// A per-file hash awaiting application to its parent artifact. The parent is
/// written by the async artifact writer, so a hash produced right after the
/// parent is re-queued usually arrives before the parent row is flushed. These
/// are buffered and applied on the writer's flush tick (by which point the
/// parent is persisted), retried a bounded number of times.
#[derive(Clone)]
struct PendingHash {
    case_id: Uuid,
    parent_id: Uuid,
    /// The module that produced the `file_hash` record, so a give-up is
    /// attributed to it in the processing log.
    module_id: String,
    outcome: PendingHashOutcome,
    attempts: u32,
}

/// What the hasher determined about a file.
///
/// A refusal or failure to hash is a finding in its own right and has to reach
/// the parent artifact. Dropping the `Skipped` variant (as this pipeline once
/// did) left an oversized or unreadable file looking like an ordinary
/// FileEntry with blank hash columns — the same as a file nobody had got to
/// yet, and the same as a file whose digests were verified.
#[derive(Clone)]
enum PendingHashOutcome {
    Digests {
        md5: String,
        sha1: String,
        sha256: String,
    },
    Skipped {
        reason: String,
    },
}

/// How many given-up hash outcomes the writer holds, keyed by the file's
/// artifact id, waiting for that file's record to reach a saved batch
/// (HUNT-199). Each is a few hundred bytes, so the cap bounds the store to
/// tens of megabytes. Past it a give-up is not held: the processing-log row
/// written at the give-up remains the only record of the digests, and the
/// server log says the entry was not held.
const MAX_LATE_HASHES: usize = 65_536;

/// Given-up hash outcomes, keyed by the parent artifact id, checked against
/// every batch the artifact writer saves (see [`merge_late_hashes`]).
type LateHashes = Arc<StdMutex<HashMap<Uuid, PendingHash>>>;

/// Fold every held late hash whose file is in `batch` into that file's
/// metadata, so the digests (or the skip reason) are written by the same
/// INSERT, in the same transaction, as the record itself. The backend reads
/// `md5`/`sha1`/`sha256` from the metadata into the hash columns, and the skip
/// stamp is the same `content_incomplete` / `content_incomplete_reason` /
/// `hash_skipped` triple `mark_file_hashes_skipped_batch` writes. Returns the
/// ids merged; the caller drops them from the store once the batch commits.
/// A case mismatch is never merged: a parent id is only meaningful within its
/// case (B4-030).
fn merge_late_hashes(batch: &mut [Artifact], late: &LateHashes) -> Vec<Uuid> {
    let guard = late.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_empty() {
        return Vec::new();
    }
    let mut merged = Vec::new();
    for artifact in batch.iter_mut() {
        let Some(ph) = guard.get(&artifact.id) else {
            continue;
        };
        if ph.case_id != artifact.case_id {
            continue;
        }
        let Some(meta) = artifact.metadata.as_object_mut() else {
            continue;
        };
        match &ph.outcome {
            PendingHashOutcome::Digests { md5, sha1, sha256 } => {
                meta.insert("md5".into(), serde_json::Value::from(md5.as_str()));
                meta.insert("sha1".into(), serde_json::Value::from(sha1.as_str()));
                meta.insert("sha256".into(), serde_json::Value::from(sha256.as_str()));
            }
            PendingHashOutcome::Skipped { reason } => {
                meta.insert("content_incomplete".into(), serde_json::Value::Bool(true));
                meta.insert(
                    "content_incomplete_reason".into(),
                    serde_json::Value::from(format!("hash_skipped_{reason}")),
                );
                meta.insert(
                    "hash_skipped".into(),
                    serde_json::Value::from(reason.as_str()),
                );
            }
        }
        merged.push(artifact.id);
    }
    merged
}

/// After a batch carrying late hashes commits: drop them from the store and
/// write a processing-log row against each file saying the loss recorded at
/// the give-up was made good, so the earlier error row is not read alone.
async fn settle_late_hashes(db: &Arc<dyn DatabaseConnection>, late: &LateHashes, ids: &[Uuid]) {
    if ids.is_empty() {
        return;
    }
    let settled: Vec<PendingHash> = {
        let mut guard = late.lock().unwrap_or_else(|e| e.into_inner());
        ids.iter().filter_map(|id| guard.remove(id)).collect()
    };
    for ph in settled {
        let message = match &ph.outcome {
            PendingHashOutcome::Digests { md5, .. } => format!(
                "digests applied when this file's record was saved, after the apply loop had \
                 given up on it ({} attempts); the earlier error row for this file is \
                 superseded. md5 {md5}",
                ph.attempts
            ),
            PendingHashOutcome::Skipped { reason } => format!(
                "hash_skipped ({reason}) applied when this file's record was saved, after the \
                 apply loop had given up on it ({} attempts); the earlier error row for this \
                 file is superseded",
                ph.attempts
            ),
        };
        if let Err(e) = db
            .record_processing_log(
                ph.case_id,
                ph.parent_id,
                &ph.module_id,
                "complete",
                0,
                Some(&message),
                0,
            )
            .await
        {
            warn!(
                "Late hash applied to artifact {} (case {}) but its processing-log note failed: {:#}",
                ph.parent_id, ph.case_id, e
            );
        }
    }
}

/// Apply buffered file-hash outcomes to their now-persisted parents. Matches
/// are applied and removed; misses are retained (attempt-counted) for the next
/// flush; entries past the retry cap are given up on with an explicit
/// per-artifact error naming the evidence that lost its digests, written to
/// the case's processing log against the file (HUNT-199) as well as the
/// server log, and held in `late` (up to [`MAX_LATE_HASHES`]) so that if the
/// file's record is saved later, the digests are written with it.
async fn drain_pending_hashes(
    db: &Option<Arc<dyn DatabaseConnection>>,
    pending: &Arc<StdMutex<Vec<PendingHash>>>,
    late: &LateHashes,
) {
    const MAX_HASH_APPLY_ATTEMPTS: u32 = 60; // ~30s at the 500ms flush cadence
    let Some(db) = db else { return };
    let batch: Vec<PendingHash> = {
        let mut guard = pending.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    };
    if batch.is_empty() {
        return;
    }

    // The give-ups of this drain, written to the processing log once the
    // batch writes below are done.
    let mut given_up: Vec<(PendingHash, String)> = Vec::new();
    /// Give up on one entry loudly. Silence here is the failure mode the
    /// examiner cannot see: the artifact keeps empty hash columns and there is
    /// nothing in the record to say the digests were computed and then lost.
    fn give_up(given_up: &mut Vec<(PendingHash, String)>, ph: PendingHash, cause: &str) {
        match &ph.outcome {
            PendingHashOutcome::Digests { md5, .. } => error!(
                "EVIDENCE LOSS: gave up applying file hashes to artifact {} (case {}) after {} \
                 attempts ({}); md5 {} was computed but never stored, so this file has no \
                 recorded digest",
                ph.parent_id, ph.case_id, ph.attempts, cause, md5
            ),
            PendingHashOutcome::Skipped { reason } => error!(
                "EVIDENCE LOSS: gave up recording hash_skipped ({}) on artifact {} (case {}) \
                 after {} attempts ({}); this file has neither a digest nor a reason it lacks one",
                reason, ph.parent_id, ph.case_id, ph.attempts, cause
            ),
        }
        given_up.push((ph, cause.to_string()));
    }

    let (digest_entries, skip_entries): (Vec<PendingHash>, Vec<PendingHash>) = batch
        .into_iter()
        .partition(|ph| matches!(ph.outcome, PendingHashOutcome::Digests { .. }));

    let mut misses: Vec<PendingHash> = Vec::new();

    // One transaction for the whole flush instead of an autocommit UPDATE per
    // file. The batch returns the parents that matched no row (not yet
    // persisted); those are retried, attempt-counted, up to the cap.
    if !digest_entries.is_empty() {
        let tuples: Vec<(Uuid, Uuid, String, String, String)> = digest_entries
            .iter()
            .filter_map(|ph| match &ph.outcome {
                PendingHashOutcome::Digests { md5, sha1, sha256 } => Some((
                    ph.case_id,
                    ph.parent_id,
                    md5.clone(),
                    sha1.clone(),
                    sha256.clone(),
                )),
                PendingHashOutcome::Skipped { .. } => None,
            })
            .collect();

        match db.apply_file_hashes_batch(&tuples).await {
            Ok(missed_ids) => {
                let missed: std::collections::HashSet<Uuid> = missed_ids.into_iter().collect();
                for mut ph in digest_entries {
                    if !missed.contains(&ph.parent_id) {
                        continue; // applied, drop
                    }
                    ph.attempts += 1;
                    if ph.attempts < MAX_HASH_APPLY_ATTEMPTS {
                        misses.push(ph);
                    } else {
                        give_up(&mut given_up, ph, "parent never persisted");
                    }
                }
            }
            Err(e) => {
                // A transaction-level failure fails the whole flush; retry all
                // (idempotent) under the attempt cap.
                error!(
                    "Failed to apply file-hash batch ({} entries): {:#}",
                    tuples.len(),
                    e
                );
                let cause = format!("batch write failed: {e:#}");
                for mut ph in digest_entries {
                    ph.attempts += 1;
                    if ph.attempts < MAX_HASH_APPLY_ATTEMPTS {
                        misses.push(ph);
                    } else {
                        give_up(&mut given_up, ph, &cause);
                    }
                }
            }
        }
    }

    // Same retry discipline for "this file was not hashed, and here is why".
    if !skip_entries.is_empty() {
        let tuples: Vec<(Uuid, Uuid, String)> = skip_entries
            .iter()
            .filter_map(|ph| match &ph.outcome {
                PendingHashOutcome::Skipped { reason } => {
                    Some((ph.case_id, ph.parent_id, reason.clone()))
                }
                PendingHashOutcome::Digests { .. } => None,
            })
            .collect();

        match db.mark_file_hashes_skipped_batch(&tuples).await {
            Ok(missed_ids) => {
                let missed: std::collections::HashSet<Uuid> = missed_ids.into_iter().collect();
                for mut ph in skip_entries {
                    if !missed.contains(&ph.parent_id) {
                        continue;
                    }
                    ph.attempts += 1;
                    if ph.attempts < MAX_HASH_APPLY_ATTEMPTS {
                        misses.push(ph);
                    } else {
                        give_up(&mut given_up, ph, "parent never persisted");
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to record hash_skipped batch ({} entries): {:#}",
                    tuples.len(),
                    e
                );
                let cause = format!("batch write failed: {e:#}");
                for mut ph in skip_entries {
                    ph.attempts += 1;
                    if ph.attempts < MAX_HASH_APPLY_ATTEMPTS {
                        misses.push(ph);
                    } else {
                        give_up(&mut given_up, ph, &cause);
                    }
                }
            }
        }
    }

    if !misses.is_empty() {
        pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(misses);
    }

    // The parent row cannot carry the loss — it is the row that could not be
    // written to — so the loss is recorded in the processing log, which is
    // keyed by artifact id with no foreign key on it, against the file and
    // the module that hashed it. The digests travel in the message: they were
    // computed from the evidence, and this row is where they survive.
    for (ph, cause) in given_up {
        // Hold the outcome so a later save of the file's record carries it
        // (HUNT-199). Past the cap the processing-log row below is the record.
        {
            let mut held = late.lock().unwrap_or_else(|e| e.into_inner());
            if held.len() < MAX_LATE_HASHES || held.contains_key(&ph.parent_id) {
                held.insert(ph.parent_id, ph.clone());
            } else {
                warn!(
                    "late-hash store full ({} entries); the give-up for artifact {} (case {}) is \
                     not held, so only its processing-log row records it",
                    MAX_LATE_HASHES, ph.parent_id, ph.case_id
                );
            }
        }
        let message = match &ph.outcome {
            PendingHashOutcome::Digests { md5, sha1, sha256 } => format!(
                "digests computed and not stored on this file: after {} attempts ({cause}) \
                 the file's record could not be updated, so its hash columns are blank. \
                 md5 {md5}, sha1 {sha1}, sha256 {sha256}",
                ph.attempts
            ),
            PendingHashOutcome::Skipped { reason } => format!(
                "hash_skipped ({reason}) not stored on this file: after {} attempts ({cause}) \
                 the file's record could not be updated, so it carries neither a digest nor \
                 the reason it has none",
                ph.attempts
            ),
        };
        if let Err(e) = db
            .record_processing_log(
                ph.case_id,
                ph.parent_id,
                &ph.module_id,
                "error",
                0,
                Some(&message),
                0,
            )
            .await
        {
            error!(
                "EVIDENCE LOSS: could not record the hash give-up for artifact {} (case {}) in \
                 the processing log either ({:#}); only this log line holds it: {}",
                ph.parent_id, ph.case_id, e, message
            );
        }
    }
}

/// How long a case's active ingestion profile is trusted before it is re-read
/// from the database.
///
/// The cache used to be load-once-per-case: after the first artifact of a case
/// was processed, activating a different profile (triage -> deep, or a custom
/// one) changed only the database row and the UI. Live module selection stayed
/// on the profile that happened to be cached first, for the lifetime of the
/// process, with nothing anywhere saying so — an examiner who switched to a
/// deep profile got triage-scope processing and a report that claimed
/// otherwise. Two seconds is negligible against an ingest and costs at most one
/// indexed query per case per interval.
const PROFILE_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

/// Default drain-out window for an `exit_on_idle` orchestrator: how long the
/// queue must stay empty, with no active tasks, before the run is considered
/// finished. Override with [`Orchestrator::with_idle_timeout`].
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// A case's active profile as last read from the database.
///
/// `profile: None` caches the "this case has no active profile" answer (run
/// every module), which must be remembered too — otherwise every artifact of an
/// unprofiled case re-queries the database.
#[derive(Clone)]
struct CachedProfile {
    profile: Option<IngestionProfile>,
    loaded_at: Instant,
    /// Set by [`Orchestrator::set_profile`]: an explicit in-process override
    /// that the database refresh must not undo.
    pinned: bool,
}

impl CachedProfile {
    fn is_stale(&self) -> bool {
        !self.pinned && self.loaded_at.elapsed() >= PROFILE_REFRESH_INTERVAL
    }
}

/// Error message written on a job that a stopped process left pending or
/// running. It names what is known: the job did not finish and was not resumed.
/// When the process stopped is not recorded anywhere, so it is not claimed.
pub const INTERRUPTED_JOB_MESSAGE: &str = "Interrupted: the process running this job stopped \
    before it finished, and jobs are not resumed after a restart. The status was recorded \
    when the next process started, not when the job stopped. Run the module again.";
/// Detail written on an ingest run a stopped process left `running`.
const INTERRUPTED_INGEST_MESSAGE: &str = "the process that was processing this source stopped \
    before its walk ended; the interruption was recorded at the next start";

pub struct Orchestrator {
    /// The bounded, spill-to-disk work queue every worker pops from and pushes
    /// produced artifacts back into.
    queue: TaskQueue,
    /// External submission port, kept as a channel because callers outside this
    /// crate hold `UnboundedSender<Artifact>` clones of it. A pump task inside
    /// [`Orchestrator::run`] moves whatever arrives here straight into `queue`,
    /// so the channel never accumulates: it carries root ingests and ad-hoc
    /// submissions, not the pipeline's fan-out.
    task_sender: UnboundedSender<Artifact>,
    task_receiver: UnboundedReceiver<Artifact>,
    ad_hoc_sender: MpscSender<AdHocRequest>,
    ad_hoc_receiver: MpscReceiver<AdHocRequest>,
    event_broadcaster: BroadcastSender<Artifact>,
    status_broadcaster: BroadcastSender<OrchestratorEvent>,
    registry: HashMap<ArtifactType, Vec<Arc<dyn ForensicsModule>>>,
    module_lookup: HashMap<String, Arc<dyn ForensicsModule>>,
    active_profiles: Arc<RwLock<HashMap<Uuid, CachedProfile>>>, // Per-case profiles
    active_tasks: Arc<AtomicUsize>,
    cancellation: CancellationHandle,
    exit_on_idle: bool,
    /// When this orchestrator was constructed (Unix seconds). The start-up
    /// sweep of interrupted jobs stops at this instant so a job this process
    /// accepted itself is never mistaken for one a dead process left behind.
    started_at: i64,
    idle_timeout: Duration,
    db: Option<Arc<dyn DatabaseConnection>>,
    worker_count: usize, // Number of parallel workers for artifact processing
    progress_tracker: Arc<ProgressTracker>,
    processing_log_sender: MpscSender<ProcessingLogRecord>,
    processing_log_receiver: Option<MpscReceiver<ProcessingLogRecord>>,
    artifact_write_sender: MpscSender<Vec<Artifact>>,
    artifact_write_receiver: Option<MpscReceiver<Vec<Artifact>>>,
    pending_hashes: Arc<StdMutex<Vec<PendingHash>>>,
    /// The memory governor and the reader it samples; see [`crate::memory_guard`].
    memory_guard: MemoryGuard,
    memory_reader: Arc<dyn MemoryReader>,
}

/// The record a source carries when no module in this build claimed it.
///
/// Returns `None` unless every condition holds, because each of them changes
/// what the silence means:
///
/// - the artifact is an ingested **source** (`RawEvidence` with no parent), not
///   a file inside one. A file no parser reads is ordinary; a whole exhibit that
///   nothing reads is the thing an examiner must be told;
/// - at least one module actually ran over it, so "nothing claimed it" is a
///   finding rather than a description of an empty module registry;
/// - none of them failed or was cancelled — a source that produced nothing
///   because a module crashed has unknown results, not empty ones, and the
///   processing history is where that is already recorded;
/// - and nothing at all was produced.
///
/// The record carries the incompleteness pair because that is what it is: the
/// evidence is present and its contents were not recovered. It says so about
/// **this build** rather than about the file, and a later run that does parse it
/// can supersede this record the way any other answered statement is superseded.
fn unclaimed_source_record(
    artifact: &Artifact,
    produced_nothing: bool,
    modules_ran: usize,
    any_module_failed: bool,
) -> Option<Artifact> {
    if !produced_nothing
        || any_module_failed
        || modules_ran == 0
        || artifact.parent_id.is_some()
        || artifact.artifact_type != ArtifactType::RawEvidence
    {
        return None;
    }

    let string_field = |key: &str| {
        artifact
            .metadata
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    let name = string_field("name").unwrap_or_else(|| "this source".to_string());
    // What the source was taken to be, in the order the answer is trustworthy:
    // what a parser detected, then what the examiner declared, then neither.
    let detected = string_field("detected_type")
        .or_else(|| string_field("content_type"))
        .or_else(|| {
            string_field("user_specified_type")
                .filter(|t| t != "auto")
                .map(|t| format!("declared as {t}"))
        });

    let metadata = serde_json::json!({
        "type": "SourceUnparsed",
        "name": format!("{name} — no module in this build parses it"),
        "source_name": name,
        "source_path": string_field("path"),
        "detected_type": detected,
        "modules_run": modules_ran,
        "inventory_incomplete": true,
        "inventory_incomplete_reason": crate::io::IncompleteReason::UnresolvedStructure.as_str(),
        "inventory_incomplete_detail": format!(
            "{modules_ran} module(s) ran over this source and none of them claimed it"
        ),
        "message": format!(
            "{modules_ran} module(s) ran over this source and none of them produced anything \
             from it: no parser in this build reads this format. This is a statement about \
             this build, not about the evidence — the source may well hold data another tool, \
             or a later version of this one, can read. Nothing below it is missing because the \
             evidence was empty."
        ),
    });

    Some(
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id),
    )
}

/// Mark what an earlier run of this module left under the same parent as
/// superseded by this run's record.
///
/// Parsed records are matched by their record `type`, timeline events by the
/// `source_module` that wrote them — a re-run of the mail parser says nothing
/// about the signature analysis or the EXIF events sitting beside its output.
/// `seen` keeps it to one statement per (parent, kind): the run's later records
/// of the same kind belong to this run too.
async fn supersede_earlier_run(
    db: &dyn DatabaseConnection,
    new_art: &Artifact,
    run_started_at: &str,
    module_id: &str,
    seen: &mut HashSet<(Uuid, String, String)>,
) {
    let Some(parent_id) = new_art.parent_id else {
        return;
    };
    let (field, value) = match new_art.metadata.get("type").and_then(|v| v.as_str()) {
        Some(record_type) => ("type", record_type.to_string()),
        None => match new_art
            .metadata
            .get("source_module")
            .and_then(|v| v.as_str())
        {
            Some(source_module) => ("source_module", source_module.to_string()),
            // Nothing on this record says what kind it is, so nothing can be
            // said about which earlier record it answers. Leaving both standing
            // is the honest outcome.
            None => return,
        },
    };
    if !seen.insert((parent_id, field.to_string(), value.clone())) {
        return;
    }
    match db
        .supersede_records_from_an_earlier_run(
            new_art.case_id,
            parent_id,
            field,
            &value,
            run_started_at,
            new_art.id,
            module_id,
        )
        .await
    {
        Ok(0) => {}
        Ok(n) => info!(
            "Re-run of {module_id}: {n} record(s) of {value} under {parent_id} marked superseded"
        ),
        Err(e) => warn!(
            "Re-run of {module_id}: an earlier run's {value} records under {parent_id} could \
             not be marked superseded, so both runs' answers stand: {e}"
        ),
    }
}

/// Whether an ad-hoc run that carried a credential goes on to persist what the
/// module produced.
#[derive(Debug, PartialEq, Eq)]
enum CredentialSettlement {
    /// Persist the records as any re-run would; they supersede the locked
    /// statement.
    Continue,
    /// The job has been closed and nothing the module produced is recorded.
    Stop,
}

/// Act on what a module did with an examiner-supplied credential (HUNT-120).
///
/// * **Accepted** — the records are persisted by the ordinary path, and the
///   HUNT-107 supersession marks the earlier "locked" statement superseded.
/// * **Rejected** — nothing the module produced is recorded. Its own output
///   would be another "could not unlock" record, and persisting it would
///   supersede the one already standing; a wrong password is an attempt, not a
///   new finding about the evidence. The job fails saying so.
/// * **Not used** — the module never looked at the secret (the artifact was not
///   of the kind it opens). Nothing is recorded, and the job says why.
///
/// Each outcome is written to the audit log with the kind of secret, never its
/// value.
#[allow(clippy::too_many_arguments)]
async fn settle_credential_run(
    db: &dyn DatabaseConnection,
    log_sender: &MpscSender<ProcessingLogRecord>,
    artifact: &Artifact,
    job_id: Uuid,
    module_id: &str,
    kind: crate::credential::CredentialKind,
    requested_by: &str,
    outcome: Option<crate::credential::CredentialOutcome>,
    module_returned_ok: bool,
    duration_ms: u64,
) -> CredentialSettlement {
    use crate::credential::CredentialOutcome;
    if !module_returned_ok {
        // The ordinary error path records the failure; the audit says the
        // attempt ended in a module error, not in a verdict on the secret.
        audit_credential_outcome(
            db,
            artifact,
            job_id,
            module_id,
            kind,
            requested_by,
            "module_error",
            None,
        )
        .await;
        return CredentialSettlement::Continue;
    }
    let (label, message) = match outcome {
        Some(CredentialOutcome::Accepted) => {
            audit_credential_outcome(
                db,
                artifact,
                job_id,
                module_id,
                kind,
                requested_by,
                "accepted",
                None,
            )
            .await;
            return CredentialSettlement::Continue;
        }
        Some(CredentialOutcome::Rejected { reason }) => {
            let message = format!(
                "The supplied {} did not open this artifact ({reason}). Nothing in the case \
                 changed: the record saying it is locked still stands.",
                kind.label()
            );
            audit_credential_outcome(
                db,
                artifact,
                job_id,
                module_id,
                kind,
                requested_by,
                "rejected",
                Some(&reason),
            )
            .await;
            ("rejected", message)
        }
        None => {
            let message = format!(
                "The supplied {} was not used: {module_id} found nothing on this artifact that \
                 it opens with one. Nothing in the case changed.",
                kind.label()
            );
            audit_credential_outcome(
                db,
                artifact,
                job_id,
                module_id,
                kind,
                requested_by,
                "not_used",
                None,
            )
            .await;
            ("not_used", message)
        }
    };
    info!(
        "Credential run on {} by {}: {} {} ({})",
        artifact.id,
        module_id,
        kind.as_str(),
        label,
        requested_by
    );
    record_processing_log(
        log_sender,
        ProcessingLogRecord {
            case_id: artifact.case_id,
            artifact_id: artifact.id,
            module_id: module_id.to_string(),
            status: "error".to_string(),
            artifacts_produced: 0,
            error_message: Some(message.clone()),
            zero_yield: None,
            duration_ms,
        },
    )
    .await;
    fail_job(db, job_id, &message).await;
    CredentialSettlement::Stop
}

/// Close a job as failed with `message` (never a secret). A job that cannot be
/// read or updated is logged: a job left `running` with nothing saying why is
/// the silent failure this exists to prevent.
async fn fail_job(db: &dyn DatabaseConnection, job_id: Uuid, message: &str) {
    match db.get_job(job_id).await {
        Ok(Some(mut job)) => {
            job.status = crate::profile::JobStatus::Failed;
            job.error_message = Some(message.to_string());
            job.artifacts_produced = 0;
            job.completed_at = Some(chrono::Utc::now().timestamp());
            if let Err(e) = db.update_job(&job).await {
                error!("Failed to mark job {job_id} failed ({message}): {e}");
            }
        }
        Ok(None) => error!("Job {job_id} not found; could not record its failure: {message}"),
        Err(e) => error!("Could not read job {job_id} to record its failure ({message}): {e}"),
    }
}

/// The audit row for a credential attempt's outcome: who, which artifact,
/// which kind of secret, which module, which job, and what happened. The value
/// is not an argument, so it cannot reach the row.
#[allow(clippy::too_many_arguments)]
async fn audit_credential_outcome(
    db: &dyn DatabaseConnection,
    artifact: &Artifact,
    job_id: Uuid,
    module_id: &str,
    kind: crate::credential::CredentialKind,
    requested_by: &str,
    outcome: &str,
    reason: Option<&str>,
) {
    let mut details = format!(
        "kind={}; module={}; job={}; outcome={}",
        kind.as_str(),
        module_id,
        job_id,
        outcome
    );
    if let Some(reason) = reason {
        details.push_str(&format!("; reason={reason}"));
    }
    if let Err(e) = db
        .record_audit_event(
            Some(artifact.case_id),
            requested_by,
            "credential_outcome",
            Some("artifact"),
            Some(artifact.id),
            Some(&details),
        )
        .await
    {
        error!(
            "The outcome of a credential attempt on {} could not be written to the audit \
             log ({}): {}",
            artifact.id, outcome, e
        );
    }
}

/// Apply the supersession a produced record declares, if it declares one.
///
/// A module that answers an earlier refusal emits a record carrying
/// `supersedes_status`: the `status` value, of records of its own `type` under
/// the same parent, that its existence makes out of date. The earlier records
/// are marked, never deleted — that the refusal happened is itself part of the
/// case — and the census then reads only the current statement (HUNT-090).
///
/// Failure is logged and never fails the run: the new record is already in the
/// case, and refusing the run because a mark did not land would lose the
/// answer as well as the marking of the question.
async fn apply_supersession(db: &dyn crate::db::DatabaseConnection, record: &Artifact) {
    let Some(status) = record
        .metadata
        .get("supersedes_status")
        .and_then(|v| v.as_str())
    else {
        return;
    };
    // Which field carries that value. `status` is the usual one; the memory
    // stages call theirs `analysis_stage`, and a record says which it means
    // rather than the matcher guessing.
    let field = record
        .metadata
        .get("supersedes_field")
        .and_then(|v| v.as_str())
        .unwrap_or("status");
    let Some(record_type) = record.metadata.get("type").and_then(|v| v.as_str()) else {
        warn!(
            "record {} declares supersedes_status but carries no type; nothing marked",
            record.id
        );
        return;
    };
    let Some(parent_id) = record.parent_id else {
        warn!(
            "record {} declares supersedes_status but has no parent; the scope of the \
             supersession cannot be established, so nothing is marked",
            record.id
        );
        return;
    };

    match db
        .mark_records_superseded(
            record.case_id,
            parent_id,
            record_type,
            field,
            status,
            record.id,
        )
        .await
    {
        Ok(0) => debug!(
            "record {} supersedes {} '{}' records: none were present to mark",
            record.id, record_type, status
        ),
        Ok(n) => info!(
            "record {} supersedes {} earlier {} '{}' record(s)",
            record.id, n, record_type, status
        ),
        Err(e) => error!(
            "record {} supersedes {} '{}' records and the mark failed, so the earlier \
             statement still counts as missing data: {}",
            record.id, record_type, status, e
        ),
    }
}

impl Orchestrator {
    pub fn new(db: Option<Arc<dyn DatabaseConnection>>, buffer_size: usize) -> Self {
        // The task queue is [`TaskQueue`]: bounded in memory, spilled to disk,
        // and lossless. It replaced an unbounded channel, which had no bound at
        // all (an ext4 image producing 80K+ FileEntry artifacts held every one
        // of them in full until a worker got to it, and a large enough image
        // simply exhausted memory). A bounded *channel* is not the answer
        // either: workers here are both producers and consumers, so a blocking
        // `send().await` parks the very task that would have drained the queue —
        // classic deadlock. See `task_queue` for the whole argument.
        const AD_HOC_QUEUE_CAPACITY: usize = 1_000; // Ad-hoc requests are rare

        const PROCESSING_LOG_CAPACITY: usize = 10_000;
        const ARTIFACT_WRITE_CAPACITY: usize = 10_000;

        let (task_sender, task_receiver) = unbounded_channel();
        let (ad_hoc_sender, ad_hoc_receiver) = mpsc_channel(AD_HOC_QUEUE_CAPACITY);
        let (event_broadcaster, _) = broadcast_channel(buffer_size);
        let (status_broadcaster, _) = broadcast_channel(1024);
        let (processing_log_sender, processing_log_receiver) =
            mpsc_channel(PROCESSING_LOG_CAPACITY);
        let (artifact_write_sender, artifact_write_receiver) =
            mpsc_channel(ARTIFACT_WRITE_CAPACITY);

        // Default to number of CPU cores for parallelism; `SEANCE_WORKERS`
        // overrides it, which is how a memory peak is attributed to what each
        // worker holds in flight (HUNT-114) and how a small host is told to
        // run fewer parses at once.
        let worker_count = std::env::var("SEANCE_WORKERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
            });

        let active_tasks = Arc::new(AtomicUsize::new(0));
        let queue = TaskQueue::new(DEFAULT_QUEUE_CAPACITY, active_tasks.clone());
        let memory_reader: Arc<dyn MemoryReader> = Arc::new(memory_guard::ProcReader::default());
        let memory_guard = MemoryGuard::from_env(memory_reader.as_ref());

        Self {
            queue,
            task_sender,
            task_receiver,
            ad_hoc_sender,
            ad_hoc_receiver,
            event_broadcaster,
            status_broadcaster,
            registry: HashMap::new(),
            module_lookup: HashMap::new(),
            active_profiles: Arc::new(RwLock::new(HashMap::new())),
            active_tasks,
            cancellation: CancellationHandle::new(),
            exit_on_idle: false,
            started_at: chrono::Utc::now().timestamp(),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            db,
            worker_count,
            progress_tracker: Arc::new(ProgressTracker::new()),
            processing_log_sender,
            processing_log_receiver: Some(processing_log_receiver),
            artifact_write_sender,
            artifact_write_receiver: Some(artifact_write_receiver),
            pending_hashes: Arc::new(StdMutex::new(Vec::new())),
            memory_guard,
            memory_reader,
        }
    }

    /// Replace the memory governor and the reader it samples. The default is
    /// configured from `SEANCE_MEMORY_LIMIT`; this is how a test or an
    /// embedder supplies its own budget or a fixed reading.
    pub fn with_memory_guard(mut self, guard: MemoryGuard, reader: Arc<dyn MemoryReader>) -> Self {
        self.memory_guard = guard;
        self.memory_reader = reader;
        self
    }

    /// The governor this orchestrator consults; valid after `run()` has taken
    /// ownership, for reading pressure and peak usage.
    pub fn memory_guard(&self) -> MemoryGuard {
        self.memory_guard.clone()
    }

    /// Set the number of parallel workers (default: CPU core count)
    pub fn with_worker_count(mut self, count: usize) -> Self {
        self.worker_count = count.max(1); // At least 1 worker
        self
    }

    /// How many queued artifacts are held in memory before the queue spills to
    /// disk (default [`DEFAULT_QUEUE_CAPACITY`]).
    ///
    /// Lowering this trades disk I/O for resident memory; nothing is ever
    /// dropped at either setting. Must be called before any work is queued —
    /// it replaces the queue, so anything already in it would be discarded, and
    /// this asserts rather than losing it silently.
    pub fn with_queue_capacity(mut self, capacity: usize) -> Self {
        assert!(
            self.queue.is_empty(),
            "with_queue_capacity must be set before any artifact is queued"
        );
        self.queue = TaskQueue::new(capacity, self.active_tasks.clone());
        self
    }

    pub fn with_exit_on_idle(mut self, enabled: bool) -> Self {
        self.exit_on_idle = enabled;
        self
    }

    /// How long the queue must stay empty, with no active tasks, before an
    /// `exit_on_idle` orchestrator shuts down (default
    /// [`DEFAULT_IDLE_TIMEOUT`]).
    ///
    /// Pre-queue ingest work does not leave the queue empty — see
    /// [`ActiveTaskGuard::new`] — so this window is about drain-out, not about
    /// waiting for a caller to start. Shortening it is what makes that race
    /// testable in bounded time.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Submitter for initial tasks. Whatever is sent here is moved into the
    /// bounded [`TaskQueue`] by the pump task in `run()`.
    ///
    /// A [`TaskSubmitter`] rather than the raw channel sender, because the
    /// count has to move with the send: the pump decrements `active_tasks` for
    /// a submission it must reject and the worker's guard decrements it when
    /// the task completes, so a caller that sent on the bare channel without
    /// incrementing first drove the counter through zero to `usize::MAX` — the
    /// figure `/api/v1/status` reports and `exit_on_idle` waits on (HUNT-043).
    pub fn task_submitter(&self) -> TaskSubmitter {
        TaskSubmitter::new(self.task_sender.clone(), self.active_tasks.clone())
    }

    /// A handle on the bounded work queue: its per-case census and its spill
    /// statistics. Cheap to clone, and valid after `run()` has taken ownership
    /// of the orchestrator.
    pub fn task_queue(&self) -> TaskQueue {
        self.queue.clone()
    }

    /// Per-case breakdown of outstanding work — the denominator a single case's
    /// progress is entitled to, as opposed to the process-wide
    /// [`Orchestrator::active_tasks`] count.
    pub fn case_census(&self) -> CaseTaskCensus {
        self.queue.census()
    }

    // Receiver for consuming broadcast events (e.g., for SSE or TUI updates)
    pub fn event_receiver(&self) -> BroadcastReceiver<Artifact> {
        self.event_broadcaster.subscribe()
    }

    // Sender for broadcasting events (e.g., for SSE or TUI updates)
    pub fn event_sender(&self) -> BroadcastSender<Artifact> {
        self.event_broadcaster.clone()
    }

    // Sender for broadcasting orchestrator status events
    pub fn status_sender(&self) -> BroadcastSender<OrchestratorEvent> {
        self.status_broadcaster.clone()
    }

    // Active task counter
    pub fn active_tasks(&self) -> Arc<AtomicUsize> {
        self.active_tasks.clone()
    }

    /// Clonable handle for cancelling processing (e.g. from an API endpoint).
    pub fn cancellation_handle(&self) -> CancellationHandle {
        self.cancellation.clone()
    }

    /// Create a progress reporter bound to this orchestrator's status bus.
    pub fn progress_reporter(&self, module_id: impl Into<String>) -> ProgressReporter {
        ProgressReporter::new(self.status_broadcaster.clone(), module_id)
    }

    // Create an ingestion service for properly ingesting initial artifacts
    pub fn ingestion_service(&self) -> crate::ingestion::IngestionService {
        crate::ingestion::IngestionService::new(
            self.db.clone(),
            self.task_sender.clone(),
            self.event_broadcaster.clone(),
            self.active_tasks.clone(),
        )
        .with_status_sender(self.status_broadcaster.clone())
    }

    /// Returns information about all registered modules.
    pub fn module_info_list(&self) -> Vec<ModuleInfo> {
        self.module_lookup
            .values()
            .map(|m| ModuleInfo {
                id: m.id().to_string(),
                version: m.version().to_string(),
                subscribes_to: m
                    .subscribes_to()
                    .iter()
                    .map(|t| format!("{:?}", t))
                    .collect(),
                execution_mode: format!("{:?}", m.execution_mode()),
            })
            .collect()
    }

    pub fn register_module(&mut self, module: Arc<dyn ForensicsModule>) {
        let module_id = module.id().to_string();
        if module.execution_mode() == ExecutionMode::Automatic {
            for subscribed_type in module.subscribes_to() {
                debug!(
                    "Registering module '{}' (v{}) for artifact type {:?}",
                    module_id,
                    module.version(),
                    subscribed_type
                );
                self.registry
                    .entry(subscribed_type)
                    .or_default()
                    .push(module.clone());
            }
        } else {
            info!("Module '{}' registered as opt-in (ad-hoc only)", module_id);
        }
        // All modules (including opt-in) available for ad-hoc execution
        self.module_lookup.insert(module_id.clone(), module);
    }

    /// Set the active ingestion profile for a case.
    ///
    /// An explicit in-process override: it PINS the entry, so the periodic
    /// database refresh cannot replace it. Activating a profile through the API
    /// writes the database row instead, and reaches running workers via that
    /// refresh.
    pub async fn set_profile(&self, case_id: Uuid, profile: Option<IngestionProfile>) {
        let mut profiles = self.active_profiles.write().await;
        match &profile {
            Some(p) => info!(
                "Setting active profile for case {}: '{}' with {} enabled modules",
                case_id,
                p.name,
                p.enabled_modules.len()
            ),
            None => info!(
                "Clearing active profile for case {} (all modules will run)",
                case_id
            ),
        }
        profiles.insert(
            case_id,
            CachedProfile {
                profile,
                loaded_at: Instant::now(),
                pinned: true,
            },
        );
    }

    /// Get a sender for submitting ad-hoc execution requests
    pub fn ad_hoc_submitter(&self) -> MpscSender<AdHocRequest> {
        self.ad_hoc_sender.clone()
    }

    /// Check if a module should run under the current profile for a case.
    ///
    /// The pipeline calls [`Self::should_run_module_static`] from its spawned
    /// workers, which hold no `&self`; this instance form exists for the tests,
    /// which drive an `Orchestrator` directly.
    #[cfg(test)]
    async fn should_run_module(&self, case_id: Uuid, module_id: &str) -> bool {
        Self::should_run_module_static(case_id, module_id, &self.active_profiles).await
    }

    /// Queue an already-formed artifact directly.
    ///
    /// This path records **no acquisition baseline**: no MD5/SHA-1/SHA-256 over
    /// the source, no `integrity_checks` row, no secret scrubbing of the
    /// metadata it persists. Ingesting evidence through it produces artifacts
    /// with nothing to verify a later copy against, so evidence ingest goes
    /// through [`crate::ingestion::IngestionService::ingest_artifact`] — which
    /// this orchestrator hands out via
    /// [`Orchestrator::ingestion_service`] — and this entry point is for
    /// callers that have no source file to hash.
    pub async fn ingest_artifact(
        &self,
        case_id: Uuid,
        artifact_type: ArtifactType,
        data: Option<Arc<dyn crate::data_source::DataSource>>,
        metadata: serde_json::Value,
    ) -> Result<(), ModuleError> {
        let artifact = Artifact::new(case_id, artifact_type, data, metadata);
        info!(
            "Ingesting initial artifact: {:?} (ID: {}) for case {}",
            artifact.artifact_type, artifact.id, artifact.case_id
        );

        if let Some(db_conn) = &self.db {
            db_conn.record_artifact(&artifact).await.map_err(|e| {
                ModuleError::FatalError(format!("Failed to record initial artifact to DB: {}", e))
            })?;
        }

        self.active_tasks.fetch_add(1, Ordering::SeqCst);
        if let Err(rejected) = self.queue.push(artifact) {
            // The artifact never reached the queue, so no worker will ever run
            // the matching decrement. Roll it back or `active_tasks` stays
            // above zero for the life of the process: an `exit_on_idle` run
            // then never reaches its idle branch, never emits
            // `ProcessingComplete`, and the caller that reported this failure
            // hangs on the orchestrator instead of exiting on it. Same rule as
            // `IngestionService::persist_and_queue`.
            self.active_tasks.fetch_sub(1, Ordering::SeqCst);
            return Err(ModuleError::FatalError(format!(
                "Failed to send artifact to queue: {:?}",
                rejected.id
            )));
        }
        Ok(())
    }

    pub async fn run(mut self) {
        info!(
            "Orchestrator starting with {} parallel workers (Exit on idle: {})...",
            self.worker_count, self.exit_on_idle
        );

        // A job still pending or running in the database was queued in the
        // memory of a process that has stopped; nothing will run it. Mark it
        // failed, and say why, before any screen can read it as work in
        // progress. This runs before a single request is accepted.
        if let Some(db) = self.db.as_ref() {
            match db
                .fail_interrupted_jobs(self.started_at, INTERRUPTED_JOB_MESSAGE)
                .await
            {
                Ok(jobs) => {
                    for job in &jobs {
                        warn!(
                            "Job {} ({}) in case {} was left unfinished by a stopped process; \
                             marked failed",
                            job.id, job.module_id, job.case_id
                        );
                    }
                    if !jobs.is_empty() {
                        warn!(
                            "{} job(s) interrupted by an earlier shutdown were marked failed",
                            jobs.len()
                        );
                    }
                }
                Err(e) => warn!(
                    "Could not sweep interrupted jobs: {}. A job left pending or running by a \
                     stopped process still shows that status.",
                    e
                ),
            }

            // The same for ingest runs (HUNT-113): a walk queued by a process
            // that stopped never ends, and the case it left behind reads as
            // complete unless its source says otherwise.
            match db
                .mark_interrupted_ingest_runs(self.started_at, INTERRUPTED_INGEST_MESSAGE)
                .await
            {
                Ok(runs) => {
                    for run in &runs {
                        let recorded = run.artifacts_recorded.unwrap_or(0);
                        warn!(
                            "Ingest of {} in case {} was left unfinished by a stopped process \
                             with {} artifacts recorded; marked interrupted",
                            run.source_label, run.case_id, recorded
                        );
                        stamp_source_unfinished(
                            db.as_ref(),
                            run.case_id,
                            run.source_artifact_id,
                            IngestRun::INTERRUPTED,
                            &format!(
                                "processing of this source was interrupted by a stopped \
                                 process; {recorded} artifacts were recorded under it before \
                                 it stopped, and what its walk had not reached is absent from \
                                 this case, not from the evidence. Re-ingest the source to \
                                 complete it"
                            ),
                        )
                        .await;
                    }
                }
                Err(e) => warn!(
                    "Could not sweep interrupted ingest runs: {}. A source whose processing a \
                     stopped process never finished still reads as complete.",
                    e
                ),
            }
        }

        // Wrap shared state in Arc for worker tasks
        let registry = Arc::new(self.registry);
        let active_profiles = self.active_profiles.clone();
        let event_broadcaster = self.event_broadcaster.clone();
        let status_broadcaster = self.status_broadcaster.clone();
        let queue = self.queue.clone();
        let census = self.queue.census();
        let active_tasks = self.active_tasks.clone();
        let db = self.db.clone();
        let progress_tracker = self.progress_tracker.clone();
        let log_sender = self.processing_log_sender.clone();
        let cancellation = self.cancellation.clone();

        // Spawn background artifact writer — sole DB writer for pipeline artifacts
        let artifact_db = self.db.clone();
        let writer_pending_hashes = self.pending_hashes.clone();
        let writer_late_hashes: LateHashes = Arc::new(StdMutex::new(HashMap::new()));
        let mut artifact_receiver = self
            .artifact_write_receiver
            .take()
            .expect("artifact_write_receiver already taken");
        let artifact_writer_handle = tokio::spawn(async move {
            const FLUSH_THRESHOLD: usize = 1000;
            // Cap on artifacts retained across failed flushes. Beyond this the
            // oldest overflow is dropped (loudly) to bound memory.
            const MAX_PENDING: usize = 100_000;
            let mut buffer: Vec<Artifact> = Vec::with_capacity(1000);
            let mut flush_interval = time::interval(Duration::from_millis(500));
            flush_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    batch = artifact_receiver.recv() => {
                        match batch {
                            Some(artifacts) => {
                                buffer.extend(artifacts);
                                if buffer.len() >= FLUSH_THRESHOLD {
                                    flush_artifact_buffer(&artifact_db, &mut buffer, MAX_PENDING, &writer_late_hashes).await;
                                    // Parents just flushed: apply any buffered hashes.
                                    drain_pending_hashes(&artifact_db, &writer_pending_hashes, &writer_late_hashes).await;
                                }
                            }
                            None => {
                                // Channel closed: final flush. Retry before giving
                                // up; this is the last chance to persist evidence.
                                if let Some(db) = &artifact_db {
                                    final_flush_artifact_buffer(db, &mut buffer, &writer_late_hashes).await;
                                }
                                // Final drain: keep applying buffered hashes until
                                // all parents are matched or the retry cap is hit.
                                for _ in 0..60 {
                                    drain_pending_hashes(&artifact_db, &writer_pending_hashes, &writer_late_hashes).await;
                                    if writer_pending_hashes.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
                                        break;
                                    }
                                    time::sleep(Duration::from_millis(200)).await;
                                }
                                debug!("Artifact writer shutting down");
                                break;
                            }
                        }
                    }
                    _ = flush_interval.tick() => {
                        flush_artifact_buffer(&artifact_db, &mut buffer, MAX_PENDING, &writer_late_hashes).await;
                        drain_pending_hashes(&artifact_db, &writer_pending_hashes, &writer_late_hashes).await;
                    }
                }
            }
        });

        // Spawn background processing log writer
        let log_db = self.db.clone();
        let mut log_receiver = self
            .processing_log_receiver
            .take()
            .expect("processing_log_receiver already taken");
        let log_writer_handle = tokio::spawn(async move {
            let mut batch: Vec<crate::db::ProcessingLogRow> = Vec::with_capacity(100);
            let mut flush_interval = time::interval(Duration::from_millis(500));
            flush_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    record = log_receiver.recv() => {
                        match record {
                            Some(r) => {
                                batch.push(crate::db::ProcessingLogRow {
                                    case_id: r.case_id,
                                    artifact_id: r.artifact_id,
                                    module_id: r.module_id,
                                    status: r.status,
                                    artifacts_produced: r.artifacts_produced,
                                    error_message: r.error_message,
                                    duration_ms: r.duration_ms,
                                    zero_yield: r.zero_yield,
                                });
                                if batch.len() >= 100 {
                                    if let Some(db) = &log_db {
                                        match db.record_processing_log_batch(&batch).await {
                                            Ok(()) => batch.clear(),
                                            Err(e) => {
                                                // Retain for retry rather than dropping the log
                                                // entries; bound memory if failures persist.
                                                warn!("Failed to flush processing log batch: {}", e);
                                                cap_processing_log_backlog(&mut batch, &format!("{e:#}"));
                                            }
                                        }
                                    } else {
                                        batch.clear();
                                    }
                                }
                            }
                            None => {
                                // Channel closed, flush remaining
                                if !batch.is_empty() {
                                    if let Some(db) = &log_db {
                                        if let Err(e) = write_processing_log_with_retry(db, &batch).await {
                                            error!(
                                                "EVIDENCE LOSS: final processing-log flush failed after \
                                                 retries; {} rows not saved: {:#}",
                                                batch.len(), e
                                            );
                                            record_processing_log_lost(&batch, &format!("{e:#}"));
                                        }
                                    }
                                }
                                debug!("Processing log writer shutting down");
                                break;
                            }
                        }
                    }
                    _ = flush_interval.tick() => {
                        if !batch.is_empty() {
                            if let Some(db) = &log_db {
                                match db.record_processing_log_batch(&batch).await {
                                    Ok(()) => batch.clear(),
                                    Err(e) => {
                                        warn!("Failed to flush processing log batch on timer: {}", e);
                                        cap_processing_log_backlog(&mut batch, &format!("{e:#}"));
                                    }
                                }
                            } else {
                                batch.clear();
                            }
                        }
                    }
                }
            }
        });

        // Pump: move externally submitted artifacts into the bounded queue.
        //
        // `task_submitter()` hands out `UnboundedSender<Artifact>` clones that
        // live in other crates, so the submission port stays a channel. Draining
        // it straight into the queue is what keeps it from becoming the
        // unbounded backlog again: the channel holds only what has arrived since
        // the pump last ran, and the queue (which spills) holds the rest.
        let mut submitted = self.task_receiver;
        let pump_queue = self.queue.clone();
        let pump_active_tasks = self.active_tasks.clone();
        let pump_handle = tokio::spawn(async move {
            while let Some(artifact) = submitted.recv().await {
                if let Err(rejected) = pump_queue.push(artifact) {
                    // Submitted after the run finished. Say which artifact was
                    // not examined, and release the count its submitter took.
                    error!(
                        "EVIDENCE NOT EXAMINED: artifact {} ({:?}, case {}) was submitted after \
                         the task queue closed and will not be processed",
                        rejected.id, rejected.artifact_type, rejected.case_id
                    );
                    pump_active_tasks.fetch_sub(1, Ordering::SeqCst);
                }
            }
            // The submission port is gone; nothing else can arrive from outside.
            pump_queue.close();
        });

        // The memory governor's monitor. Samples every 250 ms and publishes the
        // pressure the workers gate on. Under High it shrinks the queue's
        // in-memory window so new work spills at once; when Critical outlasts
        // its grace period it cancels every case with outstanding work, which
        // is the same clean path an examiner's cancel takes (in-flight batches
        // flush, queued work drains unprocessed, sources are stamped
        // incomplete), and records why for the terminal event.
        memory_guard::apply_oom_score_adj_from_env();
        let monitor_handle = {
            let guard = self.memory_guard.clone();
            let queue = self.queue.clone();
            let census = self.queue.census();
            let cancellation = self.cancellation.clone();
            let busy_tasks = self.active_tasks.clone();
            tokio::spawn(guard.run_monitor(
                self.memory_reader.clone(),
                move || busy_tasks.load(Ordering::SeqCst) > 0,
                {
                    let queue = queue.clone();
                    move |pressure| {
                        queue.set_window(
                            (pressure >= memory_guard::Pressure::High)
                                .then_some(memory_guard::HIGH_PRESSURE_QUEUE_WINDOW),
                        );
                    }
                },
                move |_stop| {
                    for (case_id, _) in census.snapshot() {
                        cancellation.cancel_case(case_id);
                    }
                },
            ))
        };

        // Spawn worker tasks for parallel artifact processing
        let artifact_write_sender = self.artifact_write_sender.clone();
        let mut worker_handles = Vec::with_capacity(self.worker_count);
        for worker_id in 0..self.worker_count {
            let registry = registry.clone();
            let active_profiles = active_profiles.clone();
            let event_broadcaster = event_broadcaster.clone();
            let status_broadcaster = status_broadcaster.clone();
            let queue = queue.clone();
            let active_tasks = active_tasks.clone();
            let db = db.clone();
            let progress_tracker = progress_tracker.clone();
            let log_sender = log_sender.clone();
            let artifact_write_sender = artifact_write_sender.clone();
            let cancellation = cancellation.clone();
            let pending_hashes = self.pending_hashes.clone();
            let memory_guard = self.memory_guard.clone();

            let handle = tokio::spawn(async move {
                debug!("Worker {} started", worker_id);
                // Workers park inside `pop()` rather than contending on a shared
                // receiver lock, and push their own produced artifacts straight
                // back into the same queue — which never blocks a producer, so
                // the producer/consumer deadlock a bounded channel would cause
                // cannot arise.
                while let Some(art) = queue.pop().await {
                    // The memory governor's gate: free while pressure is Ok,
                    // one task at a time while High, closed while Critical
                    // until pressure falls or the run is stopped. Held for the
                    // whole task, so a blocked worker parks here with the
                    // artifact it already owns rather than taking another.
                    let _admission = memory_guard.admit().await;
                    // A stop is only ever seen here by the worker that was parked
                    // when it fired (a popped artifact is in neither the queue
                    // nor the in-flight census, so the monitor's snapshot cannot
                    // name its case), and by anything that arrives after it. Each
                    // cancels its own case, so the run drains as cancelled and is
                    // never reported complete.
                    if memory_guard.is_stopped() {
                        cancellation.cancel_case(art.case_id);
                    }
                    Self::process_artifact_worker(
                        art,
                        &registry,
                        &active_profiles,
                        &event_broadcaster,
                        &status_broadcaster,
                        &queue,
                        &active_tasks,
                        &db,
                        &progress_tracker,
                        &log_sender,
                        &artifact_write_sender,
                        &cancellation,
                        &pending_hashes,
                    )
                    .await;
                }
                debug!("Worker {} shutting down: task queue drained", worker_id);
            });
            worker_handles.push(handle);
        }

        // Main loop handles ad-hoc requests, progress reporting, and idle timeout
        let exit_on_idle = self.exit_on_idle;
        let idle_window = self.idle_timeout;
        let active_tasks_check = self.active_tasks.clone();
        let module_lookup = Arc::new(self.module_lookup.clone());
        // Ad-hoc jobs run one at a time, as they did when the main loop ran them
        // inline; what changed is that the loop is no longer blocked while one runs.
        let ad_hoc_slot = Arc::new(tokio::sync::Semaphore::new(1));
        let mut ad_hoc_receiver = self.ad_hoc_receiver;
        let db_adhoc = self.db.clone();
        let event_broadcaster_adhoc = self.event_broadcaster.clone();
        let status_broadcaster_adhoc = self.status_broadcaster.clone();
        let queue_adhoc = self.queue.clone();
        let active_tasks_adhoc = self.active_tasks.clone();
        let progress_tracker_main = self.progress_tracker.clone();
        let log_sender_adhoc = self.processing_log_sender.clone();

        let mut progress_interval = time::interval(Duration::from_secs(2));
        progress_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut was_busy = false;
        // Trailing-window rate + discovery-state for honest ETA on PhaseProgress,
        // one per case: two cases ingesting at once have their own throughputs,
        // and a shared window would report each the other's rate.
        let mut throughput: HashMap<Uuid, ThroughputTracker> = HashMap::new();

        // Fast poll so cancellation exits promptly instead of waiting for the
        // 2s progress tick or the idle timeout.
        let mut cancel_interval = time::interval(Duration::from_millis(200));
        cancel_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let cancellation_main = self.cancellation.clone();
        let memory_guard_main = self.memory_guard.clone();
        let db_main = self.db.clone();
        // For the depth line below: what the task queue is holding, so a memory
        // peak can be attributed rather than guessed at (HUNT-114). The queue is
        // an Arc and safe to hold; the write/log channels are NOT sampled here,
        // because holding a Sender clone for the run keeps the channel open past
        // shutdown and the writer never drains.
        let stats_queue = self.queue.clone();
        let mut depth_ticks: u32 = 0;
        // Set when a per-case cancel is lifted after draining, and consumed by
        // the idle branch below. A drained per-case cancel clears its own flags,
        // so without this the idle path can no longer tell a stopped run from a
        // finished one and reports `ProcessingComplete` — telling an examiner
        // who cancelled mid-ingest that the run finished. Holds the cases whose
        // cancel drained, so the terminal event names the right case.
        let mut drained_cancels: Vec<Uuid> = Vec::new();

        // Idle timeout: pinned outside the loop so it persists across select! iterations.
        // The progress_interval tick (2s) would otherwise recreate time::sleep each iteration,
        // preventing the timeout from ever completing.
        let idle_timeout = time::sleep(idle_window);
        tokio::pin!(idle_timeout);

        loop {
            tokio::select! {
                ad_hoc_result = ad_hoc_receiver.recv() => {
                    match ad_hoc_result {
                        Some(request) => {
                            // Receiving an ad-hoc job does NOT lift the case's
                            // cancel: that let one "run module" request
                            // resurrect an ingest the examiner had stopped,
                            // because the poison is what makes the queued
                            // artifacts drain unprocessed. The cancel clears
                            // itself below, once the queue is actually empty.
                            //
                            // The job runs on its own task so this loop keeps
                            // ticking while a long module (the deep carver, an
                            // archive brute force) works: cancel, progress,
                            // the memory governor and terminal events must not
                            // stall behind it. The guard keeps the orchestrator
                            // busy for as long as the job is queued or running,
                            // so an idle exit cannot overtake it.
                            let busy = ActiveTaskGuard::new(active_tasks_adhoc.clone());
                            let module_lookup = module_lookup.clone();
                            let db = db_adhoc.clone();
                            let events = event_broadcaster_adhoc.clone();
                            let status = status_broadcaster_adhoc.clone();
                            let queue = queue_adhoc.clone();
                            let active_tasks = active_tasks_adhoc.clone();
                            let log_sender = log_sender_adhoc.clone();
                            let cancellation = cancellation_main.clone();
                            let slot = ad_hoc_slot.clone();
                            tokio::spawn(async move {
                                let _busy = busy;
                                let Ok(_slot) = slot.acquire_owned().await else {
                                    return;
                                };
                                Self::process_ad_hoc_request_static(
                                    request,
                                    &module_lookup,
                                    &db,
                                    &events,
                                    &status,
                                    &queue,
                                    &active_tasks,
                                    &log_sender,
                                    &cancellation,
                                ).await;
                            });
                        }
                        None => {
                            warn!("Ad-hoc request queue disconnected.");
                        }
                    }
                }
                _ = cancel_interval.tick() => {
                    // A per-case cancel exists to make queued work drain
                    // unprocessed. Once nothing is queued or in flight, it has
                    // done exactly that, and holding it any longer would
                    // silently discard work submitted afterwards. Lifting it
                    // here (rather than when a new job arrives) is what keeps a
                    // cancel from being undone mid-drain.
                    if active_tasks_check.load(Ordering::SeqCst) == 0
                        && cancellation_main.has_cancelled_cases()
                    {
                        let lifted = cancellation_main.take_all_case_cancels();
                        info!("Cancellation drained; lifted {} per-case cancel(s)", lifted.len());
                        // Remember it so the terminal event for this run is
                        // `ProcessingCancelled`, not `ProcessingComplete`.
                        drained_cancels.extend(lifted);
                    }
                    if cancellation_main.is_shutting_down()
                        && active_tasks_check.load(Ordering::SeqCst) == 0
                    {
                        // One terminal event per case that did work. A single
                        // process-wide total stamped with one case's id told
                        // that case's examiner how much of ANOTHER case had
                        // been processed.
                        let snapshots = progress_tracker_main.case_snapshots().await;
                        let total: usize = snapshots.iter().map(|s| s.processed).sum();
                        if snapshots.is_empty() {
                            let _ = status_broadcaster_adhoc.send(OrchestratorEvent::ProcessingCancelled {
                                case_id: None,
                                artifacts_processed: 0,
                            });
                        } else {
                            for snap in &snapshots {
                                let _ = status_broadcaster_adhoc.send(OrchestratorEvent::ProcessingCancelled {
                                    case_id: Some(snap.case_id),
                                    artifacts_processed: snap.processed,
                                });
                            }
                        }
                        info!("Processing cancelled after {} artifacts. Shutting down.", total);
                        break;
                    }
                }
                _ = progress_interval.tick() => {
                    let active = active_tasks_check.load(Ordering::SeqCst);
                    if active > 0 {
                        // New busy period: measure rate/discovery from scratch.
                        if !was_busy {
                            throughput.clear();
                            // `was_busy` only goes false once the previous run has
                            // reported its terminal event, so this is a NEW run.
                            // A cancel lifted from the previous one must not
                            // label it: a completeness warning that fires on runs
                            // nobody stopped is one examiners learn to ignore.
                            drained_cancels.clear();
                        }
                        was_busy = true;
                        // Every fifth 2 s tick while busy: how deep each stage's
                        // queue is. A walk of 40,000 small files peaked at
                        // 9.5 GB resident and nothing said where the bytes
                        // were; this line is what attributes such a peak.
                        depth_ticks += 1;
                        if depth_ticks.is_multiple_of(5) {
                            let q = stats_queue.stats();
                            info!(
                                "queue depths: active_tasks={active} task_queue resident={} \
                                 spilled={} (peak_resident={}, spilled_total={}, spill_failures={})",
                                q.resident,
                                q.spilled,
                                q.peak_resident,
                                q.spilled_total,
                                q.spill_failures,
                            );
                        }
                        // Reset idle timer while busy
                        idle_timeout.as_mut().reset(time::Instant::now() + idle_window);
                        emit_case_progress(
                            &progress_tracker_main,
                            &census,
                            &mut throughput,
                            &status_broadcaster_adhoc,
                            Instant::now(),
                        ).await;
                    } else {
                        // Idle. Complete a run when we saw it busy on an earlier
                        // tick, OR when a fast run finished ENTIRELY between two
                        // ticks (so `was_busy` was never armed) but still
                        // processed work. `total_processed` is non-zero after
                        // such a run and cleared by reset_run below, so idle
                        // ticks with no work are a no-op (an empty case map).
                        // Without this, a sub-2s ingest never emits
                        // ProcessingComplete and the UI stalls on its last phase.
                        let processed = progress_tracker_main.total_processed().await;
                        // A cancel that drained before any artifact was
                        // processed arms neither `was_busy` nor the counter,
                        // yet its run must still be closed and reported.
                        if was_busy
                            || processed > 0
                            || memory_guard_main.is_stopped()
                            || !drained_cancels.is_empty()
                        {
                            was_busy = false;
                            emit_run_terminal_events(
                                &progress_tracker_main,
                                &status_broadcaster_adhoc,
                                &cancellation_main,
                                &drained_cancels,
                                db_main.as_ref(),
                                &memory_guard_main,
                            ).await;
                            // Idle again: clear per-run counters/case so the next
                            // ingest wave reports its own case and a fresh count.
                            progress_tracker_main.reset_run().await;
                        }
                        // The cancel belonged to the run just terminated; a later
                        // run must not inherit it.
                        drained_cancels.clear();
                    }
                }
                _ = &mut idle_timeout, if exit_on_idle => {
                    if active_tasks_check.load(Ordering::SeqCst) == 0 {
                        // Emit the terminal event before exiting. Same rule as
                        // the idle branch: a stopped run is never reported
                        // complete.
                        emit_run_terminal_events(
                            &progress_tracker_main,
                            &status_broadcaster_adhoc,
                            &cancellation_main,
                            &drained_cancels,
                            db_main.as_ref(),
                            &memory_guard_main,
                        ).await;
                        info!(
                            "Orchestrator idle for {:.1}s with no active tasks. Exiting.",
                            idle_window.as_secs_f64()
                        );
                        break;
                    } else {
                        // Still busy, reset the timer
                        idle_timeout.as_mut().reset(time::Instant::now() + idle_window);
                    }
                }
            }
        }

        // Close the queue first so any worker parked in `pop()` is released and
        // any late producer is told (and can roll its count back) rather than
        // enqueueing into a run that is over.
        self.queue.close();

        // Then abort the workers. A worker mid-module cannot be waited on: the
        // module runs on the blocking pool and may take minutes, and we only
        // reach here after the idle window elapsed with active_tasks == 0, so
        // all work is complete and abort is safe.
        monitor_handle.abort();
        for handle in &worker_handles {
            handle.abort();
        }
        for handle in worker_handles {
            let _ = handle.await;
        }

        // The pump parks on `recv()`, and the submission port is cloned into
        // other crates that outlive this run, so the channel may never close on
        // its own. Aborting it drops the receiver, which is what makes a later
        // `task_submitter().send(..)` fail loudly instead of queueing work into
        // an orchestrator that has exited.
        pump_handle.abort();
        let _ = pump_handle.await;

        // Drop ALL sender clones to close channels and unblock background writers.
        // self.* are the originals, local vars are clones made for workers/main loop.
        drop(self.task_sender);

        drop(self.artifact_write_sender);
        drop(artifact_write_sender);
        let _ = artifact_writer_handle.await;

        drop(self.processing_log_sender);
        drop(log_sender);
        drop(log_sender_adhoc);
        let _ = log_writer_handle.await;

        info!("Orchestrator terminated.");
    }

    /// Static worker method for processing artifacts in parallel
    async fn process_artifact_worker(
        artifact: Artifact,
        registry: &HashMap<ArtifactType, Vec<Arc<dyn ForensicsModule>>>,
        active_profiles: &Arc<RwLock<HashMap<Uuid, CachedProfile>>>,
        event_broadcaster: &BroadcastSender<Artifact>,
        status_broadcaster: &BroadcastSender<OrchestratorEvent>,
        queue: &TaskQueue,
        active_tasks: &Arc<AtomicUsize>,
        db: &Option<Arc<dyn DatabaseConnection>>,
        progress_tracker: &Arc<ProgressTracker>,
        log_sender: &MpscSender<ProcessingLogRecord>,
        artifact_write_sender: &MpscSender<Vec<Artifact>>,
        cancellation: &CancellationHandle,
        pending_hashes: &Arc<StdMutex<Vec<PendingHash>>>,
    ) {
        debug!(
            "Processing artifact: {:?} (ID: {}) for case {}",
            artifact.artifact_type, artifact.id, artifact.case_id
        );

        let case_id = artifact.case_id;
        // Guarantees active_tasks is decremented on every exit path, and keeps
        // this artifact counted against its own case for the whole run.
        let _task_guard =
            ActiveTaskGuard::adopt_in_flight(active_tasks.clone(), queue.census(), case_id);

        // Cancelled: drain the queue without dispatching any modules. Scoped to
        // this artifact's case so cancelling case A never stops case B.
        if cancellation.is_cancelled(case_id) {
            debug!("Skipping artifact {} (processing cancelled)", artifact.id);
            return;
        }

        // Track progress and emit PhaseStarted for new artifact types
        let is_new_phase = progress_tracker
            .record_artifact(&artifact.artifact_type, artifact.case_id)
            .await;
        if is_new_phase {
            let phase = phase_name(&artifact.artifact_type).to_string();
            info!(
                "[*] {} ({})",
                phase,
                format!("{:?}", artifact.artifact_type)
            );
            let _ = status_broadcaster.send(OrchestratorEvent::PhaseStarted {
                case_id: artifact.case_id,
                phase,
                artifact_type: format!("{:?}", artifact.artifact_type),
            });
        }

        // Ensure profile is loaded for this case
        Self::ensure_profile_loaded_static(artifact.case_id, active_profiles, db).await;

        // Broadcast the artifact BEFORE processing (e.g., for 'queued' state).
        // Only clone when someone is listening: during headless ingest there are
        // no SSE subscribers, so this skips a full Artifact (heap metadata) clone
        // per artifact.
        if event_broadcaster.receiver_count() > 0 {
            if let Err(e) = event_broadcaster.send(artifact.clone()) {
                debug!("Failed to broadcast artifact before processing: {}", e);
            }
        }

        let mut produced_artifacts = Vec::new();

        // Resolve which subscribed modules run for this case. The profile filter
        // is the only per-module async dependency, so it is evaluated up front
        // (profile-skipped modules are logged here, as before). Everything else
        // runs in a single blocking dispatch below.
        let mut modules_to_run: Vec<Arc<dyn ForensicsModule>> = Vec::new();
        if let Some(modules) = registry.get(&artifact.artifact_type) {
            for module in modules {
                if Self::should_run_module_static(artifact.case_id, module.id(), active_profiles)
                    .await
                {
                    modules_to_run.push(module.clone());
                } else {
                    debug!(
                        "Module '{}' skipped due to profile filtering for case {}",
                        module.id(),
                        artifact.case_id
                    );
                    record_processing_log(
                        log_sender,
                        ProcessingLogRecord {
                            case_id: artifact.case_id,
                            artifact_id: artifact.id,
                            module_id: module.id().to_string(),
                            status: "skipped".to_string(),
                            artifacts_produced: 0,
                            error_message: Some("Skipped by profile filter".to_string()),
                            zero_yield: None,
                            duration_ms: 0,
                        },
                    )
                    .await;
                }
            }
        } else {
            debug!(
                "No modules subscribed to artifact type {:?} (ID: {}) for case {}",
                artifact.artifact_type, artifact.id, artifact.case_id
            );
        }

        // Run ALL of this artifact's modules in ONE blocking dispatch instead of
        // one spawn_blocking per module. Each file previously paid N sequential
        // thread-pool hand-offs (N = subscribed modules, most rejecting the input
        // in microseconds); this collapses that to a single hand-off and clones
        // the artifact once (into an Arc) rather than once per module.
        // Cancellation is checked between modules with the cheap sync
        // is_cancelled; the running set is updated per module (sync) so the live
        // "what's running" display is preserved, notably for long parses.
        struct ModuleOutcome {
            module_id: String,
            duration_ms: u64,
            result: std::result::Result<Vec<Artifact>, ModuleError>,
            /// Artifacts the module handed to the streaming sink, already
            /// persisted and re-queued; not in `result` (HUNT-125).
            streamed: usize,
        }

        // A blocking dispatch that never returns its outcomes is a FAILURE, not
        // an artifact that produced nothing. Absorbing a join error into an
        // empty outcome list (as this once did) makes "every module ran and
        // found nothing" and "no module ran at all" identical downstream: no
        // ModuleError event, no failed processing-log row, and a case that
        // presents as fully processed while an evidence subtree skipped every
        // filesystem and application parser. So: retry the batch once, and if
        // it fails again record an explicit failure per scheduled module
        // (B3-006). Retrying is safe because a task that did not join produced
        // nothing the writer ever saw -- there is no half-persisted batch to
        // duplicate.
        const BATCH_DISPATCH_ATTEMPTS: u32 = 2;

        let artifact_type_str = format!("{:?}", artifact.artifact_type);

        // Modules the cancel stopped before they were dispatched. They need
        // their own processing-log rows: "the examiner stopped the run before
        // this module was reached" and "this module was never scheduled" are
        // otherwise the same absence of a row.
        // Artifacts streaming modules handed over mid-run and already dispatched.
        let mut streamed_total: usize = 0;
        let (outcomes, not_run): (Vec<ModuleOutcome>, Vec<String>) = if modules_to_run.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let art_arc = Arc::new(artifact.clone());
            let modules_blocking: Arc<Vec<Arc<dyn ForensicsModule>>> = Arc::new(modules_to_run);
            let case_id_blocking = artifact.case_id;
            let mut attempt: u32 = 1;
            loop {
                // Batches a streaming module hands over while it runs. The
                // channel is small on purpose: a module that outruns the
                // writer waits here instead of piling its output up (HUNT-125).
                let (stream_tx, mut stream_rx) = tokio::sync::mpsc::channel::<Vec<Artifact>>(2);
                let cancel = cancellation.clone();
                let modules = modules_blocking.clone();
                let art = art_arc.clone();
                let pt = progress_tracker.clone();
                // `ModuleStarted` has to be sent from here, next to the run
                // itself. Emitting it on the async side while applying outcomes
                // put every Started immediately before its Completed, after the
                // work was already done: the live "Running: ..." view never
                // showed anything and every module looked instantaneous in the
                // audit timeline.
                let status_tx = status_broadcaster.clone();
                let type_str = artifact_type_str.clone();
                let handle = tokio::task::spawn_blocking(move || {
                    let mut out = Vec::with_capacity(modules.len());
                    let mut skipped: Vec<String> = Vec::new();
                    let mut cancelled = false;
                    for module in modules.iter() {
                        // Stop dispatching further modules once cancelled, and
                        // name the ones that never got to run.
                        if cancelled || cancel.is_cancelled(case_id_blocking) {
                            cancelled = true;
                            skipped.push(module.id().to_string());
                            continue;
                        }
                        let module_id = module.id().to_string();
                        let _ = status_tx.send(OrchestratorEvent::ModuleStarted {
                            case_id: case_id_blocking,
                            module_id: module_id.clone(),
                            artifact_type: type_str.clone(),
                        });
                        // Guard rather than a bare module_finished call: if this
                        // task unwinds, the "currently running" set must not keep
                        // showing a module that will never finish.
                        let running = RunningModuleGuard::new(&pt, &module_id);
                        let start = Instant::now();
                        let mut streamed = 0usize;
                        let result = run_module_streaming(module, &art, &mut |batch| {
                            streamed += batch.len();
                            // A closed channel means the async side is gone;
                            // the module's own result is discarded with it.
                            let _ = stream_tx.blocking_send(batch);
                        });
                        let duration_ms = start.elapsed().as_millis() as u64;
                        drop(running);
                        out.push(ModuleOutcome {
                            module_id,
                            duration_ms,
                            result,
                            streamed,
                        });
                    }
                    (out, skipped)
                });
                // Dispatch each streamed batch as it arrives. The channel
                // closes when the blocking task ends (its sender is dropped),
                // which is what ends this loop.
                while let Some(mut batch) = stream_rx.recv().await {
                    for art in batch.iter_mut() {
                        art.case_id = artifact.case_id;
                    }
                    streamed_total += batch.len();
                    // The writer's queue is bounded in messages, and a streamed
                    // message can hold thousands of artifacts, so a writer that
                    // has fallen behind is waited for rather than fed: without
                    // this the bound on memory is the channel's 10,000 messages,
                    // not the few that are meant to be in flight (HUNT-125).
                    while !artifact_write_sender.is_closed()
                        && artifact_write_sender.max_capacity() - artifact_write_sender.capacity()
                            > STREAM_WRITER_BACKLOG_MESSAGES
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Self::dispatch_produced_batch(
                        batch,
                        artifact.case_id,
                        event_broadcaster,
                        queue,
                        active_tasks,
                        artifact_write_sender,
                        cancellation,
                    )
                    .await;
                }
                let joined = handle.await;

                match joined {
                    Ok(out) => break out,
                    // A retry re-runs the module from the start, and what it
                    // already streamed is persisted: re-running would record it
                    // twice. So only a dispatch that streamed nothing retries.
                    Err(join_err) if attempt < BATCH_DISPATCH_ATTEMPTS && streamed_total == 0 => {
                        error!(
                            "Module batch blocking task failed for artifact {} \
                             (attempt {}/{}): {}; retrying",
                            artifact.id, attempt, BATCH_DISPATCH_ATTEMPTS, join_err
                        );
                        attempt += 1;
                    }
                    Err(join_err) => {
                        error!(
                            "Module batch blocking task failed for artifact {} \
                             after {} attempts: {}; recording every scheduled \
                             module as failed",
                            artifact.id, BATCH_DISPATCH_ATTEMPTS, join_err
                        );
                        // `id()` is read here, on the async side, so the failure
                        // record survives whatever made the blocking task die.
                        break (
                            modules_blocking
                                .iter()
                                .map(|module| ModuleOutcome {
                                    module_id: module.id().to_string(),
                                    duration_ms: 0,
                                    streamed: 0,
                                    result: Err(ModuleError::FatalError(format!(
                                        "module dispatch for artifact {} did not complete after {} \
                                         attempts ({}); this module did not run and this artifact's \
                                         results are unknown, not empty",
                                        artifact.id, BATCH_DISPATCH_ATTEMPTS, join_err
                                    ))),
                                })
                                .collect(),
                            Vec::new(),
                        );
                    }
                }
            }
        };

        // A cancel that stops the module list must leave a record for every
        // module it stopped, or a partially processed artifact is indistinguish-
        // able from a fully processed one in the run's provenance.
        let any_module_cancelled = !not_run.is_empty();
        for module_id in not_run {
            warn!(
                "Module '{}' did not run on artifact {}: processing for case {} was cancelled",
                module_id, artifact.id, artifact.case_id
            );
            record_processing_log(
                log_sender,
                ProcessingLogRecord {
                    case_id: artifact.case_id,
                    artifact_id: artifact.id,
                    module_id,
                    status: "cancelled".to_string(),
                    artifacts_produced: 0,
                    error_message: Some(
                        "Processing was cancelled before this module ran; this artifact's \
                         results for it are unknown, not empty"
                            .to_string(),
                    ),
                    zero_yield: None,
                    duration_ms: 0,
                },
            )
            .await;
        }

        // Counted for the "nothing claimed this source" statement below: a
        // source that produced nothing because every module completed with
        // nothing to add is a different fact from one where a module failed or
        // was cancelled (HUNT-060).
        let mut modules_ran = 0usize;
        let mut any_module_failed = any_module_cancelled;
        // "Ran and produced nothing" is the same sentence over and over, and it
        // was a row each: 98.5% of 23.4 million rows on one case, and 27 rows
        // per artifact on another. The sentence is kept; the rows are folded
        // into one per status per artifact (HUNT-074).
        let mut ran_with_no_output: Vec<(String, u64)> = Vec::new();
        let mut declined_the_input: Vec<(String, u64)> = Vec::new();

        // Apply the batch outcomes: emit status/log events and collect produced
        // artifacts. Same bookkeeping the per-module loop did, now after the run.
        for ModuleOutcome {
            module_id,
            duration_ms: duration,
            result,
            streamed,
        } in outcomes
        {
            progress_tracker
                .record_module_duration(&module_id, duration)
                .await;
            modules_ran += 1;
            match result {
                Ok(new_arts) => {
                    let count = new_arts.len() + streamed;
                    if duration > 100 {
                        info!(
                            "Module '{}' took {}ms (produced {} artifacts)",
                            module_id, duration, count
                        );
                    }
                    for mut new_art in new_arts {
                        new_art.case_id = artifact.case_id;
                        // A `file_hash` record is intercepted below and never
                        // persisted; it carries the producing module so a
                        // failure to apply it can be attributed (HUNT-199).
                        if new_art.metadata.get("type").and_then(|v| v.as_str())
                            == Some("file_hash")
                            && new_art.metadata.get("source_module").is_none()
                        {
                            if let Some(map) = new_art.metadata.as_object_mut() {
                                map.insert("source_module".into(), module_id.clone().into());
                            }
                        }
                        produced_artifacts.push(new_art);
                    }
                    let _ = status_broadcaster.send(OrchestratorEvent::ModuleCompleted {
                        case_id: artifact.case_id,
                        module_id: module_id.clone(),
                        artifacts_produced: count,
                        duration_ms: duration,
                    });
                    // The fold. A module that produced something keeps its own
                    // row; one that ran and found nothing joins the list on the
                    // artifact's single row (HUNT-074).
                    if count == 0 {
                        ran_with_no_output.push((module_id, duration));
                    } else {
                        record_processing_log(
                            log_sender,
                            ProcessingLogRecord {
                                case_id: artifact.case_id,
                                artifact_id: artifact.id,
                                module_id,
                                status: "complete".to_string(),
                                artifacts_produced: count,
                                error_message: None,
                                zero_yield: None,
                                duration_ms: duration,
                            },
                        )
                        .await;
                    }
                }
                Err(e) => match &e {
                    ModuleError::InvalidInputFormat(_) => {
                        debug!(
                            "Module '{}' skipped artifact {}: {}",
                            module_id, artifact.id, e
                        );
                        let _ = status_broadcaster.send(OrchestratorEvent::ModuleCompleted {
                            case_id: artifact.case_id,
                            module_id: module_id.clone(),
                            artifacts_produced: 0,
                            duration_ms: duration,
                        });
                        declined_the_input.push((module_id, duration));
                    }
                    _ => {
                        any_module_failed = true;
                        error!(
                            "Module '{}' failed to process artifact ID {}: {}",
                            module_id, artifact.id, e
                        );
                        let _ = status_broadcaster.send(OrchestratorEvent::ModuleError {
                            case_id: artifact.case_id,
                            module_id: module_id.clone(),
                            artifact_id: artifact.id,
                            error: e.to_string(),
                        });
                        record_processing_log(
                            log_sender,
                            ProcessingLogRecord {
                                case_id: artifact.case_id,
                                artifact_id: artifact.id,
                                module_id,
                                status: "error".to_string(),
                                artifacts_produced: 0,
                                error_message: Some(e.to_string()),
                                zero_yield: None,
                                duration_ms: duration,
                            },
                        )
                        .await;
                    }
                },
            }
        }

        // Intercept file-hash records (metadata type == "file_hash"): apply the
        // hash to the parent artifact (setting its columns + merging md5/sha1/
        // sha256 into its metadata) and drop the record. It is neither persisted
        // as a visible artifact nor re-queued, so it cannot loop back into the
        // hasher. Records flagged `hash_skipped` carry no hashes; they are
        // buffered too, so the reason the file was not hashed reaches the parent
        // instead of vanishing (B6-005).
        if !produced_artifacts.is_empty() {
            let (hash_records, rest): (Vec<Artifact>, Vec<Artifact>) =
                produced_artifacts.into_iter().partition(|art| {
                    art.metadata.get("type").and_then(|v| v.as_str()) == Some("file_hash")
                });
            produced_artifacts = rest;

            // Buffer hashes for deferred application. The parent artifact is
            // written by the async writer and may not be flushed yet, so
            // applying here would race (miss). The writer drains this buffer on
            // its flush tick, by which point the parent is persisted.
            if db.is_some() && !hash_records.is_empty() {
                let mut pend = pending_hashes.lock().unwrap_or_else(|e| e.into_inner());
                for rec in hash_records {
                    let Some(parent_id) = rec.parent_id else {
                        error!(
                            "file_hash record {} has no parent_id; the digests it carries cannot \
                             be attributed to any file (case {})",
                            rec.id, artifact.case_id
                        );
                        continue;
                    };
                    let md5 = rec.metadata.get("md5").and_then(|v| v.as_str());
                    let sha1 = rec.metadata.get("sha1").and_then(|v| v.as_str());
                    let sha256 = rec.metadata.get("sha256").and_then(|v| v.as_str());
                    let outcome = match (md5, sha1, sha256) {
                        (Some(md5), Some(sha1), Some(sha256)) => PendingHashOutcome::Digests {
                            md5: md5.to_string(),
                            sha1: sha1.to_string(),
                            sha256: sha256.to_string(),
                        },
                        // No digests. Either the hasher said why (`hash_skipped`)
                        // or it did not, and "the record is malformed" is itself
                        // a reason the file has no digest. Both must reach the
                        // parent; a file with blank hash columns and no marker
                        // is indistinguishable from a verified one.
                        _ => PendingHashOutcome::Skipped {
                            reason: rec
                                .metadata
                                .get("hash_skipped")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unrecorded")
                                .to_string(),
                        },
                    };
                    let module_id = rec
                        .metadata
                        .get("source_module")
                        .and_then(|v| v.as_str())
                        .unwrap_or("plugin.hash.file_hasher")
                        .to_string();
                    pend.push(PendingHash {
                        case_id: artifact.case_id,
                        parent_id,
                        module_id,
                        outcome,
                        attempts: 0,
                    });
                }
            }
        }

        // The two folds. Each is one row carrying the modules it names and how
        // long each of them took, so nothing the row-per-module shape recorded
        // is lost — the read paths expand it back (HUNT-074).
        for (status, folded) in [
            ("complete", &mut ran_with_no_output),
            ("skipped", &mut declined_the_input),
        ] {
            if folded.is_empty() {
                continue;
            }
            let duration_ms = folded.iter().map(|(_, d)| *d).sum();
            record_processing_log(
                log_sender,
                ProcessingLogRecord {
                    case_id: artifact.case_id,
                    artifact_id: artifact.id,
                    // The row is about several modules; `zero_yield` names them.
                    module_id: String::new(),
                    status: status.to_string(),
                    artifacts_produced: 0,
                    error_message: None,
                    zero_yield: Some(std::mem::take(folded)),
                    duration_ms,
                },
            )
            .await;
        }

        // A source nothing in this build parses must say so about itself.
        //
        // `case001.pcap` and two pagefiles were accepted into a case, detected
        // from their extension as RawEvidence, and produced nothing: every
        // screen showed the source with an empty tree. The per-artifact history
        // was complete — eighteen modules, each `complete` with
        // `artifacts_produced: 0` — but that records the fact as the ABSENCE of
        // a network module from a list of eighteen storage and memory ones,
        // which an examiner has to open the history and then notice. "Nothing in
        // this build claims this source" is a positive fact about the evidence,
        // and the risk of leaving it to be inferred is an examiner concluding
        // from a quiet case that the source held nothing (HUNT-060).
        if let Some(record) = unclaimed_source_record(
            &artifact,
            produced_artifacts.is_empty() && streamed_total == 0,
            modules_ran,
            any_module_failed,
        ) {
            produced_artifacts.push(record);
        }

        // Persist the produced batch, then broadcast + re-queue. The writer
        // needs every produced artifact, but only non-TimelineEvent artifacts
        // are ever re-dispatched, so we hand the whole batch to the writer by
        // MOVE and clone only the (usually smaller) re-queued subset -- instead
        // of deep-cloning the entire batch (TimelineEvents are the bulk of a
        // timeline-heavy ingest and were being cloned only to be dropped).
        if !produced_artifacts.is_empty() {
            Self::dispatch_produced_batch(
                produced_artifacts,
                case_id,
                event_broadcaster,
                queue,
                active_tasks,
                artifact_write_sender,
                cancellation,
            )
            .await;
        }
        progress_tracker.record_completed(case_id).await;
        // active_tasks decrement handled by _task_guard (RAII)
    }

    /// Persist one batch of produced artifacts, broadcast it, and re-queue the
    /// ones other modules consume. The tail of [`Self::process_artifact_worker`],
    /// separate so a streaming module's mid-run batches (HUNT-125) take exactly
    /// the path its returned remainder does.
    async fn dispatch_produced_batch(
        produced_artifacts: Vec<Artifact>,
        case_id: Uuid,
        event_broadcaster: &BroadcastSender<Artifact>,
        queue: &TaskQueue,
        active_tasks: &Arc<AtomicUsize>,
        artifact_write_sender: &MpscSender<Vec<Artifact>>,
        cancellation: &CancellationHandle,
    ) {
        if produced_artifacts.is_empty() {
            return;
        }
        {
            let requeue_count = produced_artifacts.len();

            // On cancel, artifacts already produced are persisted so evidence is
            // never half-written, but nothing new is dispatched.
            let requeue = !cancellation.is_cancelled(case_id);
            // Only clone for broadcast when a subscriber is listening (skips a
            // per-artifact clone during headless ingest).
            let has_event_subs = event_broadcaster.receiver_count() > 0;
            if has_event_subs {
                for art in &produced_artifacts {
                    if let Err(e) = event_broadcaster.send(art.clone()) {
                        debug!("Failed to broadcast produced artifact: {}", e);
                    }
                }
            }

            // Clone only what gets re-queued; the rest reaches the writer by move.
            let to_requeue: Vec<Artifact> = if requeue {
                produced_artifacts
                    .iter()
                    .filter(|a| a.artifact_type != ArtifactType::TimelineEvent)
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };

            if requeue_count > 1000 {
                info!(
                    "Large batch: re-queuing {} artifacts into pipeline...",
                    requeue_count
                );
            }

            // The writer stores metadata and never reads an artifact's bytes,
            // so the batch goes to it without its data sources: the re-queued
            // clones above hold them for the modules that will, and the queue
            // parks byte-backed ones on disk. Left attached, every blob a
            // plist carried out stayed in memory for as long as the writer was
            // behind — which on a walk of 40,000 small files was the whole
            // run (HUNT-114).
            let mut produced_artifacts = produced_artifacts;
            for art in produced_artifacts.iter_mut() {
                art.data = None;
            }
            // Persist the whole batch (moved -- no whole-batch clone). On send
            // failure the channel returns the batch, so we can still log its ids.
            if let Err(e) = artifact_write_sender.send(produced_artifacts).await {
                let ids: Vec<Uuid> = e.0.iter().map(|a| a.id).collect();
                // Still re-queued below: the children are examined, but under
                // parents that were never persisted, and the report must say so.
                record_artifacts_lost(
                    &ids,
                    "failed to queue produced artifacts for the DB writer",
                    "artifact writer channel closed",
                );
            }

            for new_art in to_requeue {
                active_tasks.fetch_add(1, Ordering::SeqCst);
                // Never blocks: past the queue's resident bound this spills to
                // disk rather than parking the worker, which is what keeps a
                // producer that is also a consumer from deadlocking the pool.
                if let Err(rejected) = queue.push(new_art) {
                    error!(
                        "Failed to re-queue artifact {} ({:?}): the task queue is closed, so it \
                         will not be processed",
                        rejected.id, rejected.artifact_type
                    );
                    active_tasks.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
    }

    /// Load a case's active profile from the database, re-reading it once the
    /// cached copy is older than [`PROFILE_REFRESH_INTERVAL`].
    ///
    /// A profile decides which modules run, so a stale copy means the wrong
    /// evidence gets parsed. The refresh is what makes an API profile change
    /// take effect on a process that is already ingesting; without it the first
    /// profile a case ever saw was the only one it ever used. A database error
    /// keeps the previous answer (and re-tries at the next interval) rather
    /// than silently widening the module set to "run everything".
    async fn ensure_profile_loaded_static(
        case_id: Uuid,
        active_profiles: &Arc<RwLock<HashMap<Uuid, CachedProfile>>>,
        db: &Option<Arc<dyn DatabaseConnection>>,
    ) {
        {
            let profiles = active_profiles.read().await;
            match profiles.get(&case_id) {
                Some(cached) if !cached.is_stale() => return,
                // Nothing cached, or the copy has aged out: fall through and
                // ask the database.
                _ => {}
            }
        }

        let Some(db) = db else { return };
        let loaded = match db.get_active_profile(case_id).await {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    "Could not read the active profile for case {} ({}); keeping the previous module selection",
                    case_id, e
                );
                return;
            }
        };

        let mut profiles = active_profiles.write().await;
        // set_profile may have pinned an override while we were querying.
        if profiles.get(&case_id).is_some_and(|c| c.pinned) {
            return;
        }
        match &loaded {
            Some(p) => debug!(
                "Active profile for case {} is '{}' ({} enabled modules)",
                case_id,
                p.name,
                p.enabled_modules.len()
            ),
            None => debug!("Case {} has no active profile; all modules run", case_id),
        }
        profiles.insert(
            case_id,
            CachedProfile {
                profile: loaded,
                loaded_at: Instant::now(),
                pinned: false,
            },
        );
    }

    /// Helper for non-self methods
    async fn should_run_module_static(
        case_id: Uuid,
        module_id: &str,
        active_profiles: &Arc<RwLock<HashMap<Uuid, CachedProfile>>>,
    ) -> bool {
        let profiles = active_profiles.read().await;
        match profiles.get(&case_id).and_then(|c| c.profile.as_ref()) {
            Some(p) => p.should_run_module(module_id),
            None => true, // No profile = run all modules
        }
    }

    /// Process one artifact inline. The pipeline calls
    /// [`Self::process_artifact_worker`] from its spawned workers, which hold
    /// no `&self`; this instance form exists for the tests, which drive an
    /// `Orchestrator` directly.
    #[cfg(test)]
    async fn process_artifact(&self, artifact: Artifact) {
        Self::process_artifact_worker(
            artifact,
            &self.registry,
            &self.active_profiles,
            &self.event_broadcaster,
            &self.status_broadcaster,
            &self.queue,
            &self.active_tasks,
            &self.db,
            &self.progress_tracker,
            &self.processing_log_sender,
            &self.artifact_write_sender,
            &self.cancellation,
            &self.pending_hashes,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_ad_hoc_request_static(
        request: AdHocRequest,
        module_lookup: &HashMap<String, Arc<dyn ForensicsModule>>,
        db: &Option<Arc<dyn DatabaseConnection>>,
        event_broadcaster: &BroadcastSender<Artifact>,
        status_broadcaster: &BroadcastSender<OrchestratorEvent>,
        queue: &TaskQueue,
        active_tasks: &Arc<AtomicUsize>,
        log_sender: &MpscSender<ProcessingLogRecord>,
        cancellation: &CancellationHandle,
    ) {
        info!(
            "Processing ad-hoc request: module '{}' on artifact {}",
            request.module_id, request.artifact_id
        );

        let db_conn = match db {
            Some(db) => db,
            None => {
                error!("Ad-hoc request failed: no database connection");
                return;
            }
        };

        // Cancellation applies to ad-hoc work too. Running a module for a case
        // whose processing the examiner just stopped both contradicts the
        // instruction and writes new artifacts into a case that is being torn
        // down; the job says so instead of running silently. The cancel is
        // lifted automatically once the queue drains, so the same request
        // succeeds on a retry moments later.
        if cancellation.is_cancelled(request.case_id) {
            warn!(
                "Ad-hoc job {} not run: processing for case {} is cancelled",
                request.job_id, request.case_id
            );
            fail_job(
                db_conn.as_ref(),
                request.job_id,
                "Processing for this case was cancelled; the job did not run. \
                 Retry once cancellation has finished.",
            )
            .await;
            return;
        }

        // Look up the module
        let module = match module_lookup.get(&request.module_id) {
            Some(m) => m.clone(),
            None => {
                error!(
                    "Ad-hoc request failed: module '{}' not found",
                    request.module_id
                );
                fail_job(
                    db_conn.as_ref(),
                    request.job_id,
                    &format!("Module '{}' not found", request.module_id),
                )
                .await;
                return;
            }
        };

        // Update job status to Running
        match db_conn.get_job(request.job_id).await {
            Ok(Some(mut job)) => {
                job.status = crate::profile::JobStatus::Running;
                if let Err(e) = db_conn.update_job(&job).await {
                    error!("Failed to update job status to Running: {}", e);
                }
            }
            Ok(None) => error!(
                "Ad-hoc job {} not found; it cannot be marked running",
                request.job_id
            ),
            Err(e) => error!(
                "Could not read ad-hoc job {} to mark it running: {e}",
                request.job_id
            ),
        }

        // Fetch artifact from database
        let mut artifact = match db_conn.get_artifact(request.artifact_id).await {
            Ok(Some(art)) => art,
            Ok(None) => {
                error!(
                    "Ad-hoc request failed: artifact {} not found",
                    request.artifact_id
                );
                fail_job(
                    db_conn.as_ref(),
                    request.job_id,
                    &format!("Artifact {} not found", request.artifact_id),
                )
                .await;
                return;
            }
            Err(e) => {
                error!("Ad-hoc request failed: error fetching artifact: {}", e);
                fail_job(
                    db_conn.as_ref(),
                    request.job_id,
                    &format!("Error fetching artifact: {e}"),
                )
                .await;
                return;
            }
        };

        // DB-loaded artifacts carry no DataSource. If the caller resolved one
        // (the API's content resolver), stamp it on so the module has data to
        // read — otherwise e.g. the deep carver reads nothing and silently
        // produces zero files.
        if artifact.data.is_none() {
            if let Some(ds) = &request.data_source {
                artifact.data = Some(ds.clone());
            }
        }

        // No secret is merged into the artifact's metadata any more: a
        // per-run secret arrives only as `request.credential`, scoped to the
        // module call below (SEC-204).

        // Execute module on artifact
        debug!(
            "Executing module '{}' on artifact {}",
            module.id(),
            artifact.id
        );
        let module_id_str = module.id().to_string();
        let artifact_type_str = format!("{:?}", artifact.artifact_type);

        // Emit ModuleStarted
        let _ = status_broadcaster.send(OrchestratorEvent::ModuleStarted {
            case_id: artifact.case_id,
            module_id: module_id_str.clone(),
            artifact_type: artifact_type_str,
        });
        let start = Instant::now();
        // Stamped before the run so that "what this run wrote" and "what an
        // earlier run left" can be told apart afterwards.
        let run_started_at = chrono::Utc::now().to_rfc3339();

        // An examiner-supplied credential (HUNT-120) is visible to the module
        // for this one `process` call and nowhere else, and is dropped — its
        // value zeroed — the moment the module returns. What the module did
        // with it decides what happens to the records it produced.
        let mut request = request;
        let credential = request.credential.take();
        if let Some(cred) = credential.as_ref() {
            if cred.artifact_id() != artifact.id || cred.kind().module_id() != module.id() {
                let message = format!(
                    "A {} was supplied for a different artifact or module than this run's; it was not used and nothing in the case changed.",
                    cred.kind().label()
                );
                fail_job(db_conn.as_ref(), request.job_id, &message).await;
                audit_credential_outcome(
                    db_conn.as_ref(),
                    &artifact,
                    request.job_id,
                    &module_id_str,
                    cred.kind(),
                    cred.requested_by(),
                    "refused_mismatch",
                    None,
                )
                .await;
                return;
            }
        }
        // On a blocking thread: a module is synchronous and may run for
        // minutes, and must not pin an async worker. The credential scope is
        // thread-local, so it is entered on the thread that runs the module.
        let result = {
            let (module, artifact, credential) =
                (module.clone(), artifact.clone(), credential.clone());
            tokio::task::spawn_blocking(move || {
                crate::credential::scoped(credential, || run_module_isolated(&module, &artifact))
            })
            .await
            .unwrap_or_else(|e| {
                Err(ModuleError::FatalError(format!(
                    "Module '{module_id_str}' did not complete: its task failed ({e})"
                )))
            })
        };
        let credential_report = credential
            .as_ref()
            .map(|c| (c.kind(), c.requested_by().to_string(), c.outcome()));
        drop(credential);
        if let Some((kind, requested_by, outcome)) = credential_report {
            let duration_ms = start.elapsed().as_millis() as u64;
            let settle = settle_credential_run(
                db_conn.as_ref(),
                log_sender,
                &artifact,
                request.job_id,
                &module_id_str,
                kind,
                &requested_by,
                outcome,
                result.is_ok(),
                duration_ms,
            )
            .await;
            if settle == CredentialSettlement::Stop {
                return;
            }
        }

        // Update job based on result. The module has already run, so what it
        // produced is recorded whether or not its job row can be read: a job
        // that cannot be found loses the status, never the results.
        let mut job = match db_conn.get_job(request.job_id).await {
            Ok(Some(job)) => Some(job),
            Ok(None) => {
                error!(
                    "Ad-hoc job {} not found after module '{}' ran; its results are recorded \
                     but the job row cannot be updated",
                    request.job_id, module_id_str
                );
                None
            }
            Err(e) => {
                error!(
                    "Could not read ad-hoc job {} after module '{}' ran ({e}); its results are \
                     recorded but the job row cannot be updated",
                    request.job_id, module_id_str
                );
                None
            }
        };
        {
            match result {
                Ok(new_artifacts) => {
                    let count = new_artifacts.len();
                    let duration = start.elapsed().as_millis() as u64;
                    info!(
                        "Ad-hoc execution succeeded: module '{}' produced {} artifacts",
                        module.id(),
                        count
                    );
                    // Emit ModuleCompleted
                    let _ = status_broadcaster.send(OrchestratorEvent::ModuleCompleted {
                        case_id: artifact.case_id,
                        module_id: module_id_str.clone(),
                        artifacts_produced: count,
                        duration_ms: duration,
                    });
                    record_processing_log(
                        log_sender,
                        ProcessingLogRecord {
                            case_id: artifact.case_id,
                            artifact_id: artifact.id,
                            module_id: module_id_str.clone(),
                            status: "complete".to_string(),
                            artifacts_produced: count,
                            error_message: None,
                            zero_yield: None,
                            duration_ms: duration,
                        },
                    )
                    .await;
                    if let Some(job) = job.as_mut() {
                        job.status = crate::profile::JobStatus::Complete;
                        job.artifacts_produced = count;
                        job.completed_at = Some(chrono::Utc::now().timestamp());
                    }

                    // One supersession per (parent, kind) — the first record
                    // of a kind marks what came before it, and the rest of this
                    // run's records of the same kind are that run's too.
                    let mut superseded_keys: HashSet<(Uuid, String, String)> = HashSet::new();

                    // Record and broadcast produced artifacts
                    for mut new_art in new_artifacts {
                        new_art.case_id = artifact.case_id;

                        if let Err(e) = db_conn.record_artifact(&new_art).await {
                            // The row does not exist, so broadcasting it and
                            // queueing it for further processing would parent
                            // children onto a missing artifact (FK failures /
                            // orphaned output). Skip it and surface the loss
                            // instead of pretending it landed (BUG-193).
                            error!(
                                "EVIDENCE LOSS: failed to record ad-hoc produced artifact {} ({:?}); \
                                 not broadcasting or queueing it: {}",
                                new_art.id, new_art.artifact_type, e
                            );
                            continue;
                        }

                        // A re-run can answer an earlier refusal: a password
                        // opens a backup recorded as unreadable, a symbol pack
                        // arrives after a memory pass gave up. A record that
                        // says so names the status it answers, and the earlier
                        // statement is marked superseded — kept, because the
                        // refusal happened, but no longer counted as missing
                        // data by the census a report draws on (HUNT-090).
                        apply_supersession(db_conn.as_ref(), &new_art).await;

                        // What an earlier run of this same module left under
                        // this artifact stops being current when this run
                        // answers it. Nothing is deleted — the first run's
                        // answer is part of the examination's history — but two
                        // runs' records must not stand side by side with
                        // nothing saying which is which (HUNT-107).
                        supersede_earlier_run(
                            db_conn.as_ref(),
                            &new_art,
                            &run_started_at,
                            &module_id_str,
                            &mut superseded_keys,
                        )
                        .await;

                        // Broadcast the new artifact (only when subscribed)
                        if event_broadcaster.receiver_count() > 0 {
                            if let Err(e) = event_broadcaster.send(new_art.clone()) {
                                debug!("Failed to broadcast produced artifact: {}", e);
                            }
                        }

                        // Queue non-timeline artifacts for further processing
                        if new_art.artifact_type != crate::artifact::ArtifactType::TimelineEvent {
                            active_tasks.fetch_add(1, Ordering::SeqCst);
                            if let Err(rejected) = queue.push(new_art) {
                                error!(
                                    "Failed to queue produced artifact {}: the task queue is \
                                     closed, so it will not be processed",
                                    rejected.id
                                );
                                active_tasks.fetch_sub(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
                Err(e) => match &e {
                    ModuleError::InvalidInputFormat(_) => {
                        let duration = start.elapsed().as_millis() as u64;
                        let declined = format!("module declined this input: {e}");
                        debug!(
                            "Ad-hoc module '{}' skipped artifact {}: {}",
                            module.id(),
                            artifact.id,
                            e
                        );
                        let _ = status_broadcaster.send(OrchestratorEvent::ModuleCompleted {
                            case_id: artifact.case_id,
                            module_id: module_id_str.clone(),
                            artifacts_produced: 0,
                            duration_ms: duration,
                        });
                        record_processing_log(
                            log_sender,
                            ProcessingLogRecord {
                                case_id: artifact.case_id,
                                artifact_id: artifact.id,
                                module_id: module_id_str.clone(),
                                status: "skipped".to_string(),
                                artifacts_produced: 0,
                                error_message: Some(declined.clone()),
                                zero_yield: None,
                                duration_ms: duration,
                            },
                        )
                        .await;
                        // Complete, not failed: declining an input is not an
                        // error, but "0 produced" alone would read as a run that
                        // looked and found nothing.
                        if let Some(job) = job.as_mut() {
                            job.status = crate::profile::JobStatus::Complete;
                            job.artifacts_produced = 0;
                            job.error_message = Some(declined);
                            job.completed_at = Some(chrono::Utc::now().timestamp());
                        }
                    }
                    _ => {
                        let duration = start.elapsed().as_millis() as u64;
                        error!(
                            "Ad-hoc execution failed: module '{}' returned error: {}",
                            module.id(),
                            e
                        );
                        let _ = status_broadcaster.send(OrchestratorEvent::ModuleError {
                            case_id: artifact.case_id,
                            module_id: module_id_str.clone(),
                            artifact_id: artifact.id,
                            error: e.to_string(),
                        });
                        record_processing_log(
                            log_sender,
                            ProcessingLogRecord {
                                case_id: artifact.case_id,
                                artifact_id: artifact.id,
                                module_id: module_id_str.clone(),
                                status: "error".to_string(),
                                artifacts_produced: 0,
                                error_message: Some(e.to_string()),
                                zero_yield: None,
                                duration_ms: duration,
                            },
                        )
                        .await;
                        if let Some(job) = job.as_mut() {
                            job.status = crate::profile::JobStatus::Failed;
                            job.error_message = Some(format!("Module execution error: {}", e));
                            job.completed_at = Some(chrono::Utc::now().timestamp());
                        }
                    }
                },
            }

            if let Some(job) = &job {
                if let Err(e) = db_conn.update_job(job).await {
                    error!("Failed to update job status: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::InputCapability;
    use serde_json::json;

    /// BUG-027 / BUG-043 / B2-115: one process-wide counter triple was stamped
    /// with whichever case wrote most recently, so progress reported for case A
    /// carried case B's totals — a client filtering by case_id was shown
    /// another case's work. Counts belong to the case that produced them.
    #[tokio::test]
    async fn concurrent_cases_do_not_share_progress_counts() {
        let tracker = ProgressTracker::new();
        let case_a = Uuid::new_v4();
        let case_b = Uuid::new_v4();

        for _ in 0..3 {
            tracker
                .record_artifact(&ArtifactType::FileEntry, case_a)
                .await;
        }
        tracker.record_completed(case_a).await;
        tracker
            .record_artifact(&ArtifactType::ParsedRecord, case_b)
            .await;

        let snapshots = tracker.case_snapshots().await;
        assert_eq!(snapshots.len(), 2, "each case must be reported on its own");

        let a = snapshots
            .iter()
            .find(|s| s.case_id == case_a)
            .expect("case A must be reported");
        let b = snapshots
            .iter()
            .find(|s| s.case_id == case_b)
            .expect("case B must be reported");
        assert_eq!(a.processed, 3);
        assert_eq!(a.completed, 1);
        assert_eq!(a.by_type, vec![("FileEntry".to_string(), 3)]);
        assert_eq!(
            b.processed, 1,
            "case B must not be credited with case A's artifacts"
        );
        assert_eq!(b.completed, 0);
        assert_eq!(b.by_type, vec![("ParsedRecord".to_string(), 1)]);
    }

    /// HUNT-019. `active_tasks` is a process-wide count, and using it as one
    /// case's progress denominator let another case's ingest move that case's
    /// bar.
    ///
    /// This pins the worst window of it: case B has just queued a large ingest
    /// and none of it has reached a worker yet, so case B has no progress
    /// snapshot at all. The old code saw a single snapshot, concluded the whole
    /// process-wide queue must belong to that case, and reported case A a
    /// denominator of 502 for the two artifacts case A actually had.
    #[tokio::test]
    async fn another_cases_queue_must_not_inflate_this_cases_denominator() {
        let tracker = ProgressTracker::new();
        let census = CaseTaskCensus::new();
        let case_a = Uuid::new_v4();
        let case_b = Uuid::new_v4();

        // Case A: two artifacts entered processing, one finished, one queued.
        tracker
            .record_artifact(&ArtifactType::FileEntry, case_a)
            .await;
        tracker
            .record_artifact(&ArtifactType::FileEntry, case_a)
            .await;
        tracker.record_completed(case_a).await;
        census.enqueued(case_a);

        // Case B queued 500 artifacts a moment ago; nothing of its own has been
        // dequeued, so it has no snapshot yet.
        for _ in 0..500 {
            census.enqueued(case_b);
        }

        let (tx, mut rx) = broadcast_channel(64);
        let mut throughput = HashMap::new();
        emit_case_progress(&tracker, &census, &mut throughput, &tx, Instant::now()).await;

        let mut seen: Option<(usize, usize)> = None;
        while let Ok(event) = rx.try_recv() {
            if let OrchestratorEvent::PhaseProgress {
                case_id,
                tasks_completed,
                tasks_total,
                ..
            } = event
            {
                assert_ne!(
                    case_id, case_b,
                    "a case that has processed nothing yet must not be reported on"
                );
                if case_id == case_a {
                    seen = Some((tasks_completed, tasks_total));
                }
            }
        }

        let (completed, total) = seen.expect("case A must be reported on");
        assert_eq!(completed, 1);
        assert_eq!(
            total, 2,
            "case A's denominator is its own 1 finished + 1 queued, never case B's 500"
        );
    }

    /// HUNT-019, the other half. With two cases ingesting at once each must
    /// still get a determinate bar built from its own work.
    ///
    /// The previous code detected the collision and gave up: it set `tasks_total`
    /// to what the case had already *seen* — a lower bound that walks backwards
    /// as more work is discovered — and forced `discovering`, so no ETA was ever
    /// offered to anybody while a second case was running.
    #[tokio::test]
    async fn two_ingesting_cases_each_get_their_own_denominator() {
        let tracker = ProgressTracker::new();
        let census = CaseTaskCensus::new();
        let case_a = Uuid::new_v4();
        let case_b = Uuid::new_v4();

        for _ in 0..4 {
            tracker
                .record_artifact(&ArtifactType::FileEntry, case_a)
                .await;
            tracker.record_completed(case_a).await;
        }
        for _ in 0..3 {
            census.enqueued(case_a);
        }

        for _ in 0..2 {
            tracker
                .record_artifact(&ArtifactType::ParsedRecord, case_b)
                .await;
        }
        tracker.record_completed(case_b).await;
        for _ in 0..40 {
            census.enqueued(case_b);
        }

        let (tx, mut rx) = broadcast_channel(64);
        let mut throughput = HashMap::new();
        emit_case_progress(&tracker, &census, &mut throughput, &tx, Instant::now()).await;

        let mut totals: HashMap<Uuid, usize> = HashMap::new();
        while let Ok(event) = rx.try_recv() {
            if let OrchestratorEvent::PhaseProgress {
                case_id,
                tasks_total,
                ..
            } = event
            {
                totals.insert(case_id, tasks_total);
            }
        }
        assert_eq!(
            totals.get(&case_a),
            Some(&7),
            "case A: 4 finished + 3 of its own still queued"
        );
        assert_eq!(
            totals.get(&case_b),
            Some(&41),
            "case B: 1 finished + 40 of its own still queued"
        );
    }

    /// The phase flags were process-wide too: case B's first FileEntry was not
    /// a new phase because case A had already seen one, so case B's watcher
    /// never got the PhaseStarted for it.
    #[tokio::test]
    async fn a_new_phase_is_new_per_case() {
        let tracker = ProgressTracker::new();
        let case_a = Uuid::new_v4();
        let case_b = Uuid::new_v4();

        assert!(
            tracker
                .record_artifact(&ArtifactType::FileEntry, case_a)
                .await
        );
        assert!(
            !tracker
                .record_artifact(&ArtifactType::FileEntry, case_a)
                .await
        );
        assert!(
            tracker
                .record_artifact(&ArtifactType::FileEntry, case_b)
                .await,
            "case B's first FileEntry is a new phase for case B"
        );
    }

    /// LIVE-006: the run duration was measured from orchestrator construction,
    /// so a 10-second ingest on a server that had been up a quarter of an hour
    /// was reported as "complete in 914.0s". Each run is timed from its own
    /// first artifact, and a second job must not inherit the first job's clock.
    #[tokio::test]
    async fn run_duration_is_measured_from_the_job_not_orchestrator_start() {
        let tracker = ProgressTracker::new();
        let case = Uuid::new_v4();

        let first_run_start = Instant::now();
        tracker
            .record_artifact(&ArtifactType::FileEntry, case)
            .await;

        // The first run ends; the orchestrator then sits idle before the next
        // job is submitted.
        tracker.reset_run().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        tracker
            .record_artifact(&ArtifactType::FileEntry, case)
            .await;
        let snapshots = tracker.case_snapshots().await;
        assert_eq!(snapshots.len(), 1);
        let elapsed = snapshots[0].elapsed;
        let since_first_run = first_run_start.elapsed();
        assert!(
            elapsed + Duration::from_millis(40) < since_first_run,
            "the second job's duration ({:?}) must exclude the idle gap before it ({:?})",
            elapsed,
            since_first_run
        );
    }

    #[tokio::test]
    async fn progress_tracker_reset_run_clears_counts_and_case() {
        let tracker = ProgressTracker::new();
        let case = Uuid::new_v4();
        tracker
            .record_artifact(&ArtifactType::FileEntry, case)
            .await;
        tracker.record_completed(case).await;

        tracker.reset_run().await;

        assert_eq!(tracker.total_processed().await, 0);
        assert!(tracker.case_snapshots().await.is_empty());
    }

    #[test]
    fn type_index_round_trips_and_covers_every_variant() {
        // Each variant maps to a distinct in-bounds slot, and that slot points
        // back at the same variant — so the per-type atomic counters can never
        // be mis-keyed. The exhaustive match in type_index already forces this
        // list to be updated when a variant is added; this locks the ordering.
        for (i, t) in TRACKED_TYPES.iter().enumerate() {
            assert_eq!(
                type_index(t),
                i,
                "type_index disagrees with TRACKED_TYPES[{i}]"
            );
        }
    }

    #[tokio::test]
    async fn snapshot_reports_only_seen_types_by_debug_name() {
        // snapshot must key counts by the ArtifactType Debug name and omit
        // types with a zero count, matching the old HashMap<String,_> shape the
        // SSE consumer relies on.
        let tracker = ProgressTracker::new();
        let case = Uuid::new_v4();
        tracker
            .record_artifact(&ArtifactType::FileEntry, case)
            .await;
        tracker
            .record_artifact(&ArtifactType::FileEntry, case)
            .await;
        tracker
            .record_artifact(&ArtifactType::ParsedRecord, case)
            .await;

        let snapshots = tracker.case_snapshots().await;
        assert_eq!(snapshots.len(), 1);
        let total = snapshots[0].processed;
        assert_eq!(total, 3);
        let mut sorted = snapshots[0].by_type.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                ("FileEntry".to_string(), 2),
                ("ParsedRecord".to_string(), 1),
            ]
        );
    }

    /// A simple test module that produces N artifacts from each input.
    struct TestModule {
        id: String,
        subscribes_to: Vec<ArtifactType>,
        produce_count: usize,
    }

    impl TestModule {
        fn new(id: &str, subscribes_to: Vec<ArtifactType>, produce_count: usize) -> Self {
            Self {
                id: id.to_string(),
                subscribes_to,
                produce_count,
            }
        }
    }

    impl ForensicsModule for TestModule {
        fn id(&self) -> &str {
            &self.id
        }
        fn version(&self) -> &str {
            "1.0.0"
        }
        fn subscribes_to(&self) -> Vec<ArtifactType> {
            self.subscribes_to.clone()
        }
        fn input_capability(&self) -> InputCapability {
            InputCapability::Stream
        }
        fn process(&self, artifact: &Artifact) -> std::result::Result<Vec<Artifact>, ModuleError> {
            let mut out = Vec::new();
            for i in 0..self.produce_count {
                let meta = json!({
                    "source_module": self.id,
                    "index": i,
                    "parent_name": artifact.metadata.get("name").and_then(|v| v.as_str()).unwrap_or("unknown"),
                });
                let child = Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
                    .with_parent(artifact.id);
                out.push(child);
            }
            Ok(out)
        }
    }

    /// A module that always returns InvalidInputFormat (skip).
    struct SkippingModule;
    impl ForensicsModule for SkippingModule {
        fn id(&self) -> &str {
            "test.skipper"
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
        fn process(&self, _artifact: &Artifact) -> std::result::Result<Vec<Artifact>, ModuleError> {
            Err(ModuleError::InvalidInputFormat("Not my format".to_string()))
        }
    }

    /// Produces one re-queuable artifact (FileEntry) and one terminal artifact
    /// (TimelineEvent) per input, to exercise the persist-all / requeue-subset
    /// split in the produced-batch handling.
    struct MixedProducer;
    impl ForensicsModule for MixedProducer {
        fn id(&self) -> &str {
            "test.mixed_producer"
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
            Ok(vec![
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::FileEntry,
                    None,
                    json!({ "name": "child" }),
                )
                .with_parent(artifact.id),
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::TimelineEvent,
                    None,
                    json!({ "timestamp": 1 }),
                )
                .with_parent(artifact.id),
            ])
        }
    }

    /// A module that streams: `batches` batches of `per_batch` timeline
    /// events go to the sink as it runs, and one file entry is returned.
    struct StreamingProducer {
        batches: usize,
        per_batch: usize,
    }
    impl ForensicsModule for StreamingProducer {
        fn id(&self) -> &str {
            "test.streaming_producer"
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
            // The non-streaming entry point keeps everything, as before.
            let mut all = Vec::new();
            self.process_streaming(artifact, &mut |b| all.extend(b))
                .map(|mut rest| {
                    all.append(&mut rest);
                    all
                })
        }
        fn process_streaming(
            &self,
            artifact: &Artifact,
            sink: &mut dyn FnMut(Vec<Artifact>),
        ) -> std::result::Result<Vec<Artifact>, ModuleError> {
            for _ in 0..self.batches {
                sink(
                    (0..self.per_batch)
                        .map(|i| {
                            Artifact::new(
                                Uuid::nil(), // the orchestrator stamps the case
                                ArtifactType::TimelineEvent,
                                None,
                                json!({ "timestamp": i }),
                            )
                            .with_parent(artifact.id)
                        })
                        .collect(),
                );
            }
            Ok(vec![Artifact::new(
                artifact.case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": "child" }),
            )
            .with_parent(artifact.id)])
        }
    }

    /// HUNT-125. What a streaming module hands over mid-run is persisted like
    /// what it returns, is attributed to the case, is counted in the module's
    /// yield, and is not re-queued when it is a timeline event.
    #[tokio::test]
    async fn streamed_batches_are_persisted_counted_and_attributed_to_the_case() {
        let mut orch = Orchestrator::new(None, 10);
        orch.register_module(Arc::new(StreamingProducer {
            batches: 3,
            per_batch: 4,
        }));
        let mut status_rx = orch.status_sender().subscribe();
        let case_id = Uuid::new_v4();
        let input = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "in"}),
        );
        let mut write_rx = orch.artifact_write_receiver.take().unwrap();
        orch.process_artifact(input).await;

        let mut persisted: Vec<Artifact> = Vec::new();
        while let Ok(batch) = write_rx.try_recv() {
            persisted.extend(batch);
        }
        let events = persisted
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
            .count();
        assert_eq!(events, 12, "every streamed event is persisted, once");
        assert_eq!(persisted.len(), 13, "and the returned file entry with them");
        assert!(
            persisted.iter().all(|a| a.case_id == case_id),
            "a streamed artifact carries the case the orchestrator is working"
        );

        let mut requeued = Vec::new();
        while let Some(a) = orch.queue.try_pop() {
            requeued.push(a.artifact_type.clone());
        }
        assert_eq!(requeued, vec![ArtifactType::FileEntry]);

        let mut yielded = None;
        while let Ok(Ok(ev)) =
            tokio::time::timeout(Duration::from_millis(300), status_rx.recv()).await
        {
            if let OrchestratorEvent::ModuleCompleted {
                module_id,
                artifacts_produced,
                ..
            } = ev
            {
                if module_id == "test.streaming_producer" {
                    yielded = Some(artifacts_produced);
                }
            }
        }
        assert_eq!(
            yielded,
            Some(13),
            "the yield counts what was streamed and what was returned"
        );
    }

    /// HUNT-125. The point of streaming is that memory stops scaling with the
    /// output, so a module that outruns the writer must WAIT, not pile its
    /// batches up. With the writer not draining, the module is stopped after a
    /// bounded number of batches; once the writer drains, it completes with
    /// every batch accounted for.
    #[tokio::test]
    async fn a_streaming_module_waits_for_a_writer_that_is_behind() {
        const BATCHES: usize = 200;
        let mut orch = Orchestrator::new(None, 10);
        orch.register_module(Arc::new(StreamingProducer {
            batches: BATCHES,
            per_batch: 1,
        }));
        let case_id = Uuid::new_v4();
        let input = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "in"}),
        );
        let mut write_rx = orch.artifact_write_receiver.take().unwrap();
        let orch = Arc::new(orch);
        let running = {
            let orch = orch.clone();
            tokio::spawn(async move { orch.process_artifact(input).await })
        };

        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            !running.is_finished(),
            "the module must be held back by a writer that is not draining"
        );
        let mut held = 0usize;
        while let Ok(batch) = write_rx.try_recv() {
            held += batch.len();
        }
        assert!(
            held <= 2 * STREAM_WRITER_BACKLOG_MESSAGES + 4,
            "only a bounded number of batches may be in flight behind the writer: {held}"
        );

        // Drain until the run finishes; nothing may be lost on the way.
        let mut total = held;
        while !running.is_finished() {
            while let Ok(batch) = write_rx.try_recv() {
                total += batch.len();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        running.await.unwrap();
        while let Ok(batch) = write_rx.try_recv() {
            total += batch.len();
        }
        assert_eq!(
            total,
            BATCHES + 1,
            "every streamed event and the returned entry"
        );
    }

    /// A module whose `id()` panics whenever it is read from a thread other
    /// than the one that built it.
    ///
    /// `process()` panics are caught by `run_module_isolated`, so the only way
    /// to reproduce a real batch-join failure is to kill the blocking dispatch
    /// task itself: `id()` is read inside that task, and the panic there makes
    /// `spawn_blocking(..).await` return `Err(JoinError)` with no outcomes —
    /// exactly the production failure mode of B3-006.
    struct PanicOnDispatchModule {
        owner: std::thread::ThreadId,
    }

    impl PanicOnDispatchModule {
        fn new() -> Self {
            Self {
                owner: std::thread::current().id(),
            }
        }
    }

    impl ForensicsModule for PanicOnDispatchModule {
        fn id(&self) -> &str {
            if std::thread::current().id() != self.owner {
                panic!("PanicOnDispatchModule: simulated dispatch-thread death");
            }
            "test.panics_on_dispatch"
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
        fn process(&self, _artifact: &Artifact) -> std::result::Result<Vec<Artifact>, ModuleError> {
            unreachable!("the dispatch task dies before process() is reached")
        }
    }

    /// A module that always fails fatally.
    struct FailingModule;
    impl ForensicsModule for FailingModule {
        fn id(&self) -> &str {
            "test.failer"
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
        fn process(&self, _artifact: &Artifact) -> std::result::Result<Vec<Artifact>, ModuleError> {
            Err(ModuleError::FatalError("Something went wrong".to_string()))
        }
    }

    /// A submission is counted from the moment it is sent, and a refused one
    /// is not counted at all (HUNT-043).
    #[test]
    fn a_task_submitter_counts_what_it_sends_and_not_what_it_could_not() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let active = Arc::new(AtomicUsize::new(0));
        let submitter = TaskSubmitter::new(tx, active.clone());
        let artifact = |name: &str| {
            Artifact::new(
                Uuid::new_v4(),
                crate::artifact::ArtifactType::RawEvidence,
                None,
                serde_json::json!({ "name": name }),
            )
        };
        submitter.send(artifact("a")).expect("receiver alive");
        assert_eq!(active.load(Ordering::SeqCst), 1);
        drop(rx);
        assert!(submitter.send(artifact("b")).is_err());
        assert_eq!(
            active.load(Ordering::SeqCst),
            1,
            "a refused submission must not stay counted"
        );
    }

    #[test]
    fn test_orchestrator_creation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let orch = Orchestrator::new(None, 100);
            assert_eq!(orch.module_info_list().len(), 0);
        });
    }

    #[test]
    fn test_worker_count_builder() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let orch = Orchestrator::new(None, 100).with_worker_count(4);
            // Just verify it doesn't panic; worker count is internal
            assert_eq!(orch.module_info_list().len(), 0);
        });
    }

    #[test]
    fn test_register_module() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut orch = Orchestrator::new(None, 100);
            let module = Arc::new(TestModule::new(
                "test.parser",
                vec![ArtifactType::FileEntry],
                2,
            ));
            orch.register_module(module);

            let info = orch.module_info_list();
            assert_eq!(info.len(), 1);
            assert_eq!(info[0].id, "test.parser");
            assert_eq!(info[0].version, "1.0.0");
        });
    }

    #[test]
    fn test_register_multiple_modules() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut orch = Orchestrator::new(None, 100);
            orch.register_module(Arc::new(TestModule::new(
                "mod.a",
                vec![ArtifactType::FileEntry],
                1,
            )));
            orch.register_module(Arc::new(TestModule::new(
                "mod.b",
                vec![ArtifactType::Container],
                1,
            )));
            orch.register_module(Arc::new(TestModule::new(
                "mod.c",
                vec![ArtifactType::FileEntry, ArtifactType::Container],
                0,
            )));

            let info = orch.module_info_list();
            assert_eq!(info.len(), 3);

            // Verify registry has both types mapped
            assert!(orch.registry.contains_key(&ArtifactType::FileEntry));
            assert!(orch.registry.contains_key(&ArtifactType::Container));
            // FileEntry should have mod.a and mod.c
            assert_eq!(orch.registry[&ArtifactType::FileEntry].len(), 2);
            // Container should have mod.b and mod.c
            assert_eq!(orch.registry[&ArtifactType::Container].len(), 2);
        });
    }

    #[test]
    fn test_module_info_list() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut orch = Orchestrator::new(None, 100);
            orch.register_module(Arc::new(TestModule::new(
                "plugin.test.multi",
                vec![ArtifactType::FileEntry, ArtifactType::SystemArtifact],
                3,
            )));

            let info = orch.module_info_list();
            assert_eq!(info.len(), 1);
            assert_eq!(info[0].id, "plugin.test.multi");
            assert!(info[0].subscribes_to.len() >= 2);
        });
    }

    /// A cache entry an in-process caller set explicitly (never DB-refreshed).
    fn pinned(profile: IngestionProfile) -> CachedProfile {
        CachedProfile {
            profile: Some(profile),
            loaded_at: Instant::now(),
            pinned: true,
        }
    }

    #[tokio::test]
    async fn test_profile_filtering() {
        let case_id = Uuid::new_v4();
        let profiles: Arc<RwLock<HashMap<Uuid, CachedProfile>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // No profile = allow all
        assert!(Orchestrator::should_run_module_static(case_id, "any.module", &profiles).await);

        // Profile with enabled list = only enabled modules
        let mut profile = IngestionProfile::new(case_id, "test".into(), "test profile".into());
        profile.enabled_modules = vec!["mod.a".into(), "mod.b".into()];
        profiles.write().await.insert(case_id, pinned(profile));

        assert!(Orchestrator::should_run_module_static(case_id, "mod.a", &profiles).await);
        assert!(Orchestrator::should_run_module_static(case_id, "mod.b", &profiles).await);
        assert!(!Orchestrator::should_run_module_static(case_id, "mod.c", &profiles).await);

        // Profile with disabled list
        let mut profile2 = IngestionProfile::new(case_id, "test2".into(), "test profile 2".into());
        profile2.disabled_modules = vec!["mod.bad".into()];
        profiles.write().await.insert(case_id, pinned(profile2));

        assert!(Orchestrator::should_run_module_static(case_id, "mod.a", &profiles).await);
        assert!(!Orchestrator::should_run_module_static(case_id, "mod.bad", &profiles).await);

        // Different case ID = no profile = allow all
        let other_case = Uuid::new_v4();
        assert!(Orchestrator::should_run_module_static(other_case, "mod.bad", &profiles).await);
    }

    #[tokio::test]
    async fn test_set_and_clear_profile() {
        let orch = Orchestrator::new(None, 100);
        let case_id = Uuid::new_v4();

        // Set a profile
        let profile = IngestionProfile::new(case_id, "custom".into(), "Custom profile".into());
        orch.set_profile(case_id, Some(profile)).await;

        assert!(orch.should_run_module(case_id, "any_module").await);

        // Set a profile with enabled modules
        let mut profile2 = IngestionProfile::new(case_id, "restricted".into(), "restricted".into());
        profile2.enabled_modules = vec!["mod.allowed".into()];
        orch.set_profile(case_id, Some(profile2)).await;

        assert!(orch.should_run_module(case_id, "mod.allowed").await);
        assert!(!orch.should_run_module(case_id, "mod.blocked").await);

        // Clear profile
        orch.set_profile(case_id, None).await;
        assert!(orch.should_run_module(case_id, "mod.blocked").await);
    }

    #[tokio::test]
    async fn test_progress_tracker() {
        let tracker = ProgressTracker::new();
        let case_id = Uuid::new_v4();

        // Initially empty
        assert!(tracker.case_snapshots().await.is_empty());
        assert_eq!(tracker.total_processed().await, 0);

        // record_artifact increments and returns true for new phase
        tracker
            .record_artifact(&ArtifactType::FileEntry, case_id)
            .await;
        tracker
            .record_artifact(&ArtifactType::FileEntry, case_id)
            .await;
        tracker
            .record_artifact(&ArtifactType::ParsedRecord, case_id)
            .await;

        let snapshots = tracker.case_snapshots().await;
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].case_id, case_id);
        assert_eq!(snapshots[0].processed, 3);
        let by_type = &snapshots[0].by_type;
        assert_eq!(by_type.len(), 2);

        let file_count = by_type
            .iter()
            .find(|(k, _)| k == "FileEntry")
            .map(|(_, v)| *v)
            .unwrap_or(0);
        assert_eq!(file_count, 2);
    }

    #[tokio::test]
    async fn test_phase_tracking() {
        let tracker = ProgressTracker::new();
        let case_id = Uuid::new_v4();

        // First time seeing FileEntry -> new phase = true
        let is_new = tracker
            .record_artifact(&ArtifactType::FileEntry, case_id)
            .await;
        assert!(is_new);

        // Second time -> not new = false
        let is_new = tracker
            .record_artifact(&ArtifactType::FileEntry, case_id)
            .await;
        assert!(!is_new);

        // Different type -> new phase = true
        let is_new = tracker
            .record_artifact(&ArtifactType::ParsedRecord, case_id)
            .await;
        assert!(is_new);
    }

    #[tokio::test]
    async fn test_task_submitter() {
        let orch = Orchestrator::new(None, 10);
        let sender = orch.task_submitter();
        let case_id = Uuid::new_v4();

        let artifact = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "test.txt"}),
        );
        // Should be able to send without blocking
        sender.send(artifact).unwrap();
    }

    #[tokio::test]
    async fn test_event_broadcast() {
        let orch = Orchestrator::new(None, 10);
        let mut rx = orch.event_receiver();
        let tx = orch.event_sender();
        let case_id = Uuid::new_v4();

        let artifact = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "test.txt"}),
        );
        tx.send(artifact).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.case_id, case_id);
    }

    #[test]
    fn test_phase_name() {
        assert_eq!(phase_name(&ArtifactType::Container), "Container Extraction");
        assert_eq!(phase_name(&ArtifactType::FileEntry), "File Extraction");
        assert_eq!(phase_name(&ArtifactType::ParsedRecord), "Record Parsing");
    }

    #[tokio::test]
    async fn test_active_tasks_counter() {
        let orch = Orchestrator::new(None, 10);
        let counter = orch.active_tasks();

        assert_eq!(counter.load(Ordering::SeqCst), 0);
        counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        counter.fetch_sub(1, Ordering::SeqCst);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_ingest_without_db() {
        let orch = Orchestrator::new(None, 100);
        let case_id = Uuid::new_v4();

        // Ingest should work without a database connection
        let result = orch
            .ingest_artifact(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({"name": "evidence.bin"}),
            )
            .await;
        assert!(result.is_ok());

        // Active tasks should have been incremented
        assert_eq!(orch.active_tasks().load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_module_error_variants() {
        let err1 = ModuleError::InvalidInputFormat("bad format".into());
        assert!(format!("{}", err1).contains("bad format"));

        let err2 = ModuleError::ParsingError("parse failed".into());
        assert!(format!("{}", err2).contains("parse failed"));

        let err3 = ModuleError::FatalError("fatal".into());
        assert!(format!("{}", err3).contains("fatal"));
    }

    /// A module returning InvalidInputFormat is a skip, not a failure:
    /// the orchestrator should emit ModuleCompleted with artifacts_produced=0,
    /// not ModuleError.
    #[tokio::test]
    async fn test_skipping_module_emits_completed_with_zero_artifacts() {
        let mut orch = Orchestrator::new(None, 10);
        orch.register_module(Arc::new(SkippingModule));

        let mut status_rx = orch.status_sender().subscribe();
        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "x"}));

        orch.process_artifact(artifact).await;

        let mut saw_completed = false;
        let mut saw_error = false;
        while let Ok(Ok(event)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), status_rx.recv()).await
        {
            match event {
                OrchestratorEvent::ModuleCompleted {
                    module_id,
                    artifacts_produced,
                    ..
                } if module_id == "test.skipper" && artifacts_produced == 0 => {
                    saw_completed = true;
                    break;
                }
                OrchestratorEvent::ModuleError { module_id, .. } if module_id == "test.skipper" => {
                    saw_error = true;
                }
                _ => {}
            }
        }
        assert!(
            saw_completed,
            "Expected ModuleCompleted with 0 artifacts for skip path"
        );
        assert!(!saw_error, "Skip path must not emit ModuleError");
    }

    /// A module returning FatalError must surface as ModuleError on the status bus
    /// so the GUI/REPL can mark the run as errored.
    #[tokio::test]
    async fn test_failing_module_emits_module_error() {
        let mut orch = Orchestrator::new(None, 10);
        orch.register_module(Arc::new(FailingModule));

        let mut status_rx = orch.status_sender().subscribe();
        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "x"}));

        orch.process_artifact(artifact).await;

        let mut saw_error = false;
        while let Ok(Ok(event)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), status_rx.recv()).await
        {
            if let OrchestratorEvent::ModuleError {
                module_id, error, ..
            } = event
            {
                if module_id == "test.failer" && error.contains("Something went wrong") {
                    saw_error = true;
                    break;
                }
            }
        }
        assert!(saw_error, "Expected ModuleError for fatal module failure");
    }

    /// B3-006: when the blocking module dispatch never joins, the artifact must
    /// be recorded as FAILED, not as an artifact that produced nothing.
    ///
    /// What an examiner learns: a module that could not be run says so, so the
    /// case does not present as fully processed. The wrong answer this guards
    /// against is silence — the pre-fix code turned the join error into an
    /// empty outcome list, which is byte-for-byte what "every module ran and
    /// found nothing" looks like downstream: no ModuleError event, no failed
    /// processing-log row, nothing to retry, and an evidence subtree that
    /// skipped every parser while the UI showed it complete.
    #[tokio::test]
    async fn batch_dispatch_join_failure_is_reported_not_silently_empty() {
        let mut orch = Orchestrator::new(None, 10);
        orch.register_module(Arc::new(PanicOnDispatchModule::new()));

        let mut status_rx = orch.status_sender().subscribe();
        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "x"}));

        orch.process_artifact(artifact).await;

        let mut saw_error: Option<String> = None;
        let mut saw_completed = false;
        while let Ok(Ok(event)) =
            tokio::time::timeout(std::time::Duration::from_millis(500), status_rx.recv()).await
        {
            match event {
                OrchestratorEvent::ModuleError {
                    module_id, error, ..
                } if module_id == "test.panics_on_dispatch" => {
                    saw_error = Some(error);
                    break;
                }
                OrchestratorEvent::ModuleCompleted { module_id, .. }
                    if module_id == "test.panics_on_dispatch" =>
                {
                    saw_completed = true;
                }
                _ => {}
            }
        }

        let error = saw_error.expect(
            "a dispatch that never joined must emit ModuleError, not resolve to an empty batch",
        );
        assert!(
            error.contains("did not complete"),
            "the error must say the module did not run, got: {error}"
        );
        assert!(
            !saw_completed,
            "a failed dispatch must never be reported as a completed module"
        );
    }

    /// Every module subscribed to an artifact type must run for a single
    /// artifact, each emitting its own outcome. Guards the change from one
    /// spawn_blocking-per-module to one blocking dispatch per artifact: the
    /// producer, the skipper, and the failer all subscribe to FileEntry and all
    /// three outcomes must appear for one input.
    #[tokio::test]
    async fn test_all_subscribed_modules_run_for_one_artifact() {
        let mut orch = Orchestrator::new(None, 10);
        orch.register_module(Arc::new(TestModule::new(
            "test.producer",
            vec![ArtifactType::FileEntry],
            2,
        )));
        orch.register_module(Arc::new(SkippingModule)); // test.skipper
        orch.register_module(Arc::new(FailingModule)); // test.failer

        let mut status_rx = orch.status_sender().subscribe();
        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "x"}));
        orch.process_artifact(artifact).await;

        let mut producer_completed: Option<usize> = None;
        let mut skipper_completed_zero = false;
        let mut failer_errored = false;
        while let Ok(Ok(event)) =
            tokio::time::timeout(std::time::Duration::from_millis(300), status_rx.recv()).await
        {
            match event {
                OrchestratorEvent::ModuleCompleted {
                    module_id,
                    artifacts_produced,
                    ..
                } => {
                    if module_id == "test.producer" {
                        producer_completed = Some(artifacts_produced);
                    }
                    if module_id == "test.skipper" && artifacts_produced == 0 {
                        skipper_completed_zero = true;
                    }
                }
                OrchestratorEvent::ModuleError { module_id, .. } if module_id == "test.failer" => {
                    failer_errored = true;
                }
                _ => {}
            }
        }
        assert_eq!(
            producer_completed,
            Some(2),
            "producer must run and report 2 artifacts"
        );
        assert!(skipper_completed_zero, "skipper must complete with 0");
        assert!(failer_errored, "failer must emit ModuleError");
    }

    #[tokio::test]
    async fn produced_batch_persists_all_and_requeues_only_non_timeline() {
        // Guards the produced-batch split: every produced artifact must still be
        // queued to the writer (persisted), while only non-TimelineEvent
        // artifacts are re-dispatched. This is what lets the writer take the
        // batch by move and only the re-queued subset be cloned.
        let mut orch = Orchestrator::new(None, 10);
        orch.register_module(Arc::new(MixedProducer));
        let case_id = Uuid::new_v4();
        let input = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "root" }),
        );

        // Observe exactly what the async writer would persist.
        let mut write_rx = orch.artifact_write_receiver.take().unwrap();
        orch.process_artifact(input).await;

        // Both produced artifacts are queued for persistence, including the
        // terminal TimelineEvent.
        let batch = write_rx
            .try_recv()
            .expect("a batch was queued to the writer");
        assert_eq!(batch.len(), 2, "the whole produced batch must be persisted");
        assert!(batch
            .iter()
            .any(|a| a.artifact_type == ArtifactType::FileEntry));
        assert!(batch
            .iter()
            .any(|a| a.artifact_type == ArtifactType::TimelineEvent));

        // Only the non-TimelineEvent artifact is re-queued into the pipeline.
        let mut requeued = Vec::new();
        while let Some(a) = orch.queue.try_pop() {
            requeued.push(a.artifact_type.clone());
        }
        assert_eq!(requeued, vec![ArtifactType::FileEntry]);
    }

    /// HUNT-025. A module's fan-out must not be held in memory in full.
    ///
    /// One FileEntry produces two hundred children through the real pipeline,
    /// with a queue bound of sixteen. The unbounded channel this replaced kept
    /// every one of those two hundred artifacts — metadata document and all —
    /// resident until a worker got to it, which on a real ext4 or NTFS image is
    /// hundreds of thousands of artifacts and an ingest that dies part-way
    /// through an examination.
    ///
    /// Both halves matter and are asserted: the resident set stays inside the
    /// bound, AND every artifact is still examined. A queue that met the bound
    /// by dropping the overflow would be a worse bug than the one it fixed —
    /// evidence found and then silently discarded.
    #[tokio::test]
    async fn a_large_fan_out_spills_rather_than_holding_every_artifact_in_memory() {
        const FAN_OUT: usize = 200;
        const CAPACITY: usize = 16;

        let mut orch = Orchestrator::new(None, 512)
            .with_worker_count(1)
            .with_exit_on_idle(true)
            .with_idle_timeout(Duration::from_millis(200))
            .with_queue_capacity(CAPACITY);
        orch.register_module(Arc::new(TestModule::new(
            "test.fanout",
            vec![ArtifactType::FileEntry],
            FAN_OUT,
        )));

        let queue = orch.task_queue();
        let mut status_rx = orch.status_sender().subscribe();
        let case_id = Uuid::new_v4();
        orch.ingest_artifact(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "root" }),
        )
        .await
        .expect("the root artifact must be queued");

        let handle = tokio::spawn(orch.run());
        tokio::time::timeout(Duration::from_secs(30), handle)
            .await
            .expect("the run must reach idle and exit")
            .expect("the orchestrator task must not panic");

        let mut total_artifacts = 0usize;
        while let Ok(event) = status_rx.try_recv() {
            if let OrchestratorEvent::ProcessingComplete {
                case_id: reported,
                total_artifacts: n,
                ..
            } = event
            {
                if reported == case_id {
                    total_artifacts = n;
                }
            }
        }
        assert_eq!(
            total_artifacts,
            FAN_OUT + 1,
            "the root and every one of its children must be examined"
        );

        let stats = queue.stats();
        assert!(
            stats.peak_resident <= CAPACITY,
            "the queue must never hold more than {CAPACITY} artifacts in memory, peaked at {}",
            stats.peak_resident
        );
        assert!(
            stats.spilled_total >= (FAN_OUT - CAPACITY) as u64,
            "the fan-out past the bound belongs on disk, only {} spilled",
            stats.spilled_total
        );
        assert_eq!(
            stats.spill_failures, 0,
            "the spill must have worked; a failure means the bound was not in force"
        );
        assert_eq!(
            queue.census().active(case_id),
            0,
            "a finished run leaves no outstanding work for the case"
        );
    }

    #[tokio::test]
    async fn test_cancellation_per_case_is_isolated() {
        let orch = Orchestrator::new(None, 10);
        let handle = orch.cancellation_handle();
        let clone = handle.clone();
        let case_a = Uuid::new_v4();
        let case_b = Uuid::new_v4();

        assert!(!handle.is_cancelled(case_a));
        assert!(!handle.is_cancelled(case_b));

        // Cancelling one case must not affect the other, and must not trigger a
        // global shutdown (the orchestrator keeps serving other cases).
        clone.cancel_case(case_a);
        assert!(handle.is_cancelled(case_a), "clones share cancelled cases");
        assert!(
            !handle.is_cancelled(case_b),
            "a per-case cancel must not spill to other cases"
        );
        assert!(
            !handle.is_shutting_down(),
            "a per-case cancel must not shut the orchestrator down"
        );
    }

    #[tokio::test]
    async fn test_clear_case_cancel_lifts_the_poison() {
        let orch = Orchestrator::new(None, 10);
        let handle = orch.cancellation_handle();
        let case_a = Uuid::new_v4();
        let case_b = Uuid::new_v4();

        handle.cancel_case(case_a);
        assert!(handle.is_cancelled(case_a));

        // A new ingest clears the cancel so the case runs again; other cases and
        // a never-cancelled case are unaffected.
        handle.clear_case_cancel(case_a);
        assert!(
            !handle.is_cancelled(case_a),
            "clearing a per-case cancel must let the case process again"
        );
        handle.clear_case_cancel(case_b); // no-op, must not panic
        assert!(!handle.is_cancelled(case_b));

        // A global shutdown still overrides a cleared per-case flag.
        handle.cancel_all();
        assert!(handle.is_cancelled(case_a), "global shutdown wins");
    }

    #[tokio::test]
    async fn clearing_all_case_cancels_reports_what_it_lifted() {
        // B2-061: the orchestrator lifts per-case cancels only once the queue
        // has drained. Until then `has_cancelled_cases` must stay true, which is
        // what keeps a newly submitted ad-hoc job from resuming a cancelled
        // ingest.
        let orch = Orchestrator::new(None, 10);
        let handle = orch.cancellation_handle();
        let case_a = Uuid::new_v4();
        let case_b = Uuid::new_v4();

        assert!(!handle.has_cancelled_cases());
        handle.cancel_case(case_a);
        handle.cancel_case(case_b);
        assert!(handle.has_cancelled_cases());

        assert_eq!(handle.clear_all_case_cancels(), 2);
        assert!(!handle.is_cancelled(case_a));
        assert!(!handle.is_cancelled(case_b));
        assert!(!handle.has_cancelled_cases());
        // Idempotent: a second sweep lifts nothing and must not panic.
        assert_eq!(handle.clear_all_case_cancels(), 0);
    }

    #[tokio::test]
    async fn test_global_cancel_shuts_down_all_cases() {
        let orch = Orchestrator::new(None, 10);
        let handle = orch.cancellation_handle();
        let case_a = Uuid::new_v4();
        let case_b = Uuid::new_v4();

        handle.cancel_all();
        assert!(handle.is_shutting_down());
        assert!(
            handle.is_cancelled(case_a),
            "global cancel covers every case"
        );
        assert!(
            handle.is_cancelled(case_b),
            "global cancel covers every case"
        );
    }

    /// Cancelled orchestrator must not dispatch modules for queued artifacts.
    #[tokio::test]
    async fn test_worker_skips_artifact_when_cancelled() {
        let mut orch = Orchestrator::new(None, 10);
        orch.register_module(Arc::new(FailingModule));
        orch.cancellation_handle().cancel_all();

        let mut status_rx = orch.status_sender().subscribe();
        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "x"}));

        orch.process_artifact(artifact).await;

        // No ModuleStarted/ModuleError may be emitted for the skipped artifact
        while let Ok(Ok(event)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), status_rx.recv()).await
        {
            match event {
                OrchestratorEvent::ModuleStarted { .. } | OrchestratorEvent::ModuleError { .. } => {
                    panic!("cancelled orchestrator must not dispatch modules");
                }
                _ => {}
            }
        }
    }

    /// ProgressReporter must rate-limit report() but always emit report_now().
    #[tokio::test]
    async fn test_progress_reporter_rate_limit() {
        let (tx, mut rx) = broadcast_channel(64);
        let reporter = ProgressReporter::new(tx, "test.module");
        let artifact_id = Uuid::new_v4();

        // First call emits; the following rapid calls are suppressed (1s window)
        for i in 0..5u64 {
            reporter.report(artifact_id, i, Some(100), "items");
        }
        // Unconditional final update
        reporter.report_now(artifact_id, 100, Some(100), "items");

        let mut received = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let OrchestratorEvent::ModuleProgress {
                module_id,
                units_done,
                units_total,
                unit,
                ..
            } = event
            {
                assert_eq!(module_id, "test.module");
                assert_eq!(units_total, Some(100));
                assert_eq!(unit, "items");
                received.push(units_done);
            }
        }
        assert_eq!(
            received,
            vec![0, 100],
            "expected first report + report_now only"
        );
    }

    /// Regression: ModuleError must carry the failing artifact's id so the
    /// GUI can offer a "re-run this module on this artifact" link.
    #[tokio::test]
    async fn failing_module_emits_error_with_artifact_id() {
        let mut orch = Orchestrator::new(None, 10);
        orch.register_module(Arc::new(FailingModule));

        let mut status_rx = orch.status_sender().subscribe();
        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "x"}));
        let expected_artifact_id = artifact.id;

        orch.process_artifact(artifact).await;

        let mut got_artifact_id: Option<Uuid> = None;
        while let Ok(Ok(event)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), status_rx.recv()).await
        {
            if let OrchestratorEvent::ModuleError {
                module_id,
                artifact_id,
                ..
            } = event
            {
                if module_id == "test.failer" {
                    got_artifact_id = Some(artifact_id);
                    break;
                }
            }
        }
        assert_eq!(
            got_artifact_id,
            Some(expected_artifact_id),
            "ModuleError must report the artifact_id that failed"
        );
    }

    /// ThroughputTracker: while tasks_total keeps climbing the run is
    /// "discovering" and ETA is suppressed; once tasks_total holds steady for
    /// two ticks it stabilizes, a trailing-window rate is available, and ETA is
    /// computed. Instants are injected so the derivation is deterministic.
    #[test]
    fn throughput_tracker_rate_eta_and_discovery() {
        let mut tr = ThroughputTracker::new();
        let t0 = Instant::now();

        // Tick 1: first observation, total 8. Always discovering, no ETA.
        let s = tr.observe(t0, 0, 8);
        assert!(s.discovering, "first tick is always discovering");
        assert_eq!(s.eta_seconds, None);

        // Tick 2: total climbs 8 -> 12 (producers fanning out). Resets stability.
        let s = tr.observe(t0 + Duration::from_secs(2), 3, 12);
        assert!(s.discovering, "growing total => still discovering");
        assert_eq!(s.eta_seconds, None, "no ETA while discovering");

        // Tick 3: total stable at 12 (1st stable tick). Below threshold => still discovering.
        let s = tr.observe(t0 + Duration::from_secs(4), 6, 12);
        assert!(s.discovering);
        assert_eq!(s.eta_seconds, None);

        // Tick 4: total stable at 12 (2nd stable tick) => discovered.
        let s = tr.observe(t0 + Duration::from_secs(6), 9, 12);
        assert!(!s.discovering, "stable for 2 ticks => not discovering");
        // Completed advanced 0 -> 9 over the 6s window => 1.5/s.
        assert!(
            (s.rate_per_sec - 1.5).abs() < 1e-6,
            "rate = {}",
            s.rate_per_sec
        );
        // remaining = 12 - 9 = 3; eta = ceil(3 / 1.5) = 2.
        assert_eq!(s.eta_seconds, Some(2));

        // Tick 5: total climbs again 12 -> 20 => back to discovering, ETA suppressed.
        let s = tr.observe(t0 + Duration::from_secs(8), 11, 20);
        assert!(s.discovering, "a renewed increase re-enters discovery");
        assert_eq!(s.eta_seconds, None);
    }

    /// A new busy wave gets a fresh per-case ThroughputTracker (the main loop
    /// clears the map when it goes from idle to busy), which must re-enter
    /// "discovering" rather than inheriting the previous wave's stable state.
    #[test]
    fn a_new_busy_wave_re_enters_discovery() {
        let mut tr = ThroughputTracker::new();
        let t0 = Instant::now();
        // Drive to a stable, non-discovering state.
        tr.observe(t0, 0, 4);
        tr.observe(t0 + Duration::from_secs(2), 1, 4);
        let s = tr.observe(t0 + Duration::from_secs(4), 2, 4);
        assert!(!s.discovering);

        let mut fresh = ThroughputTracker::new();
        let s = fresh.observe(t0 + Duration::from_secs(6), 2, 4);
        assert!(
            s.discovering,
            "a new wave's first tick must be discovering again"
        );
        assert_eq!(s.eta_seconds, None);
    }
}

#[cfg(test)]
mod pre_queue_idle_tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    /// Length of the pre-queue phase these tests simulate. Acquisition hashing
    /// of a 512 MB image takes minutes; the shape that matters is only that it
    /// outlasts the orchestrator's idle window, so the window is shortened and
    /// the phase kept short enough for a unit test.
    const PRE_QUEUE_WORK: Duration = Duration::from_millis(900);
    const IDLE_WINDOW: Duration = Duration::from_millis(200);

    /// A real file to hash, so `IngestionService::ingest_artifact` runs its
    /// actual acquisition-hashing path rather than skipping it.
    fn evidence_file() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp evidence file");
        let bytes = vec![0xABu8; 1024 * 1024];
        f.write_all(&bytes).expect("write evidence");
        f.flush().expect("flush evidence");
        f
    }

    fn evidence_metadata(file: &tempfile::NamedTempFile) -> serde_json::Value {
        json!({
            "name": "evidence.dd",
            "source_path": file.path().to_str().expect("utf-8 temp path"),
        })
    }

    /// LIVE-001. Ingest whose pre-queue work outlasts the idle window must
    /// still reach the queue.
    ///
    /// Reproduces the live failure: `seance scan` on a 512 MB image spends
    /// ~20 s computing MD5 + SHA-1 + SHA-256 before the first artifact is
    /// queued, while an `exit_on_idle` orchestrator is already counting down
    /// from an empty queue. Without the guard the orchestrator exits mid-hash
    /// and the ingest hits a closed channel, so nothing is ever examined —
    /// see `pre_queue_work_without_guard_loses_the_evidence`, which pins that
    /// behaviour.
    #[tokio::test]
    async fn pre_queue_work_longer_than_idle_window_still_ingests() {
        let file = evidence_file();
        let orchestrator = Orchestrator::new(None, 100)
            .with_exit_on_idle(true)
            .with_idle_timeout(IDLE_WINDOW)
            .with_worker_count(2);
        let ingestion = orchestrator.ingestion_service();
        let active_tasks = orchestrator.active_tasks();
        let handle = tokio::spawn(orchestrator.run());

        let guard = ActiveTaskGuard::new(active_tasks);
        // Stand-in for acquisition hashing of a large image.
        tokio::time::sleep(PRE_QUEUE_WORK).await;
        let result = ingestion
            .ingest_artifact(
                Uuid::new_v4(),
                ArtifactType::RawEvidence,
                None,
                evidence_metadata(&file),
            )
            .await;
        drop(guard);

        assert!(
            result.is_ok(),
            "evidence queued after {:?} of pre-queue work must still be accepted, got {:?}",
            PRE_QUEUE_WORK,
            result.err()
        );

        // And the guard must not wedge the run: once the artifact is processed
        // the orchestrator still reaches idle and exits.
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("orchestrator must still exit on idle after the guard is dropped")
            .expect("orchestrator task panicked");
    }

    /// The unguarded shape, pinned so the guarded test above is known to be
    /// testing something real: with nothing marking the pre-queue phase busy,
    /// the orchestrator exits after the idle window and the evidence is lost
    /// with `Failed to send artifact to queue` — exactly what the product did.
    ///
    /// NOTE for whoever moves the guard down into
    /// `IngestionService::ingest_artifact` (the durable fix for this class):
    /// this test will then start failing, because the ingest will hold its own
    /// guard and the send will succeed. That is the fix working. Delete or
    /// invert this test at that point — do NOT make it pass again by removing
    /// the guard.
    #[tokio::test]
    async fn pre_queue_work_without_guard_loses_the_evidence() {
        let file = evidence_file();
        let orchestrator = Orchestrator::new(None, 100)
            .with_exit_on_idle(true)
            .with_idle_timeout(IDLE_WINDOW)
            .with_worker_count(2);
        let ingestion = orchestrator.ingestion_service();
        let active_tasks = orchestrator.active_tasks();
        let handle = tokio::spawn(orchestrator.run());

        tokio::time::sleep(PRE_QUEUE_WORK).await;
        let result = ingestion
            .ingest_artifact(
                Uuid::new_v4(),
                ArtifactType::RawEvidence,
                None,
                evidence_metadata(&file),
            )
            .await;

        let err = result.expect_err("orchestrator has exited; the queue is gone");
        assert!(
            err.to_string().contains("Failed to send artifact to queue"),
            "unexpected error for a dead queue: {err}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
        // A failed send must also roll back the count it took, or a later run
        // sharing this counter could never go idle.
        assert_eq!(
            active_tasks.load(Ordering::SeqCst),
            0,
            "a rejected ingest must not leave the active-task count raised"
        );
    }

    /// Same rule for the orchestrator's own direct-queue entry point.
    ///
    /// `Orchestrator::ingest_artifact` incremented `active_tasks` and then
    /// used `map_err(..)?` on the send, so a rejected artifact left the count
    /// permanently at 1: nothing downstream owns the decrement for an artifact
    /// that never reached a worker. An `exit_on_idle` run whose ingest failed
    /// that way could never take its idle branch, so the caller that had
    /// already been told the ingest failed then waited on an orchestrator that
    /// would never finish — the scan neither examines the evidence nor
    /// terminates.
    #[tokio::test]
    async fn direct_ingest_rolls_back_the_count_when_the_queue_is_gone() {
        let orchestrator = Orchestrator::new(None, 100);
        let active_tasks = orchestrator.active_tasks();
        // Close the queue the way a finished `run()` does, without needing one.
        orchestrator.task_queue().close();

        let err = orchestrator
            .ingest_artifact(
                Uuid::new_v4(),
                ArtifactType::RawEvidence,
                None,
                json!({ "name": "evidence.dd" }),
            )
            .await
            .expect_err("the queue is closed; the artifact cannot be accepted");
        assert!(
            err.to_string().contains("Failed to send artifact to queue"),
            "unexpected error for a closed queue: {err}"
        );
        assert_eq!(
            active_tasks.load(Ordering::SeqCst),
            0,
            "a rejected direct ingest must not leave the active-task count raised, \
             or the orchestrator can never go idle"
        );
    }
}

#[cfg(test)]
mod unclaimed_source_tests {
    use super::*;
    use serde_json::json;

    fn source(metadata: serde_json::Value) -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::RawEvidence,
            None,
            metadata,
        )
    }

    /// HUNT-060. A source every module ran over and none claimed showed an
    /// empty tree on every screen, with the fact recorded only as the absence
    /// of a network module from a list of eighteen storage and memory ones.
    #[test]
    fn a_source_nothing_parsed_says_so_about_itself() {
        let pcap = source(json!({"name": "case001.pcap", "path": "/ev/case001.pcap"}));
        let record = unclaimed_source_record(&pcap, true, 18, false).expect("a record is emitted");

        assert_eq!(record.metadata["type"], "SourceUnparsed");
        assert_eq!(record.parent_id, Some(pcap.id));
        assert_eq!(record.metadata["modules_run"], 18);
        assert_eq!(record.metadata["source_name"], "case001.pcap");
        // It is a shortfall, and belongs in the census as one: the evidence is
        // here and its contents were not recovered.
        assert_eq!(record.metadata["inventory_incomplete"], json!(true));
        // And it says whose limitation it is.
        let message = record.metadata["message"].as_str().unwrap();
        assert!(message.contains("this build"), "{message}");
        assert!(
            message.contains("not about the evidence"),
            "the record must not read as 'the source was empty': {message}"
        );
    }

    /// Every condition changes what the silence means, so each one withholds
    /// the record rather than guessing.
    #[test]
    fn it_is_withheld_wherever_the_silence_means_something_else() {
        let src = source(json!({"name": "case001.pcap"}));

        // Something WAS produced: ordinary.
        assert!(unclaimed_source_record(&src, false, 18, false).is_none());
        // A module failed or was cancelled: the results are unknown, not empty,
        // and saying "nothing parses this" would be a claim the run cannot make.
        assert!(unclaimed_source_record(&src, true, 18, true).is_none());
        // Nothing ran at all: that is a statement about the module registry.
        assert!(unclaimed_source_record(&src, true, 0, false).is_none());

        // A FILE inside a source that no parser reads is ordinary — the record
        // is for a whole exhibit nothing claimed.
        let inner = Artifact::new(
            src.case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "notes.txt"}),
        )
        .with_parent(src.id);
        assert!(unclaimed_source_record(&inner, true, 18, false).is_none());
    }

    /// What the source was taken to be is the first thing an examiner asks of
    /// this record, and a declared type is weaker evidence than a detected one.
    #[test]
    fn the_record_names_what_the_source_was_taken_to_be() {
        let detected = source(json!({"name": "x.bin", "detected_type": "MP3"}));
        let record = unclaimed_source_record(&detected, true, 3, false).unwrap();
        assert_eq!(record.metadata["detected_type"], "MP3");

        let declared = source(json!({"name": "x.bin", "user_specified_type": "disk_image"}));
        let record = unclaimed_source_record(&declared, true, 3, false).unwrap();
        assert_eq!(record.metadata["detected_type"], "declared as disk_image");

        // "auto" is not a declaration; it is the absence of one.
        let neither = source(json!({"name": "x.bin", "user_specified_type": "auto"}));
        let record = unclaimed_source_record(&neither, true, 3, false).unwrap();
        assert!(record.metadata["detected_type"].is_null());
    }
}

#[cfg(test)]
mod late_hash_tests {
    use super::*;
    use serde_json::json;

    fn held(case_id: Uuid, parent_id: Uuid, outcome: PendingHashOutcome) -> LateHashes {
        let late: LateHashes = Arc::new(StdMutex::new(HashMap::new()));
        late.lock().unwrap().insert(
            parent_id,
            PendingHash {
                case_id,
                parent_id,
                module_id: "plugin.hash.file_hasher".into(),
                outcome,
                attempts: 60,
            },
        );
        late
    }

    /// A held skip reason is written with the late record as the same triple
    /// `mark_file_hashes_skipped_batch` stamps (HUNT-199).
    #[test]
    fn a_held_skip_reason_is_stamped_on_the_late_record() {
        let case_id = Uuid::new_v4();
        let mut record = Artifact::new(case_id, ArtifactType::FileEntry, None, json!({}));
        let late = held(
            case_id,
            record.id,
            PendingHashOutcome::Skipped {
                reason: "size".into(),
            },
        );
        let merged = merge_late_hashes(std::slice::from_mut(&mut record), &late);
        assert_eq!(merged, vec![record.id]);
        assert_eq!(record.metadata["content_incomplete"], json!(true));
        assert_eq!(
            record.metadata["content_incomplete_reason"],
            json!("hash_skipped_size")
        );
        assert_eq!(record.metadata["hash_skipped"], json!("size"));
        assert!(record.metadata.get("md5").is_none());
    }

    /// A parent id is only meaningful within its case: a record of another
    /// case with the same id is never given the held digests (B4-030).
    #[test]
    fn a_held_digest_never_crosses_cases() {
        let mut record = Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, None, json!({}));
        let late = held(
            Uuid::new_v4(),
            record.id,
            PendingHashOutcome::Digests {
                md5: "m".into(),
                sha1: "s".into(),
                sha256: "t".into(),
            },
        );
        assert!(merge_late_hashes(std::slice::from_mut(&mut record), &late).is_empty());
        assert!(record.metadata.get("md5").is_none());
        assert_eq!(late.lock().unwrap().len(), 1, "still held for its own case");
    }
}

/// The writers' failure paths: what is retried, what is isolated, and above all
/// what is *reported* when evidence cannot be saved.
#[cfg(test)]
mod writer_loss_tests {
    use super::*;
    use crate::db::ProcessingLogRow;
    use crate::profile::{AdHocJob, IngestionProfile, ProcessingLogEntry};
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex as StdMutex2;

    /// A database that refuses what it is told to refuse.
    #[derive(Default)]
    struct StubDb {
        /// Refuse, with SQLite's foreign-key error, any batch holding a row
        /// marked `orphan`.
        refuse_orphans: bool,
        /// Refuse every artifact batch for a non-foreign-key reason.
        fail_artifacts: AtomicBool,
        /// Refuse every processing-log batch.
        fail_log: AtomicBool,
        stored: StdMutex2<Vec<Uuid>>,
        superseded_by: StdMutex2<Vec<Uuid>>,
        attempts: AtomicUsize,
    }

    #[async_trait]
    impl DatabaseConnection for StubDb {
        async fn initialize(&self) -> Result<()> {
            Ok(())
        }
        async fn create_case(&self, _n: &str, _e: &str) -> Result<Uuid> {
            Ok(Uuid::new_v4())
        }
        async fn record_artifact(&self, a: &Artifact) -> Result<()> {
            self.record_artifacts_batch(std::slice::from_ref(a)).await
        }
        async fn record_artifacts_batch(&self, artifacts: &[Artifact]) -> Result<()> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.fail_artifacts.load(Ordering::SeqCst) {
                anyhow::bail!("database is locked");
            }
            if self.refuse_orphans
                && artifacts
                    .iter()
                    .any(|a| a.metadata.get("orphan") == Some(&json!(true)))
            {
                anyhow::bail!("(code: 787) FOREIGN KEY constraint failed");
            }
            self.stored
                .lock()
                .unwrap()
                .extend(artifacts.iter().map(|a| a.id));
            Ok(())
        }
        async fn mark_records_superseded(
            &self,
            _case_id: Uuid,
            _parent_id: Uuid,
            _record_type: &str,
            _field: &str,
            _status: &str,
            by_artifact: Uuid,
        ) -> Result<u64> {
            self.superseded_by.lock().unwrap().push(by_artifact);
            Ok(1)
        }
        async fn record_processing_log_batch(&self, _e: &[ProcessingLogRow]) -> Result<()> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.fail_log.load(Ordering::SeqCst) {
                anyhow::bail!("database is locked");
            }
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

    fn artifact(metadata: serde_json::Value) -> Artifact {
        Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, metadata)
    }

    fn late() -> LateHashes {
        Arc::new(StdMutex::new(HashMap::new()))
    }

    fn log_row() -> ProcessingLogRow {
        ProcessingLogRow {
            case_id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            module_id: "m".into(),
            status: "error".into(),
            artifacts_produced: 0,
            error_message: None,
            duration_ms: 1,
            zero_yield: None,
        }
    }

    /// One refused row must cost only itself at shutdown: the rest of the
    /// buffer is written, and the one that cannot be is reported as lost.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn final_flush_isolates_a_refused_row_and_records_what_remains() {
        let _g = crate::evidence_loss::TEST_SERIAL
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::evidence_loss::reset_for_test();
        let db = Arc::new(StubDb {
            refuse_orphans: true,
            ..Default::default()
        });
        let dyn_db: Arc<dyn DatabaseConnection> = db.clone();
        let mut buffer = vec![
            artifact(json!({})),
            artifact(json!({"orphan": true})),
            artifact(json!({})),
        ];
        let orphan_id = buffer[1].id;

        final_flush_artifact_buffer(&dyn_db, &mut buffer, &late()).await;

        assert_eq!(db.stored.lock().unwrap().len(), 2, "valid rows are written");
        assert!(buffer.is_empty());
        let loss = crate::evidence_loss::snapshot().not_written;
        assert_eq!(loss.dropped, 1);
        assert_eq!(loss.ids, vec![orphan_id.to_string()]);
    }

    /// A final flush that fails outright records every artifact it lost.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn final_flush_failure_is_recorded_as_evidence_loss() {
        let _g = crate::evidence_loss::TEST_SERIAL
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::evidence_loss::reset_for_test();
        let db = Arc::new(StubDb::default());
        db.fail_artifacts.store(true, Ordering::SeqCst);
        let dyn_db: Arc<dyn DatabaseConnection> = db;
        let mut buffer = vec![artifact(json!({})), artifact(json!({}))];

        final_flush_artifact_buffer(&dyn_db, &mut buffer, &late()).await;

        let loss = crate::evidence_loss::snapshot().not_written;
        assert_eq!(loss.dropped, 2);
        assert!(loss.first_reason.unwrap().contains("database is locked"));
    }

    /// A superseding record written through the isolation path still marks what
    /// it answers; a refused one marks nothing.
    #[tokio::test]
    async fn isolated_writes_still_apply_supersession() {
        let db = Arc::new(StubDb {
            refuse_orphans: true,
            ..Default::default()
        });
        let dyn_db: Arc<dyn DatabaseConnection> = db.clone();
        let parent = Uuid::new_v4();
        let answer = artifact(json!({
            "supersedes_status": "locked",
            "type": "whatsapp_status",
        }))
        .with_parent(parent);
        let refused_answer = artifact(json!({
            "orphan": true,
            "supersedes_status": "locked",
            "type": "whatsapp_status",
        }))
        .with_parent(parent);
        let answer_id = answer.id;

        let refused =
            write_isolating_refused_rows(&dyn_db, vec![answer, refused_answer.clone()]).await;

        assert_eq!(refused.len(), 1);
        assert_eq!(
            *db.superseded_by.lock().unwrap(),
            vec![answer_id],
            "only the stored answer supersedes"
        );
    }

    /// A foreign-key refusal cannot clear on retry, so it must not be retried
    /// (the backoff sleeps 100+200+400 ms and stalls every worker behind it).
    #[tokio::test]
    async fn a_foreign_key_refusal_is_not_retried() {
        let db = Arc::new(StubDb {
            refuse_orphans: true,
            ..Default::default()
        });
        let dyn_db: Arc<dyn DatabaseConnection> = db.clone();
        let batch = vec![artifact(json!({"orphan": true}))];
        let started = Instant::now();
        assert!(write_batch_with_retry(&dyn_db, &batch).await.is_err());
        assert_eq!(db.attempts.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() < Duration::from_millis(90));
    }

    /// The writer's channel closing under a producing worker is recorded, and
    /// the loss names the batch.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_closed_writer_channel_is_recorded_as_evidence_loss() {
        let _g = crate::evidence_loss::TEST_SERIAL
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::evidence_loss::reset_for_test();
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<Artifact>>(1);
        drop(rx);
        let (events, _) = tokio::sync::broadcast::channel::<Artifact>(4);
        let active = Arc::new(AtomicUsize::new(0));
        let queue = TaskQueue::new(16, active.clone());
        let produced = vec![artifact(json!({})), artifact(json!({}))];
        let case_id = produced[0].case_id;

        Orchestrator::dispatch_produced_batch(
            produced,
            case_id,
            &events,
            &queue,
            &active,
            &tx,
            &CancellationHandle::new(),
        )
        .await;

        let loss = crate::evidence_loss::snapshot().not_written;
        assert_eq!(loss.dropped, 2);
        assert!(loss.first_reason.unwrap().contains("channel closed"));
    }

    /// The processing log is provenance: a failed final flush and a shed
    /// backlog are both reported, under their own cause.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn processing_log_loss_is_recorded_under_its_own_cause() {
        let _g = crate::evidence_loss::TEST_SERIAL
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::evidence_loss::reset_for_test();

        let mut backlog: Vec<ProcessingLogRow> = (0..5003).map(|_| log_row()).collect();
        cap_processing_log_backlog(&mut backlog, "database is locked");
        assert_eq!(backlog.len(), 5000);
        let snap = crate::evidence_loss::snapshot();
        assert_eq!(snap.processing_log.dropped, 3);
        assert_eq!(snap.not_written.dropped, 0, "artifacts were not lost");

        let db = Arc::new(StubDb::default());
        db.fail_log.store(true, Ordering::SeqCst);
        let dyn_db: Arc<dyn DatabaseConnection> = db;
        let rows = vec![log_row(), log_row()];
        let err = write_processing_log_with_retry(&dyn_db, &rows)
            .await
            .unwrap_err();
        record_processing_log_lost(&rows, &format!("{err:#}"));
        assert_eq!(
            crate::evidence_loss::snapshot().processing_log.dropped,
            5,
            "the failed final flush is counted too"
        );
    }
}
