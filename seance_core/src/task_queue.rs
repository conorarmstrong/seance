//! The orchestrator's work queue: bounded in memory, spilled to disk, never
//! lossy — plus the per-case census that makes one case's progress bar its own.
//!
//! # Why this is not a channel
//!
//! The pipeline's workers are *both* consumers and producers: a worker dequeues
//! one FileSystem artifact and enqueues the eighty thousand FileEntry artifacts
//! the parser found inside it. That shape rules out the two obvious queues.
//!
//! * An **unbounded** channel (what this replaced) lets the fan-out accumulate
//!   without limit. A large ext4 or NTFS image produces hundreds of thousands of
//!   artifacts, each carrying a metadata document of its own, and the process
//!   dies on allocation part-way through an examination.
//! * A **bounded** channel deadlocks. `send().await` parks the producing worker,
//!   which is also the thread that would have drained the queue; with every
//!   worker parked in `send`, nothing consumes and the run stops for good.
//!
//! # What this does instead
//!
//! Producers never block and never lose work. The queue holds up to `capacity`
//! artifacts in memory; everything beyond that is serialized to a temporary
//! file and represented in memory by a small descriptor. Workers pop from the
//! resident set, and when it empties the queue reads a batch of descriptors back
//! from disk. Memory is bounded by `capacity`, there is no blocking send to
//! deadlock on, and nothing queued is ever discarded — dropping queued work
//! would silently lose evidence, which is the one outcome worse than running out
//! of memory.
//!
//! ## The one thing that cannot be spilled
//!
//! [`Artifact::data`] is an `Arc<dyn DataSource>` — a live, in-process capability
//! (an extent map onto the open evidence image, a window into a container entry,
//! a decompressed buffer). It is `#[serde(skip)]` precisely because no byte
//! representation of it exists: only the parser that built it could build it
//! again. So a spilled task keeps its handle resident and re-attaches it on the
//! way back in. Rebuilding a substitute from metadata would hand the module
//! *different bytes than the ones its parent found*, and reading nothing would be
//! worse still — a module that silently examines an empty file reports the file
//! as clean.
//!
//! The residual is therefore honest rather than absolute: artifact bodies are
//! bounded by `capacity`, while one data-source handle per spilled task stays in
//! memory. Handles are small next to the metadata documents they accompany
//! (a pointer plus an extent list, against a JSON document per artifact), which
//! is where the growth actually came from.
//!
//! ## Degrading when the spill itself fails
//!
//! If the temporary file cannot be created or written, the queue keeps the
//! artifact in memory and says so, loudly, once. That trades the memory bound
//! back for correctness, which is the right way round: a queue that dropped the
//! artifact would remove evidence from the examination with nothing in the
//! record to say it had ever been found.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::Semaphore;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::artifact::Artifact;
use crate::data_source::{ByteSliceDataSource, DataSource};
use crate::temp_spill::TempSpill;

/// Artifacts held in memory before the queue starts spilling, unless overridden
/// with [`crate::orchestrator::Orchestrator::with_queue_capacity`].
///
/// Sized so an ordinary ingest never touches the disk at all: the queue only
/// spills once a producer has outrun the workers by this many artifacts, which
/// on a real image happens exactly when the alternative was unbounded growth.
pub const DEFAULT_QUEUE_CAPACITY: usize = 10_000;

/// Spilled tasks read back into memory in one refill. Large enough that the
/// per-refill seek is amortized over many artifacts, small enough that the
/// refill cannot itself exceed the resident bound.
const REFILL_BATCH: usize = 256;

/// Per-case breakdown of the work the orchestrator is holding.
///
/// The process-wide `active_tasks` counter answers "is anything happening",
/// which is what an idle-exit decision needs. It cannot answer "how much of
/// THIS case's ingest is left", which is what a progress bar needs, and using it
/// as the denominator meant a second case's ingest moved the first case's bar:
/// case A's percentage was computed against case B's queue depth, and case A's
/// ETA was derived from work that was never case A's (HUNT-019 / BUG-027).
///
/// Counts here are derived from the artifacts themselves — every increment names
/// the case on the artifact being queued or run — so they cannot be skewed by a
/// caller that pokes the process-wide atomic directly.
#[derive(Clone, Debug, Default)]
pub struct CaseTaskCensus {
    counts: Arc<StdMutex<HashMap<Uuid, CaseTaskCount>>>,
}

/// One case's outstanding work: waiting in the queue, and being processed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CaseTaskCount {
    queued: usize,
    in_flight: usize,
}

impl CaseTaskCount {
    fn is_settled(&self) -> bool {
        self.queued == 0 && self.in_flight == 0
    }
}

impl CaseTaskCensus {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut HashMap<Uuid, CaseTaskCount>) -> R) -> R {
        let mut guard = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// An artifact for `case_id` entered the queue.
    pub fn enqueued(&self, case_id: Uuid) {
        self.with(|counts| counts.entry(case_id).or_default().queued += 1);
    }

    /// An artifact for `case_id` left the queue.
    pub fn dequeued(&self, case_id: Uuid) {
        self.with(|counts| {
            let settled = match counts.get_mut(&case_id) {
                // Saturating rather than wrapping: a caller that queued work
                // without going through this queue must not roll the count of a
                // case that has none into billions.
                Some(count) => {
                    count.queued = count.queued.saturating_sub(1);
                    count.is_settled()
                }
                None => false,
            };
            if settled {
                counts.remove(&case_id);
            }
        });
    }

    /// A worker began running modules on an artifact for `case_id`.
    pub fn started(&self, case_id: Uuid) {
        self.with(|counts| counts.entry(case_id).or_default().in_flight += 1);
    }

    /// A worker finished (or abandoned) an artifact for `case_id`.
    pub fn finished(&self, case_id: Uuid) {
        self.with(|counts| {
            let settled = match counts.get_mut(&case_id) {
                Some(count) => {
                    count.in_flight = count.in_flight.saturating_sub(1);
                    count.is_settled()
                }
                None => false,
            };
            if settled {
                counts.remove(&case_id);
            }
        });
    }

    /// Work outstanding for one case: queued plus in flight. This is the
    /// denominator a case's progress bar is entitled to, and nothing else's.
    pub fn active(&self, case_id: Uuid) -> usize {
        self.with(|counts| {
            counts
                .get(&case_id)
                .map_or(0, |count| count.queued + count.in_flight)
        })
    }

    /// Every case with outstanding work, ordered by case id so the reading is
    /// stable between calls.
    pub fn snapshot(&self) -> Vec<(Uuid, usize)> {
        let mut rows: Vec<(Uuid, usize)> = self.with(|counts| {
            counts
                .iter()
                .map(|(case_id, count)| (*case_id, count.queued + count.in_flight))
                .collect()
        });
        rows.sort_by_key(|(case_id, _)| *case_id);
        rows
    }
}

/// What the queue has been doing, for tests and for operator diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TaskQueueStats {
    /// Artifacts currently held in memory.
    pub resident: usize,
    /// Artifacts currently held on disk.
    pub spilled: usize,
    /// The most artifacts ever held in memory at once this run. Bounded by
    /// `capacity` unless a spill failure forced the degraded in-memory mode.
    pub peak_resident: usize,
    /// Artifacts written to the spill file over the whole run.
    pub spilled_total: u64,
    /// Times a spill could not be performed and the artifact was kept in
    /// memory instead. Non-zero means the memory bound is not in force.
    pub spill_failures: u64,
    /// The configured resident bound.
    pub capacity: usize,
}

/// The orchestrator's task queue. Cheap to clone; every clone is the same queue.
#[derive(Clone)]
pub struct TaskQueue {
    inner: Arc<Inner>,
}

struct Inner {
    state: StdMutex<State>,
    /// One permit per queued task. A worker parks here instead of polling, and
    /// a producer hands over a permit after the task is safely in the queue —
    /// so a permit always implies a task, never the other way round.
    available: Semaphore,
    census: CaseTaskCensus,
    /// The process-wide outstanding-work counter. The queue only touches it to
    /// settle the books for a task it can no longer produce (a spill read-back
    /// failure); without that, an idle-exit run would wait forever on work that
    /// no longer exists.
    active_tasks: Arc<AtomicUsize>,
    capacity: usize,
    /// A temporary, lower resident bound set by the memory governor while
    /// pressure is high (`usize::MAX` = none). New work past it spills to disk
    /// at once; what is already resident is left alone, never dropped.
    window: AtomicUsize,
}

struct State {
    resident: VecDeque<Artifact>,
    spilled: VecDeque<SpilledTask>,
    spill: Option<SpillFile>,
    /// Set once the spill file could not be created or written, so the
    /// degraded (fully resident) mode is explained once rather than per
    /// artifact.
    spill_unavailable: bool,
    peak_resident: usize,
    spilled_total: u64,
    spill_failures: u64,
    closed: bool,
    /// How the spill file is made; a field so a test can make it fail.
    make_spill: fn() -> std::io::Result<SpillFile>,
}

/// An artifact parked on disk: where its body lives, and the live data-source
/// handle that no file can hold.
struct SpilledTask {
    id: Uuid,
    case_id: Uuid,
    offset: u64,
    len: usize,
    /// The live data source, kept resident because a handle cannot be written
    /// to a file — `None` when the source was bytes and went to disk instead.
    data: Option<Arc<dyn DataSource>>,
    /// Where the source's bytes were parked, when it was nothing but bytes
    /// (`DataSource::resident_bytes`): re-materialised on the way back in.
    bytes: Option<(u64, usize)>,
}

/// The backing file for spilled artifact bodies.
///
/// Append at `write_offset`, read at recorded offsets, truncate once the backlog
/// drains so a run with several fan-out bursts does not accumulate every burst
/// on disk. The [`TempSpill`] guard removes the file on every exit path,
/// including an unwinding panic.
struct SpillFile {
    _guard: TempSpill,
    file: std::fs::File,
    write_offset: u64,
}

impl SpillFile {
    fn create() -> std::io::Result<Self> {
        let guard = TempSpill::write(b"", "taskqueue", "spill")?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(guard.path())?;
        Ok(Self {
            _guard: guard,
            file,
            write_offset: 0,
        })
    }

    /// Append a record and return the offset it was written at.
    fn append(&mut self, bytes: &[u8]) -> std::io::Result<u64> {
        self.file.seek(SeekFrom::Start(self.write_offset))?;
        self.file.write_all(bytes)?;
        let offset = self.write_offset;
        self.write_offset += bytes.len() as u64;
        Ok(offset)
    }

    fn read_record(&mut self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Only ever called with no descriptors outstanding, so no live record can
    /// be truncated away.
    fn reset(&mut self) -> std::io::Result<()> {
        self.file.set_len(0)?;
        self.write_offset = 0;
        Ok(())
    }
}

/// The outcome of consuming one permit.
enum Taken {
    Task(Box<Artifact>),
    /// Closed and drained: nothing will ever arrive.
    Drained,
    /// This permit's task is gone (a spill read-back loss). Wait for real work.
    Retry,
}

impl State {
    fn push_resident(&mut self, artifact: Artifact) {
        self.resident.push_back(artifact);
        if self.resident.len() > self.peak_resident {
            self.peak_resident = self.resident.len();
        }
    }

    fn enqueue(&mut self, artifact: Artifact, capacity: usize) {
        // Once anything has spilled, everything behind it spills too: letting a
        // late artifact sit resident in front of an early spilled one would
        // reorder the pipeline for no gain.
        if self.spilled.is_empty() && self.resident.len() < capacity {
            self.push_resident(artifact);
            return;
        }
        if let Err(artifact) = self.spill_artifact(artifact) {
            // Spilling failed and has already said so. Memory pressure is the
            // lesser harm: a dropped artifact is evidence removed from the
            // examination with nothing in the record to say it was found.
            self.push_resident(artifact);
        }
    }

    /// Move one artifact's body to disk. Returns the artifact back, unspilled,
    /// if it could not be written for any reason.
    ///
    /// The `Err` variant IS the artifact, handed back so the caller can keep it
    /// — the same shape `std::sync::mpsc::SendError<T>` uses, and the reason
    /// nothing is ever dropped on this path. Boxing it to shrink the `Result`
    /// would allocate to return evidence we already own, so the lint is
    /// declined here rather than satisfied.
    #[allow(clippy::result_large_err)]
    fn spill_artifact(&mut self, artifact: Artifact) -> Result<(), Artifact> {
        if self.spill.is_none() {
            if self.spill_unavailable {
                return Err(artifact);
            }
            match (self.make_spill)() {
                Ok(file) => self.spill = Some(file),
                Err(e) => {
                    self.spill_unavailable = true;
                    self.spill_failures += 1;
                    error!(
                        "Task-queue spill file could not be created ({e}); the queue will hold \
                         every queued artifact in memory for the rest of this run. Nothing is \
                         dropped, so an ingest larger than memory will now fail on allocation \
                         rather than spill to disk."
                    );
                    return Err(artifact);
                }
            }
        }

        let bytes = match serde_json::to_vec(&artifact) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.spill_failures += 1;
                warn!(
                    "Queued artifact {} could not be serialized for spill ({e}); keeping it in \
                     memory rather than losing it",
                    artifact.id
                );
                return Err(artifact);
            }
        };

        let id = artifact.id;
        let case_id = artifact.case_id;
        // The part of the artifact a file cannot hold is kept resident and
        // re-attached on the way back in (see the module docs) — unless the
        // source is nothing but bytes, which go to the file beside the body.
        let resident = artifact
            .data
            .as_ref()
            .and_then(|d| d.resident_bytes().map(|b| b.to_vec()));
        let data = if resident.is_some() {
            None
        } else {
            artifact.data.clone()
        };

        let appended = {
            let spill = self
                .spill
                .as_mut()
                .expect("spill file was just created or already present");
            spill.append(&bytes).and_then(|offset| {
                let parked = match &resident {
                    Some(payload) => Some((spill.append(payload)?, payload.len())),
                    None => None,
                };
                Ok((offset, parked))
            })
        };

        match appended {
            Ok((offset, parked)) => {
                self.spilled.push_back(SpilledTask {
                    id,
                    case_id,
                    offset,
                    len: bytes.len(),
                    data,
                    bytes: parked,
                });
                self.spilled_total += 1;
                Ok(())
            }
            Err(e) => {
                self.spill_unavailable = true;
                self.spill_failures += 1;
                error!(
                    "Task-queue spill write failed ({e}); the queue will hold every queued \
                     artifact in memory for the rest of this run. Nothing is dropped."
                );
                Err(artifact)
            }
        }
    }

    /// Take the next artifact, refilling from disk when memory has drained.
    ///
    /// Returns the artifact (if any) and the cases of any spilled tasks that
    /// could not be read back — those are gone, and the caller has to settle
    /// their accounting so the run can still finish.
    fn dequeue(&mut self, capacity: usize) -> (Option<Artifact>, Vec<Uuid>) {
        if let Some(artifact) = self.resident.pop_front() {
            return (Some(artifact), Vec::new());
        }
        let lost = self.refill_from_spill(capacity);
        (self.resident.pop_front(), lost)
    }

    fn refill_from_spill(&mut self, capacity: usize) -> Vec<Uuid> {
        let want = REFILL_BATCH.min(capacity.max(1));
        let mut lost = Vec::new();
        for _ in 0..want {
            let Some(task) = self.spilled.pop_front() else {
                break;
            };
            let read = match self.spill.as_mut() {
                Some(spill) => spill.read_record(task.offset, task.len).and_then(|body| {
                    let payload = match task.bytes {
                        Some((offset, len)) => Some(spill.read_record(offset, len)?),
                        None => None,
                    };
                    Ok((body, payload))
                }),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "the task-queue spill file is gone",
                )),
            };
            let decoded = read.and_then(|(body, payload)| {
                serde_json::from_slice::<Artifact>(&body)
                    .map(|artifact| (artifact, payload))
                    .map_err(std::io::Error::other)
            });
            match decoded {
                Ok((mut artifact, payload)) => {
                    artifact.data = match payload {
                        Some(bytes) => Some(Arc::new(ByteSliceDataSource::new(bytes))),
                        None => task.data,
                    };
                    self.push_resident(artifact);
                }
                Err(e) => {
                    // The artifact was queued, so it was found; it will now
                    // never be examined. That is evidence loss and is recorded
                    // as such, not logged and forgotten.
                    lost.push(task.case_id);
                    error!(
                        "EVIDENCE LOSS: queued artifact {} (case {}) was spilled to disk and \
                         could not be read back ({e}); it will never be processed",
                        task.id, task.case_id
                    );
                    crate::evidence_loss::record(
                        crate::evidence_loss::LossCause::NeverProcessed,
                        1,
                        &format!("task-queue spill read-back failed: {e}"),
                        std::iter::once(task.id.to_string()),
                    );
                }
            }
        }
        if self.spilled.is_empty() {
            if let Some(spill) = self.spill.as_mut() {
                if let Err(e) = spill.reset() {
                    debug!("Could not truncate the drained task-queue spill file: {e}");
                }
            }
        }
        lost
    }
}

impl TaskQueue {
    /// A queue holding at most `capacity` artifacts in memory.
    ///
    /// `active_tasks` is the orchestrator's process-wide outstanding-work
    /// counter; the queue only decrements it for work it can no longer produce.
    pub fn new(capacity: usize, active_tasks: Arc<AtomicUsize>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: StdMutex::new(State {
                    resident: VecDeque::new(),
                    spilled: VecDeque::new(),
                    spill: None,
                    spill_unavailable: false,
                    peak_resident: 0,
                    spilled_total: 0,
                    spill_failures: 0,
                    closed: false,
                    make_spill: SpillFile::create,
                }),
                available: Semaphore::new(0),
                census: CaseTaskCensus::new(),
                active_tasks,
                capacity: capacity.max(1),
                window: AtomicUsize::new(usize::MAX),
            }),
        }
    }

    /// Shrink (`Some`) or restore (`None`) the in-memory window. Used by the
    /// memory governor: under pressure, newly queued work spills to disk
    /// straight away instead of filling the resident set up to `capacity`.
    /// Nothing is discarded either way.
    pub fn set_window(&self, window: Option<usize>) {
        self.inner
            .window
            .store(window.unwrap_or(usize::MAX), Ordering::Relaxed);
    }

    /// The per-case breakdown of work this queue and its workers are holding.
    pub fn census(&self) -> CaseTaskCensus {
        self.inner.census.clone()
    }

    pub fn stats(&self) -> TaskQueueStats {
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        TaskQueueStats {
            resident: state.resident.len(),
            spilled: state.spilled.len(),
            peak_resident: state.peak_resident,
            spilled_total: state.spilled_total,
            spill_failures: state.spill_failures,
            capacity: self.inner.capacity,
        }
    }

    /// Queued tasks not yet handed to a worker.
    pub fn len(&self) -> usize {
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.resident.len() + state.spilled.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_closed(&self) -> bool {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closed
    }

    /// Queue one artifact. Never blocks and never discards.
    ///
    /// Returns the artifact back only when the queue is closed — the run is
    /// over, so the caller must roll back whatever it counted for this task and
    /// report that the artifact was not examined.
    ///
    /// See `State::spill_artifact` for why the large `Err` variant is
    /// deliberate: it is the artifact itself, returned rather than discarded.
    #[allow(clippy::result_large_err)]
    pub fn push(&self, artifact: Artifact) -> Result<(), Artifact> {
        let case_id = artifact.case_id;
        {
            let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed {
                return Err(artifact);
            }
            let window = self.inner.window.load(Ordering::Relaxed).max(1);
            state.enqueue(artifact, self.inner.capacity.min(window));
        }
        // Count it, then release the permit: a worker must never be able to see
        // a permit for a task the census does not know about.
        self.inner.census.enqueued(case_id);
        self.inner.available.add_permits(1);
        Ok(())
    }

    /// Take the next artifact, waiting for one to arrive. `None` once the queue
    /// is closed and drained.
    pub async fn pop(&self) -> Option<Artifact> {
        loop {
            // Parking here is what makes an idle worker free. The semaphore is
            // never closed, so a permit handed on by an exiting worker still
            // reaches the next one (see `Taken::Drained`).
            let permit = self.inner.available.acquire().await.ok()?;
            permit.forget();
            match self.take_one() {
                Taken::Task(artifact) => return Some(*artifact),
                Taken::Drained => {
                    self.inner.available.add_permits(1);
                    return None;
                }
                Taken::Retry => continue,
            }
        }
    }

    /// Non-blocking [`Self::pop`], for callers that must not await (and tests).
    pub fn try_pop(&self) -> Option<Artifact> {
        loop {
            let permit = self.inner.available.try_acquire().ok()?;
            permit.forget();
            match self.take_one() {
                Taken::Task(artifact) => return Some(*artifact),
                Taken::Drained => {
                    self.inner.available.add_permits(1);
                    return None;
                }
                Taken::Retry => continue,
            }
        }
    }

    /// Consume the permit this caller is holding. One permit is one task, so
    /// any *extra* tasks this call retired take their own permits with them.
    fn take_one(&self) -> Taken {
        let (artifact, lost, closed, empty) = {
            let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            // Refill under the same bound `push` enqueues under: the governor's
            // window, not the static capacity, or one pop under pressure reads
            // a whole batch back into memory.
            let window = self.inner.window.load(Ordering::Relaxed).max(1);
            let (artifact, lost) = state.dequeue(self.inner.capacity.min(window));
            let empty = state.resident.is_empty() && state.spilled.is_empty();
            (artifact, lost, state.closed, empty)
        };

        let retired = usize::from(artifact.is_some()) + lost.len();
        for _ in 1..retired {
            if let Ok(extra) = self.inner.available.try_acquire() {
                extra.forget();
            }
        }

        for case_id in lost {
            // Work that no longer exists must stop counting as outstanding, or
            // an idle-exit run waits on it forever and never reports at all.
            self.inner.census.dequeued(case_id);
            self.inner.active_tasks.fetch_sub(1, Ordering::SeqCst);
        }

        if let Some(artifact) = artifact {
            self.inner.census.dequeued(artifact.case_id);
            return Taken::Task(Box::new(artifact));
        }

        if closed && empty {
            return Taken::Drained;
        }
        Taken::Retry
    }

    /// Stop accepting new work. Queued tasks still drain; workers see `None`
    /// from [`Self::pop`] only once nothing is left.
    pub fn close(&self) {
        {
            let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed {
                return;
            }
            state.closed = true;
        }
        // Wake one parked worker; each one that exits hands the permit on, so
        // the whole pool learns without the queue knowing how large it is.
        self.inner.available.add_permits(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactType;
    use crate::data_source::ByteSliceDataSource;
    use serde_json::json;

    fn artifact(case_id: Uuid, name: &str) -> Artifact {
        Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": name }),
        )
    }

    fn queue(capacity: usize) -> TaskQueue {
        TaskQueue::new(capacity, Arc::new(AtomicUsize::new(0)))
    }

    fn name_of(artifact: &Artifact) -> String {
        artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    }

    /// The memory governor shrinks the resident window under pressure: new
    /// work spills at once, and restoring the window changes nothing already
    /// queued. Either way every task comes back, in order.
    #[tokio::test]
    async fn a_pressure_window_spills_early_and_loses_nothing() {
        let case_id = Uuid::new_v4();
        let q = queue(100);
        q.set_window(Some(4));
        for i in 0..50 {
            q.push(artifact(case_id, &format!("f{i}"))).expect("open");
        }
        let stats = q.stats();
        assert!(
            stats.peak_resident <= 4,
            "peaked at {}",
            stats.peak_resident
        );
        assert_eq!(stats.spilled_total, 46);

        q.set_window(None);
        for i in 50..60 {
            q.push(artifact(case_id, &format!("f{i}"))).expect("open");
        }
        let mut drained = Vec::new();
        while let Some(a) = q.try_pop() {
            drained.push(name_of(&a));
        }
        let expected: Vec<String> = (0..60).map(|i| format!("f{i}")).collect();
        assert_eq!(drained, expected);
        assert_eq!(q.census().active(case_id), 0);
    }

    /// The refill honours the governor's window as `push` does: popping under
    /// pressure must not read a whole batch of spilled artifacts back in.
    #[test]
    fn a_refill_under_pressure_stays_inside_the_window() {
        let case_id = Uuid::new_v4();
        let q = queue(1000);
        q.set_window(Some(4));
        for i in 0..100 {
            q.push(artifact(case_id, &format!("f{i}"))).expect("open");
        }
        let mut drained = Vec::new();
        while let Some(a) = q.try_pop() {
            drained.push(name_of(&a));
        }
        assert_eq!(drained.len(), 100);
        let peak = q.stats().peak_resident;
        assert!(peak <= 4, "resident peaked at {peak} with the window at 4");
    }

    /// When the spill file cannot be made, nothing is dropped: the queue says
    /// so (`spill_failures`) and keeps every artifact resident.
    #[test]
    fn a_spill_that_cannot_be_created_keeps_everything_resident() {
        let case_id = Uuid::new_v4();
        let q = queue(2);
        q.inner.state.lock().unwrap().make_spill =
            || Err(std::io::Error::other("injected: no space"));
        for i in 0..10 {
            q.push(artifact(case_id, &format!("f{i}"))).expect("open");
        }
        let stats = q.stats();
        assert_eq!(stats.spilled, 0);
        assert_eq!(stats.resident, 10);
        assert_eq!(stats.spill_failures, 1, "explained once, not per artifact");
        let drained: Vec<String> = std::iter::from_fn(|| q.try_pop())
            .map(|a| name_of(&a))
            .collect();
        let expected: Vec<String> = (0..10).map(|i| format!("f{i}")).collect();
        assert_eq!(drained, expected);
    }

    /// A spilled task whose body cannot be read back is evidence loss, recorded
    /// as such, and its accounting is settled so the run can still finish: the
    /// outstanding-work counter, the census and the semaphore permits all agree
    /// with what is actually left in the queue.
    #[test]
    fn spilled_tasks_that_cannot_be_read_back_are_recorded_and_settled() {
        let _serial = crate::evidence_loss::TEST_SERIAL
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::evidence_loss::reset_for_test();

        let case_id = Uuid::new_v4();
        let active = Arc::new(AtomicUsize::new(0));
        let q = TaskQueue::new(2, active.clone());
        for i in 0..6 {
            // The submitter counts each task, as the orchestrator does.
            active.fetch_add(1, Ordering::SeqCst);
            q.push(artifact(case_id, &format!("f{i}"))).expect("open");
        }
        assert_eq!(q.stats().spilled, 4);
        // Damage the spill file after the fact.
        {
            let state = q.inner.state.lock().unwrap();
            state
                .spill
                .as_ref()
                .expect("spilled")
                .file
                .set_len(0)
                .unwrap();
        }

        let got: Vec<String> = std::iter::from_fn(|| q.try_pop())
            .map(|a| name_of(&a))
            .collect();
        assert_eq!(got, vec!["f0", "f1"], "only the resident ones survive");
        // The 4 lost tasks stopped counting as outstanding; the 2 popped are
        // still the worker's to finish.
        assert_eq!(active.load(Ordering::SeqCst), 2);
        assert_eq!(q.census().active(case_id), 0);
        assert!(q.is_empty());
        assert_eq!(
            q.inner.available.available_permits(),
            0,
            "no permit may outlive its task, or pop() would spin"
        );
        let loss = crate::evidence_loss::snapshot().never_processed;
        assert_eq!(loss.dropped, 4);
        assert_eq!(loss.ids.len(), 4);
        crate::evidence_loss::reset_for_test();
    }

    /// HUNT-025. The queue must hold a bounded number of artifacts in memory
    /// while still returning every one of them.
    ///
    /// The unbounded channel this replaced had no bound at all: a fan-out of a
    /// few hundred thousand FileEntry artifacts sat in memory in full until a
    /// worker got to it, and an ingest large enough simply died. Capping without
    /// spilling is not an option either — a dropped task is an artifact that was
    /// found and then never examined, with nothing in the record to say so.
    #[tokio::test]
    async fn spilling_bounds_resident_memory_without_losing_a_single_task() {
        let case_id = Uuid::new_v4();
        let q = queue(8);
        for i in 0..500 {
            q.push(artifact(case_id, &format!("f{i}"))).expect("open");
        }

        let stats = q.stats();
        assert!(
            stats.peak_resident <= 8,
            "the resident set must stay within the bound, peaked at {}",
            stats.peak_resident
        );
        assert_eq!(
            stats.spilled_total, 492,
            "everything past the bound belongs on disk"
        );
        assert_eq!(stats.spill_failures, 0, "the spill itself must have worked");

        let mut drained = Vec::new();
        while let Some(a) = q.try_pop() {
            drained.push(name_of(&a));
        }
        assert_eq!(drained.len(), 500, "every queued task must come back");
        let expected: Vec<String> = (0..500).map(|i| format!("f{i}")).collect();
        assert_eq!(drained, expected, "and in the order it was queued");
        assert_eq!(q.census().active(case_id), 0, "the census must settle");
    }

    /// A spilled artifact's `DataSource` is a live in-process capability that no
    /// file can hold. Losing it on the way through the spill would hand the
    /// module an artifact with no bytes — which reads downstream as a file that
    /// was examined and found to contain nothing.
    #[tokio::test]
    async fn a_spilled_task_keeps_the_data_source_no_file_could_hold() {
        let case_id = Uuid::new_v4();
        let q = queue(1);
        // The first stays resident; the second must spill.
        q.push(artifact(case_id, "resident")).expect("open");

        let mut carrier = artifact(case_id, "spilled");
        carrier.data = Some(Arc::new(ByteSliceDataSource::new(b"evidence".to_vec())));
        q.push(carrier).expect("open");
        assert_eq!(
            q.stats().spilled_total,
            1,
            "the second one must have spilled"
        );

        let first = q.try_pop().expect("resident task");
        assert_eq!(name_of(&first), "resident");

        let second = q.try_pop().expect("spilled task");
        assert_eq!(name_of(&second), "spilled");
        let data = second
            .data
            .as_ref()
            .expect("a spilled artifact must come back with its data source");
        let mut buf = vec![0u8; 8];
        let read = data.read_at(0, &mut buf).expect("read the source");
        assert_eq!(&buf[..read], b"evidence");
    }

    /// HUNT-114. A source that is nothing but bytes is parked in the spill file
    /// beside the artifact's body and re-materialised on the way back, so the
    /// queue holds no handle to it while it waits; a source with a live handle
    /// stays resident as before. Measured on a walk of 40,000 small files:
    /// 190,000 artifacts spilled with every carried-out blob still in memory.
    #[tokio::test]
    async fn a_spilled_byte_source_leaves_memory_and_a_handle_source_does_not() {
        #[derive(Debug)]
        struct Handle;
        impl DataSource for Handle {
            fn read_at(&self, _offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
                buf[0] = 7;
                Ok(1)
            }
            fn size(&self) -> u64 {
                1
            }
        }
        let case_id = Uuid::new_v4();
        let q = queue(1);
        q.push(artifact(case_id, "resident")).expect("open");

        let bytes: Arc<dyn DataSource> =
            Arc::new(ByteSliceDataSource::new(vec![0xABu8; 64 * 1024]));
        let mut by_bytes = artifact(case_id, "bytes");
        by_bytes.data = Some(bytes.clone());
        q.push(by_bytes).expect("open");
        assert_eq!(
            Arc::strong_count(&bytes),
            1,
            "the spilled artifact's bytes went to disk; the queue holds no handle to them"
        );

        let handle: Arc<dyn DataSource> = Arc::new(Handle);
        let mut by_handle = artifact(case_id, "handle");
        by_handle.data = Some(handle.clone());
        q.push(by_handle).expect("open");
        assert_eq!(
            Arc::strong_count(&handle),
            2,
            "a live handle cannot be written to a file and stays resident"
        );

        q.try_pop().expect("resident");
        let back = q.try_pop().expect("bytes");
        assert_eq!(name_of(&back), "bytes");
        let data = back.data.as_ref().expect("re-materialised");
        assert_eq!(data.size(), 64 * 1024);
        let mut buf = vec![0u8; 64 * 1024];
        assert_eq!(data.read_at(0, &mut buf).unwrap(), 64 * 1024);
        assert!(buf.iter().all(|b| *b == 0xAB));
        let back = q.try_pop().expect("handle");
        assert_eq!(name_of(&back), "handle");
        let mut one = [0u8; 1];
        back.data.as_ref().unwrap().read_at(0, &mut one).unwrap();
        assert_eq!(one[0], 7);
    }

    /// The deadlock the unbounded channel existed to avoid must not come back.
    /// Every worker is also a producer here, and pushes far past the bound while
    /// other workers are trying to pop. With a bounded `send().await` this shape
    /// stops for good; a spilling queue never blocks a producer, so it drains.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn producers_that_are_also_consumers_never_wedge_the_queue() {
        let case_id = Uuid::new_v4();
        let q = queue(2);
        let processed = Arc::new(AtomicUsize::new(0));

        // 4 roots, each fanning out to 50 children: 204 tasks through a queue
        // that holds 2.
        for i in 0..4 {
            q.push(artifact(case_id, &format!("root{i}")))
                .expect("open");
        }

        let mut workers = Vec::new();
        for _ in 0..4 {
            let q = q.clone();
            let processed = processed.clone();
            workers.push(tokio::spawn(async move {
                while let Some(a) = q.pop().await {
                    processed.fetch_add(1, Ordering::SeqCst);
                    if name_of(&a).starts_with("root") {
                        for j in 0..50 {
                            let child = artifact(a.case_id, &format!("child{j}"));
                            if q.push(child).is_err() {
                                break;
                            }
                        }
                    }
                }
            }));
        }

        // Wait for the whole fan-out to drain, then close so the workers exit.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while processed.load(Ordering::SeqCst) < 204 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        q.close();
        for worker in workers {
            tokio::time::timeout(std::time::Duration::from_secs(5), worker)
                .await
                .expect("a worker must not be wedged in the queue")
                .expect("worker task must not panic");
        }

        assert_eq!(
            processed.load(Ordering::SeqCst),
            204,
            "every task must be processed exactly once"
        );
        assert!(q.stats().peak_resident <= 2, "the bound must have held");
        assert_eq!(q.census().active(case_id), 0);
    }

    /// A closed queue hands the artifact back rather than swallowing it, so the
    /// caller can roll back its accounting and say the artifact was not examined.
    #[tokio::test]
    async fn a_closed_queue_returns_the_artifact_instead_of_dropping_it() {
        let case_id = Uuid::new_v4();
        let q = queue(4);
        q.push(artifact(case_id, "before")).expect("open");
        q.close();

        let rejected = q
            .push(artifact(case_id, "after"))
            .expect_err("a closed queue must not accept work");
        assert_eq!(name_of(&rejected), "after");

        // Work queued before the close still drains.
        let drained = q.try_pop().expect("queued work drains after close");
        assert_eq!(name_of(&drained), "before");
        assert!(q.try_pop().is_none(), "and then the queue is finished");
    }

    /// Closing wakes every parked worker, not just one: each worker that learns
    /// the queue is finished passes the news on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn closing_releases_every_parked_worker() {
        let q = queue(4);
        let mut workers = Vec::new();
        for _ in 0..3 {
            let q = q.clone();
            workers.push(tokio::spawn(async move { q.pop().await.is_none() }));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        q.close();
        for worker in workers {
            let drained = tokio::time::timeout(std::time::Duration::from_secs(5), worker)
                .await
                .expect("every parked worker must be released by close()")
                .expect("worker task must not panic");
            assert!(drained, "a closed, empty queue yields None");
        }
    }

    /// HUNT-019. One case's outstanding work is its own: a second case ingesting
    /// at the same time must not move it.
    #[test]
    fn the_census_counts_each_case_separately() {
        let census = CaseTaskCensus::new();
        let case_a = Uuid::new_v4();
        let case_b = Uuid::new_v4();

        census.enqueued(case_a);
        census.enqueued(case_a);
        for _ in 0..500 {
            census.enqueued(case_b);
        }
        assert_eq!(census.active(case_a), 2);
        assert_eq!(census.active(case_b), 500);

        // One of case A's artifacts moves from the queue into a worker: still
        // outstanding, still case A's.
        census.dequeued(case_a);
        census.started(case_a);
        assert_eq!(census.active(case_a), 2);

        census.finished(case_a);
        census.dequeued(case_a);
        assert_eq!(census.active(case_a), 0, "case A is settled");
        assert_eq!(census.active(case_b), 500, "case B is untouched");

        assert_eq!(
            census.snapshot(),
            vec![(case_b, 500)],
            "a settled case leaves no entry behind"
        );
    }

    /// A caller that queued work without this queue must not drive another
    /// case's count negative (and with a `usize`, wildly positive).
    #[test]
    fn the_census_never_underflows_an_unknown_case() {
        let census = CaseTaskCensus::new();
        let unknown = Uuid::new_v4();
        census.dequeued(unknown);
        census.finished(unknown);
        assert_eq!(census.active(unknown), 0);
        assert!(census.snapshot().is_empty());
    }
}
