//! Cross-view process detection: `psxview`, and the thread stages it rests on.
//!
//! There is no such thing as *the* list of processes on a Windows machine.
//! There are several places the kernel records that a process exists, they are
//! maintained independently, and malware that hides a process has to edit all
//! of them to stay hidden. Comparing them is the oldest and still the most
//! reliable rootkit test in memory forensics, and it is the only test in this
//! crate whose finding is an **absence**.
//!
//! The views correlated here:
//!
//! | View | What it reads | What its silence means |
//! |---|---|---|
//! | [`ProcessView::PsList`] | `PsActiveProcessHead` → `ActiveProcessLinks` | the kernel does not link to this process |
//! | [`ProcessView::PsScan`] | `Proc` pool allocations | the allocator does not hold this process |
//! | [`ProcessView::ThrdScan`] | `Thre` pool allocations → owning `_EPROCESS` | nothing — a process with no recovered thread is ordinary |
//! | [`ProcessView::Session`] | `_MM_SESSION_SPACE.ProcessList` | nothing — kernel processes belong to no session |
//! | [`ProcessView::DesktopThread`] | `tagDESKTOP.PtiList` → `tagTHREADINFO.ppi.Process` | nothing — a process with no GUI thread is ordinary |
//!
//! **The fourth column is the point.** Two of the five views enumerate every
//! process on the machine, so their silence is evidence. The other three
//! enumerate a subset *by construction*: the System process has no session and
//! no desktop thread, and a process whose threads have all exited has no thread
//! left to be found. Treating those absences as findings would flag `System` on
//! every image ever examined, and a tool that cries wolf on `System` will be
//! ignored when it is right. [`ProcessView::enumerates_every_process`] is where
//! that distinction lives, and a view for which it is false never reports
//! `Some(false)`.
//!
//! # A missing row and an unrun view must not look the same
//!
//! Every cell of the output is an `Option<bool>` and not a `bool`:
//!
//! * `Some(true)` — this view found the process;
//! * `Some(false)` — this view ran, reached everything it could have reached,
//!   is a view whose silence means something, and did **not** find it;
//! * `None` — nothing can be concluded. The view was not attempted on this
//!   build, or it stopped early, or its addresses could not be compared with
//!   this row's.
//!
//! Upstream renders every cell as a bare `True`/`False`. A `False` from a sweep
//! that stopped halfway through the image is indistinguishable there from a
//! `False` that means "this process has been unlinked", and only one of the two
//! is a finding.
//!
//! # Correlating addresses across two address spaces
//!
//! Every view but one produces **kernel virtual** `_EPROCESS` addresses. The
//! exception is the pool sweep on builds before Windows 10, which runs in
//! physical memory precisely so that it can see allocations the kernel no
//! longer maps — and its addresses are therefore physical. Comparing the two
//! directly would put every process in its own row and report the whole machine
//! as hidden.
//!
//! The correlation goes one way only: every kernel virtual address the other
//! views produced is translated to physical through the kernel address space,
//! and the sweep's physical hits are looked up in that map. A hit that matches
//! nothing becomes a row of its own — which is the correct answer for a process
//! the virtual address space no longer maps. An address that could not be
//! translated is counted, and while that count is non-zero no view is allowed
//! to establish absence for a physical-only row, because the process it could
//! not translate might have been that one.
//!
//! # What "hidden" is allowed to mean
//!
//! A process in the pool and off the active list is usually not a rootkit: it
//! is a process that exited, whose `_EPROCESS` the kernel unlinked and whose
//! allocation has not been reused. [`Concealment`] separates the two by exit
//! time, and refuses to guess when the exit time could not be read.

// the counter is the walk's budget, checked against a cap inside the loop and
// read after it to report how much was covered; `enumerate` yields an index that
// does not outlive the iteration.
#![allow(clippy::explicit_counter_loop)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_core::time::{filetime_to_rfc3339, filetime_to_unix_secs};
use seance_memory::object::{ListSpec, ListStop, ObjError, StructReader};
use seance_memory::Incomplete;
use seance_symbols::SymbolError;

use crate::poolscan::{
    builtin_constraints_for, image_file_name, pool_scan, render_tag, PoolConstraint, PoolError,
    PoolScanConfig, PoolSymbols, PoolTypes, ScanSpace,
};
use crate::process::{
    list_processes, Field, ProcessError, ProcessList, ProcessListConfig, ProcessSymbols,
    ProcessTime, MEMBER_IMAGE_FILE_NAME, TYPE_EPROCESS, TYPE_LIST_ENTRY,
};
use crate::profile::WindowsProfile;
use crate::vad::VadError;

#[path = "psxview_suspicious.rs"]
pub mod suspicious;
#[path = "psxview_suspicious_survey.rs"]
pub mod suspicious_survey;
#[path = "psxview_threads.rs"]
pub mod threads;

pub use suspicious::{
    suspicious_threads, StartAddressKind, StartRegion, Suspicion, SuspicionKind, SuspiciousThreads,
    SuspiciousThreadsConfig, ThreadStartFinding,
};
pub use suspicious_survey::{
    survey_suspicious_threads, SuspiciousThreadSymbols, SuspiciousThreadsSurvey, UnjudgedProcess,
};
pub use threads::{
    list_process_threads, read_thread, scan_threads, OwningProcessLink, ThreadList,
    ThreadListConfig, ThreadOrigin, ThreadRecord, ThreadScanConfig, ThreadScanOutcome,
    ThreadSymbols,
};

// ── Names this module knows ─────────────────────────────────────────────────

/// The session space a process's `Session` points at.
pub const TYPE_MM_SESSION_SPACE: &str = "_MM_SESSION_SPACE";

/// The member of `_MM_SESSION_SPACE` heading its list of processes.
pub const MEMBER_SESSION_PROCESS_LIST: &str = "ProcessList";

/// The member of `_EPROCESS` that threads it onto its session's list.
pub const MEMBER_SESSION_PROCESS_LINKS: &str = "SessionProcessLinks";

/// The GUI desktop object, in the window manager's symbols.
pub const TYPE_TAG_DESKTOP: &str = "tagDESKTOP";

/// The window manager's per-thread structure.
pub const TYPE_TAG_THREADINFO: &str = "tagTHREADINFO";

/// The window manager's per-process structure, which names the `_EPROCESS`.
pub const TYPE_TAG_PROCESSINFO: &str = "tagPROCESSINFO";

/// The member of `tagDESKTOP` heading its list of GUI threads.
pub const MEMBER_DESKTOP_THREAD_LIST: &str = "PtiList";

/// The member of `tagTHREADINFO` that threads it onto a desktop.
pub const MEMBER_DESKTOP_THREAD_LINK: &str = "PtiLink";

/// The member of `tagTHREADINFO` pointing at its `tagPROCESSINFO`.
pub const MEMBER_THREAD_PROCESS_INFO: &str = "ppi";

/// The member of `tagPROCESSINFO` pointing at the `_EPROCESS`.
pub const MEMBER_PROCESS_INFO_PROCESS: &str = "Process";

/// The pool tag Windows 8 and later allocate an `_EPROCESS` under.
pub const TAG_PROCESS: [u8; 4] = *b"Proc";

/// The pool tag earlier builds allocate a *protected* `_EPROCESS` under.
pub const TAG_PROCESS_PROTECTED: [u8; 4] = *b"Pro\xe3";

/// The pool tag a `tagDESKTOP` is allocated under.
pub const TAG_DESKTOP: [u8; 4] = *b"Desk";

/// Ceiling on processes one session's list will report.
pub const MAX_SESSION_PROCESSES: usize = 65_536;

/// Ceiling on desktops one sweep will follow.
pub const MAX_DESKTOPS: usize = 4_096;

/// Ceiling on GUI threads one desktop's list will report.
pub const MAX_DESKTOP_THREADS: usize = 65_536;

/// Ceiling on individually recorded notes per view. The counts stay exact.
pub const MAX_RECORDED_NOTES: usize = 256;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops a cross-view or a thread stage before it can produce
/// an answer worth reading.
///
/// Note what is *not* here: a view that could not run. That is a fact about one
/// view, it lands on [`ViewOutcome::status`] as [`ViewStatus::NotAttempted`] or
/// [`ViewStatus::Failed`], and the correlation then refuses to derive an
/// absence from it. A cross-view with four working views and one that could not
/// run is still evidence; a cross-view that silently dropped the fifth is not.
#[derive(Debug, thiserror::Error)]
pub enum PsXViewError {
    /// This analysis cannot be performed on this build with what is available,
    /// and no partial answer would be honest. The message names what is
    /// missing.
    #[error("this analysis cannot be performed on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// Address arithmetic that would have wrapped the 64-bit address space.
    #[error("{0}")]
    Overflow(String),

    /// A typed read failed for a reason that invalidates the whole stage rather
    /// than one row.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the stage depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// The process list could not be described for this build.
    #[error(transparent)]
    Process(#[from] ProcessError),

    /// The pool layout could not be established.
    #[error(transparent)]
    Pool(#[from] PoolError),

    /// A process's memory ranges could not be walked.
    #[error(transparent)]
    Vad(#[from] VadError),
}

impl PsXViewError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            PsXViewError::Unsupported { .. } => "unsupported_build",
            PsXViewError::Overflow(_) => "overflow",
            PsXViewError::Object(err) => err.class(),
            PsXViewError::Symbols(_) => "symbols",
            PsXViewError::Process(err) => err.class(),
            PsXViewError::Pool(err) => err.class(),
            PsXViewError::Vad(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            PsXViewError::Object(err) => err.incomplete_reason(),
            PsXViewError::Process(err) => err.incomplete_reason(),
            PsXViewError::Pool(err) => err.incomplete_reason(),
            PsXViewError::Vad(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be analysed" refusal.
    pub fn unsupported(detail: impl Into<String>) -> PsXViewError {
        PsXViewError::Unsupported {
            detail: detail.into(),
        }
    }
}

/// Turn a raw FILETIME field into a [`ProcessTime`].
///
/// Zero is [`ProcessTime::NotRecorded`] before anything else: a zero `ExitTime`
/// means the process was still running, and converting it would date every
/// running process to 1601-01-01 — which is exactly the column
/// [`Concealment`] reads to decide whether an unlinked process is a finding or
/// an ordinary corpse.
pub(crate) fn classify_process_filetime(raw: i128) -> ProcessTime {
    if raw == 0 {
        return ProcessTime::NotRecorded;
    }
    let Ok(filetime) = u64::try_from(raw) else {
        return ProcessTime::Implausible { raw };
    };
    match (
        filetime_to_unix_secs(filetime),
        filetime_to_rfc3339(filetime),
    ) {
        (Some(unix_seconds), Some(rfc3339)) => ProcessTime::At {
            filetime,
            unix_seconds,
            rfc3339,
        },
        _ => ProcessTime::Implausible { raw },
    }
}

// ── The views ───────────────────────────────────────────────────────────────

/// One place the kernel records that a process exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcessView {
    /// The active process list: `PsActiveProcessHead` through
    /// `_EPROCESS.ActiveProcessLinks`. What every API that reports running
    /// processes ultimately reads, and therefore what a rootkit edits.
    PsList,
    /// The pool sweep for `Proc` allocations. Sees what the *allocator* holds,
    /// which includes processes the kernel no longer links to.
    PsScan,
    /// The pool sweep for `Thre` allocations, resolved to the process each
    /// thread belongs to. A process is reachable here whenever any of its
    /// threads is still in the pool.
    ThrdScan,
    /// Each session's own list of processes, `_MM_SESSION_SPACE.ProcessList`
    /// through `_EPROCESS.SessionProcessLinks`. A separate list, maintained
    /// separately, and frequently left intact by an unlink of the active list.
    Session,
    /// The window manager's desktops, `tagDESKTOP.PtiList` through
    /// `tagTHREADINFO.PtiLink`, resolved to the owning process. Reaches any
    /// process with a GUI thread, through structures a kernel rootkit has no
    /// reason to touch.
    DesktopThread,
}

impl ProcessView {
    /// Every view, in the order a report renders them.
    pub fn all() -> [ProcessView; 5] {
        [
            ProcessView::PsList,
            ProcessView::PsScan,
            ProcessView::ThrdScan,
            ProcessView::Session,
            ProcessView::DesktopThread,
        ]
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ProcessView::PsList => "pslist",
            ProcessView::PsScan => "psscan",
            ProcessView::ThrdScan => "thrdscan",
            ProcessView::Session => "session",
            ProcessView::DesktopThread => "desktop_thread",
        }
    }

    /// Whether a process being absent from this view means anything.
    ///
    /// **True for exactly two views**, and getting this wrong is the difference
    /// between a tool that finds rootkits and a tool that flags `System` on
    /// every image:
    ///
    /// * the active process list and the pool sweep enumerate *every* process,
    ///   so a process they do not hold is a process they have lost;
    /// * a process legitimately has no session (`System`, `Registry`), no GUI
    ///   thread (every service), and no thread left in the pool (a process
    ///   whose threads have all exited and whose allocations were reused).
    ///   Those three views can confirm that a process exists and can never show
    ///   that one does not.
    pub fn enumerates_every_process(self) -> bool {
        matches!(self, ProcessView::PsList | ProcessView::PsScan)
    }

    /// What an absence from this view would mean, in the examiner's terms.
    pub fn absence_means(self) -> &'static str {
        match self {
            ProcessView::PsList => "the kernel's active process list does not link to this process",
            ProcessView::PsScan => {
                "no pool allocation tagged as a process was recovered for this process"
            }
            ProcessView::ThrdScan => {
                "no thread of this process was recovered from the pool, which is ordinary for a \
                 process whose threads have all exited"
            }
            ProcessView::Session => {
                "this process is on no session's process list, which is ordinary for a process \
                 that belongs to no session"
            }
            ProcessView::DesktopThread => {
                "this process has no thread on any desktop, which is ordinary for a process with \
                 no user interface"
            }
        }
    }
}

/// How far a view got, which decides whether its silence is evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewStatus {
    /// The view ran and reached everything it could have reached. Only in this
    /// state can an absence from it be stated.
    Complete,
    /// The view ran and could not see everything: a walk that stopped early, a
    /// sweep that could not read part of the image, a cap that fired.
    Partial {
        /// What it could not see.
        detail: String,
    },
    /// The view was not run at all — this build has no such structure, or an
    /// input it needed was unavailable. **Nothing** may be concluded from its
    /// empty result.
    NotAttempted {
        /// Why, in the examiner's terms.
        detail: String,
    },
    /// The view was attempted and failed outright.
    Failed {
        /// What happened.
        detail: String,
    },
}

impl ViewStatus {
    /// Whether the view reached everything it could have reached.
    pub fn is_complete(&self) -> bool {
        matches!(self, ViewStatus::Complete)
    }

    /// Whether the view ran at all.
    pub fn ran(&self) -> bool {
        matches!(self, ViewStatus::Complete | ViewStatus::Partial { .. })
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ViewStatus::Complete => "complete",
            ViewStatus::Partial { .. } => "partial",
            ViewStatus::NotAttempted { .. } => "not_attempted",
            ViewStatus::Failed { .. } => "failed",
        }
    }

    /// The explanation, when there is one.
    pub fn detail(&self) -> Option<&str> {
        match self {
            ViewStatus::Complete => None,
            ViewStatus::Partial { detail }
            | ViewStatus::NotAttempted { detail }
            | ViewStatus::Failed { detail } => Some(detail),
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"kind": self.as_str(), "detail": self.detail()})
    }
}

/// One process as one view saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewHit {
    /// The `_EPROCESS`, as a **kernel virtual** address, when the view produced
    /// one or one could be resolved for it.
    pub process: Option<u64>,
    /// The address in the space that was swept, for a sweep that did not run in
    /// the kernel's own space.
    pub scanned: Option<u64>,
    /// The structure that led here: the `_ETHREAD`, the `_MM_SESSION_SPACE`,
    /// the `tagDESKTOP`, the pool header. Published so the chain can be checked
    /// by hand.
    pub via: Option<u64>,
}

/// What one view found, and how far it got.
#[derive(Debug, Clone)]
pub struct ViewOutcome {
    /// Which view this is.
    pub view: ProcessView,
    /// How far it got.
    pub status: ViewStatus,
    /// What it found.
    pub hits: Vec<ViewHit>,
    /// How many of its hits could not be tied to a kernel virtual address.
    ///
    /// While this is non-zero the view cannot establish an absence, because the
    /// process it failed to place might have been the one being asked about.
    pub unresolved: usize,
    /// Notes, capped by [`PsXViewConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total.
    pub notes_total: usize,
}

impl ViewOutcome {
    /// A view that was not attempted, with the reason it was not.
    pub fn not_attempted(view: ProcessView, detail: impl Into<String>) -> Self {
        Self {
            view,
            status: ViewStatus::NotAttempted {
                detail: detail.into(),
            },
            hits: Vec::new(),
            unresolved: 0,
            notes: Vec::new(),
            notes_total: 0,
        }
    }

    /// A view that was attempted and failed.
    pub fn failed(view: ProcessView, detail: impl Into<String>) -> Self {
        Self {
            view,
            status: ViewStatus::Failed {
                detail: detail.into(),
            },
            hits: Vec::new(),
            unresolved: 0,
            notes: Vec::new(),
            notes_total: 0,
        }
    }

    /// The distinct kernel virtual `_EPROCESS` addresses this view produced,
    /// ascending.
    pub fn processes(&self) -> Vec<u64> {
        let mut out: Vec<u64> = self.hits.iter().filter_map(|hit| hit.process).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Whether this view can be asked to *deny* that a process exists.
    ///
    /// Three things must hold at once, and dropping any one of them
    /// manufactures findings: the view must be one whose silence means anything
    /// at all, it must have reached everything it could have reached, and every
    /// one of its hits must have been placed in the kernel address space.
    pub fn establishes_absence(&self) -> bool {
        self.view.enumerates_every_process() && self.status.is_complete() && self.unresolved == 0
    }

    /// Whether this view held the process at a kernel virtual address.
    ///
    /// `Some(true)` when it did. `Some(false)` only when
    /// [`ViewOutcome::establishes_absence`] holds, so that absence is
    /// established rather than merely unobserved. `None` otherwise, which a
    /// report must render as "cannot say" and never as a blank cell beside a
    /// `true`.
    pub fn contains(&self, process: u64) -> Option<bool> {
        if self.hits.iter().any(|hit| hit.process == Some(process)) {
            return Some(true);
        }
        if self.establishes_absence() {
            Some(false)
        } else {
            None
        }
    }

    /// Whether this view held a process at an address in the swept space.
    pub fn contains_scanned(&self, scanned: u64) -> Option<bool> {
        if self.hits.iter().any(|hit| hit.scanned == Some(scanned)) {
            return Some(true);
        }
        if self.establishes_absence() {
            Some(false)
        } else {
            None
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "view": self.view.as_str(),
            "status": self.status.to_json(),
            "enumerates_every_process": self.view.enumerates_every_process(),
            "establishes_absence": self.establishes_absence(),
            "absence_means": self.view.absence_means(),
            "found": self.processes().len(),
            "hits": self.hits.len(),
            "unresolved": self.unresolved,
            "notes": self.notes,
            "notes_total": self.notes_total,
        })
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Where a session keeps its own list of processes.
#[derive(Debug, Clone)]
pub struct SessionSymbols {
    /// Path to the `Session` pointer inside `_EPROCESS`.
    pub session: String,
    /// Path to the list head inside `_MM_SESSION_SPACE`.
    pub process_list: String,
    /// Byte offset of `SessionProcessLinks` inside `_EPROCESS`.
    ///
    /// Published for the same reason the process list publishes its own: every
    /// address this view produced was computed by subtracting it.
    pub links_offset: u64,
}

/// Where the window manager keeps its desktops' threads.
#[derive(Debug, Clone)]
pub struct DesktopSymbols {
    /// Declared size of `tagDESKTOP`, which bounds the allocations a sweep will
    /// believe.
    pub desktop_size: u64,
    /// Path to the thread-list head inside `tagDESKTOP`.
    pub thread_list: String,
    /// Byte offset of `PtiLink` inside `tagTHREADINFO`.
    pub thread_link_offset: u64,
    /// Path to the `tagPROCESSINFO` pointer inside `tagTHREADINFO`.
    pub process_info: String,
    /// Path to the `_EPROCESS` pointer inside `tagPROCESSINFO`.
    pub process: String,
}

/// Everything the cross-view needs to know about this build's layout.
///
/// Resolved once per image. The two views that can be absent from a build —
/// sessions and desktops — record **why** they are absent rather than being
/// silently dropped, so that a cross-view over a build without the window
/// manager's symbols is visibly a three-view cross-view and not a five-view one
/// that happened to find nothing.
#[derive(Debug, Clone)]
pub struct PsXViewSymbols {
    /// Layout of the process list.
    pub process: ProcessSymbols,
    /// Layout of pool allocations.
    pub pool: PoolSymbols,
    /// Layout of threads.
    pub thread: ThreadSymbols,
    /// Layout of the session view, when this build supports it.
    pub session: Option<SessionSymbols>,
    /// Why the session view cannot run, when it cannot.
    pub session_unavailable: Option<String>,
    /// Layout of the desktop view, when this image's symbols support it.
    pub desktop: Option<DesktopSymbols>,
    /// Why the desktop view cannot run, when it cannot.
    pub desktop_unavailable: Option<String>,
}

impl PsXViewSymbols {
    /// Resolve every layout fact a cross-view of this image needs.
    ///
    /// # Errors
    ///
    /// [`PsXViewError`] naming what is missing, for the three views without
    /// which there is no cross-view at all: the process list, the pool, and
    /// threads. The session and desktop views are optional, and their absence
    /// is recorded rather than fatal.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, PsXViewError> {
        let process = ProcessSymbols::from_profile(profile)?;
        let pool = PoolSymbols::from_profile(profile)?;
        let thread = ThreadSymbols::from_profile(profile)?;
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        let (session, session_unavailable) = match resolve_session(profile, &reader, &process) {
            Ok(symbols) => (Some(symbols), None),
            Err(detail) => (None, Some(detail)),
        };
        let (desktop, desktop_unavailable) = match resolve_desktop(profile, &reader, &pool) {
            Ok(symbols) => (Some(symbols), None),
            Err(detail) => (None, Some(detail)),
        };

        Ok(Self {
            process,
            pool,
            thread,
            session,
            session_unavailable,
            desktop,
            desktop_unavailable,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process.to_json(),
            "thread": self.thread.to_json(),
            "session_available": self.session.is_some(),
            "session_unavailable": self.session_unavailable,
            "desktop_available": self.desktop.is_some(),
            "desktop_unavailable": self.desktop_unavailable,
            "pool_space": self.pool.space.as_str(),
        })
    }
}

/// Resolve the session view's layout, or say why it cannot be resolved.
fn resolve_session(
    profile: &WindowsProfile,
    reader: &StructReader,
    process: &ProcessSymbols,
) -> Result<SessionSymbols, String> {
    let Some(session) = process.session.clone() else {
        return Err(format!(
            "'{TYPE_EPROCESS}' has no Session on this build, so a process cannot be reached from a \
             session's own list"
        ));
    };
    if !profile.symbols.has_type(TYPE_MM_SESSION_SPACE) {
        return Err(format!(
            "the symbol table has no '{TYPE_MM_SESSION_SPACE}', so a session's own process list \
             cannot be located without assuming an offset"
        ));
    }
    if reader
        .member_offset(TYPE_MM_SESSION_SPACE, MEMBER_SESSION_PROCESS_LIST)
        .is_err()
    {
        return Err(format!(
            "'{TYPE_MM_SESSION_SPACE}' has no {MEMBER_SESSION_PROCESS_LIST} on this build"
        ));
    }
    let links_offset = reader
        .member_offset(TYPE_EPROCESS, MEMBER_SESSION_PROCESS_LINKS)
        .map_err(|err| {
            format!(
                "'{TYPE_EPROCESS}.{MEMBER_SESSION_PROCESS_LINKS}' could not be located, so the \
                 structure a session link belongs to cannot be recovered: {err}"
            )
        })?
        .bytes();
    Ok(SessionSymbols {
        session,
        process_list: MEMBER_SESSION_PROCESS_LIST.to_string(),
        links_offset,
    })
}

/// Resolve the desktop view's layout, or say why it cannot be resolved.
///
/// The extra condition beyond the symbols is the address space. A desktop's
/// thread list is walked from a head **embedded in the desktop object**, so the
/// head's address is in whichever space the sweep ran in — while the `Flink`
/// values inside it are kernel virtual. On a build whose pool sweep runs in
/// physical memory the two cannot be mixed, and a walk from a physical head
/// would follow whatever the first eight bytes there happened to be. That is
/// refused here rather than attempted, because it would not fail: it would
/// produce threads.
fn resolve_desktop(
    profile: &WindowsProfile,
    reader: &StructReader,
    pool: &PoolSymbols,
) -> Result<DesktopSymbols, String> {
    for type_name in [TYPE_TAG_DESKTOP, TYPE_TAG_THREADINFO, TYPE_TAG_PROCESSINFO] {
        if !profile.symbols.has_type(type_name) {
            return Err(format!(
                "the symbol table has no '{type_name}', so the window manager's desktops cannot be \
                 read; a kernel symbol pack alone does not describe them"
            ));
        }
    }
    if pool.space != ScanSpace::KernelVirtual {
        return Err(format!(
            "this build's pool sweep runs in the {} address space, so a desktop's thread-list head \
             would be an address in that space while the links inside it are kernel virtual",
            pool.space.as_str()
        ));
    }
    if reader
        .member_offset(TYPE_TAG_DESKTOP, MEMBER_DESKTOP_THREAD_LIST)
        .is_err()
    {
        return Err(format!(
            "'{TYPE_TAG_DESKTOP}' has no {MEMBER_DESKTOP_THREAD_LIST}"
        ));
    }
    let thread_link_offset = reader
        .member_offset(TYPE_TAG_THREADINFO, MEMBER_DESKTOP_THREAD_LINK)
        .map_err(|err| format!("'{TYPE_TAG_THREADINFO}.{MEMBER_DESKTOP_THREAD_LINK}': {err}"))?
        .bytes();
    if reader
        .member_offset(TYPE_TAG_THREADINFO, MEMBER_THREAD_PROCESS_INFO)
        .is_err()
    {
        return Err(format!(
            "'{TYPE_TAG_THREADINFO}' has no {MEMBER_THREAD_PROCESS_INFO}, so a desktop thread \
             cannot be attributed to a process"
        ));
    }
    if reader
        .member_offset(TYPE_TAG_PROCESSINFO, MEMBER_PROCESS_INFO_PROCESS)
        .is_err()
    {
        return Err(format!(
            "'{TYPE_TAG_PROCESSINFO}' has no {MEMBER_PROCESS_INFO_PROCESS}"
        ));
    }
    let desktop_size = reader
        .size_of(TYPE_TAG_DESKTOP)
        .map_err(|err| format!("'{TYPE_TAG_DESKTOP}' has no declared size: {err}"))?
        .bytes();
    Ok(DesktopSymbols {
        desktop_size,
        thread_list: MEMBER_DESKTOP_THREAD_LIST.to_string(),
        thread_link_offset,
        process_info: MEMBER_THREAD_PROCESS_INFO.to_string(),
        process: MEMBER_PROCESS_INFO_PROCESS.to_string(),
    })
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Caps and geometry for one cross-view.
#[derive(Debug, Clone)]
pub struct PsXViewConfig {
    /// Caps for the active-process-list walk.
    pub process: ProcessListConfig,
    /// Caps and geometry for the pool sweeps.
    pub pool: PoolScanConfig,
    /// Ceiling on processes one session's list will report.
    pub max_session_processes: usize,
    /// Ceiling on desktops followed.
    pub max_desktops: usize,
    /// Ceiling on GUI threads one desktop's list will report.
    pub max_desktop_threads: usize,
    /// Ceiling on individually recorded notes per view.
    pub max_recorded_notes: usize,
}

impl Default for PsXViewConfig {
    fn default() -> Self {
        Self {
            process: ProcessListConfig::default(),
            pool: PoolScanConfig::default(),
            max_session_processes: MAX_SESSION_PROCESSES,
            max_desktops: MAX_DESKTOPS,
            max_desktop_threads: MAX_DESKTOP_THREADS,
            max_recorded_notes: MAX_RECORDED_NOTES,
        }
    }
}

// ── Rows ────────────────────────────────────────────────────────────────────

/// Whether one view held one process, and whether that means anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewPresence {
    /// Which view.
    pub view: ProcessView,
    /// `Some(true)` found, `Some(false)` established absent, `None` cannot say.
    pub present: Option<bool>,
}

impl ViewPresence {
    /// Serializable form for artifact metadata.
    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({"view": self.view.as_str(), "present": self.present})
    }
}

/// What a row's pattern of presences amounts to.
///
/// The verdict a report renders, so that a reader does not have to diff two
/// tables to find the process that is in one and not the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Concealment {
    /// No view that could establish an absence reported one.
    Consistent,
    /// The process is missing from a view whose silence means something, and it
    /// had **exited** — which is why the kernel no longer links to it.
    /// Ordinary, and the single most common reason a pool sweep finds a process
    /// the list does not.
    Terminated {
        /// The views that did not hold it.
        missing: Vec<ProcessView>,
    },
    /// The process is missing from such a view and it had **not** exited. This
    /// is the finding: a live process the kernel does not admit to.
    Hidden {
        /// The views that did not hold it.
        missing: Vec<ProcessView>,
        /// What that amounts to, in the examiner's terms.
        detail: String,
    },
    /// The process is missing from such a view and whether it had exited could
    /// not be read, so the two explanations cannot be told apart.
    Unexplained {
        /// The views that did not hold it.
        missing: Vec<ProcessView>,
        /// Why the question could not be settled.
        detail: String,
    },
}

impl Concealment {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            Concealment::Consistent => "consistent",
            Concealment::Terminated { .. } => "terminated",
            Concealment::Hidden { .. } => "hidden",
            Concealment::Unexplained { .. } => "unexplained",
        }
    }

    /// The views that did not hold the process, where that is established.
    pub fn missing(&self) -> &[ProcessView] {
        match self {
            Concealment::Consistent => &[],
            Concealment::Terminated { missing }
            | Concealment::Hidden { missing, .. }
            | Concealment::Unexplained { missing, .. } => missing,
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let detail = match self {
            Concealment::Hidden { detail, .. } | Concealment::Unexplained { detail, .. } => {
                Some(detail.as_str())
            }
            _ => None,
        };
        serde_json::json!({
            "kind": self.as_str(),
            "missing": self.missing().iter().map(|view| view.as_str()).collect::<Vec<_>>(),
            "detail": detail,
        })
    }
}

/// One process, and which views held it.
#[derive(Debug, Clone)]
pub struct CrossViewRow {
    /// The `_EPROCESS` as a kernel virtual address, when any view produced one.
    ///
    /// `None` for a process recovered only by a physical sweep and matched to
    /// no virtual address — which is the ordinary state of a process the kernel
    /// address space no longer maps.
    pub address: Option<u64>,
    /// The address in the swept space, when a sweep that did not run in the
    /// kernel's own space found it.
    pub scanned: Option<u64>,
    /// `UniqueProcessId`.
    pub pid: Field<u64>,
    /// `ImageFileName`.
    pub image_file_name: Field<String>,
    /// When the process started.
    pub create_time: ProcessTime,
    /// When it exited. [`ProcessTime::NotRecorded`] for a process that was
    /// still running, which is what makes an absence from the active list a
    /// finding rather than a corpse.
    pub exit_time: ProcessTime,
    /// One entry per view, in [`ProcessView::all`] order.
    pub views: Vec<ViewPresence>,
    /// Everything odd about the row that did not disqualify it.
    pub notes: Vec<String>,
}

impl CrossViewRow {
    /// The views that held this process.
    pub fn found_in(&self) -> Vec<ProcessView> {
        self.views
            .iter()
            .filter(|entry| entry.present == Some(true))
            .map(|entry| entry.view)
            .collect()
    }

    /// The views that established this process is not in them.
    pub fn missing_from(&self) -> Vec<ProcessView> {
        self.views
            .iter()
            .filter(|entry| entry.present == Some(false))
            .map(|entry| entry.view)
            .collect()
    }

    /// The views that can say nothing either way about this process.
    pub fn inconclusive_in(&self) -> Vec<ProcessView> {
        self.views
            .iter()
            .filter(|entry| entry.present.is_none())
            .map(|entry| entry.view)
            .collect()
    }

    /// Whether the process had exited by the time the image was taken.
    ///
    /// `None` when the exit time could not be read, which is not the same as
    /// "still running" and is the difference between [`Concealment::Hidden`]
    /// and [`Concealment::Unexplained`].
    pub fn has_exited(&self) -> Option<bool> {
        match &self.exit_time {
            ProcessTime::NotRecorded => Some(false),
            ProcessTime::At { .. } => Some(true),
            _ => None,
        }
    }

    /// Whether the structure this row was read from records having been
    /// created at all.
    ///
    /// Every `_EPROCESS` the kernel ever started carries a non-zero
    /// `CreateTime`, so a zero one means the bytes at this address are not a
    /// process: they are a zeroed page that some view produced a pointer into.
    /// Calling that "a live process the kernel is hiding" is the same mistake
    /// as a validity test that admits zero, and it is the one shape of false
    /// positive this stage can manufacture, because three of its five views
    /// derive an `_EPROCESS` address from a pointer inside another structure.
    ///
    /// The row is still reported — as [`Concealment::Unexplained`], which an
    /// examiner reads, rather than as a detection they act on.
    ///
    /// [`ProcessTime::NotApplicable`] is a *build* with no such member and is
    /// deliberately not this: on such a build the exit time is equally absent,
    /// so [`CrossViewRow::has_exited`] already refuses to answer.
    pub fn records_a_creation(&self) -> bool {
        !matches!(self.create_time, ProcessTime::NotRecorded)
    }

    /// The views this row was found in, as a comma-separated list.
    fn found_list(&self) -> String {
        let found = self.found_in();
        if found.is_empty() {
            return "no view".to_string();
        }
        found
            .iter()
            .map(|view| view.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// What this row amounts to.
    pub fn concealment(&self) -> Concealment {
        let missing = self.missing_from();
        if missing.is_empty() {
            return Concealment::Consistent;
        }
        let names = missing
            .iter()
            .map(|view| view.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        match self.has_exited() {
            Some(true) => Concealment::Terminated { missing },
            Some(false) if self.records_a_creation() => Concealment::Hidden {
                detail: format!(
                    "the process had not exited and is missing from: {names}; it was found by: {}",
                    self.found_list()
                ),
                missing,
            },
            Some(false) => Concealment::Unexplained {
                detail: format!(
                    "the structure at this address is missing from: {names}, and records neither a \
                     creation nor an exit; a process the kernel started always records when, so \
                     these bytes are a candidate rather than a running process the kernel is \
                     concealing"
                ),
                missing,
            },
            None => Concealment::Unexplained {
                detail: format!(
                    "the process is missing from: {names}, and its exit time could not be read, so \
                     it cannot be told whether the kernel unlinked it because it had exited"
                ),
                missing,
            },
        }
    }

    /// Whether this row is the finding the cross-view exists for.
    pub fn is_hidden(&self) -> bool {
        matches!(self.concealment(), Concealment::Hidden { .. })
    }

    /// The name to render, whatever state it is in.
    fn display_name(&self) -> String {
        match &self.image_file_name {
            Field::Known(name) if !name.is_empty() => name.clone(),
            Field::Known(_) => "<empty name>".to_string(),
            Field::NotApplicable => "<no name>".to_string(),
            Field::NotDeclared { member } => format!("<no {member} on this build>"),
            Field::Unavailable(_) => "<name unreadable>".to_string(),
        }
    }

    /// One sentence an examiner can read without consulting another table.
    ///
    /// The whole reason this stage exists is that a process visible to one view
    /// and not another is a finding, and a reader should not have to diff two
    /// listings to see it.
    pub fn summary(&self) -> String {
        let name = self.display_name();
        let pid = match self.pid.known() {
            Some(pid) => format!("pid {pid}"),
            None => "pid unknown".to_string(),
        };
        let at = match (self.address, self.scanned) {
            (Some(address), _) => format!("{address:#x}"),
            (None, Some(scanned)) => format!("{scanned:#x} in the swept space"),
            (None, None) => "an unknown address".to_string(),
        };
        let found = self.found_list();
        let missing = self
            .concealment()
            .missing()
            .iter()
            .map(|view| view.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        match self.concealment() {
            Concealment::Consistent => format!(
                "{name} ({pid}) at {at} was found by {found}, and no view that could have \
                 contradicted that did"
            ),
            Concealment::Terminated { .. } => format!(
                "{name} ({pid}) at {at} was found by {found} and is absent from {missing}, which \
                 is expected: it had exited"
            ),
            Concealment::Hidden { .. } => format!(
                "{name} ({pid}) at {at} was found by {found} and is ABSENT from {missing} despite \
                 not having exited"
            ),
            // Covers both ways the question stays open: an exit time that
            // could not be read, and a structure that records no creation at
            // all and so was never a running process to conceal.
            Concealment::Unexplained { .. } => format!(
                "{name} ({pid}) at {at} was found by {found} and is absent from {missing}; whether \
                 that is concealment or an ordinary terminated process could not be established"
            ),
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "scanned": self.scanned,
            "pid": self.pid.to_json(),
            "image_file_name": self.image_file_name.to_json(),
            "create_time": self.create_time.to_json(),
            "exit_time": self.exit_time.to_json(),
            "views": self.views.iter().map(|entry| entry.to_json()).collect::<Vec<_>>(),
            "found_in": self.found_in().iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            "missing_from": self.missing_from().iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            "inconclusive_in": self
                .inconclusive_in()
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<_>>(),
            "has_exited": self.has_exited(),
            "concealment": self.concealment().to_json(),
            "hidden": self.is_hidden(),
            "summary": self.summary(),
            "notes": self.notes,
        })
    }
}

/// Every process every view found, correlated.
#[derive(Debug, Clone)]
pub struct CrossView {
    /// One entry per view, in [`ProcessView::all`] order.
    pub views: Vec<ViewOutcome>,
    /// One row per distinct process, ordered by address.
    pub rows: Vec<CrossViewRow>,
    /// How many kernel virtual addresses could not be translated to physical.
    ///
    /// While this is non-zero, a process recovered only by a physical sweep
    /// cannot be said to be absent from the views that produce virtual
    /// addresses.
    pub untranslatable: usize,
    /// How many kernel virtual addresses shared a physical page with another,
    /// and so were displaced from the physical-to-virtual map.
    ///
    /// Carries the same caveat as `untranslatable`: while this is non-zero, a
    /// process recovered only by a physical sweep cannot be said to be absent
    /// from the views that produce virtual addresses.
    pub aliased: usize,
    /// Notes about the correlation itself.
    pub notes: Vec<String>,
}

impl CrossView {
    /// The outcome of one view.
    pub fn view(&self, view: ProcessView) -> Option<&ViewOutcome> {
        self.views.iter().find(|outcome| outcome.view == view)
    }

    /// The rows that are the finding: a process that had not exited and that a
    /// view whose silence means something did not hold.
    pub fn hidden(&self) -> Vec<&CrossViewRow> {
        self.rows.iter().filter(|row| row.is_hidden()).collect()
    }

    /// The rows missing from such a view where whether the process had exited
    /// could not be established.
    ///
    /// Deliberately separate from [`CrossView::hidden`]: these need an examiner
    /// and must not be counted as detections, but they must not be dropped
    /// either.
    pub fn unexplained(&self) -> Vec<&CrossViewRow> {
        self.rows
            .iter()
            .filter(|row| matches!(row.concealment(), Concealment::Unexplained { .. }))
            .collect()
    }

    /// Whether every view ran and reached everything it could have reached.
    ///
    /// The question a report must ask before writing "no process on this
    /// machine was hidden": a cross-view with a view that did not run has not
    /// tested what that view would have tested.
    pub fn is_complete(&self) -> bool {
        self.views.iter().all(|view| view.status.is_complete())
            && self.untranslatable == 0
            && self.aliased == 0
    }

    /// One sentence for the top of a report.
    pub fn summary(&self) -> String {
        let ran = self.views.iter().filter(|view| view.status.ran()).count();
        let deciding = self
            .views
            .iter()
            .filter(|view| view.establishes_absence())
            .count();
        format!(
            "{} process(es) correlated across {ran} view(s) that ran, {deciding} of which can \
             establish an absence; {} had not exited and are missing from at least one of those, \
             and {} more are missing from one but could not be shown either way",
            self.rows.len(),
            self.hidden().len(),
            self.unexplained().len(),
        )
    }

    /// Everything a report must declare about this cross-view.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        for view in &self.views {
            match &view.status {
                ViewStatus::Complete => {}
                ViewStatus::Partial { detail } => out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the {} view did not reach everything it could have, so a process it did \
                         not list cannot be said to be absent from it: {detail}",
                        view.view.as_str()
                    ),
                )),
                ViewStatus::NotAttempted { detail } => out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the {} view was not run, so nothing follows from a process not appearing \
                         in it: {detail}",
                        view.view.as_str()
                    ),
                )),
                ViewStatus::Failed { detail } => out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!("the {} view failed: {detail}", view.view.as_str()),
                )),
            }
            if view.unresolved > 0 {
                out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "{} result(s) of the {} view could not be placed in the kernel address \
                         space, so it cannot be asked whether it holds a given process",
                        view.unresolved,
                        view.view.as_str()
                    ),
                ));
            }
        }
        if self.untranslatable > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} process address(es) could not be translated to physical, so a process \
                     recovered only by a physical sweep cannot be matched against them",
                    self.untranslatable
                ),
            ));
        }
        if self.aliased > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} process address(es) shared a physical page with another and were \
                     displaced from the translation map, so a process recovered only by a \
                     physical sweep cannot be matched against them",
                    self.aliased
                ),
            ));
        }
        if self.rows.is_empty() {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "no view produced a process, so this result says nothing about the machine"
                    .to_string(),
            ));
        }
        out
    }

    /// Serializable form for the cross-view artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "views": self.views.iter().map(ViewOutcome::to_json).collect::<Vec<_>>(),
            "rows": self.rows.iter().map(CrossViewRow::to_json).collect::<Vec<_>>(),
            "count": self.rows.len(),
            "hidden": self.hidden().iter().map(|row| row.summary()).collect::<Vec<_>>(),
            "hidden_count": self.hidden().len(),
            "unexplained": self
                .unexplained()
                .iter()
                .map(|row| row.summary())
                .collect::<Vec<_>>(),
            "unexplained_count": self.unexplained().len(),
            "untranslatable": self.untranslatable,
            "aliased": self.aliased,
            "complete": self.is_complete(),
            "summary": self.summary(),
            "notes": self.notes,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

// ── The cross-view ──────────────────────────────────────────────────────────

/// Correlate every view of the process list this image supports.
///
/// # Errors
///
/// Only for failures that make correlation impossible to start. A view that
/// could not run is **not** an error: it is recorded as
/// [`ViewStatus::NotAttempted`] or [`ViewStatus::Failed`], and every row then
/// reports `None` rather than `false` for it.
pub fn cross_view(
    profile: &WindowsProfile,
    symbols: &PsXViewSymbols,
    config: &PsXViewConfig,
) -> Result<CrossView, PsXViewError> {
    let kernel = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );

    // The views that produce kernel virtual addresses run first, so that the
    // pool sweep — which on older builds produces physical ones — has something
    // to be matched against.
    let (pslist, list) = pslist_view(profile, symbols, config);
    let thrdscan = thrdscan_view(profile, symbols, config);
    let session = session_view(profile, symbols, config, &kernel, list.as_ref());
    let desktop = desktop_view(profile, symbols, config);

    let mut virtual_addresses: Vec<u64> = Vec::new();
    for view in [&pslist, &thrdscan, &session, &desktop] {
        virtual_addresses.extend(view.processes());
    }
    virtual_addresses.sort_unstable();
    virtual_addresses.dedup();

    // Translation is only needed when the sweep runs somewhere other than the
    // kernel's own space. Doing it unconditionally would invent an
    // `untranslatable` count on builds where the question does not arise.
    let (physical_to_virtual, untranslatable, aliased) =
        if symbols.pool.space == ScanSpace::KernelVirtual {
            (HashMap::new(), 0, 0)
        } else {
            translate_all(profile, &virtual_addresses)
        };
    let psscan = psscan_view(profile, symbols, config, &physical_to_virtual);

    let views = vec![pslist, psscan, thrdscan, session, desktop];
    let rows = build_rows(
        profile,
        symbols,
        &kernel,
        &views,
        list.as_ref(),
        untranslatable,
        aliased,
    );

    let mut notes = Vec::new();
    if symbols.pool.space != ScanSpace::KernelVirtual {
        notes.push(format!(
            "the pool sweep ran in the {} address space, so its results were matched against the \
             other views by translating each of their addresses",
            symbols.pool.space.as_str()
        ));
    }

    Ok(CrossView {
        views,
        rows,
        untranslatable,
        aliased,
        notes,
    })
}

/// Translate every kernel virtual address to physical, counting the failures
/// and the aliases.
///
/// Two virtual addresses can share one physical page, and the map is keyed by
/// physical address, so the second one displaces the first. That loses a view's
/// claim on a process just as surely as a failed translation does, and this
/// correlation exists to say whether a process is hidden — so count it rather
/// than let it vanish.
fn translate_all(profile: &WindowsProfile, addresses: &[u64]) -> (HashMap<u64, u64>, usize, usize) {
    let mut map = HashMap::new();
    let mut untranslatable = 0usize;
    let mut aliased = 0usize;
    for &address in addresses {
        match profile
            .kernel_space
            .mapping(address, 1)
            .ok()
            .and_then(|runs| runs.first().map(|run| run.mapped_offset))
        {
            Some(physical) => {
                if map.insert(physical, address).is_some() {
                    aliased += 1;
                }
            }
            None => untranslatable += 1,
        }
    }
    (map, untranslatable, aliased)
}

/// The active process list.
fn pslist_view(
    profile: &WindowsProfile,
    symbols: &PsXViewSymbols,
    config: &PsXViewConfig,
) -> (ViewOutcome, Option<ProcessList>) {
    let list = match list_processes(profile, &symbols.process, &config.process) {
        Ok(list) => list,
        Err(err) => {
            return (
                ViewOutcome::failed(ProcessView::PsList, err.to_string()),
                None,
            )
        }
    };
    let hits = list
        .processes
        .iter()
        .map(|process| ViewHit {
            process: Some(process.address),
            scanned: None,
            via: None,
        })
        .collect();
    // Reaching every entry is the question here, not reading every field of
    // every entry: a process whose name was paged out is still a process this
    // view held.
    let status = if list.forward_stop.is_complete() && list.backward_stop.is_none() {
        ViewStatus::Complete
    } else {
        ViewStatus::Partial {
            detail: stop_detail(&list.forward_stop, list.backward_stop.as_ref()),
        }
    };
    (
        ViewOutcome {
            view: ProcessView::PsList,
            status,
            hits,
            unresolved: 0,
            notes: Vec::new(),
            notes_total: 0,
        },
        Some(list),
    )
}

/// Join a view's reasons for not having reached everything, bounded.
///
/// A view seeded from a process list can accumulate one reason per seed, and a
/// detail string built from all of them on a corrupt list would be megabytes
/// long while saying no more than its first few lines. It is capped — and the
/// total is stated, because a truncated list that did not say it was truncated
/// would understate what went wrong.
fn joined_detail(reasons: &[String], cap: usize) -> String {
    if reasons.len() <= cap {
        return reasons.join("; ");
    }
    format!(
        "{}; and {} more, {} in total",
        reasons[..cap].join("; "),
        reasons.len().saturating_sub(cap),
        reasons.len()
    )
}

/// How a pair of list walks ended, in one sentence.
fn stop_detail(forward: &ListStop, backward: Option<&ListStop>) -> String {
    let forward = forward
        .incomplete()
        .map(|incomplete| incomplete.detail)
        .unwrap_or_else(|| "the forward walk completed".to_string());
    match backward.and_then(ListStop::incomplete) {
        Some(backward) => format!("{forward}; walking the other way: {}", backward.detail),
        None => forward,
    }
}

/// The pool sweep for processes.
fn psscan_view(
    profile: &WindowsProfile,
    symbols: &PsXViewSymbols,
    config: &PsXViewConfig,
    physical_to_virtual: &HashMap<u64, u64>,
) -> ViewOutcome {
    let constraints = builtin_constraints_for(&[TAG_PROCESS, TAG_PROCESS_PROTECTED]);
    if constraints.is_empty() {
        return ViewOutcome::not_attempted(
            ProcessView::PsScan,
            format!(
                "no pool constraint describes a process allocation tagged {} or {}",
                render_tag(&TAG_PROCESS),
                render_tag(&TAG_PROCESS_PROTECTED)
            ),
        );
    }
    let scan = match pool_scan(profile, &symbols.pool, &constraints, &config.pool) {
        Ok(scan) => scan,
        Err(err) => return ViewOutcome::failed(ProcessView::PsScan, err.to_string()),
    };

    let mut hits = Vec::new();
    let mut unresolved = 0usize;
    for object in scan.of_type(TYPE_EPROCESS) {
        let hit = match scan.space {
            // The sweep ran in the kernel's own space, so its addresses are
            // directly comparable with every other view's.
            ScanSpace::KernelVirtual => ViewHit {
                process: Some(object.address),
                scanned: None,
                via: Some(object.pool_header),
            },
            ScanSpace::Physical => {
                let resolved = physical_to_virtual.get(&object.address).copied();
                if resolved.is_none() {
                    unresolved += 1;
                }
                ViewHit {
                    process: resolved,
                    scanned: Some(object.address),
                    via: Some(object.pool_header),
                }
            }
        };
        hits.push(hit);
    }

    let status = if scan.is_complete() {
        ViewStatus::Complete
    } else {
        ViewStatus::Partial {
            detail: scan
                .incomplete
                .iter()
                .map(|incomplete| incomplete.detail.clone())
                .collect::<Vec<_>>()
                .join("; "),
        }
    };
    ViewOutcome {
        view: ProcessView::PsScan,
        status,
        hits,
        // A physical hit that matched no virtual address is not a *failure* to
        // place a process: it is a process the kernel address space no longer
        // maps, which is exactly what a physical sweep exists to find. It is
        // still counted, because until it is placed this view cannot be asked
        // whether it holds some other process at a virtual address.
        unresolved,
        notes: Vec::new(),
        notes_total: 0,
    }
}

/// The pool sweep for threads, resolved to the process each belongs to.
fn thrdscan_view(
    profile: &WindowsProfile,
    symbols: &PsXViewSymbols,
    config: &PsXViewConfig,
) -> ViewOutcome {
    let thread_config = ThreadScanConfig {
        pool: config.pool.clone(),
        ..ThreadScanConfig::default()
    };
    let outcome = match scan_threads(profile, &symbols.thread, &symbols.pool, &thread_config) {
        Ok(outcome) => outcome,
        Err(err) => return ViewOutcome::failed(ProcessView::ThrdScan, err.to_string()),
    };

    let mut hits = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut notes = Vec::new();
    let mut notes_total = 0usize;
    for thread in &outcome.threads {
        let Some(&process) = thread.owning_process.known() else {
            notes_total += 1;
            if notes.len() < config.max_recorded_notes {
                notes.push(format!(
                    "the thread at {:#x} names no process that could be read, so it places no \
                     process in this view",
                    thread.address
                ));
            }
            continue;
        };
        if !seen.insert(process) {
            continue;
        }
        hits.push(ViewHit {
            process: Some(process),
            scanned: None,
            via: Some(thread.address),
        });
    }

    let status = if outcome.is_complete() {
        ViewStatus::Complete
    } else {
        ViewStatus::Partial {
            detail: outcome
                .incomplete()
                .iter()
                .map(|incomplete| incomplete.detail.clone())
                .collect::<Vec<_>>()
                .join("; "),
        }
    };
    ViewOutcome {
        view: ProcessView::ThrdScan,
        status,
        hits,
        unresolved: 0,
        notes,
        notes_total,
    }
}

/// Each session's own list of processes.
///
/// Seeded from the active process list, because a session is reached through a
/// process's `Session` pointer and there is no kernel-wide list of sessions to
/// walk. That does **not** make the view redundant: a process unlinked from the
/// active list is routinely still on its session's list, and that is precisely
/// the case this view catches. It does mean the view can only reach sessions
/// that at least one listed process belongs to, which is one more reason its
/// silence means nothing.
fn session_view(
    profile: &WindowsProfile,
    symbols: &PsXViewSymbols,
    config: &PsXViewConfig,
    reader: &StructReader,
    list: Option<&ProcessList>,
) -> ViewOutcome {
    let Some(session_symbols) = symbols.session.as_ref() else {
        return ViewOutcome::not_attempted(
            ProcessView::Session,
            symbols
                .session_unavailable
                .clone()
                .unwrap_or_else(|| "this build has no session process list".to_string()),
        );
    };
    let Some(list) = list else {
        return ViewOutcome::not_attempted(
            ProcessView::Session,
            "the active process list this view is seeded from could not be walked, so no session \
             could be reached"
                .to_string(),
        );
    };
    if !profile.symbols.has_type(TYPE_LIST_ENTRY) {
        return ViewOutcome::not_attempted(
            ProcessView::Session,
            format!("the symbol table has no '{TYPE_LIST_ENTRY}'"),
        );
    }

    let mut hits = Vec::new();
    let mut seen_processes: HashSet<u64> = HashSet::new();
    let mut seen_sessions: HashSet<u64> = HashSet::new();
    let mut notes: Vec<String> = Vec::new();
    let mut notes_total = 0usize;
    let mut partial: Vec<String> = Vec::new();

    for record in &list.processes {
        // A seed that could not be read is a session this view may never have
        // visited, so it is recorded and the view stops claiming to have
        // reached everything. Dropping it silently would let a view that
        // skipped half its seeds still report itself Complete, and
        // `CrossView::is_complete` is what a report reads before writing that
        // no process on this machine was hidden.
        let eprocess = match reader.object(record.address, TYPE_EPROCESS) {
            Ok(eprocess) => eprocess,
            Err(err) => {
                notes_total += 1;
                if notes.len() < config.max_recorded_notes {
                    notes.push(format!(
                        "the process at {:#x} could not be read, so the session it belongs to was \
                         never visited: {err}",
                        record.address
                    ));
                }
                partial.push(format!(
                    "the process at {:#x} could not be read, so its session was never visited",
                    record.address
                ));
                continue;
            }
        };
        let session = match eprocess.int(&session_symbols.session) {
            Ok(value) => match value.as_u64() {
                Some(session) => session,
                None => {
                    notes_total += 1;
                    if notes.len() < config.max_recorded_notes {
                        notes.push(format!(
                            "'{TYPE_EPROCESS}.{}' at {:#x} is negative, which is not an address, so \
                             the session it names was never visited",
                            session_symbols.session, record.address
                        ));
                    }
                    partial.push(format!(
                        "the session pointer of the process at {:#x} is not an address",
                        record.address
                    ));
                    continue;
                }
            },
            Err(err) => {
                notes_total += 1;
                if notes.len() < config.max_recorded_notes {
                    notes.push(format!(
                        "'{TYPE_EPROCESS}.{}' at {:#x} could not be read, so the session it names \
                         was never visited: {err}",
                        session_symbols.session, record.address
                    ));
                }
                partial.push(format!(
                    "the session pointer of the process at {:#x} could not be read",
                    record.address
                ));
                continue;
            }
        };
        // A null session is the ordinary state of a kernel-only process, not a
        // failure, and it places no process in this view either way.
        if session == 0 || !seen_sessions.insert(session) {
            continue;
        }
        let head = match reader
            .object(session, TYPE_MM_SESSION_SPACE)
            .and_then(|space| space.member_address(&session_symbols.process_list))
        {
            Ok(head) => head,
            Err(err) => {
                notes_total += 1;
                if notes.len() < config.max_recorded_notes {
                    notes.push(format!(
                        "the session space at {session:#x} could not be read: {err}"
                    ));
                }
                partial.push(format!("the session space at {session:#x} was unreadable"));
                continue;
            }
        };
        let spec = ListSpec::new(TYPE_LIST_ENTRY, "Flink")
            .in_container(TYPE_EPROCESS, MEMBER_SESSION_PROCESS_LINKS)
            .with_max_entries(config.max_session_processes);
        let walk = match reader.walk_list(head, &spec) {
            Ok(walk) => walk,
            Err(err) => {
                partial.push(format!(
                    "the process list of the session at {session:#x} could not be walked: {err}"
                ));
                continue;
            }
        };
        let (entries, stop) = walk.walk_to_end();
        for entry in entries {
            if seen_processes.insert(entry.address()) {
                hits.push(ViewHit {
                    process: Some(entry.address()),
                    scanned: None,
                    via: Some(session),
                });
            }
        }
        if let Some(incomplete) = stop.incomplete() {
            partial.push(format!(
                "the process list of the session at {session:#x}: {}",
                incomplete.detail
            ));
        }
    }

    // The view can be no more complete than the list it was seeded from.
    if !(list.forward_stop.is_complete() && list.backward_stop.is_none()) {
        partial.push(
            "the active process list this view is seeded from did not reach every entry, so a \
             session no listed process belongs to was never visited"
                .to_string(),
        );
    }

    let status = if partial.is_empty() {
        ViewStatus::Complete
    } else {
        ViewStatus::Partial {
            detail: joined_detail(&partial, config.max_recorded_notes),
        }
    };
    ViewOutcome {
        view: ProcessView::Session,
        status,
        hits,
        unresolved: 0,
        notes,
        notes_total,
    }
}

/// The window manager's desktops, resolved to the process behind each GUI
/// thread.
fn desktop_view(
    profile: &WindowsProfile,
    symbols: &PsXViewSymbols,
    config: &PsXViewConfig,
) -> ViewOutcome {
    let Some(desktop) = symbols.desktop.as_ref() else {
        return ViewOutcome::not_attempted(
            ProcessView::DesktopThread,
            symbols
                .desktop_unavailable
                .clone()
                .unwrap_or_else(|| "this image's symbols do not describe desktops".to_string()),
        );
    };

    let constraint = PoolConstraint::new(TAG_DESKTOP, TYPE_TAG_DESKTOP)
        .executive("Desktop")
        .min_size(desktop.desktop_size)
        .page_type(PoolTypes::any());
    let scan = match pool_scan(profile, &symbols.pool, &[constraint], &config.pool) {
        Ok(scan) => scan,
        Err(err) => return ViewOutcome::failed(ProcessView::DesktopThread, err.to_string()),
    };

    // The sweep is guaranteed by `resolve_desktop` to have run in the kernel's
    // own space, so a desktop's embedded list head is a kernel virtual address
    // and the links inside it can be followed.
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let mut hits = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut notes: Vec<String> = Vec::new();
    let mut notes_total = 0usize;
    let mut partial: Vec<String> = Vec::new();
    let mut desktops = 0usize;

    for object in scan.of_type(TYPE_TAG_DESKTOP) {
        if desktops >= config.max_desktops {
            partial.push(format!(
                "the walk stopped at its cap of {} desktop(s)",
                config.max_desktops
            ));
            break;
        }
        desktops += 1;
        let head = match reader
            .object(object.address, TYPE_TAG_DESKTOP)
            .and_then(|desk| desk.member_address(&desktop.thread_list))
        {
            Ok(head) => head,
            Err(err) => {
                notes_total += 1;
                if notes.len() < config.max_recorded_notes {
                    notes.push(format!(
                        "the desktop at {:#x} could not be read: {err}",
                        object.address
                    ));
                }
                continue;
            }
        };
        let spec = ListSpec::new(TYPE_LIST_ENTRY, "Flink")
            .in_container(TYPE_TAG_THREADINFO, MEMBER_DESKTOP_THREAD_LINK)
            .with_max_entries(config.max_desktop_threads);
        let walk = match reader.walk_list(head, &spec) {
            Ok(walk) => walk,
            Err(err) => {
                partial.push(format!(
                    "the thread list of the desktop at {:#x} could not be walked: {err}",
                    object.address
                ));
                continue;
            }
        };
        let (entries, stop) = walk.walk_to_end();
        for entry in entries {
            let process = entry
                .follow(&desktop.process_info)
                .ok()
                .flatten()
                .and_then(|info| info.pointer(&desktop.process).ok())
                .filter(|address| *address != 0);
            let Some(process) = process else {
                notes_total += 1;
                if notes.len() < config.max_recorded_notes {
                    notes.push(format!(
                        "the desktop thread at {:#x} names no process that could be read",
                        entry.address()
                    ));
                }
                continue;
            };
            if seen.insert(process) {
                hits.push(ViewHit {
                    process: Some(process),
                    scanned: None,
                    via: Some(object.address),
                });
            }
        }
        if let Some(incomplete) = stop.incomplete() {
            partial.push(format!(
                "the thread list of the desktop at {:#x}: {}",
                object.address, incomplete.detail
            ));
        }
    }

    if !scan.is_complete() {
        partial
            .push("the sweep that found the desktops did not examine the whole image".to_string());
    }
    let status = if partial.is_empty() {
        ViewStatus::Complete
    } else {
        ViewStatus::Partial {
            detail: joined_detail(&partial, config.max_recorded_notes),
        }
    };
    ViewOutcome {
        view: ProcessView::DesktopThread,
        status,
        hits,
        unresolved: 0,
        notes,
        notes_total,
    }
}

// ── Correlation ─────────────────────────────────────────────────────────────

/// How a row is keyed.
///
/// Virtual before scanned, so that the order of the output is a property of the
/// kernel address space and not of which view happened to run first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RowKey {
    /// Keyed by kernel virtual address, which is every view but a physical
    /// sweep.
    Virtual(u64),
    /// Keyed by an address in the swept space, for a process that matched no
    /// kernel virtual address at all.
    Scanned(u64),
}

/// One process's identity, read from wherever its structure could be reached.
struct Identity {
    pid: Field<u64>,
    image_file_name: Field<String>,
    create_time: ProcessTime,
    exit_time: ProcessTime,
}

impl Identity {
    /// An identity nothing could be read for.
    ///
    /// Every field is `Unavailable` and none of them is a default. A zero
    /// `ExitTime` invented here would turn an unreadable structure into
    /// "the process was still running", which is the input to the finding.
    fn unreadable(detail: String) -> Self {
        Self {
            pid: Field::Unavailable(detail.clone()),
            image_file_name: Field::Unavailable(detail.clone()),
            create_time: ProcessTime::Unavailable(detail.clone()),
            exit_time: ProcessTime::Unavailable(detail),
        }
    }
}

/// Read a process's identity through a reader that can reach its structure.
fn read_identity(reader: &StructReader, symbols: &ProcessSymbols, address: u64) -> Identity {
    let object = match reader.object(address, TYPE_EPROCESS) {
        Ok(object) => object,
        Err(err) => return Identity::unreadable(err.to_string()),
    };
    let pid = match object.int(&symbols.unique_process_id) {
        Ok(value) => match value.as_u64() {
            Some(value) => Field::Known(value),
            None => Field::Unavailable("the process id is negative".to_string()),
        },
        Err(err) => Field::Unavailable(err.to_string()),
    };
    let name = match object.bytes(MEMBER_IMAGE_FILE_NAME) {
        Ok(raw) => Field::Known(image_file_name(&raw)),
        Err(err) => Field::Unavailable(err.to_string()),
    };
    let read_time = |path: Option<&str>| match path {
        None => ProcessTime::NotApplicable,
        Some(path) => match object.int(path) {
            Ok(value) => classify_process_filetime(value.as_i128()),
            Err(err) => ProcessTime::Unavailable(err.to_string()),
        },
    };
    Identity {
        pid,
        image_file_name: name,
        create_time: read_time(symbols.create_time.as_deref()),
        exit_time: read_time(symbols.exit_time.as_deref()),
    }
}

/// Turn the views' hits into one row per distinct process.
fn build_rows(
    profile: &WindowsProfile,
    symbols: &PsXViewSymbols,
    kernel: &StructReader,
    views: &[ViewOutcome],
    list: Option<&ProcessList>,
    untranslatable: usize,
    aliased: usize,
) -> Vec<CrossViewRow> {
    // Which views hold each key. A `BTreeMap` because the order of the output
    // must be a property of the image and not of the order the views ran in.
    let mut found: BTreeMap<RowKey, Vec<ProcessView>> = BTreeMap::new();
    for view in views {
        for hit in &view.hits {
            let key = match (hit.process, hit.scanned) {
                (Some(process), _) => RowKey::Virtual(process),
                (None, Some(scanned)) => RowKey::Scanned(scanned),
                (None, None) => continue,
            };
            let entry = found.entry(key).or_default();
            if !entry.contains(&view.view) {
                entry.push(view.view);
            }
        }
    }

    // A reader over the swept layer, for the identity of a process only a
    // physical sweep reached. Its pointers still resolve in the kernel's space,
    // which is what `with_native` models.
    let swept = StructReader::with_native(
        match symbols.pool.space {
            ScanSpace::Physical => Arc::clone(&profile.physical),
            ScanSpace::KernelVirtual => Arc::clone(&profile.kernel_space),
        },
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );

    let mut rows = Vec::with_capacity(found.len());
    for (key, held_by) in found {
        let (address, scanned) = match key {
            RowKey::Virtual(address) => (Some(address), None),
            RowKey::Scanned(scanned) => (None, Some(scanned)),
        };
        let mut notes = Vec::new();

        // Prefer what the process list already read: it came from the same
        // structure, and reusing it keeps a row from disagreeing with the
        // process listing about the same process.
        let listed = address.and_then(|address| list.and_then(|list| list.at(address)));
        let identity = match (listed, address) {
            (Some(record), _) => Identity {
                pid: record.pid.clone(),
                image_file_name: record.image_file_name.clone(),
                create_time: record.create_time.clone(),
                exit_time: record.exit_time.clone(),
            },
            (None, Some(address)) => read_identity(kernel, &symbols.process, address),
            (None, None) => {
                notes.push(
                    "this process was recovered only by a sweep of an address space that is not \
                     the kernel's, so its fields were read there"
                        .to_string(),
                );
                read_identity(&swept, &symbols.process, scanned.unwrap_or(0))
            }
        };

        let presences = views
            .iter()
            .map(|view| {
                let present = if held_by.contains(&view.view) {
                    Some(true)
                } else {
                    match address {
                        Some(address) => view.contains(address),
                        // A row with no kernel virtual address matched nothing
                        // any view produced. A view can only be said not to
                        // hold it once every virtual address survived
                        // translation — otherwise the one that did not might
                        // have been this very process. An address displaced by
                        // an alias is as absent from the map as one that never
                        // translated, so both have to be zero.
                        None if untranslatable == 0 && aliased == 0 => {
                            view.contains_scanned(scanned.unwrap_or(0))
                        }
                        None => None,
                    }
                };
                ViewPresence {
                    view: view.view,
                    present,
                }
            })
            .collect();

        rows.push(CrossViewRow {
            address,
            scanned,
            pid: identity.pid,
            image_file_name: identity.image_file_name,
            create_time: identity.create_time,
            exit_time: identity.exit_time,
            views: presences,
            notes,
        });
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{profile, table, Image};
    use seance_memory::Architecture;

    /// A layer whose translation is whatever the test says it is, so two
    /// virtual addresses can be pointed at one physical page. The shared
    /// fixture cannot express that: its kernel space *is* its physical layer,
    /// so distinct addresses are distinct by construction.
    #[derive(Debug)]
    struct AliasingLayer {
        /// Virtual address -> physical offset.
        translations: std::collections::HashMap<u64, u64>,
        meta: seance_memory::meta::LayerMeta,
        source: seance_core::data_source::ByteSliceDataSource,
    }

    impl AliasingLayer {
        fn new(translations: &[(u64, u64)]) -> Self {
            Self {
                translations: translations.iter().copied().collect(),
                meta: seance_memory::meta::LayerMeta::new(
                    seance_memory::format::MemoryImageFormat::Raw,
                ),
                source: seance_core::data_source::ByteSliceDataSource::new(vec![0u8; 0x1000]),
            }
        }
    }

    impl seance_core::data_source::DataSource for AliasingLayer {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            seance_core::data_source::DataSource::read_at(&self.source, offset, buf)
        }
        fn size(&self) -> u64 {
            seance_core::data_source::DataSource::size(&self.source)
        }
    }

    impl seance_memory::MemoryLayer for AliasingLayer {
        fn min_address(&self) -> u64 {
            0
        }
        fn max_address(&self) -> u64 {
            u64::MAX
        }
        fn mapping(
            &self,
            offset: u64,
            length: u64,
        ) -> Result<Vec<seance_memory::MappedRange>, seance_memory::LayerError> {
            match self.translations.get(&offset) {
                Some(&physical) => Ok(vec![seance_memory::MappedRange {
                    offset,
                    length,
                    mapped_offset: physical,
                    mapped_length: length,
                    encoding: seance_memory::Encoding::Identity,
                    source: seance_memory::BackingSource::Primary,
                    via: None,
                }]),
                None => Ok(Vec::new()),
            }
        }
        fn layer_meta(&self) -> &seance_memory::meta::LayerMeta {
            &self.meta
        }
        fn as_data_source(&self) -> &dyn seance_core::data_source::DataSource {
            &self.source
        }
    }

    /// Two virtual addresses on one physical page: the map is keyed by physical
    /// address, so the second insert displaces the first. Before this was
    /// counted, that address left the correlation with no record — and the
    /// correlation's whole job is to say whether a process is hidden.
    #[test]
    fn two_addresses_on_one_physical_page_are_counted_as_aliased() {
        let layer = Arc::new(AliasingLayer::new(&[
            (0xAAAA_0000, 0x1000),
            (0xBBBB_0000, 0x1000), // same physical page as the line above
            (0xCCCC_0000, 0x2000),
        ])) as Arc<dyn seance_memory::MemoryLayer>;
        let profile = profile(layer, table(&isf()), Architecture::X64, 10, 0, Some(19041));

        let (map, untranslatable, aliased) = translate_all(
            &profile,
            &[0xAAAA_0000, 0xBBBB_0000, 0xCCCC_0000, 0xDDDD_0000],
        );

        assert_eq!(map.len(), 2, "two distinct physical pages survive");
        assert_eq!(untranslatable, 1, "0xDDDD_0000 has no mapping");
        assert_eq!(aliased, 1, "0xBBBB_0000 displaced 0xAAAA_0000");
    }

    /// 2021-06-01T00:00:00Z as a Windows FILETIME.
    const CREATE_TIME: u64 = 132_669_792_000_000_000;
    /// A minute later.
    const EXIT_TIME: u64 = CREATE_TIME + 600_000_000;

    /// The head of the active process list, at `PsActiveProcessHead`.
    const LIST_HEAD: u64 = 0x200;
    /// The allocation holding the linked process.
    const POOL_LINKED: u64 = 0x2000;
    /// The allocation holding the process that is on no list.
    const POOL_HIDDEN: u64 = 0x4000;
    /// The session space both processes belong to.
    const SESSION_AT: u64 = 0x8000;

    /// Where an object body sits inside one of these allocations: past the
    /// sixteen-byte pool header and the object header's `Body` offset.
    const BODY: u64 = 16 + 48;
    const LINKED: u64 = POOL_LINKED + BODY;
    const HIDDEN: u64 = POOL_HIDDEN + BODY;

    mod off {
        pub(super) const PID: u64 = 0;
        pub(super) const NAME: u64 = 8;
        pub(super) const CREATE_TIME: u64 = 32;
        pub(super) const EXIT_TIME: u64 = 40;
        pub(super) const ACTIVE_LINKS: u64 = 48;
        pub(super) const THREAD_LIST: u64 = 64;
        pub(super) const SESSION_LINKS: u64 = 80;
        pub(super) const SESSION: u64 = 96;

        pub(super) const SESSION_PROCESS_LIST: u64 = 8;
    }

    /// Base of a kernel address standing in for the non-paged pool a process's
    /// `_ETHREAD`s are allocated from.
    ///
    /// `_EPROCESS.ThreadListHead` links `_ETHREAD.ThreadListEntry`, and an
    /// `_ETHREAD` is a non-paged pool allocation, so both links are kernel
    /// addresses on every Windows. The pool sweep tests exactly that, because
    /// it is what separates a process from bytes that merely read like one —
    /// a fragment of a string whose name and creation time both pass. A
    /// fixture that left the member zero described a process whose thread list
    /// points at the null page, which is not a process the sweep should admit.
    ///
    /// The threads themselves are not modelled: this stage is about which view
    /// holds which process, and no view here walks a thread list.
    const KERNEL_THREAD_LIST: u64 = 0xFFFF_8000_0000_1000;

    /// A synthetic 64-bit Windows 10 ISF carrying every structure the
    /// cross-view reads except the window manager's, which a kernel symbol pack
    /// genuinely does not have.
    fn isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "4A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}
  },
  "base_types": "#,
            crate::image_fixture::BASE_TYPES_X64,
            r#",
  "user_types": {
    "_POOL_HEADER": {"size": 16, "kind": "struct", "fields": {
      "BlockSize": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "PoolType": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "PoolTag": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_QUAD": {"size": 8, "kind": "struct", "fields": {
      "Value": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_OBJECT_HEADER": {"size": 56, "kind": "struct", "fields": {
      "PointerCount": {"offset": 0, "type": {"kind": "base", "name": "long"}},
      "HandleCount": {"offset": 8, "type": {"kind": "base", "name": "long"}},
      "TypeIndex": {"offset": 24, "type": {"kind": "base", "name": "unsigned char"}},
      "InfoMask": {"offset": 26, "type": {"kind": "base", "name": "unsigned char"}},
      "Body": {"offset": 48, "type": {"kind": "struct", "name": "_QUAD"}}
    }},
    "_OBJECT_HEADER_CREATOR_INFO": {"size": 32, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_NAME_INFO": {"size": 32, "kind": "struct", "fields": {}},
    "_LIST_ENTRY": {"size": 16, "kind": "struct", "fields": {
      "Flink": {"offset": 0, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
      "Blink": {"offset": 8, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
    }},
    "_LARGE_INTEGER": {"size": 8, "kind": "union", "fields": {
      "QuadPart": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_CLIENT_ID": {"size": 16, "kind": "struct", "fields": {
      "UniqueThread": {"offset": 0, "type": {"kind": "pointer",
                       "subtype": {"kind": "base", "name": "unsigned char"}}},
      "UniqueProcess": {"offset": 8, "type": {"kind": "pointer",
                        "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_KTHREAD": {"size": 24, "kind": "struct", "fields": {
      "Process": {"offset": 0, "type": {"kind": "pointer",
                  "subtype": {"kind": "base", "name": "unsigned char"}}},
      "State": {"offset": 8, "type": {"kind": "base", "name": "unsigned char"}}
    }},
    "_ETHREAD": {"size": 640, "kind": "struct", "fields": {
      "Cid": {"offset": 0, "type": {"kind": "struct", "name": "_CLIENT_ID"}},
      "ThreadListEntry": {"offset": 16, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "CreateTime": {"offset": 32, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ExitTime": {"offset": 40, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "Tcb": {"offset": 64, "type": {"kind": "struct", "name": "_KTHREAD"}}
    }},
    "_MM_SESSION_SPACE": {"size": 64, "kind": "struct", "fields": {
      "SessionId": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "ProcessList": {"offset": 8, "type": {"kind": "struct", "name": "_LIST_ENTRY"}}
    }},
    "_EPROCESS": {"size": 256, "kind": "struct", "fields": {
      "UniqueProcessId": {"offset": 0, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ImageFileName": {"offset": 8, "type": {"kind": "array", "count": 15,
                        "subtype": {"kind": "base", "name": "unsigned char"}}},
      "CreateTime": {"offset": 32, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ExitTime": {"offset": 40, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ActiveProcessLinks": {"offset": 48, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "ThreadListHead": {"offset": 64, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "SessionProcessLinks": {"offset": 80, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "Session": {"offset": 96, "type": {"kind": "pointer",
                  "subtype": {"kind": "struct", "name": "_MM_SESSION_SPACE"}}},
      "DirectoryTableBase": {"offset": 104, "type": {"kind": "base",
                             "name": "unsigned long long"}}
    }}
  },
  "enums": {},
  "symbols": {"PsActiveProcessHead": {"address": 512}}
}"#,
        ]
        .concat()
    }

    /// A `Proc` allocation holding an `_EPROCESS` with the given identity.
    fn put_process(image: &mut Image, pool: u64, pid: u64, name: &[u8], exit: u64) -> u64 {
        image.put_u16(pool, 64); // BlockSize: 64 granules of 16 bytes
        image.put_u16(pool + 2, 2); // non-paged, in the Vista encoding
        image.write(pool + 4, b"Proc");
        let header = pool + 16;
        image.put_u32(header, 7); // PointerCount
        image.put_u8(header + 26, 0); // InfoMask: no optional headers present
        let body = header + 48;
        image.put_u64(body + off::PID, pid);
        image.write(body + off::NAME, name);
        image.put_u64(body + off::CREATE_TIME, CREATE_TIME);
        image.put_u64(body + off::EXIT_TIME, exit);
        // A thread list in the kernel, one address per process, as a real
        // `_EPROCESS` carries. See [`KERNEL_THREAD_LIST`].
        image.put_u64(body + off::THREAD_LIST, KERNEL_THREAD_LIST + pool);
        image.put_u64(body + off::THREAD_LIST + 8, KERNEL_THREAD_LIST + pool);
        body
    }

    /// One linked process and one that is on no list, both in the pool.
    fn image_with(hidden_exit: u64, session: bool) -> Image {
        let mut image = Image::new();
        put_process(&mut image, POOL_LINKED, 0x200, b"explorer.exe", 0);
        put_process(&mut image, POOL_HIDDEN, 0x400, b"rootkit.exe", hidden_exit);

        // The active process list: head → linked → head. The hidden process is
        // deliberately not on it.
        let linked_link = LINKED + off::ACTIVE_LINKS;
        image.put_u64(LIST_HEAD, linked_link);
        image.put_u64(LIST_HEAD + 8, linked_link);
        image.put_u64(linked_link, LIST_HEAD);
        image.put_u64(linked_link + 8, LIST_HEAD);

        if session {
            // The session's own list: head → linked → hidden → head. The hidden
            // process is still on it, which is exactly what an unlink of the
            // active list alone leaves behind.
            let head = SESSION_AT + off::SESSION_PROCESS_LIST;
            let linked_session = LINKED + off::SESSION_LINKS;
            let hidden_session = HIDDEN + off::SESSION_LINKS;
            image.put_u64(head, linked_session);
            image.put_u64(head + 8, hidden_session);
            image.put_u64(linked_session, hidden_session);
            image.put_u64(linked_session + 8, head);
            image.put_u64(hidden_session, head);
            image.put_u64(hidden_session + 8, linked_session);
            image.put_u64(LINKED + off::SESSION, SESSION_AT);
            image.put_u64(HIDDEN + off::SESSION, SESSION_AT);
        }
        image
    }

    fn run(image: Image) -> CrossView {
        let profile = profile(
            image.layer(),
            table(&isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = PsXViewSymbols::from_profile(&profile).expect("a describable build");
        cross_view(&profile, &symbols, &PsXViewConfig::default()).expect("a runnable cross-view")
    }

    fn row_at(view: &CrossView, address: u64) -> &CrossViewRow {
        view.rows
            .iter()
            .find(|row| row.address == Some(address))
            .unwrap_or_else(|| panic!("no row for {address:#x}"))
    }

    fn presence(row: &CrossViewRow, view: ProcessView) -> Option<bool> {
        row.views
            .iter()
            .find(|entry| entry.view == view)
            .expect("every view has a cell on every row")
            .present
    }

    // ── Which absences are allowed to mean anything ─────────────────────────

    #[test]
    fn only_the_two_views_that_enumerate_every_process_can_establish_an_absence() {
        // Getting this wrong flags the System process — which has no session
        // and no desktop thread — on every image ever examined.
        assert!(ProcessView::PsList.enumerates_every_process());
        assert!(ProcessView::PsScan.enumerates_every_process());
        assert!(!ProcessView::ThrdScan.enumerates_every_process());
        assert!(!ProcessView::Session.enumerates_every_process());
        assert!(!ProcessView::DesktopThread.enumerates_every_process());
    }

    #[test]
    fn a_view_that_ran_but_did_not_finish_does_not_establish_an_absence() {
        let outcome = ViewOutcome {
            view: ProcessView::PsList,
            status: ViewStatus::Partial {
                detail: "the walk stopped at a hole".to_string(),
            },
            hits: Vec::new(),
            unresolved: 0,
            notes: Vec::new(),
            notes_total: 0,
        };
        assert!(!outcome.establishes_absence());
        assert_eq!(outcome.contains(0x1000), None);
    }

    #[test]
    fn a_view_with_a_hit_it_could_not_place_does_not_establish_an_absence() {
        // The process it could not place might be the one being asked about.
        let outcome = ViewOutcome {
            view: ProcessView::PsScan,
            status: ViewStatus::Complete,
            hits: vec![ViewHit {
                process: None,
                scanned: Some(0x9000),
                via: None,
            }],
            unresolved: 1,
            notes: Vec::new(),
            notes_total: 0,
        };
        assert!(!outcome.establishes_absence());
        assert_eq!(outcome.contains(0x1000), None);
    }

    #[test]
    fn a_complete_view_that_enumerates_everything_does_establish_an_absence() {
        let outcome = ViewOutcome {
            view: ProcessView::PsList,
            status: ViewStatus::Complete,
            hits: vec![ViewHit {
                process: Some(0x2000),
                scanned: None,
                via: None,
            }],
            unresolved: 0,
            notes: Vec::new(),
            notes_total: 0,
        };
        assert_eq!(outcome.contains(0x2000), Some(true));
        assert_eq!(outcome.contains(0x1000), Some(false));
    }

    // ── The cross-view itself ───────────────────────────────────────────────

    #[test]
    fn a_process_both_deciding_views_hold_is_consistent() {
        let view = run(image_with(0, false));
        let row = row_at(&view, LINKED);
        assert_eq!(presence(row, ProcessView::PsList), Some(true));
        assert_eq!(presence(row, ProcessView::PsScan), Some(true));
        assert_eq!(row.concealment(), Concealment::Consistent);
        assert!(!row.is_hidden());
        assert_eq!(
            row.image_file_name.known().map(String::as_str),
            Some("explorer.exe")
        );
    }

    #[test]
    fn a_process_the_sweep_found_and_the_list_did_not_is_the_finding() {
        let view = run(image_with(0, false));
        let row = row_at(&view, HIDDEN);
        assert_eq!(presence(row, ProcessView::PsScan), Some(true));
        assert_eq!(
            presence(row, ProcessView::PsList),
            Some(false),
            "the list was walked end to end, so its silence is evidence"
        );
        assert!(row.is_hidden(), "{:?}", row.concealment());
        assert_eq!(view.hidden().len(), 1);
        assert!(row.summary().contains("ABSENT"), "{}", row.summary());
        assert!(row.summary().contains("rootkit.exe"), "{}", row.summary());
        assert!(row.summary().contains("pslist"), "{}", row.summary());
    }

    #[test]
    fn a_process_that_had_exited_is_not_called_hidden_merely_for_being_unlinked() {
        // The ordinary state of a terminated process: the kernel unlinked it
        // and its allocation has not been reused. Reporting that as a rootkit
        // would bury the real findings.
        let view = run(image_with(EXIT_TIME, false));
        let row = row_at(&view, HIDDEN);
        assert_eq!(presence(row, ProcessView::PsList), Some(false));
        assert!(matches!(row.concealment(), Concealment::Terminated { .. }));
        assert!(!row.is_hidden());
        assert!(view.hidden().is_empty());
    }

    #[test]
    fn a_zeroed_structure_a_view_pointed_at_is_not_reported_as_a_hidden_process() {
        // Three of the five views derive an `_EPROCESS` address from a pointer
        // inside another structure, so a pointer into a zeroed page arrives
        // here as a process that never exited and is on no list — which reads
        // as the finding this stage exists for. A process the kernel started
        // always records when it started.
        let zeroed = CrossViewRow {
            address: Some(0x9000),
            scanned: None,
            pid: Field::Known(0),
            image_file_name: Field::Known(String::new()),
            create_time: ProcessTime::NotRecorded,
            exit_time: ProcessTime::NotRecorded,
            views: vec![
                ViewPresence {
                    view: ProcessView::PsList,
                    present: Some(false),
                },
                ViewPresence {
                    view: ProcessView::DesktopThread,
                    present: Some(true),
                },
            ],
            notes: Vec::new(),
        };
        assert!(!zeroed.is_hidden(), "{:?}", zeroed.concealment());
        assert!(matches!(
            zeroed.concealment(),
            Concealment::Unexplained { .. }
        ));
        assert!(
            !zeroed.missing_from().is_empty(),
            "the row is still reported, and still says which view lost it"
        );

        // The same row for a structure that does record a creation is the
        // finding, and this fix must not have suppressed it.
        let started = CrossViewRow {
            create_time: classify_process_filetime(i128::from(CREATE_TIME)),
            ..zeroed.clone()
        };
        assert!(started.records_a_creation());
        assert!(started.is_hidden(), "{:?}", started.concealment());
    }

    #[test]
    fn a_view_that_was_not_attempted_never_reports_an_absence() {
        // This image's symbols do not describe the window manager, so the
        // desktop view cannot run. Every row must say "cannot tell" for it and
        // never "not present".
        let view = run(image_with(0, false));
        let desktop = view
            .view(ProcessView::DesktopThread)
            .expect("the view is listed even when it did not run");
        assert!(matches!(desktop.status, ViewStatus::NotAttempted { .. }));
        assert!(desktop
            .status
            .detail()
            .expect("a reason")
            .contains(TYPE_TAG_DESKTOP));
        for row in &view.rows {
            assert_eq!(presence(row, ProcessView::DesktopThread), None);
        }
    }

    #[test]
    fn a_process_with_no_recovered_thread_is_not_accused_by_the_thread_view() {
        // No `Thre` allocation exists in this image at all, so the thread view
        // holds nothing. It must still not deny that either process exists.
        let view = run(image_with(0, false));
        for row in &view.rows {
            assert_eq!(presence(row, ProcessView::ThrdScan), None);
        }
    }

    #[test]
    fn the_session_list_still_holds_a_process_the_active_list_has_lost() {
        // An unlink of the active process list alone leaves the session's own
        // list intact, and this is the view that catches it.
        let view = run(image_with(0, true));
        let session = view
            .view(ProcessView::Session)
            .expect("the session view is listed");
        assert!(session.status.ran(), "{:?}", session.status);
        assert_eq!(session.processes(), vec![LINKED, HIDDEN]);
        let row = row_at(&view, HIDDEN);
        assert_eq!(presence(row, ProcessView::Session), Some(true));
        assert_eq!(presence(row, ProcessView::PsList), Some(false));
        assert!(row.is_hidden());
    }

    #[test]
    fn a_seed_the_session_view_could_not_read_stops_it_claiming_to_have_reached_every_session() {
        // The session view is seeded from the active process list, so a seed it
        // could not read is a session it may never have visited. Dropping that
        // silently would let the view report itself Complete, and
        // `CrossView::is_complete` is what a report reads before writing that
        // nothing on this machine was hidden.
        use crate::process::{ProcessRecord, WalkDirection};

        let profile = profile(
            image_with(0, true).layer(),
            table(&isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = PsXViewSymbols::from_profile(&profile).expect("a describable build");
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        let unreadable = ProcessRecord {
            address: 0x1F00_0000,
            direction: WalkDirection::Forward,
            pid: Field::Known(0x600),
            ppid: Field::NotApplicable,
            image_file_name: Field::NotApplicable,
            image_name_well_formed: true,
            threads: Field::NotApplicable,
            handles: Field::NotApplicable,
            session_id: Field::NotApplicable,
            wow64: Field::NotApplicable,
            create_time: ProcessTime::NotRecorded,
            exit_time: ProcessTime::NotRecorded,
            peb: Field::NotApplicable,
            notes: Vec::new(),
        };
        let list = ProcessList {
            head: LIST_HEAD,
            links_offset: off::ACTIVE_LINKS,
            processes: vec![unreadable],
            forward_stop: ListStop::Wrapped,
            backward_stop: None,
        };

        let outcome = session_view(
            &profile,
            &symbols,
            &PsXViewConfig::default(),
            &reader,
            Some(&list),
        );
        assert!(
            matches!(outcome.status, ViewStatus::Partial { .. }),
            "an unreadable seed must not leave the view calling itself complete: {:?}",
            outcome.status
        );
        assert!(!outcome.establishes_absence());
        assert!(
            outcome.notes_total >= 1,
            "the seed that could not be read is recorded"
        );
    }

    #[test]
    fn the_session_view_never_denies_a_process_even_when_it_is_complete() {
        // A kernel-only process belongs to no session, so its absence from
        // every session list is ordinary and must never be reported as one.
        let view = run(image_with(0, true));
        let session = view
            .view(ProcessView::Session)
            .expect("the session view is listed");
        assert!(!session.establishes_absence());
        assert_eq!(session.contains(0xDEAD_BEEF), None);
    }

    #[test]
    fn a_build_without_a_session_space_records_why_rather_than_an_empty_view() {
        let isf = isf().replace("\"_MM_SESSION_SPACE\"", "\"_NO_SUCH_SESSION_SPACE\"");
        let profile = profile(
            image_with(0, true).layer(),
            table(&isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = PsXViewSymbols::from_profile(&profile).expect("a describable build");
        assert!(symbols.session.is_none());
        assert!(symbols
            .session_unavailable
            .as_deref()
            .expect("a reason")
            .contains(TYPE_MM_SESSION_SPACE));

        let view =
            cross_view(&profile, &symbols, &PsXViewConfig::default()).expect("a runnable run");
        let session = view
            .view(ProcessView::Session)
            .expect("still listed, with its reason");
        assert!(matches!(session.status, ViewStatus::NotAttempted { .. }));
        for row in &view.rows {
            assert_eq!(presence(row, ProcessView::Session), None);
        }
    }

    #[test]
    fn every_row_carries_a_cell_for_every_view_so_a_gap_cannot_be_read_as_a_no() {
        let view = run(image_with(0, true));
        assert!(!view.rows.is_empty());
        for row in &view.rows {
            let listed: Vec<ProcessView> = row.views.iter().map(|entry| entry.view).collect();
            assert_eq!(listed, ProcessView::all().to_vec());
        }
    }

    #[test]
    fn a_cross_view_with_a_view_that_did_not_run_is_not_complete() {
        let view = run(image_with(0, false));
        assert!(
            !view.is_complete(),
            "the desktop view cannot run on a kernel-only symbol table"
        );
        assert!(view
            .incomplete()
            .iter()
            .any(|incomplete| incomplete.detail.contains("was not run")));
    }

    #[test]
    fn the_rows_are_ordered_by_address_so_the_output_does_not_depend_on_view_order() {
        let view = run(image_with(0, true));
        let addresses: Vec<Option<u64>> = view.rows.iter().map(|row| row.address).collect();
        let mut sorted = addresses.clone();
        sorted.sort();
        assert_eq!(addresses, sorted);
    }

    #[test]
    fn the_serialised_form_names_the_hidden_process_at_the_top_level() {
        let view = run(image_with(0, false));
        let json = view.to_json();
        assert_eq!(json["hidden_count"], 1);
        let hidden = json["hidden"].as_array().expect("an array of summaries");
        assert_eq!(hidden.len(), 1);
        assert!(hidden[0]
            .as_str()
            .expect("a sentence")
            .contains("rootkit.exe"));
        assert_eq!(json["complete"], false);
    }

    #[test]
    fn the_summary_says_how_many_views_can_establish_an_absence() {
        // The count is what a reader needs before believing an absence: a
        // cross-view where no view can establish one has found nothing, however
        // many empty cells it renders.
        let view = run(image_with(0, false));
        let deciding = view
            .views
            .iter()
            .filter(|outcome| outcome.establishes_absence())
            .count();
        assert!(
            deciding >= 1,
            "the active process list was walked end to end"
        );
        let summary = view.summary();
        assert!(summary.contains("establish an absence"), "{summary}");
        assert!(
            summary.contains(&format!("{deciding} of which")),
            "{summary}"
        );
    }

    #[test]
    fn a_process_id_read_from_the_pool_matches_the_one_the_list_reports() {
        // The hidden process is on no list, so its identity is read from the
        // structure the sweep found. A row whose fields came out of the wrong
        // offsets would still render, which is why this is asserted.
        let view = run(image_with(0, false));
        assert_eq!(row_at(&view, LINKED).pid.known(), Some(&0x200));
        assert_eq!(row_at(&view, HIDDEN).pid.known(), Some(&0x400));
        assert_eq!(
            row_at(&view, HIDDEN)
                .image_file_name
                .known()
                .map(String::as_str),
            Some("rootkit.exe")
        );
    }
}
