//! Threads: `thrdscan` and `threads`.
//!
//! A process is a container. Nothing in a process *runs*; its threads do. Two
//! findings follow from that, and neither is visible in a process list:
//!
//! * A thread whose `_ETHREAD` is in the pool but whose owning `_EPROCESS` is
//!   on no list is a process that was executing code and is invisible to every
//!   API that asks the kernel what is running. That is the third view
//!   [`crate::psxview::cross_view`] correlates.
//! * A thread whose start address is not in any mapped image is code that was
//!   written into a process rather than loaded into it, which is the whole of
//!   [`crate::psxview::suspicious`].
//!
//! # Two ways to reach a thread, and they answer different questions
//!
//! **`threads`** walks `_EPROCESS.ThreadListHead` through
//! `_ETHREAD.ThreadListEntry`. It enumerates the threads the kernel currently
//! links to *this* process, so it answers "what is this process running". Like
//! every list walk it sees exactly what the links say, which is what a rootkit
//! edits.
//!
//! **`thrdscan`** sweeps the pool for `Thre` allocations. It answers "what
//! threads has this machine had", including threads whose process exited and
//! threads unlinked from their process. It cannot say which of those a process
//! is running now, because a freed allocation looks like a live one until its
//! contents are checked.
//!
//! Both are implemented here and neither is described as the other.
//!
//! # `ThreadListEntry` is not at offset zero
//!
//! The same arithmetic that makes the process list dangerous applies here: the
//! link is embedded partway into `_ETHREAD`, so every `Flink` points into the
//! middle of the next thread and the structure begins that many bytes earlier.
//! The offset comes from the symbol table through
//! [`seance_memory::object::ListSpec::in_container`] and is published on
//! [`ThreadList::links_offset`] so it can be checked rather than trusted.
//!
//! # The owning process moved, and the create time is stored differently
//!
//! Getting from a thread to its process is `_ETHREAD.ThreadsProcess` on XP and
//! 2003, and `_ETHREAD.Tcb.Process` — the `_KTHREAD` embedded at the front —
//! from Vista onward. Which one this build has is asked of the symbol table,
//! and a build with neither is refused by name rather than silently yielding
//! threads that belong to nobody.
//!
//! On the builds that have `ThreadsProcess`, `_ETHREAD.CreateTime` stores the
//! FILETIME **shifted left by three bits**, the low three being flags. Reading
//! it unshifted dates every thread to roughly eight times its true age, which
//! lands in the far future and reads as a plausible-looking timestamp rather
//! than as an error. [`ThreadSymbols::create_time_is_shifted`] records which
//! convention this build uses and it is applied once, here.

use std::collections::HashSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{ListSpec, ListStop, Obj, StructReader};
use seance_memory::{Incomplete, MemoryLayer};

use crate::poolscan::{
    builtin_constraints_for, pool_scan, PoolScanConfig, PoolScanOutcome, PoolSymbols, ScanSpace,
};
use crate::process::{Field, ProcessTime, TYPE_EPROCESS, TYPE_LIST_ENTRY};
use crate::profile::WindowsProfile;
use crate::psxview::{classify_process_filetime, PsXViewError};

// ── Names this module knows ─────────────────────────────────────────────────

/// The executive thread structure.
pub const TYPE_ETHREAD: &str = "_ETHREAD";

/// The member of `_ETHREAD` that threads it onto its process's thread list.
pub const MEMBER_THREAD_LIST_ENTRY: &str = "ThreadListEntry";

/// The member of `_EPROCESS` that heads its thread list.
pub const MEMBER_THREAD_LIST_HEAD: &str = "ThreadListHead";

/// The pool tag Windows 8 and later allocate an `_ETHREAD` under.
pub const TAG_THREAD: [u8; 4] = *b"Thre";

/// The pool tag earlier builds allocate a *protected* `_ETHREAD` under.
///
/// The top bit of the last byte marks the allocation protected. Both tags are
/// swept regardless of build, because freed pool from before an upgrade carries
/// the older spelling.
pub const TAG_THREAD_PROTECTED: [u8; 4] = *b"Thr\xe5";

/// `_KTHREAD.State` for a thread that has terminated.
///
/// The state a thread is left in after it returns and before its `_ETHREAD` is
/// freed. A terminated thread's start address says nothing about what the
/// process is running now, so [`crate::psxview::suspicious`] excludes it.
pub const THREAD_STATE_TERMINATED: u64 = 4;

/// Largest process id NT hands out.
///
/// Ids are handed out in multiples of four from a bitmap; the top of the range
/// is the largest such value that fits in 32 bits. A `Cid.UniqueProcess` above
/// it is not a process id, it is the bytes at that offset not being one.
pub const MAX_PID: u64 = 0xFFFF_FFFC;

/// Ceiling on the threads one process's thread list will report.
///
/// The largest thread counts seen on real machines are in the low thousands.
/// Reaching this means the link chain is wrong, and it is reported as a cap
/// rather than as the end of the list.
pub const MAX_THREADS_PER_PROCESS: usize = 65_536;

/// Ceiling on threads one pool sweep will decode.
pub const MAX_SCANNED_THREADS: usize = 1_000_000;

// ── Layout ──────────────────────────────────────────────────────────────────

/// Resolve the first of `candidates` that this build's `type_name` actually has.
///
/// This module used to carry its own copy, which returned a bare `Option` built
/// from `member_offset(..).is_ok()` and so reported "the symbol table could not
/// answer" as "this build has no such member". Those are opposite claims and the
/// shared helper keeps them apart; there is one definition of it so the two
/// cannot drift.
use seance_memory::binding::first_member;

/// How this build gets from a thread to the process that owns it.
///
/// Two shapes and no default. A build with neither is refused, because a thread
/// attributed to the wrong process attributes its start address, its stack and
/// its timestamps to the wrong process too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwningProcessLink {
    /// XP and 2003: `_ETHREAD.ThreadsProcess` points straight at the
    /// `_EPROCESS`.
    ThreadsProcess(String),
    /// Vista and later: the `_KTHREAD` embedded at the front of `_ETHREAD` as
    /// `Tcb` carries the `Process` pointer.
    TcbProcess(String),
}

impl OwningProcessLink {
    /// The member path the pointer is read from.
    pub fn path(&self) -> &str {
        match self {
            OwningProcessLink::ThreadsProcess(path) | OwningProcessLink::TcbProcess(path) => path,
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            OwningProcessLink::ThreadsProcess(_) => "threads_process",
            OwningProcessLink::TcbProcess(_) => "tcb_process",
        }
    }
}

/// The member paths this build's threads are read through.
///
/// Resolved once per image and checked once, so a build whose `_ETHREAD` the
/// symbols cannot describe fails here naming the member that is missing, rather
/// than at thread three hundred having already emitted rows read at the wrong
/// offsets.
#[derive(Debug, Clone)]
pub struct ThreadSymbols {
    /// Path to the thread id.
    pub cid_unique_thread: String,
    /// Path to the owning process's id.
    pub cid_unique_process: String,
    /// How the owning `_EPROCESS` is reached.
    pub owning_process: OwningProcessLink,
    /// Byte offset of `ThreadListEntry` inside `_ETHREAD`, when this build has
    /// one. `None` makes [`list_process_threads`] refuse rather than guess.
    pub thread_list_entry: Option<u64>,
    /// Path to the thread-list head inside `_EPROCESS`.
    pub thread_list_head: Option<String>,
    /// Path to the kernel start address.
    pub start_address: Option<String>,
    /// Path to the user-mode start address, which is the one an examiner cares
    /// about: `StartAddress` is `RtlUserThreadStart` for every user thread.
    pub win32_start_address: Option<String>,
    /// Path to the creation FILETIME.
    pub create_time: Option<String>,
    /// Path to the exit FILETIME.
    pub exit_time: Option<String>,
    /// Path to the scheduler state.
    pub state: Option<String>,
    /// Whether this build stores `CreateTime` shifted left by three bits.
    ///
    /// True exactly on the builds that have `ThreadsProcess`. Applying the
    /// shift where it is not wanted, or omitting it where it is, produces a
    /// timestamp that is wrong by a factor of eight and still renders as a
    /// date.
    pub create_time_is_shifted: bool,
}

impl ThreadSymbols {
    /// Resolve every layout fact a thread read of this image needs.
    ///
    /// # Errors
    ///
    /// [`PsXViewError::Unsupported`] naming what is missing, for the three
    /// facts without which a thread is not a thread: the client id, the owning
    /// process link, and `_ETHREAD` itself. Everything else is optional and an
    /// absent optional member becomes [`Field::NotApplicable`] on every record
    /// rather than a zero.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, PsXViewError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        if !profile.symbols.has_type(TYPE_ETHREAD) {
            return Err(PsXViewError::unsupported(format!(
                "the symbol table has no '{TYPE_ETHREAD}', so there is no thread structure to read"
            )));
        }

        let cid_unique_thread = first_member(&reader, TYPE_ETHREAD, &["Cid.UniqueThread"])?
            .ok_or_else(|| {
                PsXViewError::unsupported(format!(
                    "'{TYPE_ETHREAD}' has no Cid.UniqueThread, so a thread cannot be identified"
                ))
            })?
            .to_string();
        let cid_unique_process = first_member(&reader, TYPE_ETHREAD, &["Cid.UniqueProcess"])?
            .ok_or_else(|| {
                PsXViewError::unsupported(format!(
                    "'{TYPE_ETHREAD}' has no Cid.UniqueProcess, so a thread cannot be attributed \
                     to a process"
                ))
            })?
            .to_string();

        // XP first: a build that somehow declared both would be the earlier
        // shape, and `ThreadsProcess` is the member that also decides how
        // `CreateTime` is stored.
        let owning_process = match first_member(&reader, TYPE_ETHREAD, &["ThreadsProcess"])? {
            Some(path) => OwningProcessLink::ThreadsProcess(path.to_string()),
            None => match first_member(&reader, TYPE_ETHREAD, &["Tcb.Process", "Process"])? {
                Some(path) => OwningProcessLink::TcbProcess(path.to_string()),
                None => {
                    return Err(PsXViewError::unsupported(format!(
                        "'{TYPE_ETHREAD}' has neither ThreadsProcess nor Tcb.Process, so no \
                         thread can be attributed to the process that owns it"
                    )))
                }
            },
        };
        let create_time_is_shifted = matches!(owning_process, OwningProcessLink::ThreadsProcess(_));

        let thread_list_head = if profile.symbols.has_type(TYPE_EPROCESS) {
            first_member(&reader, TYPE_EPROCESS, &[MEMBER_THREAD_LIST_HEAD])?.map(str::to_string)
        } else {
            None
        };

        Ok(Self {
            cid_unique_thread,
            cid_unique_process,
            owning_process,
            thread_list_entry: reader
                .member_offset(TYPE_ETHREAD, MEMBER_THREAD_LIST_ENTRY)
                .ok()
                .map(|o| o.bytes()),
            thread_list_head,
            start_address: first_member(
                &reader,
                TYPE_ETHREAD,
                &["StartAddress", "Tcb.StartAddress"],
            )?
            .map(str::to_string),
            win32_start_address: first_member(
                &reader,
                TYPE_ETHREAD,
                &["Win32StartAddress", "Tcb.Win32StartAddress"],
            )?
            .map(str::to_string),
            create_time: first_member(
                &reader,
                TYPE_ETHREAD,
                &["CreateTime.QuadPart", "CreateTime"],
            )?
            .map(str::to_string),
            exit_time: first_member(&reader, TYPE_ETHREAD, &["ExitTime.QuadPart", "ExitTime"])?
                .map(str::to_string),
            state: first_member(&reader, TYPE_ETHREAD, &["Tcb.State", "State"])?
                .map(str::to_string),
            create_time_is_shifted,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "cid_unique_thread": self.cid_unique_thread,
            "cid_unique_process": self.cid_unique_process,
            "owning_process": self.owning_process.as_str(),
            "owning_process_path": self.owning_process.path(),
            "thread_list_entry": self.thread_list_entry,
            "thread_list_head": self.thread_list_head,
            "start_address": self.start_address,
            "win32_start_address": self.win32_start_address,
            "create_time": self.create_time,
            "exit_time": self.exit_time,
            "state": self.state,
            "create_time_is_shifted": self.create_time_is_shifted,
        })
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// How a thread was reached, which bounds what its address means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadOrigin {
    /// Reached by walking a process's `ThreadListHead`. The address is a kernel
    /// virtual address and the thread was linked to that process at capture.
    ProcessThreadList,
    /// Recovered by sweeping the pool. The address is in the swept space, which
    /// is **not** the kernel's virtual space on builds before Windows 10, and
    /// the thread may be a freed allocation rather than a live thread.
    PoolScan {
        /// The space [`ThreadRecord::address`] is in.
        space: ScanSpace,
    },
}

impl ThreadOrigin {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ThreadOrigin::ProcessThreadList => "process_thread_list",
            ThreadOrigin::PoolScan { .. } => "pool_scan",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(self) -> serde_json::Value {
        match self {
            ThreadOrigin::PoolScan { space } => {
                serde_json::json!({"kind": "pool_scan", "space": space.as_str()})
            }
            other => serde_json::json!({"kind": other.as_str()}),
        }
    }
}

/// One thread, as the image describes it.
#[derive(Debug, Clone)]
pub struct ThreadRecord {
    /// Where the `_ETHREAD` is, in the space named by
    /// [`ThreadRecord::origin`].
    pub address: u64,
    /// How the thread was reached.
    pub origin: ThreadOrigin,
    /// `Cid.UniqueThread`.
    pub tid: Field<u64>,
    /// `Cid.UniqueProcess`: the id of the process the thread says it belongs
    /// to. Not authoritative on its own — a freed allocation's client id is
    /// whatever was last written there — which is why the owning pointer is
    /// read as well.
    pub pid: Field<u64>,
    /// The `_EPROCESS` the thread belongs to, as a **kernel virtual** address.
    ///
    /// A kernel pointer regardless of which space the thread structure itself
    /// was found in, so it is directly comparable with the addresses a process
    /// list produces.
    pub owning_process: Field<u64>,
    /// `StartAddress`: where the kernel starts the thread. For a user thread
    /// this is `RtlUserThreadStart` and is the same for every thread on the
    /// machine, which is why it is not the interesting one.
    pub start_address: Field<u64>,
    /// `Win32StartAddress`: the address the thread was actually created to run.
    /// This is what [`crate::psxview::suspicious`] tests against the VAD tree.
    pub win32_start_address: Field<u64>,
    /// When the thread was created.
    pub create_time: ProcessTime,
    /// When it exited. [`ProcessTime::NotRecorded`] for a thread that was still
    /// running.
    pub exit_time: ProcessTime,
    /// The scheduler state.
    pub state: Field<u64>,
    /// Everything odd about the record that did not disqualify it.
    pub notes: Vec<String>,
}

impl ThreadRecord {
    /// Whether the thread had exited by the time the image was taken.
    ///
    /// `None` when neither the exit time nor the state could be read, which is
    /// not the same as "still running" and must not render as it.
    pub fn is_terminated(&self) -> Option<bool> {
        let by_time = match &self.exit_time {
            ProcessTime::NotRecorded => Some(false),
            ProcessTime::At { .. } => Some(true),
            _ => None,
        };
        if by_time == Some(true) {
            return Some(true);
        }
        let by_state = self
            .state
            .known()
            .map(|state| *state == THREAD_STATE_TERMINATED);
        if by_state == Some(true) {
            return Some(true);
        }
        // Both must agree on "still running" before that can be claimed.
        match (by_time, by_state) {
            (Some(false), Some(false)) => Some(false),
            (Some(false), None) => Some(false),
            (None, Some(false)) => Some(false),
            _ => None,
        }
    }

    /// Whether the client id looks like one NT would have handed out.
    ///
    /// Both ids are multiples of four and the process id is inside the range
    /// the kernel allocates from. A `false` is not proof the structure is not a
    /// thread — it is proof it should not be counted as one without saying so.
    pub fn client_id_is_plausible(&self) -> Option<bool> {
        let (Some(tid), Some(pid)) = (self.tid.known(), self.pid.known()) else {
            return None;
        };
        Some(*tid % 4 == 0 && *pid % 4 == 0 && *pid != 0 && *pid <= MAX_PID)
    }

    /// The names of the fields that exist and could not be read.
    pub fn unreadable_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.tid.is_unavailable() {
            out.push("tid");
        }
        if self.pid.is_unavailable() {
            out.push("pid");
        }
        if self.owning_process.is_unavailable() {
            out.push("owning_process");
        }
        if self.start_address.is_unavailable() {
            out.push("start_address");
        }
        if self.win32_start_address.is_unavailable() {
            out.push("win32_start_address");
        }
        if matches!(self.create_time, ProcessTime::Unavailable(_)) {
            out.push("create_time");
        }
        if matches!(self.exit_time, ProcessTime::Unavailable(_)) {
            out.push("exit_time");
        }
        if self.state.is_unavailable() {
            out.push("state");
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "origin": self.origin.to_json(),
            "tid": self.tid.to_json(),
            "pid": self.pid.to_json(),
            "owning_process": self.owning_process.to_json(),
            "start_address": self.start_address.to_json(),
            "win32_start_address": self.win32_start_address.to_json(),
            "create_time": self.create_time.to_json(),
            "exit_time": self.exit_time.to_json(),
            "state": self.state.to_json(),
            "terminated": self.is_terminated(),
            "client_id_plausible": self.client_id_is_plausible(),
            "unreadable_fields": self.unreadable_fields(),
            "notes": self.notes,
        })
    }
}

// ── Reading one thread ──────────────────────────────────────────────────────

/// Read an integer or pointer member into a [`Field`].
fn read_unsigned(object: &Obj, path: Option<&str>) -> Field<u64> {
    let Some(path) = path else {
        return Field::NotApplicable;
    };
    match object.int(path) {
        Ok(value) => match value.as_u64() {
            Some(value) => Field::Known(value),
            None => Field::Unavailable(format!(
                "'{}.{path}' is negative, which is not a count or an identifier",
                object.type_name()
            )),
        },
        Err(err) => Field::Unavailable(err.to_string()),
    }
}

/// Read a thread FILETIME, undoing the three-bit shift on the builds that use
/// it.
///
/// Zero stays [`ProcessTime::NotRecorded`] either way: every running thread has
/// a zero exit time, and converting it would date every live thread to
/// 1601-01-01, which reads as a thread that has exited.
fn read_time(object: &Obj, path: Option<&str>, shifted: bool) -> ProcessTime {
    let Some(path) = path else {
        return ProcessTime::NotApplicable;
    };
    match object.int(path) {
        Ok(value) => {
            let raw = value.as_i128();
            if !shifted {
                return classify_process_filetime(raw);
            }
            if raw < 0 {
                // A negative value cannot have its low three bits stripped and
                // still be a time; reporting the raw value keeps the evidence.
                return ProcessTime::Implausible { raw };
            }
            classify_process_filetime(raw >> 3)
        }
        Err(err) => ProcessTime::Unavailable(err.to_string()),
    }
}

/// Read one `_ETHREAD` into a record.
///
/// Never fails. Every field that cannot be read becomes [`Field::Unavailable`]
/// carrying the reason, because the thread's presence at that address is
/// evidence independently of whether its page was captured, and dropping the
/// row would silently shorten the thread list.
pub fn read_thread(symbols: &ThreadSymbols, thread: &Obj, origin: ThreadOrigin) -> ThreadRecord {
    let mut notes = Vec::new();

    let tid = read_unsigned(thread, Some(symbols.cid_unique_thread.as_str()));
    let pid = read_unsigned(thread, Some(symbols.cid_unique_process.as_str()));

    // A null owning pointer is not "no process": every thread has one. The
    // field exists and does not name a process, which is `Unavailable` and not
    // a zero that would later be matched against an `_EPROCESS` at address 0.
    let path = symbols.owning_process.path();
    let owning_process = match thread.int(path) {
        Ok(value) => match value.as_u64() {
            Some(0) => Field::Unavailable(format!(
                "'{}.{path}' is null, and every thread belongs to a process",
                thread.type_name()
            )),
            Some(value) => Field::Known(value),
            None => Field::Unavailable(format!(
                "'{}.{path}' is negative, which is not an address",
                thread.type_name()
            )),
        },
        Err(err) => Field::Unavailable(err.to_string()),
    };

    if let (Some(&tid), Some(&pid)) = (tid.known(), pid.known()) {
        if tid % 4 != 0 {
            notes.push(format!(
                "the thread id {tid} is not a multiple of four, and every id NT hands out is"
            ));
        }
        if pid % 4 != 0 {
            notes.push(format!(
                "the owning process id {pid} is not a multiple of four, and every id NT hands out \
                 is"
            ));
        }
        if pid > MAX_PID {
            notes.push(format!(
                "the owning process id {pid} is above the largest id NT hands out ({MAX_PID})"
            ));
        }
    }

    let create_time = read_time(
        thread,
        symbols.create_time.as_deref(),
        symbols.create_time_is_shifted,
    );
    // The exit time is never shifted, on any build.
    let exit_time = read_time(thread, symbols.exit_time.as_deref(), false);
    if let (ProcessTime::At { filetime: born, .. }, ProcessTime::At { filetime: died, .. }) =
        (&create_time, &exit_time)
    {
        if died < born {
            notes.push(format!(
                "the exit time {died} precedes the create time {born}, so one of the two was not \
                 read from this thread"
            ));
        }
    }

    ThreadRecord {
        address: thread.address(),
        origin,
        tid,
        pid,
        owning_process,
        start_address: read_unsigned(thread, symbols.start_address.as_deref()),
        win32_start_address: read_unsigned(thread, symbols.win32_start_address.as_deref()),
        create_time,
        exit_time,
        state: read_unsigned(thread, symbols.state.as_deref()),
        notes,
    }
}

// ── threads: one process's thread list ──────────────────────────────────────

/// Caps for one thread-list walk.
#[derive(Debug, Clone)]
pub struct ThreadListConfig {
    /// Ceiling on threads reported for one process.
    pub max_threads: usize,
}

impl Default for ThreadListConfig {
    fn default() -> Self {
        Self {
            max_threads: MAX_THREADS_PER_PROCESS,
        }
    }
}

/// One process's threads, and everything the walk could not do.
#[derive(Debug, Clone)]
pub struct ThreadList {
    /// The `_EPROCESS` the list belongs to.
    pub process: u64,
    /// Address of the list head, which is embedded in the `_EPROCESS`.
    pub head: u64,
    /// The offset subtracted from every list link to recover its `_ETHREAD`.
    ///
    /// Published so the arithmetic every address in this list rests on can be
    /// checked rather than trusted.
    pub links_offset: u64,
    /// The threads, in the order the list gave them.
    pub threads: Vec<ThreadRecord>,
    /// Why the forward walk ended. Only [`ListStop::Wrapped`] means the list
    /// was enumerated end to end.
    pub forward_stop: ListStop,
    /// Why the backward walk ended, when the forward one stopped early enough
    /// to make one worth doing.
    pub backward_stop: Option<ListStop>,
}

impl ThreadList {
    /// Whether the list was walked end to end and every field of every row was
    /// either read or explicitly absent.
    ///
    /// The question a report must ask before writing "this process was running
    /// these threads": a walk that stopped early says nothing about what it did
    /// not reach.
    pub fn is_complete(&self) -> bool {
        self.forward_stop.is_complete()
            && self.backward_stop.is_none()
            && self
                .threads
                .iter()
                .all(|thread| thread.unreadable_fields().is_empty())
    }

    /// Whether the walk reached every entry, regardless of whether every field
    /// of every entry was readable.
    ///
    /// This is the weaker question, and the right one for "could this list have
    /// contained a thread it did not show me".
    pub fn reached_every_entry(&self) -> bool {
        self.forward_stop.is_complete() && self.backward_stop.is_none()
    }

    /// The threads that had not terminated when the image was taken.
    pub fn live(&self) -> impl Iterator<Item = &ThreadRecord> {
        self.threads
            .iter()
            .filter(|thread| thread.is_terminated() != Some(true))
    }

    /// Everything a report must declare about this list.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(incomplete) = self.forward_stop.incomplete() {
            out.push(Incomplete::new(
                incomplete.reason,
                format!(
                    "walking the thread list of the process at {:#x} forward from {:#x}: {}",
                    self.process, self.head, incomplete.detail
                ),
            ));
        }
        if let Some(stop) = &self.backward_stop {
            if let Some(incomplete) = stop.incomplete() {
                out.push(Incomplete::new(
                    incomplete.reason,
                    format!(
                        "walking the thread list of the process at {:#x} backward from {:#x}: {}",
                        self.process, self.head, incomplete.detail
                    ),
                ));
            }
        }
        for thread in &self.threads {
            let unreadable = thread.unreadable_fields();
            if !unreadable.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the thread at {:#x} has field(s) that exist and could not be read: {}",
                        thread.address,
                        unreadable.join(", ")
                    ),
                ));
            }
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "head": self.head,
            "links_offset": self.links_offset,
            "count": self.threads.len(),
            "threads": self.threads.iter().map(ThreadRecord::to_json).collect::<Vec<_>>(),
            "forward_stop": self.forward_stop.as_str(),
            "backward_stop": self.backward_stop.as_ref().map(ListStop::as_str),
            "complete": self.is_complete(),
            "reached_every_entry": self.reached_every_entry(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Walk one process's `ThreadListHead` and report every thread on it.
///
/// The list is walked forward first. If the forward walk stops early — an
/// `_ETHREAD` whose page was not captured breaks the chain — the list is walked
/// **backward** as well, because it is doubly linked and the threads past the
/// break are still reachable from the other end. Anything already seen is
/// skipped, which is what makes the two walks meet in the middle rather than
/// report the same thread twice.
///
/// # Errors
///
/// Only for failures that make the walk impossible to start: a build with no
/// `ThreadListHead` or no `ThreadListEntry`, or an `_EPROCESS` whose head
/// address cannot be computed. A failure *during* the walk is not an error —
/// the threads found before it are evidence, and it is recorded in
/// [`ThreadList::incomplete`] beside them.
pub fn list_process_threads(
    profile: &WindowsProfile,
    symbols: &ThreadSymbols,
    process: u64,
    config: &ThreadListConfig,
) -> Result<ThreadList, PsXViewError> {
    let Some(head_path) = symbols.thread_list_head.as_deref() else {
        return Err(PsXViewError::unsupported(format!(
            "'{TYPE_EPROCESS}' has no {MEMBER_THREAD_LIST_HEAD} on this build, so a process's \
             threads cannot be enumerated from it"
        )));
    };
    let Some(links_offset) = symbols.thread_list_entry else {
        return Err(PsXViewError::unsupported(format!(
            "'{TYPE_ETHREAD}' has no {MEMBER_THREAD_LIST_ENTRY} on this build, so the structure a \
             thread-list link belongs to cannot be recovered"
        )));
    };
    if !profile.symbols.has_type(TYPE_LIST_ENTRY) {
        return Err(PsXViewError::unsupported(format!(
            "the symbol table has no '{TYPE_LIST_ENTRY}', so the thread list's links cannot be \
             followed"
        )));
    }

    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let eprocess = reader.object(process, TYPE_EPROCESS)?;
    // The head is *embedded* in the `_EPROCESS`, so its address is the member's
    // address rather than a value read out of it. Following it as a pointer
    // would take the first thread's link address as the head and never wrap.
    let head = eprocess.member_address(head_path)?;

    let mut threads: Vec<ThreadRecord> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();

    let forward_stop = walk_threads(
        &reader,
        symbols,
        config,
        head,
        "Flink",
        &mut seen,
        &mut threads,
    )?;
    // A cap is a bound the caller set, not a chain that could not be followed;
    // walking backward after one would re-walk the same list from the other end
    // and defeat the bound.
    let capped = matches!(forward_stop, ListStop::CapReached { .. });
    let backward_stop = if forward_stop.is_complete() || capped {
        None
    } else {
        Some(walk_threads(
            &reader,
            symbols,
            config,
            head,
            "Blink",
            &mut seen,
            &mut threads,
        )?)
    };

    Ok(ThreadList {
        process,
        head,
        links_offset,
        threads,
        forward_stop,
        backward_stop,
    })
}

/// One pass over a thread list in one direction.
fn walk_threads(
    reader: &StructReader,
    symbols: &ThreadSymbols,
    config: &ThreadListConfig,
    head: u64,
    member: &str,
    seen: &mut HashSet<u64>,
    threads: &mut Vec<ThreadRecord>,
) -> Result<ListStop, PsXViewError> {
    // `in_container` is what turns a link address into the structure it is
    // embedded in, and it checks against the symbol table that the named member
    // really is the link — pointing it at a different member would subtract a
    // wrong constant from every entry and yield a list of structures that all
    // parse.
    let spec = ListSpec::new(TYPE_LIST_ENTRY, member)
        .in_container(TYPE_ETHREAD, MEMBER_THREAD_LIST_ENTRY)
        .with_max_entries(config.max_threads);
    let walk = reader.walk_list(head, &spec)?;
    let (entries, stop) = walk.walk_to_end();
    for entry in entries {
        if !seen.insert(entry.address()) {
            continue;
        }
        threads.push(read_thread(
            symbols,
            &entry,
            ThreadOrigin::ProcessThreadList,
        ));
    }
    Ok(stop)
}

// ── thrdscan: the pool sweep ────────────────────────────────────────────────

/// Caps and geometry for one thread sweep.
#[derive(Debug, Clone)]
pub struct ThreadScanConfig {
    /// Caps and geometry for the underlying pool sweep.
    pub pool: PoolScanConfig,
    /// Ceiling on threads decoded from the sweep's objects.
    pub max_threads: usize,
}

impl Default for ThreadScanConfig {
    fn default() -> Self {
        Self {
            pool: PoolScanConfig::default(),
            max_threads: MAX_SCANNED_THREADS,
        }
    }
}

/// What one thread sweep found, and everything it could not do.
#[derive(Debug, Clone)]
pub struct ThreadScanOutcome {
    /// The threads, in ascending address order within the swept space.
    pub threads: Vec<ThreadRecord>,
    /// Which address space was swept, which is the space every
    /// [`ThreadRecord::address`] here is in.
    pub space: ScanSpace,
    /// The underlying sweep's own account of what it examined and rejected.
    pub scan: PoolScanOutcome,
    /// How many recovered allocations could not be decoded as an `_ETHREAD` at
    /// all. Counted rather than dropped silently.
    pub undecodable: usize,
    /// Whether the thread cap fired. The sweep stopped; the image did not run
    /// out of threads.
    pub truncated: bool,
}

impl ThreadScanOutcome {
    /// Whether every mapped byte was swept and every thread decoded.
    ///
    /// The question a report must ask before writing "this machine ran no such
    /// thread": an incomplete sweep that found nothing says nothing about the
    /// machine.
    pub fn is_complete(&self) -> bool {
        !self.truncated && self.undecodable == 0 && self.scan.is_complete()
    }

    /// The distinct `_EPROCESS` addresses the threads point at.
    ///
    /// Ascending and deduplicated: this is the cross-view's thread-derived
    /// process list, and its order must not depend on which thread happened to
    /// be found first.
    pub fn owning_processes(&self) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .threads
            .iter()
            .filter_map(|thread| thread.owning_process.known().copied())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Everything a report must declare about this result.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.scan.incomplete.clone();
        if self.truncated {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                "the thread sweep stopped at its cap; the image was not exhausted".to_string(),
            ));
        }
        if self.undecodable > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} recovered allocation(s) tagged as threads could not be read as an \
                     '{TYPE_ETHREAD}'",
                    self.undecodable
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "threads": self.threads.iter().map(ThreadRecord::to_json).collect::<Vec<_>>(),
            "count": self.threads.len(),
            "space": self.space.as_str(),
            "undecodable": self.undecodable,
            "truncated": self.truncated,
            "complete": self.is_complete(),
            "scan": self.scan.to_json(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Sweep the pool for `_ETHREAD` allocations.
///
/// This is `thrdscan`. It finds threads the kernel no longer links to — a
/// thread whose process exited, and a thread a rootkit unlinked — which is
/// exactly what a thread-list walk cannot see by construction.
///
/// # Errors
///
/// Only for failures that make the whole sweep meaningless: a symbol table that
/// cannot describe a pool allocation, or a build whose thread tags this crate
/// does not know. An allocation that failed validation is not an error — it is
/// counted in [`PoolScanOutcome::rejected`].
pub fn scan_threads(
    profile: &WindowsProfile,
    symbols: &ThreadSymbols,
    pool: &PoolSymbols,
    config: &ThreadScanConfig,
) -> Result<ThreadScanOutcome, PsXViewError> {
    let constraints = builtin_constraints_for(&[TAG_THREAD, TAG_THREAD_PROTECTED]);
    if constraints.is_empty() {
        return Err(PsXViewError::unsupported(
            "no pool constraint describes an '_ETHREAD' allocation, so a thread sweep would have \
             nothing to look for and its empty result would read as a machine with no threads",
        ));
    }
    let scan = pool_scan(profile, pool, &constraints, &config.pool)?;

    // The allocation's bytes live in the swept layer; every pointer inside it
    // is a kernel virtual address. Getting these two the wrong way round does
    // not fail — it silently reads unrelated bytes that parse.
    let layer: Arc<dyn MemoryLayer> = match scan.space {
        ScanSpace::Physical => Arc::clone(&profile.physical),
        ScanSpace::KernelVirtual => Arc::clone(&profile.kernel_space),
    };
    let reader = StructReader::with_native(
        layer,
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );

    let mut threads = Vec::new();
    let mut undecodable = 0usize;
    let mut truncated = false;
    for object in scan.of_type(TYPE_ETHREAD) {
        if threads.len() >= config.max_threads {
            truncated = true;
            break;
        }
        match reader.object(object.address, TYPE_ETHREAD) {
            Ok(thread) => threads.push(read_thread(
                symbols,
                &thread,
                ThreadOrigin::PoolScan { space: scan.space },
            )),
            Err(_) => undecodable += 1,
        }
    }

    Ok(ThreadScanOutcome {
        threads,
        space: scan.space,
        scan,
        undecodable,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{profile, table, Image};
    use crate::poolscan::POOL_ALIGNMENT_64;
    use seance_memory::Architecture;

    /// 2021-06-01T00:00:00Z as a Windows FILETIME.
    const CREATE_TIME: u64 = 132_669_792_000_000_000;

    const EPROCESS_AT: u64 = 0x1000;
    const THREAD_A: u64 = 0x3000;
    const THREAD_B: u64 = 0x4000;

    /// Offsets the synthetic 64-bit thread ISF declares.
    mod off {
        pub(super) const EPROCESS_THREAD_LIST_HEAD: u64 = 64;

        pub(super) const ETHREAD_CID_THREAD: u64 = 0;
        pub(super) const ETHREAD_CID_PROCESS: u64 = 8;
        pub(super) const ETHREAD_LIST_ENTRY: u64 = 16;
        pub(super) const ETHREAD_CREATE_TIME: u64 = 32;
        pub(super) const ETHREAD_EXIT_TIME: u64 = 40;
        pub(super) const ETHREAD_START: u64 = 48;
        pub(super) const ETHREAD_WIN32_START: u64 = 56;
        pub(super) const ETHREAD_TCB_PROCESS: u64 = 64;
        pub(super) const ETHREAD_TCB_STATE: u64 = 72;
    }

    /// A synthetic 64-bit Windows 10 ISF with an `_ETHREAD` reachable both by
    /// list and by sweep.
    fn win10_thread_isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "1A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
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
      "StartAddress": {"offset": 48, "type": {"kind": "pointer",
                       "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Win32StartAddress": {"offset": 56, "type": {"kind": "pointer",
                            "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Tcb": {"offset": 64, "type": {"kind": "struct", "name": "_KTHREAD"}}
    }},
    "_EPROCESS": {"size": 640, "kind": "struct", "fields": {
      "UniqueProcessId": {"offset": 0, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ImageFileName": {"offset": 8, "type": {"kind": "array", "count": 15,
                        "subtype": {"kind": "base", "name": "unsigned char"}}},
      "CreateTime": {"offset": 32, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ActiveProcessLinks": {"offset": 48, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "ThreadListHead": {"offset": 64, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "DirectoryTableBase": {"offset": 96, "type": {"kind": "base",
                             "name": "unsigned long long"}}
    }}
  },
  "enums": {},
  "symbols": {"PsActiveProcessHead": {"address": 512}}
}"#,
        ]
        .concat()
    }

    /// A synthetic 32-bit Windows XP ISF: `ThreadsProcess` and a shifted
    /// `CreateTime`.
    fn xp_thread_isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "2A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 332}}
  },
  "base_types": "#,
            crate::image_fixture::BASE_TYPES_X86,
            r#",
  "user_types": {
    "_POOL_HEADER": {"size": 8, "kind": "struct", "fields": {
      "PoolType": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "BlockSize": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "PoolTag": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_LIST_ENTRY": {"size": 8, "kind": "struct", "fields": {
      "Flink": {"offset": 0, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
      "Blink": {"offset": 4, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
    }},
    "_LARGE_INTEGER": {"size": 8, "kind": "union", "fields": {
      "QuadPart": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_CLIENT_ID": {"size": 8, "kind": "struct", "fields": {
      "UniqueThread": {"offset": 0, "type": {"kind": "pointer",
                       "subtype": {"kind": "base", "name": "unsigned char"}}},
      "UniqueProcess": {"offset": 4, "type": {"kind": "pointer",
                        "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_ETHREAD": {"size": 256, "kind": "struct", "fields": {
      "Cid": {"offset": 0, "type": {"kind": "struct", "name": "_CLIENT_ID"}},
      "ThreadListEntry": {"offset": 8, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "CreateTime": {"offset": 16, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ExitTime": {"offset": 24, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ThreadsProcess": {"offset": 32, "type": {"kind": "pointer",
                         "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_EPROCESS": {"size": 608, "kind": "struct", "fields": {
      "UniqueProcessId": {"offset": 0, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ImageFileName": {"offset": 4, "type": {"kind": "array", "count": 16,
                        "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ThreadListHead": {"offset": 32, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "DirectoryTableBase": {"offset": 48, "type": {"kind": "base", "name": "unsigned long"}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#,
        ]
        .concat()
    }

    /// An `_ETHREAD` written at `at`, linked between `flink` and `blink`.
    #[allow(clippy::too_many_arguments)]
    fn put_thread(
        image: &mut Image,
        at: u64,
        tid: u64,
        pid: u64,
        owner: u64,
        flink: u64,
        blink: u64,
        win32_start: u64,
    ) {
        image.put_u64(at + off::ETHREAD_CID_THREAD, tid);
        image.put_u64(at + off::ETHREAD_CID_PROCESS, pid);
        image.put_u64(at + off::ETHREAD_LIST_ENTRY, flink);
        image.put_u64(at + off::ETHREAD_LIST_ENTRY + 8, blink);
        image.put_u64(at + off::ETHREAD_CREATE_TIME, CREATE_TIME);
        image.put_u64(at + off::ETHREAD_EXIT_TIME, 0);
        image.put_u64(at + off::ETHREAD_START, 0x7FF0_0000);
        image.put_u64(at + off::ETHREAD_WIN32_START, win32_start);
        image.put_u64(at + off::ETHREAD_TCB_PROCESS, owner);
    }

    fn win10_profile(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&win10_thread_isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        )
    }

    /// Two threads linked onto one process, forming a closed ring with the head
    /// embedded in the `_EPROCESS`.
    fn two_thread_image() -> Image {
        let mut image = Image::new();
        let head = EPROCESS_AT + off::EPROCESS_THREAD_LIST_HEAD;
        let link_a = THREAD_A + off::ETHREAD_LIST_ENTRY;
        let link_b = THREAD_B + off::ETHREAD_LIST_ENTRY;
        image.put_u64(head, link_a);
        image.put_u64(head + 8, link_b);
        put_thread(
            &mut image,
            THREAD_A,
            0x100,
            0x200,
            EPROCESS_AT,
            link_b,
            head,
            0x40_0000,
        );
        put_thread(
            &mut image,
            THREAD_B,
            0x104,
            0x200,
            EPROCESS_AT,
            head,
            link_a,
            0x40_1000,
        );
        image
    }

    fn symbols_of(profile: &WindowsProfile) -> ThreadSymbols {
        ThreadSymbols::from_profile(profile).expect("a describable build")
    }

    // ── Layout resolution ───────────────────────────────────────────────────

    #[test]
    fn a_build_with_tcb_process_reaches_the_owner_through_the_embedded_kthread() {
        let profile = win10_profile(Image::new());
        let symbols = symbols_of(&profile);
        assert_eq!(
            symbols.owning_process,
            OwningProcessLink::TcbProcess("Tcb.Process".to_string())
        );
        assert!(
            !symbols.create_time_is_shifted,
            "only the ThreadsProcess builds shift the create time"
        );
    }

    #[test]
    fn a_build_with_threads_process_is_the_shifted_create_time_shape() {
        let profile = profile(
            Image::new().layer(),
            table(&xp_thread_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        );
        let symbols = symbols_of(&profile);
        assert_eq!(
            symbols.owning_process,
            OwningProcessLink::ThreadsProcess("ThreadsProcess".to_string())
        );
        assert!(symbols.create_time_is_shifted);
    }

    #[test]
    fn a_build_whose_ethread_names_no_owning_process_is_refused_by_name() {
        // The whole point of failing closed: a thread that cannot be attributed
        // to a process must not be emitted attributed to nobody, because a
        // cross-view would then read it as a process that no view found.
        let isf = xp_thread_isf().replace("\"ThreadsProcess\"", "\"SomethingElse\"");
        let profile = profile(
            Image::new().layer(),
            table(&isf),
            Architecture::X86,
            5,
            1,
            Some(2600),
        );
        let err = ThreadSymbols::from_profile(&profile).expect_err("no owning-process member");
        let message = err.to_string();
        assert!(message.contains("ThreadsProcess"), "{message}");
        assert!(message.contains("Tcb.Process"), "{message}");
        assert_eq!(err.class(), "unsupported_build");
    }

    #[test]
    fn a_symbol_table_without_an_ethread_is_refused_rather_than_returning_no_threads() {
        let isf = win10_thread_isf().replace("\"_ETHREAD\"", "\"_NOT_A_THREAD\"");
        let profile = profile(
            Image::new().layer(),
            table(&isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let err = ThreadSymbols::from_profile(&profile).expect_err("no _ETHREAD");
        assert!(err.to_string().contains("_ETHREAD"), "{err}");
    }

    // ── The thread list ─────────────────────────────────────────────────────

    #[test]
    fn a_process_thread_list_yields_every_thread_and_closes_on_the_head() {
        let profile = win10_profile(two_thread_image());
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect("a runnable walk");

        assert_eq!(list.forward_stop, ListStop::Wrapped);
        assert!(list.backward_stop.is_none());
        assert_eq!(list.threads.len(), 2);
        assert_eq!(list.links_offset, off::ETHREAD_LIST_ENTRY);
        assert_eq!(list.head, EPROCESS_AT + off::EPROCESS_THREAD_LIST_HEAD);
        let addresses: Vec<u64> = list.threads.iter().map(|t| t.address).collect();
        assert_eq!(addresses, vec![THREAD_A, THREAD_B]);
        assert!(list.is_complete());
        assert!(list.incomplete().is_empty());
    }

    #[test]
    fn the_container_offset_is_subtracted_so_a_link_becomes_the_thread_it_is_inside() {
        // `ThreadListEntry` is sixteen bytes into `_ETHREAD`. A walk that did
        // not subtract it would report threads at 0x3010 and 0x4010, and every
        // field of both would read from a plausible place inside the structure.
        let profile = win10_profile(two_thread_image());
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect("a runnable walk");
        assert_eq!(list.threads[0].address, THREAD_A);
        assert_eq!(list.threads[0].tid.known(), Some(&0x100));
        assert_eq!(list.threads[1].tid.known(), Some(&0x104));
    }

    #[test]
    fn a_thread_list_that_points_back_into_itself_stops_at_the_cycle() {
        let mut image = two_thread_image();
        // B now points at A's link rather than at the head, so the ring never
        // reaches the head again.
        image.put_u64(
            THREAD_B + off::ETHREAD_LIST_ENTRY,
            THREAD_A + off::ETHREAD_LIST_ENTRY,
        );
        let profile = win10_profile(image);
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect("a runnable walk");

        assert!(matches!(list.forward_stop, ListStop::Cycle { .. }));
        assert!(!list.is_complete(), "a cycle is not a complete list");
        assert!(
            list.incomplete()
                .iter()
                .any(|i| i.detail.contains("does not terminate")),
            "{:?}",
            list.incomplete()
        );
    }

    #[test]
    fn a_thread_list_capped_by_the_caller_says_so_rather_than_ending() {
        let profile = win10_profile(two_thread_image());
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig { max_threads: 1 },
        )
        .expect("a runnable walk");
        assert_eq!(list.threads.len(), 1);
        assert!(matches!(list.forward_stop, ListStop::CapReached { .. }));
        assert!(
            list.backward_stop.is_none(),
            "a cap is a bound the caller set, not a break in the chain"
        );
        assert!(!list.is_complete());
    }

    #[test]
    fn a_build_without_a_thread_list_entry_refuses_the_walk_naming_the_member() {
        let isf = win10_thread_isf().replace("\"ThreadListEntry\"", "\"NotTheLink\"");
        let profile = profile(
            two_thread_image().layer(),
            table(&isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = symbols_of(&profile);
        assert!(symbols.thread_list_entry.is_none());
        let err = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect_err("the link member is gone");
        assert!(err.to_string().contains(MEMBER_THREAD_LIST_ENTRY), "{err}");
    }

    #[test]
    fn a_build_without_a_thread_list_head_refuses_the_walk_naming_the_member() {
        let isf = win10_thread_isf().replace("\"ThreadListHead\"", "\"NoSuchHead\"");
        let profile = profile(
            two_thread_image().layer(),
            table(&isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = symbols_of(&profile);
        assert!(symbols.thread_list_head.is_none());
        let err = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect_err("the head member is gone");
        assert!(err.to_string().contains(MEMBER_THREAD_LIST_HEAD), "{err}");
    }

    // ── One thread's fields ─────────────────────────────────────────────────

    #[test]
    fn a_null_owning_process_is_unavailable_and_never_the_address_zero() {
        // A zero here would later be matched against an `_EPROCESS` at address
        // zero, which is how a cross-view invents a process nobody has.
        let mut image = two_thread_image();
        image.put_u64(THREAD_A + off::ETHREAD_TCB_PROCESS, 0);
        let profile = win10_profile(image);
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect("a runnable walk");
        let thread = &list.threads[0];
        assert!(thread.owning_process.is_unavailable());
        assert_eq!(thread.owning_process.known(), None);
        assert!(thread.unreadable_fields().contains(&"owning_process"));
    }

    #[test]
    fn a_running_thread_has_no_exit_time_rather_than_a_date_in_1601() {
        let profile = win10_profile(two_thread_image());
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect("a runnable walk");
        assert_eq!(list.threads[0].exit_time, ProcessTime::NotRecorded);
        assert_eq!(list.threads[0].is_terminated(), Some(false));
    }

    #[test]
    fn a_thread_with_an_exit_time_is_terminated() {
        let mut image = two_thread_image();
        image.put_u64(THREAD_A + off::ETHREAD_EXIT_TIME, CREATE_TIME + 1_000_000);
        let profile = win10_profile(image);
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect("a runnable walk");
        assert_eq!(list.threads[0].is_terminated(), Some(true));
        assert!(list.threads[0].exit_time.is_known());
    }

    #[test]
    fn the_terminated_state_marks_a_thread_terminated_even_with_no_exit_time() {
        let mut image = two_thread_image();
        image.put_u8(THREAD_A + off::ETHREAD_TCB_STATE, 4);
        let profile = win10_profile(image);
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect("a runnable walk");
        assert_eq!(
            list.threads[0].state.known(),
            Some(&THREAD_STATE_TERMINATED)
        );
        assert_eq!(list.threads[0].is_terminated(), Some(true));
    }

    #[test]
    fn a_client_id_that_is_not_a_multiple_of_four_is_noted_rather_than_accepted_silently() {
        let mut image = two_thread_image();
        image.put_u64(THREAD_A + off::ETHREAD_CID_THREAD, 0x101);
        let profile = win10_profile(image);
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect("a runnable walk");
        assert_eq!(list.threads[0].client_id_is_plausible(), Some(false));
        assert!(
            list.threads[0]
                .notes
                .iter()
                .any(|note| note.contains("multiple of four")),
            "{:?}",
            list.threads[0].notes
        );
    }

    #[test]
    fn the_xp_create_time_is_shifted_down_by_three_bits_before_it_is_a_date() {
        // Stored shifted left by three; read unshifted it becomes roughly eight
        // times the age, which lands centuries away and still renders as a
        // date.
        let mut image = Image::new();
        let head = EPROCESS_AT + 32;
        let link = THREAD_A + 8;
        image.put_u32(head, link as u32);
        image.put_u32(head + 4, link as u32);
        image.put_u32(THREAD_A, 0x100);
        image.put_u32(THREAD_A + 4, 0x200);
        image.put_u32(link, head as u32);
        image.put_u32(link + 4, head as u32);
        image.put_u64(THREAD_A + 16, CREATE_TIME << 3);
        image.put_u32(THREAD_A + 32, EPROCESS_AT as u32);

        let profile = profile(
            image.layer(),
            table(&xp_thread_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        );
        let symbols = symbols_of(&profile);
        let list = list_process_threads(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ThreadListConfig::default(),
        )
        .expect("a runnable walk");
        assert_eq!(list.threads.len(), 1);
        assert_eq!(list.threads[0].create_time.filetime(), Some(CREATE_TIME));
    }

    // ── thrdscan ────────────────────────────────────────────────────────────

    const POOL_THREAD: u64 = 0x8000;

    /// A Windows-8-shaped `Thre` allocation holding an `_ETHREAD`.
    fn put_pool_thread(image: &mut Image, pool: u64, tid: u64, pid: u64, owner: u64) -> u64 {
        image.put_u16(pool, 64); // BlockSize: 64 granules of 16 bytes
        image.put_u16(pool + 2, 2); // non-paged, Vista encoding
        image.write(pool + 4, b"Thre");
        let header = pool + 16;
        image.put_u32(header, 7); // PointerCount
        image.put_u8(header + 26, 0); // InfoMask: no optional headers
        let body = header + 48;
        image.put_u64(body + off::ETHREAD_CID_THREAD, tid);
        image.put_u64(body + off::ETHREAD_CID_PROCESS, pid);
        image.put_u64(body + off::ETHREAD_CREATE_TIME, CREATE_TIME);
        image.put_u64(body + off::ETHREAD_TCB_PROCESS, owner);
        body
    }

    #[test]
    fn a_pool_swept_thread_is_decoded_and_points_at_its_owning_process() {
        let mut image = Image::new();
        let body = put_pool_thread(&mut image, POOL_THREAD, 0x100, 0x200, EPROCESS_AT);
        let profile = win10_profile(image);
        let symbols = symbols_of(&profile);
        let pool = PoolSymbols::from_profile(&profile).expect("a describable build");
        let outcome = scan_threads(&profile, &symbols, &pool, &ThreadScanConfig::default())
            .expect("a runnable sweep");

        assert_eq!(outcome.threads.len(), 1, "{:?}", outcome.scan.rejected);
        let thread = &outcome.threads[0];
        assert_eq!(thread.address, body);
        assert_eq!(
            thread.origin,
            ThreadOrigin::PoolScan {
                space: ScanSpace::KernelVirtual
            }
        );
        assert_eq!(thread.tid.known(), Some(&0x100));
        assert_eq!(thread.owning_process.known(), Some(&EPROCESS_AT));
        assert_eq!(outcome.owning_processes(), vec![EPROCESS_AT]);
    }

    #[test]
    fn the_sweep_reports_the_space_it_ran_in_because_that_bounds_what_it_could_find() {
        let mut image = Image::new();
        put_pool_thread(&mut image, POOL_THREAD, 0x100, 0x200, EPROCESS_AT);
        let profile = win10_profile(image);
        let symbols = symbols_of(&profile);
        let pool = PoolSymbols::from_profile(&profile).expect("a describable build");
        let outcome = scan_threads(&profile, &symbols, &pool, &ThreadScanConfig::default())
            .expect("a runnable sweep");
        // Windows 10 sweeps the kernel's virtual space, so the addresses this
        // outcome carries are directly comparable with a list walk's.
        assert_eq!(outcome.space, ScanSpace::KernelVirtual);
        assert_eq!(outcome.to_json()["space"], "kernel_virtual");
    }

    #[test]
    fn a_thread_cap_is_reported_as_a_cap_and_not_as_the_end_of_the_image() {
        let mut image = Image::new();
        put_pool_thread(&mut image, POOL_THREAD, 0x100, 0x200, EPROCESS_AT);
        put_pool_thread(
            &mut image,
            POOL_THREAD + 64 * POOL_ALIGNMENT_64,
            0x104,
            0x200,
            EPROCESS_AT,
        );
        let profile = win10_profile(image);
        let symbols = symbols_of(&profile);
        let pool = PoolSymbols::from_profile(&profile).expect("a describable build");
        let outcome = scan_threads(
            &profile,
            &symbols,
            &pool,
            &ThreadScanConfig {
                max_threads: 1,
                ..ThreadScanConfig::default()
            },
        )
        .expect("a runnable sweep");
        assert_eq!(outcome.threads.len(), 1);
        assert!(outcome.truncated);
        assert!(!outcome.is_complete());
        assert!(outcome
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("cap")));
    }

    #[test]
    fn owning_processes_are_deduplicated_and_ordered_so_the_answer_does_not_depend_on_scan_order() {
        let mut image = Image::new();
        put_pool_thread(&mut image, POOL_THREAD, 0x100, 0x200, EPROCESS_AT);
        put_pool_thread(
            &mut image,
            POOL_THREAD + 64 * POOL_ALIGNMENT_64,
            0x104,
            0x200,
            EPROCESS_AT,
        );
        let profile = win10_profile(image);
        let symbols = symbols_of(&profile);
        let pool = PoolSymbols::from_profile(&profile).expect("a describable build");
        let outcome = scan_threads(&profile, &symbols, &pool, &ThreadScanConfig::default())
            .expect("a runnable sweep");
        assert_eq!(outcome.threads.len(), 2, "{:?}", outcome.scan.rejected);
        assert_eq!(outcome.owning_processes(), vec![EPROCESS_AT]);
    }
}
