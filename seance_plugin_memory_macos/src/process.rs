//! The process listings: `allproc` and the task queue.
//!
//! XNU keeps two lists of the same thing. `allproc` is the BSD side — a
//! null-terminated `LIST_HEAD` of `struct proc` — and `tasks` is the Mach side,
//! a circular queue of `struct task`, each of which points back at its `proc`
//! through `bsd_info`. A process normally appears on both. One that appears on
//! only one has been unlinked from the other, which is worth an examiner's
//! attention, so both are walked and both are reported.
//!
//! This module does **not** decide what a discrepancy means. It reports which
//! listing saw each process and lets an examiner read the table, because
//! "unlinked by a rootkit", "caught mid-`exit` during a non-atomic acquisition"
//! and "the walk stopped early" all produce the same shape, and the third is
//! reported separately by [`ProcessList::stop`].
//!
//! # Why every offset comes from the symbol pack
//!
//! `proc.p_pid` sits at offset 16 on Darwin 12 through 17 and at offset 96 on
//! Darwin 18 — one Apple release apart. `p_start` is at 1048, 1064, 960 and 928
//! across four packs in this repository. A hardcoded offset here would produce
//! a complete, confident, entirely wrong process list on every build but one,
//! and nothing downstream could tell. Every member is declared in
//! [`PROC_LAYOUT`] / [`TASK_LAYOUT`] and resolved through
//! [`seance_memory::binding`], so a build that spells one differently yields
//! [`Field::NotDeclared`] for that column and a complete list for the rest.
//!
//! All 117 sixty-four-bit Kernel Debug Kit packs in
//! `reference/volatility3/volatility3/symbols` declare every member named here.
//!
//! **Unvalidated.** See [`crate::unvalidated`]: this has never been run against
//! a real macOS capture. The walk is transcribed from Volatility 3's
//! `plugins/mac/pslist.py` and from the symbol packs.

use std::collections::{BTreeMap, HashSet};

use seance_core::io::IncompleteReason;
use seance_memory::binding::{
    BindError, BuildBinding, Field, MemberSet, MemberSpec, Necessity, TypeSpec,
};
use seance_memory::meta::Incomplete;
use seance_memory::object::{ListSpec, ListStop, Obj, ObjError, StructReader};
use serde_json::json;

use crate::fields::{int_field, pointer_field, required_path, text_field};
use crate::module::{STAGE_PROCESSES, STAGE_TASK_PROCESSES};
use crate::profile::MacProfile;

/// Ceiling on entries one listing will return.
///
/// Far above any real machine — a busy Mac runs a few hundred processes — so
/// reaching it means the chain is wrong, not that the machine was busy.
pub const DEFAULT_MAX_PROCESSES: usize = 65_536;

/// What the `allproc` walk needs from the symbol pack.
///
/// Only the four things without which there is no list at all are required. Any
/// column a build does not declare is [`Field::NotDeclared`] on the row — an
/// answer about the build, not a gap in the evidence — because a stage that
/// died on a missing `p_name` would cost the examiner the process list to save
/// them a duplicate of `p_comm`.
pub const PROC_LAYOUT: MemberSet = MemberSet::new(
    STAGE_PROCESSES,
    &[
        TypeSpec {
            key: "proc",
            candidates: &["proc"],
            necessity: Necessity::Required {
                without_it: "there is no process structure to read, so no process can be \
                             described at all",
            },
        },
        TypeSpec {
            key: "proclist",
            candidates: &["proclist"],
            necessity: Necessity::Required {
                without_it: "the head of the process list cannot be read, so the walk has no \
                             starting point",
            },
        },
    ],
    &[
        MemberSpec {
            key: "list_head",
            types: &["proclist"],
            members: &["lh_first"],
            necessity: Necessity::Required {
                without_it: "the first process on the list cannot be reached, so the list cannot \
                             be walked",
            },
        },
        MemberSpec {
            key: "next",
            types: &["proc"],
            members: &["p_list.le_next"],
            necessity: Necessity::Required {
                without_it: "the list cannot be followed past its first entry, and a one-entry \
                             process list would read as a machine running one process",
            },
        },
        MemberSpec::new("pid", &["proc"], &["p_pid"]),
        MemberSpec::new("ppid", &["proc"], &["p_ppid"]),
        MemberSpec::new("uid", &["proc"], &["p_uid"]),
        MemberSpec::new("gid", &["proc"], &["p_gid"]),
        MemberSpec::new("comm", &["proc"], &["p_comm"]),
        MemberSpec::new("name", &["proc"], &["p_name"]),
        MemberSpec::new("start_seconds", &["proc"], &["p_start.tv_sec"]),
        MemberSpec::new("start_microseconds", &["proc"], &["p_start.tv_usec"]),
        MemberSpec::new("state", &["proc"], &["p_stat"]),
        MemberSpec::new("task", &["proc"], &["task"]),
    ],
);

/// What the Mach task-queue walk needs.
pub const TASK_LAYOUT: MemberSet = MemberSet::new(
    STAGE_TASK_PROCESSES,
    &[
        TypeSpec {
            key: "task",
            candidates: &["task"],
            necessity: Necessity::Required {
                without_it: "there is no task structure, so the Mach-side listing cannot be \
                             walked at all",
            },
        },
        TypeSpec {
            key: "queue_entry",
            candidates: &["queue_entry"],
            necessity: Necessity::Required {
                without_it: "the task queue's links cannot be located, so the queue cannot be \
                             followed",
            },
        },
    ],
    &[MemberSpec {
        key: "bsd_info",
        types: &["task"],
        members: &["bsd_info"],
        necessity: Necessity::Required {
            without_it: "a task cannot be related to the BSD process it belongs to, so the \
                         listing could name no process",
        },
    }],
);

/// A stage in this module could not run.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// The symbol pack does not support this stage on this build.
    #[error(transparent)]
    Bind(#[from] BindError),
    /// A symbol the stage needs is absent.
    #[error(transparent)]
    Symbols(#[from] seance_symbols::SymbolError),
    /// A structure could not be read.
    #[error(transparent)]
    Object(#[from] ObjError),
    /// The stage refused for a reason of its own.
    #[error("{0}")]
    Refused(String),
}

/// Why a chain walk ended.
///
/// Only [`ChainStop::Terminated`] means the whole list was enumerated.
/// Everything else means the answer is partial, and the record must say so — a
/// process list that stopped after 40 of 400 is not a short answer, it is a
/// wrong one, and in a report it is indistinguishable from a machine running 40
/// processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStop {
    /// The chain reached its natural end: a null forward link on a
    /// `LIST_HEAD`, or a circular queue that came back to its head.
    Terminated,
    /// A forward link pointed somewhere the walk had already been.
    Cycle {
        /// The address arrived at twice.
        address: u64,
    },
    /// The entry cap fired. The walk stopped; the list did not.
    CapReached {
        /// The cap that fired.
        cap: usize,
    },
    /// The chain continues and this image cannot follow it.
    Unreadable {
        /// Where the walk stopped, when the stop names an address.
        ///
        /// `None` when it does not. A walk that ended in a symbol lookup or an
        /// arithmetic refusal has no address to give, and writing `0x0` in its
        /// place would put an address into the record that nothing was read
        /// from — a fabricated fact, and one an examiner would reasonably quote.
        at: Option<u64>,
        /// Why.
        detail: String,
        /// How the artifact should record it.
        reason: IncompleteReason,
    },
}

impl ChainStop {
    /// Whether the list was fully enumerated.
    pub fn is_complete(&self) -> bool {
        matches!(self, ChainStop::Terminated)
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainStop::Terminated => "terminated",
            ChainStop::Cycle { .. } => "cycle",
            ChainStop::CapReached { .. } => "cap_reached",
            ChainStop::Unreadable { .. } => "unreadable",
        }
    }

    /// What to stamp onto the artifact, or `None` when the list was complete.
    pub fn incomplete(&self) -> Option<Incomplete> {
        match self {
            ChainStop::Terminated => None,
            ChainStop::Cycle { address } => Some(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the process chain returned to {address:#x}, so it does not terminate and the \
                     entries past that point were not enumerated"
                ),
            )),
            ChainStop::CapReached { cap } => Some(Incomplete::new(
                IncompleteReason::CapReached,
                format!("the walk stopped at its cap of {cap} entries; the list continues"),
            )),
            ChainStop::Unreadable { at, detail, reason } => Some(Incomplete::new(
                *reason,
                match at {
                    Some(at) => format!(
                        "the chain continues past {at:#x} and could not be followed: {detail}"
                    ),
                    None => format!(
                        "the chain could not be followed to its end, and the stop names no \
                         address: {detail}"
                    ),
                },
            )),
        }
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = json!({"stop": self.as_str(), "complete": self.is_complete()});
        if let Some(incomplete) = self.incomplete() {
            value["reason"] = json!(incomplete.reason.as_str());
            value["detail"] = json!(incomplete.detail);
        }
        value
    }

    /// The equivalent stop for a [`ListStop`] from the shared list walker.
    fn from_list_stop(stop: &ListStop) -> Self {
        match stop {
            ListStop::Wrapped => ChainStop::Terminated,
            ListStop::Cycle { address } => ChainStop::Cycle { address: *address },
            ListStop::CapReached { cap } => ChainStop::CapReached { cap: *cap },
            other => {
                let incomplete = other.incomplete().unwrap_or_else(|| {
                    Incomplete::new(
                        IncompleteReason::UnresolvedStructure,
                        "the walk ended without recording a reason",
                    )
                });
                ChainStop::Unreadable {
                    // The address the stop itself names, and none invented when
                    // it names none: a null forward link and an unacquired hole
                    // both know where they were, and a symbol or arithmetic
                    // failure genuinely does not.
                    at: match other {
                        ListStop::NullLink { at } => Some(*at),
                        ListStop::Hole(hole) => Some(hole.address),
                        _ => None,
                    },
                    detail: incomplete.detail,
                    reason: incomplete.reason,
                }
            }
        }
    }
}

/// One process, as the kernel structures described it.
#[derive(Debug, Clone)]
pub struct MacProcess {
    /// Address of the `proc` structure in the kernel address space.
    pub address: u64,
    /// Process id.
    pub pid: Field<i64>,
    /// Parent process id.
    pub ppid: Field<i64>,
    /// Real user id.
    pub uid: Field<i64>,
    /// Real group id.
    pub gid: Field<i64>,
    /// `p_comm`, the truncated accounting name (17 bytes on every pack here).
    pub comm: Field<String>,
    /// `p_name`, the longer name (33 bytes on every pack here).
    pub name: Field<String>,
    /// Start time, whole seconds since the Unix epoch, exactly as the kernel
    /// held it. Not formatted here: a rendered timestamp implies a timezone and
    /// a calendar this module has no business choosing.
    pub start_seconds: Field<i64>,
    /// Start time, microseconds part.
    pub start_microseconds: Field<i64>,
    /// `p_stat`, the BSD process state, as the raw number. Not translated into
    /// a name: the enumeration is not in the symbol pack, so a name here would
    /// be this crate's opinion rather than the kernel's.
    pub state: Field<i64>,
    /// The Mach task this process belongs to.
    pub task: Field<u64>,
}

impl MacProcess {
    /// Serializable form for one row.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "proc_address": self.address,
            "proc_address_hex": format!("{:#x}", self.address),
            "pid": self.pid.to_json_with(|v| json!(v)),
            "ppid": self.ppid.to_json_with(|v| json!(v)),
            "uid": self.uid.to_json_with(|v| json!(v)),
            "gid": self.gid.to_json_with(|v| json!(v)),
            "comm": self.comm.to_json(),
            "name": self.name.to_json(),
            "start_time_unix_seconds": self.start_seconds.to_json_with(|v| json!(v)),
            "start_time_microseconds": self.start_microseconds.to_json_with(|v| json!(v)),
            "bsd_state": self.state.to_json_with(|v| json!(v)),
            "task_address": self.task.to_json_address(),
        })
    }

    /// The process id, when it was read. Used to relate the two listings.
    pub fn known_pid(&self) -> Option<i64> {
        self.pid.known().copied()
    }
}

/// One listing of the machine's processes.
#[derive(Debug, Clone)]
pub struct ProcessList {
    /// Which kernel structure was walked: `"allproc"` or `"tasks"`.
    pub source: &'static str,
    /// The processes reached, in walk order.
    pub processes: Vec<MacProcess>,
    /// Why the walk ended.
    pub stop: ChainStop,
    /// The kernel's own process counter (`nprocs`), when this build declares it.
    ///
    /// Reported as read and nothing more. Whether it counts exactly the entries
    /// on `allproc` has **not** been verified against a capture, so this crate
    /// does not compare the two and call a difference a hidden process. An
    /// examiner with a real image can make that comparison; a tool that made it
    /// on this evidence would be guessing in a report.
    pub kernel_process_count: Field<i64>,
}

impl ProcessList {
    /// Whether every entry on the list was enumerated.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete()
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "name": format!("macOS processes ({})", self.source),
            "listing_source": self.source,
            "process_count": self.processes.len(),
            "processes": self.processes.iter().map(MacProcess::to_json).collect::<Vec<_>>(),
            "walk": self.stop.to_json(),
            "kernel_process_count": self.kernel_process_count.to_json_with(|v| json!(v)),
            "incomplete": self
                .stop
                .incomplete()
                .map(|i| vec![i.to_json()])
                .unwrap_or_default(),
        })
    }
}

/// The symbol facts the `allproc` walk resolved for this build.
#[derive(Debug, Clone)]
pub struct ProcessSymbols {
    binding: BuildBinding,
    proc_type: &'static str,
    proclist_type: &'static str,
    proc_size: u64,
}

impl ProcessSymbols {
    /// Resolve [`PROC_LAYOUT`] against this image's kernel build.
    pub fn from_profile(profile: &MacProfile) -> Result<Self, ProcessError> {
        let reader = profile.reader();
        let binding = PROC_LAYOUT.bind(&reader)?;
        let proc = binding.type_of("proc")?;
        let proclist = binding.type_of("proclist")?;
        let proc_type = proc.type_name().ok_or_else(|| {
            ProcessError::Refused("this build declares no 'proc' structure".to_string())
        })?;
        let proclist_type = proclist.type_name().ok_or_else(|| {
            ProcessError::Refused("this build declares no 'proclist' structure".to_string())
        })?;
        let proc_size = proc.size().ok_or_else(|| {
            ProcessError::Refused(
                "this build declares a 'proc' structure with no size, so no entry can be \
                 bounds-checked before it is read"
                    .to_string(),
            )
        })?;
        Ok(Self {
            binding,
            proc_type,
            proclist_type,
            proc_size,
        })
    }

    /// How each declaration resolved on this build, for the record.
    pub fn to_json(&self) -> serde_json::Value {
        self.binding.to_json()
    }
}

/// Tuning for one walk.
#[derive(Debug, Clone, Copy)]
pub struct ProcessWalkConfig {
    /// Ceiling on entries.
    pub max_processes: usize,
}

impl Default for ProcessWalkConfig {
    fn default() -> Self {
        Self {
            max_processes: DEFAULT_MAX_PROCESSES,
        }
    }
}

/// Walk `allproc`, the BSD process list.
///
/// The chain is null-terminated rather than circular, so a null forward link is
/// the *normal* end and is reported as complete. Running it through the shared
/// circular-list walker would report every healthy macOS image as a truncated
/// list, which is the opposite error and just as misleading.
pub fn list_allproc(
    profile: &MacProfile,
    symbols: &ProcessSymbols,
    config: &ProcessWalkConfig,
) -> Result<ProcessList, ProcessError> {
    let reader = profile.reader();
    let head_address = profile.symbol("allproc")?;
    let head = reader.object(head_address, symbols.proclist_type)?;

    let head_path = required_path(
        &symbols.binding,
        "list_head",
        "the first process on the list cannot be reached and the list cannot be walked",
    )
    .map_err(ProcessError::Refused)?;
    let next_path = required_path(
        &symbols.binding,
        "next",
        "the list cannot be followed past its first entry, and a one-entry answer would read as \
         a machine running one process",
    )
    .map_err(ProcessError::Refused)?;

    let mut current = head.pointer(head_path)?;
    let mut processes = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();

    let stop = loop {
        if current == 0 {
            break ChainStop::Terminated;
        }
        if processes.len() >= config.max_processes {
            break ChainStop::CapReached {
                cap: config.max_processes,
            };
        }
        if !visited.insert(current) {
            break ChainStop::Cycle { address: current };
        }
        if !profile.kernel_space.is_valid(current, symbols.proc_size) {
            break ChainStop::Unreadable {
                at: Some(current),
                detail: format!(
                    "the {} byte(s) of the process structure at {current:#x} were not acquired",
                    symbols.proc_size
                ),
                reason: IncompleteReason::ShortRead,
            };
        }

        let object = match reader.object(current, symbols.proc_type) {
            Ok(object) => object,
            Err(err) => {
                break ChainStop::Unreadable {
                    at: Some(current),
                    detail: err.to_string(),
                    reason: IncompleteReason::UnresolvedStructure,
                }
            }
        };
        processes.push(read_process(&symbols.binding, &object, current));

        current = match object.pointer(next_path) {
            Ok(next) => next,
            Err(err) => {
                break ChainStop::Unreadable {
                    at: Some(current),
                    detail: err.to_string(),
                    reason: IncompleteReason::UnresolvedStructure,
                }
            }
        };
    };

    Ok(ProcessList {
        source: "allproc",
        processes,
        stop,
        kernel_process_count: kernel_process_count(profile, &reader),
    })
}

/// The symbol facts the task-queue walk resolved for this build.
#[derive(Debug, Clone)]
pub struct TaskSymbols {
    binding: BuildBinding,
    task_type: &'static str,
    queue_type: &'static str,
}

impl TaskSymbols {
    /// Resolve [`TASK_LAYOUT`] against this image's kernel build.
    pub fn from_profile(profile: &MacProfile) -> Result<Self, ProcessError> {
        let reader = profile.reader();
        let binding = TASK_LAYOUT.bind(&reader)?;
        let task_type = binding.type_of("task")?.type_name().ok_or_else(|| {
            ProcessError::Refused("this build declares no 'task' structure".to_string())
        })?;
        let queue_type = binding.type_of("queue_entry")?.type_name().ok_or_else(|| {
            ProcessError::Refused("this build declares no 'queue_entry' structure".to_string())
        })?;
        Ok(Self {
            binding,
            task_type,
            queue_type,
        })
    }

    /// How each declaration resolved on this build.
    pub fn to_json(&self) -> serde_json::Value {
        self.binding.to_json()
    }
}

/// Walk the Mach task queue and report the BSD process behind each task.
///
/// The queue is circular, so the shared walker's `Wrapped` ending is the correct
/// notion of complete here and is used directly.
pub fn list_tasks(
    profile: &MacProfile,
    task_symbols: &TaskSymbols,
    proc_symbols: &ProcessSymbols,
    config: &ProcessWalkConfig,
) -> Result<ProcessList, ProcessError> {
    let reader = profile.reader();
    let head_address = profile.symbol("tasks")?;

    let bsd_path = required_path(
        &task_symbols.binding,
        "bsd_info",
        "a task cannot be related to the BSD process it belongs to, so this listing could name \
         no process",
    )
    .map_err(ProcessError::Refused)?;

    let spec = ListSpec::new(task_symbols.queue_type, "next")
        .in_container(task_symbols.task_type, "tasks")
        .with_max_entries(config.max_processes);
    let walk = reader.walk_list(head_address, &spec)?;
    let (tasks, list_stop) = walk.walk_to_end();

    let mut processes = Vec::new();
    let mut stop = ChainStop::from_list_stop(&list_stop);
    // One unreadable task must not cost the rest of the queue, but it must not
    // vanish either. Both halves are kept: how many entries the queue held that
    // could not be resolved to a process, and the first of them. Reporting only
    // the last — which is what overwriting `stop` in the loop did — turned
    // fifty unresolved tasks into one sentence about the fiftieth, and threw
    // away the queue walk's own verdict (a cap, a cycle) on the way past.
    let mut unresolved = 0usize;
    let mut first_unresolved: Option<(u64, String)> = None;
    let mut note_unresolved = |at: u64, detail: String| {
        unresolved += 1;
        if first_unresolved.is_none() {
            first_unresolved = Some((at, detail));
        }
    };

    for task in &tasks {
        let proc_address = match task.pointer(bsd_path) {
            Ok(address) => address,
            Err(err) => {
                note_unresolved(
                    task.address(),
                    format!(
                        "the BSD process pointer of the task at {:#x} could not be read: {err}",
                        task.address()
                    ),
                );
                continue;
            }
        };
        if proc_address == 0 {
            // A task with no BSD process. Real — the kernel task itself is one
            // — and not an error, so it is skipped without marking the walk
            // short.
            continue;
        }
        match reader.object(proc_address, proc_symbols.proc_type) {
            Ok(object) => {
                processes.push(read_process(&proc_symbols.binding, &object, proc_address))
            }
            Err(err) => note_unresolved(
                proc_address,
                format!("the process at {proc_address:#x} could not be read: {err}"),
            ),
        }
    }

    // Only when the queue walk itself ran to its end: a cap or a cycle already
    // says the count is a floor, and is the more important of the two facts
    // because it bounds the whole listing rather than some of its entries.
    if let (true, Some((at, detail))) = (stop.is_complete(), first_unresolved) {
        stop = ChainStop::Unreadable {
            at: Some(at),
            detail: format!(
                "{unresolved} task(s) on the queue could not be resolved to a process, so this \
                 listing is short by at least that many; the first: {detail}"
            ),
            reason: IncompleteReason::UnresolvedStructure,
        };
    }

    Ok(ProcessList {
        source: "tasks",
        processes,
        stop,
        kernel_process_count: kernel_process_count(profile, &reader),
    })
}

/// Which listing saw each process.
///
/// Pure set arithmetic over the two lists: no macOS-specific judgement is made
/// here, and none should be read into it. A process on one listing and not the
/// other has been unlinked from one of them — by a rootkit, by an acquisition
/// that caught the machine mid-`exit`, or because one of the walks stopped
/// early. The third possibility is why [`CrossView::both_listings_complete`]
/// exists: a difference computed from a truncated listing is not evidence of
/// anything.
#[derive(Debug, Clone)]
pub struct CrossView {
    /// One row per process id seen by either listing.
    pub rows: Vec<CrossViewRow>,
    /// Whether both walks ran to their natural end. When this is false the
    /// discrepancies below are not findings.
    pub both_listings_complete: bool,
    /// Processes on neither listing carrying a readable pid. Counted because a
    /// row with no pid cannot be related across listings and would otherwise
    /// silently disappear from this table.
    pub unrelatable_entries: usize,
}

/// One process id, and which listing held it.
#[derive(Debug, Clone)]
pub struct CrossViewRow {
    /// The process id.
    pub pid: i64,
    /// The best name either listing carried, when one of them did.
    pub name: Option<String>,
    /// Seen on the BSD `allproc` list.
    pub on_allproc: bool,
    /// Seen on the Mach task queue.
    pub on_tasks: bool,
}

impl CrossView {
    /// Whether every process id was on both listings.
    pub fn agrees(&self) -> bool {
        self.rows.iter().all(|row| row.on_allproc && row.on_tasks)
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        // Computed before the macro rather than inside it: a comparison built
        // on a listing that stopped early is not a finding, and this array is
        // what says so.
        let mut incomplete: Vec<serde_json::Value> = Vec::new();
        if !self.both_listings_complete {
            incomplete.push(
                Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    "at least one of the two listings did not run to its end, so a process \
                     missing from one of them here is not evidence that it was hidden",
                )
                .to_json(),
            );
        }
        let rows: Vec<serde_json::Value> = self
            .rows
            .iter()
            .map(|row| {
                json!({
                    "pid": row.pid,
                    "name": row.name,
                    "on_allproc": row.on_allproc,
                    "on_tasks": row.on_tasks,
                })
            })
            .collect();

        json!({
            "name": "macOS process cross-view",
            "row_count": self.rows.len(),
            "listings_agree": self.agrees(),
            "both_listings_complete": self.both_listings_complete,
            "unrelatable_entries": self.unrelatable_entries,
            "rows": rows,
            "incomplete": incomplete,
        })
    }
}

/// Build the cross-view from the two listings.
pub fn cross_view(allproc: &ProcessList, tasks: &ProcessList) -> CrossView {
    let mut rows: BTreeMap<i64, CrossViewRow> = BTreeMap::new();
    let mut unrelatable = 0usize;

    let mut absorb = |list: &ProcessList, on_allproc: bool| {
        for process in &list.processes {
            let Some(pid) = process.known_pid() else {
                unrelatable += 1;
                continue;
            };
            // Swept 2026-07-31: this is the only `known()`-then-fallback chain
            // in any tier, so the defect below was confined to this one site.
            //
            // A field that was read and is EMPTY is still `known`, so preferring
            // `p_name` outright let an empty one shadow a populated `p_comm`.
            // xnu keeps them adjacent -- `p_comm` is a 17-byte short name the
            // kernel always sets, `p_name` a 33-byte buffer it frequently does
            // not -- so on a real Mac most rows would have carried a blank name
            // while the name sat one field away. Prefer the longer name only
            // when it actually says something.
            let name = process
                .name
                .known()
                .filter(|text| !text.trim().is_empty())
                .or_else(|| process.comm.known().filter(|text| !text.trim().is_empty()))
                .cloned();
            let row = rows.entry(pid).or_insert(CrossViewRow {
                pid,
                name: None,
                on_allproc: false,
                on_tasks: false,
            });
            if row.name.is_none() {
                row.name = name;
            }
            if on_allproc {
                row.on_allproc = true;
            } else {
                row.on_tasks = true;
            }
        }
    };
    absorb(allproc, true);
    absorb(tasks, false);

    CrossView {
        rows: rows.into_values().collect(),
        both_listings_complete: allproc.is_complete() && tasks.is_complete(),
        unrelatable_entries: unrelatable,
    }
}

/// Read every declared column of one `proc`.
fn read_process(binding: &BuildBinding, object: &Obj, address: u64) -> MacProcess {
    MacProcess {
        address,
        pid: int_field(binding, object, "pid"),
        ppid: int_field(binding, object, "ppid"),
        uid: int_field(binding, object, "uid"),
        gid: int_field(binding, object, "gid"),
        comm: text_field(binding, object, "comm"),
        name: text_field(binding, object, "name"),
        start_seconds: int_field(binding, object, "start_seconds"),
        start_microseconds: int_field(binding, object, "start_microseconds"),
        state: int_field(binding, object, "state"),
        task: pointer_field(binding, object, "task"),
    }
}

/// The kernel's own process counter, when this build has one.
fn kernel_process_count(profile: &MacProfile, reader: &StructReader) -> Field<i64> {
    const SYMBOL: &str = "nprocs";
    if !profile.has_symbol(SYMBOL) {
        return Field::NotDeclared { member: SYMBOL };
    }
    let address = match profile.symbol(SYMBOL) {
        Ok(address) => address,
        Err(err) => return Field::Unavailable(err.to_string()),
    };
    // `nprocs` is a plain `int`, so it is read as four little-endian bytes
    // rather than through a structure. A short read is refused: three bytes of
    // a count and one byte of nothing is a number.
    let mut buffer = [0u8; 4];
    match reader.read_into(address, &mut buffer) {
        Ok(()) => Field::Known(i64::from(i32::from_le_bytes(buffer))),
        Err(err) => Field::Unavailable(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: Option<i64>, name: &str) -> MacProcess {
        MacProcess {
            address: 0xffff_ff80_1234_0000,
            pid: match pid {
                Some(value) => Field::Known(value),
                None => Field::Unavailable("the pid could not be read".into()),
            },
            ppid: Field::Known(1),
            uid: Field::Known(501),
            gid: Field::Known(20),
            comm: Field::Known(name.to_string()),
            name: Field::Known(name.to_string()),
            start_seconds: Field::Known(1_561_060_941),
            start_microseconds: Field::Known(0),
            state: Field::Known(2),
            task: Field::Known(0xffff_ff80_5678_0000),
        }
    }

    fn listing(source: &'static str, processes: Vec<MacProcess>, stop: ChainStop) -> ProcessList {
        ProcessList {
            source,
            processes,
            stop,
            kernel_process_count: Field::NotDeclared { member: "nprocs" },
        }
    }

    #[test]
    fn a_null_forward_link_ends_the_bsd_list_completely() {
        // XNU's allproc is a null-terminated LIST_HEAD, not a circular list.
        // Reporting its natural end as truncation would mark every healthy
        // macOS image incomplete, and an examiner who sees "incomplete" on
        // every image stops reading the flag.
        assert!(ChainStop::Terminated.is_complete());
        assert!(ChainStop::Terminated.incomplete().is_none());
    }

    #[test]
    fn a_capped_walk_is_never_reported_as_a_short_machine() {
        let stop = ChainStop::CapReached { cap: 64 };
        assert!(!stop.is_complete());
        let incomplete = stop.incomplete().expect("a capped walk is incomplete");
        assert_eq!(incomplete.reason, IncompleteReason::CapReached);
        assert!(incomplete.detail.contains("the list continues"));
    }

    #[test]
    fn a_cycle_is_reported_with_the_address_it_returned_to() {
        let stop = ChainStop::Cycle {
            address: 0xffff_ff80_0011_2233,
        };
        let incomplete = stop.incomplete().expect("a cycle is incomplete");
        assert!(
            incomplete.detail.contains("0xffffff8000112233"),
            "{incomplete:?}"
        );
        assert_eq!(stop.as_str(), "cycle");
    }

    #[test]
    fn the_shared_walkers_wrapped_ending_is_complete_and_its_null_link_is_not() {
        // The task queue IS circular, so `Wrapped` is its natural end.
        assert!(ChainStop::from_list_stop(&ListStop::Wrapped).is_complete());
        assert!(!ChainStop::from_list_stop(&ListStop::NullLink { at: 0x10 }).is_complete());
    }

    #[test]
    fn a_stop_reports_the_address_it_was_given_and_never_invents_one() {
        // The address in this sentence is one an examiner will quote. A stop
        // that knows where it happened must say so, and a stop that does not
        // must not fill the gap with 0x0 — which reads as "the walk stopped at
        // physical zero" and is a statement about the evidence that nothing
        // established.
        let known = ChainStop::from_list_stop(&ListStop::NullLink {
            at: 0xffff_ff80_0044_5566,
        });
        let detail = known
            .incomplete()
            .expect("a null link is incomplete")
            .detail;
        assert!(detail.contains("0xffffff8000445566"), "{detail}");

        let unknown = ChainStop::from_list_stop(&ListStop::Failed {
            detail: "the symbol table could not answer for 'tasks'".to_string(),
            reason: IncompleteReason::UnresolvedStructure,
        });
        let detail = unknown
            .incomplete()
            .expect("a failure is incomplete")
            .detail;
        assert!(!detail.contains("0x0"), "an address was invented: {detail}");
        assert!(detail.contains("names no address"), "{detail}");
    }

    #[test]
    fn the_cross_view_marks_a_process_missing_from_one_listing() {
        let allproc = listing(
            "allproc",
            vec![process(Some(1), "launchd"), process(Some(42), "hidden")],
            ChainStop::Terminated,
        );
        let tasks = listing(
            "tasks",
            vec![process(Some(1), "launchd")],
            ChainStop::Terminated,
        );
        let view = cross_view(&allproc, &tasks);

        assert_eq!(view.rows.len(), 2);
        assert!(!view.agrees());
        assert!(view.both_listings_complete);
        let hidden = view.rows.iter().find(|r| r.pid == 42).expect("pid 42");
        assert!(hidden.on_allproc);
        assert!(!hidden.on_tasks);
    }

    #[test]
    fn a_difference_computed_from_a_truncated_listing_is_marked_as_not_a_finding() {
        // This is the whole reason the flag exists. A process absent from a
        // walk that stopped early has not been shown to be absent from the
        // machine, and a cross-view that did not say so would manufacture a
        // hidden-process finding out of a cap.
        let allproc = listing(
            "allproc",
            vec![process(Some(1), "launchd"), process(Some(42), "second")],
            ChainStop::CapReached { cap: 2 },
        );
        let tasks = listing(
            "tasks",
            vec![process(Some(1), "launchd")],
            ChainStop::Terminated,
        );
        let view = cross_view(&allproc, &tasks);
        assert!(!view.both_listings_complete);
        let json = view.to_json();
        assert_eq!(json["both_listings_complete"], json!(false));
        assert!(!json["incomplete"].as_array().expect("an array").is_empty());
    }

    #[test]
    fn a_row_with_no_readable_pid_is_counted_rather_than_dropped() {
        // Silently dropping it would shrink the table and make two listings
        // agree that do not.
        let allproc = listing(
            "allproc",
            vec![process(None, "unreadable"), process(Some(1), "launchd")],
            ChainStop::Terminated,
        );
        let tasks = listing(
            "tasks",
            vec![process(Some(1), "launchd")],
            ChainStop::Terminated,
        );
        let view = cross_view(&allproc, &tasks);
        assert_eq!(view.unrelatable_entries, 1);
        assert_eq!(view.rows.len(), 1);
        assert_eq!(view.to_json()["unrelatable_entries"], json!(1));
    }

    #[test]
    fn a_listing_serialises_its_walk_verdict_beside_its_count() {
        // A count without the verdict is the number that ends up in a report.
        let list = listing(
            "allproc",
            vec![process(Some(1), "launchd")],
            ChainStop::CapReached { cap: 1 },
        );
        let json = list.to_json();
        assert_eq!(json["process_count"], json!(1));
        assert_eq!(json["walk"]["complete"], json!(false));
        assert_eq!(json["walk"]["reason"], json!("cap_reached"));
        assert!(!json["incomplete"].as_array().expect("an array").is_empty());
    }

    #[test]
    fn the_declarations_name_a_stage_and_justify_every_required_member() {
        // A required member with no justification prints nothing an examiner
        // can act on when it fires.
        for set in [PROC_LAYOUT, TASK_LAYOUT] {
            assert!(!set.stage.key.is_empty());
            for spec in set.members {
                if let Necessity::Required { without_it } = spec.necessity {
                    assert!(
                        without_it.len() > 30,
                        "{} is required with no useful justification",
                        spec.key
                    );
                }
            }
            for spec in set.types {
                if let Necessity::Required { without_it } = spec.necessity {
                    assert!(
                        without_it.len() > 30,
                        "{} is required with no useful justification",
                        spec.key
                    );
                }
            }
        }
    }
}
