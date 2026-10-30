//! The process list, walked from `init_task` through `task_struct.tasks`.
//!
//! Everything else in this crate hangs off this list, so the thing it must get
//! right is not the walk — [`seance_memory::object::ListWalk`] already makes
//! that cycle-safe, capped and honest about unacquired links — but the *verdict*
//! it publishes beside the count.
//!
//! > A walk that stopped early says nothing about what it did not reach, and a
//! > short process list looks exactly like a quiet machine.
//!
//! That is why [`TaskList::is_complete`] is the conjunction of the walk's own
//! ending and every row's readability, why [`TaskList::incomplete`] names each
//! reason in the examiner's terms, and why [`TaskInventory`] travels onto every
//! later stage that was handed this list. A bash-history stage that examined
//! every process it was given would otherwise report itself complete over a list
//! that never reached the shell doing the work.
//!
//! ## What varies by build here, and what does not
//!
//! - `task_struct.state` became `__state` in Linux 5.14. A member difference.
//! - `cred.uid` is a bare `unsigned int` on Linux 3.2 and a `kuid_t` wrapping
//!   one from 3.5, so the value is at `uid` on one build and `uid.val` on the
//!   other. A member-**path** difference, which is why the candidate list holds
//!   paths rather than names.
//! - `task_struct.start_time` is a `timespec` on Linux 3.2 and a `u64` of
//!   nanoseconds from 4.11. The *unit* changes with the candidate that resolved,
//!   so the row records which one did rather than publishing a number whose
//!   meaning the reader has to guess.
//!
//! None of those is an error on any build. Every one of them is
//! [`Field::NotDeclared`] on the builds that do not have it, which is an answer.

// The assertions in this module's tests relate compile-time bounds to each
// other, so that changing one in isolation fails the build. Clippy sees both
// sides are const and calls them pointless; that relationship is their point.
#![allow(clippy::assertions_on_constants)]

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, MemberUse, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::{ListSpec, ListStop, Obj, StructReader};

use crate::capabilities;
use crate::error::{name_list, StageError};
use crate::module::STAGE_LINUX_PROCESSES;
use crate::profile::LinuxProfile;
use crate::read::{read_cap_mask, read_char_array, read_integer, read_signed, signed_to_json};

/// The symbol the process list starts at.
///
/// A single name rather than an ordered list because every Linux kernel that has
/// ever existed calls it this: `init_task` is the statically allocated
/// `task_struct` of the idle thread, and the circular `tasks` list threads
/// through it.
pub const INIT_TASK_SYMBOLS: [&str; 1] = ["init_task"];

/// `PF_KTHREAD` — the `task_struct.flags` bit the kernel sets on a thread with
/// no user address space.
///
/// A constant of the kernel's own ABI rather than a layout fact, which is why it
/// is not in the [`MemberSet`]: the *offset* of `flags` varies by build and is
/// declared; the meaning of bit 21 inside it has not changed since 2.6.
pub const PF_KTHREAD: i64 = 0x0020_0000;

/// Ceiling on processes one walk will report.
///
/// Far above any real machine — a busy Linux server runs a few thousand tasks —
/// so reaching it means the link chain is wrong, not that the machine was busy.
/// Reaching it is recorded as [`ListStop::CapReached`], never as the end of the
/// list.
pub const MAX_TASKS: usize = 65_536;

/// Everything the process-list stage needs out of the symbol table.
///
/// Declared in one place and resolved once. Nothing between this declaration and
/// the walk can turn a build-variant member into a stage failure, because the
/// only route to a failure is a `required` declaration carrying a written
/// statement of what is lost.
pub const TASK_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_PROCESSES,
    &[
        TypeSpec::new("task", &["task_struct"]).required(
            "no process structure can be located at all, so nothing can be said about what this \
             machine was running",
        ),
        TypeSpec::new("list_link", &["list_head"]).required(
            "the kernel's list links cannot be sized, so no process could be reached from \
             init_task",
        ),
    ],
    &[
        MemberSpec::new("tasks", &["task_struct"], &["tasks"]).required(
            "the process list has no links to follow, so no process beyond init_task could be \
             reached and the listing would be a single row that reads like an idle machine",
        ),
        MemberSpec::new("list_next", &["list_head"], &["next"]).required(
            "a list link has no forward pointer, so the process list cannot be walked at all",
        ),
        // Linux 3.2 spells the thread id `pid` and the process id `tgid`; that
        // has not changed, but both are declared so a build that drops one is
        // answered rather than failed.
        MemberSpec::new("pid", &["task_struct"], &["pid"]),
        MemberSpec::new("tgid", &["task_struct"], &["tgid"]),
        MemberSpec::new("comm", &["task_struct"], &["comm"]),
        // `state` became `__state` in Linux 5.14.
        MemberSpec::new("state", &["task_struct"], &["state", "__state"]),
        MemberSpec::new("exit_state", &["task_struct"], &["exit_state"]),
        MemberSpec::new("flags", &["task_struct"], &["flags"]),
        MemberSpec::new("mm", &["task_struct"], &["mm"]),
        // `real_parent` is the process that forked this one; `parent` is who
        // gets the exit signal, and they differ under ptrace. Preferring
        // `real_parent` matches what an examiner means by "parent".
        MemberSpec::new("real_parent", &["task_struct"], &["real_parent", "parent"]),
        MemberSpec::new("cred", &["task_struct"], &["cred", "real_cred"]),
        // A `timespec` of seconds on Linux 3.2, a `u64` of nanoseconds from
        // 4.11. Which one resolved decides the unit, and the unit is published.
        MemberSpec::new(
            "start_time",
            &["task_struct"],
            &["start_time.tv_sec", "start_time"],
        ),
        // `kuid_t` wraps the value in a `val` member from Linux 3.5; before
        // that the id is the member itself. Both spellings, most recent first,
        // because the wrapped form must not be read as an aggregate.
        MemberSpec::new("uid", &["cred"], &["uid.val", "uid"]),
        MemberSpec::new("gid", &["cred"], &["gid.val", "gid"]),
        MemberSpec::new("euid", &["cred"], &["euid.val", "euid"]),
        MemberSpec::new("egid", &["cred"], &["egid.val", "egid"]),
        // Capability sets (each a `kernel_cap_t`, read as an 8-byte LE mask).
        // `cap_ambient` did not exist before Linux 4.3, so its absence is
        // NotDeclared, not damage — the binding produces that from the missing
        // candidate. The bounding set is spelled `cap_bset` in the kernel.
        MemberSpec::new("cap_effective", &["cred"], &["cap_effective"]),
        MemberSpec::new("cap_permitted", &["cred"], &["cap_permitted"]),
        MemberSpec::new("cap_inheritable", &["cred"], &["cap_inheritable"]),
        MemberSpec::new("cap_bounding", &["cred"], &["cap_bset"]),
        MemberSpec::new("cap_ambient", &["cred"], &["cap_ambient"]),
    ],
);

/// Caps for one process-list walk.
#[derive(Debug, Clone)]
pub struct TaskListConfig {
    /// Ceiling on processes reported.
    pub max_tasks: usize,
}

impl Default for TaskListConfig {
    fn default() -> Self {
        Self {
            max_tasks: MAX_TASKS,
        }
    }
}

/// A process's five capability sets, each an 8-byte mask (or an absence).
///
/// `ambient` is [`Field::NotDeclared`] on kernels older than Linux 4.3, which is
/// an answer — "this kernel had no ambient set" — not a gap.
#[derive(Debug, Clone)]
pub struct CapabilityFields {
    pub effective: Field<u64>,
    pub permitted: Field<u64>,
    pub inheritable: Field<u64>,
    pub bounding: Field<u64>,
    pub ambient: Field<u64>,
}

impl CapabilityFields {
    fn all_unavailable(detail: &str) -> Self {
        let u = || Field::Unavailable(detail.to_string());
        Self {
            effective: u(),
            permitted: u(),
            inheritable: u(),
            bounding: u(),
            ambient: u(),
        }
    }

    /// The names of the capability sets that exist on this build and could not
    /// be read.
    ///
    /// Distinct from a set this build never had: `ambient` on a kernel older
    /// than 4.3 is [`Field::NotDeclared`] — an answer, not a gap — and is not
    /// listed here. Only [`Field::Unavailable`] sets are, because those are the
    /// ones whose bytes should have read and did not. The capabilities stage
    /// counts these against its own completeness, since [`TaskList::is_complete`]
    /// does not look at capability fields.
    pub fn unreadable(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (name, field) in [
            ("cap_effective", &self.effective),
            ("cap_permitted", &self.permitted),
            ("cap_inheritable", &self.inheritable),
            ("cap_bounding", &self.bounding),
            ("cap_ambient", &self.ambient),
        ] {
            if field.is_unavailable() {
                out.push(name);
            }
        }
        out
    }

    /// One capability set as `{ mask_hex, capabilities: [names] }`, or the
    /// absence reason. Named so an examiner reads `CAP_SYS_ADMIN`, not `0x...`.
    fn mask_to_json(m: &Field<u64>) -> serde_json::Value {
        match m {
            Field::Known(mask) => serde_json::json!({
                "mask_hex": format!("{mask:#x}"),
                "capabilities": capabilities::decode(*mask),
            }),
            Field::NotDeclared { member } => {
                serde_json::json!({ "not_declared": member })
            }
            Field::NotApplicable => serde_json::json!({ "not_applicable": true }),
            Field::Unavailable(detail) => serde_json::json!({ "unavailable": detail }),
        }
    }

    /// Serializable form: each of the five sets as `{ mask_hex, capabilities }`
    /// or its absence reason. Public so the dedicated capabilities stage renders
    /// each process's sets identically to how the task list already does, rather
    /// than growing a second wire shape the frontend would have to decode.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "effective": Self::mask_to_json(&self.effective),
            "permitted": Self::mask_to_json(&self.permitted),
            "inheritable": Self::mask_to_json(&self.inheritable),
            "bounding": Self::mask_to_json(&self.bounding),
            "ambient": Self::mask_to_json(&self.ambient),
        })
    }
}

/// One process, as the kernel's task list describes it.
#[derive(Debug, Clone)]
pub struct TaskRecord {
    /// Address of the `task_struct` in the kernel address space.
    ///
    /// The handle every later stage takes. It is a fact even when every field
    /// below is [`Field::Unavailable`], because the list linked to it.
    pub address: u64,
    /// `task_struct.pid` — the *thread* id in POSIX terms.
    pub tid: Field<i64>,
    /// `task_struct.tgid` — the *process* id in POSIX terms, which is what
    /// `ps` prints and what an examiner means by "PID".
    pub pid: Field<i64>,
    /// The `tgid` of `real_parent`. [`Field::NotApplicable`] when the parent
    /// pointer is null, which is what `init_task` itself has.
    pub ppid: Field<i64>,
    /// `task_struct.comm`, truncated at its first NUL.
    pub comm: Field<String>,
    /// Whether every byte of `comm` before its NUL was valid UTF-8.
    ///
    /// A process name is one of the few fields an attacker chooses, so a name
    /// that had to be repaired to render is worth saying so about.
    pub comm_well_formed: bool,
    /// The scheduler state word, as the kernel held it. Not decoded into a
    /// label: the bit meanings changed across the 4.x series and a wrong label
    /// is worse than a number.
    pub state: Field<i64>,
    /// `task_struct.exit_state`. Non-zero means the task had exited and had not
    /// yet been reaped.
    pub exit_state: Field<i64>,
    /// `task_struct.flags`.
    pub flags: Field<i64>,
    /// Whether `PF_KTHREAD` is set. [`Field::NotDeclared`] when this build
    /// declares no `flags` member, which is not the same as "not a kernel
    /// thread".
    pub kernel_thread: Field<bool>,
    /// The `mm_struct` pointer. Zero means no user address space, which is what
    /// a kernel thread has, and is what stops the environment and bash stages
    /// from looking for user memory that was never there.
    pub mm: Field<u64>,
    /// Real user id.
    pub uid: Field<i64>,
    /// Real group id.
    pub gid: Field<i64>,
    /// Effective user id.
    pub euid: Field<i64>,
    /// Effective group id.
    pub egid: Field<i64>,
    /// The raw start-time value, in whatever unit this build stores it.
    ///
    /// Deliberately **not** a wall-clock timestamp. Linux stores this as an
    /// offset from boot, and turning it into a date needs the boot wall-clock
    /// time, which this stage does not establish. Publishing a date here without
    /// that would put a time in the case record that the machine never recorded.
    pub start_time: Field<i64>,
    /// The unit `start_time` is in, decided by which candidate this build
    /// declared. `None` when the member was not declared at all.
    pub start_time_unit: Option<&'static str>,
    /// The process's capability sets, from `cred.cap_*`.
    pub capabilities: CapabilityFields,
    /// Anything odd about the row that did not disqualify it.
    pub notes: Vec<String>,
}

impl TaskRecord {
    /// A row carrying only an address, for tests that correlate on address.
    ///
    /// The cross-view keys on the structure's address and reads no other field,
    /// so a test of it should not have to invent thirteen plausible ones.
    #[cfg(test)]
    pub(crate) fn address_only_for_test(address: u64) -> Self {
        Self {
            address,
            tid: Field::Unavailable("not read".into()),
            pid: Field::Unavailable("not read".into()),
            ppid: Field::Unavailable("not read".into()),
            comm: Field::Unavailable("not read".into()),
            comm_well_formed: true,
            state: Field::Unavailable("not read".into()),
            exit_state: Field::Unavailable("not read".into()),
            flags: Field::Unavailable("not read".into()),
            kernel_thread: Field::Unavailable("not read".into()),
            mm: Field::Unavailable("not read".into()),
            uid: Field::Unavailable("not read".into()),
            gid: Field::Unavailable("not read".into()),
            euid: Field::Unavailable("not read".into()),
            egid: Field::Unavailable("not read".into()),
            start_time: Field::Unavailable("not read".into()),
            start_time_unit: None,
            capabilities: CapabilityFields::all_unavailable("not read"),
            notes: Vec::new(),
        }
    }

    /// The names of the fields that exist on this build and could not be read.
    ///
    /// The list a report must declare beside the row. Empty means every column
    /// is either a value or a stated absence.
    pub fn unreadable_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (name, unavailable) in [
            ("tid", self.tid.is_unavailable()),
            ("pid", self.pid.is_unavailable()),
            ("ppid", self.ppid.is_unavailable()),
            ("comm", self.comm.is_unavailable()),
            ("state", self.state.is_unavailable()),
            ("exit_state", self.exit_state.is_unavailable()),
            ("flags", self.flags.is_unavailable()),
            ("kernel_thread", self.kernel_thread.is_unavailable()),
            ("mm", self.mm.is_unavailable()),
            ("uid", self.uid.is_unavailable()),
            ("gid", self.gid.is_unavailable()),
            ("euid", self.euid.is_unavailable()),
            ("egid", self.egid.is_unavailable()),
            ("start_time", self.start_time.is_unavailable()),
        ] {
            if unavailable {
                out.push(name);
            }
        }
        out
    }

    /// Whether this task has a user address space.
    ///
    /// `None` when `mm` could not be read or is not declared: "we do not know"
    /// and "this is a kernel thread" are different claims, and the stages that
    /// read user memory must skip on the first without recording it as the
    /// second.
    pub fn has_user_memory(&self) -> Option<bool> {
        self.mm.known().map(|address| *address != 0)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            // Exact form beside the number: JSON numbers are IEEE doubles and
            // every x86-64 kernel address is above 2^53, so the numeric form can
            // arrive at a client rounded by up to a kilobyte. A pointer quoted
            // in a report has to be the pointer that was read.
            "address_hex": format!("{:#x}", self.address),
            "tid": signed_to_json(&self.tid),
            "pid": signed_to_json(&self.pid),
            "ppid": signed_to_json(&self.ppid),
            "comm": self.comm.to_json(),
            "comm_well_formed": self.comm_well_formed,
            "state": signed_to_json(&self.state),
            "exit_state": signed_to_json(&self.exit_state),
            "flags": signed_to_json(&self.flags),
            "kernel_thread": self.kernel_thread.to_json(),
            "mm": self.mm.to_json_address(),
            "has_user_memory": self.has_user_memory(),
            "uid": signed_to_json(&self.uid),
            "gid": signed_to_json(&self.gid),
            "euid": signed_to_json(&self.euid),
            "egid": signed_to_json(&self.egid),
            "start_time": signed_to_json(&self.start_time),
            "start_time_unit": self.start_time_unit,
            "start_time_is_wall_clock": false,
            "capabilities": self.capabilities.to_json(),
            "unreadable_fields": self.unreadable_fields(),
            "notes": self.notes,
        })
    }
}

/// Every process on the kernel's task list, and everything the walk could not
/// do.
#[derive(Debug, Clone)]
pub struct TaskList {
    /// Address of `init_task`.
    pub init_task: u64,
    /// Address of the `list_head` the walk started from — `init_task` plus the
    /// offset of its `tasks` member.
    pub head: u64,
    /// The offset subtracted from every list link to recover its `task_struct`.
    ///
    /// Published so the arithmetic every address in this list rests on can be
    /// checked rather than trusted.
    pub links_offset: u64,
    /// The processes, in the order the list gave them.
    ///
    /// `init_task` itself is not among them: the walk starts at its `tasks`
    /// member and ends when it returns there, which is the same set Volatility's
    /// `linux.pslist` reports.
    pub tasks: Vec<TaskRecord>,
    /// Why the walk ended. Only [`ListStop::Wrapped`] means the list was
    /// enumerated end to end.
    pub stop: ListStop,
    /// What this kernel build actually provided for the stage, as
    /// [`BuildBinding::to_json`] records it: for every member the stage wanted,
    /// whether this build had it, which of the accepted names it had it under,
    /// and where.
    ///
    /// Carried on the finding rather than logged, because it is what makes a
    /// blank column readable — "this build has no such field" rather than an
    /// empty cell — and it is what a defence expert needs in order to check the
    /// analysis against the same symbol pack.
    pub layout: serde_json::Value,
}

impl TaskList {
    /// Whether the list was walked end to end and every field of every row was
    /// either read or explicitly absent.
    ///
    /// The question a report must ask before writing "this machine was running
    /// these processes".
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete()
            && self
                .tasks
                .iter()
                .all(|task| task.unreadable_fields().is_empty())
    }

    /// Everything a report must declare about this list.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(incomplete) = self.stop.incomplete() {
            out.push(Incomplete::new(
                incomplete.reason,
                format!(
                    "walking the kernel task list from init_task at {:#x}: {}",
                    self.init_task, incomplete.detail
                ),
            ));
        }
        for task in &self.tasks {
            let unreadable = task.unreadable_fields();
            if !unreadable.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the task_struct at {:#x} has field(s) that exist on this build and \
                         could not be read: {}",
                        task.address,
                        unreadable.join(", ")
                    ),
                ));
            }
        }
        out
    }

    /// The completeness stamp every stage that walks this list must carry.
    pub fn inventory(&self) -> TaskInventory {
        TaskInventory {
            head: self.head,
            listed: self.tasks.len(),
            complete: self.is_complete(),
            incomplete: self.incomplete(),
        }
    }

    /// Serializable form for the process-list artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "init_task": self.init_task,
            "init_task_hex": format!("{:#x}", self.init_task),
            "head": self.head,
            "head_hex": format!("{:#x}", self.head),
            "links_offset": self.links_offset,
            "count": self.tasks.len(),
            "complete": self.is_complete(),
            "walk_stop": self.stop.as_str(),
            // What `complete` does and does not mean. It says the walk of the
            // kernel's task list finished normally and every field read; it
            // does NOT say these are all the processes that existed. Unlinking
            // a `task_struct` from this list is the standard way of hiding a
            // process on Linux and leaves the process running, so a listing
            // that renders as complete without saying this invites the one
            // conclusion an examiner must not draw from it.
            "enumeration_method": "task_list_walk",
            "enumeration_scope_note": ENUMERATION_SCOPE_NOTE,
            "corroborated_by_second_method": false,
            "tasks": self.tasks.iter().map(TaskRecord::to_json).collect::<Vec<_>>(),
            "layout": self.layout,
            "incomplete": self
                .incomplete()
                .iter()
                .map(Incomplete::to_json)
                .collect::<Vec<_>>(),
        })
    }
}

/// How complete the process inventory a downstream stage rested on was.
///
/// Every stage that is handed a [`TaskList`] can measure only what *it* failed
/// to do. None of them can see that the list itself stopped ten processes early,
/// because a short list looks exactly like a quiet machine. Without this, a bash
/// stage that examined every process it was given reports itself complete over a
/// list that never reached the shell, and an examiner reads "no shell history on
/// this machine" from a stage that never saw the shell.
#[derive(Debug, Clone)]
pub struct TaskInventory {
    /// Address of the `list_head` the list was walked from.
    pub head: u64,
    /// How many processes the stage was handed.
    pub listed: usize,
    /// Whether that was every process on the task list.
    pub complete: bool,
    /// Why it was not, when it was not. Empty when `complete`.
    pub incomplete: Vec<Incomplete>,
}

impl TaskInventory {
    /// Whether the inventory is a total rather than a floor.
    pub fn is_complete(&self) -> bool {
        self.complete && self.incomplete.is_empty()
    }

    /// Serializable form, for embedding in a stage's artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let complete = self.is_complete();
        let meaning = if complete {
            "The task list this stage walked was enumerated end to end, so the set of processes \
             examined here is every process the kernel had linked."
        } else {
            "The task list this stage walked stopped short, so the processes examined here are a \
             floor. Nothing here is a statement about a process the list never reached."
        };
        serde_json::json!({
            "head": self.head,
            "head_hex": format!("{:#x}", self.head),
            "listed": self.listed,
            "complete": complete,
            "count_is_floor": !complete,
            "meaning": meaning,
            "incomplete": self
                .incomplete
                .iter()
                .map(Incomplete::to_json)
                .collect::<Vec<_>>(),
        })
    }

    /// Stamp this inventory onto a stage's record body.
    pub fn stamp(&self, value: &mut serde_json::Value) {
        if let Some(object) = value.as_object_mut() {
            object.insert("task_inventory".into(), self.to_json());
        }
    }
}

/// Bind the process-list stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = reader_for(profile);
    Ok(TASK_LAYOUT.bind(&reader)?)
}

/// A struct reader over the kernel address space.
pub fn reader_for(profile: &LinuxProfile) -> StructReader {
    StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    )
}

/// Walk the kernel's task list from `init_task`.
///
/// # Errors
///
/// Only when the stage could not run at all: the symbol table declares no
/// `init_task`, or a member the stage declared `required` is absent. A walk that
/// stopped early is **not** an error — it is a [`TaskList`] whose
/// [`TaskList::is_complete`] is false and whose [`TaskList::incomplete`] says
/// why, because the processes reached before it stopped are real evidence.
pub fn list_tasks(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    config: &TaskListConfig,
) -> Result<TaskList, StageError> {
    let init_task = profile
        .symbols
        .symbol_address(INIT_TASK_SYMBOLS[0])
        .map_err(|_| StageError::NoStartSymbol {
            stage: STAGE_LINUX_PROCESSES.key,
            candidates: name_list(&INIT_TASK_SYMBOLS),
            without_it: "there is no process structure to start the list walk from, so no \
                         process on this machine can be enumerated",
        })?;

    let task_type = required_type(layout, "task")?;
    let link_type = required_type(layout, "list_link")?;
    let links = required_member(layout, "tasks")?;
    let forward = required_member(layout, "list_next")?;
    let links_offset = layout
        .member("tasks")?
        .offset()
        .expect("a declared member has an offset");

    let head = init_task
        .checked_add(links_offset)
        .ok_or_else(|| StageError::NoStartSymbol {
            stage: STAGE_LINUX_PROCESSES.key,
            candidates: name_list(&INIT_TASK_SYMBOLS),
            without_it: "the address of its task-list link does not fit in the address space, so \
                         the walk has nowhere to begin",
        })?;

    let reader = reader_for(profile);
    let spec = ListSpec::new(link_type, forward)
        .in_container(task_type, links)
        .with_max_entries(config.max_tasks);
    let walk = reader.walk_list(head, &spec)?;
    let (entries, stop) = walk.walk_to_end();

    let tasks = entries
        .iter()
        .map(|obj| read_task(layout, obj))
        .collect::<Result<Vec<_>, StageError>>()?;

    Ok(TaskList {
        init_task,
        head,
        links_offset,
        tasks,
        stop,
        layout: layout.to_json(),
    })
}

/// What a process list built from one linked list can and cannot claim.
///
/// Attached to the artifact rather than stated once in documentation, for the
/// reason the reporting layer already applies to qualifications: records are
/// read individually, and a caveat that lives somewhere else is a caveat that
/// gets separated from the finding it qualifies.
pub const ENUMERATION_SCOPE_NOTE: &str =
    "These processes were enumerated by walking the kernel's task list from `init_task`. A \
     `task_struct` that has been unlinked from that list — the standard method of hiding a \
     process on Linux — keeps running and does not appear here. `complete` above means the \
     walk terminated normally and every field was readable; it does NOT mean this is every \
     process that existed. No second enumeration method corroborates this list, so a process \
     absent from it has not been shown to be absent from the machine.";

/// The type name this build declares for a required type key.
fn required_type(layout: &BuildBinding, key: &'static str) -> Result<&'static str, StageError> {
    Ok(layout
        .type_of(key)?
        .type_name()
        .expect("a required type is declared or binding refused the stage"))
}

/// The member path this build declares for a required member key.
fn required_member(layout: &BuildBinding, key: &'static str) -> Result<&'static str, StageError> {
    Ok(layout
        .member(key)?
        .member()
        .expect("a required member is declared or binding refused the stage"))
}

/// Read one `task_struct` into a row.
///
/// Never fails on a field: every way of not getting a value is a variant on the
/// row, so a process whose page was not acquired is reported as a process with
/// unreadable fields rather than dropped from the list. Dropping it would make
/// the listing shorter by exactly the process an examiner most wants to see.
fn read_task(layout: &BuildBinding, obj: &Obj) -> Result<TaskRecord, StageError> {
    let (comm, comm_well_formed) = read_char_array(layout, obj, "comm")?;
    let flags = read_integer(layout, obj, "flags")?;
    let kernel_thread = match &flags {
        Field::Known(value) => Field::Known((*value & PF_KTHREAD) != 0),
        Field::NotApplicable => Field::NotApplicable,
        Field::NotDeclared { member } => Field::NotDeclared { member },
        Field::Unavailable(detail) => Field::Unavailable(detail.clone()),
    };
    let mm = layout.read_pointer(obj, "mm")?;

    let (start_time, start_time_unit) = read_start_time(layout, obj)?;
    let ppid = read_parent_pid(layout, obj)?;
    let ((uid, gid, euid, egid), capabilities) = read_credentials(layout, obj)?;

    Ok(TaskRecord {
        address: obj.address(),
        tid: read_signed(layout, obj, "pid")?,
        pid: read_signed(layout, obj, "tgid")?,
        ppid,
        comm,
        comm_well_formed,
        state: read_integer(layout, obj, "state")?,
        exit_state: read_integer(layout, obj, "exit_state")?,
        flags,
        kernel_thread,
        mm,
        uid,
        gid,
        euid,
        egid,
        start_time,
        start_time_unit,
        capabilities,
        notes: Vec::new(),
    })
}

/// The start time and the unit this build stores it in.
///
/// The unit comes from *which* candidate the build declared, which is exactly
/// what the binding records. A row that published the number without the unit
/// would invite a reader to treat 1403606200 and 1403606200000000000 as the same
/// kind of thing.
fn read_start_time(
    layout: &BuildBinding,
    obj: &Obj,
) -> Result<(Field<i64>, Option<&'static str>), StageError> {
    let unit = match layout.member("start_time")?.member() {
        Some("start_time.tv_sec") => Some("seconds_since_boot"),
        Some("start_time") => Some("nanoseconds_since_boot"),
        Some(_) | None => None,
    };
    Ok((read_integer(layout, obj, "start_time")?, unit))
}

/// The parent's process id, through whichever parent pointer this build
/// declares.
fn read_parent_pid(layout: &BuildBinding, obj: &Obj) -> Result<Field<i64>, StageError> {
    let bound = layout.member("real_parent")?;
    let path = match bound.resolution() {
        MemberUse::Declared { member, .. } => *member,
        MemberUse::NotDeclared => {
            return Ok(Field::NotDeclared {
                member: bound.candidates()[0],
            })
        }
        MemberUse::Unavailable { detail } => return Ok(Field::Unavailable(detail.clone())),
    };
    Ok(match obj.follow(path) {
        // A null parent pointer is a fact about this task, not a gap: it is what
        // `init_task` itself carries.
        Ok(None) => Field::NotApplicable,
        Ok(Some(parent)) => read_signed(layout, &parent, "tgid")?,
        Err(err) => Field::Unavailable(err.to_string()),
    })
}

/// The four credential ids, through whichever credential pointer this build
/// declares.
///
/// All four share the fate of the pointer: when `cred` is null or unreadable,
/// every one of them is the same kind of absence, and reporting three of them as
/// zero because the fourth failed would put ids in the record that were never
/// read.
type Credentials = (Field<i64>, Field<i64>, Field<i64>, Field<i64>);

fn read_credentials(
    layout: &BuildBinding,
    obj: &Obj,
) -> Result<(Credentials, CapabilityFields), StageError> {
    let bound = layout.member("cred")?;
    let path = match bound.resolution() {
        MemberUse::Declared { member, .. } => *member,
        MemberUse::NotDeclared => {
            let absent = || Field::NotDeclared {
                member: bound.candidates()[0],
            };
            let cap_absent = || Field::NotDeclared {
                member: bound.candidates()[0],
            };
            return Ok((
                (absent(), absent(), absent(), absent()),
                CapabilityFields {
                    effective: cap_absent(),
                    permitted: cap_absent(),
                    inheritable: cap_absent(),
                    bounding: cap_absent(),
                    ambient: cap_absent(),
                },
            ));
        }
        MemberUse::Unavailable { detail } => {
            let damaged = || Field::Unavailable(detail.clone());
            return Ok((
                (damaged(), damaged(), damaged(), damaged()),
                CapabilityFields::all_unavailable(detail),
            ));
        }
    };
    match obj.follow(path) {
        Ok(Some(cred)) => Ok((
            (
                read_integer(layout, &cred, "uid")?,
                read_integer(layout, &cred, "gid")?,
                read_integer(layout, &cred, "euid")?,
                read_integer(layout, &cred, "egid")?,
            ),
            CapabilityFields {
                effective: read_cap_mask(layout, &cred, "cap_effective")?,
                permitted: read_cap_mask(layout, &cred, "cap_permitted")?,
                inheritable: read_cap_mask(layout, &cred, "cap_inheritable")?,
                bounding: read_cap_mask(layout, &cred, "cap_bounding")?,
                ambient: read_cap_mask(layout, &cred, "cap_ambient")?,
            },
        )),
        Ok(None) => Ok((
            (
                Field::NotApplicable,
                Field::NotApplicable,
                Field::NotApplicable,
                Field::NotApplicable,
            ),
            CapabilityFields {
                effective: Field::NotApplicable,
                permitted: Field::NotApplicable,
                inheritable: Field::NotApplicable,
                bounding: Field::NotApplicable,
                ambient: Field::NotApplicable,
            },
        )),
        Err(err) => {
            let damaged = || Field::Unavailable(err.to_string());
            Ok((
                (damaged(), damaged(), damaged(), damaged()),
                CapabilityFields::all_unavailable(&err.to_string()),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> TaskRecord {
        TaskRecord {
            address: 0xFFFF_8800_1F99_4740,
            tid: Field::Known(1),
            pid: Field::Known(1),
            ppid: Field::Known(0),
            comm: Field::Known("init".into()),
            comm_well_formed: true,
            state: Field::Known(1),
            exit_state: Field::Known(0),
            flags: Field::Known(0x40_0100),
            kernel_thread: Field::Known(false),
            mm: Field::Known(0xFFFF_8800_1F9A_0000),
            uid: Field::Known(0),
            gid: Field::Known(0),
            euid: Field::Known(0),
            egid: Field::Known(0),
            start_time: Field::Known(3),
            start_time_unit: Some("seconds_since_boot"),
            capabilities: CapabilityFields {
                effective: Field::Known(capabilities::full_mask()),
                permitted: Field::Known(capabilities::full_mask()),
                inheritable: Field::Known(0),
                bounding: Field::Known(capabilities::full_mask()),
                ambient: Field::Known(0),
            },
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_row_with_every_field_read_declares_nothing_unreadable() {
        assert!(row().unreadable_fields().is_empty());
    }

    /// The distinction the whole `Field` type exists for, asserted on the row an
    /// examiner actually reads: a build with no such member is not damage, and
    /// only damage may put a field in `unreadable_fields`.
    #[test]
    fn a_member_this_build_lacks_is_not_reported_as_unreadable() {
        let mut task = row();
        task.state = Field::NotDeclared { member: "state" };
        assert!(
            task.unreadable_fields().is_empty(),
            "an absent member is an answer, not a gap in the evidence"
        );

        task.state = Field::Unavailable("the page was not acquired".into());
        assert_eq!(task.unreadable_fields(), vec!["state"]);
    }

    #[test]
    fn a_task_with_no_user_address_space_is_distinguishable_from_an_unknown_one() {
        let mut task = row();
        assert_eq!(task.has_user_memory(), Some(true));
        task.mm = Field::Known(0);
        assert_eq!(task.has_user_memory(), Some(false));
        // "We could not read mm" must never render as "this is a kernel
        // thread": the stages that read user memory skip on both, and only one
        // of them is a finding.
        task.mm = Field::Unavailable("the page was not acquired".into());
        assert_eq!(task.has_user_memory(), None);
    }

    #[test]
    fn the_start_time_is_never_published_as_a_wall_clock_time() {
        let json = row().to_json();
        assert_eq!(json["start_time_unit"], "seconds_since_boot");
        assert_eq!(
            json["start_time_is_wall_clock"], false,
            "Linux stores this as an offset from boot; rendering it as a date without the boot \
             wall-clock time would put a time in the record the machine never held"
        );
    }

    #[test]
    fn an_address_carries_its_exact_hex_beside_the_rounded_number() {
        let json = row().to_json();
        assert_eq!(json["address_hex"], "0xffff88001f994740");
        assert_eq!(json["mm"]["value_hex"], "0xffff88001f9a0000");
    }

    fn list(stop: ListStop, tasks: Vec<TaskRecord>) -> TaskList {
        TaskList {
            init_task: 0xFFFF_FFFF_8160_D020,
            head: 0xFFFF_FFFF_8160_D190,
            links_offset: 368,
            tasks,
            stop,
            layout: serde_json::json!({"stage": "linux_processes"}),
        }
    }

    /// A walk that stopped early must never publish `complete`, and the reason
    /// must name what happened. A short list and a quiet machine look identical
    /// without it.
    #[test]
    fn a_truncated_walk_is_not_a_complete_listing() {
        let full = list(ListStop::Wrapped, vec![row()]);
        assert!(full.is_complete());
        assert!(full.incomplete().is_empty());

        let capped = list(ListStop::CapReached { cap: 64 }, vec![row()]);
        assert!(!capped.is_complete());
        let reasons = capped.incomplete();
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].reason, IncompleteReason::CapReached);
        assert!(reasons[0].detail.contains("init_task"), "{:?}", reasons[0]);

        let cyclic = list(
            ListStop::Cycle {
                address: 0xFFFF_8800_1F99_4740,
            },
            vec![row()],
        );
        assert!(!cyclic.is_complete());
        assert_eq!(
            cyclic.incomplete()[0].reason,
            IncompleteReason::UnresolvedStructure
        );
    }

    /// The inventory is what makes a later stage's completeness honest.
    #[test]
    fn the_inventory_says_a_short_list_is_a_floor() {
        let capped = list(ListStop::CapReached { cap: 1 }, vec![row()]);
        let inventory = capped.inventory();
        assert!(!inventory.is_complete());
        let json = inventory.to_json();
        assert_eq!(json["count_is_floor"], true);
        assert!(json["meaning"]
            .as_str()
            .is_some_and(|text| text.contains("floor")));

        let mut body = serde_json::json!({"rows": []});
        inventory.stamp(&mut body);
        assert_eq!(body["task_inventory"]["listed"], 1);
    }

    #[test]
    fn the_kernel_thread_flag_reads_the_bit_the_kernel_sets() {
        assert_eq!(PF_KTHREAD, 0x0020_0000);
        // A kernel thread: PF_KTHREAD set.
        assert!(0x0020_0040i64 & PF_KTHREAD != 0);
        // A user process: it is not.
        assert!(0x0040_0100i64 & PF_KTHREAD == 0);
    }

    /// Every member the stage declares must be reachable by the key the stage
    /// looks it up under. A key typo is invisible to a build and blanks a
    /// column, so the declaration is asserted against the lookups.
    #[test]
    fn every_key_the_stage_reads_is_a_key_the_stage_declared() {
        const READ_KEYS: &[&str] = &[
            "tasks",
            "list_next",
            "pid",
            "tgid",
            "comm",
            "state",
            "exit_state",
            "flags",
            "mm",
            "real_parent",
            "cred",
            "start_time",
            "uid",
            "gid",
            "euid",
            "egid",
            "cap_effective",
            "cap_permitted",
            "cap_inheritable",
            "cap_bounding",
            "cap_ambient",
        ];
        for key in READ_KEYS {
            assert!(
                TASK_LAYOUT.members.iter().any(|spec| spec.key == *key),
                "{key} is read by the stage and declared nowhere"
            );
        }
        assert_eq!(TASK_LAYOUT.members.len(), READ_KEYS.len());
        assert_eq!(TASK_LAYOUT.stage.key, STAGE_LINUX_PROCESSES.key);
    }

    /// The `state`/`__state` and `uid`/`uid.val` pairs are the two shapes of
    /// build variance this crate exists to survive, and the order within each
    /// decides which layout a build with both is read under.
    #[test]
    fn the_build_variant_members_list_every_spelling_in_a_fixed_order() {
        let spec = |key: &str| {
            *TASK_LAYOUT
                .members
                .iter()
                .find(|spec| spec.key == key)
                .expect("declared")
        };
        assert_eq!(spec("state").members, ["state", "__state"].as_slice());
        assert_eq!(
            spec("real_parent").members,
            ["real_parent", "parent"].as_slice()
        );
        assert_eq!(spec("cred").members, ["cred", "real_cred"].as_slice());
        // The wrapped form first: on a kernel with `kuid_t`, reading `uid`
        // resolves to an aggregate and the value inside it would never be read.
        assert_eq!(spec("uid").members, ["uid.val", "uid"].as_slice());
        assert_eq!(
            spec("start_time").members,
            ["start_time.tv_sec", "start_time"].as_slice()
        );
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    /// **A one-method process list must say what it cannot see.**
    ///
    /// The Windows tier corroborates its list walk with a pool sweep, and its
    /// parity test asserts the two agree. The Linux tier walks one list and had
    /// nothing to say about a `task_struct` unlinked from it — which is the
    /// standard way of hiding a process, leaves the process running, and would
    /// simply not appear.
    ///
    /// `complete: true` beside a listing, with no qualifier, invites exactly
    /// the conclusion an examiner must not draw: that this is every process.
    #[test]
    fn the_process_list_states_that_an_unlinked_task_would_not_appear() {
        let list = TaskList {
            init_task: 0xffff_ffff_8fc0_fb40,
            head: 0xffff_ffff_8fc0_fb98,
            links_offset: 0x58,
            tasks: Vec::new(),
            stop: seance_memory::object::ListStop::Wrapped,
            layout: serde_json::json!({}),
        };
        let json = list.to_json();

        assert_eq!(json["enumeration_method"], "task_list_walk");
        assert_eq!(
            json["corroborated_by_second_method"], false,
            "nothing cross-checks this list today, and the record must not imply otherwise"
        );
        let note = json["enumeration_scope_note"].as_str().expect("a note");
        assert!(
            note.contains("unlinked"),
            "the note must name the technique that defeats this enumeration: {note}"
        );
        assert!(
            note.contains("does NOT mean this is every process"),
            "the note must say plainly what `complete` is not: {note}"
        );
    }
}
