//! Shell command history recovered from a running shell's heap.
//!
//! `bash` keeps its in-memory history as an array of `HIST_ENTRY` structures on
//! its own heap. Each is three pointers wide — the command line, the timestamp
//! string, and an opaque `data` pointer — and when `HISTTIMEFORMAT` is in effect
//! the timestamp string is a `#` followed by the Unix epoch in decimal. None of
//! that is in the kernel, and none of it is on disk until the shell exits, so
//! this is one of the few stages that can show what an interactive session was
//! doing at the moment of capture even when `.bash_history` was never written.
//!
//! ## How an entry is found
//!
//! 1. Read the shell's heap — the virtual memory areas overlapping `start_brk`
//!    to `brk` — out of the process's own address space.
//! 2. Collect the address of every `#` byte in it.
//! 3. Scan the same bytes for a pointer whose value is one of those addresses.
//!    That pointer is a candidate `HIST_ENTRY.timestamp`.
//! 4. The structure begins one pointer earlier, so `line` is the pointer before
//!    it. Follow both, and accept the entry only if the timestamp is `#` plus at
//!    least nine digits and nothing else, and the line is non-empty.
//!
//! Step 3 is a byte scan at every offset rather than every aligned offset, which
//! is what Volatility 3 does, and it matters: an unaligned match is still a real
//! pointer in a real structure whenever the heap chunk it lives in is unaligned.
//!
//! ## The layout that is not in the ISF
//!
//! `HIST_ENTRY` belongs to bash, not to the kernel, so no kernel symbol table
//! declares it. Volatility ships a hand-written `bash64.json` for exactly this
//! reason. [`HistEntryLayout`] is the same three-pointer shape, derived from the
//! address space's own pointer width rather than assumed, and it is written down
//! here as a **stated assumption about a userland program** rather than smuggled
//! in as a kernel fact. A build of bash that changed it would be found by the
//! validity check in step 4 failing, not by a wrong answer.
//!
//! ## What an empty result means
//!
//! Nothing, unless the row says otherwise. A shell that was started without
//! `HISTTIMEFORMAT` writes no `#` timestamps and yields no entries here; so does
//! a shell whose heap was not captured. Both are recorded on the row, and
//! neither is reported as "this user ran no commands".

use std::collections::HashSet;

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::Obj;

use crate::error::StageError;
use crate::module::STAGE_LINUX_BASH_HISTORY;
use crate::profile::LinuxProfile;
use crate::read::{read_c_string, signed_to_json};
use crate::space::{self, ProcessSpace, SpaceRefusal};
use crate::tasks::{TaskInventory, TaskList, TaskRecord};

/// Process names this stage examines.
///
/// Matching on the name is how Volatility 3 selects, and it is a real limitation
/// rather than a filter: a shell renamed by the attacker, or an interactive
/// `zsh`, is not examined. That is stated on the survey so an empty result is
/// never read as "nobody used a shell".
pub const SHELL_NAMES: [&str; 3] = ["bash", "sh", "dash"];

/// Shortest a bash timestamp string can be: `#` plus a nine-digit epoch.
///
/// Nine rather than ten because Unix time passed ten digits in 2001 and this is
/// a lower bound, not an expectation. The check that matters is that everything
/// after the `#` is decimal.
pub const MIN_TIMESTAMP_LEN: usize = 10;

/// Longest command line this stage will follow.
pub const MAX_COMMAND_LEN: usize = 4096;

/// Longest timestamp string this stage will follow.
pub const MAX_TIMESTAMP_LEN: usize = 64;

/// Bytes of one shell's heap this stage will read.
///
/// A shell's heap is normally well under a megabyte. The bound stops a corrupt
/// `brk` from turning one process into an unbounded read, and when it fires it
/// is recorded, so a short result is never mistaken for a short history.
pub const MAX_HEAP_BYTES: u64 = 64 * 1024 * 1024;

/// Ceiling on virtual memory areas walked for one process.
pub const MAX_VMAS: usize = 65_536;

/// Ceiling on history entries recovered for one process.
pub const MAX_ENTRIES: usize = 100_000;

/// Everything the bash-history stage needs out of the symbol table.
///
/// Note what is **not** here: `HIST_ENTRY`. It is a bash structure and no kernel
/// symbol table declares it; see [`HistEntryLayout`].
pub const BASH_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_BASH_HISTORY,
    &[
        TypeSpec::new("mm", &["mm_struct"]).required(
            "a process's memory descriptor cannot be located, so no shell's own address space \
             can be opened and no command history can be recovered",
        ),
        TypeSpec::new("vma", &["vm_area_struct"]).required(
            "a process's memory areas cannot be described, so the shell's heap cannot be found",
        ),
    ],
    &[
        MemberSpec::new("mm", &["task_struct"], &["mm"]).required(
            "a task carries no pointer to its memory descriptor, so no shell's own address space \
             can be reached",
        ),
        MemberSpec::new("pgd", &["mm_struct"], &["pgd"])
            .required("a shell's page-table root cannot be found, so its heap cannot be read"),
        // Linux 6.1 replaced the `mmap` linked list with a maple tree in
        // `mm_mt`. This stage reads the list; a kernel that has only the tree is
        // refused with that sentence rather than reporting an empty history.
        MemberSpec::new("mmap", &["mm_struct"], &["mmap"]).required(
            "this kernel build keeps its virtual memory areas somewhere other than the 'mmap' \
             linked list — Linux 6.1 and later use a maple tree in 'mm_mt' — which this build of \
             Séance does not walk, so the shell's heap cannot be located. That is a limit of \
             this tool and not a finding that the shell had no history",
        ),
        MemberSpec::new("brk", &["mm_struct"], &["brk"])
            .required("the top of the heap is unknown, so the heap cannot be bounded"),
        MemberSpec::new("start_brk", &["mm_struct"], &["start_brk"])
            .required("the base of the heap is unknown, so the heap cannot be bounded"),
        MemberSpec::new("vm_start", &["vm_area_struct"], &["vm_start"]).required(
            "a memory area has no start, so no area can be tested against the heap's bounds",
        ),
        MemberSpec::new("vm_end", &["vm_area_struct"], &["vm_end"]).required(
            "a memory area has no end, so no area can be tested against the heap's bounds",
        ),
        MemberSpec::new("vm_next", &["vm_area_struct"], &["vm_next"]).required(
            "the memory-area list has no forward link, so only the first area could be examined",
        ),
    ],
);

/// The `HIST_ENTRY` layout, derived from the address space's pointer width.
///
/// bash declares:
///
/// ```text
/// typedef struct _hist_entry {
///     char *line;
///     char *timestamp;
///     histdata_t data;
/// } HIST_ENTRY;
/// ```
///
/// Three pointers, in that order, with no padding on either supported ABI. This
/// is a stated assumption about a **userland program**, not a kernel fact, and
/// it is why every candidate is validated by dereferencing both pointers rather
/// than trusted because the arithmetic worked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistEntryLayout {
    /// Pointer width in bytes.
    pub pointer: u64,
}

impl HistEntryLayout {
    /// The layout for a given pointer width.
    pub const fn new(pointer: u64) -> Self {
        Self { pointer }
    }

    /// Offset of `line`.
    pub const fn line_offset(self) -> u64 {
        0
    }

    /// Offset of `timestamp`.
    pub const fn timestamp_offset(self) -> u64 {
        self.pointer
    }

    /// Total size.
    pub const fn size(self) -> u64 {
        self.pointer * 3
    }
}

/// Caps for one bash-history survey.
#[derive(Debug, Clone)]
pub struct BashConfig {
    /// Bytes of one shell's heap read.
    pub max_heap_bytes: u64,
    /// Memory areas walked for one process.
    pub max_vmas: usize,
    /// History entries recovered for one process.
    pub max_entries: usize,
}

impl Default for BashConfig {
    fn default() -> Self {
        Self {
            max_heap_bytes: MAX_HEAP_BYTES,
            max_vmas: MAX_VMAS,
            max_entries: MAX_ENTRIES,
        }
    }
}

/// One recovered history entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BashCommand {
    /// Address of the `HIST_ENTRY` in the shell's own address space.
    pub entry_address: u64,
    /// The Unix time the shell recorded against the command.
    pub timestamp_unix: i64,
    /// That time as an RFC 3339 string, when it is a time a clock could show.
    ///
    /// `None` rather than a fabricated date for a value outside the range a
    /// timestamp can take: a `#0` marker is not 1970, it is a marker that is not
    /// a time.
    pub timestamp_rfc3339: Option<String>,
    /// The command line.
    pub command: String,
    /// Whether the command's bytes were valid UTF-8. A `false` means bytes were
    /// replaced to render it, which for a command line is worth stating.
    pub command_well_formed: bool,
}

impl BashCommand {
    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "entry_address": self.entry_address,
            "entry_address_hex": format!("{:#x}", self.entry_address),
            "timestamp_unix": self.timestamp_unix,
            "timestamp": self.timestamp_rfc3339,
            "command": self.command,
            "command_well_formed": self.command_well_formed,
        })
    }
}

/// What happened when this stage looked at one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BashOutcome {
    /// The whole heap was read and searched.
    Searched {
        /// Bytes of heap examined.
        bytes: u64,
        /// Memory areas that made up the heap.
        areas: usize,
    },
    /// Part of the heap was not captured, so the entries found are a floor.
    PartiallySearched {
        /// Bytes examined.
        read: u64,
        /// Bytes that could not be examined.
        unread: u64,
    },
    /// The process's address space could not be opened.
    NotRead(SpaceRefusal),
    /// The heap's bounds could not be established.
    HeapUnbounded(String),
    /// This process has no memory area overlapping the heap's bounds.
    NoHeap,
    /// The entry cap fired. The search stopped; the history did not.
    CapReached {
        /// The cap that fired.
        cap: usize,
    },
}

impl BashOutcome {
    /// Whether this outcome means evidence is missing.
    pub fn is_a_gap(&self) -> bool {
        match self {
            BashOutcome::Searched { .. } => false,
            BashOutcome::NotRead(refusal) => refusal.is_a_gap(),
            BashOutcome::PartiallySearched { .. }
            | BashOutcome::HeapUnbounded(_)
            | BashOutcome::CapReached { .. } => true,
            // A shell with no heap area is odd but complete: there is nowhere
            // the history could be, and nothing was missed.
            BashOutcome::NoHeap => false,
        }
    }

    /// Stable machine-readable class.
    pub fn class(&self) -> &'static str {
        match self {
            BashOutcome::Searched { .. } => "searched",
            BashOutcome::PartiallySearched { .. } => "partially_searched",
            BashOutcome::NotRead(_) => "not_read",
            BashOutcome::HeapUnbounded(_) => "heap_unbounded",
            BashOutcome::NoHeap => "no_heap",
            BashOutcome::CapReached { .. } => "cap_reached",
        }
    }

    /// One sentence an examiner reads.
    pub fn detail(&self) -> String {
        match self {
            BashOutcome::Searched { bytes, areas } => format!(
                "{bytes} byte(s) of heap across {areas} memory area(s) were read and searched in \
                 full"
            ),
            BashOutcome::PartiallySearched { read, unread } => format!(
                "{read} byte(s) of heap were searched and {unread} were not captured by the \
                 acquisition, so any history in them is not represented here"
            ),
            BashOutcome::NotRead(refusal) => refusal.detail(),
            BashOutcome::HeapUnbounded(detail) => {
                format!("this shell's heap could not be bounded, so nothing was searched: {detail}")
            }
            BashOutcome::NoHeap => {
                "this process has no memory area overlapping the heap the kernel describes"
                    .to_string()
            }
            BashOutcome::CapReached { cap } => format!(
                "the search stopped at its cap of {cap} history entries; the shell's history \
                 continues past what is listed here"
            ),
        }
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "class": self.class(),
            "detail": self.detail(),
            "is_a_gap": self.is_a_gap(),
        })
    }
}

/// One shell's recovered history.
#[derive(Debug, Clone)]
pub struct ShellHistory {
    /// Address of the `task_struct`.
    pub task_address: u64,
    /// The process id.
    pub pid: Field<i64>,
    /// The process name that selected this task.
    pub comm: Field<String>,
    /// The commands, oldest first.
    pub commands: Vec<BashCommand>,
    /// What happened.
    pub outcome: BashOutcome,
}

impl ShellHistory {
    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "task_address": self.task_address,
            "task_address_hex": format!("{:#x}", self.task_address),
            "pid": signed_to_json(&self.pid),
            "comm": self.comm.to_json(),
            "count": self.commands.len(),
            "commands": self.commands.iter().map(BashCommand::to_json).collect::<Vec<_>>(),
            "outcome": self.outcome.to_json(),
        })
    }
}

/// Every shell's recovered history, and what the stage could not establish.
#[derive(Debug, Clone)]
pub struct BashSurvey {
    /// One entry per shell process found on the task list.
    pub shells: Vec<ShellHistory>,
    /// Processes on the list whose name was not one this stage examines.
    ///
    /// Counted rather than dropped: an empty survey over a machine with 130
    /// processes should say that 127 of them were not shells, not merely that
    /// nothing was found.
    pub not_a_shell: usize,
    /// Processes whose name could not be read, so it is not known whether they
    /// were shells.
    ///
    /// A gap: a shell whose `comm` was unreadable is a shell this stage did not
    /// examine, and that is different from a process known not to be one.
    pub name_unknown: usize,
    /// Which structure layout produced these figures.
    ///
    /// `tasks.rs` and `lsmod.rs` published this and these two stages did not,
    /// so their records could not answer the question the binding exists to
    /// answer: under which candidate member name did each offset resolve. A
    /// report that can say that for some findings and not others invites the
    /// question of why.
    pub layout: serde_json::Value,
    /// How complete the list the stage walked was.
    pub inventory: TaskInventory,
}

impl BashSurvey {
    /// Total commands recovered.
    pub fn command_count(&self) -> usize {
        self.shells.iter().map(|s| s.commands.len()).sum()
    }

    /// Whether every shell on the list was searched and nothing was missed.
    pub fn is_complete(&self) -> bool {
        self.inventory.is_complete()
            && self.name_unknown == 0
            && !self.shells.iter().any(|s| s.outcome.is_a_gap())
    }

    /// Everything a report must declare about this survey.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if self.name_unknown > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} process(es) on the task list had a name that could not be read, so it is \
                     not known whether they were shells and they were not searched",
                    self.name_unknown
                ),
            ));
        }
        for shell in &self.shells {
            if !shell.outcome.is_a_gap() {
                continue;
            }
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the shell at {:#x} was not searched in full: {}",
                    shell.task_address,
                    shell.outcome.detail()
                ),
            ));
        }
        out
    }

    /// Serializable form for the bash-history artifact.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "shell_count": self.shells.len(),
            "command_count": self.command_count(),
            "not_a_shell": self.not_a_shell,
            "name_unknown": self.name_unknown,
            "shell_names_examined": SHELL_NAMES,
            "selection_note": "Shells are selected by process name. A shell running under \
                               another name, and any interactive shell that is not one of the \
                               names listed here, was not searched — so an empty result is not a \
                               statement that no commands were run.",
            "complete": self.is_complete(),
            "layout": self.layout,
            "shells": self.shells.iter().map(ShellHistory::to_json).collect::<Vec<_>>(),
            "incomplete": self
                .incomplete()
                .iter()
                .map(Incomplete::to_json)
                .collect::<Vec<_>>(),
        });
        self.inventory.stamp(&mut value);
        value
    }
}

/// Bind the bash-history stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(BASH_LAYOUT.bind(&reader)?)
}

/// Recover shell history from every shell process on the list.
///
/// # Errors
///
/// Only for a lookup the stage never declared. Every way one shell can fail to
/// yield history is a variant on its row.
pub fn survey_bash(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &BashConfig,
) -> Result<BashSurvey, StageError> {
    let reader = crate::tasks::reader_for(profile);
    let task_type = layout
        .member("mm")?
        .type_name()
        .expect("a required member is declared or binding refused the stage");
    let entry = HistEntryLayout::new(profile.pointer_size());

    let mut shells = Vec::new();
    let mut not_a_shell = 0usize;
    let mut name_unknown = 0usize;

    for task in &tasks.tasks {
        let Some(name) = task.comm.known() else {
            // A process whose name could not be read might be a shell. Counting
            // it apart from "not a shell" is what stops an unreadable name from
            // silently shrinking the set of things that were looked at.
            name_unknown += 1;
            continue;
        };
        if !SHELL_NAMES.contains(&name.as_str()) {
            not_a_shell += 1;
            continue;
        }
        let obj = match reader.object(task.address, task_type) {
            Ok(obj) => obj,
            Err(err) => {
                shells.push(shell_row(
                    task,
                    Vec::new(),
                    BashOutcome::NotRead(SpaceRefusal::Unreadable(err.to_string())),
                ));
                continue;
            }
        };
        let (commands, outcome) = read_history(profile, layout, &obj, entry, config)?;
        shells.push(shell_row(task, commands, outcome));
    }

    Ok(BashSurvey {
        shells,
        not_a_shell,
        name_unknown,
        layout: layout.to_json(),
        inventory: tasks.inventory(),
    })
}

/// One row, carrying the identity the task list already established.
fn shell_row(task: &TaskRecord, commands: Vec<BashCommand>, outcome: BashOutcome) -> ShellHistory {
    ShellHistory {
        task_address: task.address,
        pid: task.pid.clone(),
        comm: task.comm.clone(),
        commands,
        outcome,
    }
}

/// Recover one shell's history.
fn read_history(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    task: &Obj,
    entry: HistEntryLayout,
    config: &BashConfig,
) -> Result<(Vec<BashCommand>, BashOutcome), StageError> {
    let mm = match space::memory_descriptor(layout, task, "mm")? {
        Ok(mm) => mm,
        Err(refusal) => return Ok((Vec::new(), BashOutcome::NotRead(refusal))),
    };
    let start_brk = match required_unsigned(layout, &mm, "start_brk")? {
        Ok(value) => value,
        Err(detail) => return Ok((Vec::new(), BashOutcome::HeapUnbounded(detail))),
    };
    let brk = match required_unsigned(layout, &mm, "brk")? {
        Ok(value) => value,
        Err(detail) => return Ok((Vec::new(), BashOutcome::HeapUnbounded(detail))),
    };

    let areas = match heap_areas(layout, &mm, start_brk, brk, config)? {
        Ok(areas) => areas,
        Err(detail) => return Ok((Vec::new(), BashOutcome::HeapUnbounded(detail))),
    };
    if areas.is_empty() {
        return Ok((Vec::new(), BashOutcome::NoHeap));
    }

    let opened = match space::open(profile, layout, &mm, "pgd")? {
        Ok(opened) => opened,
        Err(refusal) => return Ok((Vec::new(), BashOutcome::NotRead(refusal))),
    };

    let mut commands: Vec<BashCommand> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut read_total = 0u64;
    let mut unread_total = 0u64;
    let mut budget = config.max_heap_bytes;
    let mut capped = false;

    for (start, end) in &areas {
        let length = end.saturating_sub(*start);
        let runs = space::read_runs(&*opened.layer, *start, length, budget);
        read_total = read_total.saturating_add(runs.bytes_read);
        unread_total = unread_total.saturating_add(runs.bytes_unread);
        budget = budget.saturating_sub(runs.bytes_read);
        for (run_start, bytes) in &runs.runs {
            if commands.len() >= config.max_entries {
                capped = true;
                break;
            }
            search_run(
                &opened,
                entry,
                *run_start,
                bytes,
                config.max_entries,
                &mut seen,
                &mut commands,
            );
        }
        if capped {
            break;
        }
    }

    // Oldest first, which is how a history reads and how the oracle orders it.
    commands.sort_by(|a, b| {
        a.timestamp_unix
            .cmp(&b.timestamp_unix)
            .then_with(|| a.entry_address.cmp(&b.entry_address))
    });

    let outcome = if capped || commands.len() >= config.max_entries {
        BashOutcome::CapReached {
            cap: config.max_entries,
        }
    } else if unread_total > 0 {
        BashOutcome::PartiallySearched {
            read: read_total,
            unread: unread_total,
        }
    } else {
        BashOutcome::Searched {
            bytes: read_total,
            areas: areas.len(),
        }
    };
    Ok((commands, outcome))
}

/// Search one contiguous run of heap bytes for history entries.
///
/// Two passes over the same bytes: the first records where every `#` is, the
/// second looks for a pointer holding one of those addresses. A pointer that
/// spans the end of the run is not found, which is a consequence of refusing to
/// stitch acquired bytes to unacquired ones and is accounted for by the run's
/// own unread total.
fn search_run(
    space: &ProcessSpace,
    entry: HistEntryLayout,
    run_start: u64,
    bytes: &[u8],
    max_entries: usize,
    seen: &mut HashSet<u64>,
    out: &mut Vec<BashCommand>,
) {
    let pointer = entry.pointer as usize;
    if bytes.len() < pointer {
        return;
    }
    let mut markers: HashSet<u64> = HashSet::new();
    for (offset, byte) in bytes.iter().enumerate() {
        if *byte == b'#' {
            markers.insert(run_start.wrapping_add(offset as u64));
        }
    }
    if markers.is_empty() {
        return;
    }

    for offset in 0..=(bytes.len() - pointer) {
        if out.len() >= max_entries {
            return;
        }
        let value = read_pointer(&bytes[offset..offset + pointer]);
        if !markers.contains(&value) {
            continue;
        }
        // The timestamp pointer is the second member, so the structure starts
        // one pointer earlier.
        let timestamp_at = run_start.wrapping_add(offset as u64);
        let Some(entry_address) = timestamp_at.checked_sub(entry.timestamp_offset()) else {
            continue;
        };
        if !seen.insert(entry_address) {
            continue;
        }
        let line_at = entry_address.wrapping_add(entry.line_offset());
        let Some(line_pointer) = pointer_at(space, bytes, run_start, line_at, pointer) else {
            continue;
        };
        if line_pointer == 0 {
            continue;
        }
        let Some(command) = validated_entry(space, entry_address, value, line_pointer) else {
            continue;
        };
        out.push(command);
    }
}

/// A pointer at `address`, taken from the run's bytes when it lies inside them
/// and read from the address space when it does not.
fn pointer_at(
    space: &ProcessSpace,
    bytes: &[u8],
    run_start: u64,
    address: u64,
    width: usize,
) -> Option<u64> {
    if address >= run_start {
        let offset = (address - run_start) as usize;
        if offset + width <= bytes.len() {
            return Some(read_pointer(&bytes[offset..offset + width]));
        }
    }
    let mut buf = vec![0u8; width];
    seance_core::io::read_exact_or_fail(
        space.layer.as_data_source(),
        address,
        &mut buf,
        "a HIST_ENTRY pointer",
    )
    .ok()?;
    Some(read_pointer(&buf))
}

/// A little-endian pointer of 4 or 8 bytes.
fn read_pointer(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate().take(8) {
        value |= u64::from(*byte) << (index * 8);
    }
    value
}

/// Follow both pointers and accept the entry only if both are what a
/// `HIST_ENTRY` holds.
///
/// This is the step that makes the byte scan safe. Any 8 bytes on a heap can
/// happen to equal the address of a `#`; only a real `HIST_ENTRY` has, one
/// pointer earlier, a pointer to a non-empty string, and at the matched address
/// a `#` followed by nothing but digits.
fn validated_entry(
    space: &ProcessSpace,
    entry_address: u64,
    timestamp_pointer: u64,
    line_pointer: u64,
) -> Option<BashCommand> {
    let (timestamp, _) = read_c_string(&*space.layer, timestamp_pointer, MAX_TIMESTAMP_LEN).ok()?;
    let seconds = parse_history_timestamp(&timestamp)?;
    let (command, command_well_formed) =
        read_c_string(&*space.layer, line_pointer, MAX_COMMAND_LEN).ok()?;
    if command.is_empty() {
        return None;
    }
    Some(BashCommand {
        entry_address,
        timestamp_unix: seconds,
        timestamp_rfc3339: chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
            .map(|dt| dt.to_rfc3339()),
        command,
        command_well_formed,
    })
}

/// The Unix seconds a bash history timestamp marker holds.
///
/// `None` for anything that is not `#` followed by at least nine decimal digits
/// and nothing else. Accepting a looser shape is what turns a byte scan into a
/// list of coincidences.
pub fn parse_history_timestamp(text: &str) -> Option<i64> {
    if text.len() < MIN_TIMESTAMP_LEN {
        return None;
    }
    let digits = text.strip_prefix('#')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i64>().ok()
}

/// Read a member the stage declared `required`, as an unsigned value.
///
/// The `Err` side is a sentence rather than a stage failure: the member is
/// declared, so binding already proved this build has it, and a value that
/// would not read is damage to *this process's* evidence and not to the stage.
fn required_unsigned(
    layout: &BuildBinding,
    obj: &Obj,
    key: &'static str,
) -> Result<Result<u64, String>, StageError> {
    Ok(match layout.read_unsigned(obj, key)? {
        Field::Known(value) => Ok(value),
        Field::NotApplicable => Err(format!("this process records no '{key}'")),
        Field::NotDeclared { member } => Err(format!(
            "this kernel build declares no '{member}', which the stage requires"
        )),
        Field::Unavailable(detail) => Err(detail),
    })
}

/// The virtual memory areas that make up this process's heap.
///
/// The same test Volatility 3 applies: an area is part of the heap when it
/// starts at or below `brk` and ends at or above `start_brk`. The walk is
/// bounded and cycle-safe, because a corrupt `vm_next` chain must bound the work
/// rather than hang an ingest.
fn heap_areas(
    layout: &BuildBinding,
    mm: &Obj,
    start_brk: u64,
    brk: u64,
    config: &BashConfig,
) -> Result<Result<Vec<(u64, u64)>, String>, StageError> {
    let mut areas = Vec::new();
    let mmap_path = layout
        .member("mmap")?
        .member()
        .expect("a required member is declared or binding refused the stage");
    let mut current = match mm.follow(mmap_path) {
        Ok(Some(vma)) => vma,
        Ok(None) => return Ok(Ok(areas)),
        Err(err) => return Ok(Err(err.to_string())),
    };

    let mut visited: HashSet<u64> = HashSet::new();
    for _ in 0..config.max_vmas {
        if !visited.insert(current.address()) {
            return Ok(Err(format!(
                "the memory-area list returns to {:#x}, so it does not terminate and the heap \
                 cannot be bounded from it",
                current.address()
            )));
        }
        let start = match layout.read_unsigned(&current, "vm_start")? {
            Field::Known(value) => value,
            other => {
                return Ok(Err(format!(
                    "a memory area's start could not be read ({}), so the heap cannot be bounded",
                    other.kind()
                )))
            }
        };
        let end = match layout.read_unsigned(&current, "vm_end")? {
            Field::Known(value) => value,
            other => {
                return Ok(Err(format!(
                    "a memory area's end could not be read ({}), so the heap cannot be bounded",
                    other.kind()
                )))
            }
        };
        if start <= brk && end >= start_brk && end > start {
            areas.push((start, end));
        }
        let next_path = layout
            .member("vm_next")?
            .member()
            .expect("a required member is declared or binding refused the stage");
        current = match current.follow(next_path) {
            Ok(Some(next)) => next,
            Ok(None) => return Ok(Ok(areas)),
            Err(err) => return Ok(Err(err.to_string())),
        };
    }
    Ok(Err(format!(
        "the memory-area list did not end within {} areas, so the heap cannot be bounded from it",
        config.max_vmas
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hist_entry_is_three_pointers_with_the_timestamp_second() {
        let layout = HistEntryLayout::new(8);
        assert_eq!(layout.line_offset(), 0);
        assert_eq!(layout.timestamp_offset(), 8);
        assert_eq!(layout.size(), 24);

        let layout = HistEntryLayout::new(4);
        assert_eq!(layout.timestamp_offset(), 4);
        assert_eq!(layout.size(), 12);
    }

    /// The check that turns a byte scan into evidence. Anything looser makes the
    /// stage a list of coincidences that happen to sit next to a `#`.
    #[test]
    fn only_a_hash_followed_by_digits_is_a_history_timestamp() {
        assert_eq!(parse_history_timestamp("#1403606200"), Some(1_403_606_200));
        assert_eq!(parse_history_timestamp("#999999999"), Some(999_999_999));

        assert_eq!(parse_history_timestamp("#12345"), None, "too short");
        assert_eq!(parse_history_timestamp("1403606200"), None, "no marker");
        assert_eq!(parse_history_timestamp("#14036062xx"), None, "not digits");
        assert_eq!(parse_history_timestamp("#-403606200"), None, "not digits");
        assert_eq!(parse_history_timestamp("# 403606200"), None, "not digits");
        assert_eq!(parse_history_timestamp("#"), None);
        assert_eq!(parse_history_timestamp(""), None);
    }

    #[test]
    fn a_pointer_is_read_at_the_declared_width_and_byte_order() {
        assert_eq!(
            read_pointer(&[0x40, 0x47, 0x99, 0x1F, 0x00, 0x88, 0xFF, 0xFF]),
            0xFFFF_8800_1F99_4740
        );
        assert_eq!(read_pointer(&[0x01, 0x02, 0x03, 0x04]), 0x0403_0201);
    }

    fn history(outcome: BashOutcome) -> ShellHistory {
        ShellHistory {
            task_address: 0xFFFF_8800_1F99_4740,
            pid: Field::Known(3976),
            comm: Field::Known("bash".into()),
            commands: vec![BashCommand {
                entry_address: 0x1F0_0000,
                timestamp_unix: 1_403_606_200,
                timestamp_rfc3339: Some("2014-06-24T10:36:40+00:00".into()),
                command: "sudo bash".into(),
                command_well_formed: true,
            }],
            outcome,
        }
    }

    fn survey(shells: Vec<ShellHistory>, name_unknown: usize, listed: bool) -> BashSurvey {
        BashSurvey {
            shells,
            layout: serde_json::json!({}),
            not_a_shell: 127,
            name_unknown,
            inventory: TaskInventory {
                head: 0xFFFF_FFFF_8160_D190,
                listed: 133,
                complete: listed,
                incomplete: if listed {
                    Vec::new()
                } else {
                    vec![Incomplete::new(
                        IncompleteReason::CapReached,
                        "the walk stopped at its cap",
                    )]
                },
            },
        }
    }

    #[test]
    fn a_fully_searched_shell_over_a_full_task_list_is_complete() {
        let s = survey(
            vec![history(BashOutcome::Searched {
                bytes: 0x2_0000,
                areas: 1,
            })],
            0,
            true,
        );
        assert!(s.is_complete());
        assert!(s.incomplete().is_empty());
        assert_eq!(s.command_count(), 1);
    }

    /// A process whose name could not be read might have been a shell. Folding
    /// it into "not a shell" would shrink the set of things that were looked at
    /// without saying so.
    #[test]
    fn a_process_whose_name_could_not_be_read_makes_the_survey_incomplete() {
        let s = survey(
            vec![history(BashOutcome::Searched {
                bytes: 0x2_0000,
                areas: 1,
            })],
            2,
            true,
        );
        assert!(!s.is_complete());
        let reasons = s.incomplete();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].detail.contains("whether they were shells"));
    }

    #[test]
    fn a_heap_that_was_only_partly_captured_makes_the_survey_incomplete() {
        let s = survey(
            vec![history(BashOutcome::PartiallySearched {
                read: 0x1000,
                unread: 0x1000,
            })],
            0,
            true,
        );
        assert!(!s.is_complete());
        assert_eq!(s.incomplete().len(), 1);
    }

    /// The record must state that shells are selected by name, because that is
    /// the difference between "no commands were run" and "no process called
    /// bash, sh or dash was on the list".
    #[test]
    fn the_survey_states_that_shells_are_selected_by_name() {
        let s = survey(Vec::new(), 0, true);
        let json = s.to_json();
        assert_eq!(json["shell_count"], 0);
        assert_eq!(json["command_count"], 0);
        assert_eq!(json["not_a_shell"], 127);
        let note = json["selection_note"].as_str().expect("a note");
        assert!(
            note.contains("not a statement that no commands were run"),
            "{note}"
        );
    }

    #[test]
    fn every_outcome_reads_as_a_sentence_and_grades_itself() {
        for outcome in [
            BashOutcome::Searched { bytes: 1, areas: 1 },
            BashOutcome::PartiallySearched { read: 1, unread: 1 },
            BashOutcome::NotRead(SpaceRefusal::NoUserAddressSpace),
            BashOutcome::HeapUnbounded("x".into()),
            BashOutcome::NoHeap,
            BashOutcome::CapReached { cap: 10 },
        ] {
            assert!(!outcome.class().is_empty());
            assert!(!outcome.detail().is_empty());
            assert_eq!(outcome.to_json()["is_a_gap"], outcome.is_a_gap());
        }
    }

    #[test]
    fn every_key_the_stage_reads_is_a_key_the_stage_declared() {
        const READ_KEYS: &[&str] = &[
            "mm",
            "pgd",
            "mmap",
            "brk",
            "start_brk",
            "vm_start",
            "vm_end",
            "vm_next",
        ];
        for key in READ_KEYS {
            assert!(
                BASH_LAYOUT.members.iter().any(|spec| spec.key == *key),
                "{key} is read by the stage and declared nowhere"
            );
        }
        assert_eq!(BASH_LAYOUT.members.len(), READ_KEYS.len());
        assert_eq!(BASH_LAYOUT.stage.key, STAGE_LINUX_BASH_HISTORY.key);
    }

    /// The maple-tree refusal is the one place this stage says "this tool cannot
    /// read that kernel". It must say so in those terms and not as a finding.
    #[test]
    fn the_maple_tree_refusal_is_phrased_as_a_tool_limit() {
        let spec = BASH_LAYOUT
            .members
            .iter()
            .find(|spec| spec.key == "mmap")
            .expect("declared");
        let seance_memory::binding::Necessity::Required { without_it } = spec.necessity else {
            panic!("the mmap walk is what locates the heap and must be required");
        };
        assert!(without_it.contains("mm_mt"), "{without_it}");
        assert!(
            without_it.contains("limit of this tool"),
            "a tool limit must never be phrased as a finding about the machine: {without_it}"
        );
    }
}
