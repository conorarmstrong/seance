//! A second way to find processes, so the first one can be checked.
//!
//! # Why this exists
//!
//! [`crate::tasks`] enumerates processes by walking the kernel's task list from
//! `init_task`. That is how the kernel itself enumerates them, and it is exact
//! — for every process still on the list. Unlinking a `task_struct` from that
//! list is the standard way of hiding a process on Linux: the scheduler holds
//! its own references, so the process goes on running, and the walk simply does
//! not reach it.
//!
//! A list walk cannot detect that. Nothing about a correct traversal of a
//! doubly-linked list reveals an entry that was removed from it. The only way
//! to find such a process is to look for the structure itself, without
//! following anybody's pointers to it — which is what this does.
//!
//! Séance's Windows tier has had this for a long time (`poolscan`, `psxview`),
//! and its parity test asserts the two views agree. This closes the same gap on
//! Linux.
//!
//! # What makes a candidate believable
//!
//! Scanning raw memory for a structure means deciding, for arbitrary bytes,
//! whether they are a `task_struct`. Getting that wrong in either direction is
//! costly: a missed process defeats the point, and a fabricated one puts a
//! process that never existed in front of an examiner. So the test is
//! deliberately conservative and every criterion is structural rather than
//! statistical:
//!
//! 1. **`comm` is a plausible process name.** Up to 15 printable bytes then a
//!    NUL, within the kernel's `TASK_COMM_LEN` of 16. This is the cheapest
//!    filter and rejects almost everything.
//! 2. **`pid` and `tgid` are plausible.** Non-negative, within
//!    `PID_MAX_LIMIT`, and `tgid` is either equal to `pid` (a thread-group
//!    leader) or another plausible id.
//! 3. **The list links are self-consistent.** `tasks.next->prev` points back at
//!    this structure's own link member. That is the invariant a doubly-linked
//!    list holds by construction, and it is the criterion that raw bytes will
//!    not satisfy by chance: it requires two pointers, sixteen bytes apart in
//!    the candidate, to agree with a third pointer somewhere else entirely.
//!
//! An **unlinked** process fails (3) by definition — that is what unlinking
//! means. It is therefore accepted on (1) and (2) plus a fourth condition: the
//! structure sits at a plausible kernel address and its `comm` is well-formed.
//! Such a candidate is reported with a lower confidence, because the check that
//! makes the others solid is exactly the one it cannot pass.
//!
//! # What this establishes, and what it deliberately does not
//!
//! **It corroborates the task list.** Measured against a real 15 GiB capture it
//! independently confirms **576 of 587** processes, sweeping the whole image
//! without truncating. A process both methods found is one whose presence does
//! not rest on the task list being honest, and that is what the process stage
//! now records.
//!
//! **It does not enumerate hidden processes, and says so.** The same sweep also
//! matches several thousand structures that are not tasks — page-cache text
//! that happens to sit at the right offsets. Reporting each as a candidate
//! hidden process would put thousands of unfounded findings in a report and
//! bury any real one, so [`CrossView`] counts them and refuses to report them,
//! and the artifact states plainly that an unlinked process would NOT be
//! surfaced. Counting the noise and hiding the noise are the same decision.
//!
//! # What it took to correlate at all
//!
//! The first version of this module was wired in and reverted. It matched 11 of
//! 587 processes and reported 65,514 structures as absent from the task list,
//! every one of those rows saying it was what a hidden process looks like. Four
//! separate causes, each found only by measuring against real evidence:
//!
//! 1. **The addresses were incomparable.** The sweep reported physical offsets
//!    and the list reports virtual addresses. [`calibrate_direct_map`] now
//!    measures the conversion from the evidence rather than assuming a constant
//!    KASLR moves, requiring several list entries to agree and refusing if two
//!    disagree.
//! 2. **The sweep skipped most of memory.** It read fixed windows and abandoned
//!    any window whose read spanned a hole, which on a capture with 256,330
//!    segments is nearly all of them. It now sweeps the layer's mapped
//!    sections.
//! 3. **`comm` alone admitted ordinary text.** It accepted anything printable,
//!    and on a machine that stores mail it matched **maildir filenames** out of
//!    the page cache — `,W=11420:2,S`, `W=1996:2,Sa` — tens of thousands of
//!    them. [`plausible_comm`] now accepts only the characters a program name
//!    actually contains.
//! 4. **The identifiers were too permissive.** PID 0 belongs to the idle task
//!    and to nothing else, and a one-character program name essentially does
//!    not occur, while a single printable byte followed by a NUL is everywhere
//!    in memory. Both are now required.
//!
//! Correlation across those fixes: **11 → 0 → 198 → 236 → 576** of 587. Every
//! number came from the capture, and every intermediate one looked like progress
//! while the thing was still unusable — which is why the real-capture test
//! asserts the correlation itself rather than that the code ran.
//!
//! # What this is not
//!
//! It is not a replacement for the list walk, and it is not more trustworthy
//! than one. It is a *different* method whose failures would be uncorrelated
//! with the list walk's, which is the only property that would make a
//! cross-view worth having.

use crate::profile::LinuxProfile;
use crate::tasks::{TaskList, TaskRecord};
use seance_memory::binding::BuildBinding;
use serde_json::json;

/// The kernel's `TASK_COMM_LEN`: 15 characters plus the NUL.
pub const TASK_COMM_LEN: usize = 16;

/// `PID_MAX_LIMIT` on 64-bit Linux — the ceiling `pid_max` may be raised to.
///
/// A candidate whose id exceeds this is not a process id, whatever else it may
/// be.
pub const PID_MAX_LIMIT: i64 = 4 * 1024 * 1024;

/// `LIST_POISON1` on x86-64: what `list_del` writes into `next`.
///
/// `include/linux/poison.h` defines it as `0x100 + POISON_POINTER_DELTA`, and
/// `POISON_POINTER_DELTA` is `CONFIG_ILLEGAL_POINTER_VALUE`, which x86-64
/// defaults to `0xdead000000000000`.
pub const LIST_POISON1: u64 = 0xdead_0000_0000_0100;

/// `LIST_POISON2` — what `list_del` writes into `prev`.
pub const LIST_POISON2: u64 = 0xdead_0000_0000_0122;

/// The lowest address the kernel's half of the canonical space begins at.
///
/// Every pointer inside a `task_struct`'s list links is a kernel address, so a
/// value below this is not one and the candidate is not a task.
pub const KERNEL_SPACE_FLOOR: u64 = 0xffff_0000_0000_0000;

/// How sure the scan is that a candidate is a real `task_struct`.
///
/// Grades, not a score. A number would imply a precision this has no basis for,
/// and an examiner reading "0.82" would have no way to act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// The list links are self-consistent: the entry `tasks.next` points at
    /// points back here. Arbitrary memory does not satisfy that by chance —
    /// it requires a pointer in the candidate to name a location whose own
    /// pointer names the candidate back.
    LinksConsistent,
    /// The links carry `LIST_POISON1`/`LIST_POISON2` — the exact values
    /// `list_del` writes.
    ///
    /// This is not a weaker grade than [`Confidence::LinksConsistent`]; it is a
    /// **different finding**. The structure is certainly a `task_struct`,
    /// because nothing else has those two constants sixteen bytes apart, and it
    /// was certainly removed from the task list by `list_del`. What that does
    /// not settle is *why*: a process that exited leaves the same trace as one
    /// a rootkit unlinked.
    Unlinked,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::LinksConsistent => "links_consistent",
            Confidence::Unlinked => "unlinked_list_poison",
        }
    }

    /// What this grade means, for a record an examiner reads.
    pub fn meaning(self) -> &'static str {
        match self {
            Confidence::LinksConsistent => {
                "The structure's own list links are self-consistent: the entry it points \
                 forward to points back at it. Arbitrary memory does not satisfy that by \
                 chance, so this is a task_struct."
            }
            Confidence::Unlinked => {
                "This structure's list links hold LIST_POISON1 and LIST_POISON2 — the exact \
                 values the kernel's `list_del` writes when it removes an entry from a list. \
                 So it is certainly a task_struct, and it was certainly removed from the task \
                 list. What that does NOT establish is why: a process that exited normally \
                 leaves the same trace as one deliberately unlinked to hide it. Treat it as a \
                 structure worth explaining, not as proof of either."
            }
        }
    }
}

/// One structure the scan believes is a `task_struct`.
#[derive(Debug, Clone)]
pub struct ScannedTask {
    /// Where it was found, in the kernel address space.
    pub address: u64,
    /// The process name, as read.
    pub comm: String,
    /// `task_struct.pid` — the thread id.
    pub tid: i64,
    /// `task_struct.tgid` — what an examiner calls the PID.
    pub pid: i64,
    /// How sure the scan is.
    pub confidence: Confidence,
}

impl ScannedTask {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "comm": self.comm,
            "tid": self.tid,
            "pid": self.pid,
            "confidence": self.confidence.as_str(),
            "confidence_meaning": self.confidence.meaning(),
        })
    }
}

/// Whether `bytes` are a plausible `comm`.
///
/// The kernel writes a NUL-terminated name into a 16-byte field and does not
/// clear what was there before, so trailing rubbish after the NUL is normal and
/// is ignored. What must hold is that the name itself is printable and
/// non-empty: a process with an unprintable name is possible in principle, and
/// accepting one here would admit most of memory.
pub fn plausible_comm(bytes: &[u8]) -> Option<String> {
    if bytes.len() < TASK_COMM_LEN {
        return None;
    }
    let end = bytes[..TASK_COMM_LEN].iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    let name = &bytes[..end];
    if !name.iter().all(|&b| comm_character(b)) {
        return None;
    }
    Some(String::from_utf8_lossy(name).into_owned())
}

/// Whether a byte can appear in a `comm`.
///
/// # Why this is a list and not `is_ascii_graphic`
///
/// It was `is_ascii_graphic`, and on a real capture the scan matched **maildir
/// filenames** out of the page cache — `,W=11420:2,S`, `W=1996:2,Sa`,
/// `-2-37:2,Sc`. They are printable, they are NUL-terminated inside sixteen
/// bytes, and there were tens of thousands of them on a machine that stores
/// mail. Every one became a candidate hidden process.
///
/// A `comm` is not arbitrary printable text. The kernel takes it from the
/// executable's basename, or a driver writes a fixed name for a kernel thread,
/// so the characters that actually occur are those of a program name:
/// `systemd`, `kworker/R-rcu_g`, `pool_workqueue_`, `irq/9-acpi`,
/// `systemd-journal`, `[kthreadd]`.
///
/// Parentheses are admitted: systemd names its pre-exec helpers `(sd-pam)`,
/// `(sd-executor)` and `(sd-sync)` with `prctl(PR_SET_NAME)`, and refusing them
/// left a live `(sd-pam)` and its parent out of the scan on a real capture.
///
/// Excluding `,` `=` `"` and the shell punctuation costs nothing real and
/// removes the class of text that dominated the false positives. It is a
/// filter on what Linux writes, not a guess about what looks name-like.
fn comm_character(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'_' | b'-' | b'/' | b'.' | b':' | b'[' | b']' | b'+' | b'~' | b'#' | b'(' | b')'
        )
}

/// Whether an identifier could be a Linux pid.
pub fn plausible_pid(value: i64) -> bool {
    (0..=PID_MAX_LIMIT).contains(&value)
}

/// Whether `pid`/`tgid` are a plausible pair.
///
/// A thread-group leader has `pid == tgid`; a thread has `tgid` naming its
/// leader, which is a *lower or equal* id because the leader was created first.
/// A `tgid` above its own `pid` is not a pairing the kernel produces.
pub fn plausible_id_pair(tid: i64, tgid: i64) -> bool {
    plausible_pid(tid) && plausible_pid(tgid) && tgid <= tid
}

/// What the cross-view concluded about one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossViewVerdict {
    /// Both methods found it. The ordinary case.
    Both,
    /// The list walk found it and the scan did not.
    ///
    /// Not a finding about the process: the scan covers the region it was given
    /// and a `task_struct` outside that region is simply out of its reach.
    ListOnly,
    /// The scan found it and the list walk did not.
    ///
    /// **This is the one worth an examiner's attention.** It is what an
    /// unlinked — hidden — process looks like. It is also what a stale remnant
    /// of an exited process looks like, and the verdict says so rather than
    /// asserting the alarming reading.
    ScanOnly,
}

impl CrossViewVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            CrossViewVerdict::Both => "both",
            CrossViewVerdict::ListOnly => "list_only",
            CrossViewVerdict::ScanOnly => "scan_only",
        }
    }

    pub fn meaning(self) -> &'static str {
        match self {
            CrossViewVerdict::Both => {
                "Both the task-list walk and the independent scan found this process."
            }
            CrossViewVerdict::ListOnly => {
                "The task-list walk found this process and the scan did not. That is not a \
                 finding about the process: the scan examines the region it was given, and a \
                 structure outside that region is out of its reach."
            }
            CrossViewVerdict::ScanOnly => {
                "An independent scan found this structure and the kernel's task list does not \
                 contain it. A process UNLINKED from the task list looks exactly like this, \
                 and so does a stale remnant of a process that has exited. This is worth \
                 examining; it is not by itself proof of either."
            }
        }
    }
}

/// One process, as both methods saw it.
#[derive(Debug, Clone)]
pub struct CrossViewRow {
    pub address: u64,
    pub comm: Option<String>,
    pub pid: Option<i64>,
    pub verdict: CrossViewVerdict,
    /// The scan's confidence, when the scan found it.
    pub scan_confidence: Option<Confidence>,
}

impl CrossViewRow {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "comm": self.comm,
            "pid": self.pid,
            "verdict": self.verdict.as_str(),
            "verdict_meaning": self.verdict.meaning(),
            "scan_confidence": self.scan_confidence.map(Confidence::as_str),
        })
    }
}

/// Correlate a list walk against a scan.
///
/// Keyed on the structure's address, which is the one identifier both methods
/// establish independently and neither can be mistaken about: the list walk
/// reached it by following a pointer to it, and the scan found the bytes
/// sitting there.
pub fn cross_view(list: &TaskList, scanned: &[ScannedTask]) -> Vec<CrossViewRow> {
    use std::collections::BTreeMap;

    let mut rows: BTreeMap<u64, CrossViewRow> = BTreeMap::new();

    for task in &list.tasks {
        rows.insert(
            task.address,
            CrossViewRow {
                address: task.address,
                comm: task_comm(task),
                pid: task_pid(task),
                verdict: CrossViewVerdict::ListOnly,
                scan_confidence: None,
            },
        );
    }

    for found in scanned {
        rows.entry(found.address)
            .and_modify(|row| {
                row.verdict = CrossViewVerdict::Both;
                row.scan_confidence = Some(found.confidence);
            })
            .or_insert_with(|| CrossViewRow {
                address: found.address,
                comm: Some(found.comm.clone()),
                pid: Some(found.pid),
                verdict: CrossViewVerdict::ScanOnly,
                scan_confidence: Some(found.confidence),
            });
    }

    rows.into_values().collect()
}

fn task_comm(task: &TaskRecord) -> Option<String> {
    match &task.comm {
        seance_memory::binding::Field::Known(name) => Some(name.clone()),
        _ => None,
    }
}

fn task_pid(task: &TaskRecord) -> Option<i64> {
    match &task.pid {
        seance_memory::binding::Field::Known(value) => Some(*value),
        _ => None,
    }
}

/// Everything the cross-view establishes, ready for an artifact.
#[derive(Debug, Clone)]
pub struct CrossView {
    pub rows: Vec<CrossViewRow>,
    /// Structures the scan found that the list does not contain.
    pub scan_only: usize,
    /// Whether the scan ran at all. A cross-view over a scan that did not run
    /// is not a corroboration and must not read as one.
    pub scan_ran: bool,
}

impl CrossView {
    pub fn build(list: &TaskList, scanned: &[ScannedTask], scan_ran: bool) -> Self {
        let rows = cross_view(list, scanned);
        let scan_only = rows
            .iter()
            .filter(|r| r.verdict == CrossViewVerdict::ScanOnly)
            .count();
        Self {
            rows,
            scan_only,
            scan_ran,
        }
    }

    /// Processes the list found that the scan independently confirmed.
    pub fn corroborated(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.verdict == CrossViewVerdict::Both)
            .count()
    }

    /// Processes the list walk reported, corroborated or not.
    pub fn from_list(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.verdict != CrossViewVerdict::ScanOnly)
            .count()
    }

    /// **Only the rows the list walk also found.**
    ///
    /// Scan-only structures are deliberately excluded — see the
    /// `hidden_process_detection` key in [`Self::to_json`] for why reporting
    /// them individually would be worse than reporting nothing.
    fn reportable_rows(&self) -> Vec<serde_json::Value> {
        self.rows
            .iter()
            .filter(|r| r.verdict != CrossViewVerdict::ScanOnly)
            .map(CrossViewRow::to_json)
            .collect()
    }

    pub fn to_json(&self) -> serde_json::Value {
        let corroborated = self.corroborated();
        let from_list = self.from_list();
        json!({
            "scan_ran": self.scan_ran,
            "rows": self.reportable_rows(),
            "processes_from_list": from_list,
            "corroborated_by_scan": corroborated,
            "corroboration_note": if self.scan_ran {
                "Each process in the kernel's task list was looked for a second time by \
                 scanning physical memory for task_struct signatures, independently of the \
                 list. A process both methods found is one whose presence does not rest on \
                 the task list being honest."
            } else {
                "No independent scan ran, so this list is NOT corroborated. A process unlinked \
                 from the kernel's task list would not appear in it and nothing here would \
                 show that."
            },
            // The count is reported and the structures are not, and the two
            // decisions are the same decision.
            "scan_only_count": self.scan_only,
            "hidden_process_detection": if self.scan_ran {
                "NOT PERFORMED. This scan corroborates the task list; it does NOT enumerate \
                 processes hidden from it. Measured against a known-good capture the signature \
                 confirmed 576 of 587 real processes but also matched several thousand \
                 structures that are not tasks — page-cache text that happens to sit at the \
                 right offsets. Listing those as candidate hidden processes would bury any \
                 real one and put thousands of unfounded findings in a report, so \
                 `scan_only_count` is given as a measure of the scan's noise and the \
                 structures behind it are deliberately not reported as findings. A process \
                 unlinked from the task list would therefore NOT be surfaced here."
            } else {
                "NOT PERFORMED: no scan ran."
            },
        })
    }
}

/// Read the `comm` and identifiers a candidate would have, if it is a task.
///
/// Split from the scan itself so the decision can be tested against bytes
/// without an address space.
pub fn candidate_from_bytes(
    bytes: &[u8],
    comm_offset: usize,
    pid_offset: usize,
    tgid_offset: usize,
) -> Option<(String, i64, i64)> {
    let comm = plausible_comm(bytes.get(comm_offset..)?)?;
    let tid = read_i32(bytes, pid_offset)?;
    let tgid = read_i32(bytes, tgid_offset)?;
    if !plausible_id_pair(tid, tgid) || !ids_match_the_name(&comm, tid) {
        return None;
    }
    Some((comm, tid, tgid))
}

/// Whether a name and a thread id can belong to the same task.
///
/// # The two constraints, and what each removed
///
/// **PID 0 is the idle task.** The kernel gives it to `swapper/N` and to
/// nothing else, so a structure carrying `pid == 0` under any other name is not
/// a task. On a real capture the surviving false positives were overwhelmingly
/// of this shape — `h`, `01`, `N`, `9`, `G`, all with `tid == 0`.
///
/// **A `comm` of one character.** The kernel takes it from an executable's
/// basename, and single-character program names essentially do not occur on a
/// running system, while single printable characters followed by a NUL are
/// everywhere in memory. Real short names — `sh`, `ps`, `vi` — are two.
///
/// Both are constraints on what Linux writes, not guesses about what looks
/// plausible, which is why they can be applied without weakening a real finding.
fn ids_match_the_name(comm: &str, tid: i64) -> bool {
    if tid == 0 && !comm.starts_with("swapper") {
        return false;
    }
    comm.chars().count() >= 2
}

fn read_i32(bytes: &[u8], at: usize) -> Option<i64> {
    let slice = bytes.get(at..at.checked_add(4)?)?;
    Some(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as i64)
}

/// What the candidate's own list links say about it, before any pointer is
/// followed.
///
/// Split out so the decision is testable against bytes alone. Following
/// `next` needs an address space; deciding whether it is worth following does
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkShape {
    /// Both pointers are the poison values `list_del` writes.
    Poisoned,
    /// Both pointers are plausible kernel addresses. `next` is worth following
    /// to see whether it points back.
    Kernel { next: u64, prev: u64 },
    /// Neither. These are not a `list_head`'s pointers, so the candidate is not
    /// a `task_struct` however plausible its name looked.
    NotLinks,
}

/// Classify a candidate's `tasks` list links.
///
/// This is what makes the scan usable. `comm` plus a plausible identifier pair
/// admits far too much — measured on a real capture it produced 65,525
/// candidates and filled its own cap before reaching the memory where the real
/// `task_struct`s live, so the scan found none of them. A `list_head` whose two
/// pointers are both canonical kernel addresses, or both exactly the kernel's
/// poison constants, is a far narrower thing.
pub fn classify_links(bytes: &[u8], tasks_offset: usize) -> LinkShape {
    let Some(window) = bytes.get(tasks_offset..tasks_offset.saturating_add(16)) else {
        return LinkShape::NotLinks;
    };
    let next = u64::from_le_bytes(window[..8].try_into().expect("eight bytes"));
    let prev = u64::from_le_bytes(window[8..16].try_into().expect("eight bytes"));

    if next == LIST_POISON1 && prev == LIST_POISON2 {
        return LinkShape::Poisoned;
    }
    // Both must be kernel pointers, and pointer-aligned: a `list_head` lives
    // inside a structure the allocator aligned, so an odd address is not one.
    if next >= KERNEL_SPACE_FLOOR && prev >= KERNEL_SPACE_FLOOR && next % 8 == 0 && prev % 8 == 0 {
        return LinkShape::Kernel { next, prev };
    }
    LinkShape::NotLinks
}

/// Whether `next` really is the next **task** in the task list.
///
/// # Why `next->prev == self` is not enough on its own
///
/// It proves the candidate sits in *a* doubly-linked list. The kernel is built
/// out of them — every one of its lists satisfies that invariant by
/// construction — so on a real capture 65,490 structures passed it, the scan
/// filled its own cap, and it stopped having examined a fraction of memory.
///
/// So this asks the question that distinguishes a task list from every other
/// list: `tasks.next` in a `task_struct` points at the `tasks` member of
/// **another `task_struct`**. Back up from it by the same member offset and the
/// bytes there must themselves read as a process — a plausible `comm` and a
/// plausible identifier pair. A `list_head` belonging to anything else does not
/// have a process name at that distance from it.
///
/// # What a `false` means
///
/// That the link was not corroborated — never that the structure is fake. A
/// neighbour outside the acquisition reads nothing, and an unreadable neighbour
/// is not evidence about the candidate.
///
/// # Two mappings
///
/// `next` is tried in the direct map first, where every slab-allocated task
/// lives, and then — when the caller knows it — in the kernel image mapping,
/// where `init_task` lives. The last task on the list links forward to
/// `init_task`, so without the second try that task is never corroborated.
/// Both tries demand the same back-pointer and the same task-shaped
/// neighbour, so the second mapping widens what can be reached, not what is
/// accepted.
fn next_is_a_task(
    physical: &dyn seance_memory::layer::MemoryLayer,
    kernel_base: u64,
    image_shift: Option<u64>,
    offsets: ScanOffsets,
    next: u64,
    mine: u64,
) -> bool {
    [Some(kernel_base), image_shift]
        .into_iter()
        .flatten()
        .filter_map(|base| next.checked_sub(base))
        .any(|next_phys| neighbour_is_a_task(physical, offsets, next_phys, mine))
}

/// The half of [`next_is_a_task`] that works on one physical address.
fn neighbour_is_a_task(
    physical: &dyn seance_memory::layer::MemoryLayer,
    offsets: ScanOffsets,
    next_phys: u64,
    mine: u64,
) -> bool {
    // `list_head` is { next, prev }; `prev` is the second pointer. The
    // doubly-linked invariant first, because it costs one 8-byte read.
    let mut back = [0u8; 8];
    if seance_core::io::read_full(
        physical.as_data_source(),
        next_phys.wrapping_add(8),
        &mut back,
    ) != 8
        || u64::from_le_bytes(back) != mine
    {
        return false;
    }

    // Now the question that separates the task list from every other list:
    // is the structure containing that link a task_struct?
    let Some(neighbour) = next_phys.checked_sub(offsets.tasks as u64) else {
        return false;
    };
    let mut buf = vec![0u8; offsets.size];
    if seance_core::io::read_full(physical.as_data_source(), neighbour, &mut buf) != offsets.size {
        return false;
    }
    candidate_from_bytes(&buf, offsets.comm, offsets.pid, offsets.tgid).is_some()
}

/// Offsets the scan needs, taken from the build's own layout.
///
/// Resolved once rather than per candidate: a scan that re-resolved a member
/// for every address in a 15 GiB image would spend its whole time in the symbol
/// table.
#[derive(Debug, Clone, Copy)]
pub struct ScanOffsets {
    pub comm: usize,
    pub pid: usize,
    pub tgid: usize,
    pub tasks: usize,
    pub size: usize,
}

impl ScanOffsets {
    /// Resolve from a bound layout, or say which member was missing.
    pub fn resolve(layout: &BuildBinding, task_size: u64) -> Option<Self> {
        fn at(layout: &BuildBinding, key: &'static str) -> Option<usize> {
            layout.member(key).ok()?.offset().map(|o| o as usize)
        }
        Some(Self {
            comm: at(layout, "comm")?,
            pid: at(layout, "pid")?,
            tgid: at(layout, "tgid")?,
            tasks: at(layout, "tasks")?,
            size: task_size as usize,
        })
    }
}

/// Whether the profile is one this scan can run against.
pub fn can_scan(profile: &LinuxProfile) -> bool {
    profile.pointer_size() == 8
}

/// The constant that turns a physical offset into the virtual address the
/// kernel uses for it.
///
/// # Why this is derived rather than assumed
///
/// The scan works in physical space, because that is where every structure is
/// exactly once and where an unlinked one is still findable. The list walk
/// works in virtual space, because every pointer in a kernel list is a virtual
/// address. Correlating the two needs one to be expressed in the other's terms.
///
/// Linux maps all of physical memory linearly at `page_offset_base`, so a
/// single addition converts between them — but that base moves with KASLR and
/// differs by configuration, so it cannot be a constant in this file.
///
/// It is instead **measured from the evidence**: take a `task_struct` the list
/// walk already found, translate its virtual address through the page tables to
/// a physical one, and the difference is the offset. `task_struct` is slab
/// memory and slab memory lives in the direct map, so the relation holds for
/// every candidate the scan will find.
///
/// Measuring it from one entry and *checking* it against others is what makes
/// this safe: a wrong offset does not produce a subtly wrong answer, it
/// produces no correlation at all, and the check catches that before any
/// finding is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectMapOffset(pub u64);

impl DirectMapOffset {
    /// Convert a physical offset to the kernel virtual address for it.
    pub fn to_virtual(self, physical: u64) -> u64 {
        self.0.wrapping_add(physical)
    }
}

/// How many list entries must agree before the offset is trusted.
///
/// One could be a coincidence. Requiring several, and requiring them to agree
/// with each other, is what distinguishes a measured constant from a guess.
const CALIBRATION_AGREEMENTS: usize = 3;

/// Measure the direct-map offset, or return `None` and let the caller decline
/// to cross-view at all.
///
/// `None` is not a failure to be worked around. Reporting a cross-view built on
/// an offset that could not be established would compare virtual addresses
/// against physical ones — which never match, so every process the scan found
/// would be reported as absent from the list, and every one of those rows says
/// it is what a hidden process looks like. That is not a degraded answer, it is
/// tens of thousands of false accusations.
pub fn calibrate_direct_map(profile: &LinuxProfile, list: &TaskList) -> Option<DirectMapOffset> {
    let mut agreed: Option<u64> = None;
    let mut agreements = 0usize;

    for task in list.tasks.iter().take(64) {
        // The page tables say where this virtual address really lives.
        let Ok(runs) = profile.kernel_space.mapping(task.address, 1) else {
            continue;
        };
        let Some(run) = runs.first() else { continue };
        // The offset within the page has to be preserved for the subtraction to
        // mean anything, and `mapping` reports the run's start rather than the
        // exact byte, so recover it.
        let page_offset = task.address - run.offset;
        let physical = run.mapped_offset + page_offset;
        let candidate = task.address.wrapping_sub(physical);

        match agreed {
            None => {
                agreed = Some(candidate);
                agreements = 1;
            }
            Some(existing) if existing == candidate => {
                agreements += 1;
                if agreements >= CALIBRATION_AGREEMENTS {
                    return Some(DirectMapOffset(existing));
                }
            }
            Some(_) => {
                // Two entries disagree about the offset, so it is not the
                // linear relation this assumes. Refuse rather than pick one.
                return None;
            }
        }
    }
    None
}

/// Corroborate a task-list walk with an independent sweep of physical memory,
/// the way the analysis module runs it.
///
/// A scan that cannot run yields a cross-view saying so rather than nothing:
/// "checked and agreed" and "not checked" must never render alike. Every early
/// return here is that case.
pub fn corroborate_list(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    list: &TaskList,
) -> CrossView {
    let uncorroborated = || CrossView::build(list, &[], false);

    if !can_scan(profile) {
        return uncorroborated();
    }
    let Ok(size) = profile.symbols.size_of("task_struct") else {
        return uncorroborated();
    };
    let Some(offsets) = ScanOffsets::resolve(layout, size) else {
        return uncorroborated();
    };
    // The sweep works in physical space and the list in virtual space. Without
    // this constant the two sets of addresses cannot be compared at all, and
    // every process would read as uncorroborated.
    let Some(direct_map) = calibrate_direct_map(profile, list) else {
        return uncorroborated();
    };
    let outcome = scan_physical(
        profile.physical.as_ref(),
        offsets,
        direct_map.0,
        &ScanConfig {
            // `init_task` is in the kernel image, not the direct map; the
            // profile's proved shift is that mapping's constant.
            image_shift: Some(profile.kernel_shift.value.shift),
            ..ScanConfig::default()
        },
    );
    CrossView::build(list, &outcome.tasks, true)
}

/// How much of the image to sweep, and what to spend doing it.
#[derive(Debug, Clone, Copy)]
pub struct ScanConfig {
    /// Bytes to sweep before stopping. A capture is larger than the region a
    /// `task_struct` can be in, and a scan that ran to the end of a 15 GiB
    /// image would cost minutes for nothing.
    pub max_bytes: u64,
    /// Candidates to report before stopping. A cap that fires is stated.
    pub max_candidates: usize,
    /// `virtual - physical` of the kernel **image** mapping (the profile's
    /// proved kernel shift), when known.
    ///
    /// Slab-allocated tasks sit in the direct map, but `init_task` is a static
    /// in the kernel image, and the image is mapped at a different base. The
    /// last task on the list links forward to `init_task`, so without this its
    /// neighbour check cannot land and a live process reads as out of the
    /// scan's reach.
    pub image_shift: Option<u64>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_bytes: 16 * 1024 * 1024 * 1024,
            max_candidates: 65_536,
            image_shift: None,
        }
    }
}

/// What a sweep produced.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub tasks: Vec<ScannedTask>,
    /// Bytes actually examined.
    pub bytes_scanned: u64,
    /// True when a cap stopped the sweep before it covered the image. A capped
    /// sweep establishes nothing about what it did not reach, and a cross-view
    /// built on one must not read as exhaustive.
    pub truncated: bool,
}

impl ScanOutcome {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "count": self.tasks.len(),
            "bytes_scanned": self.bytes_scanned,
            "truncated": self.truncated,
            "tasks": self.tasks.iter().map(ScannedTask::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Sweep physical memory for `task_struct` signatures.
///
/// Physical rather than virtual, deliberately: a structure unlinked from the
/// task list is still mapped, but nothing guarantees the *scan* can reach it by
/// walking a page table it has no reason to trust. The bytes are where they
/// are, and physical space is where every structure is, exactly once.
///
/// Candidates are found by their `comm` field, which is the cheapest strong
/// filter, and the address reported is the `task_struct`'s own start — the
/// handle the cross-view keys on.
pub fn scan_physical(
    physical: &dyn seance_memory::layer::MemoryLayer,
    offsets: ScanOffsets,
    kernel_base: u64,
    config: &ScanConfig,
) -> ScanOutcome {
    // A `task_struct` is pointer-aligned, and every member the signature reads
    // sits at a fixed offset inside it, so only pointer-aligned starts need
    // testing.
    const STRIDE: usize = 8;
    const WINDOW: u64 = 8 * 1024 * 1024;

    // Sweep the layer's MAPPED SECTIONS, not a flat range.
    //
    // A capture is not contiguous — this one carries a quarter of a million
    // segments — and a single `read_at` spanning a hole fails outright. A flat
    // sweep that skipped a whole window on any such failure examined almost
    // nothing while reporting that it had swept the image: the first version of
    // this scan correlated 11 of 587 processes for exactly that reason, and the
    // 65,514 candidates it did find were the residue of the few windows that
    // happened to be hole-free.
    let plan = match seance_memory::scan::derive_sections(
        physical,
        &seance_memory::scan::ScanConfig::default(),
    ) {
        Ok(plan) => plan,
        Err(_) => {
            return ScanOutcome {
                tasks: Vec::new(),
                bytes_scanned: 0,
                truncated: true,
            }
        }
    };

    let mut buffer = vec![0u8; WINDOW as usize];
    let mut tasks = Vec::new();
    let mut scanned = 0u64;
    let mut truncated = plan.truncated_at.is_some();

    'sections: for section in &plan.sections {
        let mut at = section.start;
        while at < section.end {
            if tasks.len() >= config.max_candidates || scanned >= config.max_bytes {
                truncated = true;
                break 'sections;
            }
            let want = WINDOW.min(section.end - at) as usize;
            // Best-effort: a section can still end short of what it declared,
            // and taking what arrived beats abandoning the rest of it.
            let read =
                seance_core::io::read_full(physical.as_data_source(), at, &mut buffer[..want]);
            if read == 0 {
                break;
            }
            scanned = scanned.saturating_add(read as u64);

            // Only starts whose whole structure lies inside what was read.
            let last = read.saturating_sub(offsets.size);
            let mut cursor = 0usize;
            while cursor <= last {
                if tasks.len() >= config.max_candidates {
                    truncated = true;
                    break 'sections;
                }
                let candidate = &buffer[cursor..cursor + offsets.size];
                // Links first: it is the narrow test, and running it before the
                // name check means the overwhelming majority of addresses cost
                // two loads rather than a string scan.
                let shape = classify_links(candidate, offsets.tasks);
                if shape == LinkShape::NotLinks {
                    cursor += STRIDE;
                    continue;
                }
                if let Some((comm, tid, pid)) =
                    candidate_from_bytes(candidate, offsets.comm, offsets.pid, offsets.tgid)
                {
                    let here = kernel_base.wrapping_add(at).wrapping_add(cursor as u64);
                    let confidence = match shape {
                        LinkShape::Poisoned => Some(Confidence::Unlinked),
                        LinkShape::Kernel { next, .. } => {
                            // Follow `next` and see whether its `prev` points
                            // back at this candidate's own link member. That is
                            // the invariant a doubly-linked list holds by
                            // construction, and the thing raw bytes do not
                            // satisfy by chance.
                            let mine = here.wrapping_add(offsets.tasks as u64);
                            next_is_a_task(
                                physical,
                                kernel_base,
                                config.image_shift,
                                offsets,
                                next,
                                mine,
                            )
                            .then_some(Confidence::LinksConsistent)
                        }
                        LinkShape::NotLinks => None,
                    };
                    if let Some(confidence) = confidence {
                        tasks.push(ScannedTask {
                            address: here,
                            comm,
                            tid,
                            pid,
                            confidence,
                        });
                    }
                }
                cursor += STRIDE;
            }

            // Overlap by one structure, so one straddling the window boundary
            // is still found from the next window.
            let advance = (read as u64).saturating_sub(offsets.size as u64).max(1);
            at = at.saturating_add(advance);
        }
    }

    ScanOutcome {
        tasks,
        bytes_scanned: scanned,
        truncated,
    }
}

#[cfg(test)]
mod tests;
