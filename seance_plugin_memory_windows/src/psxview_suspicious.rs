//! Suspicious threads: where a thread started running, and whether anything
//! was ever loaded there.
//!
//! Windows creates a thread by giving it a start address. For an ordinary
//! thread that address is inside a mapped image — a `.exe` or a `.dll` the
//! loader mapped from disk — so the VAD covering it is *file-backed* and its
//! original protection is `PAGE_EXECUTE_WRITECOPY`, which is the protection
//! every image section is mapped with and nothing else is.
//!
//! Code that was **written into** a process rather than loaded into it has no
//! file behind it. It lives in a private, committed, executable allocation, and
//! a thread whose start address falls in one of those did not start in anything
//! the loader put there. That is the signature of every remote-injection
//! technique that ends in `CreateRemoteThread`, of most shellcode loaders, and
//! of the second stage of process hollowing.
//!
//! # This is a claim about which VAD an address fell in
//!
//! Everything here reduces to [`crate::vad::VadTree::containing`], so the range
//! arithmetic in [`crate::vad`] is load-bearing: an off-by-one page attributes a
//! start address to the neighbouring allocation, which may be an innocent one,
//! and the finding then names the wrong region — or is not made at all.
//!
//! # What is evidence and what is a gap
//!
//! Three of the tests here are positive statements about the process:
//!
//! * the range backing the start address maps **no file**;
//! * it maps a file but its original protection is not the one an image section
//!   is mapped with;
//! * it maps an executable image that is **not** the process's own executable,
//!   which is what a hollowed process looks like from the inside.
//!
//! Two are gaps, and they are kept apart from the three by
//! [`SuspicionKind::is_gap`]:
//!
//! * the range's protection could not be established, because this image's
//!   `MmProtectToValue` was not available;
//! * the range is long-form and the file behind it could not be read.
//!
//! A gap is not a finding. Reporting "backed by no file" for a range whose file
//! name simply could not be read would manufacture an injection out of an
//! unacquired page, and that is the specific mistake this module is written not
//! to make.
//!
//! # What is deliberately not reported
//!
//! A start address that falls in **no** VAD at all is counted
//! ([`SuspiciousThreads::starts_outside_the_tree`]) and not reported as a
//! finding. It means either the thread structure or the VAD tree was smeared
//! during acquisition, and either way the address cannot be attributed to a
//! region. Upstream drops these silently; here they are counted, because a
//! process where most starts landed outside the tree is a process whose result
//! should not be relied on.
//!
//! Terminated threads are excluded. A thread that has exited says nothing about
//! what the process is running, and its `Win32StartAddress` frequently points
//! into memory that has since been freed and reused.

use std::collections::HashSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::first_member;
use seance_memory::object::StructReader;
use seance_memory::Incomplete;

use crate::poolscan::image_file_name;
use crate::process::{ProcessSymbols, MEMBER_IMAGE_FILE_NAME, TYPE_EPROCESS};
use crate::profile::WindowsProfile;
use crate::psxview::threads::{list_process_threads, ThreadListConfig, ThreadSymbols};
use crate::psxview::PsXViewError;
use crate::vad::{base_protection, list_vads, MappedFile, VadSymbols, VadWalkConfig};

/// The original protection every image section is mapped with.
///
/// Not a heuristic: the memory manager maps a section from a file
/// copy-on-write and executable, and a thread starting in a range with any
/// other original protection did not start in a mapped image section.
pub const PROTECTION_IMAGE: &str = "PAGE_EXECUTE_WRITECOPY";

/// The thread type.
pub const TYPE_ETHREAD: &str = "_ETHREAD";

/// The XP/2003 bit saying `Win32StartAddress` holds an LPC message id.
pub const MEMBER_LPC_MSG_ID_VALID: &str = "LpcReceivedMsgIdValid";

/// The member naming where a process's own executable is mapped.
pub const MEMBER_SECTION_BASE_ADDRESS: &str = "SectionBaseAddress";

/// Fewest ranges a process's VAD tree must hold before its threads are judged.
///
/// A live process has dozens: its image, its heaps, its stacks, every loaded
/// DLL. A tree that yielded a handful was smeared during acquisition or belongs
/// to a process caught mid-teardown, and every "this address is in no
/// file-backed range" derived from it would be an artefact of the acquisition.
/// The same guard upstream applies.
pub const MIN_VADS_FOR_ANALYSIS: usize = 5;

/// Ceiling on individually recorded notes. The counts stay exact.
pub const MAX_RECORDED_NOTES: usize = 256;

// ── What was tested ─────────────────────────────────────────────────────────

/// Which of a thread's two start addresses a finding is about.
///
/// Both are reported because they answer different questions. `StartAddress` is
/// where the *kernel* starts the thread, which for every user thread on the
/// machine is the same address inside `ntdll`; `Win32StartAddress` is the
/// address the thread was actually created to run, and is the one an injection
/// sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartAddressKind {
    /// `_ETHREAD.StartAddress`.
    Start,
    /// `_ETHREAD.Win32StartAddress`.
    Win32Start,
}

impl StartAddressKind {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            StartAddressKind::Start => "start",
            StartAddressKind::Win32Start => "win32_start",
        }
    }
}

/// The range a start address fell in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartRegion {
    /// No VAD covers the address. The thread structure or the tree was smeared;
    /// nothing can be concluded about the address.
    NoVad,
    /// The range covering the address.
    Vad {
        /// Address of the VAD node, so the claim can be checked by hand.
        node: u64,
        /// First byte of the range.
        base: u64,
        /// Last byte of the range, inclusive.
        end: u64,
        /// The range's original protection, when this image's protection table
        /// was available. `None` is "not established", never "no protection".
        protection: Option<String>,
        /// The file mapped into the range.
        file: MappedFile,
    },
}

impl StartRegion {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            StartRegion::NoVad => serde_json::json!({"kind": "no_vad"}),
            StartRegion::Vad {
                node,
                base,
                end,
                protection,
                file,
            } => serde_json::json!({
                "kind": "vad",
                "node": node,
                "base": base,
                "end": end,
                "protection": protection,
                "file": file.to_json(),
            }),
        }
    }
}

/// One thing that is wrong, or one thing that could not be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspicionKind {
    /// The range backing the start address maps no file. The thread began
    /// executing in memory that was written rather than loaded.
    PrivateRegion,
    /// The range maps a file, but its original protection is not the one an
    /// image section is mapped with.
    UnexpectedProtection,
    /// The range maps an executable image that is not the process's own.
    ForeignImage,
    /// **A gap.** The range's protection could not be established, so it could
    /// not be compared against an image section's.
    ProtectionUnknown,
    /// **A gap.** The range can map a file and the file could not be read, so
    /// it could not be shown either to be backed or to be private.
    BackingUnknown,
}

impl SuspicionKind {
    /// Whether this is a gap in the evidence rather than a statement about the
    /// process.
    ///
    /// The distinction a report must preserve. A gap and a finding render the
    /// same in a table of strings, and a reader who cannot tell them apart will
    /// read "the backing could not be read" as "there is no backing", which is
    /// the accusation this module exists to make only when it is true.
    pub fn is_gap(self) -> bool {
        matches!(
            self,
            SuspicionKind::ProtectionUnknown | SuspicionKind::BackingUnknown
        )
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            SuspicionKind::PrivateRegion => "private_region",
            SuspicionKind::UnexpectedProtection => "unexpected_protection",
            SuspicionKind::ForeignImage => "foreign_image",
            SuspicionKind::ProtectionUnknown => "protection_unknown",
            SuspicionKind::BackingUnknown => "backing_unknown",
        }
    }
}

/// One suspicion, with the sentence an examiner reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suspicion {
    /// Which test produced it.
    pub kind: SuspicionKind,
    /// What it means, in the examiner's terms.
    pub detail: String,
}

impl Suspicion {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind.as_str(),
            "gap": self.kind.is_gap(),
            "detail": self.detail,
        })
    }
}

/// One start address of one thread, and everything wrong with where it points.
#[derive(Debug, Clone)]
pub struct ThreadStartFinding {
    /// The `_EPROCESS` the thread belongs to.
    pub process: u64,
    /// The process id, when it was readable.
    pub pid: Option<u64>,
    /// The process's image name, when it was readable.
    pub image_file_name: Option<String>,
    /// The `_ETHREAD`.
    pub thread: u64,
    /// The thread id, when it was readable.
    pub tid: Option<u64>,
    /// Which start address this is about.
    pub which: StartAddressKind,
    /// The address itself.
    pub address: u64,
    /// The range it fell in.
    pub region: StartRegion,
    /// What is wrong, and what could not be checked.
    pub suspicions: Vec<Suspicion>,
}

impl ThreadStartFinding {
    /// Whether at least one suspicion is a statement about the process rather
    /// than a gap in the evidence.
    ///
    /// A finding for which this is false says only "this could not be checked",
    /// and must not be counted or rendered as a detection.
    pub fn is_evidence(&self) -> bool {
        self.suspicions
            .iter()
            .any(|suspicion| !suspicion.kind.is_gap())
    }

    /// Whether this finding carries the signal the module exists for: a thread
    /// that began executing in memory no file backs.
    pub fn is_private_start(&self) -> bool {
        self.suspicions
            .iter()
            .any(|suspicion| suspicion.kind == SuspicionKind::PrivateRegion)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "pid": self.pid,
            "image_file_name": self.image_file_name,
            "thread": self.thread,
            "tid": self.tid,
            "which": self.which.as_str(),
            "address": self.address,
            "region": self.region.to_json(),
            "suspicions": self.suspicions.iter().map(Suspicion::to_json).collect::<Vec<_>>(),
            "evidence": self.is_evidence(),
            "private_start": self.is_private_start(),
        })
    }
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Caps and inputs for one process's suspicious-thread analysis.
#[derive(Debug, Clone)]
pub struct SuspiciousThreadsConfig {
    /// Caps for the thread-list walk.
    pub threads: ThreadListConfig,
    /// Caps for the VAD walk, and the kernel's protection table when it could
    /// be read. Without the table every protection is unknown, which is
    /// recorded rather than assumed away.
    pub vad: VadWalkConfig,
    /// Fewest ranges the tree must hold before the process is judged.
    pub min_vads: usize,
    /// Ceiling on individually recorded notes.
    pub max_recorded_notes: usize,
    /// Most processes an image-wide survey judges before it stops and says it
    /// stopped. Not used by [`suspicious_threads`], which judges one.
    pub max_processes: usize,
    /// Ceiling on individually recorded skipped and out-of-scope processes in
    /// a survey. The counts stay exact.
    pub max_recorded_skips: usize,
    /// The lowest address that is not a user address on this image, when it
    /// is known. A start address at or above it is a kernel-mode start --
    /// a kernel thread working inside a user process -- which no VAD can
    /// cover by construction; it is counted apart from a start that fell in no
    /// range, which is a smeared tree. `None` treats every start in no range as
    /// the latter, which is the conservative reading.
    pub kernel_floor: Option<u64>,
}

/// Default ceiling on the processes one survey judges.
pub const MAX_SURVEY_PROCESSES: usize = 4096;

/// Default ceiling on recorded skipped processes in one survey.
pub const MAX_RECORDED_SKIPS: usize = 256;

impl Default for SuspiciousThreadsConfig {
    fn default() -> Self {
        Self {
            threads: ThreadListConfig::default(),
            vad: VadWalkConfig::default(),
            min_vads: MIN_VADS_FOR_ANALYSIS,
            max_recorded_notes: MAX_RECORDED_NOTES,
            max_processes: MAX_SURVEY_PROCESSES,
            max_recorded_skips: MAX_RECORDED_SKIPS,
            kernel_floor: None,
        }
    }
}

impl SuspiciousThreadsConfig {
    /// The shipped caps, with this image's `MmProtectToValue` loaded so a
    /// range's protection can be compared at all (MEM-022: a VAD walk that is
    /// not handed the table reads every protection as unknown).
    pub fn for_profile(profile: &WindowsProfile) -> Self {
        Self {
            vad: VadWalkConfig::for_profile(profile),
            kernel_floor: kernel_floor(profile),
            ..Self::default()
        }
    }
}

/// Symbol holding where the kernel half of the address space begins.
pub const SYMBOL_SYSTEM_RANGE_START: &str = "MmSystemRangeStart";

/// The canonical start of the kernel half on x64.
pub const X64_KERNEL_HALF_START: u64 = 0xFFFF_8000_0000_0000;

/// The highest the kernel floor can be on 32-bit Windows (a `/3GB` boot).
pub const X86_HIGHEST_KERNEL_FLOOR: u64 = 0xC000_0000;

/// The lowest kernel address for a pointer size and, on 32-bit, the
/// `MmSystemRangeStart` value read from the image.
///
/// On x64 this is always the canonical kernel half, `0xFFFF8000_00000000`,
/// whatever the image says. The user ceiling (`MmHighestUserAddress`,
/// `0x7FFF_FFFE_FFFF`) is not a kernel floor: the non-canonical hole between
/// the two holds no mapping, so a start there is a smeared or garbage value
/// that cannot be placed -- never a kernel thread.
///
/// On 32-bit it is `MmSystemRangeStart` when that read and is plausible
/// (2 to 3 GiB), otherwise `0xC0000000` -- the floor under a `/3GB` boot, the
/// highest it can be -- so a user start between 2 and 3 GiB is never waved
/// through as a kernel one. On an ordinary 2 GiB boot that fallback leaves
/// kernel starts between 2 and 3 GiB counted as unplaced, the conservative
/// error.
pub fn kernel_floor_from(pointer_size: u64, system_range_start: Option<u64>) -> Option<u64> {
    match pointer_size {
        8 => Some(X64_KERNEL_HALF_START),
        4 => Some(
            system_range_start
                .filter(|start| (0x8000_0000..=X86_HIGHEST_KERNEL_FLOOR).contains(start))
                .unwrap_or(X86_HIGHEST_KERNEL_FLOOR),
        ),
        _ => None,
    }
}

/// The lowest kernel address on this image; see [`kernel_floor_from`].
/// `MmSystemRangeStart` is read only on 32-bit builds, where it moves.
pub fn kernel_floor(profile: &WindowsProfile) -> Option<u64> {
    let pointer = profile.pointer_size();
    let read = if pointer == 4 {
        profile
            .symbols
            .symbol_address(SYMBOL_SYSTEM_RANGE_START)
            .ok()
            .and_then(|rva| profile.kernel_base.value.checked_add(rva))
            .and_then(|address| {
                let reader = StructReader::new(
                    Arc::clone(&profile.kernel_space),
                    Arc::clone(&profile.symbols),
                );
                reader.read_bytes(address, 4).ok()
            })
            .and_then(|bytes| {
                Some(u64::from(u32::from_le_bytes(
                    bytes.get(..4)?.try_into().ok()?,
                )))
            })
    } else {
        None
    };
    kernel_floor_from(pointer, read)
}

// ── Result ──────────────────────────────────────────────────────────────────

/// One process's threads judged against its own memory map.
#[derive(Debug, Clone)]
pub struct SuspiciousThreads {
    /// The `_EPROCESS`.
    pub process: u64,
    /// The process id, when it was readable.
    pub pid: Option<u64>,
    /// The process's image name, when it was readable.
    pub image_file_name: Option<String>,
    /// The file the process's own executable is mapped from, when it could be
    /// established. `None` disables the foreign-image test rather than passing
    /// it.
    pub executable: Option<String>,
    /// Whether the threads were judged at all. `false` means the tree was too
    /// small to judge against and every field below it is empty for that
    /// reason, not because the process is clean.
    pub analysed: bool,
    /// How many ranges the process's VAD tree held.
    pub vads: usize,
    /// Whether that tree was walked in full. A partial tree cannot support "no
    /// thread started outside a mapped image".
    pub vad_complete: bool,
    /// Whether the thread list was walked end to end.
    pub threads_complete: bool,
    /// How many threads were examined.
    pub threads_examined: usize,
    /// How many were skipped because they had terminated.
    pub threads_terminated: usize,
    /// How many distinct start addresses fell in no VAD at all and were not
    /// kernel addresses.
    pub starts_outside_the_tree: usize,
    /// How many distinct start addresses were kernel addresses (on x64 at or
    /// above the canonical kernel half, never in the non-canonical hole) on a
    /// thread whose `_KTHREAD.SystemThread` is set: a kernel thread working
    /// inside this process. No VAD covers one, so it is not a question this
    /// analysis can answer; the `tamper_checks` stage's orphan-thread group
    /// asks whether it lies in a loaded module.
    pub starts_in_kernel_space: usize,
    /// How many distinct start addresses were kernel addresses on a thread
    /// that is not known to be a kernel thread: `_KTHREAD.SystemThread` was
    /// clear, undeclared on this build, or unreadable. No VAD covers such an
    /// address, and the `tamper_checks` orphan-thread group sets aside every
    /// thread it cannot establish as a kernel thread, so neither stage judges
    /// it. Counted, and the process is incomplete.
    pub kernel_starts_on_threads_not_known_as_system: usize,
    /// How many threads' `Win32StartAddress` held an LPC message id rather
    /// than an address. On Windows XP and Server 2003 the field is a union
    /// with `LpcReceivedMessageId`, and `LpcReceivedMsgIdValid` says which it
    /// holds; judging a message id as an address places a small integer in
    /// whatever range covers the bottom of the address space.
    pub win32_starts_holding_an_lpc_message_id: usize,
    /// How many threads' `LpcReceivedMsgIdValid` could not be read, on a build
    /// that has it. Their `Win32StartAddress` was not judged, because it could
    /// not be told apart from a message id.
    pub lpc_flag_unreadable: usize,
    /// How many distinct start addresses were tested.
    pub starts_tested: usize,
    /// The findings, in the order the threads were walked.
    pub findings: Vec<ThreadStartFinding>,
    /// Notes, capped by [`SuspiciousThreadsConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total.
    pub notes_total: usize,
}

impl SuspiciousThreads {
    /// The findings that are statements about the process rather than gaps.
    pub fn evidence(&self) -> impl Iterator<Item = &ThreadStartFinding> {
        self.findings.iter().filter(|f| f.is_evidence())
    }

    /// The findings that record only that a check could not be performed.
    pub fn gaps(&self) -> impl Iterator<Item = &ThreadStartFinding> {
        self.findings.iter().filter(|f| !f.is_evidence())
    }

    /// Whether every input this analysis rests on was complete.
    ///
    /// Only when this is true can the result support "no thread in this process
    /// started outside a mapped image".
    pub fn is_complete(&self) -> bool {
        self.analysed
            && self.vad_complete
            && self.threads_complete
            && self.starts_outside_the_tree == 0
            && self.kernel_starts_on_threads_not_known_as_system == 0
            && self.lpc_flag_unreadable == 0
    }

    /// Everything a report must declare about this analysis.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if !self.analysed {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the process at {:#x} was not judged: its VAD tree held {} range(s), too few \
                     to tell an unbacked allocation from a smeared tree",
                    self.process, self.vads
                ),
            ));
            return out;
        }
        if !self.vad_complete {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the VAD tree of the process at {:#x} was not fully walked, so a start address \
                     may have been attributed to no range when a range it did not reach held it",
                    self.process
                ),
            ));
        }
        if !self.threads_complete {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the thread list of the process at {:#x} was not walked end to end, so a \
                     thread it did not reach was not judged at all",
                    self.process
                ),
            ));
        }
        if self.starts_outside_the_tree > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} start address(es) of the process at {:#x} fell in no range at all, so they \
                     could not be judged",
                    self.starts_outside_the_tree, self.process
                ),
            ));
        }
        if self.kernel_starts_on_threads_not_known_as_system > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} kernel start address(es) of the process at {:#x} are on threads whose \
                     _KTHREAD.SystemThread is clear, unreadable or not declared, so neither this \
                     analysis nor the tamper_checks orphan-thread group judged them",
                    self.kernel_starts_on_threads_not_known_as_system, self.process
                ),
            ));
        }
        if self.lpc_flag_unreadable > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} thread(s) of the process at {:#x} had an unreadable \
                     {MEMBER_LPC_MSG_ID_VALID} flag, so their Win32StartAddress could not be told \
                     apart from an LPC message id and was not judged",
                    self.lpc_flag_unreadable, self.process
                ),
            ));
        }
        if self.executable.is_none() && self.analysed {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the executable of the process at {:#x} could not be established, so a thread \
                     starting in some other application's image was not tested for",
                    self.process
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "pid": self.pid,
            "image_file_name": self.image_file_name,
            "executable": self.executable,
            "analysed": self.analysed,
            "vads": self.vads,
            "vad_complete": self.vad_complete,
            "threads_complete": self.threads_complete,
            "threads_examined": self.threads_examined,
            "threads_terminated": self.threads_terminated,
            "starts_tested": self.starts_tested,
            "starts_outside_the_tree": self.starts_outside_the_tree,
            "starts_in_kernel_space": self.starts_in_kernel_space,
            "kernel_starts_on_threads_not_known_as_system":
                self.kernel_starts_on_threads_not_known_as_system,
            "win32_starts_holding_an_lpc_message_id": self.win32_starts_holding_an_lpc_message_id,
            "lpc_flag_unreadable": self.lpc_flag_unreadable,
            "findings": self.findings.iter().map(ThreadStartFinding::to_json).collect::<Vec<_>>(),
            "evidence_count": self.evidence().count(),
            "gap_count": self.gaps().count(),
            "complete": self.is_complete(),
            "notes": self.notes,
            "notes_total": self.notes_total,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

// ── The analysis ────────────────────────────────────────────────────────────

/// Record a note, keeping the recorded list bounded without losing the count.
///
/// The count is what a report needs: a process with three hundred
/// unattributable start addresses is a different claim from one with three,
/// and truncating the list must not truncate that number.
fn record_note(notes: &mut Vec<String>, total: &mut usize, cap: usize, text: String) {
    *total += 1;
    if notes.len() < cap {
        notes.push(text);
    }
}

/// Judge one process's threads against its own memory map.
///
/// # Errors
///
/// Only for failures that make the analysis impossible: an `_EPROCESS` that
/// cannot be read at all, a build whose VAD tree cannot be walked, or a build
/// whose threads cannot be enumerated. A thread whose fields could not be read
/// is not an error — it is counted, and the counts are on the result.
pub fn suspicious_threads(
    profile: &WindowsProfile,
    process_symbols: &ProcessSymbols,
    thread_symbols: &ThreadSymbols,
    vad_symbols: &VadSymbols,
    process: u64,
    config: &SuspiciousThreadsConfig,
) -> Result<SuspiciousThreads, PsXViewError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let eprocess = reader.object(process, TYPE_EPROCESS)?;

    let pid = eprocess
        .int(&process_symbols.unique_process_id)
        .ok()
        .and_then(|value| value.as_u64());
    let image_file_name = eprocess
        .bytes(MEMBER_IMAGE_FILE_NAME)
        .ok()
        .map(|raw| image_file_name(&raw));

    let mut notes: Vec<String> = Vec::new();
    let mut notes_total = 0usize;
    let cap = config.max_recorded_notes;

    let tree = list_vads(profile, vad_symbols, process, &config.vad)?;
    if config.vad.protections.is_none() {
        record_note(
            &mut notes,
            &mut notes_total,
            cap,
            "this image's protection table was not available, so no range's protection could be \
             compared against the one an image section is mapped with"
                .to_string(),
        );
    }

    if tree.vads.len() < config.min_vads {
        record_note(
            &mut notes,
            &mut notes_total,
            cap,
            format!(
                "the VAD tree held {} range(s), fewer than the {} needed to tell an unbacked \
                 allocation from a smeared tree, so no thread was judged",
                tree.vads.len(),
                config.min_vads
            ),
        );
        return Ok(SuspiciousThreads {
            process,
            pid,
            image_file_name,
            executable: None,
            analysed: false,
            vads: tree.vads.len(),
            vad_complete: tree.is_complete(),
            threads_complete: false,
            threads_examined: 0,
            threads_terminated: 0,
            starts_outside_the_tree: 0,
            starts_in_kernel_space: 0,
            kernel_starts_on_threads_not_known_as_system: 0,
            win32_starts_holding_an_lpc_message_id: 0,
            lpc_flag_unreadable: 0,
            starts_tested: 0,
            findings: Vec::new(),
            notes,
            notes_total,
        });
    }

    // The process's own executable, found the way the process itself sees it:
    // the range covering `SectionBaseAddress` is the image the process was
    // created from. Without it the foreign-image test is not performed, which
    // is stated rather than passed.
    let executable = if eprocess.has_member(MEMBER_SECTION_BASE_ADDRESS) {
        match eprocess.int(MEMBER_SECTION_BASE_ADDRESS) {
            Ok(value) => match value.as_u64() {
                Some(0) | None => None,
                Some(base) => tree
                    .containing(base)
                    .and_then(|vad| vad.file.name().map(str::to_string)),
            },
            Err(err) => {
                record_note(
                    &mut notes,
                    &mut notes_total,
                    cap,
                    format!("'{MEMBER_SECTION_BASE_ADDRESS}' could not be read: {err}"),
                );
                None
            }
        }
    } else {
        record_note(
            &mut notes,
            &mut notes_total,
            cap,
            format!(
                "this build's '{TYPE_EPROCESS}' has no {MEMBER_SECTION_BASE_ADDRESS}, so the \
                 process's own executable could not be identified"
            ),
        );
        None
    };

    let list = list_process_threads(profile, thread_symbols, process, &config.threads)?;
    let threads_complete = list.reached_every_entry();

    let mut findings = Vec::new();
    let mut checked: HashSet<(u64, bool)> = HashSet::new();
    let mut threads_examined = 0usize;
    let mut threads_terminated = 0usize;
    let mut starts_outside = 0usize;
    let mut starts_kernel = 0usize;
    let mut kernel_unexamined = 0usize;
    // Whether a thread is a kernel thread, read the way the tamper_checks
    // orphan-thread group reads it (`Tcb.SystemThread` on NT 6+, the
    // `_ETHREAD` flag on NT 5.x), so the two stages divide kernel starts on
    // the same test.
    let system_thread_path =
        first_member(&reader, TYPE_ETHREAD, &["Tcb.SystemThread", "SystemThread"])
            .ok()
            .flatten();
    let mut lpc_message_ids = 0usize;
    let mut lpc_flag_unreadable = 0usize;
    // XP and Server 2003 overlay Win32StartAddress with LpcReceivedMessageId;
    // a build whose _ETHREAD has this bit is one where the field can hold
    // either, and the bit says which.
    let lpc_union = reader.has_member(TYPE_ETHREAD, MEMBER_LPC_MSG_ID_VALID);
    let mut starts_tested = 0usize;

    for thread in &list.threads {
        // A thread that has exited says nothing about what the process runs
        // now, and its start address frequently points into memory that has
        // since been freed and reused.
        if thread.is_terminated() == Some(true) {
            threads_terminated += 1;
            continue;
        }
        threads_examined += 1;
        let tid = thread.tid.known().copied();

        // Whether Win32StartAddress is an address at all on this thread.
        let mut win32_is_an_address = true;
        if lpc_union {
            match reader
                .object(thread.address, TYPE_ETHREAD)
                .and_then(|ethread| ethread.int(MEMBER_LPC_MSG_ID_VALID))
                .map(|value| value.as_u64())
            {
                Ok(Some(0)) => {}
                Ok(Some(_)) => {
                    win32_is_an_address = false;
                    lpc_message_ids += 1;
                }
                Ok(None) | Err(_) => {
                    win32_is_an_address = false;
                    lpc_flag_unreadable += 1;
                    record_note(
                        &mut notes,
                        &mut notes_total,
                        cap,
                        format!(
                            "the {MEMBER_LPC_MSG_ID_VALID} flag of the thread at {:#x} could not \
                             be read, so its Win32StartAddress could not be told apart from an \
                             LPC message id and was not judged",
                            thread.address
                        ),
                    );
                }
            }
        }

        for (which, field) in [
            (StartAddressKind::Start, &thread.start_address),
            (StartAddressKind::Win32Start, &thread.win32_start_address),
        ] {
            if which == StartAddressKind::Win32Start && !win32_is_an_address {
                continue;
            }
            let Some(&address) = field.known() else {
                continue;
            };
            // A null start address is a thread caught during creation, not a
            // thread starting at address zero.
            if address == 0 {
                continue;
            }
            // A kernel address is judged together with whether the thread is
            // a kernel thread, so the same address on a kernel and on a user
            // thread is two questions; any other address is one.
            let in_kernel_half = config.kernel_floor.is_some_and(|floor| address >= floor);
            // `None` when the build declares no SystemThread; otherwise the
            // read, which may fail.
            let system_flag = if in_kernel_half {
                system_thread_path.map(|path| {
                    reader
                        .object(thread.address, TYPE_ETHREAD)
                        .and_then(|ethread| ethread.unsigned(path))
                        .ok()
                })
            } else {
                None
            };
            let is_system_thread = system_flag == Some(Some(1));
            // Processes routinely create many threads at one address; there is
            // nothing to learn from judging the same address twice.
            if !checked.insert((address, is_system_thread)) {
                continue;
            }
            starts_tested += 1;

            if in_kernel_half {
                // A kernel address: no VAD covers one by construction, so it
                // says nothing about the tree and nothing this analysis can
                // judge. On a kernel thread it is the tamper_checks
                // orphan-thread group's question. On a thread not known to be
                // one, that group sets it aside too, so it is judged by
                // neither stage and the process says so.
                if is_system_thread {
                    starts_kernel += 1;
                } else {
                    kernel_unexamined += 1;
                    record_note(
                        &mut notes,
                        &mut notes_total,
                        cap,
                        format!(
                            "the {} address {address:#x} of the thread at {:#x} is a kernel \
                             address, but the thread's _KTHREAD.SystemThread is {}, so it was \
                             judged neither here nor by the tamper_checks orphan-thread group",
                            which.as_str(),
                            thread.address,
                            match system_flag {
                                Some(Some(_)) => "clear",
                                Some(None) => "unreadable",
                                None => "not declared on this build",
                            }
                        ),
                    );
                }
                continue;
            }

            let Some(vad) = tree.containing(address) else {
                starts_outside += 1;
                record_note(
                    &mut notes,
                    &mut notes_total,
                    cap,
                    format!(
                        "the {} address {address:#x} of the thread at {:#x} falls in no range, so \
                         it could not be judged",
                        which.as_str(),
                        thread.address
                    ),
                );
                continue;
            };

            let mut suspicions = Vec::new();
            match &vad.file {
                MappedFile::NotApplicable | MappedFile::None => suspicions.push(Suspicion {
                    kind: SuspicionKind::PrivateRegion,
                    detail: format!(
                        "the thread began executing in the range at {:#x}, which is backed by no \
                         file, so the code there was written into the process rather than loaded \
                         into it",
                        vad.start
                    ),
                }),
                MappedFile::Unavailable(detail) => suspicions.push(Suspicion {
                    kind: SuspicionKind::BackingUnknown,
                    detail: format!(
                        "the file behind the range at {:#x} could not be read, so the range can be \
                         shown neither to be backed nor to be private: {detail}",
                        vad.start
                    ),
                }),
                MappedFile::Name(name) => {
                    if let Some(executable) = executable.as_deref() {
                        let lower = name.to_ascii_lowercase();
                        if lower.ends_with(".exe") && lower != executable.to_ascii_lowercase() {
                            suspicions.push(Suspicion {
                                kind: SuspicionKind::ForeignImage,
                                detail: format!(
                                    "the range at {:#x} maps {name}, an application image that is \
                                     not this process's own executable ({executable})",
                                    vad.start
                                ),
                            });
                        }
                    }
                }
            }
            // Compare the ACCESS protection, not the whole rendered string.
            // `protection_names` joins every bit the mask sets, and the upper
            // half of `MmProtectToValue` is the lower half with a guard, cache
            // or write-combine attribute added — so the very same mapped image
            // reads `PAGE_EXECUTE_WRITECOPY` at index 7 and
            // `PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE` at index 23. Matching the
            // joined string against one constant makes the second an
            // `UnexpectedProtection`, which on this path is an injected-thread
            // claim about an ordinary thread in an ordinary image.
            match vad
                .protection_names
                .as_deref()
                .map(|names| (names, base_protection(names)))
            {
                Some((_, Some(PROTECTION_IMAGE))) => {}
                Some((protection, Some(_))) => suspicions.push(Suspicion {
                    kind: SuspicionKind::UnexpectedProtection,
                    detail: format!(
                        "the range at {:#x} was created with {protection}, and every range an \
                         image section is mapped into is created with {PROTECTION_IMAGE}",
                        vad.start
                    ),
                }),
                // Qualifiers with no access protection beside them name nothing
                // to compare. That is an unread table entry, and reporting it as
                // an unexpected protection would assert an injected thread on
                // the strength of a value nobody established.
                Some((protection, None)) => suspicions.push(Suspicion {
                    kind: SuspicionKind::ProtectionUnknown,
                    detail: format!(
                        "the protection of the range at {:#x} names only cache or guard \
                         attributes ({protection}) and no access protection, so it could not be \
                         compared against the one an image section is mapped with",
                        vad.start
                    ),
                }),
                None => suspicions.push(Suspicion {
                    kind: SuspicionKind::ProtectionUnknown,
                    detail: format!(
                        "the protection of the range at {:#x} could not be established, so it \
                         could not be compared against the one an image section is mapped with",
                        vad.start
                    ),
                }),
            }

            if suspicions.is_empty() {
                continue;
            }
            findings.push(ThreadStartFinding {
                process,
                pid,
                image_file_name: image_file_name.clone(),
                thread: thread.address,
                tid,
                which,
                address,
                region: StartRegion::Vad {
                    node: vad.address,
                    base: vad.start,
                    end: vad.end,
                    protection: vad.protection_names.clone(),
                    file: vad.file.clone(),
                },
                suspicions,
            });
        }
    }

    Ok(SuspiciousThreads {
        process,
        pid,
        image_file_name,
        executable,
        analysed: true,
        vads: tree.vads.len(),
        vad_complete: tree.is_complete(),
        threads_complete,
        threads_examined,
        threads_terminated,
        starts_outside_the_tree: starts_outside,
        starts_in_kernel_space: starts_kernel,
        kernel_starts_on_threads_not_known_as_system: kernel_unexamined,
        win32_starts_holding_an_lpc_message_id: lpc_message_ids,
        lpc_flag_unreadable,
        starts_tested,
        findings,
        notes,
        notes_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hollow::ScanStop;
    use crate::poolscan::test_support::{profile, table, Image};
    use crate::process::{Field, ProcessList, ProcessRecord, ProcessTime, WalkDirection};
    use crate::psxview::{
        survey_suspicious_threads, SuspiciousThreadSymbols, SuspiciousThreadsSurvey,
    };
    use crate::vad::ProtectionTable;
    use seance_memory::object::ListStop;
    use seance_memory::Architecture;

    const EPROCESS_AT: u64 = 0x1000;
    const THREAD_AT: u64 = 0x3000;

    /// Six VAD nodes, chained down the right-hand side so the tree is a list —
    /// which is enough for the arithmetic under test and keeps the fixture flat.
    const VADS: [u64; 6] = [0x5000, 0x5100, 0x5200, 0x5300, 0x5400, 0x5500];

    const FILE_OBJECT_AT: u64 = 0x6000;
    const FILE_NAME_AT: u64 = 0x6100;
    const EXE_FILE_OBJECT_AT: u64 = 0x6400;
    const EXE_FILE_NAME_AT: u64 = 0x6500;
    const SUBSECTION_AT: u64 = 0x6800;
    const CONTROL_AREA_AT: u64 = 0x6900;
    const EXE_SUBSECTION_AT: u64 = 0x6A00;
    const EXE_CONTROL_AREA_AT: u64 = 0x6B00;

    mod off {
        pub(super) const TAG_DISTANCE: u64 = 12;

        pub(super) const EPROCESS_PID: u64 = 0;
        pub(super) const EPROCESS_NAME: u64 = 8;
        pub(super) const EPROCESS_THREAD_LIST_HEAD: u64 = 64;
        pub(super) const EPROCESS_VAD_ROOT: u64 = 104;
        pub(super) const EPROCESS_SECTION_BASE: u64 = 112;

        pub(super) const ETHREAD_CID_THREAD: u64 = 0;
        pub(super) const ETHREAD_CID_PROCESS: u64 = 8;
        pub(super) const ETHREAD_LIST_ENTRY: u64 = 16;
        pub(super) const ETHREAD_START: u64 = 48;
        pub(super) const ETHREAD_WIN32_START: u64 = 56;
        pub(super) const ETHREAD_TCB_PROCESS: u64 = 64;
        pub(super) const ETHREAD_LPC_FLAGS: u64 = 96;
        /// `Tcb.SystemThread`, bit 0.
        pub(super) const ETHREAD_SYSTEM_THREAD: u64 = 80;

        pub(super) const VAD_LEFT: u64 = 0;
        pub(super) const VAD_RIGHT: u64 = 8;
        pub(super) const VAD_START_VPN: u64 = 24;
        pub(super) const VAD_END_VPN: u64 = 28;
        pub(super) const VAD_FLAGS: u64 = 36;
        pub(super) const VAD_SUBSECTION: u64 = 48;
    }

    const PROTECT_TABLE_AT: u64 = 0x7000;

    /// A synthetic 64-bit Windows 10 ISF carrying processes, threads and VADs.
    fn isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "3A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
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
      "State": {"offset": 8, "type": {"kind": "base", "name": "unsigned char"}},
      "SystemThread": {"offset": 16, "type": {"kind": "bitfield", "bit_position": 0,
                       "bit_length": 1, "type": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_ETHREAD": {"size": 128, "kind": "struct", "fields": {
      "Cid": {"offset": 0, "type": {"kind": "struct", "name": "_CLIENT_ID"}},
      "ThreadListEntry": {"offset": 16, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "CreateTime": {"offset": 32, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ExitTime": {"offset": 40, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "StartAddress": {"offset": 48, "type": {"kind": "pointer",
                       "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Win32StartAddress": {"offset": 56, "type": {"kind": "pointer",
                            "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Tcb": {"offset": 64, "type": {"kind": "struct", "name": "_KTHREAD"}},
      "LpcReceivedMsgIdValid": {"offset": 96, "type": {"kind": "bitfield", "bit_position": 0,
                                "bit_length": 1, "type": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_UNICODE_STRING": {"size": 16, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 8, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_FILE_OBJECT": {"size": 32, "kind": "struct", "fields": {
      "FileName": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_EX_FAST_REF": {"size": 8, "kind": "union", "fields": {
      "Object": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_CONTROL_AREA": {"size": 32, "kind": "struct", "fields": {
      "FilePointer": {"offset": 0, "type": {"kind": "union", "name": "_EX_FAST_REF"}}
    }},
    "_SUBSECTION": {"size": 32, "kind": "struct", "fields": {
      "ControlArea": {"offset": 0, "type": {"kind": "pointer",
                      "subtype": {"kind": "struct", "name": "_CONTROL_AREA"}}}
    }},
    "_RTL_BALANCED_NODE": {"size": 24, "kind": "struct", "fields": {
      "Left": {"offset": 0, "type": {"kind": "pointer",
               "subtype": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}}},
      "Right": {"offset": 8, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}}},
      "ParentValue": {"offset": 16, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_RTL_AVL_TREE": {"size": 8, "kind": "struct", "fields": {
      "Root": {"offset": 0, "type": {"kind": "pointer",
               "subtype": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}}}
    }},
    "_MMVAD_FLAGS": {"size": 4, "kind": "struct", "fields": {
      "Protection": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0,
                     "bit_length": 5, "type": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_MMVAD_SHORT_U": {"size": 4, "kind": "union", "fields": {
      "VadFlags": {"offset": 0, "type": {"kind": "struct", "name": "_MMVAD_FLAGS"}}
    }},
    "_MMVAD_SHORT": {"size": 48, "kind": "struct", "fields": {
      "VadNode": {"offset": 0, "type": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}},
      "StartingVpn": {"offset": 24, "type": {"kind": "base", "name": "unsigned long"}},
      "EndingVpn": {"offset": 28, "type": {"kind": "base", "name": "unsigned long"}},
      "u": {"offset": 36, "type": {"kind": "union", "name": "_MMVAD_SHORT_U"}}
    }},
    "_MMVAD": {"size": 128, "kind": "struct", "fields": {
      "Core": {"offset": 0, "type": {"kind": "struct", "name": "_MMVAD_SHORT"}},
      "Subsection": {"offset": 48, "type": {"kind": "pointer",
                     "subtype": {"kind": "struct", "name": "_SUBSECTION"}}}
    }},
    "_EPROCESS": {"size": 256, "kind": "struct", "fields": {
      "UniqueProcessId": {"offset": 0, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ImageFileName": {"offset": 8, "type": {"kind": "array", "count": 15,
                        "subtype": {"kind": "base", "name": "unsigned char"}}},
      "CreateTime": {"offset": 32, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ActiveProcessLinks": {"offset": 48, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "ThreadListHead": {"offset": 64, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "DirectoryTableBase": {"offset": 96, "type": {"kind": "base",
                             "name": "unsigned long long"}},
      "VadRoot": {"offset": 104, "type": {"kind": "struct", "name": "_RTL_AVL_TREE"}},
      "SectionBaseAddress": {"offset": 112, "type": {"kind": "pointer",
                             "subtype": {"kind": "base", "name": "unsigned char"}}}
    }}
  },
  "enums": {},
  "symbols": {"MmProtectToValue": {"address": 28672}}
}"#,
        ]
        .concat()
    }

    /// A VAD node with its tag, range, protection index and right-hand child.
    #[allow(clippy::too_many_arguments)]
    fn put_vad(
        image: &mut Image,
        at: u64,
        tag: &[u8; 4],
        start_page: u32,
        end_page: u32,
        right: u64,
        protection: u32,
        subsection: u64,
    ) {
        image.write(at - off::TAG_DISTANCE, tag);
        image.put_u64(at + off::VAD_LEFT, 0);
        image.put_u64(at + off::VAD_RIGHT, right);
        image.put_u32(at + off::VAD_START_VPN, start_page);
        image.put_u32(at + off::VAD_END_VPN, end_page);
        image.put_u32(at + off::VAD_FLAGS, protection);
        image.put_u64(at + off::VAD_SUBSECTION, subsection);
    }

    /// A `_SUBSECTION` → `_CONTROL_AREA` → `_FILE_OBJECT` chain naming a file.
    fn put_mapped_file(
        image: &mut Image,
        subsection: u64,
        control: u64,
        file_object: u64,
        name_at: u64,
        name: &str,
    ) {
        image.put_u64(subsection, control);
        image.put_u64(control, file_object);
        let bytes = name.encode_utf16().count() * 2;
        image.put_u16(file_object, bytes as u16);
        image.put_u16(file_object + 2, bytes as u16);
        image.put_u64(file_object + 8, name_at);
        image.put_utf16(name_at, name);
    }

    /// A protection table whose index 7 is `PAGE_EXECUTE_WRITECOPY` and whose
    /// index 6 is `PAGE_EXECUTE_READWRITE`, as a real one's are.
    fn put_protect_table(image: &mut Image) {
        let values: [u32; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];
        for (index, value) in values.iter().enumerate() {
            image.put_u32(PROTECT_TABLE_AT + (index as u64) * 4, *value);
        }
    }

    /// Protection index of `PAGE_EXECUTE_WRITECOPY` in the table above.
    const PROT_IMAGE: u32 = 7;
    /// Protection index of `PAGE_EXECUTE_READWRITE`.
    const PROT_RWX: u32 = 6;

    /// Page numbers of the ranges the fixture lays down.
    const IMAGE_PAGE: u32 = 0x400; // 0x400000, the process's own executable
    const OTHER_EXE_PAGE: u32 = 0x500;
    const PRIVATE_PAGE: u32 = 0x600;

    /// A process with six ranges, one live thread, and a start address the
    /// caller chooses.
    fn fixture(start: u64, win32_start: u64) -> Image {
        let mut image = Image::new();
        put_protect_table(&mut image);

        // The tree: a chain of six nodes down the right-hand side.
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, VADS[0]);
        // 0: the process's own executable, file backed, mapped as an image.
        put_vad(
            &mut image,
            VADS[0],
            b"Vad ",
            IMAGE_PAGE,
            IMAGE_PAGE,
            VADS[1],
            PROT_IMAGE,
            EXE_SUBSECTION_AT,
        );
        put_mapped_file(
            &mut image,
            EXE_SUBSECTION_AT,
            EXE_CONTROL_AREA_AT,
            EXE_FILE_OBJECT_AT,
            EXE_FILE_NAME_AT,
            "\\Device\\HarddiskVolume1\\Windows\\explorer.exe",
        );
        // 1: another application's image, also mapped as an image.
        put_vad(
            &mut image,
            VADS[1],
            b"Vad ",
            OTHER_EXE_PAGE,
            OTHER_EXE_PAGE,
            VADS[2],
            PROT_IMAGE,
            SUBSECTION_AT,
        );
        put_mapped_file(
            &mut image,
            SUBSECTION_AT,
            CONTROL_AREA_AT,
            FILE_OBJECT_AT,
            FILE_NAME_AT,
            "\\Device\\HarddiskVolume1\\Temp\\dropper.exe",
        );
        // 2: private, executable, backed by nothing — the injected region.
        put_vad(
            &mut image,
            VADS[2],
            b"VadS",
            PRIVATE_PAGE,
            PRIVATE_PAGE,
            VADS[3],
            PROT_RWX,
            0,
        );
        // 3, 4, 5: ordinary private ranges, present only so the tree is large
        // enough to be judged.
        for (index, page) in [(3usize, 0x700u32), (4, 0x800), (5, 0x900)] {
            put_vad(
                &mut image,
                VADS[index],
                b"VadS",
                page,
                page,
                if index + 1 < VADS.len() {
                    VADS[index + 1]
                } else {
                    0
                },
                2,
                0,
            );
        }

        image.put_u64(EPROCESS_AT + off::EPROCESS_PID, 0x400);
        image.write(EPROCESS_AT + off::EPROCESS_NAME, b"explorer.exe");
        image.put_u64(
            EPROCESS_AT + off::EPROCESS_SECTION_BASE,
            u64::from(IMAGE_PAGE) * 4096,
        );

        let head = EPROCESS_AT + off::EPROCESS_THREAD_LIST_HEAD;
        let link = THREAD_AT + off::ETHREAD_LIST_ENTRY;
        image.put_u64(head, link);
        image.put_u64(head + 8, link);
        image.put_u64(link, head);
        image.put_u64(link + 8, head);
        image.put_u64(THREAD_AT + off::ETHREAD_CID_THREAD, 0x100);
        image.put_u64(THREAD_AT + off::ETHREAD_CID_PROCESS, 0x400);
        image.put_u64(THREAD_AT + off::ETHREAD_START, start);
        image.put_u64(THREAD_AT + off::ETHREAD_WIN32_START, win32_start);
        image.put_u64(THREAD_AT + off::ETHREAD_TCB_PROCESS, EPROCESS_AT);
        image
    }

    fn run(image: Image, with_protections: bool) -> SuspiciousThreads {
        let profile = profile(
            image.layer(),
            table(&isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let process_symbols = ProcessSymbols::from_profile(&profile).expect("a describable build");
        let thread_symbols = ThreadSymbols::from_profile(&profile).expect("a describable build");
        let vad_symbols = VadSymbols::from_profile(&profile).expect("a describable build");
        let protections = if with_protections {
            ProtectionTable::from_profile(&profile).ok().map(Arc::new)
        } else {
            None
        };
        let config = SuspiciousThreadsConfig {
            vad: VadWalkConfig {
                protections,
                ..VadWalkConfig::default()
            },
            ..SuspiciousThreadsConfig::default()
        };
        suspicious_threads(
            &profile,
            &process_symbols,
            &thread_symbols,
            &vad_symbols,
            EPROCESS_AT,
            &config,
        )
        .expect("a runnable analysis")
    }

    const IMAGE_START: u64 = (IMAGE_PAGE as u64) * 4096 + 0x100;
    const OTHER_EXE_START: u64 = (OTHER_EXE_PAGE as u64) * 4096 + 0x100;
    const PRIVATE_START: u64 = (PRIVATE_PAGE as u64) * 4096 + 0x100;

    #[test]
    fn a_thread_starting_in_the_processes_own_image_is_not_a_finding() {
        let out = run(fixture(IMAGE_START, IMAGE_START), true);
        assert!(out.analysed);
        assert_eq!(out.vads, 6);
        assert_eq!(
            out.executable.as_deref(),
            Some("\\Device\\HarddiskVolume1\\Windows\\explorer.exe")
        );
        assert!(
            out.findings.is_empty(),
            "a thread in a file-backed image section is ordinary: {:?}",
            out.findings
        );
        assert_eq!(out.starts_tested, 1, "both addresses are the same one");
    }

    #[test]
    fn an_image_range_on_a_non_cached_page_is_not_an_unexpected_protection() {
        // The upper half of `MmProtectToValue` is the lower half with a guard,
        // cache or write-combine attribute added, so the SAME access protection
        // renders as `PAGE_EXECUTE_WRITECOPY` at index 7 and
        // `PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE` at index 23. Comparing the
        // joined string to one constant turns an ordinary thread in an ordinary
        // image into a reported injected thread.
        let mut image = fixture(IMAGE_START, IMAGE_START);
        image.put_u32(PROTECT_TABLE_AT + u64::from(PROT_IMAGE) * 4, 0x80 | 0x200);
        let out = run(image, true);

        assert!(out.analysed);
        assert!(
            out.findings.is_empty(),
            "only the cache attribute differs; the access protection is exactly the one an \
             image section is mapped with: {:?}",
            out.findings
        );
    }

    #[test]
    fn a_protection_naming_only_a_cache_attribute_is_unknown_rather_than_unexpected() {
        // A table entry setting a qualifier bit and no access bit names no
        // protection at all. Calling that unexpected asserts an injected thread
        // on the strength of a value nobody established.
        let mut image = fixture(IMAGE_START, IMAGE_START);
        image.put_u32(PROTECT_TABLE_AT + u64::from(PROT_IMAGE) * 4, 0x200);
        let out = run(image, true);

        let finding = out
            .findings
            .iter()
            .find(|f| f.address == IMAGE_START)
            .expect("an unreadable protection is still reported");
        assert!(finding
            .suspicions
            .iter()
            .any(|s| s.kind == SuspicionKind::ProtectionUnknown));
        assert!(
            !finding
                .suspicions
                .iter()
                .any(|s| s.kind == SuspicionKind::UnexpectedProtection),
            "a protection that was never named cannot be the wrong one"
        );
    }

    #[test]
    fn a_thread_starting_in_a_private_executable_range_is_the_finding_this_exists_for() {
        let out = run(fixture(IMAGE_START, PRIVATE_START), true);
        let finding = out
            .findings
            .iter()
            .find(|f| f.address == PRIVATE_START)
            .expect("the private start is reported");
        assert_eq!(finding.which, StartAddressKind::Win32Start);
        assert!(finding.is_private_start());
        assert!(finding.is_evidence());
        assert!(finding
            .suspicions
            .iter()
            .any(|s| s.kind == SuspicionKind::PrivateRegion));
        // A private RWX range is also not the protection an image section has.
        assert!(finding
            .suspicions
            .iter()
            .any(|s| s.kind == SuspicionKind::UnexpectedProtection));
        assert_eq!(out.evidence().count(), 1);
    }

    #[test]
    fn the_reported_range_is_the_one_the_address_actually_falls_in() {
        let out = run(fixture(IMAGE_START, PRIVATE_START), true);
        let finding = &out.findings[0];
        match &finding.region {
            StartRegion::Vad { base, end, .. } => {
                assert_eq!(*base, u64::from(PRIVATE_PAGE) * 4096);
                assert_eq!(*end, u64::from(PRIVATE_PAGE) * 4096 + 4095);
            }
            other => panic!("expected a range, got {other:?}"),
        }
    }

    #[test]
    fn a_thread_starting_in_another_applications_executable_is_flagged_as_a_foreign_image() {
        let out = run(fixture(IMAGE_START, OTHER_EXE_START), true);
        let finding = out
            .findings
            .iter()
            .find(|f| f.address == OTHER_EXE_START)
            .expect("the foreign image is reported");
        assert!(finding
            .suspicions
            .iter()
            .any(|s| s.kind == SuspicionKind::ForeignImage));
        assert!(
            !finding.is_private_start(),
            "the range is file backed; the finding is that it is the wrong file"
        );
    }

    #[test]
    fn a_start_address_in_no_range_is_counted_and_not_reported_as_an_injection() {
        // Attributing an unattributable address to "no file backs it" would
        // manufacture an injection out of a smeared VAD tree.
        let out = run(fixture(IMAGE_START, 0x7FFF_0000), true);
        assert_eq!(out.starts_outside_the_tree, 1);
        assert!(
            out.findings.iter().all(|f| f.address != 0x7FFF_0000),
            "{:?}",
            out.findings
        );
        assert!(!out.is_complete());
        assert!(out
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("fell in no range")));
    }

    #[test]
    fn a_kernel_start_address_is_counted_apart_and_is_not_a_smeared_tree() {
        // Measured on the Windows 11 capture: 78 starts in no range, every one
        // a kernel address -- kernel threads working inside csrss, lsass,
        // svchost. No VAD can cover a kernel address, so counting them as a
        // smeared tree made every process on a clean machine incomplete.
        let mut image = fixture(IMAGE_START, 0xFFFF_F802_3570_0000);
        image.put_u8(THREAD_AT + off::ETHREAD_SYSTEM_THREAD, 1);
        let profile = profile(
            image.layer(),
            table(&isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let config = SuspiciousThreadsConfig {
            kernel_floor: Some(0xFFFF_8000_0000_0000),
            ..SuspiciousThreadsConfig::for_profile(&profile)
        };
        let out = suspicious_threads(
            &profile,
            &ProcessSymbols::from_profile(&profile).expect("a describable build"),
            &ThreadSymbols::from_profile(&profile).expect("a describable build"),
            &VadSymbols::from_profile(&profile).expect("a describable build"),
            EPROCESS_AT,
            &config,
        )
        .expect("a runnable analysis");
        assert_eq!(out.starts_in_kernel_space, 1);
        assert_eq!(out.starts_outside_the_tree, 0);
        assert!(out.findings.is_empty(), "{:?}", out.findings);
        assert!(out.is_complete(), "{:?}", out.incomplete());
        assert_eq!(out.to_json()["starts_in_kernel_space"], 1);
    }

    #[test]
    fn a_user_address_in_no_range_is_still_unattributed_with_a_kernel_floor_known() {
        let image = fixture(IMAGE_START, 0x7FFF_0000);
        let profile = profile(
            image.layer(),
            table(&isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let config = SuspiciousThreadsConfig {
            kernel_floor: Some(0xFFFF_8000_0000_0000),
            ..SuspiciousThreadsConfig::for_profile(&profile)
        };
        let out = suspicious_threads(
            &profile,
            &ProcessSymbols::from_profile(&profile).expect("a describable build"),
            &ThreadSymbols::from_profile(&profile).expect("a describable build"),
            &VadSymbols::from_profile(&profile).expect("a describable build"),
            EPROCESS_AT,
            &config,
        )
        .expect("a runnable analysis");
        assert_eq!(out.starts_outside_the_tree, 1);
        assert_eq!(out.starts_in_kernel_space, 0);
        assert!(!out.is_complete());
    }

    /// Run the analysis with the configuration `for_profile` builds, over an
    /// ISF the caller may have altered.
    fn run_for_profile(image: Image, isf: &str) -> SuspiciousThreads {
        let profile = profile(
            image.layer(),
            table(isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let config = SuspiciousThreadsConfig::for_profile(&profile);
        suspicious_threads(
            &profile,
            &ProcessSymbols::from_profile(&profile).expect("a describable build"),
            &ThreadSymbols::from_profile(&profile).expect("a describable build"),
            &VadSymbols::from_profile(&profile).expect("a describable build"),
            EPROCESS_AT,
            &config,
        )
        .expect("a runnable analysis")
    }

    /// Where the fixture keeps the `MmHighestUserAddress` value.
    const HIGHEST_USER_AT: u64 = 0x7800;

    /// The fixture ISF with `MmHighestUserAddress` declared, as every real x64
    /// symbol table declares it.
    fn isf_with_highest_user_address() -> String {
        isf().replace(
            r#""symbols": {"MmProtectToValue": {"address": 28672}}"#,
            &format!(
                r#""symbols": {{"MmProtectToValue": {{"address": 28672}},
                   "MmHighestUserAddress": {{"address": {HIGHEST_USER_AT}}}}}"#
            ),
        )
    }

    #[test]
    fn a_non_canonical_start_is_unplaced_not_a_kernel_thread_when_the_user_ceiling_reads() {
        // Review of MEM-024: with MmHighestUserAddress read (0x7FFF_FFFE_FFFF
        // on x64), a floor of that + 1 counted the whole non-canonical hole as
        // kernel space, so a smeared StartAddress such as 0x4141414141414141
        // read as "a kernel thread working inside this process" and the
        // process stayed complete. No thread can start there; it is unplaced.
        let mut image = fixture(IMAGE_START, 0x4141_4141_4141_4141);
        image.put_u64(HIGHEST_USER_AT, 0x7FFF_FFFE_FFFF);
        image.put_u8(THREAD_AT + off::ETHREAD_SYSTEM_THREAD, 1);
        let out = run_for_profile(image, &isf_with_highest_user_address());
        assert_eq!(out.starts_in_kernel_space, 0, "{:?}", out.notes);
        assert_eq!(out.starts_outside_the_tree, 1);
        assert!(!out.is_complete());
    }

    #[test]
    fn a_canonical_kernel_start_is_still_a_kernel_start_when_the_user_ceiling_reads() {
        let mut image = fixture(IMAGE_START, 0xFFFF_F802_3570_0000);
        image.put_u64(HIGHEST_USER_AT, 0x7FFF_FFFE_FFFF);
        image.put_u8(THREAD_AT + off::ETHREAD_SYSTEM_THREAD, 1);
        let out = run_for_profile(image, &isf_with_highest_user_address());
        assert_eq!(out.starts_in_kernel_space, 1, "{:?}", out.notes);
        assert!(out.is_complete(), "{:?}", out.incomplete());
    }

    #[test]
    fn the_kernel_floor_is_the_canonical_kernel_half_on_x64_whatever_the_image_says() {
        assert_eq!(kernel_floor_from(8, None), Some(0xFFFF_8000_0000_0000));
        assert_eq!(
            kernel_floor_from(8, Some(0x7FFF_FFFF_0000)),
            Some(0xFFFF_8000_0000_0000)
        );
    }

    #[test]
    fn the_kernel_floor_on_x86_is_the_system_range_start_the_image_holds() {
        // An ordinary 2 GiB boot and a /3GB boot, read from the image.
        assert_eq!(kernel_floor_from(4, Some(0x8000_0000)), Some(0x8000_0000));
        assert_eq!(kernel_floor_from(4, Some(0xC000_0000)), Some(0xC000_0000));
        // Unread, or implausible: the highest the floor can be, so a user
        // start is never waved through as a kernel one.
        assert_eq!(kernel_floor_from(4, None), Some(0xC000_0000));
        assert_eq!(kernel_floor_from(4, Some(0x1234)), Some(0xC000_0000));
        assert_eq!(kernel_floor_from(4, Some(0xFFFF_0000)), Some(0xC000_0000));
        assert_eq!(kernel_floor_from(2, None), None);
    }

    #[test]
    fn a_kernel_start_on_a_thread_whose_system_thread_bit_is_clear_is_not_waved_through() {
        // Review of MEM-024: the tamper_checks orphan-thread group excludes
        // every thread with SystemThread clear, so a kernel start on such a
        // thread was judged by neither stage while this one called it kernel.
        let image = fixture(IMAGE_START, 0xFFFF_F802_3570_0000);
        let out = run_for_profile(image, &isf());
        assert_eq!(out.starts_in_kernel_space, 0);
        assert_eq!(out.kernel_starts_on_threads_not_known_as_system, 1);
        assert!(!out.is_complete());
        assert!(out
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("SystemThread")));
        assert_eq!(
            out.to_json()["kernel_starts_on_threads_not_known_as_system"],
            1
        );
    }

    #[test]
    fn a_kernel_start_on_a_build_without_system_thread_is_not_waved_through() {
        let mut image = fixture(IMAGE_START, 0xFFFF_F802_3570_0000);
        image.put_u8(THREAD_AT + off::ETHREAD_SYSTEM_THREAD, 1);
        let isf = isf().replace(
            r#""State": {"offset": 8, "type": {"kind": "base", "name": "unsigned char"}},
      "SystemThread": {"offset": 16, "type": {"kind": "bitfield", "bit_position": 0,
                       "bit_length": 1, "type": {"kind": "base", "name": "unsigned long"}}}"#,
            r#""State": {"offset": 8, "type": {"kind": "base", "name": "unsigned char"}}"#,
        );
        assert!(!isf.contains("SystemThread"));
        let out = run_for_profile(image, &isf);
        assert_eq!(out.starts_in_kernel_space, 0);
        assert_eq!(out.kernel_starts_on_threads_not_known_as_system, 1);
        assert!(!out.is_complete());
    }

    #[test]
    fn an_unreadable_lpc_bit_leaves_the_win32_start_unjudged_and_the_process_incomplete() {
        // The bit declared past the end of the image: a read of it fails, as
        // a paged-out or smeared _ETHREAD's would.
        let isf = isf().replace(
            r#""LpcReceivedMsgIdValid": {"offset": 96,"#,
            r#""LpcReceivedMsgIdValid": {"offset": 1048576,"#,
        );
        assert!(isf.contains("1048576"));
        let out = run_for_profile(fixture(IMAGE_START, PRIVATE_START), &isf);
        assert_eq!(out.lpc_flag_unreadable, 1);
        assert_eq!(out.win32_starts_holding_an_lpc_message_id, 0);
        assert!(out.findings.is_empty(), "{:?}", out.findings);
        assert_eq!(out.starts_tested, 1, "only StartAddress was judged");
        assert!(!out.is_complete());
        assert!(out
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("LpcReceivedMsgIdValid")));
    }

    #[test]
    fn a_win32_start_holding_an_lpc_message_id_is_not_judged_as_an_address() {
        // Measured on be2.vmem (XP SP2): smss.exe's Win32StartAddress read
        // 0x66ae, which lands in the reserved range at address zero and reads
        // as a thread started in private memory -- Volatility 3 reports it so.
        // On XP the field is a union with LpcReceivedMessageId, and the
        // thread's LpcReceivedMsgIdValid bit was set: it is a message id.
        let mut image = fixture(IMAGE_START, PRIVATE_START);
        image.put_u8(THREAD_AT + off::ETHREAD_LPC_FLAGS, 1);
        let out = run(image, true);
        assert!(out.findings.is_empty(), "{:?}", out.findings);
        assert_eq!(out.win32_starts_holding_an_lpc_message_id, 1);
        assert_eq!(out.starts_tested, 1, "only StartAddress was an address");
        assert!(out.is_complete(), "{:?}", out.incomplete());
    }

    #[test]
    fn with_the_lpc_bit_clear_the_win32_start_is_judged_as_before() {
        let out = run(fixture(IMAGE_START, PRIVATE_START), true);
        assert_eq!(out.win32_starts_holding_an_lpc_message_id, 0);
        assert_eq!(out.evidence().count(), 1);
    }

    #[test]
    fn without_a_protection_table_the_protection_is_a_gap_and_not_a_finding() {
        let out = run(fixture(IMAGE_START, IMAGE_START), false);
        let finding = out
            .findings
            .iter()
            .find(|f| f.address == IMAGE_START)
            .expect("the unknown protection is recorded");
        assert!(finding
            .suspicions
            .iter()
            .all(|s| s.kind == SuspicionKind::ProtectionUnknown));
        assert!(
            !finding.is_evidence(),
            "a check that could not be performed is not a detection"
        );
        assert_eq!(out.evidence().count(), 0);
        assert_eq!(out.gaps().count(), 1);
    }

    #[test]
    fn a_terminated_thread_is_not_judged() {
        let mut image = fixture(IMAGE_START, PRIVATE_START);
        // Tcb.State = 4, terminated.
        image.put_u8(THREAD_AT + off::ETHREAD_TCB_PROCESS + 8, 4);
        let out = run(image, true);
        assert_eq!(out.threads_terminated, 1);
        assert_eq!(out.threads_examined, 0);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn a_process_with_too_few_ranges_is_not_judged_and_says_so() {
        // A tree this small is a smeared one. An empty finding list from it
        // would read exactly like a clean process.
        let mut image = fixture(IMAGE_START, PRIVATE_START);
        image.put_u64(VADS[1] + off::VAD_RIGHT, 0);
        let out = run(image, true);
        assert!(!out.analysed);
        assert_eq!(out.vads, 2);
        assert!(out.findings.is_empty());
        assert!(!out.is_complete());
        assert!(out
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("too few")));
    }

    #[test]
    fn the_same_address_is_judged_once_however_many_threads_start_there() {
        let out = run(fixture(PRIVATE_START, PRIVATE_START), true);
        assert_eq!(out.starts_tested, 1);
        assert_eq!(out.findings.len(), 1);
    }

    // ── The image-wide survey (MEM-024) ─────────────────────────────────────

    const CLEAN_EPROCESS_AT: u64 = 0x2000;
    const CLEAN_THREAD_AT: u64 = 0x3800;
    /// An `_EPROCESS` address past the end of the fixture image.
    const UNREADABLE_EPROCESS_AT: u64 = 0x10_0000;

    /// The fixture's process, plus a second one sharing its memory map whose
    /// only thread starts in its own image.
    fn two_process_fixture(injected_start: u64) -> Image {
        let mut image = fixture(IMAGE_START, injected_start);
        let eprocess = CLEAN_EPROCESS_AT;
        image.put_u64(eprocess + off::EPROCESS_VAD_ROOT, VADS[0]);
        image.put_u64(eprocess + off::EPROCESS_PID, 0x500);
        image.write(eprocess + off::EPROCESS_NAME, b"explorer.exe");
        image.put_u64(
            eprocess + off::EPROCESS_SECTION_BASE,
            u64::from(IMAGE_PAGE) * 4096,
        );
        let head = eprocess + off::EPROCESS_THREAD_LIST_HEAD;
        let link = CLEAN_THREAD_AT + off::ETHREAD_LIST_ENTRY;
        image.put_u64(head, link);
        image.put_u64(head + 8, link);
        image.put_u64(link, head);
        image.put_u64(link + 8, head);
        image.put_u64(CLEAN_THREAD_AT + off::ETHREAD_CID_THREAD, 0x200);
        image.put_u64(CLEAN_THREAD_AT + off::ETHREAD_CID_PROCESS, 0x500);
        image.put_u64(CLEAN_THREAD_AT + off::ETHREAD_START, IMAGE_START);
        image.put_u64(CLEAN_THREAD_AT + off::ETHREAD_WIN32_START, IMAGE_START);
        image.put_u64(CLEAN_THREAD_AT + off::ETHREAD_TCB_PROCESS, eprocess);
        image
    }

    fn listed(address: u64, pid: u64, peb: Field<u64>) -> ProcessRecord {
        ProcessRecord {
            address,
            direction: WalkDirection::Forward,
            pid: Field::Known(pid),
            ppid: Field::Known(4),
            image_file_name: Field::Known("explorer.exe".to_string()),
            image_name_well_formed: true,
            threads: Field::NotApplicable,
            handles: Field::NotApplicable,
            session_id: Field::NotApplicable,
            wow64: Field::NotApplicable,
            create_time: ProcessTime::NotRecorded,
            exit_time: ProcessTime::NotRecorded,
            peb,
            notes: Vec::new(),
        }
    }

    fn process_list(processes: Vec<ProcessRecord>) -> ProcessList {
        ProcessList {
            head: 0x900,
            links_offset: 48,
            processes,
            forward_stop: ListStop::Wrapped,
            backward_stop: None,
        }
    }

    fn survey(image: Image, list: &ProcessList, max_processes: usize) -> SuspiciousThreadsSurvey {
        let profile = profile(
            image.layer(),
            table(&isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = SuspiciousThreadSymbols::from_profile(&profile).expect("a describable build");
        let config = SuspiciousThreadsConfig {
            max_processes,
            ..SuspiciousThreadsConfig::for_profile(&profile)
        };
        survey_suspicious_threads(&profile, &symbols, list, &config)
    }

    #[test]
    fn a_survey_reports_the_injected_process_and_not_the_clean_one() {
        let list = process_list(vec![
            listed(EPROCESS_AT, 0x400, Field::Known(0x7000_0000)),
            listed(CLEAN_EPROCESS_AT, 0x500, Field::Known(0x7000_0000)),
        ]);
        let out = survey(two_process_fixture(PRIVATE_START), &list, 64);

        assert!(
            out.protections_available,
            "for_profile loads MmProtectToValue"
        );
        assert_eq!(out.processes.len(), 2, "both processes are judged: {out:?}");
        let injected = out
            .processes
            .iter()
            .find(|p| p.process == EPROCESS_AT)
            .expect("the injected process is on the survey");
        assert_eq!(injected.evidence().count(), 1);
        assert!(injected
            .evidence()
            .next()
            .expect("one finding")
            .suspicions
            .iter()
            .any(|s| s.kind == SuspicionKind::PrivateRegion));
        let clean = out
            .processes
            .iter()
            .find(|p| p.process == CLEAN_EPROCESS_AT)
            .expect("the clean process is on the survey, not dropped");
        assert!(clean.analysed);
        assert!(clean.findings.is_empty(), "{:?}", clean.findings);

        assert_eq!(out.evidence_count(), 1);
        assert_eq!(out.gap_count(), 0);
        assert_eq!(out.evidence_by_kind().get("private_region"), Some(&1));
        let json = out.to_json();
        assert_eq!(json["evidence_count"], 1);
        assert_eq!(json["processes_analysed"], 2);
        // One distinct address each in the clean process; two in the injected.
        assert_eq!(json["starts_tested"], 3);
        assert_eq!(json["starts_outside_the_tree"], 0);
        assert!(out.is_complete(), "{:?}", out.incomplete());
    }

    #[test]
    fn a_process_whose_vad_walk_fails_is_listed_as_skipped_not_dropped() {
        let list = process_list(vec![
            listed(CLEAN_EPROCESS_AT, 0x500, Field::Known(0x7000_0000)),
            listed(UNREADABLE_EPROCESS_AT, 0x600, Field::Known(0x7000_0000)),
        ]);
        let out = survey(two_process_fixture(IMAGE_START), &list, 64);

        assert_eq!(out.processes.len(), 1);
        assert_eq!(out.skipped.len(), 1, "{out:?}");
        assert_eq!(out.skipped_total, 1);
        assert_eq!(out.skipped[0].process, UNREADABLE_EPROCESS_AT);
        assert!(!out.skipped[0].reason.is_empty());
        assert!(
            !out.is_complete(),
            "a failed process may be the injected one"
        );
        assert_eq!(out.to_json()["complete"], false);
    }

    #[test]
    fn a_process_with_no_user_address_space_is_out_of_scope_and_does_not_make_the_survey_incomplete(
    ) {
        let list = process_list(vec![
            listed(CLEAN_EPROCESS_AT, 0x500, Field::Known(0x7000_0000)),
            listed(UNREADABLE_EPROCESS_AT, 4, Field::NotApplicable),
        ]);
        let out = survey(two_process_fixture(IMAGE_START), &list, 64);

        assert_eq!(out.processes.len(), 1);
        assert_eq!(out.skipped_total, 0);
        assert_eq!(out.out_of_scope_total, 1);
        // Review of MEM-024: the reason states what was observed, not an
        // inference -- a WSL1 pico process also has a null Peb and does have
        // user threads.
        let reason = &out.out_of_scope[0].reason;
        assert!(reason.contains("null Peb"), "{reason}");
        assert!(
            !reason.contains("its threads are kernel threads"),
            "{reason}"
        );
        assert!(reason.contains("pico"), "{reason}");
        assert!(out.is_complete(), "{:?}", out.incomplete());
    }

    #[test]
    fn the_survey_is_incomplete_when_the_process_cap_is_hit() {
        let list = process_list(vec![
            listed(CLEAN_EPROCESS_AT, 0x500, Field::Known(0x7000_0000)),
            listed(EPROCESS_AT, 0x400, Field::Known(0x7000_0000)),
        ]);
        let out = survey(two_process_fixture(PRIVATE_START), &list, 1);

        assert_eq!(out.processes.len(), 1);
        assert_eq!(out.stop, ScanStop::CapReached { cap: 1 });
        assert!(!out.is_complete());
        assert_eq!(out.to_json()["stop"], "cap_reached");
    }

    #[test]
    fn a_gap_and_a_finding_are_distinguishable_in_the_serialised_form() {
        let out = run(fixture(IMAGE_START, PRIVATE_START), true);
        let json = out.to_json();
        assert_eq!(json["analysed"], true);
        assert_eq!(json["evidence_count"], 1);
        let suspicions = json["findings"][0]["suspicions"]
            .as_array()
            .expect("an array of suspicions");
        assert!(suspicions.iter().any(|s| s["gap"] == false));
    }
}
