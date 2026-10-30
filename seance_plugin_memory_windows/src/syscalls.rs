//! Detecting system calls issued from somewhere they should not be.
//!
//! Endpoint security products hook the user-mode stubs in `ntdll.dll`: a program
//! that wants to open a process calls `NtOpenProcess`, the hook sees it, and the
//! product decides. Malware defeats that by never entering the hooked stub. It
//! issues the `syscall` instruction from its own code, having set up the
//! registers itself, and the kernel is entered with the product none the wiser.
//! The technique is known as Hell's Gate, Halo's Gate and Tartarus Gate among
//! others; the variants differ in how they discover the system call number, not
//! in what the resulting code block looks like:
//!
//! ```text
//! mov r10, rcx          ; the first argument, where the kernel expects it
//! mov eax, 0x26         ; the system call number
//! syscall               ; enter the kernel directly
//! ret                   ; back to the caller
//! ```
//!
//! Two facts make that a finding rather than a curiosity. On Windows **only
//! `ntdll.dll` and `win32u.dll` legitimately contain `syscall` instructions** —
//! everything else goes through them, so a `syscall` in a private allocation was
//! put there by something avoiding the stubs. And the *indirect* variant does not
//! contain `syscall` at all: it jumps into the real `ntdll` stub past the hook,
//! so what marks it is a `jmp [rip+disp32]`, not `0f 05`.
//!
//! # Why this needs a disassembler
//!
//! Searching for the bytes `0f 05` finds every `syscall` instruction, and also
//! every place those two bytes occur inside a longer instruction, inside data,
//! or inside a compressed blob. It cannot tell you whether the surrounding bytes
//! form a valid block that sets up the registers the kernel requires.
//!
//! The detection is a walk over *decoded* instructions: from the candidate,
//! decode forward watching for writes to `rax`/`eax` (the call number) and `r10`
//! (the first argument), stopping at an instruction that cannot appear in such a
//! block or at the expected terminator. x86-64 instructions are one to fifteen
//! bytes and the length depends on the encoding, so knowing where the next one
//! begins means decoding this one. That is why [`iced_x86`] is a dependency.
//!
//! # What is reported
//!
//! A signal and its evidence: the address, the module that owns it or the fact
//! that none does, the decoded instructions, and which register writes were
//! seen. Not a verdict. Some legitimate software issues direct system calls —
//! anti-cheat, sandboxes, instrumentation — and whether a given block is
//! malicious is the examiner's call.

use std::collections::BTreeSet;
use std::sync::Arc;

use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, InstructionInfoFactory, IntelFormatter,
    OpAccess, Register,
};
use seance_core::io::IncompleteReason;
use seance_memory::object::StructReader;
use seance_memory::translate::TableCache;
use seance_memory::Incomplete;
use serde_json::json;
use thiserror::Error;

use crate::process::{ProcessInventory, ProcessList, ProcessRecord, ProcessSymbols};
use crate::profile::WindowsProfile;
use crate::vad::{Vad, VadSymbols, VadWalkConfig};

/// The modules that legitimately contain `syscall` instructions.
pub const VALID_SYSCALL_HANDLERS: [&str; 2] = ["ntdll.dll", "win32u.dll"];

/// Largest region examined, in bytes.
///
/// A syscall stub is tens of bytes; a region above this is a mapped image or a
/// heap, and decoding all of it costs far more than it finds. Regions past the
/// cap are counted and reported, never silently skipped.
pub const MAX_REGION_BYTES: u64 = 10_000_000;

/// Instructions decoded from one candidate before giving up. A real stub
/// terminates within a handful; this bounds the walk on attacker-controlled
/// bytes.
pub const MAX_BLOCK_INSTRUCTIONS: usize = 64;

/// Bytes decoded from one candidate.
pub const MAX_BLOCK_BYTES: usize = 256;

/// Candidates examined per process before the sweep declares itself truncated.
pub const MAX_CANDIDATES_PER_PROCESS: usize = 4096;

/// Something that stopped the analysis, as distinct from a finding.
#[derive(Debug, Error)]
pub enum SyscallError {
    /// The build or the image cannot support this stage.
    #[error("{0}")]
    Unsupported(String),
    /// The process's memory regions could not be enumerated.
    #[error("the process's memory regions could not be enumerated: {0}")]
    Regions(#[from] crate::vad::VadError),
}

impl SyscallError {
    /// An image or build this stage cannot analyse, naming why.
    pub fn unsupported(detail: impl Into<String>) -> Self {
        SyscallError::Unsupported(detail.into())
    }
}

/// Which evasion a block is evidence of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Technique {
    /// The `syscall` instruction is in the block: the kernel is entered without
    /// touching `ntdll` at all.
    Direct,
    /// The block jumps to a `syscall` elsewhere — normally the real `ntdll`
    /// stub, entered past whatever hook sits at its start.
    Indirect,
}

impl Technique {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Technique::Direct => "direct_system_call",
            Technique::Indirect => "indirect_system_call",
        }
    }

    /// The bytes a candidate starts with. These only *locate* candidates —
    /// every one is decoded and most are discarded.
    fn needle(self) -> &'static [u8] {
        match self {
            Technique::Direct => &[0x0F, 0x05],   // syscall
            Technique::Indirect => &[0xFF, 0x25], // jmp [rip+disp32]
        }
    }

    /// Whether a valid block for this technique contains `syscall` itself.
    fn wants_syscall_instruction(self) -> bool {
        matches!(self, Technique::Direct)
    }

    /// Mnemonics that cannot appear in a valid block of this shape.
    fn invalid_ops(self) -> &'static [&'static str] {
        match self {
            Technique::Direct => &["jmp", "call", "leave", "int3"],
            // An indirect block ends *at* the jmp, so a `ret` before it means
            // this is not one.
            Technique::Indirect => &["call", "leave", "int3", "ret"],
        }
    }

    /// The mnemonic a valid block ends on.
    fn termination_ops(self) -> &'static [&'static str] {
        match self {
            Technique::Direct => &["ret"],
            Technique::Indirect => &["jmp"],
        }
    }
}

/// One block with the shape of an evasive system call.
#[derive(Debug, Clone)]
pub struct SyscallBlock {
    /// Which technique it matches.
    pub technique: Technique,
    /// Virtual address of the block's **first instruction**.
    ///
    /// An instruction boundary, not the base of the window the search backed up
    /// to. An examiner who disassembles from this address sees the same stream
    /// [`SyscallBlock::disassembly`] holds; an address taken from a fixed
    /// backward offset is usually in the middle of an instruction, and
    /// disassembling from it reproduces neither the block nor anything the
    /// process ever executed.
    pub address: u64,
    /// The module owning the address, when the region is file-backed. `None`
    /// means none does, which is the more interesting answer.
    pub module: Option<String>,
    /// Whether that module legitimately issues system calls.
    ///
    /// `Some(false)` is the finding: either no legitimate handler owns this
    /// address, or a region wearing one of their names is private memory
    /// rather than a shared image mapping of the file. `None` means the
    /// region carries the name but its private/shared state could not be read,
    /// so neither answer was established — the region was searched anyway, and
    /// a row from it must not be printed as "a module issuing system calls
    /// that is not allowed to" on the strength of a field nobody could read.
    pub in_valid_handler: Option<bool>,
    /// The decoded instructions, so an examiner reads the code rather than
    /// taking this module's word for it.
    pub disassembly: String,
    /// Whether the block wrote the call number to `rax`/`eax`.
    pub sets_syscall_number: bool,
    /// Whether the block wrote the first argument to `r10`.
    pub sets_first_argument: bool,
    /// Whether a `syscall` instruction was decoded inside the block.
    pub contains_syscall: bool,
    /// For the indirect technique, where the jump goes.
    pub jump_target: Option<u64>,
}

impl SyscallBlock {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "technique": self.technique.as_str(),
            "address": self.address,
            // Exact beside the number: the address an examiner disassembles
            // from is above 2^53 in a 64-bit process and JSON numbers are IEEE
            // doubles, so the numeric form can reach a client rounded off the
            // instruction boundary this stage worked to establish.
            "address_hex": format!("{:#x}", self.address),
            "module": self.module,
            "in_valid_syscall_handler": self.in_valid_handler,
            "disassembly": self.disassembly,
            "sets_syscall_number": self.sets_syscall_number,
            "sets_first_argument": self.sets_first_argument,
            "contains_syscall": self.contains_syscall,
            "jump_target": self.jump_target,
            "jump_target_hex": self.jump_target.map(|target| format!("{target:#x}")),
        })
    }
}

/// One process's results.
#[derive(Debug, Clone)]
pub struct ProcessSyscalls {
    /// Where the `_EPROCESS` is.
    pub process: u64,
    /// Process id, when readable.
    pub pid: Option<u64>,
    /// Image name, when readable.
    pub name: Option<String>,
    /// The blocks found.
    pub blocks: Vec<SyscallBlock>,
    /// Regions skipped for exceeding the size cap.
    pub regions_too_large: usize,
    /// Regions whose bytes could not be read.
    pub regions_unreadable: usize,
    /// Regions not searched because they are a shared image mapping of a module
    /// that legitimately issues system calls.
    ///
    /// Counted rather than merely skipped: "no direct-syscall stub in this
    /// process" is a different statement from "no direct-syscall stub outside
    /// its `ntdll`", and only one of them is true when this is non-zero. A
    /// region carrying such a name that is *not* a shared image mapping is
    /// searched, not counted here — see [`trusts_module_name`].
    pub regions_in_valid_handler: usize,
    /// Regions that carry a legitimate handler's name but whose private/shared
    /// state could not be read, so the name could neither be borne out nor
    /// contradicted.
    ///
    /// These were searched — the safe direction — and every block found in one
    /// carries `in_valid_handler: null`. The count is here so a result full of
    /// `ntdll.dll` rows is read as "this image could not tell us which regions
    /// really are `ntdll`" rather than as a machine running hundreds of
    /// hand-mapped stub tables.
    pub regions_named_handler_unverified: usize,
    /// Whether the candidate cap was reached.
    pub truncated: bool,
    /// Whether the region walk itself was complete.
    pub regions_complete: bool,
}

impl ProcessSyscalls {
    /// Whether this process was examined in full.
    ///
    /// False means the answer is a floor: blocks may exist in what was skipped,
    /// and reporting "none found" would be the wrong claim.
    pub fn is_complete(&self) -> bool {
        !self.truncated
            && self.regions_complete
            && self.regions_too_large == 0
            && self.regions_unreadable == 0
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "process": self.process,
            "process_hex": format!("{:#x}", self.process),
            "pid": self.pid,
            "process_name": self.name,
            "blocks": self.blocks.iter().map(SyscallBlock::to_json).collect::<Vec<_>>(),
            "block_count": self.blocks.len(),
            "regions_too_large": self.regions_too_large,
            "regions_unreadable": self.regions_unreadable,
            "regions_in_valid_handler": self.regions_in_valid_handler,
            "regions_named_handler_unverified": self.regions_named_handler_unverified,
            "truncated": self.truncated,
            "regions_complete": self.regions_complete,
            "content_complete": self.is_complete(),
        })
    }
}

/// The whole sweep.
#[derive(Debug, Clone)]
pub struct SyscallScan {
    /// Per-process results, in process-list order.
    pub processes: Vec<ProcessSyscalls>,
    /// Processes that could not be examined at all, with the reason.
    pub skipped: Vec<(u64, String)>,
    /// How complete the process list this sweep walked was.
    ///
    /// The sweep can only examine the processes it was handed. A list that
    /// stopped short means "no evasion found" is a floor, not a finding, and
    /// this is what makes that visible on the artifact.
    pub inventory: ProcessInventory,
}

impl SyscallScan {
    /// Every block, across every process.
    pub fn blocks(&self) -> impl Iterator<Item = (&ProcessSyscalls, &SyscallBlock)> {
        self.processes
            .iter()
            .flat_map(|p| p.blocks.iter().map(move |b| (p, b)))
    }

    /// Whether every process was examined in full.
    ///
    /// Includes the inventory: a sweep that examined every process it was
    /// handed is still incomplete when the list it was handed stopped short,
    /// because the evasion it is looking for may sit in a process the list
    /// never reached.
    pub fn is_complete(&self) -> bool {
        self.inventory.is_complete()
            && self.skipped.is_empty()
            && self.processes.iter().all(ProcessSyscalls::is_complete)
    }

    /// Every reason this sweep is a floor rather than a total, in the shape the
    /// record builder reads.
    ///
    /// [`SyscallScan::is_complete`] answers *whether* the sweep fell short; this
    /// answers *why*, and it is the answer that reaches the examiner. The stage
    /// record built in `module.rs` derives `content_incomplete_reason` from a
    /// top-level `incomplete` array and from nothing else, so a sweep that knows
    /// it skipped four processes and hit its candidate cap but does not emit
    /// this reads, on the artifact, as "did not establish this result in full
    /// and recorded no reason" — an honest flag attached to a reason the code
    /// had all along and threw away.
    ///
    /// Empty exactly when [`SyscallScan::is_complete`] is true.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.inventory.incomplete.clone();
        // An inventory that says it fell short but names nothing would produce a
        // sweep flagged incomplete for no stated reason, which is the exact
        // shape this method exists to prevent. Say the one thing that is known.
        if !self.inventory.is_complete() && out.is_empty() {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the active process list walked from {:#x} did not reach every process, so \
                     any process it never listed was never searched",
                    self.inventory.head
                ),
            ));
        }
        for (process, reason) in &self.skipped {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the process at {process:#x} was not searched for evasive system calls: \
                     {reason}"
                ),
            ));
        }
        for entry in &self.processes {
            let process = entry.process;
            if entry.truncated {
                out.push(Incomplete::new(
                    IncompleteReason::CapReached,
                    format!(
                        "the search of the process at {process:#x} stopped at its candidate cap, \
                         so its memory was searched only up to that point"
                    ),
                ));
            }
            if !entry.regions_complete {
                out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the memory regions of the process at {process:#x} were not enumerated in \
                         full, so regions that were never listed were never searched"
                    ),
                ));
            }
            if entry.regions_too_large > 0 {
                out.push(Incomplete::new(
                    IncompleteReason::CapReached,
                    format!(
                        "{} region(s) of the process at {process:#x} exceeded the size cap and \
                         were not searched",
                        entry.regions_too_large
                    ),
                ));
            }
            if entry.regions_unreadable > 0 {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "{} region(s) of the process at {process:#x} could not be read and were \
                         not searched",
                        entry.regions_unreadable
                    ),
                ));
            }
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = json!({
            "name": "System call evasion",
            "processes": self
                .processes
                .iter()
                .map(ProcessSyscalls::to_json)
                .collect::<Vec<_>>(),
            "skipped": self
                .skipped
                .iter()
                .map(|(addr, why)| json!({"process": addr, "reason": why}))
                .collect::<Vec<_>>(),
            "total_blocks": self.processes.iter().map(|p| p.blocks.len()).sum::<usize>(),
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        });
        self.inventory.stamp(&mut value);
        value
    }
}

/// What the sweep is allowed to do.
#[derive(Debug, Clone)]
pub struct SyscallConfig {
    /// Which techniques to look for.
    pub techniques: Vec<Technique>,
    /// Regions above this are skipped and counted.
    pub max_region_bytes: u64,
    /// Candidates examined per process.
    pub max_candidates: usize,
    /// How the region tree is walked.
    pub vad: VadWalkConfig,
    /// Whether to report blocks inside `ntdll.dll` or `win32u.dll`.
    ///
    /// Off by default: those modules are *supposed* to contain stubs, so
    /// reporting them buries the finding under thousands of legitimate rows. An
    /// examiner chasing a patched `ntdll` turns it on.
    pub include_valid_handlers: bool,
}

impl Default for SyscallConfig {
    fn default() -> Self {
        Self {
            techniques: vec![Technique::Direct, Technique::Indirect],
            max_region_bytes: MAX_REGION_BYTES,
            max_candidates: MAX_CANDIDATES_PER_PROCESS,
            vad: VadWalkConfig::default(),
            include_valid_handlers: false,
        }
    }
}

/// Everything this stage resolves from the profile up front.
#[derive(Debug, Clone)]
pub struct SyscallSymbols {
    /// How to walk a process's memory regions.
    pub vad: VadSymbols,
    /// How to build a process's address space.
    pub process: ProcessSymbols,
}

impl SyscallSymbols {
    /// Resolve from a profile, failing closed when the image cannot support the
    /// stage.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, SyscallError> {
        if !profile.is_64bit() {
            // On 32-bit Windows the kernel is entered through the shared user
            // page, not by a `syscall` instruction, and there is no `r10`
            // argument convention. Saying so beats sweeping and reporting "none
            // found", which would imply the question had been asked.
            return Err(SyscallError::unsupported(
                "system-call evasion detection applies to 64-bit Windows; this image is 32-bit, \
                 where the kernel is entered through the shared user page rather than by a \
                 `syscall` instruction",
            ));
        }
        Ok(Self {
            vad: VadSymbols::from_profile(profile)?,
            process: ProcessSymbols::from_profile(profile)
                .map_err(|e| SyscallError::unsupported(e.to_string()))?,
        })
    }
}

/// Sweep every process for evasive system-call blocks.
///
/// A process that cannot be examined is recorded in [`SyscallScan::skipped`]
/// and the rest are still swept: one unreadable process must not cost the
/// answer for the other hundred.
pub fn scan_processes(
    profile: &WindowsProfile,
    symbols: &SyscallSymbols,
    list: &ProcessList,
    config: &SyscallConfig,
) -> SyscallScan {
    let cache = Arc::new(TableCache::new());
    let mut scan = SyscallScan {
        processes: Vec::new(),
        skipped: Vec::new(),
        inventory: list.inventory(),
    };

    for entry in &list.processes {
        match scan_process(profile, symbols, entry, config, &cache) {
            Ok(result) => scan.processes.push(result),
            Err(err) => scan.skipped.push((entry.address, err.to_string())),
        }
    }
    scan
}

/// Sweep one process.
pub fn scan_process(
    profile: &WindowsProfile,
    symbols: &SyscallSymbols,
    entry: &ProcessRecord,
    config: &SyscallConfig,
    cache: &Arc<TableCache>,
) -> Result<ProcessSyscalls, SyscallError> {
    let tree = crate::vad::list_vads(profile, &symbols.vad, entry.address, &config.vad)?;

    // No address space means the process's memory is not there to search.
    // Returning an empty result would read as "this process is clean".
    let layer =
        crate::process::process_address_space(profile, &symbols.process, entry.address, cache)
            .map_err(|err| {
                SyscallError::unsupported(format!(
                    "process {:#x} has no readable address space, so its memory could not be \
                     searched: {err}",
                    entry.address
                ))
            })?;
    let reader = StructReader::new(Arc::clone(&layer), Arc::clone(&profile.symbols));

    let mut result = ProcessSyscalls {
        process: entry.address,
        pid: entry.pid.known().copied(),
        name: entry.image_file_name.known().cloned(),
        blocks: Vec::new(),
        regions_too_large: 0,
        regions_unreadable: 0,
        regions_in_valid_handler: 0,
        regions_named_handler_unverified: 0,
        truncated: false,
        regions_complete: tree.is_complete(),
    };

    let mut candidates = 0usize;
    'regions: for vad in &tree.vads {
        if vad.size() > config.max_region_bytes {
            result.regions_too_large += 1;
            continue;
        }
        let Ok(bytes) = reader.read_bytes(vad.start, vad.size()) else {
            result.regions_unreadable += 1;
            continue;
        };

        let module = vad.file.name().map(str::to_string);
        // A name alone does not make a region `ntdll`. The name comes from the
        // control area the VAD points at, and a range that carries the name
        // while not being a shared image mapping of it is the shape of the
        // very evasion this stage looks for.
        let in_valid_handler = valid_handler_status(vad, module.as_deref());
        if in_valid_handler == Some(true) && !config.include_valid_handlers {
            result.regions_in_valid_handler += 1;
            continue;
        }
        if in_valid_handler.is_none() {
            result.regions_named_handler_unverified += 1;
        }

        for technique in &config.techniques {
            for offset in find_needles(&bytes, technique.needle()) {
                if candidates >= config.max_candidates {
                    result.truncated = true;
                    break 'regions;
                }
                candidates += 1;

                if let Some(mut block) = decode_candidate(*technique, &bytes, offset, vad.start) {
                    block.module = module.clone();
                    block.in_valid_handler = in_valid_handler;
                    result.blocks.push(block);
                }
            }
        }
    }

    Ok(result)
}

/// Every offset at which `needle` occurs.
fn find_needles(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    memchr::memmem::find_iter(haystack, needle).collect()
}

/// Whether a region's own shape bears out the module name it carries.
///
/// The stubs a legitimate `ntdll.dll` or `win32u.dll` contains live in a
/// **shared image mapping** of that file. A region that names one of them while
/// being private memory is not that file: it is memory somebody arranged to
/// carry the name, which is exactly how a Hell's-Gate loader hides a copied
/// stub table where this stage has been told not to look. A region whose
/// private/shared state could not be read is not trusted either — the whole
/// point of the skip is that the region is known-legitimate, and an unread
/// field is not knowledge.
///
/// # What a wrong answer looks like
///
/// A process with a hand-mapped `ntdll` full of direct-syscall stubs reported
/// as having no evasion at all, because the fake carried the real name.
fn trusts_module_name(vad: &Vad) -> bool {
    vad.private_memory == Some(false)
}

/// Whether the region an address lives in is a module that legitimately issues
/// system calls: `Some(true)` established, `Some(false)` established otherwise,
/// `None` when the region wears the name and nothing could corroborate it.
///
/// The three-way answer is the point. Collapsing `None` into `false` would put
/// every stub in a genuine `ntdll` on the "modules issuing system calls that
/// are not allowed to" list for any image whose `_MMVAD.PrivateMemory` could
/// not be read — an accusation resting on a field nobody managed to read.
/// Collapsing it into `true` would hand a hand-mapped `ntdll` the exemption.
fn valid_handler_status(vad: &Vad, module: Option<&str>) -> Option<bool> {
    if !module.is_some_and(is_valid_syscall_handler) {
        // Nothing here claims to be one of the two legitimate handlers, so
        // there is nothing to corroborate and the answer is known.
        return Some(false);
    }
    if trusts_module_name(vad) {
        return Some(true);
    }
    // `Some(true)` private memory wearing the name is positively not the
    // module; `None` — the flag was unread — stays unknown.
    vad.private_memory.map(|_| false)
}

/// Whether a module path is one of the two that legitimately issue system calls.
///
/// Compared on the final path component, not as a substring: a file called
/// `ntdll.dll.bak` in an attacker-controlled directory is not `ntdll.dll`.
fn is_valid_syscall_handler(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let leaf = lower.rsplit(['\\', '/']).next().unwrap_or(&lower);
    VALID_SYSCALL_HANDLERS.contains(&leaf)
}

/// Turn one byte match into a block, reported at the address it really starts
/// at.
///
/// A direct stub sets up its registers *before* the `syscall`, so decoding from
/// the matched bytes alone would never see the setup and every real stub would
/// be discarded. The search therefore backs up — and that is where the care is
/// needed, because x86-64 instructions are one to fifteen bytes and the byte a
/// fixed distance back is almost always in the middle of one. Decoding from it
/// produces a stream the processor never executed: instructions assembled from
/// the tail of one encoding and the head of the next, which can both hide a
/// genuine stub behind a bogus `call` and manufacture register writes that were
/// never there.
///
/// So the window is first resolved to real instruction boundaries
/// ([`instruction_starts`]), and the block is decoded from those. Boundaries are
/// tried **latest first**, so the block reported is the shortest run of real
/// instructions that satisfies every criterion — the stub itself, rather than
/// the stub with whatever unrelated code happened to precede it glued to the
/// front.
///
/// `bytes` is the region as read, `needle` the offset of the matched bytes
/// within it, and `base` the region's virtual address.
///
/// Returns `None` when no boundary in the window decodes into a valid block,
/// which is the ordinary outcome: most occurrences of `0f 05` are data.
fn decode_candidate(
    technique: Technique,
    bytes: &[u8],
    needle: usize,
    base: u64,
) -> Option<SyscallBlock> {
    let window_start = needle.saturating_sub(MAX_BLOCK_BYTES / 4);
    let end = needle.saturating_add(MAX_BLOCK_BYTES).min(bytes.len());
    if needle >= end {
        return None;
    }

    for relative in instruction_starts(&bytes[window_start..end], needle - window_start)
        .into_iter()
        .rev()
    {
        let start = window_start + relative;
        let address = base.saturating_add(start as u64);
        if let Some(block) = decode_block(technique, &bytes[start..end], address) {
            return Some(block);
        }
    }
    None
}

/// Every instruction boundary in `window` on the decode chain that reaches
/// `needle`, in ascending order and ending at `needle` itself.
///
/// x86-64 has no instruction alignment, so "where does the instruction
/// containing this byte begin?" has no direct answer. What can be established is
/// the standard backward-disassembly result: the earliest byte in the window
/// from which a forward decode lands *exactly* on `needle` rather than stepping
/// over it. The instruction stream from there is a stream that could have been
/// executed, and every boundary along it is a possible start for the block.
///
/// `needle` is always returned, so a window whose earlier bytes are undecodable
/// still yields the one boundary that is certain. There is no failure mode and
/// no guess: a caller receives real boundaries or the needle alone, never an
/// offset that is merely 64 bytes back.
fn instruction_starts(window: &[u8], needle: usize) -> Vec<usize> {
    for first in 0..=needle {
        let mut decoder = Decoder::new(64, &window[first..], DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut boundaries = vec![first];
        let mut position = first;

        while position < needle && decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                break;
            }
            position += instruction.len();
            if position <= needle {
                boundaries.push(position);
            }
        }
        if position == needle {
            return boundaries;
        }
    }
    vec![needle]
}

/// Decode forward from a candidate and decide whether it is a valid block.
///
/// This is the heart of the detection and the reason a byte match will not do. A
/// block is believed only when all of these held:
///
/// - the system call number was written to `rax` or `eax`,
/// - the first argument was written to `r10`,
/// - the walk reached the terminator this technique expects,
/// - and, for the direct technique, a `syscall` was decoded.
///
/// Anything else — an instruction that cannot appear in such a block, a run of
/// zero bytes, a `syscall` reached before the registers were set up — means the
/// bytes were not a stub, and `None` is returned rather than a maybe.
///
/// `bytes` must begin on an instruction boundary and `address` must be the
/// virtual address of that byte; [`decode_candidate`] is what establishes both.
fn decode_block(technique: Technique, bytes: &[u8], address: u64) -> Option<SyscallBlock> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut instruction = Instruction::default();
    let mut factory = InstructionInfoFactory::new();

    let mut disassembly = String::new();
    let mut found_rax = false;
    let mut found_r10 = false;
    let mut found_syscall = false;
    let mut found_end = false;
    let mut jump_target = None;

    let mut decoded = 0usize;
    while decoder.can_decode() && decoded < MAX_BLOCK_INSTRUCTIONS {
        decoder.decode_out(&mut instruction);
        decoded += 1;

        // A run of zero bytes decodes as `add [rax], al` indefinitely: it is
        // data, not code.
        if instruction.is_invalid() || encoding_is_zero(bytes, &instruction, address) {
            break;
        }

        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        disassembly.push_str(&format!("{:#x}: {text}; ", instruction.ip()));

        let mnemonic = mnemonic_of(&text);

        if technique.invalid_ops().contains(&mnemonic.as_str()) {
            break;
        }
        if technique.termination_ops().contains(&mnemonic.as_str()) {
            found_end = true;
            if technique == Technique::Indirect {
                jump_target = indirect_target(&instruction);
            }
            break;
        }
        if mnemonic == "syscall" {
            found_syscall = true;
            // A `syscall` reached before the registers are set up is not the
            // start of a stub, just two bytes that decoded this way.
            if !(technique.wants_syscall_instruction() && found_rax && found_r10) {
                break;
            }
            continue;
        }

        // Any instruction writing the call number or the first argument counts,
        // not only `mov`: the variants use `xor`, `lea` and arithmetic to build
        // the number precisely to defeat signatures on `mov eax, imm32`.
        let info = factory.info(&instruction);
        for used in info.used_registers() {
            if !matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::ReadWrite
                    | OpAccess::CondWrite
                    | OpAccess::ReadCondWrite
            ) {
                continue;
            }
            match used.register() {
                Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => {
                    found_rax = true
                }
                Register::R10 | Register::R10D | Register::R10W | Register::R10L => {
                    found_r10 = true
                }
                _ => {}
            }
        }
    }

    if !(found_rax && found_r10 && found_end) {
        return None;
    }
    if technique.wants_syscall_instruction() && !found_syscall {
        return None;
    }

    Some(SyscallBlock {
        technique,
        address,
        // Both are filled in by the sweep, which is the only thing that knows
        // which region the bytes came out of.
        module: None,
        in_valid_handler: None,
        disassembly,
        sets_syscall_number: found_rax,
        sets_first_argument: found_r10,
        contains_syscall: found_syscall,
        jump_target,
    })
}

/// Whether every byte of this instruction's encoding is zero.
fn encoding_is_zero(buffer: &[u8], instruction: &Instruction, base: u64) -> bool {
    let Some(start) = instruction.ip().checked_sub(base).map(|v| v as usize) else {
        return false;
    };
    let end = start.saturating_add(instruction.len());
    if start >= buffer.len() || end > buffer.len() || start == end {
        return false;
    }
    buffer[start..end].iter().all(|&b| b == 0)
}

/// The absolute target of a `jmp [rip+disp32]`, when that is what this is.
fn indirect_target(instruction: &Instruction) -> Option<u64> {
    instruction
        .is_ip_rel_memory_operand()
        .then(|| instruction.ip_rel_memory_address())
}

/// The mnemonic of a formatted instruction: everything before the first space.
fn mnemonic_of(text: &str) -> String {
    text.split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Modules issuing system calls that are not allowed to.
///
/// A convenience over [`SyscallScan`] for the question an examiner actually
/// asks.
/// A block whose region could not be shown either way (`in_valid_handler ==
/// None`) is left out of this set and counted in
/// [`ProcessSyscalls::regions_named_handler_unverified`] instead: naming
/// `ntdll.dll` here on the strength of an unread `PrivateMemory` flag would be
/// an accusation the image does not support.
pub fn unexpected_handlers(scan: &SyscallScan) -> BTreeSet<String> {
    scan.blocks()
        .filter(|(_, block)| block.in_valid_handler == Some(false))
        .filter_map(|(_, block)| block.module.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vad::{MappedFile, VadKind};

    /// `mov r10, rcx; mov eax, 0x26; syscall; ret` — the canonical Hell's Gate
    /// stub, and what every variant reduces to at the point of kernel entry.
    const HELLS_GATE: &[u8] = &[
        0x4C, 0x8B, 0xD1, // mov r10, rcx
        0xB8, 0x26, 0x00, 0x00, 0x00, // mov eax, 0x26
        0x0F, 0x05, // syscall
        0xC3, // ret
    ];

    #[test]
    fn a_canonical_direct_syscall_stub_is_recognised() {
        let block = decode_block(Technique::Direct, HELLS_GATE, 0x1000)
            .expect("the canonical stub must be recognised");
        assert!(block.sets_syscall_number, "mov eax, 0x26 sets the number");
        assert!(block.sets_first_argument, "mov r10, rcx sets the argument");
        assert!(block.contains_syscall);
        assert!(
            block.disassembly.contains("syscall"),
            "{}",
            block.disassembly
        );
    }

    #[test]
    fn a_syscall_with_no_register_setup_is_not_a_stub() {
        // `syscall; ret` alone: two bytes that decode correctly and mean
        // nothing. Without the number in eax and the argument in r10 the kernel
        // would not be entered usefully, so this is not the technique — and
        // this is the case a byte-pattern search cannot reject.
        assert!(decode_block(Technique::Direct, &[0x0F, 0x05, 0xC3], 0x1000).is_none());
    }

    #[test]
    fn a_block_containing_a_call_is_not_a_stub() {
        // `call` cannot appear: the whole point is to avoid calling into the
        // hooked module.
        let bytes = &[
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00, // mov eax, 0x26
            0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
            0x0F, 0x05, // syscall
            0xC3, // ret
        ];
        assert!(decode_block(Technique::Direct, bytes, 0x1000).is_none());
    }

    #[test]
    fn a_run_of_zero_bytes_is_data_and_not_a_block() {
        // Zeroes decode as `add [rax], al` forever; a walker that did not stop
        // would run to its cap on every zero page in the image.
        assert!(decode_block(Technique::Direct, &[0u8; 64], 0x1000).is_none());
    }

    #[test]
    fn a_block_that_never_terminates_is_refused() {
        // Register setup and a syscall, but the bytes run off the end of what
        // was read. Without the terminator there is no evidence this is a
        // complete block rather than a coincidence.
        let bytes = &[
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00, // mov eax, 0x26
            0x0F, 0x05, // syscall
        ];
        assert!(decode_block(Technique::Direct, bytes, 0x1000).is_none());
    }

    #[test]
    fn the_register_write_is_detected_however_the_number_was_built() {
        // Halo's Gate and Tartarus Gate compute the call number rather than
        // moving a literal, precisely to defeat a signature on `mov eax, imm32`.
        // The instruction walk tracks the register WRITE, so how the value was
        // produced does not matter — which is the advantage of decoding over
        // pattern matching.
        let bytes = &[
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0x31, 0xC0, // xor eax, eax
            0x83, 0xC0, 0x26, // add eax, 0x26
            0x0F, 0x05, // syscall
            0xC3, // ret
        ];
        let block = decode_block(Technique::Direct, bytes, 0x1000)
            .expect("a computed system call number is still a stub");
        assert!(block.sets_syscall_number);
        assert!(block.sets_first_argument);
    }

    /// `movabs rax, 0x0102030405060708` — ten bytes, so a window that opens
    /// anywhere inside it opens mid-instruction.
    const LONG_INSTRUCTION: &[u8] = &[0x48, 0xB8, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];

    #[test]
    fn a_block_is_reported_at_its_own_first_instruction_and_not_at_the_search_window() {
        // What an examiner does with this address is disassemble from it. The
        // search backs up from the matched `0f 05` by a fixed distance to catch
        // the register setup; reporting that distance as the finding's address
        // names a byte the stub does not begin at, and here it names a byte in
        // the middle of an unrelated ten-byte instruction.
        let mut region = LONG_INSTRUCTION.to_vec();
        region.extend_from_slice(HELLS_GATE);
        let needle = LONG_INSTRUCTION.len() + 8; // the `syscall` inside the stub

        let block = decode_candidate(Technique::Direct, &region, needle, 0x7FF0_0000)
            .expect("the canonical stub must still be recognised");
        assert_eq!(
            block.address,
            0x7FF0_0000 + LONG_INSTRUCTION.len() as u64,
            "the stub begins at `mov r10, rcx`, not at the base of the search window"
        );
        assert!(
            block.disassembly.starts_with("0x7ff0000a: "),
            "the disassembly must start where `address` says it does: {}",
            block.disassembly
        );
        assert!(
            !block.disassembly.contains("rax,102030405060708h"),
            "the unrelated instruction before the stub is not part of it: {}",
            block.disassembly
        );
        assert!(block.sets_syscall_number);
        assert!(block.sets_first_argument);
        assert!(block.contains_syscall);
    }

    #[test]
    fn a_search_window_that_opens_mid_instruction_is_realigned_before_decoding() {
        // Every byte of the long instruction except the first: decoding from
        // byte zero of this window yields a stream that was never executed.
        // What is returned must be boundaries on a stream that was.
        let mut window = LONG_INSTRUCTION[1..].to_vec();
        window.extend_from_slice(HELLS_GATE);
        let needle = LONG_INSTRUCTION.len() - 1 + 8;

        let starts = instruction_starts(&window, needle);
        assert_eq!(
            starts.last().copied(),
            Some(needle),
            "the needle is itself a boundary, and is the last resort"
        );
        assert!(
            starts.contains(&(LONG_INSTRUCTION.len() - 1)),
            "the stub's first instruction must be offered as a start: {starts:?}"
        );

        // Every offset returned must genuinely be a boundary that leads to the
        // needle, or the block decoded from it is fiction.
        for &start in &starts {
            let mut decoder = Decoder::new(64, &window[start..], DecoderOptions::NONE);
            let mut instruction = Instruction::default();
            let mut position = start;
            while position < needle {
                assert!(decoder.can_decode(), "ran out of bytes before the needle");
                decoder.decode_out(&mut instruction);
                assert!(!instruction.is_invalid(), "undecodable at {position}");
                position += instruction.len();
            }
            assert_eq!(position, needle, "offset {start} is not a boundary chain");
        }
    }

    #[test]
    fn realignment_does_not_promote_a_lone_syscall_in_data_to_a_block() {
        // Backing up and realigning must not manufacture register writes: the
        // padding before these two bytes writes neither the call number nor the
        // first argument, so this is still not the technique.
        let mut region = vec![0x90; 48]; // nop
        region.extend_from_slice(&[0x0F, 0x05, 0xC3]);
        assert!(decode_candidate(Technique::Direct, &region, 48, 0x1000).is_none());
    }

    #[test]
    fn a_stub_preceded_by_the_end_of_another_function_is_still_found() {
        // `ret` terminates a direct block, so a window that opens before the
        // previous function's `ret` decodes to a block with no register setup
        // and would be discarded. Trying every boundary is what keeps the stub
        // visible rather than silently lost.
        let mut region = vec![0x48, 0x31, 0xC0, 0xC3]; // xor rax, rax; ret
        region.extend_from_slice(HELLS_GATE);
        let needle = 4 + 8;

        let block = decode_candidate(Technique::Direct, &region, needle, 0x1000)
            .expect("a stub after another function's epilogue is still a stub");
        assert_eq!(block.address, 0x1000 + 4);
    }

    #[test]
    fn only_ntdll_and_win32u_are_valid_syscall_handlers() {
        assert!(is_valid_syscall_handler("\\Windows\\System32\\ntdll.dll"));
        assert!(is_valid_syscall_handler(
            "C:\\WINDOWS\\SYSTEM32\\WIN32U.DLL"
        ));
        assert!(!is_valid_syscall_handler(
            "\\Windows\\System32\\kernel32.dll"
        ));
        // Compared on the leaf, so a file merely NAMED like the real one in an
        // attacker-controlled directory is not excused.
        assert!(!is_valid_syscall_handler("C:\\temp\\ntdll.dll.bak"));
        assert!(!is_valid_syscall_handler("C:\\ntdll.dll\\evil.dll"));
    }

    /// A memory region carrying `name`, private or shared as given.
    fn region(private_memory: Option<bool>, name: &str) -> Vad {
        Vad {
            address: 0xffff_8000_0000_1000,
            depth: 0,
            tag: "Vad ".to_string(),
            kind: VadKind::Long,
            start: 0x7ff0_0000,
            end: 0x7ff0_0fff,
            parent: None,
            commit_charge: None,
            private_memory,
            protection: None,
            protection_names: None,
            file: MappedFile::Name(name.to_string()),
            notes: Vec::new(),
        }
    }

    #[test]
    fn private_memory_wearing_ntdlls_name_is_still_searched() {
        // The skip this guards exists because a real `ntdll.dll` is *supposed*
        // to be full of syscall stubs. But the name comes from the control area
        // the VAD points at, and a range that carries it while being private
        // memory is not that file — it is memory somebody arranged to carry the
        // name, which is precisely where a hand-mapped stub table hides. Taking
        // the name at face value means the one process on the machine running
        // Hell's Gate is the one process this stage never looks inside.
        let genuine = region(Some(false), "\\Windows\\System32\\ntdll.dll");
        assert!(
            trusts_module_name(&genuine),
            "a shared image mapping is the real module"
        );

        let hand_mapped = region(Some(true), "\\Windows\\System32\\ntdll.dll");
        assert!(
            !trusts_module_name(&hand_mapped),
            "private memory is not an image mapping, whatever it is named"
        );

        // Unread is not trusted: the skip is only sound when the region is
        // known legitimate, and a field that was never read is not knowledge.
        let unknown = region(None, "\\Windows\\System32\\win32u.dll");
        assert!(!trusts_module_name(&unknown));
    }

    #[test]
    fn a_region_whose_name_could_not_be_corroborated_is_searched_without_being_accused() {
        // Searching it is the safe direction. Recording the result as
        // "in_valid_handler: false" is not: on an image whose
        // `_MMVAD.PrivateMemory` cannot be read, that turns every one of the
        // several hundred legitimate stubs in every process's real `ntdll` into
        // a row asserting `ntdll.dll` issues system calls it is not allowed to.
        // An examiner shown that on every case learns to ignore the stage.
        let name = "\\Windows\\System32\\ntdll.dll";

        assert_eq!(
            valid_handler_status(&region(Some(false), name), Some(name)),
            Some(true),
            "a shared image mapping of ntdll is the real handler"
        );
        assert_eq!(
            valid_handler_status(&region(Some(true), name), Some(name)),
            Some(false),
            "private memory wearing the name is positively not the module"
        );
        assert_eq!(
            valid_handler_status(&region(None, name), Some(name)),
            None,
            "an unread flag establishes neither answer"
        );
        // A region with no legitimate handler's name needs no corroboration at
        // all: it is known not to be one, whatever its backing.
        assert_eq!(
            valid_handler_status(&region(None, "\\Users\\x\\evil.dll"), Some("evil.dll")),
            Some(false)
        );
        assert_eq!(valid_handler_status(&region(None, ""), None), Some(false));

        // And the uncorroborated block stays out of the accusation set while
        // the hand-mapped one does not.
        let scan = SyscallScan {
            processes: vec![ProcessSyscalls {
                process: 0x1000,
                pid: Some(4),
                name: Some("System".into()),
                blocks: vec![
                    SyscallBlock {
                        technique: Technique::Direct,
                        address: 0x7ff0_0000,
                        module: Some(name.to_string()),
                        in_valid_handler: None,
                        disassembly: String::new(),
                        sets_syscall_number: true,
                        sets_first_argument: true,
                        contains_syscall: true,
                        jump_target: None,
                    },
                    SyscallBlock {
                        technique: Technique::Direct,
                        address: 0x7ff0_1000,
                        module: Some("\\Users\\x\\evil.dll".to_string()),
                        in_valid_handler: Some(false),
                        disassembly: String::new(),
                        sets_syscall_number: true,
                        sets_first_argument: true,
                        contains_syscall: true,
                        jump_target: None,
                    },
                ],
                regions_too_large: 0,
                regions_unreadable: 0,
                regions_in_valid_handler: 0,
                regions_named_handler_unverified: 1,
                truncated: false,
                regions_complete: true,
            }],
            skipped: Vec::new(),
            inventory: whole_inventory(),
        };
        let unexpected = unexpected_handlers(&scan);
        assert!(
            !unexpected.contains(name),
            "ntdll must not be accused on an unread flag: {unexpected:?}"
        );
        assert!(
            unexpected.contains("\\Users\\x\\evil.dll"),
            "{unexpected:?}"
        );
        // But the fact that something could not be corroborated is stated.
        assert_eq!(
            scan.processes[0].to_json()["regions_named_handler_unverified"],
            1
        );
    }

    #[test]
    fn an_incomplete_sweep_never_reads_as_a_clean_process() {
        // The distinction this stage turns on: "no blocks found" and "we could
        // not look everywhere" are different answers, and a report that
        // conflated them would say a machine was clean on the strength of a
        // sweep that skipped half its memory.
        let result = ProcessSyscalls {
            process: 0x1000,
            pid: Some(4),
            name: Some("System".into()),
            blocks: Vec::new(),
            regions_too_large: 0,
            regions_unreadable: 0,
            regions_in_valid_handler: 0,
            regions_named_handler_unverified: 0,
            truncated: false,
            regions_complete: true,
        };
        assert!(result.is_complete());
        assert_eq!(result.to_json()["content_complete"], true);

        for spoil in [
            |r: &mut ProcessSyscalls| r.regions_unreadable = 1,
            |r: &mut ProcessSyscalls| r.regions_too_large = 1,
            |r: &mut ProcessSyscalls| r.truncated = true,
            |r: &mut ProcessSyscalls| r.regions_complete = false,
        ] {
            let mut probe = result.clone();
            spoil(&mut probe);
            assert!(!probe.is_complete());
            assert_eq!(probe.to_json()["content_complete"], false);
        }
    }

    /// An inventory that says the process list was walked end to end.
    fn whole_inventory() -> ProcessInventory {
        ProcessInventory {
            head: 0xffff_f800_0000_0000,
            listed: 2,
            complete: true,
            incomplete: Vec::new(),
        }
    }

    /// An inventory that says the list stopped early.
    fn short_inventory() -> ProcessInventory {
        ProcessInventory {
            head: 0xffff_f800_0000_0000,
            listed: 2,
            complete: false,
            incomplete: vec![seance_memory::Incomplete::new(
                seance_core::io::IncompleteReason::CapReached,
                "the process list stopped at its cap".to_string(),
            )],
        }
    }

    #[test]
    fn a_scan_that_skipped_a_process_is_not_complete() {
        let scan = SyscallScan {
            processes: Vec::new(),
            skipped: vec![(0x1000, "no readable address space".into())],
            inventory: whole_inventory(),
        };
        assert!(!scan.is_complete());
        assert_eq!(scan.to_json()["content_complete"], false);
    }

    #[test]
    fn a_flawless_sweep_over_a_short_process_list_is_not_reported_as_complete() {
        // The whole point of the inventory join: this sweep did everything it
        // was asked and skipped nothing. Without the inventory it would report
        // "no evasion found" as a total over a list that stopped early.
        let clean = SyscallScan {
            processes: Vec::new(),
            skipped: Vec::new(),
            inventory: whole_inventory(),
        };
        assert!(clean.is_complete());
        assert_eq!(clean.to_json()["content_complete"], true);

        let over_a_floor = SyscallScan {
            processes: Vec::new(),
            skipped: Vec::new(),
            inventory: short_inventory(),
        };
        assert!(!over_a_floor.is_complete());
        let body = over_a_floor.to_json();
        assert_eq!(body["content_complete"], false);
        assert_eq!(body["content_incomplete"], true);
        assert_eq!(body["process_inventory_incomplete"], true);
        assert_eq!(body["process_inventory"]["count_is_floor"], true);
        assert_eq!(body["process_inventory"]["listed"], 2);
        assert!(body["process_inventory"]["meaning"]
            .as_str()
            .unwrap()
            .contains("floor"));
    }

    /// A process record with every field at its complete value, for tests that
    /// spoil one of them.
    fn examined_process(process: u64) -> ProcessSyscalls {
        ProcessSyscalls {
            process,
            pid: Some(4),
            name: Some("evil.exe".into()),
            blocks: Vec::new(),
            regions_too_large: 0,
            regions_unreadable: 0,
            regions_in_valid_handler: 0,
            regions_named_handler_unverified: 0,
            truncated: false,
            regions_complete: true,
        }
    }

    /// What `module.rs::incomplete_reason` does with a stage's JSON, reproduced
    /// so this test breaks if the two ever stop agreeing on the key.
    fn reason_the_record_builder_would_extract(value: &serde_json::Value) -> Option<String> {
        let details: Vec<&str> = value
            .get("incomplete")?
            .as_array()?
            .iter()
            .filter_map(|entry| entry.get("detail").and_then(serde_json::Value::as_str))
            .collect();
        (!details.is_empty()).then(|| details.join("; "))
    }

    #[test]
    fn a_sweep_that_fell_short_carries_the_reason_the_stage_record_reads() {
        // The failure this guards: `content_complete: false` reaching the
        // artifact with `content_incomplete_reason` reading "recorded no
        // reason", because the stage knew exactly why and emitted it nowhere
        // the record builder looks. Every shortfall below is one the sweep
        // measured.
        let mut capped = examined_process(0x2000);
        capped.truncated = true;
        let mut unreadable = examined_process(0x3000);
        unreadable.regions_unreadable = 2;
        let mut oversized = examined_process(0x4000);
        oversized.regions_too_large = 1;
        let mut partial_tree = examined_process(0x5000);
        partial_tree.regions_complete = false;

        let scan = SyscallScan {
            processes: vec![capped, unreadable, oversized, partial_tree],
            skipped: vec![(0x1000, "no readable address space".into())],
            inventory: short_inventory(),
        };
        assert!(!scan.is_complete());

        let body = scan.to_json();
        let reason = reason_the_record_builder_would_extract(&body)
            .expect("a sweep that fell short must publish why where the record builder reads it");
        for expected in [
            "the process list stopped at its cap", // the inventory's own reason
            "0x1000",                              // the process that was skipped entirely
            "candidate cap",
            "could not be read",
            "exceeded the size cap",
            "not enumerated in full",
        ] {
            assert!(
                reason.contains(expected),
                "the reason must name {expected:?}: {reason}"
            );
        }
    }

    #[test]
    fn a_complete_sweep_publishes_no_reasons_at_all() {
        // The other half of the contract: "nothing was incomplete" and "we did
        // not say what was incomplete" must not render the same, so an empty
        // array here is only correct because `is_complete` agrees.
        let scan = SyscallScan {
            processes: vec![examined_process(0x2000)],
            skipped: Vec::new(),
            inventory: whole_inventory(),
        };
        assert!(scan.is_complete());
        assert!(scan.incomplete().is_empty());
        let body = scan.to_json();
        assert_eq!(body["incomplete"], serde_json::json!([]));
        assert_eq!(reason_the_record_builder_would_extract(&body), None);
    }

    #[test]
    fn the_reasons_and_the_completeness_verdict_never_disagree() {
        // Two ways of answering the same question, and an examiner sees both.
        // A sweep flagged incomplete with no reasons, or complete with reasons,
        // is a record that argues with itself.
        for scan in [
            SyscallScan {
                processes: vec![examined_process(0x2000)],
                skipped: Vec::new(),
                inventory: whole_inventory(),
            },
            SyscallScan {
                processes: vec![examined_process(0x2000)],
                skipped: Vec::new(),
                inventory: short_inventory(),
            },
            SyscallScan {
                processes: vec![examined_process(0x2000)],
                skipped: vec![(0x1000, "no readable address space".into())],
                inventory: whole_inventory(),
            },
            SyscallScan {
                processes: vec![ProcessSyscalls {
                    regions_unreadable: 1,
                    ..examined_process(0x2000)
                }],
                skipped: Vec::new(),
                inventory: whole_inventory(),
            },
            // An inventory that fell short without naming a reason: the sweep
            // must still say something rather than flag itself for nothing.
            SyscallScan {
                processes: vec![examined_process(0x2000)],
                skipped: Vec::new(),
                inventory: ProcessInventory {
                    complete: false,
                    incomplete: Vec::new(),
                    ..whole_inventory()
                },
            },
        ] {
            assert_eq!(
                scan.is_complete(),
                scan.incomplete().is_empty(),
                "completeness and reasons disagree for {scan:?}"
            );
        }
    }

    #[test]
    fn the_needles_are_the_instructions_they_claim_to_be() {
        assert_eq!(Technique::Direct.needle(), &[0x0F, 0x05]); // syscall
        assert_eq!(Technique::Indirect.needle(), &[0xFF, 0x25]); // jmp [rip+..]
        assert!(Technique::Direct.wants_syscall_instruction());
        assert!(!Technique::Indirect.wants_syscall_instruction());
    }

    #[test]
    fn an_indirect_block_is_rejected_when_it_returns_before_jumping() {
        // For the indirect technique a `ret` means the block is not one: the
        // jump into ntdll is what makes it the technique.
        let bytes = &[
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00, // mov eax, 0x26
            0xC3, // ret
        ];
        assert!(decode_block(Technique::Indirect, bytes, 0x1000).is_none());
    }
}
