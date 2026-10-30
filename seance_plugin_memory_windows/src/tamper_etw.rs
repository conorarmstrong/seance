//! A patched ETW write path, without a table of expected bytes
//! (`ROADMAP` §5.3).
//!
//! # What an examiner learns
//!
//! Whether anything in this image has disabled its own event logging. The
//! common technique is one instruction: overwrite `ntdll!EtwEventWrite`'s first
//! bytes with a `ret`, and the process stops producing ETW events while every
//! API call still succeeds. It is per-process, it leaves the file on disk
//! untouched, and nothing in an event log records it — the absence of events
//! *is* the effect.
//!
//! # Two routes, and neither needs a per-build table of expected prologues
//!
//! A check that compared the first bytes against a stored baseline would need
//! one baseline per build of `ntdll.dll`, and would rot on the next Patch
//! Tuesday. Both routes here are build-independent:
//!
//! **(a) Classification.** Decode the first instructions and report a function
//! that returns immediately (`ret`, or `xor eax,eax; ret`), traps (`int3`), or
//! whose first control transfer leaves the module. Each is reported with the
//! decoded instructions as the evidence.
//!
//! **(b) Cross-process modal comparison.** Hash the first [`PROLOGUE_BYTES`] of
//! each export across every process, take the modal value, and report a
//! minority copy with the count that agreed. This is the stronger signal and
//! the reason to build both: a patch applied to one process shows up as
//! 1-against-79 with no reference bytes needed at all, and a patch applied
//! machine-wide — where the mode is itself patched — is what route (a) catches.
//!
//! Every row says **which route fired**.
//!
//! # A region merely named `ntdll.dll` is not `ntdll.dll`
//!
//! This is `syscalls.rs`'s discipline, and here it decides what may become the
//! baseline rather than what is skipped. A hand-mapped private copy carrying
//! the name must never contribute to the mode — an attacker who could do that
//! would be choosing the baseline every other process is compared against. So
//! the mapping is corroborated the way `syscalls.rs` corroborates it (the VAD
//! holding the base is not private memory), and a copy that is not corroborated
//! is **classified but excluded from the mode**.
//!
//! # A process whose `ntdll` pages are not resident is unassessed
//!
//! Never "unpatched". On a smeared capture that will be the common outcome, and
//! an all-clear derived from unread pages is the false absence this crate is
//! shaped against. Those processes are counted, with the reason, and the group's
//! record states how many of them there were beside how many were assessed.

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_memory::MemoryLayer;
use serde_json::{json, Value};

use crate::modules::{ModuleSymbols, ModuleWalkConfig, ProcessSpace};
use crate::process::{ProcessList, ProcessRecord};
use crate::profile::WindowsProfile;
use crate::tamper::TamperError;

/// The four exports the ETW write path goes through.
///
/// `EtwEventWrite` is the one every published technique patches;
/// the other three are the paths a caller that avoided it would take.
pub const ETW_EXPORTS: &[&str] = &[
    "EtwEventWrite",
    "EtwEventWriteFull",
    "EtwEventWriteEx",
    "EtwEventWriteTransfer",
];

/// Bytes of each export's prologue read and compared.
///
/// Sixteen is enough to hold the whole of a patched stub (`ret` is one byte,
/// `xor eax,eax; ret` is three, a `jmp rel32` five) and enough of a real
/// prologue to differ between builds without being so long that a page
/// boundary inside it becomes the common case.
pub const PROLOGUE_BYTES: usize = 16;

/// The module whose exports are read.
pub const NTDLL: &str = "ntdll.dll";

/// How far a decode will run before it stops.
const MAX_DECODED_INSTRUCTIONS: usize = 8;

/// The longest an x86-64 instruction can be.
///
/// Load-bearing for a reason found by running this against a real capture: a
/// fixed-length window almost always ends **mid-instruction**, and an invalid
/// decode there is the window running out rather than a byte sequence that is
/// not code. The real `EtwEventWrite` prologue on Windows 11 26200 ends
/// `... 48 8d 6c 24 80 48 81` — the `48 81` is the start of a `sub rsp,imm32`
/// cut off by the sixteenth byte. Calling that undecodable classified the
/// genuine prologue of **369 of 491** exports on a clean capture as
/// unreadable, which is a wrong answer that happens to be harmless and would
/// not have stayed harmless.
const MAX_INSTRUCTION_BYTES: usize = 15;

/// What the first instructions of an export turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// The function returns before doing anything. This is the published
    /// technique.
    ReturnsImmediately { detail: String },
    /// The function traps — a breakpoint left in place.
    Traps,
    /// The first control transfer leaves the module's own range.
    LeavesModule { target: u64 },
    /// Nothing about the prologue is remarkable. **Not a statement that the
    /// function is unpatched**: a patch further in, or one that preserves the
    /// prologue, is not visible here.
    Ordinary,
    /// The bytes would not decode, which is itself worth reporting.
    Undecodable { detail: String },
}

impl Classification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReturnsImmediately { .. } => "returns_immediately",
            Self::Traps => "traps",
            Self::LeavesModule { .. } => "first_control_transfer_leaves_the_module",
            Self::Ordinary => "ordinary",
            Self::Undecodable { .. } => "undecodable",
        }
    }

    /// Whether this classification is a signal on its own.
    pub fn is_signal(&self) -> bool {
        matches!(
            self,
            Self::ReturnsImmediately { .. } | Self::Traps | Self::LeavesModule { .. }
        )
    }

    fn detail(&self) -> Option<String> {
        match self {
            Self::ReturnsImmediately { detail } | Self::Undecodable { detail } => {
                Some(detail.clone())
            }
            Self::LeavesModule { target } => {
                Some(format!("the first control transfer goes to {target:#018x}"))
            }
            Self::Traps | Self::Ordinary => None,
        }
    }
}

/// Classify a prologue by decoding it.
///
/// `bitness` and `ip` come from the image, not from the host: decoding 64-bit
/// bytes as 32-bit produces different instructions that are still valid, which
/// is a wrong answer that reads correctly.
pub fn classify(bytes: &[u8], ip: u64, bitness: u32, module: (u64, u64)) -> Classification {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic};

    if bytes.iter().all(|b| *b == 0) {
        return Classification::Undecodable {
            detail: "the export's first bytes are all zero, which no prologue is: the page is \
                     most likely not resident rather than the function being patched"
                .to_string(),
        };
    }
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let mut decoded: Vec<String> = Vec::new();
    for _ in 0..MAX_DECODED_INSTRUCTIONS {
        if !decoder.can_decode() {
            break;
        }
        let remaining = bytes.len().saturating_sub(decoder.position());
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            // Fewer bytes left than an instruction can be: the window ended
            // mid-instruction, which every fixed-length window does, and that
            // is not a byte sequence that fails to decode. See
            // `MAX_INSTRUCTION_BYTES`.
            if remaining < MAX_INSTRUCTION_BYTES {
                break;
            }
            return Classification::Undecodable {
                detail: format!(
                    "the byte sequence at {:#018x} does not decode as a {bitness}-bit \
                     instruction",
                    instruction.ip()
                ),
            };
        }
        decoded.push(format!("{instruction}"));

        match instruction.mnemonic() {
            Mnemonic::Ret | Mnemonic::Retf => {
                return Classification::ReturnsImmediately {
                    detail: format!(
                        "the function returns after {} instruction(s): {}",
                        decoded.len(),
                        decoded.join("; ")
                    ),
                };
            }
            Mnemonic::Int3 => return Classification::Traps,
            // `xor eax,eax` needs no arm of its own: it is the other half of
            // the published patch (`xor eax,eax; ret`, setting the
            // STATUS_SUCCESS the caller checks), and the `Ret` arm above
            // reports the whole sequence it decoded -- so the evidence names
            // it without a second rule that could disagree with the first.
            _ => {}
        }

        match instruction.flow_control() {
            FlowControl::UnconditionalBranch | FlowControl::Call => {
                let target = instruction.near_branch_target();
                if target != 0 && (target < module.0 || target >= module.1) {
                    return Classification::LeavesModule { target };
                }
                // A branch inside the module is how every real prologue that
                // tail-calls looks; it says nothing.
                return Classification::Ordinary;
            }
            FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                // The target is a value this build does not follow, so nothing
                // is claimed about where it goes.
                return Classification::Ordinary;
            }
            _ => {}
        }
    }
    Classification::Ordinary
}

/// One export of one process's `ntdll`, as read.
#[derive(Debug, Clone)]
pub struct EtwExport {
    pub process: u64,
    pub pid: Option<u64>,
    pub process_name: Option<String>,
    /// Where this process's `ntdll` is mapped.
    pub module_base: u64,
    pub export: &'static str,
    /// Virtual address of the export in this process.
    pub address: u64,
    /// The prologue, as read.
    pub bytes: Vec<u8>,
    pub classification: Classification,
    /// Whether this copy's mapping was corroborated as an image mapping. `None`
    /// means it could not be established — which is not "no".
    pub image_mapped: Option<bool>,
    /// Whether the prologue equals the modal prologue for this export.
    /// `None` when there was no mode to compare against.
    pub agrees_with_the_mode: Option<bool>,
    /// How many processes' copies agreed with the mode.
    pub mode_agreed: usize,
    /// How many copies voted in the mode: every copy not positively private
    /// memory, including those whose mapping could not be established.
    pub mode_population: usize,
    /// Whether every copy that set the mode classifies as a signal, so the mode is itself the patch. A copy that differs
    /// from such a mode is the clean one, and the modal route does not make it a signal (`MEM-020`).
    pub mode_is_patched: bool,
}

impl EtwExport {
    /// Which route, if either, makes this row a signal.
    pub fn route(&self) -> Option<&'static str> {
        let minority = self.agrees_with_the_mode == Some(false) && !self.mode_is_patched;
        match (self.classification.is_signal(), minority) {
            (true, true) => Some("both"),
            (true, false) => Some("classification"),
            (false, true) => Some("modal_comparison"),
            (false, false) => None,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "MemoryEtwExport",
            "name": format!(
                "{} in {} ({})",
                self.export,
                self.process_name.clone().unwrap_or_else(|| "?".into()),
                self.classification.as_str()
            ),
            "process_address": format!("{:#018x}", self.process),
            "pid": self.pid,
            "process_name": self.process_name,
            "module_base": format!("{:#018x}", self.module_base),
            "export": self.export,
            "address": format!("{:#018x}", self.address),
            "prologue": self
                .bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            "classification": self.classification.as_str(),
            "classification_detail": self.classification.detail(),
            "image_mapped": self.image_mapped,
            "image_mapped_note": (self.image_mapped != Some(true)).then_some(
                "This copy's mapping was not corroborated as an image mapping, so it is \
                 classified but EXCLUDED from the modal baseline. A hand-mapped private copy \
                 carrying the name must never become the baseline every other process is \
                 compared against -- an attacker who could place one would be choosing the \
                 baseline."
            ),
            "agrees_with_the_mode": self.agrees_with_the_mode,
            "mode_agreed": self.mode_agreed,
            "mode_population": self.mode_population,
            "mode_is_patched": self.mode_is_patched,
            "route": self.route(),
            "is_signal": self.route().is_some(),
            "basis": ROUTE_BASIS,
        })
    }
}

/// What both routes rest on, on every row.
pub const ROUTE_BASIS: &str =
    "Two independent routes, neither needing a stored baseline per build of ntdll. \
     CLASSIFICATION decodes the prologue and reports a function that returns immediately, \
     traps, or whose first control transfer leaves the module. MODAL COMPARISON compares this \
     copy's first 16 bytes against the modal value across every copy not shown to be private memory: \
     a patch in one process is 1-against-N with no reference bytes at all, and a patch applied \
     machine-wide -- where the mode is itself patched -- is what the classification catches. \
     `ordinary` is NOT a statement that the function is unpatched: a patch further in, or one \
     that preserves the prologue, is not visible to either route.";

/// A process this group could not assess, and why.
#[derive(Debug, Clone)]
pub struct Unassessed {
    pub process: u64,
    pub pid: Option<u64>,
    pub process_name: Option<String>,
    pub reason: String,
}

impl Unassessed {
    pub fn to_json(&self) -> Value {
        json!({
            "process_address": format!("{:#018x}", self.process),
            "pid": self.pid,
            "process_name": self.process_name,
            "reason": self.reason,
        })
    }
}

/// What one ETW examination produced.
#[derive(Debug, Clone)]
pub struct EtwOutcome {
    pub exports: Vec<EtwExport>,
    /// Processes where at least one export was read.
    pub processes_assessed: u64,
    /// Processes where none could be, each with its reason. **Counted, never
    /// reported as clean.**
    pub unassessed: Vec<Unassessed>,
    /// Per export: the modal prologue, how many agreed, and the population it
    /// was taken from.
    pub modes: BTreeMap<String, (String, usize, usize)>,
    pub notes: Vec<String>,
    pub capped: Option<String>,
}

impl EtwOutcome {
    /// Rows either route makes a signal.
    pub fn signals(&self) -> usize {
        self.exports.iter().filter(|e| e.route().is_some()).count()
    }

    pub fn describe(&self) -> String {
        format!(
            "{} export prologue(s) were read across {} process(es); {} of them are a signal on \
             one route or both. {} process(es) could not be assessed at all and are listed with \
             their reasons -- their silence is not an all-clear.",
            self.exports.len(),
            self.processes_assessed,
            self.signals(),
            self.unassessed.len()
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "exports": self.exports.iter().map(EtwExport::to_json).collect::<Vec<_>>(),
            "exports_read": self.exports.len(),
            "processes_assessed": self.processes_assessed,
            "signals": self.signals(),
            "unassessed": self.unassessed.iter().map(Unassessed::to_json).collect::<Vec<_>>(),
            "unassessed_total": self.unassessed.len(),
            "unassessed_note":
                "A process whose ntdll pages are not resident, or whose export table could not \
                 be read, is UNASSESSED and never 'unpatched'. On a smeared capture that is the \
                 common outcome, and an all-clear derived from unread pages is a false absence.",
            "modes": self
                .modes
                .iter()
                .map(|(export, (prologue, agreed, population))| {
                    json!({
                        "export": export,
                        "modal_prologue": prologue,
                        "agreed": agreed,
                        "population": population,
                    })
                })
                .collect::<Vec<_>>(),
            "statement": self.describe(),
            "basis": ROUTE_BASIS,
            "notes": self.notes,
            "content_incomplete": self.capped.is_some() || !self.unassessed.is_empty(),
            "cap_detail": self.capped,
        })
    }
}

/// One process's copy of a module, located and corroborated.
pub(crate) struct ModuleCopy {
    pub(crate) base: u64,
    pub(crate) end: u64,
    /// `Some(true)` when the mapping was corroborated as an image mapping,
    /// `Some(false)` when it was positively private memory, `None` when
    /// nothing could establish it — which is not "no".
    pub(crate) image_mapped: Option<bool>,
}

/// The exclusive end of a module whose last byte is `last`, or why it has none.
///
/// `last` comes from the loader entry's `DllBase` + `SizeOfImage`, both read
/// from the image; a module whose last byte is the top of the address space
/// has no exclusive end in 64 bits, and no user-mode module sits there, so
/// the entry is refused rather than wrapped to zero (`MEM-052`'s audit).
/// An entry with no readable size keeps its old meaning: an empty range at
/// its base.
pub fn exclusive_end(base: u64, last: Option<u64>) -> Result<u64, String> {
    match last {
        None => Ok(base),
        Some(last) => last.checked_add(1).ok_or_else(|| {
            format!(
                "this loader entry's image at {base:#x} runs to the top of the address space, \
                 which no module a process maps can do, so it is not read as that module"
            )
        }),
    }
}

/// Find one named module in this process's own loader list.
///
/// Matched on the **final path component**, never as a substring: a file called
/// `ntdll.dll.bak` in an attacker-controlled directory is not `ntdll.dll`, and
/// `syscalls.rs` carries the same rule for the same reason.
///
/// Shared with the skeleton-key group, which asks the same question of
/// `cryptdll.dll`: one function so the two groups cannot disagree about what
/// counts as finding a module.
pub(crate) fn find_module(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    vad: Option<&crate::vad::VadSymbols>,
    process: u64,
    space: &ProcessSpace,
    leaf_wanted: &str,
) -> Result<ModuleCopy, String> {
    let list = crate::modules::list_dlls(
        profile,
        symbols,
        process,
        space,
        &ModuleWalkConfig::default(),
    )
    .map_err(|err| format!("this process's loader list could not be walked: {err}"))?;

    for module in &list.modules {
        let name = module
            .base_name
            .name()
            .or_else(|| module.full_path.name())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let leaf = name.rsplit(['\\', '/']).next().unwrap_or(&name);
        if leaf != leaf_wanted {
            continue;
        }
        let Some(base) = module.base else {
            return Err(format!(
                "this process's loader entry for {leaf_wanted} has no readable DllBase, so its \
                 exports cannot be located"
            ));
        };
        let end = exclusive_end(base, module.end())?;
        // Corroborate the mapping, the way `syscalls.rs` does: the stubs of a
        // legitimate `ntdll` live in a SHARED IMAGE MAPPING of that file, so a
        // region carrying the name while being private memory is not that
        // file. `None` stays `None`: a flag that could not be read is not
        // knowledge, and collapsing it either way is the mistake that type of
        // answer exists to prevent.
        let image_mapped = vad.and_then(|vad| {
            let tree =
                crate::vad::list_vads(profile, vad, process, &crate::vad::VadWalkConfig::default())
                    .ok()?;
            let node = tree.containing(base)?;
            node.private_memory.map(|private| !private)
        });
        return Ok(ModuleCopy {
            base,
            end,
            image_mapped,
        });
    }
    Err(format!("this process's loader list holds no {leaf_wanted}"))
}

/// Read the four export prologues from one process.
fn read_process(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    vad: Option<&crate::vad::VadSymbols>,
    entry: &ProcessRecord,
    bitness: u32,
) -> Result<(Vec<EtwExport>, Option<bool>), String> {
    let space = ProcessSpace::build(
        profile,
        symbols,
        entry.address,
        &ModuleWalkConfig::default(),
    )
    .map_err(|err| format!("this process has no readable address space: {err}"))?;
    let copy = find_module(profile, symbols, vad, entry.address, &space, NTDLL)
        .map_err(|why| format!("{why}, so there is no ETW write path in it to read"))?;
    let layer: Arc<dyn MemoryLayer> = Arc::clone(space.layer());

    let headers = crate::dump::read_pe_headers(layer.as_ref(), copy.base)
        .map_err(|err| format!("ntdll's headers at {:#x} would not read: {err}", copy.base))?;
    let table = crate::dump::read_exports(
        layer.as_ref(),
        &headers,
        &crate::dump::ImportConfig::default(),
    )
    .map_err(|err| format!("ntdll's export table would not read: {err}"))?;

    let mut rows = Vec::new();
    for export in ETW_EXPORTS {
        let Some(target) = table.by_name(export) else {
            continue;
        };
        if target.forwarder.is_some() {
            // A forwarded export lives in another module entirely, so there is
            // nothing here to classify.
            continue;
        }
        let address = copy.base.saturating_add(target.rva as u64);
        let mut bytes = vec![0u8; PROLOGUE_BYTES];
        if layer.read_at(address, &mut bytes).is_err() {
            continue;
        }
        let classification = classify(&bytes, address, bitness, (copy.base, copy.end));
        rows.push(EtwExport {
            process: entry.address,
            pid: entry.pid.known().copied(),
            process_name: entry.image_file_name.known().cloned(),
            module_base: copy.base,
            export,
            address,
            bytes,
            classification,
            image_mapped: copy.image_mapped,
            agrees_with_the_mode: None,
            mode_agreed: 0,
            mode_population: 0,
            mode_is_patched: false,
        });
    }
    if rows.is_empty() {
        return Err(format!(
            "none of the {} ETW exports could be read from the ntdll at {:#x}: either the \
             export table does not name them or their pages are not resident",
            ETW_EXPORTS.len(),
            copy.base
        ));
    }
    Ok((rows, copy.image_mapped))
}

/// Examine the ETW write path across every process.
///
/// # Errors
///
/// [`TamperError::Unsupported`] only when this build's loader lists cannot be
/// described at all — without them no process's `ntdll` can be located, so
/// there is nothing to read and an empty result would read as a machine whose
/// logging was intact.
pub fn examine_etw(
    profile: &WindowsProfile,
    processes: &ProcessList,
    max_processes: usize,
) -> Result<EtwOutcome, TamperError> {
    let mut out_notes: Vec<String> = Vec::new();
    let symbols = ModuleSymbols::from_profile(profile).map_err(|err| {
        TamperError::unsupported(format!(
            "this build's loader entries cannot be described: {err}. Without them no process's \
             ntdll can be located, so no ETW export can be read and nothing is said about \
             whether this machine's event logging was disabled."
        ))
    })?;
    let bitness = if profile.architecture == seance_memory::Architecture::X86 {
        32
    } else {
        64
    };
    // Optional by design: without it every copy is `image_mapped: None`, which
    // still votes in the mode and still says on the record that nothing
    // corroborated it. Refusing to run without the VAD walk would lose the
    // classification route on a build whose VAD tree cannot be described.
    let vad = crate::vad::VadSymbols::from_profile(profile).ok();
    if vad.is_none() {
        out_notes.push(
            "this build's VAD tree cannot be described, so no copy of ntdll could be \
             corroborated as an image mapping. Every row says so, and the modal baseline is \
             taken from copies none of which was corroborated -- which is weaker than one taken \
             from corroborated copies and is stated rather than implied."
                .to_string(),
        );
    }

    let mut out = EtwOutcome {
        exports: Vec::new(),
        processes_assessed: 0,
        unassessed: Vec::new(),
        modes: BTreeMap::new(),
        notes: out_notes,
        capped: None,
    };

    for entry in processes.processes.iter().take(max_processes) {
        match read_process(profile, &symbols, vad.as_ref(), entry, bitness) {
            Ok((rows, _)) => {
                out.processes_assessed += 1;
                out.exports.extend(rows);
            }
            Err(reason) => out.unassessed.push(Unassessed {
                process: entry.address,
                pid: entry.pid.known().copied(),
                process_name: entry.image_file_name.known().cloned(),
                reason,
            }),
        }
    }
    if processes.processes.len() > max_processes {
        out.capped = Some(format!(
            "the process cap of {max_processes} stopped this group at {max_processes} of {} \
             processes; the rest were not assessed and are not reported as clean.",
            processes.processes.len()
        ));
    }

    apply_modes(&mut out);
    Ok(out)
}

/// Take the modal prologue per export and mark every row against it.
///
/// **Copies positively shown to be private memory never vote.** A copy whose
/// mapping is `Some(false)` is compared against the mode but never contributes
/// to it: an attacker able to place a private copy carrying the name would
/// otherwise be choosing the baseline. A copy whose mapping could not be
/// established (`None`) *does* vote -- "not established" is not "no" -- and
/// the notes count those separately. Where no copy votes there is no mode,
/// and every row says `agrees_with_the_mode: null` rather than being compared
/// against a baseline that does not exist.
///
/// The mode is a plurality. On a tie the pick is the byte-wise greatest
/// prologue, which is arbitrary, so a tie is named on the record in words.
pub(crate) fn apply_modes(out: &mut EtwOutcome) {
    for export in ETW_EXPORTS {
        let mut counts: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
        let mut population = 0usize;
        let mut not_established = 0usize;
        for row in out.exports.iter().filter(|r| r.export == *export) {
            // `None` — not established — is allowed to vote; `Some(false)` —
            // positively private memory — is not.
            if row.image_mapped == Some(false) {
                continue;
            }
            population += 1;
            if row.image_mapped.is_none() {
                not_established += 1;
            }
            *counts.entry(row.bytes.clone()).or_default() += 1;
        }
        let tied_at_the_top = counts
            .values()
            .max()
            .map_or(0, |top| counts.values().filter(|c| *c == top).count());
        let Some((modal, agreed)) = counts.into_iter().max_by_key(|(_, count)| *count) else {
            continue;
        };
        out.modes.insert(
            (*export).to_string(),
            (
                modal
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                agreed,
                population,
            ),
        );
        for row in out.exports.iter_mut().filter(|r| r.export == *export) {
            row.agrees_with_the_mode = Some(row.bytes == modal);
            row.mode_agreed = agreed;
            row.mode_population = population;
        }
        // A mode that is itself the patch: every copy that set it classifies as a signal. The copies that differ are then the
        // clean ones, and the modal route must not call them tampered.
        let mode_is_patched = {
            let mut setting = out
                .exports
                .iter()
                .filter(|r| r.export == *export && r.agrees_with_the_mode == Some(true))
                .peekable();
            setting.peek().is_some() && setting.all(|r| r.classification.is_signal())
        };
        for row in out.exports.iter_mut().filter(|r| r.export == *export) {
            row.mode_is_patched = mode_is_patched;
        }
        let voters = if not_established == 0 {
            format!("{population} voting copies (all corroborated as image mappings)")
        } else {
            format!(
                "{population} voting copies ({not_established} not established as image \
                 mappings, which vote but are not corroborated)"
            )
        };
        if tied_at_the_top > 1 {
            out.notes.push(format!(
                "{export}: the vote for the mode is a tie -- {tied_at_the_top} different \
                 prologues each carried by {agreed} of the {voters}. The mode shown is the \
                 byte-wise greatest of them, which is arbitrary: disagreeing with it is not \
                 evidence of a patch, and agreeing with it is not evidence of none."
            ));
        }
        // A patched mode (`MEM-020`): the copies that set the mode are
        // themselves a signal on the classification route. "Agrees with the
        // mode" must not read as reassurance, so the record says it in words
        // -- and says "machine-wide" only when every voting copy, and more
        // than one, carries the patch.
        let mut agreeing = out
            .exports
            .iter()
            .filter(|r| r.export == *export && r.agrees_with_the_mode == Some(true))
            .peekable();
        let shape = agreeing.peek().map(|r| r.classification.as_str());
        if !agreeing.all(|r| r.classification.is_signal()) {
            continue;
        }
        let Some(shape) = shape else { continue };
        let note = if population == 1 {
            format!(
                "{export}: only one copy voted, and it classifies as `{shape}`, so the mode \
                 is that one patched copy. A mode of one is no baseline: whether the patch \
                 is on other copies could not be looked at, and it is not called machine-wide. \
                 The copy is a signal on the classification route alone."
            )
        } else if agreed == population {
            format!(
                "{export}: all {agreed} of the {voters} set the mode and classify as \
                 `{shape}`, so the mode itself is patched -- a machine-wide patch across the \
                 copies that were read. The modal comparison is silent because every one of \
                 them agrees with it; each is a signal on the classification route alone."
            )
        } else if tied_at_the_top > 1 {
            format!(
                "{export}: the mode is patched only by the tie-break -- {agreed} of the \
                 {voters} classify as `{shape}` and at least as many carry another prologue. \
                 This is not a machine-wide patch; the copies that disagree with the mode may \
                 be the clean ones, and the patched copies are signals on the classification \
                 route alone."
            )
        } else {
            format!(
                "{export}: the mode is patched -- {agreed} of the {voters} set it and classify \
                 as `{shape}`, and {} carry something else. This is not a machine-wide patch; \
                 the copies that disagree with the mode may be the clean ones, and the patched \
                 copies are signals on the classification route alone.",
                population - agreed
            )
        };
        out.notes.push(note);
    }
}
