//! The processor control regions (`ROADMAP` §5.3, upstream's `kpcrs`).
//!
//! # What an examiner learns
//!
//! How many processors the kernel was managing, where each one's control
//! region (`_KPCR`) and processor control block (`_KPRCB`) lie, and **what each
//! processor was executing when the capture was taken** — the current thread
//! and the process it belongs to. The last is the fact a live capture holds
//! that a disk never can: which code was on which core at that instant.
//!
//! # The array is walked and the count is compared
//!
//! `KiProcessorBlock` is an array of `_KPRCB` pointers, one per processor, and
//! `KeNumberProcessors` is the kernel's own count. They are two facts. The
//! count carries no declared type in any ISF measured (see `tamper_timers`),
//! and on the smeared captures in this corpus it reads 0 on machines that
//! plainly had processors, so the **array** is what is walked — up to the first
//! null or non-canonical slot — and a count that disagrees with it is stated on
//! the record rather than silently preferred.
//!
//! # Each block is held to what it says about itself
//!
//! A `_KPCR` on x64 embeds its `_KPRCB` at `Prcb` and carries two pointers back
//! at itself: `Self` (the KPCR's own address) and `CurrentPrcb` (the embedded
//! PRCB). The PRCB carries `Number`, its own index. Every record publishes all
//! three comparisons — agree, disagree, or *not made* because this build does
//! not declare the member — because a KPCR reached through a corrupt slot
//! reads like a KPCR until one of them is checked, and a check that was never
//! made must not render as one that passed.
//!
//! # 32-bit builds
//!
//! On x86 the KPCR embeds the block at `PrcbData`, points at itself through
//! `SelfPcr`, and its `Prcb` member is a **pointer** to `PrcbData`. Which
//! spelling applies is decided from the symbol table's own description of the
//! member — an aggregate is embedded, a pointer is not — never from the
//! architecture.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::first_member;
use seance_memory::object::{is_canonical, StructReader};
use seance_memory::Incomplete;
use seance_symbols::TypeKind;
use serde_json::{json, Value};

use crate::profile::WindowsProfile;

/// Processor slots this walk will probe.
///
/// Windows' own architectural ceiling is 2,048 logical processors; the same
/// bound the timer walk uses.
pub const MAX_PROCESSORS: u64 = crate::tamper_timers::MAX_PROCESSORS;

/// What stops the whole survey.
#[derive(Debug, Clone)]
pub enum ProcessorBlockError {
    /// This build cannot be asked the question.
    Unsupported { detail: String },
}

impl ProcessorBlockError {
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }

    pub fn class(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "unsupported_build",
        }
    }
}

impl std::fmt::Display for ProcessorBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { detail } => write!(f, "{detail}"),
        }
    }
}

/// How this build's control regions are laid out.
#[derive(Debug, Clone)]
pub struct ProcessorSymbols {
    /// `KiProcessorBlock`, in kernel virtual space.
    pub prcb_array: u64,
    /// `KeNumberProcessors`, when declared.
    pub processor_count: Option<u64>,
    /// The `_KPCR` member that **embeds** the `_KPRCB`: `Prcb` on x64,
    /// `PrcbData` on x86.
    pub embedded_prcb: String,
    /// Its byte offset, which is what turns a PRCB pointer into a KPCR address.
    pub embedded_prcb_offset: u64,
    /// The `_KPCR` member that points back at the KPCR itself, when declared.
    pub self_member: Option<String>,
    /// The `_KPCR` member that points at the PRCB, when declared.
    pub prcb_pointer_member: Option<String>,
    /// Whether `_KPRCB.Number` is declared.
    pub number_declared: bool,
    /// Whether `_KTHREAD.Process` is declared, which is what lets the current
    /// thread be resolved to a process.
    pub thread_process_declared: bool,
}

impl ProcessorSymbols {
    /// Resolve what this build declares.
    ///
    /// # Errors
    ///
    /// [`ProcessorBlockError::Unsupported`] naming the symbol, when this build
    /// declares no `KiProcessorBlock`, no `_KPCR`, no `_KPRCB`, or no member of
    /// `_KPCR` that embeds the block.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, ProcessorBlockError> {
        let symbol = |name: &str| -> Result<u64, ProcessorBlockError> {
            let rva = profile.symbols.symbol_address(name).map_err(|_| {
                ProcessorBlockError::unsupported(format!(
                    "this build's symbol table has no '{name}', so the per-processor blocks \
                     cannot be reached and nothing can be said about what each processor was \
                     running"
                ))
            })?;
            profile.kernel_base.value.checked_add(rva).ok_or_else(|| {
                ProcessorBlockError::unsupported(format!(
                    "the address of '{name}' does not fit in 64 bits"
                ))
            })
        };
        let prcb_array = symbol("KiProcessorBlock")?;
        let processor_count = symbol("KeNumberProcessors").ok();

        for type_name in ["_KPCR", "_KPRCB"] {
            if !profile.symbols.has_type(type_name) {
                return Err(ProcessorBlockError::unsupported(format!(
                    "this build's symbol table declares no '{type_name}', so a processor block \
                     cannot be read"
                )));
            }
        }

        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        // The embedded block is the member whose type is the aggregate itself;
        // on x86 `Prcb` is a pointer and `PrcbData` is the aggregate.
        let mut embedded = None;
        let mut prcb_pointer_member = None;
        for candidate in ["Prcb", "PrcbData"] {
            let Ok(member) = profile.symbols.member("_KPCR", candidate) else {
                continue;
            };
            match profile.symbols.entry(member.ty).map(|entry| &entry.kind) {
                Ok(TypeKind::Aggregate(_)) if embedded.is_none() => {
                    embedded = Some((candidate.to_string(), member.offset));
                }
                Ok(TypeKind::Pointer { .. }) if prcb_pointer_member.is_none() => {
                    prcb_pointer_member = Some(candidate.to_string());
                }
                _ => {}
            }
        }
        if prcb_pointer_member.is_none() {
            prcb_pointer_member = first_member(&reader, "_KPCR", &["CurrentPrcb"])
                .ok()
                .flatten()
                .map(str::to_string);
        }
        let Some((embedded_prcb, embedded_prcb_offset)) = embedded else {
            return Err(ProcessorBlockError::unsupported(
                "this build's '_KPCR' embeds no '_KPRCB' under 'Prcb' or 'PrcbData', so a \
                 processor block cannot be located from its pointer",
            ));
        };
        let self_member = first_member(&reader, "_KPCR", &["Self", "SelfPcr"])
            .ok()
            .flatten()
            .map(str::to_string);

        Ok(Self {
            prcb_array,
            processor_count,
            embedded_prcb,
            embedded_prcb_offset,
            self_member,
            prcb_pointer_member,
            number_declared: reader.has_member("_KPRCB", "Number"),
            thread_process_declared: profile.symbols.has_type("_KTHREAD")
                && reader.has_member("_KTHREAD", "Process"),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "prcb_array": format!("{:#018x}", self.prcb_array),
            "processor_count": self.processor_count.map(|a| format!("{a:#018x}")),
            "embedded_prcb_member": self.embedded_prcb,
            "embedded_prcb_offset": self.embedded_prcb_offset,
            "self_member": self.self_member,
            "prcb_pointer_member": self.prcb_pointer_member,
            "number_declared": self.number_declared,
            "thread_process_declared": self.thread_process_declared,
        })
    }
}

/// The process a processor's current thread belongs to.
#[derive(Debug, Clone)]
pub struct RunningProcess {
    /// The `_EPROCESS`, which is the `_KPROCESS` the thread names.
    pub address: u64,
    pub pid: Option<u64>,
    pub name: Option<String>,
}

impl RunningProcess {
    pub fn to_json(&self) -> Value {
        json!({
            "process": format!("{:#018x}", self.address),
            "pid": self.pid,
            "name": self.name,
        })
    }
}

/// One processor.
#[derive(Debug, Clone)]
pub struct ProcessorRecord {
    /// Position in `KiProcessorBlock`.
    pub index: u64,
    /// The `_KPRCB` the slot named.
    pub prcb: u64,
    /// The `_KPCR`, recovered by subtracting the embedded block's offset.
    pub kpcr: u64,
    /// What `_KPCR.Self` holds. `None` when the member is undeclared or would
    /// not read.
    pub self_pointer: Option<u64>,
    /// Whether `Self` names this KPCR. `None` when the check was not made.
    pub self_agrees: Option<bool>,
    /// What the KPCR's PRCB pointer holds.
    pub current_prcb_pointer: Option<u64>,
    /// Whether it names the embedded block. `None` when the check was not made.
    pub current_prcb_agrees: Option<bool>,
    /// `_KPRCB.Number`.
    pub number: Option<u64>,
    /// Whether it equals the slot index. `None` when the check was not made.
    pub number_agrees: Option<bool>,
    pub current_thread: Option<u64>,
    pub next_thread: Option<u64>,
    pub idle_thread: Option<u64>,
    /// The current thread's process, when it could be followed.
    pub current_process: Option<RunningProcess>,
    /// Whether the current thread is the idle thread — a processor that was
    /// doing nothing at capture.
    pub idle: Option<bool>,
    pub major_version: Option<u64>,
    pub minor_version: Option<u64>,
    pub cpu_type: Option<u64>,
    pub cpu_id: Option<u64>,
    pub cores_per_physical_processor: Option<u64>,
    pub logical_processors_per_core: Option<u64>,
    pub gdt_base: Option<u64>,
    pub idt_base: Option<u64>,
    pub tss_base: Option<u64>,
    pub kd_version_block: Option<u64>,
    /// Why a field above is `None` when it was declared, and anything else odd.
    pub notes: Vec<String>,
    /// The KPCR could not be read at all; nothing above it is populated.
    pub unreadable: Option<String>,
}

impl ProcessorRecord {
    fn empty(index: u64, prcb: u64, kpcr: u64) -> Self {
        Self {
            index,
            prcb,
            kpcr,
            self_pointer: None,
            self_agrees: None,
            current_prcb_pointer: None,
            current_prcb_agrees: None,
            number: None,
            number_agrees: None,
            current_thread: None,
            next_thread: None,
            idle_thread: None,
            current_process: None,
            idle: None,
            major_version: None,
            minor_version: None,
            cpu_type: None,
            cpu_id: None,
            cores_per_physical_processor: None,
            logical_processors_per_core: None,
            gdt_base: None,
            idt_base: None,
            tss_base: None,
            kd_version_block: None,
            notes: Vec::new(),
            unreadable: None,
        }
    }

    /// Whether no self-check disagreed. An unmade check is not a failed one,
    /// and [`ProcessorRecord::checks_made`] says how many were made.
    pub fn is_coherent(&self) -> bool {
        self.unreadable.is_none()
            && self.self_agrees != Some(false)
            && self.current_prcb_agrees != Some(false)
            && self.number_agrees != Some(false)
    }

    /// How many of the three self-checks were made.
    pub fn checks_made(&self) -> usize {
        [
            self.self_agrees,
            self.current_prcb_agrees,
            self.number_agrees,
        ]
        .iter()
        .filter(|c| c.is_some())
        .count()
    }

    pub fn to_json(&self) -> Value {
        let hex = |v: Option<u64>| v.map(|v| format!("{v:#018x}"));
        json!({
            "type": "MemoryProcessorBlock",
            "name": format!("processor {} at {:#018x}", self.index, self.kpcr),
            "index": self.index,
            "prcb": format!("{:#018x}", self.prcb),
            "kpcr": format!("{:#018x}", self.kpcr),
            "self_pointer": hex(self.self_pointer),
            "self_agrees": self.self_agrees,
            "current_prcb_pointer": hex(self.current_prcb_pointer),
            "current_prcb_agrees": self.current_prcb_agrees,
            "number": self.number,
            "number_agrees": self.number_agrees,
            "checks_made": self.checks_made(),
            "coherent": self.is_coherent(),
            "current_thread": hex(self.current_thread),
            "next_thread": hex(self.next_thread),
            "idle_thread": hex(self.idle_thread),
            "idle": self.idle,
            "current_process": self.current_process.as_ref().map(RunningProcess::to_json),
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "cpu_type": self.cpu_type,
            "cpu_id": self.cpu_id,
            "cores_per_physical_processor": self.cores_per_physical_processor,
            "logical_processors_per_core": self.logical_processors_per_core,
            "gdt_base": hex(self.gdt_base),
            "idt_base": hex(self.idt_base),
            "tss_base": hex(self.tss_base),
            "kd_version_block": hex(self.kd_version_block),
            "notes": self.notes,
            "unreadable": self.unreadable,
        })
    }
}

/// What one survey produced.
#[derive(Debug, Clone)]
pub struct ProcessorSurvey {
    pub symbols: ProcessorSymbols,
    pub processors: Vec<ProcessorRecord>,
    /// `KeNumberProcessors`, as read.
    pub claimed: Option<u64>,
    /// Slots of `KiProcessorBlock` read, including the one that ended the walk.
    pub slots_probed: u64,
    /// Why the array walk ended.
    pub stop: String,
    /// The sentence stating a disagreement between the count and the array.
    pub count_note: Option<String>,
    /// The walk reached [`MAX_PROCESSORS`].
    pub capped: bool,
}

impl ProcessorSurvey {
    /// Processors whose self-checks disagreed or whose block would not read.
    pub fn incoherent(&self) -> usize {
        self.processors.iter().filter(|p| !p.is_coherent()).count()
    }

    /// Whether the array and the count agree, every block read, and no check
    /// failed. A survey that is not complete is a floor, not a total.
    pub fn is_complete(&self) -> bool {
        !self.capped
            && self.count_note.is_none()
            && self.processors.iter().all(|p| p.unreadable.is_none())
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if self.capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the KiProcessorBlock walk stopped at {MAX_PROCESSORS} slots, so a machine \
                     declaring more processors than that has processors this record does not \
                     hold"
                ),
            ));
        }
        if let Some(note) = &self.count_note {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                note.clone(),
            ));
        }
        for p in self.processors.iter().filter(|p| p.unreadable.is_some()) {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "processor {}'s control region at {:#018x} could not be read: {}",
                    p.index,
                    p.kpcr,
                    p.unreadable.clone().unwrap_or_default()
                ),
            ));
        }
        out
    }

    pub fn describe(&self) -> String {
        let running: Vec<String> = self
            .processors
            .iter()
            .filter_map(|p| {
                p.current_process.as_ref().map(|proc| {
                    format!(
                        "{} on processor {}",
                        proc.name
                            .clone()
                            .unwrap_or_else(|| format!("pid {:?}", proc.pid)),
                        p.index
                    )
                })
            })
            .collect();
        format!(
            "{} processor control region(s) were read from the KiProcessorBlock array; \
             KeNumberProcessors {}. {} passed every self-check that could be made and {} did \
             not.{}",
            self.processors.len(),
            match self.claimed {
                Some(c) => format!("reads {c}"),
                None => "could not be read".to_string(),
            },
            self.processors.len() - self.incoherent(),
            self.incoherent(),
            if running.is_empty() {
                String::new()
            } else {
                format!(" Running at capture: {}.", running.join(", "))
            }
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "symbols": self.symbols.to_json(),
            "processors": self.processors.iter().map(ProcessorRecord::to_json).collect::<Vec<_>>(),
            "processors_walked": self.processors.len(),
            "processors_claimed": self.claimed,
            "processor_count_note": self.count_note,
            "slots_probed": self.slots_probed,
            "walk_stop": self.stop,
            "coherent": self.processors.len() - self.incoherent(),
            "incoherent": self.incoherent(),
            "checks_basis":
                "Three checks per block, each reported as agree, disagree or not made: \
                 `_KPCR.Self` (or `SelfPcr`) must name the KPCR, the KPCR's PRCB pointer \
                 (`CurrentPrcb`, or `Prcb` where it is a pointer) must name the embedded block, \
                 and `_KPRCB.Number` must equal the slot index. A check this build's symbols \
                 cannot make is `null`, which is not a pass. The KPCR address is the slot's \
                 PRCB pointer minus the declared offset of the embedded block, so every KPCR \
                 address here rests on that offset.",
            "count_basis":
                "`KeNumberProcessors` carries no declared type in any ISF measured and reads 0 \
                 on smeared captures in this corpus, so the array is what was walked: slots \
                 up to the first null or non-canonical pointer. A count that disagrees with \
                 the array is stated, never preferred.",
            "statement": self.describe(),
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Walk `KiProcessorBlock` and read every processor's control region.
pub fn survey_processors(profile: &WindowsProfile, symbols: &ProcessorSymbols) -> ProcessorSurvey {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let pointer = reader.pointer_size().unwrap_or(8);

    let claimed = symbols.processor_count.and_then(|at| {
        let mut bytes = [0u8; 4];
        reader
            .read_into(at, &mut bytes)
            .ok()
            .map(|()| u64::from(u32::from_le_bytes(bytes)))
    });

    let mut processors = Vec::new();
    let mut slots_probed = 0u64;
    let mut stop = String::new();
    let mut capped = false;
    for index in 0..MAX_PROCESSORS {
        let at = symbols.prcb_array + index * u64::from(pointer);
        slots_probed += 1;
        let prcb = match reader.read_pointer_at(at) {
            Ok(v) => v,
            Err(err) => {
                stop = format!("slot {index} at {at:#018x} could not be read: {err}");
                break;
            }
        };
        if prcb == 0 {
            stop = format!("slot {index} is null");
            break;
        }
        if !is_canonical(prcb, pointer) {
            stop = format!("slot {index} holds {prcb:#018x}, which is not a canonical address");
            break;
        }
        let Some(kpcr) = prcb.checked_sub(symbols.embedded_prcb_offset) else {
            stop = format!(
                "slot {index} holds {prcb:#018x}, below the embedded block's offset, so no KPCR \
                 can lie before it"
            );
            break;
        };
        processors.push(read_processor(&reader, symbols, index, prcb, kpcr));
        if index + 1 == MAX_PROCESSORS {
            capped = true;
            stop = format!("the walk reached its ceiling of {MAX_PROCESSORS} slots");
        }
    }

    let count_note = match claimed {
        Some(count) if count as usize == processors.len() => None,
        Some(count) => Some(format!(
            "`KeNumberProcessors` reads {count} and the `KiProcessorBlock` array holds {} usable \
             pointer(s). The array is what was walked; the count carries no declared type in \
             any ISF measured, so its width is not knowable from the symbols.",
            processors.len()
        )),
        None => Some(format!(
            "`KeNumberProcessors` could not be read; the `KiProcessorBlock` array was probed \
             instead and holds {} usable pointer(s).",
            processors.len()
        )),
    };

    ProcessorSurvey {
        symbols: symbols.clone(),
        processors,
        claimed,
        slots_probed,
        stop,
        count_note,
        capped,
    }
}

/// Read one processor's KPCR and PRCB.
fn read_processor(
    reader: &StructReader,
    symbols: &ProcessorSymbols,
    index: u64,
    prcb: u64,
    kpcr: u64,
) -> ProcessorRecord {
    let mut record = ProcessorRecord::empty(index, prcb, kpcr);
    let pcr = match reader.object(kpcr, "_KPCR") {
        Ok(pcr) => pcr,
        Err(err) => {
            record.unreadable = Some(err.to_string());
            return record;
        }
    };

    let mut pointer_of = |object: &seance_memory::object::Obj, path: &str| -> Option<u64> {
        match object.pointer(path) {
            Ok(v) => Some(v),
            Err(err) => {
                record.notes.push(format!("'{path}' would not read: {err}"));
                None
            }
        }
    };

    if let Some(member) = &symbols.self_member {
        record.self_pointer = pointer_of(&pcr, member);
        record.self_agrees = record.self_pointer.map(|v| v == kpcr);
    }
    if let Some(member) = &symbols.prcb_pointer_member {
        record.current_prcb_pointer = pointer_of(&pcr, member);
        record.current_prcb_agrees = record.current_prcb_pointer.map(|v| v == prcb);
    }
    for (path, slot) in [
        ("GdtBase", &mut record.gdt_base),
        ("IdtBase", &mut record.idt_base),
        ("TssBase", &mut record.tss_base),
        ("KdVersionBlock", &mut record.kd_version_block),
    ] {
        if pcr.has_member(path) {
            *slot = pcr.pointer(path).ok();
        }
    }

    let block = match pcr.embedded(&symbols.embedded_prcb) {
        Ok(block) => block,
        Err(err) => {
            record
                .notes
                .push(format!("the embedded '_KPRCB' would not read: {err}"));
            return record;
        }
    };
    if symbols.number_declared {
        record.number = block.unsigned("Number").ok();
        record.number_agrees = record.number.map(|n| n == index);
    }
    let unsigned = |path: &str| -> Option<u64> {
        block
            .has_member(path)
            .then(|| block.unsigned(path).ok())
            .flatten()
    };
    record.major_version = unsigned("MajorVersion");
    record.minor_version = unsigned("MinorVersion");
    record.cpu_type = unsigned("CpuType");
    record.cpu_id = unsigned("CpuID");
    record.cores_per_physical_processor = unsigned("CoresPerPhysicalProcessor");
    record.logical_processors_per_core = unsigned("LogicalProcessorsPerCore");
    let pointer = |path: &str| -> Option<u64> {
        block
            .has_member(path)
            .then(|| block.pointer(path).ok())
            .flatten()
    };
    record.current_thread = pointer("CurrentThread");
    record.next_thread = pointer("NextThread");
    record.idle_thread = pointer("IdleThread");
    record.idle = match (record.current_thread, record.idle_thread) {
        (Some(current), Some(idle)) if idle != 0 => Some(current == idle),
        _ => None,
    };

    if symbols.thread_process_declared {
        if let Some(thread) = record.current_thread.filter(|t| *t != 0) {
            match resolve_process(reader, thread) {
                Ok(process) => record.current_process = Some(process),
                Err(why) => record.notes.push(why),
            }
        }
    }
    record
}

/// The process a thread belongs to, through `_KTHREAD.Process`.
///
/// The pointer names a `_KPROCESS`, which is the first member of the
/// `_EPROCESS` that holds it (`Pcb`, at offset zero on every build measured),
/// so the same address is read as an `_EPROCESS`. The offset is checked
/// against the symbols rather than assumed.
fn resolve_process(reader: &StructReader, thread: u64) -> Result<RunningProcess, String> {
    let kthread = reader
        .object(thread, "_KTHREAD")
        .map_err(|err| format!("the current thread at {thread:#018x} would not read: {err}"))?;
    let kprocess = kthread
        .pointer("Process")
        .map_err(|err| format!("'_KTHREAD.Process' would not read: {err}"))?;
    if kprocess == 0 {
        return Err("the current thread names no process".to_string());
    }
    let pcb_offset = reader
        .member_offset("_EPROCESS", "Pcb")
        .map(|o| o.bytes())
        .map_err(|_| {
            "this build's '_EPROCESS' declares no 'Pcb', so a '_KPROCESS' cannot be placed \
             inside one"
                .to_string()
        })?;
    let address = kprocess.checked_sub(pcb_offset).ok_or_else(|| {
        format!("the process pointer {kprocess:#018x} lies below the Pcb offset {pcb_offset}")
    })?;
    let eprocess = reader
        .object(address, "_EPROCESS")
        .map_err(|err| format!("the process at {address:#018x} would not read: {err}"))?;
    Ok(RunningProcess {
        address,
        pid: eprocess.pointer("UniqueProcessId").ok(),
        name: eprocess
            .bytes(crate::process::MEMBER_IMAGE_FILE_NAME)
            .ok()
            .map(|raw| crate::poolscan::image_file_name(&raw))
            .filter(|name| !name.is_empty()),
    })
}
