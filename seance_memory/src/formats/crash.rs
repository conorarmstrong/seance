//! Windows crash dumps — `PAGEDUMP` (32-bit) and `PAGEDU64` (64-bit), in both
//! the full and bitmap layouts.
//!
//! This is the Windows bring-up format, and not because it is common. A crash
//! dump's header **states the `DirectoryTableBase`** — the page-table root the
//! rest of memory analysis is built on — along with `KdDebuggerDataBlock`,
//! `PsActiveProcessHead`, `PsLoadedModuleList` and `PfnDataBase`. Every one of
//! those is otherwise recovered by scanning heuristics that can be wrong in
//! ways that look right. Here they are read out of a structure the kernel
//! wrote, so they are published into [`LayerMeta`] as notes and a later phase
//! can skip the self-referential DTB scan entirely.
//!
//! ## The two layouts
//!
//! | | 32-bit | 64-bit |
//! |---|---|---|
//! | second magic word | `DUMP` | `DU64` |
//! | header bytes ahead of the payload | `0x1000` (1 page) | `0x2000` (2 pages) |
//! | pointer fields | `u32` | `u64` |
//! | `_PHYSICAL_MEMORY_RUN` | two `u32` | two `u64` |
//!
//! ## The dump types
//!
//! - **`DumpType == 0x1`, full.** The payload is the physical runs listed in
//!   `PhysicalMemoryBlockBuffer`, concatenated in list order starting at the
//!   first byte after the header.
//! - **`DumpType == 0x5`, bitmap.** A `_SUMMARY_DUMP` follows the header with a
//!   bit per physical page; the payload holds only the pages whose bit is set,
//!   packed in bit order, starting at the summary's `HeaderSize`. This is why a
//!   bitmap dump of an 8 GiB machine can be a fraction of that size — and why
//!   the unset pages are [`crate::layer::MemoryHole`]s and not zeros.
//! - **`DumpType == 0x6`, kernel bitmap.** The same `_SUMMARY_DUMP` layout, and
//!   the type Task Manager's "create live kernel dump" writes, so it is now the
//!   common acquisition on a running machine. What differs is *scope*, not
//!   structure: only pages the kernel owns are written. It is decoded, and the
//!   layer carries an incompleteness saying user-mode memory was never
//!   acquired — a partial address space is worth having, but it must not read
//!   as a complete one.
//!
//! Kernel (`0x2`), small (`0x3`) and automatic (`0x4`) dumps, and `0x0`, are
//! **not** supported, exactly as upstream. They fail closed with the type
//! named, rather than producing a partial address space that reads as complete.
//!
//! ## A refused dump still states things
//!
//! Refusing to map a triage dump is not the same as having nothing to say about
//! it. The header of a dump this reader will not open is a complete
//! `_DUMP_HEADER` all the same, and it states the bugcheck code and its four
//! parameters, the moment of the crash, the build, the processor count and the
//! kernel pointers. [`header_facts`] reads them on either path, so an examiner
//! holding a minidump learns why the machine stopped instead of only that the
//! file would not decode. It changes nothing about the refusal: there is still
//! no address space in the file, and [`open`] still says so.

use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_core::io::{read_exact_or_fail, IncompleteReason};

use crate::format::MemoryImageFormat;
use crate::layer::{LayerError, MAX_SEGMENTS};
use crate::meta::{Architecture, LayerMeta};
use crate::segmented::{Segment, SegmentedLayer};

use super::{u32_at, u64_at, Endian, FormatError};

const LE: Endian = Endian::Little;

/// Windows dumps physical memory in 4 KiB pages on every architecture it
/// supports here, and the run and bitmap tables are both denominated in them.
pub const PAGE_SIZE: u64 = 0x1000;

/// First word of both layouts.
const SIGNATURE: &[u8; 4] = b"PAGE";

/// `DumpType` for a complete dump described by a run list.
pub const DUMP_TYPE_FULL: u32 = 0x1;
/// `DumpType` for a bitmap dump described by a page bitmap.
pub const DUMP_TYPE_BITMAP: u32 = 0x5;
/// `DumpType` for a kernel bitmap dump: the `0x5` layout, holding only the
/// pages the kernel owns.
pub const DUMP_TYPE_KERNEL_BITMAP: u32 = 0x6;
/// `DumpType` for a kernel dump (`CONTROL_KERNEL`) and for an automatic dump.
/// Both, on a modern Windows, are written as a `_SUMMARY_DUMP` bitmap holding
/// only the kernel's pages — the same layout as `0x6` — so a dump of these types
/// that carries a summary is read as a kernel bitmap.
pub const DUMP_TYPE_KERNEL: u32 = 0x2;
pub const DUMP_TYPE_AUTOMATIC: u32 = 0x4;

/// The `Signature` a `_SUMMARY_DUMP` begins with (`"SDMP"`). Its presence is
/// what distinguishes a bitmap-form dump from a triage/small dump that carries
/// no reconstructable address space.
const SUMMARY_SIGNATURE: &[u8; 4] = b"SDMP";

/// `_SUMMARY_DUMP` field offsets. The structure is shared by both bitnesses.
const SUMMARY_HEADER_SIZE: usize = 32;
const SUMMARY_PAGES: usize = 40;
const SUMMARY_BITMAP_SIZE: usize = 48;
/// The bitmap begins immediately after the fixed part of `_SUMMARY_DUMP`.
const SUMMARY_FIXED_BYTES: u64 = 56;

/// The largest physical address space a `_SUMMARY_DUMP` page bitmap may
/// describe, in 4 KiB pages.
///
/// `BitmapSize` is a `u64` the header states and nothing corroborates, and it
/// alone decides both how many bytes are allocated to hold the bitmap and how
/// many iterations the bit walk runs. Bounding it by the acquisition's own size
/// is not a bound at all on a multi-gigabyte dump: a corrupt or hostile field
/// that fits under the file size still forces a near-file-sized buffer and an
/// 8x-file-size bit loop before a single page is mapped.
///
/// 8 TiB is above any machine a bitmap dump has plausibly been taken from — the
/// payload has to have been written somewhere — and an acquisition above it is
/// refused with the figure named rather than being read at all.
pub const MAX_BITMAP_PAGES: u64 = (8u64 << 40) / PAGE_SIZE;

/// `IMAGE_FILE_MACHINE_ARM64`. The only machine value that says something the
/// header's own bitness does not.
const MACHINE_ARM64: u32 = 0xAA64;

/// `IMAGE_FILE_MACHINE_AMD64`. Read for one purpose only: the `CONTEXT`
/// structure the kernel wrote into `ContextRecord` is the machine's, not the
/// header's, and the only one whose field offsets this file pins is the x64
/// form (see [`Layout::context_flags`]).
const MACHINE_AMD64: u32 = 0x8664;

/// `sizeof(CONTEXT)` on x64, and `sizeof(EXCEPTION_RECORD64)`. Together with
/// `context_record` and `dump_type` these box in where `Exception` sits: the
/// space between the end of the context and `DumpType` is exactly one
/// exception record, with nothing left over. The other half of that
/// arithmetic — `CHAR VersionUser[32]`, which closes the bugcheck parameters
/// against the next named offset — is spelled out on [`Layout`] and re-run by
/// the tests, since no field is read through it.
const CONTEXT_AMD64_BYTES: usize = 3000;
const EXCEPTION_RECORD_BYTES: usize = 152;

/// `EXCEPTION_RECORD64` field offsets, relative to the record.
///
/// `ExceptionRecord` (a pointer to the nested record) sits at 8 and
/// `ExceptionInformation[15]` at 32; neither is read. The nested pointer is a
/// virtual address into an address space a refused dump does not offer, and the
/// information array is filler in both corpus dumps whenever
/// `NumberParameters` is zero.
const EXCEPTION_CODE: usize = 0;
const EXCEPTION_FLAGS: usize = 4;
const EXCEPTION_ADDRESS: usize = 16;
const EXCEPTION_PARAMETER_COUNT: usize = 24;

/// `ContextFlags` within the x64 `CONTEXT`, after the six `P1Home..P6Home`
/// `ULONG64` slots the structure opens with (6 * 8 == 0x30).
const CONTEXT_AMD64_FLAGS: usize = 0x30;

/// Which payload layout the header selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashDumpKind {
    /// `DumpType == 0x1`: every run in `PhysicalMemoryBlockBuffer` is present.
    Full,
    /// `DumpType == 0x5`: only the pages whose bitmap bit is set are present.
    Bitmap,
    /// `DumpType == 0x6`: the `0x5` layout, written with only the pages the
    /// kernel owns. Kept apart from [`CrashDumpKind::Bitmap`] because the
    /// difference is what an examiner must be told: a string that is not in
    /// this address space may still have been in the machine's user-mode
    /// memory, which was never written to the file.
    KernelBitmap,
}

impl CrashDumpKind {
    /// Stable identifier for artifact metadata and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            CrashDumpKind::Full => "full",
            CrashDumpKind::Bitmap => "bitmap",
            CrashDumpKind::KernelBitmap => "kernel_bitmap",
        }
    }

    /// The on-disk `DumpType` value this kind corresponds to.
    pub fn dump_type(self) -> u32 {
        match self {
            CrashDumpKind::Full => DUMP_TYPE_FULL,
            CrashDumpKind::Bitmap => DUMP_TYPE_BITMAP,
            CrashDumpKind::KernelBitmap => DUMP_TYPE_KERNEL_BITMAP,
        }
    }
}

/// Field offsets for one of the two `_DUMP_HEADER` layouts.
///
/// Taken from the crash-dump ISFs Volatility bundles (`symbols/windows/crash.json`
/// and `crash64.json`), which describe the *file format* and are therefore
/// version-independent — there is no Windows build whose dump header differs.
#[derive(Debug, Clone, Copy)]
struct Layout {
    format: MemoryImageFormat,
    /// The second magic word this layout is identified by.
    valid_dump: &'static [u8; 4],
    /// Bytes of header ahead of the payload: `headerpages * PAGE_SIZE`.
    header_bytes: u64,
    /// Width of the header's pointer-valued fields.
    pointer_bytes: usize,
    major_version: usize,
    minor_version: usize,
    directory_table_base: usize,
    pfn_database: usize,
    ps_loaded_module_list: usize,
    ps_active_process_head: usize,
    machine_image_type: usize,
    number_processors: usize,
    bug_check_code: usize,
    /// `BugCheckParameter1..4`, the four `ULONG_PTR` arguments the bugcheck was
    /// raised with.
    ///
    /// DERIVED, not looked up. The bundled ISFs do not name these, but their
    /// placement is forced by two offsets that are named. They begin one
    /// `ULONG` past `BugCheckCode`, and the documented `CHAR VersionUser[32]`
    /// that follows them has to end exactly where the next named field starts:
    /// on 64-bit `0x40 + 4*8 + 32 == 0x80`, which is `kd_debugger_data_block`,
    /// and on 32-bit `0x2C + 4*4 + 32 == 0x5C`, which is `pae_enabled`. Both
    /// close with nothing left over, so there is no slack for the fields to
    /// sit anywhere else. `the_bugcheck_parameter_offsets_close_between_
    /// bugcheckcode_and_the_next_named_field` re-runs that arithmetic, so the
    /// derivation can be checked rather than trusted.
    bug_check_parameters: [usize; 4],
    kd_debugger_data_block: usize,
    /// Offset of `PhysicalMemoryBlockBuffer` in the header.
    memory_descriptor: usize,
    /// Offset of `NumberOfPages` within that descriptor, and its width.
    descriptor_pages: usize,
    descriptor_pages_bytes: usize,
    /// Offset of `Run[0]` within that descriptor.
    run_array: usize,
    /// Width of `BasePage` and `PageCount`.
    run_field_bytes: usize,
    /// Offset of `ContextRecord`, the first byte the run table may not reach.
    context_record: usize,
    /// Offset of `ContextFlags` within that `CONTEXT`, when this layout's
    /// context structure is one the file pins.
    ///
    /// Only the x64 form is set. It is published as evidence that the faulting
    /// processor context is present and well-formed — not as registers: naming
    /// `Rip` or `Rsp` needs the full `winnt.h` offset table, which is
    /// documented but not vendored here, and a register attributed to the wrong
    /// slot is a fact about the crash that the bytes do not support.
    ///
    /// Setting it is not enough to read it, because the offset belongs to the
    /// CONTEXT structure rather than to the header, and this layout serves
    /// every 64-bit dump including ARM64 ones. [`Layout::context_flags_at`] is
    /// what decides, per file, whether the machine that crashed is the one
    /// these 0x30 bytes describe.
    context_flags: Option<usize>,
    /// Offset of `Exception`, the `EXCEPTION_RECORD64` describing the fault
    /// that stopped the machine.
    ///
    /// DERIVED like [`Layout::bug_check_parameters`], and only where the
    /// arithmetic closes: `context_record` (840) + `sizeof(CONTEXT)` on x64
    /// (3000) == 3840, and 3840 + `sizeof(EXCEPTION_RECORD64)` (152) == 3992,
    /// which is `dump_type`. Both ends are offsets already in this table, so
    /// the record is boxed in rather than placed by guess. Left `None` for
    /// 32-bit: closing it there would mean assuming a `sizeof(CONTEXT)` for x86
    /// that nothing else here pins, and no 32-bit dump exists in the corpus to
    /// contradict a wrong assumption.
    exception_record: Option<usize>,
    dump_type: usize,
    system_time: usize,
    system_up_time: usize,
    comment: usize,
    /// `PaeEnabled`, which only the 32-bit layout carries.
    pae_enabled: Option<usize>,
}

impl Layout {
    /// Largest `NumberOfRuns` the header can physically hold: the run table
    /// starts inside `PhysicalMemoryBlockBuffer` and cannot reach
    /// `ContextRecord`, which the kernel wrote immediately after it.
    fn max_runs(&self) -> u64 {
        let start = self.memory_descriptor + self.run_array;
        let entry = self.run_field_bytes * 2;
        ((self.context_record.saturating_sub(start)) / entry) as u64
    }

    /// Where `ContextFlags` sits in this header, for the machine the header
    /// names — or `None` when this file does not pin it.
    ///
    /// `_DUMP_HEADER64` is one structure but two machines: `MachineImageType`
    /// is `0xAA64` on an ARM64 dump, and `ARM64_NT_CONTEXT` opens with
    /// `ContextFlags` at offset 0 followed by `Cpsr` and the 31 `X` registers.
    /// [`CONTEXT_AMD64_FLAGS`] therefore lands inside the X block on such a
    /// dump, and the word published "as evidence that the faulting processor
    /// context is present and well-formed" would in fact be the low half of a
    /// saved general-purpose register.
    ///
    /// The ARM64 offset is not read at the right place instead, because this
    /// file's rule is that an offset it cannot pin is not shipped: `0x30` is
    /// grounded by arithmetic against constants already here (the six
    /// `P1Home..P6Home` slots), and nothing in this tree grounds the ARM64
    /// layout the same way. So the machine must be positively the one the x64
    /// arithmetic describes — an unstated or unrecognised `MachineImageType`
    /// leaves the structure at `ContextRecord` unidentified, and an
    /// unidentified structure is not read.
    ///
    /// Only `ContextFlags` is affected. `ContextRecord` is a fixed-size slot,
    /// so [`Layout::exception_record`] still closes against `DumpType`
    /// whatever context was written into it.
    fn context_flags_at(&self, machine_image_type: Option<u32>) -> Option<usize> {
        let within_context = self.context_flags?;
        match machine_image_type {
            Some(MACHINE_AMD64) => Some(self.context_record + within_context),
            _ => None,
        }
    }
}

const LAYOUT_32: Layout = Layout {
    format: MemoryImageFormat::WindowsCrashDump32,
    valid_dump: b"DUMP",
    header_bytes: 0x1000,
    pointer_bytes: 4,
    major_version: 8,
    minor_version: 12,
    directory_table_base: 16,
    pfn_database: 20,
    ps_loaded_module_list: 24,
    ps_active_process_head: 28,
    machine_image_type: 32,
    number_processors: 36,
    bug_check_code: 40,
    bug_check_parameters: [0x2C, 0x30, 0x34, 0x38],
    kd_debugger_data_block: 96,
    memory_descriptor: 100,
    descriptor_pages: 4,
    descriptor_pages_bytes: 4,
    run_array: 8,
    run_field_bytes: 4,
    context_record: 800,
    context_flags: None,
    exception_record: None,
    dump_type: 3976,
    system_time: 4032,
    system_up_time: 4024,
    comment: 2080,
    pae_enabled: Some(92),
};

const LAYOUT_64: Layout = Layout {
    format: MemoryImageFormat::WindowsCrashDump64,
    valid_dump: b"DU64",
    header_bytes: 0x2000,
    pointer_bytes: 8,
    major_version: 8,
    minor_version: 12,
    directory_table_base: 16,
    pfn_database: 24,
    ps_loaded_module_list: 32,
    ps_active_process_head: 40,
    machine_image_type: 48,
    number_processors: 52,
    bug_check_code: 56,
    bug_check_parameters: [0x40, 0x48, 0x50, 0x58],
    kd_debugger_data_block: 128,
    memory_descriptor: 136,
    // The bundled upstream ISF places `NumberOfPages` at 4 as a `u32`, which is
    // the padding half of the `ULONG NumberOfRuns` slot rather than the field.
    // `Run[0]` at 16 only makes sense with a `ULONG64 NumberOfPages` at 8, which
    // is what the kernel struct declares, so that is what is read here. The
    // field is published as a note and drives no decision, so the divergence
    // cannot change which bytes an examiner is shown.
    descriptor_pages: 8,
    descriptor_pages_bytes: 8,
    run_array: 16,
    run_field_bytes: 8,
    context_record: 840,
    context_flags: Some(CONTEXT_AMD64_FLAGS),
    exception_record: Some(840 + CONTEXT_AMD64_BYTES),
    dump_type: 3992,
    system_time: 4008,
    system_up_time: 4144,
    comment: 4016,
    pae_enabled: None,
};

const COMMENT_BYTES: usize = 128;

/// A parsed crash-dump header: the segment list, the architecture the layout
/// proves, and the kernel pointers the header states outright.
///
/// The stated pointers and counts are `Option` for the same reason
/// [`CrashHeaderFacts`]' are: Windows hands the crash writer header pages
/// already stamped with the `PAGE` fill pattern, so a field the kernel had no
/// value for reads back as filler rather than as zero (see [`is_page_filler`]).
/// `None` means "this file does not state it", which is a different claim from
/// a number.
#[derive(Debug, Clone)]
pub struct CrashDump {
    format: MemoryImageFormat,
    kind: CrashDumpKind,
    architecture: Architecture,
    directory_table_base: Option<u64>,
    kd_debugger_data_block: Option<u64>,
    pfn_database: Option<u64>,
    ps_loaded_module_list: Option<u64>,
    ps_active_process_head: Option<u64>,
    machine_image_type: Option<u32>,
    number_processors: Option<u32>,
    segments: Vec<Segment>,
    meta: LayerMeta,
}

impl CrashDump {
    /// Read the dump header, the run list or page bitmap, and everything the
    /// header states about the machine.
    ///
    /// # Errors
    ///
    /// - [`FormatError::NotThisFormat`] when the eight magic bytes are absent.
    /// - [`FormatError::Unsupported`] for a `DumpType` other than `0x1`, `0x5`
    ///   or `0x6`, with the value named.
    /// - [`FormatError::Malformed`] for a run table that cannot fit in the
    ///   header, a zero-length run, a bitmap that does not fit between the
    ///   summary header and the payload, a bitmap describing more than
    ///   [`MAX_BITMAP_PAGES`] pages, or any extent that overflows.
    /// - [`FormatError::Io`] when the header, summary or bitmap cannot be read
    ///   in full.
    pub fn parse(source: &dyn DataSource) -> Result<Self, FormatError> {
        let (layout, bytes) = read_header(source)?;
        let format = layout.format;
        let header = Fields {
            bytes: &bytes,
            format,
            structure: "_DUMP_HEADER",
        };

        let dump_type = header.u32(layout.dump_type)?;
        let kind = match mappable_kind(dump_type, source, &layout) {
            Some(kind) => kind,
            None => {
                // A triage or small dump (0x3, or a 0x2/0x4 with no summary) is
                // not a physical address space at all — it holds a handful of
                // structures for a bugcheck triage, not memory to map — so it is
                // named apart from a merely unknown type. What its header does
                // state about the crash is published separately, by
                // [`header_facts`], which is reachable on this path precisely
                // because the refusal below ends it.
                let detail = if is_triage_type(dump_type) {
                    format!(
                        "DumpType {dump_type:#x} carries no _SUMMARY_DUMP and no run list: it is \
                         {TRIAGE_DETAIL}"
                    )
                } else {
                    format!(
                        "DumpType {dump_type:#x}; only {DUMP_TYPE_FULL:#x} (full), \
                         {DUMP_TYPE_BITMAP:#x} (bitmap), {DUMP_TYPE_KERNEL_BITMAP:#x} \
                         (kernel bitmap), and a summary-carrying {DUMP_TYPE_KERNEL:#x}/\
                         {DUMP_TYPE_AUTOMATIC:#x} describe a physical address space this reader \
                         can map"
                    )
                };
                return Err(FormatError::unsupported(format, detail));
            }
        };

        // Two kinds of value are read out of this header, and they are read
        // differently on purpose.
        //
        // The STRUCTURAL ones decide how the file is taken apart: `DumpType`
        // above, which chose the payload layout and would already have refused
        // this dump had it held filler; the run table or page bitmap read
        // below, which is the geometry itself; and `MachineImageType`, which
        // only ever distinguishes ARM64 from the x86/x64 the pointer width
        // already proves. Guarding those would change which bytes an examiner
        // is shown rather than what this file is reported to say, so they are
        // read raw and any refusal they cause is a refusal to decode.
        //
        // The PUBLISHED ones below are facts about the machine, and nothing
        // here depends on them. They go through the filler guard because a
        // field the kernel never wrote must reach the record as absent rather
        // than as `0x45474150` — the fill pattern read as a build number, a
        // processor count, a kernel pointer or a bugcheck code. These are the
        // same offsets, read the same way, as [`CrashHeaderFacts::read`]: both
        // blocks land in one artifact, so a field guarded on one path and raw
        // on the other would put two contradictory values for one offset in
        // front of an examiner.
        let width = layout.pointer_bytes;
        let directory_table_base = header.stated_uint(layout.directory_table_base, width)?;
        let pfn_database = header.stated_uint(layout.pfn_database, width)?;
        let ps_loaded_module_list = header.stated_uint(layout.ps_loaded_module_list, width)?;
        let ps_active_process_head = header.stated_uint(layout.ps_active_process_head, width)?;
        let kd_debugger_data_block = header.stated_uint(layout.kd_debugger_data_block, width)?;
        let machine_image_type = header.stated_u32(layout.machine_image_type)?;
        let number_processors = header.stated_u32(layout.number_processors)?;
        let major_version = header.stated_u32(layout.major_version)?;
        let minor_version = header.stated_u32(layout.minor_version)?;
        let bug_check_code = header.stated_u32(layout.bug_check_code)?;
        // An all-zero FILETIME is the field never having been written. Publishing
        // it would put 1601-01-01 in front of an examiner as if it were a fact.
        let system_time = header
            .stated_uint(layout.system_time, 8)?
            .filter(|&t| t != 0);
        let system_up_time = header
            .stated_uint(layout.system_up_time, 8)?
            .filter(|&t| t != 0);
        let comment = ascii_field(header.slice(layout.comment, COMMENT_BYTES)?);
        let pae_enabled = match layout.pae_enabled {
            Some(at) => header.stated_u8(at)?,
            None => None,
        };

        // The architecture is structural: it selects how addresses are read.
        // A filler `MachineImageType` is treated exactly as an unwritten one,
        // which leaves the layout's own pointer width to prove it — the same
        // reading [`CrashHeaderFacts::read`] takes.
        let architecture = architecture_of(&layout, machine_image_type.unwrap_or(0));

        let mut meta = LayerMeta::new(format)
            .with_architecture(architecture)
            .with_note("dump_type", u64::from(dump_type))
            .with_note("dump_kind", kind.as_str())
            .with_note("header_bytes", layout.header_bytes);

        for (key, value) in [
            ("directory_table_base", directory_table_base),
            ("kd_debugger_data_block", kd_debugger_data_block),
            ("pfn_database", pfn_database),
            ("ps_loaded_module_list", ps_loaded_module_list),
            ("ps_active_process_head", ps_active_process_head),
            ("machine_image_type", machine_image_type.map(u64::from)),
            ("number_processors", number_processors.map(u64::from)),
            ("major_version", major_version.map(u64::from)),
            ("minor_version", minor_version.map(u64::from)),
            ("bug_check_code", bug_check_code.map(u64::from)),
            ("system_time_filetime", system_time),
            ("system_up_time_100ns", system_up_time),
            ("pae_enabled", pae_enabled.map(u64::from)),
        ] {
            if let Some(value) = value {
                meta = meta.with_note(key, value);
            }
        }
        if let Some(text) = comment {
            meta = meta.with_note("comment", text);
        }

        // The payload walk publishes its own counts; they are collected rather
        // than written straight into `meta` because `with_note` consumes it.
        let mut counts: Vec<(&'static str, u64)> = Vec::new();
        let segments = match kind {
            CrashDumpKind::Full => full_dump_segments(&layout, &header, &mut counts)?,
            CrashDumpKind::Bitmap | CrashDumpKind::KernelBitmap => {
                bitmap_dump_segments(&layout, source, &mut counts)?
            }
        };
        for (key, value) in counts {
            meta = meta.with_note(key, value);
        }

        // A kernel bitmap's unset bits are not "pages the machine did not
        // hold": they include every user-mode page, which was resident and
        // deliberately not written. The segments already make those addresses
        // holes, but a hole is a statement about this file, and an examiner
        // reading "that string is not in this image" needs to know that no
        // process's private memory was ever a candidate.
        if kind == CrashDumpKind::KernelBitmap {
            meta.push_incomplete(
                IncompleteReason::ShortRead,
                format!(
                    "DumpType {DUMP_TYPE_KERNEL_BITMAP:#x} is a kernel bitmap: only pages owned \
                     by the kernel were written, so user-mode memory is absent from the \
                     acquisition and every user-space address reads as an unacquired hole"
                ),
            );
        }

        if segments.is_empty() {
            return Err(FormatError::malformed(
                format,
                "the dump describes no physical memory at all".to_string(),
            ));
        }

        let declared = segments
            .iter()
            .filter_map(|s| s.memory_end())
            .max()
            .unwrap_or(0);
        meta = meta.with_declared_size(declared);

        // A dump whose payload runs past the end of the file was cut short.
        // The segments keep their declared extents so the discrepancy stays
        // visible and `SegmentedLayer` short-reads at the truncation point.
        let needed = segments
            .iter()
            .filter_map(|s| s.file_end())
            .max()
            .unwrap_or(0);
        let available = source.size();
        if needed > available {
            meta.push_incomplete(
                IncompleteReason::ShortRead,
                format!(
                    "the dump's segments require {needed:#x} bytes of file but the acquisition \
                     holds {available:#x}; the final {:#x} bytes of physical memory were not \
                     written",
                    needed - available
                ),
            );
        }

        Ok(Self {
            format,
            kind,
            architecture,
            directory_table_base,
            kd_debugger_data_block,
            pfn_database,
            ps_loaded_module_list,
            ps_active_process_head,
            machine_image_type,
            number_processors,
            segments,
            meta,
        })
    }

    /// Which of the two header layouts this dump uses.
    pub fn format(&self) -> MemoryImageFormat {
        self.format
    }

    /// Full or bitmap.
    pub fn kind(&self) -> CrashDumpKind {
        self.kind
    }

    /// The architecture the header structure proves. Never inferred from
    /// pointer-shaped values found in memory.
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// `DirectoryTableBase`: the physical address of the page-table root the
    /// kernel was using. Stated by the header, so a consumer never has to run
    /// the self-referential scan that guesses it — and `None` when the header
    /// holds filler there, which is the consumer's cue to scan after all
    /// rather than to trust an invented address.
    pub fn directory_table_base(&self) -> Option<u64> {
        self.directory_table_base
    }

    /// `KdDebuggerDataBlock`: the virtual address of `_KDDEBUGGER_DATA64`, from
    /// which the kernel base and most global lists are reachable. `None` when
    /// the header holds filler there.
    pub fn kd_debugger_data_block(&self) -> Option<u64> {
        self.kd_debugger_data_block
    }

    /// `PfnDataBase`: the virtual address of the PFN database. `None` when the
    /// header holds filler there.
    pub fn pfn_database(&self) -> Option<u64> {
        self.pfn_database
    }

    /// `PsLoadedModuleList`: the head of the loaded-driver list. `None` when
    /// the header holds filler there.
    pub fn ps_loaded_module_list(&self) -> Option<u64> {
        self.ps_loaded_module_list
    }

    /// `PsActiveProcessHead`: the head of the active-process list. `None` when
    /// the header holds filler there.
    pub fn ps_active_process_head(&self) -> Option<u64> {
        self.ps_active_process_head
    }

    /// `MachineImageType`, the `IMAGE_FILE_MACHINE_*` value, or `None` when the
    /// header holds filler there. [`CrashDump::architecture`] is not derived
    /// from this alone and stays available either way.
    pub fn machine_image_type(&self) -> Option<u32> {
        self.machine_image_type
    }

    /// `NumberProcessors`, or `None` when the header holds filler there.
    pub fn number_processors(&self) -> Option<u32> {
        self.number_processors
    }

    /// The physical runs the dump holds, in file order.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Bytes of physical memory the dump holds, summed across runs. Below the
    /// span of the address space whenever the dump is a bitmap.
    pub fn acquired_bytes(&self) -> u64 {
        self.segments
            .iter()
            .fold(0u64, |acc, s| acc.saturating_add(s.length))
    }

    /// Metadata for the layer this dump will become, carrying every pointer
    /// above as a published note.
    pub fn layer_meta(&self) -> &LayerMeta {
        &self.meta
    }

    /// Build the physical address space. `source` must be the same source
    /// [`parse`](CrashDump::parse) read.
    pub fn into_layer(self, source: Arc<dyn DataSource>) -> Result<SegmentedLayer, FormatError> {
        let format = self.format;
        SegmentedLayer::new(source, self.segments, self.meta)
            .map_err(|e| FormatError::layer(format, e))
    }
}

/// Parse `source` as a Windows crash dump and return its physical address space.
pub fn open(source: Arc<dyn DataSource>) -> Result<SegmentedLayer, FormatError> {
    let dump = CrashDump::parse(&*source)?;
    dump.into_layer(source)
}

/// The `EXCEPTION_RECORD64` the kernel wrote for the fault that stopped the
/// machine.
///
/// Every field but `code` is an `Option`, for the reason the rest of
/// [`CrashHeaderFacts`] is: these bytes are header pages the crash writer was
/// handed already stamped with the `PAGE` fill pattern, so a field the kernel
/// had no value for reads back as filler rather than as zero. `code` needs no
/// `Option` because the whole record is published only when it holds a stated,
/// non-zero `ExceptionCode` — an unwritten code means there is no exception
/// here to describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashException {
    /// `ExceptionCode`: the `NTSTATUS` of the fault (`0x80000003` is
    /// `STATUS_BREAKPOINT`).
    pub code: u32,
    /// `ExceptionFlags`, absent when the header holds filler there.
    pub flags: Option<u32>,
    /// `ExceptionAddress`: the virtual address that faulted. A virtual address
    /// and nothing more — a refused dump offers no address space in which to
    /// resolve it to a module.
    ///
    /// Absent when the kernel never wrote it. `0` here would say the faulting
    /// instruction was at a null address, which is a specific and checkable
    /// claim about the crash, so an unwritten field must reach the record as
    /// nothing at all rather than as a number.
    pub address: Option<u64>,
    /// `NumberParameters`, absent when the header holds filler there. A stated
    /// `0` is kept as a stated `0`: it says the fault carried no parameters,
    /// which is not the same as the count never having been written.
    ///
    /// The parameter array itself is not published: it is header filler
    /// whenever this is zero, and reading it would say more than the count
    /// supports.
    pub parameter_count: Option<u32>,
}

/// What a crash dump's `_DUMP_HEADER` states about the crash, whether or not
/// the file behind it can be mapped.
///
/// # Why this exists apart from [`CrashDump`]
///
/// A triage/small dump is refused as an address space, and rightly so — there
/// is no memory in it to map. But the same eight kilobytes of header that fail
/// that test carry the bugcheck code, the moment of the crash, the build and
/// the processor count, all written by the kernel. Before this those fields
/// were read only on the path that succeeds, so an examiner holding a minidump
/// was told "decode failed" about a file that plainly states which bugcheck
/// stopped the machine and when.
///
/// # Why every field is an `Option`
///
/// Windows hands the crash writer header pages already stamped with the `PAGE`
/// fill pattern, so a field the kernel had no value for holds filler rather
/// than zero (see [`is_page_filler`]). `None` therefore means "this file does
/// not state it", which is a different claim from a number, and the difference
/// has to survive to the record.
///
/// # What is deliberately absent
///
/// Everything past the header. A triage dump also holds a driver list, process
/// and thread blocks, a call stack and a data-block table, and they are real
/// and decodable — but no ISF or vendored specification in this tree describes
/// them, so decoding them would be reverse engineering published as evidence.
/// The registers of the faulting context are absent for the same reason; only
/// `ContextFlags` is published, as evidence that the context is present and
/// well-formed — and only for a machine whose CONTEXT layout this file pins,
/// which today is x64 alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashHeaderFacts {
    /// Which of the two header layouts the magic selected.
    pub format: MemoryImageFormat,
    /// The architecture the layout proves.
    pub architecture: Architecture,
    /// `DumpType`, as stated.
    pub dump_type: u32,
    /// The payload layout that `DumpType` selects, or `None` for a dump this
    /// reader will not map.
    pub kind: Option<CrashDumpKind>,
    pub major_version: Option<u32>,
    /// `MinorVersion`, which on modern Windows is the build number.
    pub minor_version: Option<u32>,
    pub machine_image_type: Option<u32>,
    pub number_processors: Option<u32>,
    /// `BugCheckCode`: the numeric stop code, and only the number.
    ///
    /// It is published to be read against Microsoft's bugcheck reference. No
    /// name is attached here: the codes' names are a curated list rather than
    /// anything these bytes state, and a partial table would carry the
    /// authority of a decode while reporting "unknown" for most of the codes
    /// Windows defines.
    pub bug_check_code: Option<u32>,
    /// `BugCheckParameter1..4`, each absent when the header holds filler there.
    pub bug_check_parameters: [Option<u64>; 4],
    pub directory_table_base: Option<u64>,
    pub pfn_database: Option<u64>,
    pub ps_loaded_module_list: Option<u64>,
    pub ps_active_process_head: Option<u64>,
    pub kd_debugger_data_block: Option<u64>,
    /// `SystemTime`: the moment of the crash, as a Windows FILETIME. Absent
    /// when it was never written — publishing an all-zero FILETIME would put
    /// 1601-01-01 in front of an examiner as if it were the crash time.
    pub system_time: Option<u64>,
    /// `SystemUpTime`, in 100 ns units.
    pub system_up_time: Option<u64>,
    /// `Comment`, when it holds text rather than fill pattern.
    pub comment: Option<String>,
    /// `PaeEnabled`, which only the 32-bit layout carries. `None` therefore
    /// covers two cases: a 64-bit header, which has no such field at all, and
    /// a 32-bit header that holds filler there. Neither states the flag, and
    /// the fill byte is `P` — 80, which is not a value a `BOOLEAN` can hold.
    pub pae_enabled: Option<u8>,
    /// The faulting exception, where the layout pins where it sits.
    pub exception: Option<CrashException>,
    /// `ContextFlags` of the faulting processor context.
    ///
    /// Absent unless the header names a machine whose CONTEXT structure this
    /// file pins, which today is x64 alone — see [`Layout::context_flags_at`].
    /// On any other machine the bytes at that offset belong to some other field
    /// of some other structure, and publishing them would be a fabricated
    /// statement about the saved context.
    pub context_flags: Option<u32>,
}

impl CrashHeaderFacts {
    /// Whether the `DumpType` this header states is one that describes a
    /// physical address space this reader can map.
    ///
    /// The record has to carry this next to the crash facts, or a panel showing
    /// a bugcheck code reads as a decoded image.
    ///
    /// It is a statement about the *type*, and only about the type — it is read
    /// from `DumpType` before a single byte of payload is examined. A full dump
    /// whose run table turns out to be malformed is refused by
    /// [`CrashDump::parse`] while this still answers `true`, and the record
    /// then carries both that refusal and this answer. Neither is wrong, but
    /// the pair reads as a contradiction unless the record says which is which,
    /// so [`CrashHeaderFacts::to_json`] publishes the scope of the claim
    /// alongside it.
    pub fn maps_an_address_space(&self) -> bool {
        self.kind.is_some()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "image_format": self.format.as_str(),
            "architecture": self.architecture.as_str(),
            "dump_type": self.dump_type,
            "dump_kind": self.kind.map(CrashDumpKind::as_str),
            "maps_an_address_space": self.maps_an_address_space(),
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "machine_image_type": self.machine_image_type,
            "number_processors": self.number_processors,
            "bug_check_code": self.bug_check_code,
            "bug_check_parameters": self.bug_check_parameters,
            "directory_table_base": self.directory_table_base,
            "pfn_database": self.pfn_database,
            "ps_loaded_module_list": self.ps_loaded_module_list,
            "ps_active_process_head": self.ps_active_process_head,
            "kd_debugger_data_block": self.kd_debugger_data_block,
            "system_time_filetime": self.system_time,
            "system_time": self.system_time.and_then(seance_core::time::filetime_to_rfc3339),
            "system_up_time_100ns": self.system_up_time,
            "comment": self.comment,
            "pae_enabled": self.pae_enabled,
            "exception_code": self.exception.map(|e| e.code),
            // `and_then`, not `map`: a field the exception record does not
            // state is absent from the record here too, exactly as it is on
            // the struct.
            "exception_flags": self.exception.and_then(|e| e.flags),
            "exception_address": self.exception.and_then(|e| e.address),
            "exception_parameter_count": self.exception.and_then(|e| e.parameter_count),
            "context_flags": self.context_flags,
        });

        // Whichever way `maps_an_address_space` came out, the record says in
        // words what that answer is a claim about. The two sentences are
        // mutually exclusive and only one can ever be present: a dump that maps
        // nothing is a triage dump, and a dump that maps something is not.
        if let Some(obj) = value.as_object_mut() {
            match self.kind {
                // The claim is about the type, not about this decode. This
                // block rides on failure records too — a full dump with a
                // malformed run table carries `decode_failed: true` beside
                // `maps_an_address_space: true` — and without this sentence the
                // examiner is left to reconcile the two unaided.
                Some(kind) => {
                    let dump_type = self.dump_type;
                    let name = kind.as_str();
                    obj.insert(
                        "address_space_detail".into(),
                        serde_json::json!(format!(
                            "maps_an_address_space is read from DumpType {dump_type:#x} \
                             ({name}) alone: a dump of that type describes a physical address \
                             space this reader can map. It is not a statement that this file's \
                             payload did decode — where the record also reports a decode \
                             failure, that failure is what happened to this acquisition"
                        )),
                    );
                }
                None => {
                    obj.insert(
                        "triage_detail".into(),
                        serde_json::json!(format!(
                            "{TRIAGE_DETAIL}. The bugcheck record here was read from the \
                             _DUMP_HEADER; the driver, process, thread and call-stack structures \
                             such a dump also carries are not decoded by this build, so nothing \
                             beyond the header is reported"
                        )),
                    );
                }
            }
        }
        value
    }

    /// Read the header of `source` and state what it holds.
    fn read(source: &dyn DataSource) -> Result<Self, FormatError> {
        let (layout, bytes) = read_header(source)?;
        let header = Fields {
            bytes: &bytes,
            format: layout.format,
            structure: "_DUMP_HEADER",
        };
        let width = layout.pointer_bytes;

        let dump_type = header.u32(layout.dump_type)?;
        let machine_image_type = header.stated_u32(layout.machine_image_type)?;

        let mut parameters = [None; 4];
        for (slot, at) in parameters.iter_mut().zip(layout.bug_check_parameters) {
            *slot = header.stated_uint(at, width)?;
        }

        // A zero `ExceptionCode` is not a status code: it is the record never
        // having been written, and an exception block published from it would
        // describe a fault that is not stated anywhere in this file.
        let exception = match layout.exception_record {
            // Prove the whole record is inside the header that was read before
            // reading any field out of it: a partial exception record would be
            // three fields and a fabricated fourth.
            Some(at) => header
                .slice(at, EXCEPTION_RECORD_BYTES)
                .and(header.stated_u32(at + EXCEPTION_CODE))?
                .filter(|&code| code != 0)
                .map(|code| -> Result<CrashException, FormatError> {
                    // Each of these keeps its filler guard all the way out to
                    // the caller. Collapsing an unstated field to zero here
                    // would publish `exception_address: 0` — a NULL-pointer
                    // dereference at the fault site, which is a claim about
                    // this crash that the bytes do not make.
                    Ok(CrashException {
                        code,
                        flags: header.stated_u32(at + EXCEPTION_FLAGS)?,
                        address: header.stated_uint(at + EXCEPTION_ADDRESS, 8)?,
                        parameter_count: header.stated_u32(at + EXCEPTION_PARAMETER_COUNT)?,
                    })
                })
                .transpose()?,
            None => None,
        };

        let context_flags = match layout.context_flags_at(machine_image_type) {
            Some(at) => header.stated_u32(at)?,
            None => None,
        };

        Ok(Self {
            format: layout.format,
            architecture: architecture_of(&layout, machine_image_type.unwrap_or(0)),
            dump_type,
            kind: mappable_kind(dump_type, source, &layout),
            major_version: header.stated_u32(layout.major_version)?,
            minor_version: header.stated_u32(layout.minor_version)?,
            machine_image_type,
            number_processors: header.stated_u32(layout.number_processors)?,
            bug_check_code: header.stated_u32(layout.bug_check_code)?,
            bug_check_parameters: parameters,
            directory_table_base: header.stated_uint(layout.directory_table_base, width)?,
            pfn_database: header.stated_uint(layout.pfn_database, width)?,
            ps_loaded_module_list: header.stated_uint(layout.ps_loaded_module_list, width)?,
            ps_active_process_head: header.stated_uint(layout.ps_active_process_head, width)?,
            kd_debugger_data_block: header.stated_uint(layout.kd_debugger_data_block, width)?,
            system_time: header
                .stated_uint(layout.system_time, 8)?
                .filter(|&t| t != 0),
            system_up_time: header
                .stated_uint(layout.system_up_time, 8)?
                .filter(|&t| t != 0),
            comment: ascii_field(header.slice(layout.comment, COMMENT_BYTES)?),
            pae_enabled: match layout.pae_enabled {
                Some(at) => header.stated_u8(at)?,
                None => None,
            },
            exception,
            context_flags,
        })
    }
}

/// What `source`'s crash-dump header states, for a caller that needs the facts
/// whether or not the file can be mapped.
///
/// `None` means these bytes do not begin a readable `_DUMP_HEADER` — not that a
/// dump states nothing. Callers that must distinguish the two report the
/// distinction themselves, as [`crate::module`] does for hibernation files.
///
/// This is deliberately not folded into [`open`]: a triage dump must keep
/// failing to open, exactly as strictly as it does today. Facts about a crash
/// and an address space to search are different things, and the whole point of
/// the refusal is that the second was never in the file.
pub fn header_facts(source: &dyn DataSource) -> Option<CrashHeaderFacts> {
    CrashHeaderFacts::read(source).ok()
}

/// What a dump this reader will not map actually is, in the words the refusal
/// uses. Held as a constant so the refusal an examiner reads in an error and
/// the `triage_detail` an examiner reads on the record cannot drift apart.
const TRIAGE_DETAIL: &str = "a triage/small dump, a set of bugcheck structures rather than a \
                             physical address space, so there is nothing to map";

/// Read the fixed header of whichever layout `source` announces.
///
/// Split out of [`CrashDump::parse`] so that [`header_facts`] reads exactly the
/// same bytes through exactly the same [`Layout`]. Two independent readers of
/// one structure would drift, and the half that drifted would be the half an
/// examiner sees when a dump cannot be mapped.
fn read_header(source: &dyn DataSource) -> Result<(Layout, Vec<u8>), FormatError> {
    let layout = detect_layout(source)?;
    let mut bytes = vec![0u8; layout.header_bytes as usize];
    read_exact_or_fail(source, 0, &mut bytes, "Windows crash dump header")
        .map_err(|e| FormatError::io(layout.format, "Windows crash dump header", e))?;
    Ok((layout, bytes))
}

/// The payload layout this `DumpType` selects, or `None` for a dump that
/// describes no physical address space this reader can map.
///
/// The decision is shared with [`header_facts`] deliberately: the record must
/// say "no memory was mapped" for exactly the dumps `parse` refuses, never for
/// a wider or narrower set.
fn mappable_kind(
    dump_type: u32,
    source: &dyn DataSource,
    layout: &Layout,
) -> Option<CrashDumpKind> {
    match dump_type {
        DUMP_TYPE_FULL => Some(CrashDumpKind::Full),
        DUMP_TYPE_BITMAP => Some(CrashDumpKind::Bitmap),
        DUMP_TYPE_KERNEL_BITMAP => Some(CrashDumpKind::KernelBitmap),
        // A kernel (0x2) or automatic (0x4) dump on a modern Windows is a
        // `_SUMMARY_DUMP` bitmap of the kernel's pages — the same layout as
        // 0x6. Accept it as a kernel bitmap when the summary is actually
        // there; without it, the dump is a triage/small dump.
        DUMP_TYPE_KERNEL | DUMP_TYPE_AUTOMATIC if has_summary_dump(source, layout) => {
            Some(CrashDumpKind::KernelBitmap)
        }
        _ => None,
    }
}

/// Whether a `DumpType` this reader declined is a triage/small dump rather than
/// a type it simply does not recognise. Only meaningful once
/// [`mappable_kind`] has already returned `None`.
fn is_triage_type(dump_type: u32) -> bool {
    matches!(dump_type, 0x3 | DUMP_TYPE_KERNEL | DUMP_TYPE_AUTOMATIC)
}

/// The header layout already fixes the pointer width, so the only thing
/// `MachineImageType` adds is ARM64 versus x64 inside the 64-bit layout.
/// Nothing else here is inferred from it.
fn architecture_of(layout: &Layout, machine_image_type: u32) -> Architecture {
    match (layout.pointer_bytes, machine_image_type) {
        (8, MACHINE_ARM64) => Architecture::Arm64,
        (8, _) => Architecture::X64,
        _ => Architecture::X86,
    }
}

/// `PAGE` plus `DUMP` or `DU64`, read fail-closed so a source holding only
/// `PAGE` is declined rather than parsed.
fn detect_layout(source: &dyn DataSource) -> Result<Layout, FormatError> {
    let mut magic = [0u8; 8];
    read_exact_or_fail(source, 0, &mut magic, "crash dump magic").map_err(|e| {
        FormatError::io(MemoryImageFormat::WindowsCrashDump64, "crash dump magic", e)
    })?;
    if &magic[0..4] != SIGNATURE {
        return Err(FormatError::not_this(
            MemoryImageFormat::WindowsCrashDump64,
            format!("the first word is {:02x?}, not {SIGNATURE:?}", &magic[0..4]),
        ));
    }
    if &magic[4..8] == LAYOUT_32.valid_dump {
        Ok(LAYOUT_32)
    } else if &magic[4..8] == LAYOUT_64.valid_dump {
        Ok(LAYOUT_64)
    } else {
        Err(FormatError::not_this(
            MemoryImageFormat::WindowsCrashDump64,
            format!(
                "the PAGE signature is followed by {:02x?}, which is neither DUMP nor DU64",
                &magic[4..8]
            ),
        ))
    }
}

/// `DumpType == 0x1`: the runs of `PhysicalMemoryBlockBuffer`, concatenated in
/// list order from the first byte after the header.
fn full_dump_segments(
    layout: &Layout,
    header: &Fields<'_>,
    counts: &mut Vec<(&'static str, u64)>,
) -> Result<Vec<Segment>, FormatError> {
    let descriptor = layout.memory_descriptor;
    let number_of_runs = u64::from(header.u32(descriptor)?);
    let number_of_pages = header.uint(
        descriptor + layout.descriptor_pages,
        layout.descriptor_pages_bytes,
    )?;

    if number_of_runs == 0 {
        return Err(FormatError::malformed(
            layout.format,
            "PhysicalMemoryBlockBuffer declares no runs".to_string(),
        ));
    }
    // The run table lives inside the header, immediately before ContextRecord.
    // A count that would run past it is a corrupt or hostile field, not a dump
    // with unusually many runs.
    if number_of_runs > layout.max_runs() {
        return Err(FormatError::malformed(
            layout.format,
            format!(
                "PhysicalMemoryBlockBuffer declares {number_of_runs} runs, but only {} fit in the \
                 dump header before ContextRecord at {:#x}",
                layout.max_runs(),
                layout.context_record
            ),
        ));
    }

    let entry_bytes = layout.run_field_bytes * 2;
    let table = descriptor + layout.run_array;
    let mut segments = Vec::with_capacity(number_of_runs as usize);
    // Payload pages are laid down in run order starting after the header.
    let mut file_page = layout.header_bytes / PAGE_SIZE;
    let mut run_pages = 0u64;

    for index in 0..number_of_runs as usize {
        let at = table + index * entry_bytes;
        let base_page = header.uint(at, layout.run_field_bytes)?;
        let page_count = header.uint(at + layout.run_field_bytes, layout.run_field_bytes)?;

        if page_count == 0 {
            return Err(FormatError::malformed(
                layout.format,
                format!("run {index} declares zero pages at base page {base_page:#x}"),
            ));
        }
        let memory_offset = base_page.checked_mul(PAGE_SIZE).ok_or_else(|| {
            FormatError::malformed(
                layout.format,
                format!("run {index} base page {base_page:#x} overflows the address space"),
            )
        })?;
        let length = page_count.checked_mul(PAGE_SIZE).ok_or_else(|| {
            FormatError::malformed(
                layout.format,
                format!("run {index} page count {page_count:#x} overflows the address space"),
            )
        })?;
        let file_offset = file_page.checked_mul(PAGE_SIZE).ok_or_else(|| {
            FormatError::malformed(
                layout.format,
                format!("run {index} starts past the end of a 64-bit file"),
            )
        })?;

        segments.push(Segment::new(file_offset, memory_offset, length));
        file_page = file_page.checked_add(page_count).ok_or_else(|| {
            FormatError::malformed(
                layout.format,
                format!("the payload of run {index} runs past the end of a 64-bit file"),
            )
        })?;
        run_pages = run_pages.saturating_add(page_count);
    }

    counts.push(("number_of_runs", number_of_runs));
    counts.push(("physical_memory_pages_declared", number_of_pages));
    counts.push(("physical_memory_pages_in_runs", run_pages));
    Ok(segments)
}

/// `DumpType == 0x5` and `0x6`: `_SUMMARY_DUMP`'s bitmap, one bit per physical
/// page, with only the set pages present in the payload. The two types share
/// this layout exactly; they differ in which pages the kernel chose to set,
/// which is recorded by the caller and not decidable here.
/// Whether a `_SUMMARY_DUMP` (a bitmap-form payload) begins at the summary
/// offset — the presence of its `"SDMP"` signature. Used to tell a modern
/// kernel/automatic dump (which this reader maps) from a triage/small dump of
/// the same `DumpType` (which it cannot). A short read reads as "no summary".
fn has_summary_dump(source: &dyn DataSource, layout: &Layout) -> bool {
    let mut sig = [0u8; 4];
    match source.read_at(layout.header_bytes, &mut sig) {
        Ok(4) => &sig == SUMMARY_SIGNATURE,
        _ => false,
    }
}

fn bitmap_dump_segments(
    layout: &Layout,
    source: &dyn DataSource,
    counts: &mut Vec<(&'static str, u64)>,
) -> Result<Vec<Segment>, FormatError> {
    let summary_at = layout.header_bytes;
    let mut fixed = [0u8; SUMMARY_FIXED_BYTES as usize];
    read_exact_or_fail(source, summary_at, &mut fixed, "_SUMMARY_DUMP")
        .map_err(|e| FormatError::io(layout.format, "_SUMMARY_DUMP", e))?;
    let fixed = Fields {
        bytes: &fixed,
        format: layout.format,
        structure: "_SUMMARY_DUMP",
    };

    // Absolute file offset of the first payload page.
    let data_at = fixed.u64(SUMMARY_HEADER_SIZE)?;
    let declared_pages = fixed.u64(SUMMARY_PAGES)?;
    let bitmap_bits = fixed.u64(SUMMARY_BITMAP_SIZE)?;

    if bitmap_bits == 0 {
        return Err(FormatError::malformed(
            layout.format,
            "_SUMMARY_DUMP declares a zero-length page bitmap".to_string(),
        ));
    }
    let bitmap_at = summary_at + SUMMARY_FIXED_BYTES;
    // `div_ceil`, not `(bits + 7) / 8`: the latter overflows on a hostile
    // `BitmapSize` of `u64::MAX` and wraps to a plausible small allocation.
    let bitmap_bytes = bitmap_bits.div_ceil(8);
    // Three independent bounds on the allocation: the bitmap cannot be larger
    // than the file, it cannot describe more memory than any machine holds, and
    // it must fit between the summary header and the payload it indexes.
    // Without all three, a hostile BitmapSize is an OOM — the file-size bound
    // alone still lets a multi-gigabyte dump allocate and fill a buffer nearly
    // its own size before anything is mapped.
    if bitmap_bytes > source.size() {
        return Err(FormatError::malformed(
            layout.format,
            format!(
                "_SUMMARY_DUMP declares {bitmap_bits} page bits, needing {bitmap_bytes:#x} bytes \
                 of bitmap, more than the whole {:#x}-byte acquisition",
                source.size()
            ),
        ));
    }
    if bitmap_bits > MAX_BITMAP_PAGES {
        return Err(FormatError::malformed(
            layout.format,
            format!(
                "_SUMMARY_DUMP declares {bitmap_bits} page bits, describing {:#x} bytes of \
                 physical address space; the most this reader will map is {MAX_BITMAP_PAGES} \
                 pages ({:#x} bytes), and a larger figure is a corrupt or hostile BitmapSize \
                 rather than a machine",
                bitmap_bits.saturating_mul(PAGE_SIZE),
                MAX_BITMAP_PAGES.saturating_mul(PAGE_SIZE),
            ),
        ));
    }
    if data_at < bitmap_at.saturating_add(bitmap_bytes) {
        return Err(FormatError::malformed(
            layout.format,
            format!(
                "_SUMMARY_DUMP puts the payload at {data_at:#x}, inside the {bitmap_bytes:#x}-byte \
                 page bitmap that begins at {bitmap_at:#x}"
            ),
        ));
    }

    let mut bitmap = vec![0u8; bitmap_bytes as usize];
    read_exact_or_fail(source, bitmap_at, &mut bitmap, "_SUMMARY_DUMP page bitmap")
        .map_err(|e| FormatError::io(layout.format, "_SUMMARY_DUMP page bitmap", e))?;

    let mut segments: Vec<Segment> = Vec::new();
    // Index of the next payload page, i.e. how many set bits have been seen.
    let mut payload_page = 0u64;
    // Start of the run currently being accumulated, if any.
    let mut run_start: Option<(u64, u64)> = None;

    for bit in 0..bitmap_bits {
        let present = bitmap[(bit / 8) as usize] & (1u8 << (bit % 8)) != 0;
        if present {
            if run_start.is_none() {
                run_start = Some((bit, payload_page));
            }
            payload_page += 1;
        } else if let Some((first_bit, first_page)) = run_start.take() {
            push_bitmap_run(
                layout,
                &mut segments,
                first_bit,
                bit - first_bit,
                first_page,
                data_at,
            )?;
        }
    }
    if let Some((first_bit, first_page)) = run_start {
        push_bitmap_run(
            layout,
            &mut segments,
            first_bit,
            bitmap_bits - first_bit,
            first_page,
            data_at,
        )?;
    }

    counts.push(("bitmap_payload_offset", data_at));
    counts.push(("bitmap_size_bits", bitmap_bits));
    counts.push(("bitmap_pages_declared", declared_pages));
    counts.push(("bitmap_pages_present", payload_page));
    Ok(segments)
}

fn push_bitmap_run(
    layout: &Layout,
    segments: &mut Vec<Segment>,
    first_bit: u64,
    pages: u64,
    first_payload_page: u64,
    data_at: u64,
) -> Result<(), FormatError> {
    if segments.len() >= MAX_SEGMENTS {
        return Err(FormatError::layer(
            layout.format,
            LayerError::TooManySegments {
                count: segments.len() + 1,
                cap: MAX_SEGMENTS,
            },
        ));
    }
    let memory_offset = first_bit.checked_mul(PAGE_SIZE).ok_or_else(|| {
        FormatError::malformed(
            layout.format,
            format!("bitmap page {first_bit:#x} overflows the address space"),
        )
    })?;
    let length = pages.checked_mul(PAGE_SIZE).ok_or_else(|| {
        FormatError::malformed(
            layout.format,
            format!("a bitmap run of {pages:#x} pages overflows the address space"),
        )
    })?;
    let file_offset = first_payload_page
        .checked_mul(PAGE_SIZE)
        .and_then(|d| data_at.checked_add(d))
        .ok_or_else(|| {
            FormatError::malformed(
                layout.format,
                format!("the payload of the bitmap run at page {first_bit:#x} overflows the file"),
            )
        })?;
    segments.push(Segment::new(file_offset, memory_offset, length));
    Ok(())
}

/// A structural buffer with fail-closed field access.
///
/// The buffer is always filled by [`read_exact_or_fail`] to the structure's
/// full declared size, so these accessors are never expected to fail; returning
/// a default instead of an error would fabricate a header field, which is the
/// failure mode this whole module exists to avoid.
struct Fields<'a> {
    bytes: &'a [u8],
    format: MemoryImageFormat,
    structure: &'static str,
}

impl Fields<'_> {
    fn u32(&self, at: usize) -> Result<u32, FormatError> {
        u32_at(self.bytes, at, LE).ok_or_else(|| self.past_end(at, 4))
    }

    fn u64(&self, at: usize) -> Result<u64, FormatError> {
        u64_at(self.bytes, at, LE).ok_or_else(|| self.past_end(at, 8))
    }

    fn uint(&self, at: usize, width: usize) -> Result<u64, FormatError> {
        match width {
            4 => self.u32(at).map(u64::from),
            _ => self.u64(at),
        }
    }

    /// The value at `at`, or `None` when those bytes are the header's own fill
    /// pattern rather than something the kernel wrote there. Reporting
    /// `0x45474150` as a number would put an invented figure on the record.
    fn stated_u32(&self, at: usize) -> Result<Option<u32>, FormatError> {
        if is_page_filler(self.slice(at, 4)?) {
            return Ok(None);
        }
        self.u32(at).map(Some)
    }

    /// As [`Fields::stated_u32`], for a one-byte field.
    ///
    /// [`is_page_filler`] compares against the pattern from its start, so this
    /// is only correct for a field whose offset is four-aligned — every
    /// sub-word field this module reads is, because the fill pattern repeats
    /// every four bytes and a byte at an aligned offset is the `P`. A real
    /// `BOOLEAN` cannot hold 0x50 anyway, so nothing legitimate is refused.
    fn stated_u8(&self, at: usize) -> Result<Option<u8>, FormatError> {
        debug_assert_eq!(
            at % 4,
            0,
            "the filler guard reads the pattern from its start"
        );
        let byte = self.slice(at, 1)?;
        if is_page_filler(byte) {
            return Ok(None);
        }
        Ok(Some(byte[0]))
    }

    /// As [`Fields::stated_u32`], for a field of `width` bytes.
    fn stated_uint(&self, at: usize, width: usize) -> Result<Option<u64>, FormatError> {
        if is_page_filler(self.slice(at, width)?) {
            return Ok(None);
        }
        self.uint(at, width).map(Some)
    }

    fn slice(&self, at: usize, len: usize) -> Result<&[u8], FormatError> {
        self.bytes
            .get(at..at.saturating_add(len))
            .ok_or_else(|| self.past_end(at, len))
    }

    fn past_end(&self, at: usize, len: usize) -> FormatError {
        FormatError::malformed(
            self.format,
            format!(
                "{} field at offset {at:#x} ({len} bytes) lies past the end of the {}-byte \
                 structure that was read",
                self.structure,
                self.bytes.len()
            ),
        )
    }
}

/// A NUL-terminated ASCII field, or `None` when it is empty, holds anything
/// that is not printable text, or is nothing but header filler. A `Comment`
/// full of binary noise is not a comment, and publishing a mangled one invites
/// it into a report.
fn ascii_field(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let text = &bytes[..end];
    if text.is_empty() || !text.iter().all(|&b| (0x20..0x7F).contains(&b)) {
        return None;
    }
    // The filler is printable ASCII, which is precisely why it got this far.
    if is_page_filler(text) {
        return None;
    }
    Some(String::from_utf8_lossy(text).into_owned())
}

/// Whether these bytes are nothing but the header's own fill pattern.
///
/// Windows allocates the dump header's pages already stamped with the repeating
/// word `PAGE` (`0x45474150`, the same four bytes as [`SIGNATURE`]) and then
/// writes the `_DUMP_HEADER` fields over it, so a field the kernel had no value
/// for reads back as filler rather than as zero. Nothing distinguishes that
/// from a written value except the pattern itself: `Comment[128]` in both
/// corpus dumps is literally `PAGE` thirty-two times over with no terminator,
/// and it was being published as an examiner-facing comment.
///
/// A real value that happens to be all-`PAGE` is therefore reported as absent.
/// That is the trade this module always makes: an absent field says "the file
/// does not state this", while a filler field published as content is a fact
/// that was never in the evidence.
fn is_page_filler(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let (whole, tail) = bytes.split_at(bytes.len() - bytes.len() % 4);
    whole
        .as_chunks::<4>()
        .0
        .iter()
        .all(|word| word == SIGNATURE)
        && tail == &SIGNATURE[..tail.len()]
}

/// `pub(crate)` so that [`crate::module`]'s tests can build a crash dump
/// without restating the header offsets this file owns: two copies of an
/// offset table is how the copies come to disagree.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `CHAR VersionUser[32]`, the fixed-size field between the bugcheck
    /// parameters and the next named offset in both layouts. No field is read
    /// through it — it is fill pattern in both corpus dumps — but its
    /// documented size is what closes the derivation of where the bugcheck
    /// parameters sit, so it lives here, where that derivation is checked.
    const VERSION_USER_BYTES: usize = 32;

    /// A 64-bit `_DUMP_HEADER` of `dump_type` and nothing behind it — which is
    /// what a triage/small dump looks like to a reader that will not decode
    /// its body.
    pub(crate) fn triage_dump_64(dump_type: u32) -> Vec<u8> {
        dump_header(&LAYOUT_64, dump_type)
    }

    /// A 64-bit full dump that decodes: two physical pages in one run.
    pub(crate) fn full_dump_64() -> Vec<u8> {
        full_dump(&LAYOUT_64, &[(0x0, 2)])
    }
    use crate::layer::{HoleReason, MemoryHole, MemoryLayer};
    use seance_core::data_source::ByteSliceDataSource;
    use std::io;

    fn put_u32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], at: usize, value: u64) {
        buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn source(bytes: Vec<u8>) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(bytes))
    }

    use seance_core::test_support::TruncatedSource;

    /// A source that remembers how far into the file anything reached.
    ///
    /// The scope boundary around the `_TRIAGE_DUMP` body is easier to state as
    /// "those bytes are never read" than as "those bytes are never published",
    /// and the first implies the second.
    #[derive(Debug)]
    struct WatchfulSource {
        bytes: Vec<u8>,
        highest: std::sync::Mutex<u64>,
    }

    impl WatchfulSource {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                highest: std::sync::Mutex::new(0),
            }
        }

        fn highest_byte_read(&self) -> u64 {
            *self
                .highest
                .lock()
                .expect("no test panics while holding this")
        }
    }

    impl DataSource for WatchfulSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let end = offset.saturating_add(buf.len() as u64);
            let mut highest = self
                .highest
                .lock()
                .expect("no test panics while holding this");
            *highest = (*highest).max(end);
            drop(highest);
            let Ok(at) = usize::try_from(offset) else {
                return Ok(0);
            };
            let Some(rest) = self.bytes.get(at..) else {
                return Ok(0);
            };
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            Ok(n)
        }

        fn size(&self) -> u64 {
            self.bytes.len() as u64
        }
    }

    /// A page whose every byte encodes its own file page index, so a test can
    /// prove a read came from the file offset it was meant to.
    fn payload_page(file_page: u64) -> Vec<u8> {
        vec![(file_page % 251) as u8; PAGE_SIZE as usize]
    }

    /// The fixed part of a `_DUMP_HEADER`, populated with the pointers a real
    /// dump states.
    fn dump_header(layout: &Layout, dump_type: u32) -> Vec<u8> {
        let mut h = vec![0u8; layout.header_bytes as usize];
        h[0..4].copy_from_slice(SIGNATURE);
        h[4..8].copy_from_slice(layout.valid_dump);
        put_u32(&mut h, layout.major_version, 15);
        put_u32(&mut h, layout.minor_version, 19041);
        write_uint(
            &mut h,
            layout.directory_table_base,
            layout.pointer_bytes,
            0x1a_b000,
        );
        write_uint(
            &mut h,
            layout.pfn_database,
            layout.pointer_bytes,
            0x8000_1000,
        );
        write_uint(
            &mut h,
            layout.ps_loaded_module_list,
            layout.pointer_bytes,
            0x8000_2000,
        );
        write_uint(
            &mut h,
            layout.ps_active_process_head,
            layout.pointer_bytes,
            0x8000_3000,
        );
        put_u32(
            &mut h,
            layout.machine_image_type,
            if layout.pointer_bytes == 8 {
                0x8664
            } else {
                0x014C
            },
        );
        put_u32(&mut h, layout.number_processors, 8);
        put_u32(&mut h, layout.bug_check_code, 0x0000_00D1);
        write_uint(
            &mut h,
            layout.kd_debugger_data_block,
            layout.pointer_bytes,
            0x8010_0000,
        );
        for (i, at) in layout.bug_check_parameters.iter().enumerate() {
            write_uint(&mut h, *at, layout.pointer_bytes, 0x1000 + i as u64);
        }
        put_u32(&mut h, layout.dump_type, dump_type);
        put_u64(&mut h, layout.system_time, 0x01D9_0000_0000_0000);
        put_u64(&mut h, layout.system_up_time, 12_345_678);
        h[layout.comment..layout.comment + 11].copy_from_slice(b"lab capture");
        if let Some(at) = layout.exception_record {
            put_u32(&mut h, at + EXCEPTION_CODE, 0x8000_0003);
            put_u32(&mut h, at + EXCEPTION_FLAGS, 1);
            put_u64(&mut h, at + EXCEPTION_ADDRESS, 0xFFFF_F804_CE8F_9280);
            put_u32(&mut h, at + EXCEPTION_PARAMETER_COUNT, 0);
        }
        if let Some(at) = layout.context_flags {
            put_u32(&mut h, layout.context_record + at, 0x0010_000F);
        }
        h
    }

    fn write_uint(buf: &mut [u8], at: usize, width: usize, value: u64) {
        if width == 4 {
            put_u32(buf, at, value as u32);
        } else {
            put_u64(buf, at, value);
        }
    }

    /// A full dump: `(base_page, page_count)` runs plus their payload pages.
    fn full_dump(layout: &Layout, runs: &[(u64, u64)]) -> Vec<u8> {
        let mut file = dump_header(layout, DUMP_TYPE_FULL);
        let descriptor = layout.memory_descriptor;
        put_u32(&mut file, descriptor, runs.len() as u32);
        let total: u64 = runs.iter().map(|r| r.1).sum();
        write_uint(
            &mut file,
            descriptor + layout.descriptor_pages,
            layout.descriptor_pages_bytes,
            total,
        );
        let table = descriptor + layout.run_array;
        for (i, &(base, count)) in runs.iter().enumerate() {
            let at = table + i * layout.run_field_bytes * 2;
            write_uint(&mut file, at, layout.run_field_bytes, base);
            write_uint(
                &mut file,
                at + layout.run_field_bytes,
                layout.run_field_bytes,
                count,
            );
        }
        let mut file_page = layout.header_bytes / PAGE_SIZE;
        for &(_, count) in runs {
            for _ in 0..count {
                file.extend_from_slice(&payload_page(file_page));
                file_page += 1;
            }
        }
        file
    }

    /// A bitmap dump: one bit per physical page, payload holding only the set
    /// ones. The payload begins one page past the end of the bitmap.
    fn bitmap_dump(layout: &Layout, present: &[bool]) -> Vec<u8> {
        let mut file = dump_header(layout, DUMP_TYPE_BITMAP);
        let summary_at = layout.header_bytes as usize;
        let bitmap_at = summary_at + SUMMARY_FIXED_BYTES as usize;
        let bitmap_bytes = present.len().div_ceil(8);
        // Round the payload start up to the next page, as a real dump does.
        let data_at = (((bitmap_at + bitmap_bytes) as u64 / PAGE_SIZE) + 1) * PAGE_SIZE;

        let mut summary = vec![0u8; (data_at as usize) - summary_at];
        summary[0..4].copy_from_slice(SIGNATURE);
        summary[4..8].copy_from_slice(layout.valid_dump);
        put_u64(&mut summary, SUMMARY_HEADER_SIZE, data_at);
        put_u64(
            &mut summary,
            SUMMARY_PAGES,
            present.iter().filter(|p| **p).count() as u64,
        );
        put_u64(&mut summary, SUMMARY_BITMAP_SIZE, present.len() as u64);
        for (bit, &set) in present.iter().enumerate() {
            if set {
                summary[SUMMARY_FIXED_BYTES as usize + bit / 8] |= 1u8 << (bit % 8);
            }
        }
        file.extend_from_slice(&summary);

        let mut file_page = data_at / PAGE_SIZE;
        for &set in present {
            if set {
                file.extend_from_slice(&payload_page(file_page));
                file_page += 1;
            }
        }
        file
    }

    // ── Valid images: full dumps ────────────────────────────────────────────

    #[test]
    fn a_valid_64_bit_full_dump_reads_back_at_its_physical_addresses() {
        // Two runs with an unacquired range between them, exactly as a machine
        // with a PCI hole produces.
        let bytes = full_dump(&LAYOUT_64, &[(0x0, 2), (0x10, 3)]);
        let parsed = CrashDump::parse(&*source(bytes.clone())).expect("a well-formed dump");

        assert_eq!(parsed.format(), MemoryImageFormat::WindowsCrashDump64);
        assert_eq!(parsed.kind(), CrashDumpKind::Full);
        assert_eq!(parsed.architecture(), Architecture::X64);
        assert_eq!(parsed.segments().len(), 2);
        assert_eq!(parsed.acquired_bytes(), 5 * PAGE_SIZE);

        let layer = open(source(bytes)).unwrap();
        assert_eq!(layer.min_address(), 0);
        assert_eq!(layer.max_address(), 0x13 * PAGE_SIZE - 1);
        assert_eq!(layer.mapped_len(), 5 * PAGE_SIZE);

        // The payload begins after two header pages, so physical page 0 is file
        // page 2 and physical page 0x10 is file page 4.
        let mut page = vec![0u8; PAGE_SIZE as usize];
        layer.read_at(0, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 2));
        layer.read_at(0x10 * PAGE_SIZE, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 4));
    }

    #[test]
    fn a_valid_32_bit_full_dump_uses_the_32_bit_field_offsets() {
        let bytes = full_dump(&LAYOUT_32, &[(0x0, 4)]);
        let parsed = CrashDump::parse(&*source(bytes.clone())).expect("a well-formed dump");

        assert_eq!(parsed.format(), MemoryImageFormat::WindowsCrashDump32);
        assert_eq!(parsed.architecture(), Architecture::X86);
        assert_eq!(parsed.directory_table_base(), Some(0x1a_b000));
        assert_eq!(parsed.kd_debugger_data_block(), Some(0x8010_0000));
        assert_eq!(parsed.machine_image_type(), Some(0x014C));

        // One header page, so physical page 0 is file page 1.
        let layer = open(source(bytes)).unwrap();
        let mut page = vec![0u8; PAGE_SIZE as usize];
        layer.read_at(0, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 1));
    }

    #[test]
    fn the_kernel_pointers_the_header_states_are_published_for_later_phases() {
        // The whole reason crash dumps are the Windows bring-up format: these
        // are stated, not scanned for.
        let parsed = CrashDump::parse(&*source(full_dump(&LAYOUT_64, &[(0, 4)]))).unwrap();

        assert_eq!(parsed.directory_table_base(), Some(0x1a_b000));
        assert_eq!(parsed.kd_debugger_data_block(), Some(0x8010_0000));
        assert_eq!(parsed.pfn_database(), Some(0x8000_1000));
        assert_eq!(parsed.ps_loaded_module_list(), Some(0x8000_2000));
        assert_eq!(parsed.ps_active_process_head(), Some(0x8000_3000));
        assert_eq!(parsed.number_processors(), Some(8));

        let json = parsed.layer_meta().to_json();
        assert_eq!(json["architecture"], "x64");
        assert_eq!(json["notes"]["directory_table_base"], 0x1a_b000);
        assert_eq!(json["notes"]["kd_debugger_data_block"], 0x8010_0000u64);
        assert_eq!(json["notes"]["ps_active_process_head"], 0x8000_3000u64);
        assert_eq!(json["notes"]["dump_kind"], "full");
        assert_eq!(json["notes"]["number_of_runs"], 1);
        assert_eq!(json["notes"]["comment"], "lab capture");
        assert_eq!(
            json["notes"]["system_time_filetime"],
            0x01D9_0000_0000_0000u64
        );
        // And the metadata is reachable through the layer, which is where the
        // profiler will look for it.
        let layer = open(source(full_dump(&LAYOUT_64, &[(0, 4)]))).unwrap();
        assert_eq!(
            layer.layer_meta().note("directory_table_base"),
            Some(&serde_json::json!(0x1a_b000u64))
        );
    }

    #[test]
    fn an_arm64_machine_type_is_taken_from_the_header_not_guessed() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 2)]);
        put_u32(&mut bytes, LAYOUT_64.machine_image_type, MACHINE_ARM64);
        let parsed = CrashDump::parse(&*source(bytes)).unwrap();
        assert_eq!(parsed.architecture(), Architecture::Arm64);
        assert_eq!(parsed.layer_meta().to_json()["architecture"], "arm64");
    }

    #[test]
    fn a_zeroed_system_time_is_absent_rather_than_published_as_1601() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 2)]);
        put_u64(&mut bytes, LAYOUT_64.system_time, 0);
        put_u64(&mut bytes, LAYOUT_64.system_up_time, 0);
        let parsed = CrashDump::parse(&*source(bytes)).unwrap();
        let json = parsed.layer_meta().to_json();
        assert!(json["notes"].get("system_time_filetime").is_none());
        assert!(json["notes"].get("system_up_time_100ns").is_none());
    }

    #[test]
    fn a_binary_comment_field_is_not_published_as_text() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 2)]);
        bytes[LAYOUT_64.comment..LAYOUT_64.comment + 4].copy_from_slice(&[0xFF, 0x01, 0x80, 0x7F]);
        let parsed = CrashDump::parse(&*source(bytes)).unwrap();
        assert!(parsed.layer_meta().to_json()["notes"]
            .get("comment")
            .is_none());
    }

    #[test]
    fn the_gap_between_runs_is_a_hole_and_never_zeros() {
        let layer = open(source(full_dump(&LAYOUT_64, &[(0x0, 2), (0x10, 2)]))).unwrap();
        let mut buf = vec![0xEEu8; 0x100];
        let err = layer
            .read_at(2 * PAGE_SIZE, &mut buf)
            .expect_err("physical memory the dump omitted must not read as zeros");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!(hole.address, 2 * PAGE_SIZE);
        assert_eq!(hole.length, 14 * PAGE_SIZE);
        assert_eq!(hole.reason, HoleReason::Unmapped);
        assert!(buf.iter().all(|&b| b == 0xEE));
    }

    // ── Valid images: bitmap dumps ──────────────────────────────────────────

    #[test]
    fn a_valid_bitmap_dump_maps_only_the_pages_whose_bit_is_set() {
        // Pages 0,1 present; 2,3 absent; 4 present; 5..7 absent; 8,9 present.
        let present = [
            true, true, false, false, true, false, false, false, true, true,
        ];
        let bytes = bitmap_dump(&LAYOUT_64, &present);
        let parsed = CrashDump::parse(&*source(bytes.clone())).expect("a well-formed bitmap dump");

        assert_eq!(parsed.kind(), CrashDumpKind::Bitmap);
        assert_eq!(parsed.segments().len(), 3, "three runs of set bits");
        assert_eq!(parsed.acquired_bytes(), 5 * PAGE_SIZE);

        let layer = open(source(bytes)).unwrap();
        assert_eq!(
            layer.size(),
            10 * PAGE_SIZE,
            "the span, not the acquired bytes"
        );
        assert_eq!(layer.mapped_len(), 5 * PAGE_SIZE);

        // Payload pages are packed in bit order, so physical page 4 is the third
        // page of the payload, not the fifth.
        let data_page = parsed
            .layer_meta()
            .note("bitmap_payload_offset")
            .unwrap()
            .as_u64()
            .unwrap()
            / PAGE_SIZE;
        let mut page = vec![0u8; PAGE_SIZE as usize];
        layer.read_at(4 * PAGE_SIZE, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == ((data_page + 2) % 251) as u8));
        layer.read_at(9 * PAGE_SIZE, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == ((data_page + 4) % 251) as u8));
    }

    #[test]
    fn an_absent_bitmap_page_is_a_hole_not_a_zeroed_page() {
        let present = [true, false, true];
        let layer = open(source(bitmap_dump(&LAYOUT_64, &present))).unwrap();
        let mut page = vec![0x5Au8; PAGE_SIZE as usize];
        let err = layer
            .read_at(PAGE_SIZE, &mut page)
            .expect_err("a page the bitmap says was not captured must not read as zeros");
        let hole = MemoryHole::from_io(&err).unwrap();
        assert_eq!((hole.address, hole.length), (PAGE_SIZE, PAGE_SIZE));
        assert!(page.iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn a_bitmap_run_spanning_a_byte_boundary_is_one_segment() {
        // Bits 3..12 set: an off-by-one in the bit walk splits this into two
        // runs or shifts the payload page, and both are invisible unless the
        // payload bytes differ.
        let mut present = [false; 16];
        for slot in present.iter_mut().take(13).skip(3) {
            *slot = true;
        }
        let bytes = bitmap_dump(&LAYOUT_64, &present);
        let parsed = CrashDump::parse(&*source(bytes.clone())).unwrap();
        assert_eq!(parsed.segments().len(), 1);
        assert_eq!(parsed.segments()[0].memory_offset, 3 * PAGE_SIZE);
        assert_eq!(parsed.segments()[0].length, 10 * PAGE_SIZE);

        let layer = open(source(bytes)).unwrap();
        let data_page = parsed
            .layer_meta()
            .note("bitmap_payload_offset")
            .unwrap()
            .as_u64()
            .unwrap()
            / PAGE_SIZE;
        let mut page = vec![0u8; PAGE_SIZE as usize];
        layer.read_at(12 * PAGE_SIZE, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == ((data_page + 9) % 251) as u8));
    }

    #[test]
    fn a_bitmap_whose_last_bit_is_set_does_not_over_claim_the_trailing_bits() {
        // 10 bits in a 2-byte bitmap: bits 10..15 exist in the byte but not in
        // the bitmap, and a walk that iterates whole bytes invents six pages.
        let present = [
            false, false, false, false, false, false, false, false, true, true,
        ];
        let parsed = CrashDump::parse(&*source(bitmap_dump(&LAYOUT_64, &present))).unwrap();
        assert_eq!(parsed.segments().len(), 1);
        assert_eq!(parsed.segments()[0].memory_offset, 8 * PAGE_SIZE);
        assert_eq!(parsed.segments()[0].length, 2 * PAGE_SIZE, "not 8 pages");
        assert_eq!(parsed.acquired_bytes(), 2 * PAGE_SIZE);
    }

    #[test]
    fn a_kernel_bitmap_dump_opens_and_says_that_user_memory_was_never_written() {
        // DumpType 0x6 is what Task Manager's live kernel dump writes, and it is
        // on-disk identical to 0x5. Refusing it left an examiner with "found,
        // cannot open" for an image that decodes perfectly well — but decoding
        // it silently would present a kernel-only address space as the machine.
        let mut bytes = bitmap_dump(&LAYOUT_64, &[true, false, true, true]);
        put_u32(&mut bytes, LAYOUT_64.dump_type, DUMP_TYPE_KERNEL_BITMAP);

        let parsed = CrashDump::parse(&*source(bytes.clone())).expect("the 0x5 layout, decoded");
        assert_eq!(parsed.kind(), CrashDumpKind::KernelBitmap);
        assert_eq!(parsed.kind().dump_type(), DUMP_TYPE_KERNEL_BITMAP);
        assert_eq!(parsed.segments().len(), 2, "two runs of set bits");
        assert_eq!(parsed.acquired_bytes(), 3 * PAGE_SIZE);

        let json = parsed.layer_meta().to_json();
        assert_eq!(json["notes"]["dump_kind"], "kernel_bitmap");
        assert_eq!(json["notes"]["dump_type"], 6);

        // The scope of the acquisition is the whole point of keeping 0x6 apart
        // from 0x5: user-mode pages were resident and deliberately not written.
        let incomplete = parsed.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::ShortRead);
        assert!(incomplete[0].detail.contains("kernel bitmap"));
        assert!(incomplete[0].detail.contains("user-mode memory"));

        // And it really opens, with the payload packed in bit order as for 0x5.
        let layer = open(source(bytes)).unwrap();
        assert_eq!(layer.mapped_len(), 3 * PAGE_SIZE);
        assert_eq!(
            layer.size(),
            4 * PAGE_SIZE,
            "the span, not the acquired bytes"
        );
    }

    #[test]
    fn a_kernel_or_automatic_dump_with_a_summary_reads_as_a_kernel_bitmap() {
        // 0x2 (kernel) and 0x4 (automatic) modern dumps carry the same
        // _SUMMARY_DUMP bitmap as 0x6; the reader keys the modern layout on the
        // "SDMP" signature and treats them as kernel-only.
        for dump_type in [DUMP_TYPE_KERNEL, DUMP_TYPE_AUTOMATIC] {
            let present = [true, false, true, true];
            let mut bytes = bitmap_dump(&LAYOUT_64, &present);
            put_u32(&mut bytes, LAYOUT_64.dump_type, dump_type);
            let sig_at = LAYOUT_64.header_bytes as usize;
            bytes[sig_at..sig_at + 4].copy_from_slice(SUMMARY_SIGNATURE);

            let parsed = CrashDump::parse(&*source(bytes.clone())).unwrap_or_else(|e| {
                panic!("DumpType {dump_type:#x} with a summary must parse: {e}")
            });
            let json = parsed.layer_meta().to_json();
            assert_eq!(json["notes"]["dump_kind"], "kernel_bitmap");
            assert_eq!(json["notes"]["dump_type"], dump_type);
            assert!(parsed
                .layer_meta()
                .incomplete()
                .iter()
                .any(|i| i.detail.contains("kernel bitmap")));
            assert_eq!(open(source(bytes)).unwrap().mapped_len(), 3 * PAGE_SIZE);
        }
    }

    #[test]
    fn a_bitmap_dump_publishes_its_declared_and_counted_page_totals() {
        let present = [true, false, true, true];
        let parsed = CrashDump::parse(&*source(bitmap_dump(&LAYOUT_64, &present))).unwrap();
        let json = parsed.layer_meta().to_json();
        assert_eq!(json["notes"]["bitmap_size_bits"], 4);
        assert_eq!(json["notes"]["bitmap_pages_declared"], 3);
        assert_eq!(json["notes"]["bitmap_pages_present"], 3);
        assert_eq!(json["notes"]["dump_kind"], "bitmap");
    }

    // ── Truncated dumps ─────────────────────────────────────────────────────

    #[test]
    fn a_dump_cut_short_mid_payload_is_flagged_incomplete_and_reads_short() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 4)]);
        bytes.truncate(bytes.len() - PAGE_SIZE as usize - 0x800);

        let parsed = CrashDump::parse(&*source(bytes.clone())).expect("the header is intact");
        assert_eq!(
            parsed.segments()[0].length,
            4 * PAGE_SIZE,
            "declared, not trimmed"
        );
        let incomplete = parsed.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::ShortRead);
        assert!(incomplete[0].detail.contains("were not written"));

        let layer = open(source(bytes)).unwrap();
        let mut buf = vec![0u8; 4 * PAGE_SIZE as usize];
        let got = layer.read_at(0, &mut buf).unwrap();
        assert_eq!(got as u64, 3 * PAGE_SIZE - 0x800, "the honest count");
    }

    #[test]
    fn a_header_shorter_than_the_layout_declares_fails_closed() {
        // A 64-bit dump needs two header pages. One page of it is not a dump.
        let bytes = full_dump(&LAYOUT_64, &[(0, 1)])[..0x1800].to_vec();
        let err = CrashDump::parse(&*source(bytes)).expect_err("must not parse a padded header");
        match err {
            FormatError::Io { ref source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof)
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_bitmap_dump_missing_its_summary_header_fails_closed() {
        let bytes = bitmap_dump(&LAYOUT_64, &[true, true, true])[..0x2010].to_vec();
        let err = CrashDump::parse(&*source(bytes)).expect_err("no _SUMMARY_DUMP");
        assert!(matches!(
            err,
            FormatError::Io { .. } | FormatError::Malformed { .. }
        ));
    }

    #[test]
    fn a_bitmap_dump_missing_its_bitmap_fails_closed_rather_than_reading_zeros() {
        // Truncating inside the bitmap would otherwise be read as "no pages are
        // present", producing an empty address space that looks like a valid
        // sparse dump.
        let full = bitmap_dump(&LAYOUT_64, &[true; 64]);
        let bytes = full[..0x2000 + SUMMARY_FIXED_BYTES as usize + 4].to_vec();
        let err = CrashDump::parse(&*source(bytes)).expect_err("the bitmap is not all there");
        assert!(matches!(err, FormatError::Io { .. }));
    }

    #[test]
    fn a_source_shorter_than_the_magic_is_declined() {
        let err = CrashDump::parse(&*source(b"PAGE".to_vec())).expect_err("not enough bytes");
        match err {
            FormatError::Io { ref source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof)
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    // ── Malformed headers ───────────────────────────────────────────────────

    #[test]
    fn a_foreign_signature_is_declined_rather_than_reported_as_damage() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 1)]);
        bytes[0..4].copy_from_slice(b"ELF\x7f");
        let err = CrashDump::parse(&*source(bytes)).expect_err("not a crash dump");
        assert!(err.is_not_this_format());
    }

    #[test]
    fn a_page_signature_with_an_unknown_dump_word_is_not_claimed() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 1)]);
        bytes[4..8].copy_from_slice(b"XXXX");
        let err = CrashDump::parse(&*source(bytes)).expect_err("neither DUMP nor DU64");
        assert!(err.is_not_this_format());
    }

    #[test]
    fn unsupported_dump_types_fail_closed_with_the_type_named() {
        // With no _SUMMARY_DUMP present (these bytes carry a run list), a small
        // (0x3), kernel (0x2) or automatic (0x4) dump is a triage dump with no
        // mappable address space, and 0x0/0xFFFFFFFF are unknown. A partial or
        // absent address space that reads as complete would be worse than no
        // answer. (0x2/0x4 *with* a summary are decoded — see the test above;
        // 0x6 is the 0x5 layout with kernel-only scope recorded.)
        for dump_type in [0x0u32, 0x2, 0x3, 0x4, 0xFFFF_FFFF] {
            let mut bytes = full_dump(&LAYOUT_64, &[(0, 1)]);
            put_u32(&mut bytes, LAYOUT_64.dump_type, dump_type);
            let err = match CrashDump::parse(&*source(bytes)) {
                Ok(_) => panic!("DumpType {dump_type:#x} must not parse"),
                Err(e) => e,
            };
            assert!(matches!(err, FormatError::Unsupported { .. }));
            assert!(err.to_string().contains(&format!("{dump_type:#x}")));
        }
    }

    #[test]
    fn a_run_count_that_cannot_fit_in_the_header_is_refused() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 1)]);
        put_u32(&mut bytes, LAYOUT_64.memory_descriptor, 0xFFFF_FFFF);
        let err = CrashDump::parse(&*source(bytes)).expect_err("a hostile run count");
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert!(err.to_string().contains("ContextRecord"));
    }

    #[test]
    fn a_dump_declaring_no_runs_is_refused() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 1)]);
        put_u32(&mut bytes, LAYOUT_64.memory_descriptor, 0);
        let err = CrashDump::parse(&*source(bytes)).expect_err("no runs");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn a_zero_length_run_is_refused_rather_than_silently_dropped() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 1), (4, 1)]);
        let at = LAYOUT_64.memory_descriptor + LAYOUT_64.run_array + LAYOUT_64.run_field_bytes;
        put_u64(&mut bytes, at, 0);
        let err = CrashDump::parse(&*source(bytes)).expect_err("a run of no pages");
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert!(err.to_string().contains("zero pages"));
    }

    #[test]
    fn run_extents_that_overflow_the_address_space_do_not_panic() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0, 1)]);
        let table = LAYOUT_64.memory_descriptor + LAYOUT_64.run_array;
        put_u64(&mut bytes, table, u64::MAX);
        let err = CrashDump::parse(&*source(bytes)).expect_err("base page overflows");
        assert!(matches!(err, FormatError::Malformed { .. }));

        let mut bytes = full_dump(&LAYOUT_64, &[(0, 1)]);
        put_u64(&mut bytes, table + LAYOUT_64.run_field_bytes, u64::MAX);
        let err = CrashDump::parse(&*source(bytes)).expect_err("page count overflows");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn runs_that_claim_the_same_physical_address_are_refused_by_the_layer() {
        let bytes = full_dump(&LAYOUT_64, &[(0, 4), (2, 4)]);
        let err = open(source(bytes)).expect_err("two runs cannot hold one address");
        assert!(matches!(err, FormatError::Layer { .. }));
    }

    #[test]
    fn a_bitmap_that_would_overlap_the_payload_is_refused() {
        let mut bytes = bitmap_dump(&LAYOUT_64, &[true, true, true]);
        // Claim a bitmap that still fits in the file but runs past the payload
        // offset the summary header itself declares.
        put_u64(&mut bytes, 0x2000 + SUMMARY_BITMAP_SIZE, 0x1_0000);
        let err = CrashDump::parse(&*source(bytes)).expect_err("the bitmap does not fit");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn a_hostile_bitmap_size_does_not_allocate() {
        let mut bytes = bitmap_dump(&LAYOUT_64, &[true, true, true]);
        put_u64(&mut bytes, 0x2000 + SUMMARY_BITMAP_SIZE, u64::MAX);
        let err =
            CrashDump::parse(&*source(bytes)).expect_err("no allocation from a hostile field");
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert!(err.to_string().contains("more than the whole"));
    }

    #[test]
    fn a_page_bitmap_larger_than_any_real_machine_is_refused_before_it_is_allocated() {
        // The file-size bound is not a bound: on a multi-gigabyte acquisition a
        // BitmapSize that sits under it still forces a near-file-sized buffer
        // and an 8x-file-size bit walk. Here the source reports 512 GiB, so the
        // file-size bound cannot be what refuses this, and the payload offset is
        // moved past the declared bitmap so the overlap bound cannot be either.
        let mut bytes = bitmap_dump(&LAYOUT_64, &[true, true, true]);
        put_u64(&mut bytes, 0x2000 + SUMMARY_HEADER_SIZE, 0x2000_0000);
        put_u64(
            &mut bytes,
            0x2000 + SUMMARY_BITMAP_SIZE,
            MAX_BITMAP_PAGES + 1,
        );
        let src = TruncatedSource::new(bytes, 512 << 30);
        let err = CrashDump::parse(&src).expect_err("no machine holds that many pages");
        assert!(matches!(err, FormatError::Malformed { .. }));
        let text = err.to_string();
        assert!(text.contains(&(MAX_BITMAP_PAGES + 1).to_string()));
    }

    #[test]
    fn a_zero_length_bitmap_is_refused() {
        let mut bytes = bitmap_dump(&LAYOUT_64, &[true, true, true]);
        put_u64(&mut bytes, 0x2000 + SUMMARY_BITMAP_SIZE, 0);
        let err = CrashDump::parse(&*source(bytes)).expect_err("a bitmap of no pages");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn a_bitmap_with_no_page_set_describes_no_memory_and_is_refused() {
        let err = CrashDump::parse(&*source(bitmap_dump(&LAYOUT_64, &[false; 16])))
            .expect_err("an address space with nothing in it is not an address space");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn the_run_table_bound_matches_what_the_header_can_physically_hold() {
        // Guards the constants: the run table sits between the descriptor and
        // ContextRecord, and both layouts must agree with their ISF offsets.
        assert_eq!(LAYOUT_32.max_runs(), (800 - 108) / 8);
        assert_eq!(LAYOUT_64.max_runs(), (840 - 152) / 16);
        assert_eq!(LAYOUT_32.header_bytes, 0x1000);
        assert_eq!(LAYOUT_64.header_bytes, 0x2000);
    }

    // ── The refusal, and the facts that now survive it ──────────────────────

    /// The safety property the header-facts work must not weaken.
    ///
    /// Reading a triage dump's header is not the same thing as being able to
    /// map it, and the moment those two are confused an examiner is handed an
    /// address space assembled out of a bugcheck record. A small dump (`0x3`)
    /// and an automatic dump with no `_SUMMARY_DUMP` behind it must both still
    /// be refused, in the words the refusal already uses.
    #[test]
    fn a_triage_dump_is_still_refused_as_an_address_space_even_though_its_header_is_read() {
        for dump_type in [0x3u32, DUMP_TYPE_KERNEL, DUMP_TYPE_AUTOMATIC] {
            let bytes = dump_header(&LAYOUT_64, dump_type);
            let err = match CrashDump::parse(&*source(bytes)) {
                Ok(_) => panic!("DumpType {dump_type:#x} carries no address space to map"),
                Err(e) => e,
            };
            assert!(matches!(err, FormatError::Unsupported { .. }));
            let text = err.to_string();
            assert!(
                text.contains("triage/small dump"),
                "the refusal must name what the file is, got: {text}"
            );
            assert!(
                text.contains("nothing to map"),
                "the refusal must say plainly that no memory was offered, got: {text}"
            );
        }
    }

    /// The `PAGE` filler is not a comment.
    ///
    /// Windows pre-fills the header pages with the repeating word `PAGE` and
    /// writes the structure over it, so `Comment[128]` in a dump the kernel
    /// never wrote a comment into reads back as `PAGEPAGEPAGE…`. Both corpus
    /// dumps are exactly that, and this decodes today, so the layer of a real
    /// acquisition was carrying an invented comment on its record.
    #[test]
    fn page_filler_is_never_published_as_a_comment() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0x0, 2)]);
        let at = LAYOUT_64.comment;
        bytes[at..at + COMMENT_BYTES].copy_from_slice(&SIGNATURE.repeat(COMMENT_BYTES / 4));
        let parsed = CrashDump::parse(&*source(bytes)).expect("a well-formed dump");
        let notes = parsed.layer_meta().to_json();
        assert!(
            notes.to_string().find("PAGEPAGE").is_none(),
            "header filler must never reach the record as content: {notes}"
        );
    }

    /// The offsets of `BugCheckParameter1..4` were derived, not looked up, so
    /// the derivation is the test: they must start one pointer past
    /// `BugCheckCode` and, with the documented `CHAR VersionUser[32]` behind
    /// them, end exactly where the next named field begins. If someone edits
    /// one of these constants without the other, this arithmetic stops closing.
    #[test]
    fn the_bugcheck_parameter_offsets_close_between_bugcheckcode_and_the_next_named_field() {
        for layout in [&LAYOUT_32, &LAYOUT_64] {
            let width = layout.pointer_bytes;
            // `BugCheckCode` is a ULONG; the parameters that follow it are
            // ULONG_PTR and therefore naturally aligned, which on 64-bit puts
            // four bytes of padding between the two.
            assert_eq!(
                layout.bug_check_parameters[0],
                (layout.bug_check_code + 4).next_multiple_of(width)
            );
            for i in 1..4 {
                assert_eq!(
                    layout.bug_check_parameters[i],
                    layout.bug_check_parameters[i - 1] + width
                );
            }
        }
        assert_eq!(
            LAYOUT_64.bug_check_parameters[3] + 8 + VERSION_USER_BYTES,
            LAYOUT_64.kd_debugger_data_block
        );
        assert_eq!(
            LAYOUT_32.bug_check_parameters[3] + 4 + VERSION_USER_BYTES,
            LAYOUT_32
                .pae_enabled
                .expect("the 32-bit layout carries PaeEnabled")
        );
    }

    /// `Exception` was derived the same way: it is the gap between the end of
    /// the x64 `CONTEXT` and `DumpType`, and that gap is exactly one
    /// `EXCEPTION_RECORD64`. The 32-bit equivalent stays absent because the
    /// same arithmetic needs a `sizeof(CONTEXT)` for x86 that nothing here
    /// pins.
    #[test]
    fn the_exception_record_fills_the_gap_between_the_context_record_and_dumptype() {
        assert_eq!(
            LAYOUT_64.exception_record,
            Some(LAYOUT_64.context_record + CONTEXT_AMD64_BYTES)
        );
        assert_eq!(
            LAYOUT_64.exception_record.unwrap() + EXCEPTION_RECORD_BYTES,
            LAYOUT_64.dump_type
        );
        assert_eq!(LAYOUT_32.exception_record, None);
        assert_eq!(LAYOUT_32.context_flags, None);
    }

    /// The finding itself: a dump that cannot be mapped still states which
    /// bugcheck stopped the machine, when, and on what build. Before this, the
    /// header was parsed only on the path that maps memory, so a refused dump
    /// told an examiner nothing but "decode failed".
    #[test]
    fn a_triage_dump_publishes_its_bugcheck_code_and_four_parameters() {
        let facts = header_facts(&*source(dump_header(&LAYOUT_64, 0x3)))
            .expect("the header is a _DUMP_HEADER whether or not it can be mapped");

        assert!(
            !facts.maps_an_address_space(),
            "reading the header must not make a triage dump mappable"
        );
        assert_eq!(facts.bug_check_code, Some(0xD1));
        assert_eq!(
            facts.bug_check_parameters,
            [Some(0x1000), Some(0x1001), Some(0x1002), Some(0x1003)]
        );

        let json = facts.to_json();
        assert_eq!(json["dump_type"], 0x3);
        assert_eq!(json["maps_an_address_space"], false);
        assert_eq!(json["minor_version"], 19041);
        assert_eq!(json["number_processors"], 8);
        assert_eq!(json["directory_table_base"], 0x1a_b000);
        assert_eq!(json["machine_image_type"], 0x8664);
        assert_eq!(json["system_time_filetime"], 0x01D9_0000_0000_0000u64);
        assert_eq!(json["exception_code"], 0x8000_0003u32);
        assert_eq!(json["exception_address"], 0xFFFF_F804_CE8F_9280u64);
        assert_eq!(json["context_flags"], 0x0010_000F);
        assert!(
            json["triage_detail"]
                .as_str()
                .is_some_and(|d| d.contains("nothing to map")),
            "a refused dump must say why no memory was offered: {json}"
        );
    }

    /// A dump this reader *can* map publishes the same block, so the crash
    /// facts do not appear and disappear depending on which branch the file
    /// took, and `maps_an_address_space` is the only thing that differs.
    #[test]
    fn a_mappable_dump_publishes_the_same_facts_and_says_it_maps_memory() {
        let facts = header_facts(&*source(full_dump(&LAYOUT_64, &[(0x0, 2)])))
            .expect("a full dump has a _DUMP_HEADER too");
        assert!(facts.maps_an_address_space());
        let json = facts.to_json();
        assert_eq!(json["dump_kind"], "full");
        assert_eq!(json["maps_an_address_space"], true);
        assert_eq!(json["bug_check_code"], 0xD1);
        assert_eq!(json["comment"], "lab capture");
        assert!(
            json["triage_detail"].is_null(),
            "a dump that maps memory is not a triage dump"
        );
    }

    /// The exception record's own fields go through the filler guard, and
    /// what the guard rejects has to stay rejected all the way to the record.
    ///
    /// `ExceptionAddress` is the field that matters here. Published as `0` it
    /// says the faulting instruction dereferenced NULL — a specific, checkable
    /// claim about the crash, and one these bytes do not make: the kernel never
    /// wrote the field, so it still holds the header's `PAGE` fill pattern.
    #[test]
    fn an_unwritten_exception_field_is_absent_rather_than_a_null_dereference() {
        let at = LAYOUT_64
            .exception_record
            .expect("the 64-bit layout pins the exception record");
        let mut bytes = dump_header(&LAYOUT_64, 0x3);
        bytes[at + EXCEPTION_FLAGS..at + EXCEPTION_FLAGS + 4].copy_from_slice(SIGNATURE);
        bytes[at + EXCEPTION_ADDRESS..at + EXCEPTION_ADDRESS + 8]
            .copy_from_slice(&SIGNATURE.repeat(2));

        let facts = header_facts(&*source(bytes)).expect("a readable header");
        let exception = facts.exception.expect("the ExceptionCode was written");
        assert_eq!(exception.code, 0x8000_0003, "the code the kernel did write");
        assert_eq!(
            exception.address, None,
            "a fill-pattern ExceptionAddress must not be published as a NULL dereference"
        );
        assert_eq!(exception.flags, None);
        assert_eq!(
            exception.parameter_count,
            Some(0),
            "a NumberParameters the kernel wrote as zero states zero parameters, which is not \
             the same as not stating it"
        );

        let json = facts.to_json();
        assert!(json["exception_address"].is_null(), "{json}");
        assert!(json["exception_flags"].is_null(), "{json}");
        assert_eq!(json["exception_code"], 0x8000_0003u32);
        assert_eq!(json["exception_parameter_count"], 0);
    }

    /// `ContextFlags` is published as evidence that the faulting processor
    /// context is present and well-formed, and the offset it is read from is a
    /// property of the CONTEXT structure rather than of the header.
    /// `LAYOUT_64` serves ARM64 dumps as well as x64 ones, and
    /// `ARM64_NT_CONTEXT` opens with `ContextFlags` at offset 0 — so 0x30 in an
    /// ARM64 context is inside the X-register block, and reading it would
    /// publish half of a saved general-purpose register as the evidence that
    /// the context is well-formed.
    #[test]
    fn an_arm64_dump_publishes_no_contextflags_from_the_x64_offset() {
        let mut bytes = dump_header(&LAYOUT_64, 0x3);
        put_u32(&mut bytes, LAYOUT_64.machine_image_type, MACHINE_ARM64);

        let facts = header_facts(&*source(bytes)).expect("a readable header");
        assert_eq!(facts.architecture, Architecture::Arm64);
        assert_eq!(
            facts.context_flags, None,
            "the x64 ContextFlags offset says nothing about an ARM64 context"
        );
        assert!(facts.to_json()["context_flags"].is_null());
        assert_eq!(
            facts.exception.map(|e| e.code),
            Some(0x8000_0003),
            "the exception record is unaffected: `ContextRecord` is a fixed-size slot, so the \
             record still closes against `DumpType` whatever context was written into it"
        );
    }

    /// The rule stated positively: the offset is shipped for the one machine
    /// whose CONTEXT this file pins, and for no other. A `MachineImageType`
    /// that is neither AMD64 nor a machine this reader knows leaves the
    /// structure at `ContextRecord` unidentified, and an unidentified structure
    /// is not read.
    #[test]
    fn contextflags_is_published_only_for_the_machine_whose_context_is_pinned() {
        let facts = header_facts(&*source(dump_header(&LAYOUT_64, 0x3))).expect("a header");
        assert_eq!(
            facts.context_flags,
            Some(0x0010_000F),
            "an x64 dump still publishes it: this must narrow the claim, not delete it"
        );

        for machine in [MACHINE_ARM64, 0x0000, 0x01C4, 0x8664 + 1] {
            let mut bytes = dump_header(&LAYOUT_64, 0x3);
            put_u32(&mut bytes, LAYOUT_64.machine_image_type, machine);
            let facts = header_facts(&*source(bytes)).expect("a header");
            assert_eq!(
                facts.context_flags, None,
                "MachineImageType {machine:#x} does not pin the structure at ContextRecord"
            );
        }
    }

    /// `maps_an_address_space` is read from `DumpType` alone, and the block it
    /// rides on is attached to failure records too — so a full dump whose run
    /// table is malformed carries `decode_failed: true` beside
    /// `maps_an_address_space: true`. Both are true statements about different
    /// things, and the record has to say which is which, or the pair reads as a
    /// contradiction.
    #[test]
    fn the_address_space_claim_states_that_it_is_about_the_dump_type() {
        let json = header_facts(&*source(full_dump(&LAYOUT_64, &[(0x0, 2)])))
            .expect("a full dump has a _DUMP_HEADER too")
            .to_json();
        assert_eq!(json["maps_an_address_space"], true);
        let detail = json["address_space_detail"]
            .as_str()
            .unwrap_or_else(|| panic!("the claim must state its own scope: {json}"));
        assert!(
            detail.contains("DumpType") && detail.contains("decode"),
            "the scope sentence must name the DumpType it is read from and disclaim this file's \
             decode: {detail}"
        );

        // The dump that maps nothing already has its own sentence, and it says
        // the opposite thing; the two must never appear together.
        let triage = header_facts(&*source(dump_header(&LAYOUT_64, 0x3)))
            .expect("a header")
            .to_json();
        assert!(triage["address_space_detail"].is_null(), "{triage}");
        assert!(triage["triage_detail"].is_string(), "{triage}");
    }

    /// The filler guard applies to numbers, not only to text. A field left at
    /// the `PAGE` fill pattern must read as absent; published as an integer it
    /// would be 1,162,167,621 (`0x45474150`) sitting on the record as if the
    /// kernel had written it.
    #[test]
    fn a_page_filler_field_is_reported_absent_rather_than_as_a_number() {
        let mut bytes = dump_header(&LAYOUT_64, 0x3);
        put_u32(&mut bytes, LAYOUT_64.minor_version, 0x4547_4150);
        put_u64(&mut bytes, LAYOUT_64.system_time, 0x4547_4150_4547_4150);
        let at = LAYOUT_64.comment;
        bytes[at..at + COMMENT_BYTES].copy_from_slice(&SIGNATURE.repeat(COMMENT_BYTES / 4));

        let json = header_facts(&*source(bytes))
            .expect("filler in some fields does not stop the header being one")
            .to_json();
        assert!(json["minor_version"].is_null(), "{json}");
        assert!(json["system_time_filetime"].is_null(), "{json}");
        assert!(json["system_time"].is_null(), "{json}");
        assert!(json["comment"].is_null(), "{json}");
        assert_eq!(
            json["bug_check_code"], 0xD1,
            "the fields the kernel did write are unaffected"
        );
    }

    /// The guard has to hold on the path that SUCCEEDS, not only on the one
    /// that refuses.
    ///
    /// A decoded dump and its header facts land in the same artifact — the
    /// container stage writes `crash_dump` from [`header_facts`] and
    /// `layer_meta` from [`CrashDump::parse`] into one metadata object — so a
    /// field guarded on one path and raw on the other puts two contradictory
    /// values for the same offset on one record, and the raw one is a number
    /// the kernel never wrote.
    #[test]
    fn a_decoded_dump_reports_a_filler_field_as_absent_rather_than_as_a_number() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0x0, 2)]);
        put_u32(&mut bytes, LAYOUT_64.minor_version, 0x4547_4150);
        put_u32(&mut bytes, LAYOUT_64.number_processors, 0x4547_4150);
        put_u64(
            &mut bytes,
            LAYOUT_64.kd_debugger_data_block,
            0x4547_4150_4547_4150,
        );
        put_u64(
            &mut bytes,
            LAYOUT_64.directory_table_base,
            0x4547_4150_4547_4150,
        );
        put_u64(&mut bytes, LAYOUT_64.system_time, 0x4547_4150_4547_4150);

        let parsed = CrashDump::parse(&*source(bytes.clone()))
            .expect("filler in these fields does not stop the run table describing memory");
        let json = parsed.layer_meta().to_json();
        for field in [
            "minor_version",
            "number_processors",
            "kd_debugger_data_block",
            "directory_table_base",
            "system_time_filetime",
        ] {
            assert!(
                json["notes"][field].is_null(),
                "a field left at the fill pattern must be absent from the record, not published \
                 as a number; {field} survived: {json}"
            );
        }
        assert!(
            !json.to_string().contains("1162297680"),
            "the fill word must never reach the record as the decimal a reader would take for a \
             build number or a processor count: {json}"
        );

        // The accessors state the same thing the notes do, and the fields the
        // kernel did write are untouched.
        assert_eq!(parsed.directory_table_base(), None);
        assert_eq!(parsed.kd_debugger_data_block(), None);
        assert_eq!(parsed.number_processors(), None);
        assert_eq!(parsed.pfn_database(), Some(0x8000_1000));
        assert_eq!(json["notes"]["major_version"], 15);
        assert_eq!(json["notes"]["pfn_database"], 0x8000_1000u64);

        // The decode itself is unchanged: the geometry is read from the run
        // table, not from any of the fields above.
        assert_eq!(parsed.architecture(), Architecture::X64);
        assert_eq!(parsed.acquired_bytes(), 2 * PAGE_SIZE);
    }

    /// The two blocks the container stage writes into one artifact must never
    /// disagree about the same offset.
    #[test]
    fn the_notes_of_a_decoded_dump_agree_with_the_header_facts_field_by_field() {
        let mut bytes = full_dump(&LAYOUT_64, &[(0x0, 2)]);
        put_u32(&mut bytes, LAYOUT_64.minor_version, 0x4547_4150);
        put_u64(
            &mut bytes,
            LAYOUT_64.ps_active_process_head,
            0x4547_4150_4547_4150,
        );

        let notes = CrashDump::parse(&*source(bytes.clone()))
            .expect("a well-formed dump")
            .layer_meta()
            .to_json();
        let facts = header_facts(&*source(bytes))
            .expect("a readable header")
            .to_json();

        for field in [
            "major_version",
            "minor_version",
            "machine_image_type",
            "number_processors",
            "bug_check_code",
            "directory_table_base",
            "pfn_database",
            "ps_loaded_module_list",
            "ps_active_process_head",
            "kd_debugger_data_block",
            "system_time_filetime",
            "system_up_time_100ns",
            "comment",
        ] {
            assert_eq!(
                notes["notes"][field], facts[field],
                "the record carries both blocks, so {field} cannot say one thing in the layer \
                 notes and another in the crash facts: {notes} vs {facts}"
            );
        }
    }

    /// `PaeEnabled` is a Windows `BOOLEAN`, and the fill pattern's first byte
    /// is `P` — 80. A header page the kernel left alone at that offset was
    /// publishing 80 for a field whose only legal values are 0 and 1.
    #[test]
    fn an_unwritten_pae_flag_is_absent_rather_than_the_letter_p() {
        let at = LAYOUT_32
            .pae_enabled
            .expect("the 32-bit layout carries PaeEnabled");
        let mut bytes = full_dump(&LAYOUT_32, &[(0x0, 2)]);
        bytes[at..at + 4].copy_from_slice(SIGNATURE);

        let notes = CrashDump::parse(&*source(bytes.clone()))
            .expect("a well-formed 32-bit dump")
            .layer_meta()
            .to_json();
        assert!(
            notes["notes"]["pae_enabled"].is_null(),
            "the fill byte must not be published as a BOOLEAN: {notes}"
        );

        let facts = header_facts(&*source(bytes)).expect("a readable header");
        assert_eq!(facts.pae_enabled, None);
        assert!(facts.to_json()["pae_enabled"].is_null());
    }

    /// And the guard must not swallow the flag when the kernel did write it:
    /// "absent" and "false" are different statements about the machine.
    #[test]
    fn a_pae_flag_the_kernel_wrote_is_still_published() {
        let at = LAYOUT_32
            .pae_enabled
            .expect("the 32-bit layout carries PaeEnabled");
        for value in [0u8, 1u8] {
            let mut bytes = full_dump(&LAYOUT_32, &[(0x0, 2)]);
            bytes[at] = value;
            let notes = CrashDump::parse(&*source(bytes.clone()))
                .expect("a well-formed 32-bit dump")
                .layer_meta()
                .to_json();
            assert_eq!(notes["notes"]["pae_enabled"], u64::from(value));
            assert_eq!(
                header_facts(&*source(bytes)).expect("a header").pae_enabled,
                Some(value)
            );
        }
    }

    /// An all-zero FILETIME is the field never having been written, and
    /// 1601-01-01 in front of an examiner is a fabricated crash time.
    #[test]
    fn an_unwritten_crash_time_is_absent_rather_than_the_filetime_epoch() {
        let mut bytes = dump_header(&LAYOUT_64, 0x3);
        put_u64(&mut bytes, LAYOUT_64.system_time, 0);
        put_u64(&mut bytes, LAYOUT_64.system_up_time, 0);
        let json = header_facts(&*source(bytes)).expect("a header").to_json();
        assert!(json["system_time_filetime"].is_null(), "{json}");
        assert!(json["system_time"].is_null(), "{json}");
        assert!(json["system_up_time_100ns"].is_null(), "{json}");
    }

    /// The deliberate scope boundary, written down where it will be noticed.
    ///
    /// A triage dump also carries a driver list, process/thread/PRCB blocks, a
    /// call stack, a string pool and a data-block table. They are genuinely
    /// there and genuinely decodable — which is exactly the trap. No ISF or
    /// vendored specification in this tree describes them, so a decoder for
    /// them would be reverse engineering presented as evidence. Nothing beyond
    /// the header is published, and nothing beyond the header is even read.
    #[test]
    fn a_triage_dump_publishes_nothing_from_beyond_the_header() {
        let mut bytes = dump_header(&LAYOUT_64, 0x3);
        bytes.extend_from_slice(&[0x5Au8; 0x4000]);
        let watched = Arc::new(WatchfulSource::new(bytes));

        let json = header_facts(&*Arc::clone(&watched) as &dyn DataSource)
            .expect("a header")
            .to_json();

        // No key may name anything from the triage body. (`triage_detail` names
        // those structures in prose, which is the opposite claim: it says they
        // are *not* decoded.)
        let keys: Vec<&String> = json.as_object().expect("an object").keys().collect();
        for forbidden in [
            "driver",
            "string_pool",
            "call_stack",
            "data_blocks",
            "prcb",
            "thread",
            "process_block",
        ] {
            assert!(
                !keys.iter().any(|k| k.contains(forbidden)),
                "the _TRIAGE_DUMP body is not decoded by this build; {forbidden} must not be \
                 published: {keys:?}"
            );
        }

        // And it is not merely unpublished: it is never read. The only byte
        // beyond the header any path may touch is the four-byte `_SUMMARY_DUMP`
        // signature probe that decides whether a 0x2/0x4 is a bitmap dump.
        let reached = watched.highest_byte_read();
        assert!(
            reached <= LAYOUT_64.header_bytes + 4,
            "nothing past the header may be read for a dump that maps nothing, but a read \
             reached {reached:#x}"
        );
    }

    /// Reading the header of something that is not a crash dump must produce
    /// no facts at all, rather than a block of nulls that reads as "a crash
    /// dump that states nothing".
    #[test]
    fn a_file_that_is_not_a_crash_dump_yields_no_header_facts() {
        assert!(header_facts(&*source(vec![0u8; 0x4000])).is_none());
        assert!(header_facts(&*source(b"PAGEXXXX".to_vec())).is_none());
        // The magic alone is not a header: the structure must be readable.
        assert!(header_facts(&*source(b"PAGEDU64".to_vec())).is_none());
    }
}
