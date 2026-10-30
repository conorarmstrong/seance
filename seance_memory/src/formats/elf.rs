//! ELF core-dump reader: `PT_LOAD` program headers become the segment list.
//!
//! This is the format `virsh dump`, VirtualBox's `.core` writer and QEMU's
//! `dump-guest-memory` produce. The whole of the memory map is in the program
//! header table: each `PT_LOAD` entry says "`p_filesz` bytes at file offset
//! `p_offset` hold physical addresses `p_paddr ..`". Everything else in the ELF
//! (sections, notes, the string table) is irrelevant to addressing memory.
//!
//! ## Why this parses the header directly instead of using `goblin`
//!
//! `goblin 0.8.2` is already in the tree (`seance_plugin_pe`), and the
//! implementation plan suggests using it. It was evaluated and rejected here,
//! for three reasons that are specific to this use, not general complaints:
//!
//! 1. **Its unified `elf::Header` decoder ignores `EI_DATA`.**
//!    `goblin::elf::Header`'s `TryFromCtx` dispatches on `EI_CLASS` and then
//!    does `bytes.pread::<header64::Header>(0)`, i.e. with `scroll::Endian`'s
//!    `Default`, which is `NATIVE` (`scroll-0.12.0/src/endian.rs:21-26`). On a
//!    little-endian host a **big-endian** core's `e_phnum`/`e_phoff` therefore
//!    decode byte-swapped, silently, and this reader must handle both
//!    endiannesses. Avoiding that means hand-dispatching on `EI_CLASS` and
//!    calling the per-class `header32::Header::parse` / `header64::Header::parse`
//!    ourselves — at which point what is left to save is the twenty lines of
//!    integer decoding below.
//! 2. **`ProgramHeader::parse` ignores `e_phentsize`** and strides by the
//!    canonical 32/56 bytes (`goblin-0.8.2/src/elf/program_header.rs:162-178`).
//!    A core declaring a different entry size would be misparsed rather than
//!    refused. This reader honours the declared stride and validates it.
//! 3. **`Elf::parse` needs the whole file in memory.** A memory core is
//!    routinely tens of gigabytes; the structural reads here are ~64 bytes plus
//!    56 per program header, and they must go through
//!    [`read_exact_or_fail`] anyway so a truncated header fails closed rather
//!    than parsing as zeros. `goblin` would only be decoding a buffer we had
//!    already read under that discipline.
//!
//! ## Deliberate departures from Volatility 3 (`framework/layers/elf.py`)
//!
//! - **ELF32 cores are read.** Upstream's `Elf64Layer` hard-requires
//!   `ELFCLASS64` and its stacker rejects anything else. A 32-bit Linux core is
//!   still a core. Note that [`crate::format::detect`] currently claims only
//!   ELF64 cores, matching upstream's detection, so an ELF32 core reaches this
//!   reader when a caller routes it here rather than by content detection.
//! - **Big-endian cores are read.** Upstream parses through an ISF whose base
//!   types are little-endian, so a big-endian core decodes to nonsense.
//! - **`e_type` must be `ET_CORE`.** Upstream's stacker claims any ELF64 file,
//!   which in Séance would route every ordinary executable and shared object on
//!   an ingested disk into the memory pipeline.
//!
//! Kept identical to upstream, deliberately:
//!
//! - Only `PT_LOAD` where `p_filesz == p_memsz > 0` becomes a segment. A
//!   partially captured `PT_LOAD` is skipped rather than half-mapped, so the
//!   address space matches the oracle byte for byte; the skip is recorded as an
//!   [`IncompleteReason::ShortRead`] naming the exact range, never dropped
//!   silently.
//! - `p_paddr` is the memory address, not `p_vaddr`.
//! - `e_version == 0` is accepted. VirtualBox writes it, in violation of the
//!   spec, and rejecting those cores would help nobody.

use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_core::io::{read_exact_or_fail, IncompleteReason};
use tracing::debug;

use super::{u16_at, u32_at, u64_at, Endian, FormatError};
use crate::format::MemoryImageFormat;
use crate::meta::{Architecture, LayerMeta};
use crate::segmented::{Segment, SegmentedLayer};

const FORMAT: MemoryImageFormat = MemoryImageFormat::ElfCore;

/// `\x7fELF`.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_NIDENT: usize = 16;

const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

/// `ET_CORE`.
const ET_CORE: u16 = 4;
/// `PT_LOAD`.
const PT_LOAD: u32 = 1;
/// `PN_XNUM`: `e_phnum` is not the real count; it lives in `shdr[0].sh_info`.
const PN_XNUM: u16 = 0xFFFF;

const EHDR32_LEN: usize = 52;
const EHDR64_LEN: usize = 64;
const PHDR32_LEN: usize = 32;
const PHDR64_LEN: usize = 56;

const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// The width of an ELF file's structures, from `EI_CLASS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElfClass {
    Elf32,
    Elf64,
}

impl ElfClass {
    fn ehdr_len(self) -> usize {
        match self {
            ElfClass::Elf32 => EHDR32_LEN,
            ElfClass::Elf64 => EHDR64_LEN,
        }
    }

    fn phdr_len(self) -> usize {
        match self {
            ElfClass::Elf32 => PHDR32_LEN,
            ElfClass::Elf64 => PHDR64_LEN,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ElfClass::Elf32 => "elf32",
            ElfClass::Elf64 => "elf64",
        }
    }
}

/// The fields of the ELF file header this reader needs. Everything else in the
/// 52/64-byte header is irrelevant to addressing memory and is not decoded.
#[derive(Debug, Clone, Copy)]
struct FileHeader {
    class: ElfClass,
    endian: Endian,
    e_machine: u16,
    e_version: u32,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
}

/// One decoded `PT_LOAD` entry.
#[derive(Debug, Clone, Copy)]
struct ProgramHeader {
    p_type: u32,
    p_offset: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

/// Open an ELF core dump as a memory layer.
///
/// # Errors
///
/// - [`FormatError::NotThisFormat`] when the magic, class, data encoding or
///   `e_type` say these bytes are not an ELF core. A caller trying several
///   readers moves past this silently.
/// - [`FormatError::Io`] when a structural header is short. Truncated evidence
///   fails closed; nothing is parsed from a zero-padded buffer.
/// - [`FormatError::Malformed`] for a header that is self-inconsistent (an
///   entry size below the class minimum, a program header table that overflows
///   the address space).
/// - [`FormatError::Unsupported`] for `PN_XNUM`, and for a userland process
///   core, whose `p_paddr` fields are all zero and which therefore describes no
///   physical address space at all.
pub fn open(source: Arc<dyn DataSource>) -> Result<SegmentedLayer, FormatError> {
    let header = read_file_header(&*source)?;
    let phdrs = read_program_headers(&*source, &header)?;

    let mut segments: Vec<Segment> = Vec::new();
    let mut skipped: Vec<(u64, u64, u64)> = Vec::new();
    let mut declared_top: u64 = 0;
    let mut pt_load_count = 0usize;

    for phdr in &phdrs {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        pt_load_count += 1;
        // A `PT_LOAD` with `p_memsz == 0` declares no memory, whatever address
        // it names. Letting it raise the declared top would invent an address
        // space reaching up to `p_paddr` with nothing in it — and since the
        // layer treats declared-but-unmapped as a hole, that empty stretch
        // would then be reported as missing memory rather than as memory the
        // image never claimed to hold.
        if phdr.p_memsz > 0 {
            declared_top = declared_top.max(phdr.p_paddr.saturating_add(phdr.p_memsz));
        }

        if phdr.p_filesz == phdr.p_memsz && phdr.p_filesz > 0 {
            segments.push(Segment::new(phdr.p_offset, phdr.p_paddr, phdr.p_memsz));
        } else {
            // Declared memory the acquisition did not fully capture. Upstream
            // drops these; so do we, so the address space matches the oracle —
            // but the drop is recorded rather than invisible.
            skipped.push((phdr.p_paddr, phdr.p_filesz, phdr.p_memsz));
        }
    }

    if segments.is_empty() {
        return Err(FormatError::malformed(
            FORMAT,
            format!(
                "no usable PT_LOAD segments: {pt_load_count} PT_LOAD of {} program headers, \
                 {} skipped for p_filesz != p_memsz or p_memsz == 0",
                phdrs.len(),
                skipped.len()
            ),
        ));
    }

    // A userland process core is also ET_CORE, but its p_paddr fields are all
    // zero and p_vaddr carries the (virtual) addresses. Building a physical
    // address space from it would either collide at address 0 or, with a single
    // segment, silently present a process's virtual memory as physical memory.
    // Name the case instead.
    if segments.len() > 1 && segments.iter().all(|s| s.memory_offset == 0) {
        return Err(FormatError::unsupported(
            FORMAT,
            format!(
                "every one of the {} PT_LOAD segments has p_paddr == 0, which is a userland \
                 process core (addresses are in p_vaddr), not a physical memory image",
                segments.len()
            ),
        ));
    }

    let mut meta = LayerMeta::new(FORMAT)
        .with_note("elf_class", header.class.as_str())
        .with_note("elf_endian", header.endian.as_str())
        .with_note("elf_machine", u64::from(header.e_machine))
        .with_note("elf_program_headers", u64::from(header.e_phnum))
        .with_note("elf_pt_load_mapped", segments.len() as u64)
        .with_note("elf_pt_load_skipped", skipped.len() as u64);

    if declared_top > 0 {
        meta = meta.with_declared_size(declared_top);
    }
    if let Some(arch) = architecture_of(header.e_machine) {
        meta = meta.with_architecture(arch);
    }
    if header.e_version != 1 {
        // VirtualBox writes 0. Accepted, but recorded: the file is out of spec
        // and an examiner may want to know which tool wrote it.
        meta = meta.with_note("elf_version", u64::from(header.e_version));
    }
    for (paddr, filesz, memsz) in &skipped {
        if *memsz == 0 {
            // The entry declares no memory at all, so nothing is missing from
            // the address space and there is no incompleteness to report.
            continue;
        }
        meta.push_incomplete(
            IncompleteReason::ShortRead,
            format!(
                "PT_LOAD at {paddr:#x} declares {memsz:#x} bytes of memory but only {filesz:#x} \
                 bytes are in the file; the segment is not mapped and the whole range reads as \
                 a hole"
            ),
        );
    }

    SegmentedLayer::new(source, segments, meta).map_err(|e| FormatError::layer(FORMAT, e))
}

/// The architecture the `e_machine` field *proves*. Unknown machines yield
/// `None`; nothing here guesses a width from a plausible-looking pointer.
fn architecture_of(e_machine: u16) -> Option<Architecture> {
    match e_machine {
        EM_386 => Some(Architecture::X86),
        EM_X86_64 => Some(Architecture::X64),
        EM_AARCH64 => Some(Architecture::Arm64),
        other => {
            debug!(e_machine = other, "ELF core with an unmapped e_machine");
            None
        }
    }
}

fn read_file_header(ds: &dyn DataSource) -> Result<FileHeader, FormatError> {
    // e_ident first: it is what decides how wide and which way round the rest
    // of the header is, so it cannot be read as part of a fixed-size slurp.
    let mut ident = [0u8; EI_NIDENT];
    read_exact_or_fail(ds, 0, &mut ident, "ELF e_ident")
        .map_err(|e| FormatError::io(FORMAT, "ELF e_ident", e))?;

    if ident[0..4] != ELF_MAGIC[..] {
        return Err(FormatError::not_this(FORMAT, "no \\x7fELF magic"));
    }
    let class = match ident[EI_CLASS] {
        ELFCLASS32 => ElfClass::Elf32,
        ELFCLASS64 => ElfClass::Elf64,
        other => {
            return Err(FormatError::not_this(
                FORMAT,
                format!("EI_CLASS {other} is neither ELFCLASS32 nor ELFCLASS64"),
            ))
        }
    };
    let endian = match ident[EI_DATA] {
        ELFDATA2LSB => Endian::Little,
        ELFDATA2MSB => Endian::Big,
        other => {
            return Err(FormatError::not_this(
                FORMAT,
                format!("EI_DATA {other} is neither ELFDATA2LSB nor ELFDATA2MSB"),
            ))
        }
    };

    let mut raw = vec![0u8; class.ehdr_len()];
    read_exact_or_fail(ds, 0, &mut raw, "ELF file header")
        .map_err(|e| FormatError::io(FORMAT, "ELF file header", e))?;

    let field = |name: &str| FormatError::malformed(FORMAT, format!("ELF header field {name}"));
    let e_type = u16_at(&raw, 16, endian).ok_or_else(|| field("e_type"))?;
    let e_machine = u16_at(&raw, 18, endian).ok_or_else(|| field("e_machine"))?;
    let e_version = u32_at(&raw, 20, endian).ok_or_else(|| field("e_version"))?;
    let (e_phoff, phentsize_at, phnum_at) = match class {
        ElfClass::Elf32 => (
            u64::from(u32_at(&raw, 28, endian).ok_or_else(|| field("e_phoff"))?),
            42,
            44,
        ),
        ElfClass::Elf64 => (
            u64_at(&raw, 32, endian).ok_or_else(|| field("e_phoff"))?,
            54,
            56,
        ),
    };
    let e_phentsize = u16_at(&raw, phentsize_at, endian).ok_or_else(|| field("e_phentsize"))?;
    let e_phnum = u16_at(&raw, phnum_at, endian).ok_or_else(|| field("e_phnum"))?;

    if e_type != ET_CORE {
        return Err(FormatError::not_this(
            FORMAT,
            format!("e_type {e_type} is not ET_CORE ({ET_CORE})"),
        ));
    }
    if e_phnum == PN_XNUM {
        // The real count lives in shdr[0].sh_info. Reading 0xFFFF program
        // headers instead would silently produce a wrong memory map.
        return Err(FormatError::unsupported(
            FORMAT,
            "e_phnum is PN_XNUM (0xffff): the program header count is held in the section \
             header table, which this reader does not parse",
        ));
    }
    if e_phnum == 0 {
        return Err(FormatError::malformed(
            FORMAT,
            "e_phnum is 0: the core describes no memory",
        ));
    }
    if usize::from(e_phentsize) < class.phdr_len() {
        return Err(FormatError::malformed(
            FORMAT,
            format!(
                "e_phentsize {e_phentsize} is below the {} minimum of {}",
                class.as_str(),
                class.phdr_len()
            ),
        ));
    }

    Ok(FileHeader {
        class,
        endian,
        e_machine,
        e_version,
        e_phoff,
        e_phentsize,
        e_phnum,
    })
}

fn read_program_headers(
    ds: &dyn DataSource,
    header: &FileHeader,
) -> Result<Vec<ProgramHeader>, FormatError> {
    let phdr_len = header.class.phdr_len();
    let stride = u64::from(header.e_phentsize);
    let mut raw = vec![0u8; phdr_len];
    // e_phnum is a u16, so the table is bounded at 65534 entries by the format
    // itself and needs no cap of ours.
    let mut out = Vec::with_capacity(usize::from(header.e_phnum));

    for index in 0..header.e_phnum {
        let at = header
            .e_phoff
            .checked_add(u64::from(index).saturating_mul(stride))
            .ok_or_else(|| {
                FormatError::malformed(
                    FORMAT,
                    format!(
                        "program header {index} at e_phoff {:#x} + {index} * {stride} overflows \
                         the address space",
                        header.e_phoff
                    ),
                )
            })?;
        read_exact_or_fail(ds, at, &mut raw, "ELF program header")
            .map_err(|e| FormatError::io(FORMAT, format!("ELF program header {index}"), e))?;
        out.push(decode_program_header(&raw, header, index)?);
    }
    Ok(out)
}

fn decode_program_header(
    raw: &[u8],
    header: &FileHeader,
    index: u16,
) -> Result<ProgramHeader, FormatError> {
    let endian = header.endian;
    let field =
        |name: &str| FormatError::malformed(FORMAT, format!("program header {index} field {name}"));

    // The two layouts differ by more than width: ELF64 moves p_flags up to
    // offset 4, so the field order is not shared.
    let (p_type, p_offset, p_paddr, p_filesz, p_memsz) = match header.class {
        ElfClass::Elf32 => (
            u32_at(raw, 0, endian).ok_or_else(|| field("p_type"))?,
            u64::from(u32_at(raw, 4, endian).ok_or_else(|| field("p_offset"))?),
            u64::from(u32_at(raw, 12, endian).ok_or_else(|| field("p_paddr"))?),
            u64::from(u32_at(raw, 16, endian).ok_or_else(|| field("p_filesz"))?),
            u64::from(u32_at(raw, 20, endian).ok_or_else(|| field("p_memsz"))?),
        ),
        ElfClass::Elf64 => (
            u32_at(raw, 0, endian).ok_or_else(|| field("p_type"))?,
            u64_at(raw, 8, endian).ok_or_else(|| field("p_offset"))?,
            u64_at(raw, 24, endian).ok_or_else(|| field("p_paddr"))?,
            u64_at(raw, 32, endian).ok_or_else(|| field("p_filesz"))?,
            u64_at(raw, 40, endian).ok_or_else(|| field("p_memsz"))?,
        ),
    };

    Ok(ProgramHeader {
        p_type,
        p_offset,
        p_paddr,
        p_filesz,
        p_memsz,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{HoleReason, MemoryHole, MemoryLayer};
    use seance_core::data_source::ByteSliceDataSource;

    // ── Synthetic fixtures, built byte by byte ──────────────────────────────

    /// One `PT_LOAD` (or other) entry to place in a fixture.
    #[derive(Debug, Clone, Copy)]
    struct Entry {
        p_type: u32,
        paddr: u64,
        /// Bytes actually written to the file for this entry.
        filesz: u64,
        /// Bytes the entry claims to describe in memory.
        memsz: u64,
        fill: u8,
    }

    impl Entry {
        fn load(paddr: u64, size: u64, fill: u8) -> Self {
            Entry {
                p_type: PT_LOAD,
                paddr,
                filesz: size,
                memsz: size,
                fill,
            }
        }
    }

    fn put_u16(out: &mut Vec<u8>, v: u16, endian: Endian) {
        match endian {
            Endian::Little => out.extend_from_slice(&v.to_le_bytes()),
            Endian::Big => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn put_u32(out: &mut Vec<u8>, v: u32, endian: Endian) {
        match endian {
            Endian::Little => out.extend_from_slice(&v.to_le_bytes()),
            Endian::Big => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn put_u64(out: &mut Vec<u8>, v: u64, endian: Endian) {
        match endian {
            Endian::Little => out.extend_from_slice(&v.to_le_bytes()),
            Endian::Big => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    /// Knobs a malformed-header test needs to reach past the valid builder.
    #[derive(Debug, Clone, Copy)]
    struct Overrides {
        e_type: u16,
        e_version: u32,
        e_phentsize: Option<u16>,
        e_phnum: Option<u16>,
        e_phoff: Option<u64>,
        ei_class: Option<u8>,
        ei_data: Option<u8>,
        magic: [u8; 4],
    }

    impl Default for Overrides {
        fn default() -> Self {
            Overrides {
                e_type: ET_CORE,
                e_version: 1,
                e_phentsize: None,
                e_phnum: None,
                e_phoff: None,
                ei_class: None,
                ei_data: None,
                magic: ELF_MAGIC,
            }
        }
    }

    /// Build a complete ELF core file: header, program header table, payloads.
    fn build(
        class: ElfClass,
        endian: Endian,
        e_machine: u16,
        entries: &[Entry],
        over: Overrides,
    ) -> Vec<u8> {
        let ehdr_len = class.ehdr_len();
        let phdr_len = class.phdr_len();
        let phentsize = over.e_phentsize.unwrap_or(phdr_len as u16);
        let phnum = over.e_phnum.unwrap_or(entries.len() as u16);
        let phoff = over.e_phoff.unwrap_or(ehdr_len as u64);

        // Payloads follow the program header table.
        let table_bytes = entries.len() as u64 * u64::from(phentsize);
        let mut payload_at = phoff + table_bytes;
        let mut offsets = Vec::new();
        for e in entries {
            offsets.push(payload_at);
            payload_at += e.filesz;
        }

        let mut out = Vec::new();
        out.extend_from_slice(&over.magic);
        out.push(over.ei_class.unwrap_or(match class {
            ElfClass::Elf32 => ELFCLASS32,
            ElfClass::Elf64 => ELFCLASS64,
        }));
        out.push(over.ei_data.unwrap_or(match endian {
            Endian::Little => ELFDATA2LSB,
            Endian::Big => ELFDATA2MSB,
        }));
        out.push(1); // EI_VERSION
        out.resize(EI_NIDENT, 0);

        put_u16(&mut out, over.e_type, endian);
        put_u16(&mut out, e_machine, endian);
        put_u32(&mut out, over.e_version, endian);
        match class {
            ElfClass::Elf32 => {
                put_u32(&mut out, 0, endian); // e_entry
                put_u32(&mut out, phoff as u32, endian);
                put_u32(&mut out, 0, endian); // e_shoff
                put_u32(&mut out, 0, endian); // e_flags
                put_u16(&mut out, ehdr_len as u16, endian);
            }
            ElfClass::Elf64 => {
                put_u64(&mut out, 0, endian); // e_entry
                put_u64(&mut out, phoff, endian);
                put_u64(&mut out, 0, endian); // e_shoff
                put_u32(&mut out, 0, endian); // e_flags
                put_u16(&mut out, ehdr_len as u16, endian);
            }
        }
        put_u16(&mut out, phentsize, endian);
        put_u16(&mut out, phnum, endian);
        put_u16(&mut out, 0, endian); // e_shentsize
        put_u16(&mut out, 0, endian); // e_shnum
        put_u16(&mut out, 0, endian); // e_shstrndx
        assert_eq!(out.len(), ehdr_len, "fixture header width");

        out.resize(phoff as usize, 0);
        for (e, &offset) in entries.iter().zip(offsets.iter()) {
            let start = out.len();
            match class {
                ElfClass::Elf32 => {
                    put_u32(&mut out, e.p_type, endian);
                    put_u32(&mut out, offset as u32, endian);
                    put_u32(&mut out, 0, endian); // p_vaddr
                    put_u32(&mut out, e.paddr as u32, endian);
                    put_u32(&mut out, e.filesz as u32, endian);
                    put_u32(&mut out, e.memsz as u32, endian);
                    put_u32(&mut out, 6, endian); // p_flags
                    put_u32(&mut out, 0x1000, endian); // p_align
                }
                ElfClass::Elf64 => {
                    put_u32(&mut out, e.p_type, endian);
                    put_u32(&mut out, 6, endian); // p_flags
                    put_u64(&mut out, offset, endian);
                    put_u64(&mut out, 0, endian); // p_vaddr
                    put_u64(&mut out, e.paddr, endian);
                    put_u64(&mut out, e.filesz, endian);
                    put_u64(&mut out, e.memsz, endian);
                    put_u64(&mut out, 0x1000, endian); // p_align
                }
            }
            // Honour a declared entry size larger than the structure.
            out.resize(start + usize::from(phentsize), 0);
        }

        for e in entries {
            out.resize(out.len() + e.filesz as usize, e.fill);
        }
        out
    }

    fn source(bytes: Vec<u8>) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(bytes))
    }

    /// The canonical fixture: two captured ranges with an MMIO gap between.
    fn two_range_core(class: ElfClass, endian: Endian, e_machine: u16) -> Vec<u8> {
        build(
            class,
            endian,
            e_machine,
            &[
                Entry::load(0x0000, 0x1000, 0xA1),
                Entry::load(0x3000, 0x1000, 0xB2),
            ],
            Overrides::default(),
        )
    }

    // ── Valid image ─────────────────────────────────────────────────────────

    #[test]
    fn a_valid_elf64_core_maps_its_pt_load_segments() {
        let layer = open(source(two_range_core(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
        )))
        .expect("a well-formed ELF64 core");

        assert_eq!(layer.segments().len(), 2);
        assert_eq!(layer.min_address(), 0);
        assert_eq!(layer.max_address(), 0x3FFF);
        assert_eq!(
            layer.size(),
            0x4000,
            "size is the span of the address space"
        );
        assert_eq!(layer.mapped_len(), 0x2000, "only two pages were captured");

        let mut page = vec![0u8; 0x1000];
        assert_eq!(layer.read_at(0, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0xA1));
        assert_eq!(layer.read_at(0x3000, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0xB2));
    }

    #[test]
    fn the_gap_between_pt_loads_is_a_hole_and_not_zeros() {
        let layer = open(source(two_range_core(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
        )))
        .unwrap();
        let mut buf = vec![0xFFu8; 0x2000];
        let err = layer
            .read_at(0x1000, &mut buf)
            .expect_err("the range the core never described must not read as zeros");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!((hole.address, hole.length), (0x1000, 0x2000));
        assert_eq!(hole.reason, HoleReason::Unmapped);
        assert!(buf.iter().all(|&b| b == 0xFF), "nothing was written");
    }

    #[test]
    fn a_valid_elf32_core_is_read_although_upstream_refuses_it() {
        let layer = open(source(two_range_core(
            ElfClass::Elf32,
            Endian::Little,
            EM_386,
        )))
        .expect("a 32-bit core is still a core");
        assert_eq!(layer.segments().len(), 2);
        assert_eq!(layer.layer_meta().architecture(), Some(Architecture::X86));
        assert_eq!(
            layer.layer_meta().note("elf_class").unwrap().as_str(),
            Some("elf32")
        );

        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x3000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0xB2));
    }

    #[test]
    fn a_big_endian_core_decodes_its_header_with_the_declared_byte_order() {
        // The case goblin's unified header decoder gets wrong: EI_DATA is
        // ignored and the fields decode with host endianness.
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            let layer = open(source(two_range_core(class, Endian::Big, EM_AARCH64)))
                .expect("a big-endian core");
            assert_eq!(layer.segments().len(), 2, "{}", class.as_str());
            assert_eq!(layer.max_address(), 0x3FFF);
            assert_eq!(layer.layer_meta().architecture(), Some(Architecture::Arm64));
            assert_eq!(
                layer.layer_meta().note("elf_endian").unwrap().as_str(),
                Some("big")
            );

            let mut page = vec![0u8; 0x1000];
            layer.read_at(0x3000, &mut page).unwrap();
            assert!(page.iter().all(|&b| b == 0xB2));
        }
    }

    #[test]
    fn non_pt_load_program_headers_are_ignored() {
        // A real core leads with PT_NOTE (type 4) carrying NT_PRSTATUS/VMCOREINFO.
        let entries = [
            Entry {
                p_type: 4, // PT_NOTE
                paddr: 0,
                filesz: 0x40,
                memsz: 0x40,
                fill: 0xEE,
            },
            Entry::load(0x2000, 0x1000, 0xC3),
        ];
        let layer = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &entries,
            Overrides::default(),
        )))
        .expect("PT_NOTE alongside PT_LOAD is normal");
        assert_eq!(layer.segments().len(), 1);
        assert_eq!(layer.min_address(), 0x2000);
    }

    #[test]
    fn a_larger_declared_entry_size_is_honoured_as_the_table_stride() {
        // goblin strides by the canonical size regardless; a core declaring a
        // wider entry would be misparsed there. Here the declared stride wins.
        let over = Overrides {
            e_phentsize: Some((PHDR64_LEN + 8) as u16),
            ..Overrides::default()
        };
        let layer = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &[
                Entry::load(0x0000, 0x1000, 0x11),
                Entry::load(0x1000, 0x1000, 0x22),
            ],
            over,
        )))
        .expect("a wider entry size is legal");
        assert_eq!(layer.segments().len(), 2);
        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(
            page.iter().all(|&b| b == 0x22),
            "the second entry was located with the declared stride"
        );
    }

    #[test]
    fn virtualbox_style_e_version_zero_is_accepted_and_recorded() {
        let over = Overrides {
            e_version: 0,
            ..Overrides::default()
        };
        let layer = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &[Entry::load(0, 0x1000, 0x5A)],
            over,
        )))
        .expect("VirtualBox's out-of-spec e_version is accepted, as upstream");
        assert_eq!(layer.layer_meta().note("elf_version").unwrap(), 0);
    }

    #[test]
    fn metadata_records_what_the_core_declared_and_what_was_mapped() {
        let layer = open(source(two_range_core(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
        )))
        .unwrap();
        let meta = layer.layer_meta();
        assert_eq!(meta.format(), Some(MemoryImageFormat::ElfCore));
        assert_eq!(meta.architecture(), Some(Architecture::X64));
        assert_eq!(meta.declared_size(), Some(0x4000));
        assert_eq!(meta.note("elf_pt_load_mapped").unwrap(), 2);
        assert_eq!(meta.note("elf_pt_load_skipped").unwrap(), 0);
        assert!(meta.incomplete().is_empty(), "nothing was skipped");
    }

    #[test]
    fn an_unknown_e_machine_yields_no_architecture_rather_than_a_guess() {
        let layer = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            0x7FFF, // not a machine we map
            &[Entry::load(0, 0x1000, 0x5A)],
            Overrides::default(),
        )))
        .unwrap();
        assert_eq!(layer.layer_meta().architecture(), None);
        assert_eq!(layer.layer_meta().note("elf_machine").unwrap(), 0x7FFF);
    }

    // ── Partially captured PT_LOAD ──────────────────────────────────────────

    #[test]
    fn a_pt_load_with_filesz_below_memsz_is_skipped_and_recorded_as_incomplete() {
        let entries = [
            Entry::load(0x0000, 0x1000, 0x11),
            Entry {
                p_type: PT_LOAD,
                paddr: 0x1000,
                filesz: 0x400,
                memsz: 0x1000,
                fill: 0x22,
            },
        ];
        let layer = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &entries,
            Overrides::default(),
        )))
        .expect("the first PT_LOAD is usable");

        assert_eq!(
            layer.segments().len(),
            1,
            "the partial segment is not mapped"
        );
        assert_eq!(layer.mapped_len(), 0x1000);
        assert_eq!(
            layer.layer_meta().declared_size(),
            Some(0x2000),
            "the declared top still counts the skipped segment"
        );

        // The skip is on the record with the exact range, so it cannot be
        // mistaken for memory that was never declared.
        let incomplete = layer.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::ShortRead);
        assert!(incomplete[0].detail.contains("0x1000"));
        assert!(incomplete[0].detail.contains("0x400"));
        assert_eq!(layer.layer_meta().note("elf_pt_load_skipped").unwrap(), 1);

        // And the range reads as a hole, not as the 0x400 captured bytes
        // followed by fabricated zeros.
        let mut buf = [0u8; 16];
        let err = layer.read_at(0x1000, &mut buf).expect_err("unmapped");
        assert_eq!(MemoryHole::from_io(&err).unwrap().address, 0x1000);
    }

    #[test]
    fn a_zero_length_pt_load_is_skipped_rather_than_breaking_the_segment_index() {
        let entries = [
            Entry {
                p_type: PT_LOAD,
                paddr: 0x8000,
                filesz: 0,
                memsz: 0,
                fill: 0,
            },
            Entry::load(0x0000, 0x1000, 0x77),
        ];
        let layer = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &entries,
            Overrides::default(),
        )))
        .expect("the empty entry is simply not a segment");
        assert_eq!(layer.segments().len(), 1);
        assert_eq!(layer.max_address(), 0xFFF);
    }

    // ── Truncated image ─────────────────────────────────────────────────────

    #[test]
    fn a_truncated_file_header_fails_closed() {
        let full = two_range_core(ElfClass::Elf64, Endian::Little, EM_X86_64);
        for cut in [0usize, 4, 15, 16, 40, EHDR64_LEN - 1] {
            let err = open(source(full[..cut].to_vec()))
                .expect_err("a header that is not all present must not parse");
            match err {
                FormatError::Io { .. } | FormatError::NotThisFormat { .. } => {}
                other => panic!("cut {cut} gave the wrong error: {other}"),
            }
        }
    }

    #[test]
    fn a_truncated_program_header_table_fails_closed_rather_than_parsing_zeros() {
        // The file header promises two program headers; the file stops inside
        // the second one. The zero tail must not be read as a PT_LOAD at
        // address zero.
        let full = two_range_core(ElfClass::Elf64, Endian::Little, EM_X86_64);
        let cut = EHDR64_LEN + PHDR64_LEN + 8;
        let err = open(source(full[..cut].to_vec())).expect_err("truncated program header table");
        match err {
            FormatError::Io {
                ref what,
                ref source,
                ..
            } => {
                assert!(what.contains("program header 1"), "names the entry: {what}");
                assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_core_whose_payload_is_missing_reports_an_honest_short_read() {
        // The program header table is intact and describes 0x2000 bytes of
        // memory, but the file ends after the first page. The layer is built —
        // the segment list is right — and the read stops honestly at the end of
        // the evidence rather than padding.
        let full = two_range_core(ElfClass::Elf64, Endian::Little, EM_X86_64);
        let cut = EHDR64_LEN + 2 * PHDR64_LEN + 0x1000 + 0x200;
        let layer = open(source(full[..cut].to_vec())).expect("the headers are all present");
        let mut page = vec![0u8; 0x1000];
        assert_eq!(
            layer.read_at(0x3000, &mut page).unwrap(),
            0x200,
            "the honest count, not the declared one"
        );
        let mut probe = [0u8; 0x400];
        let err = read_exact_or_fail(layer.as_data_source(), 0x3000, &mut probe, "page")
            .expect_err("truncated evidence must not parse");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_program_header_table_pointing_past_the_end_of_the_file_fails_closed() {
        let over = Overrides {
            e_phoff: Some(0x10_0000),
            ..Overrides::default()
        };
        let mut bytes = build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &[Entry::load(0, 0x1000, 0x5A)],
            over,
        );
        bytes.truncate(EHDR64_LEN + 0x100);
        let err = open(source(bytes)).expect_err("the table is not in the file");
        assert!(matches!(err, FormatError::Io { .. }));
    }

    // ── Malformed headers ───────────────────────────────────────────────────

    #[test]
    fn non_elf_bytes_are_not_claimed() {
        let err = open(source(vec![0x5A; 0x1000])).expect_err("no ELF magic");
        assert!(err.is_not_this_format());
        let mut wrong = two_range_core(ElfClass::Elf64, Endian::Little, EM_X86_64);
        wrong[1] = b'X';
        assert!(open(source(wrong)).unwrap_err().is_not_this_format());
    }

    #[test]
    fn ordinary_elf_executables_are_never_claimed_as_memory_images() {
        // ET_EXEC and ET_DYN are what an ingested disk image is full of.
        for e_type in [1u16 /* REL */, 2 /* EXEC */, 3 /* DYN */] {
            let over = Overrides {
                e_type,
                ..Overrides::default()
            };
            let err = open(source(build(
                ElfClass::Elf64,
                Endian::Little,
                EM_X86_64,
                &[Entry::load(0, 0x1000, 0x5A)],
                over,
            )))
            .expect_err("an ordinary ELF binary must not be claimed");
            assert!(err.is_not_this_format(), "e_type {e_type}: {err}");
        }
    }

    #[test]
    fn an_invalid_class_or_data_encoding_does_not_panic_and_is_not_claimed() {
        for (class, data) in [
            (Some(0u8), None),
            (Some(9), None),
            (None, Some(0)),
            (None, Some(7)),
        ] {
            let over = Overrides {
                ei_class: class,
                ei_data: data,
                ..Overrides::default()
            };
            let err = open(source(build(
                ElfClass::Elf64,
                Endian::Little,
                EM_X86_64,
                &[Entry::load(0, 0x1000, 0x5A)],
                over,
            )))
            .expect_err("an invalid e_ident must not parse");
            assert!(err.is_not_this_format(), "{err}");
        }
    }

    #[test]
    fn a_core_declaring_no_program_headers_is_refused() {
        let over = Overrides {
            e_phnum: Some(0),
            ..Overrides::default()
        };
        let err = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &[Entry::load(0, 0x1000, 0x5A)],
            over,
        )))
        .expect_err("a core with no program headers describes no memory");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn pn_xnum_is_refused_by_name_rather_than_parsing_65535_bogus_entries() {
        let over = Overrides {
            e_phnum: Some(PN_XNUM),
            ..Overrides::default()
        };
        let err = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &[Entry::load(0, 0x1000, 0x5A)],
            over,
        )))
        .expect_err("PN_XNUM is not supported");
        match err {
            FormatError::Unsupported { ref detail, .. } => assert!(detail.contains("PN_XNUM")),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn an_entry_size_below_the_class_minimum_is_refused() {
        let over = Overrides {
            e_phentsize: Some(16),
            ..Overrides::default()
        };
        let err = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &[Entry::load(0, 0x1000, 0x5A)],
            over,
        )))
        .expect_err("a stride shorter than the structure overlaps entries");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn an_absurd_program_header_offset_does_not_panic_or_allocate() {
        // e_phoff patched in place rather than built, so the fixture builder is
        // not asked to lay out a u64::MAX-byte file.
        let mut bytes = build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &[Entry::load(0, 0x1000, 0x5A)],
            Overrides::default(),
        );
        bytes[32..40].copy_from_slice(&(u64::MAX - 8).to_le_bytes()); // e_phoff
        bytes[56..58].copy_from_slice(&64u16.to_le_bytes()); // e_phnum
        let err = open(source(bytes)).expect_err("the table is nowhere near the file");
        match err {
            FormatError::Malformed { ref detail, .. } => assert!(detail.contains("overflows")),
            FormatError::Io { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_core_with_pt_load_entries_but_none_usable_is_refused() {
        let entries = [Entry {
            p_type: PT_LOAD,
            paddr: 0x1000,
            filesz: 0x100,
            memsz: 0x1000,
            fill: 0x33,
        }];
        let err = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &entries,
            Overrides::default(),
        )))
        .expect_err("nothing is mappable");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("no usable PT_LOAD"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_userland_process_core_is_named_rather_than_mapped_as_physical_memory() {
        // Every PT_LOAD of a process core has p_paddr == 0; the addresses live
        // in p_vaddr. Mapping it would present virtual memory as physical.
        let entries = [
            Entry::load(0, 0x1000, 0x11),
            Entry::load(0, 0x1000, 0x22),
            Entry::load(0, 0x1000, 0x33),
        ];
        let err = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &entries,
            Overrides::default(),
        )))
        .expect_err("a process core is not a memory image");
        match err {
            FormatError::Unsupported { ref detail, .. } => {
                assert!(detail.contains("p_vaddr"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn overlapping_pt_load_addresses_are_refused_rather_than_silently_resolved() {
        let entries = [
            Entry::load(0x1000, 0x1000, 0x11),
            Entry::load(0x1800, 0x1000, 0x22),
        ];
        let err = open(source(build(
            ElfClass::Elf64,
            Endian::Little,
            EM_X86_64,
            &entries,
            Overrides::default(),
        )))
        .expect_err("two sets of bytes cannot share one address");
        match err {
            FormatError::Layer { source, .. } => assert!(matches!(
                source,
                crate::layer::LayerError::OverlappingSegments { .. }
            )),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn an_empty_source_does_not_panic() {
        let err = open(source(Vec::new())).expect_err("nothing to read");
        assert!(matches!(err, FormatError::Io { .. }));
    }
}
