//! The PE reader discovery needs: enough of the Portable Executable format to
//! prove that an address holds the Windows kernel, and to read the CodeView
//! record that names the symbol file describing it.
//!
//! # Why constants are allowed here and nowhere else
//!
//! Everything else in this crate reads structure offsets out of the symbol
//! table, because a kernel structure's layout changes between Windows builds
//! and a hardcoded offset silently produces a confident wrong answer. PE is the
//! opposite kind of thing: it is a *published file format* whose header offsets
//! are fixed by the PE/COFF specification and identical in every image ever
//! linked. `e_lfanew` is at 0x3C in a file from 1993 and in a file from
//! yesterday. Reading it from a symbol table would be circular anyway — the
//! symbol table is the thing this module is trying to select.
//!
//! So the constants below are format constants, not layout guesses, and each
//! one is named after the specification field it comes from.
//!
//! # What an examiner learns from this module
//!
//! Two facts, and both are load-bearing:
//!
//! - **This address holds the kernel image.** Not "some 64-bit code", not "a
//!   driver": an image whose CodeView record names one of the four PDB files
//!   Windows kernels are built with. A wrong answer here anchors every symbol
//!   lookup in the case at the wrong address, and every subsequent finding —
//!   process list, module list, injected code — is then read out of unrelated
//!   memory and parses perfectly.
//! - **Which build it is.** The GUID and age of the kernel's PDB select the
//!   symbol file. A wrong GUID selects symbols for a different Windows build,
//!   and a different build puts `_EPROCESS.UniqueProcessId` at a different
//!   offset. That failure is invisible: the process list is full, the PIDs look
//!   like PIDs, and every one of them is garbage.
//!
//! Every read here therefore fails closed. A truncated header, a debug
//! directory that runs off the end of the image, a PDB name that is not ASCII —
//! each is an error naming what was wrong, never a default that lets the caller
//! proceed on a guess.

use std::sync::Arc;

use seance_core::io::read_exact_or_fail;
use seance_memory::layer::{MemoryHole, MemoryLayer};

/// PDB file names a Windows kernel is built with.
///
/// Uniprocessor, PAE, PAE-multiprocessor and the modern unified kernel. An
/// image whose CodeView record names none of these is not the kernel, however
/// well-formed its headers are, and accepting it would anchor the whole
/// analysis on a driver.
pub const KERNEL_PDB_NAMES: [&str; 4] = [
    "ntkrnlmp.pdb",
    "ntkrnlpa.pdb",
    "ntkrpamp.pdb",
    "ntoskrnl.pdb",
];

/// `IMAGE_DOS_HEADER.e_magic`.
pub const DOS_MAGIC: [u8; 2] = *b"MZ";
/// `IMAGE_NT_HEADERS.Signature`.
pub const NT_SIGNATURE: [u8; 4] = *b"PE\0\0";
/// Offset of `IMAGE_DOS_HEADER.e_lfanew`.
const E_LFANEW_OFFSET: usize = 0x3C;
/// Bytes of DOS header read to reach `e_lfanew`.
const DOS_HEADER_BYTES: usize = 0x40;
/// Largest `e_lfanew` this reader will follow.
///
/// The specification permits any value; a corrupt or hostile one would send the
/// reader an arbitrary distance into memory. 64 KiB is far beyond every real
/// DOS stub and keeps the follow bounded.
const MAX_E_LFANEW: u32 = 0x1_0000;
/// Offset of `IMAGE_FILE_HEADER` inside `IMAGE_NT_HEADERS`, i.e. just past the
/// four-byte signature.
const FILE_HEADER_OFFSET: usize = 4;
/// Size of `IMAGE_FILE_HEADER`.
const FILE_HEADER_BYTES: usize = 20;
/// Offset of `IMAGE_FILE_HEADER.Machine`.
const FILE_MACHINE_OFFSET: usize = 0;
/// Offset of `IMAGE_FILE_HEADER.SizeOfOptionalHeader`.
const FILE_SIZE_OF_OPTIONAL_OFFSET: usize = 0x10;
/// Offset of `IMAGE_OPTIONAL_HEADER` inside `IMAGE_NT_HEADERS`.
const OPTIONAL_HEADER_OFFSET: usize = FILE_HEADER_OFFSET + FILE_HEADER_BYTES;
/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`.
const PE32_MAGIC: u16 = 0x010B;
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
const PE32_PLUS_MAGIC: u16 = 0x020B;
/// Offset of `MajorOperatingSystemVersion`, identical in both optional-header
/// shapes because the 32/64 divergence starts later, at `ImageBase`.
const OPT_OS_MAJOR_OFFSET: usize = 0x28;
/// Offset of `MinorOperatingSystemVersion`.
const OPT_OS_MINOR_OFFSET: usize = 0x2A;
/// Offset of `SizeOfImage`, also identical in both shapes.
const OPT_SIZE_OF_IMAGE_OFFSET: usize = 0x38;
/// Offset of `NumberOfRvaAndSizes` in a PE32 optional header.
const OPT32_NUMBER_OF_RVA_OFFSET: usize = 0x5C;
/// Offset of `NumberOfRvaAndSizes` in a PE32+ optional header.
const OPT64_NUMBER_OF_RVA_OFFSET: usize = 0x6C;
/// Offset of `DataDirectory[0]` in a PE32 optional header.
const OPT32_DATA_DIRECTORY_OFFSET: usize = 0x60;
/// Offset of `DataDirectory[0]` in a PE32+ optional header.
const OPT64_DATA_DIRECTORY_OFFSET: usize = 0x70;
/// Size of one `IMAGE_DATA_DIRECTORY`.
const DATA_DIRECTORY_ENTRY_BYTES: usize = 8;
/// `IMAGE_DIRECTORY_ENTRY_EXPORT`.
const DIRECTORY_ENTRY_EXPORT: usize = 0;
/// `IMAGE_DIRECTORY_ENTRY_DEBUG`.
const DIRECTORY_ENTRY_DEBUG: usize = 6;
/// Size of one `IMAGE_DEBUG_DIRECTORY`.
const DEBUG_DIRECTORY_BYTES: usize = 28;
/// Offset of `IMAGE_DEBUG_DIRECTORY.Type`.
const DEBUG_TYPE_OFFSET: usize = 12;
/// Offset of `IMAGE_DEBUG_DIRECTORY.SizeOfData`.
const DEBUG_SIZE_OF_DATA_OFFSET: usize = 16;
/// Offset of `IMAGE_DEBUG_DIRECTORY.AddressOfRawData`, the RVA at which the
/// CodeView blob lives once the image is loaded.
const DEBUG_ADDRESS_OF_RAW_DATA_OFFSET: usize = 20;
/// `IMAGE_DEBUG_TYPE_CODEVIEW`.
const DEBUG_TYPE_CODEVIEW: u32 = 2;
/// Debug directory entries this reader will examine. A real kernel has fewer
/// than ten; the cap bounds a corrupt `SizeOfData`.
const MAX_DEBUG_ENTRIES: usize = 32;
/// Offset of `IMAGE_EXPORT_DIRECTORY.Name`.
const EXPORT_NAME_RVA_OFFSET: usize = 12;
/// Bytes of export-directory header read.
const EXPORT_DIRECTORY_BYTES: usize = 16;
/// Longest module name this reader will take from an export directory.
const MAX_EXPORT_NAME_BYTES: usize = 64;

/// Magic of a CodeView PDB 7.0 record.
pub const RSDS_MAGIC: [u8; 4] = *b"RSDS";
/// Bytes of an RSDS record before the PDB file name: magic, GUID and age.
pub const RSDS_FIXED_BYTES: usize = 4 + 16 + 4;
/// Longest PDB file name this reader will accept.
///
/// `MAX_PATH`. A record claiming more is either corrupt or an attempt to make
/// the reader allocate, and either way the name is not usable evidence.
pub const MAX_PDB_NAME_BYTES: usize = 260;

/// `IMAGE_FILE_MACHINE_I386`.
pub const MACHINE_I386: u16 = 0x014C;
/// `IMAGE_FILE_MACHINE_AMD64`.
pub const MACHINE_AMD64: u16 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`.
pub const MACHINE_ARM64: u16 = 0xAA64;

/// The CodeView identity of one PE image.
///
/// This triple is what selects a symbol file, and it is the only thing that
/// may: two Windows builds can share a kernel file name, a size and a
/// timestamp, but never a GUID. An examiner reading this in a report is reading
/// the answer to "how do you know these symbols describe this machine?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbIdentity {
    /// PDB file name with any path stripped, e.g. `ntkrnlmp.pdb`.
    pub pdb: String,
    /// PDB GUID, 32 uppercase hex characters, in the byte order a symbol server
    /// uses. See [`format_pdb_guid`] for why that order is not the raw one.
    pub guid: String,
    /// PDB age: how many times the PDB was rewritten for the same GUID.
    /// Symbol identity is GUID *and* age; two ages of one GUID are different
    /// files with different contents.
    pub age: u32,
}

impl PdbIdentity {
    /// The identity string an ISF declares, `{database}|{GUID}|{age}`.
    ///
    /// Compared byte-for-byte against
    /// [`seance_symbols::IsfMetadata::windows_identifier`]. There is no
    /// near-match tier: a symbol file that is close is a symbol file that is
    /// wrong.
    pub fn identifier(&self) -> String {
        format!("{}|{}|{}", self.pdb, self.guid, self.age)
    }

    /// Whether this names one of the PDB files a Windows kernel is built with.
    pub fn is_kernel(&self) -> bool {
        KERNEL_PDB_NAMES
            .iter()
            .any(|name| self.pdb.eq_ignore_ascii_case(name))
    }
}

/// A Windows kernel image located and proved at a known address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelImage {
    /// Address the image is loaded at, in the space it was read through.
    pub base: u64,
    /// The CodeView identity that selects its symbols.
    pub pdb: PdbIdentity,
    /// `IMAGE_FILE_HEADER.Machine`, so the caller can refuse a kernel whose
    /// word size disagrees with the paging mode the address space was built
    /// under. Those two disagreeing means one of them is wrong.
    pub machine: u16,
    /// Whether the optional header is PE32+.
    pub pe32_plus: bool,
    /// `SizeOfImage`, the span the loaded image occupies.
    pub size_of_image: u32,
    /// `MajorOperatingSystemVersion` from the optional header.
    ///
    /// The kernel's own statement of the Windows version it belongs to,
    /// available before any symbol table is loaded. It is coarser than
    /// `_KUSER_SHARED_DATA` — it carries no build number — so it is a floor,
    /// not a substitute.
    pub os_major: u32,
    /// `MinorOperatingSystemVersion`.
    pub os_minor: u32,
    /// The name in the export directory, when it had one. `ntoskrnl.exe` here
    /// corroborates the CodeView record from a second, independent structure.
    pub export_name: Option<String>,
}

impl KernelImage {
    /// Whether the machine field agrees with a 64-bit address space.
    pub fn is_64bit_machine(&self) -> bool {
        matches!(self.machine, MACHINE_AMD64 | MACHINE_ARM64)
    }

    /// Whether the export directory independently names an NT kernel.
    ///
    /// Corroboration only. Its absence is not evidence against the image: the
    /// export directory can be paged out while the headers are resident.
    pub fn export_name_is_kernel(&self) -> bool {
        match &self.export_name {
            Some(name) => {
                let lower = name.to_ascii_lowercase();
                lower.starts_with("ntoskrnl") || lower.starts_with("ntkr")
            }
            None => false,
        }
    }
}

/// Everything that can stop this module proving an image.
#[derive(Debug, thiserror::Error)]
pub enum PeError {
    /// Bytes the header needed are not in the evidence: unmapped, paged out or
    /// past the end of the acquisition. Never confused with "the field said
    /// zero".
    #[error("{what} at {address:#x} could not be read: {source}")]
    Unreadable {
        /// What was being read, in the examiner's terms.
        what: String,
        /// Where the read started.
        address: u64,
        /// The underlying failure, carrying a [`MemoryHole`] when there was one.
        #[source]
        source: std::io::Error,
    },

    /// The bytes were readable and are not a PE image, or not one this reader
    /// will follow.
    #[error("the image at {address:#x} is not a usable PE: {detail}")]
    NotPe {
        /// Where the image was expected.
        address: u64,
        /// Which specific check failed.
        detail: String,
    },

    /// The image is a PE but carries no CodeView record, so nothing names its
    /// symbol file. Distinct from [`PeError::NotPe`]: this *is* an image, it
    /// simply cannot be identified, and an examiner may want to know that a
    /// stripped kernel was found rather than no kernel at all.
    #[error("the PE image at {address:#x} has no CodeView (RSDS) debug record")]
    NoCodeView {
        /// Where the image is loaded.
        address: u64,
    },

    /// Address arithmetic on a value read out of the image left the addressable
    /// range. Always an error: a wrapped address is a wrong address, and
    /// following one reads an unrelated part of memory.
    #[error("address arithmetic for the image at {address:#x} overflowed: {detail}")]
    Overflow {
        /// Where the image is loaded.
        address: u64,
        /// Which computation overflowed.
        detail: String,
    },
}

impl PeError {
    /// The memory hole behind this failure, if the failure was one.
    ///
    /// Lets a caller record *which* bytes of the kernel header were missing,
    /// rather than only that identification failed.
    pub fn hole(&self) -> Option<MemoryHole> {
        match self {
            PeError::Unreadable { source, .. } => MemoryHole::from_io(source),
            _ => None,
        }
    }
}

/// Format the 16 raw bytes of a CodeView GUID the way a symbol server names it.
///
/// The record stores a `GUID`, whose first three fields are little-endian
/// integers and whose last is a byte array. The symbol-server name prints those
/// integers big-endian, so bytes 0..4 and 4..6 and 6..8 reverse and bytes 8..16
/// do not. Getting this wrong yields a GUID that is 32 valid hex characters,
/// matches nothing in any symbol store, and looks exactly like a missing symbol
/// pack rather than like a bug.
pub fn format_pdb_guid(raw: &[u8; 16]) -> String {
    const ORDER: [usize; 16] = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut out = String::with_capacity(32);
    for index in ORDER {
        // Two hex digits per byte, upper case, exactly as a symbol store names
        // the directory.
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let byte = raw[index];
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0F)] as char);
    }
    out
}

/// Decode a CodeView PDB 7.0 record from bytes already read out of the image.
///
/// `bytes` must begin at the `RSDS` magic. Returns `None` when the buffer does
/// not hold a well-formed record — a caller scanning memory sees a great many
/// byte sequences that begin plausibly and are not records, and each one must
/// be discarded rather than half-decoded.
pub fn parse_rsds(bytes: &[u8]) -> Option<PdbIdentity> {
    if bytes.len() <= RSDS_FIXED_BYTES {
        return None;
    }
    if bytes[..4] != RSDS_MAGIC {
        return None;
    }
    let mut guid_raw = [0u8; 16];
    guid_raw.copy_from_slice(&bytes[4..20]);
    let age = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

    let tail = &bytes[RSDS_FIXED_BYTES..];
    let end = tail.iter().position(|&b| b == 0)?;
    if end == 0 || end > MAX_PDB_NAME_BYTES {
        return None;
    }
    let name_bytes = &tail[..end];
    // A PDB name is an ASCII file path. Anything else is not a name that was
    // written by a linker, and a lossy conversion would put characters in the
    // case record that were never in the evidence.
    if !name_bytes
        .iter()
        .all(|&b| b.is_ascii_graphic() || b == b' ')
    {
        return None;
    }
    let full = std::str::from_utf8(name_bytes).ok()?;
    // Linkers embed the full build-machine path. Only the file name identifies
    // the symbol file, and the path leaks the build machine's directory layout
    // into every artifact that quotes it.
    let name = full
        .rsplit(['\\', '/'])
        .next()
        .filter(|n| !n.is_empty())?
        .to_string();

    Some(PdbIdentity {
        pdb: name,
        guid: format_pdb_guid(&guid_raw),
        age,
    })
}

/// Read exactly `len` bytes at `address`, or fail.
///
/// Never partially fills: a header half-read is a header whose fields cannot be
/// trusted, and a caller handed a buffer that is part evidence and part zeros
/// has no way to tell the two apart.
fn read_exact(
    layer: &dyn MemoryLayer,
    address: u64,
    len: usize,
    what: &str,
) -> Result<Vec<u8>, PeError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    // Guard the addition the read helper is about to do on our behalf, so an
    // address near the top of the space cannot turn a bounds check into an
    // arithmetic panic.
    if address.checked_add(len as u64).is_none() {
        return Err(PeError::Overflow {
            address,
            detail: format!(
                "reading {len} byte(s) of {what} runs past the top of the address space"
            ),
        });
    }
    let mut buf = vec![0u8; len];
    read_exact_or_fail(layer.as_data_source(), address, &mut buf, what).map_err(|source| {
        PeError::Unreadable {
            what: what.to_string(),
            address,
            source,
        }
    })?;
    Ok(buf)
}

fn u16_at(buf: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = buf.get(offset..end)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = buf.get(offset..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// An address inside a loaded image, from its base and a relative virtual
/// address.
fn rva_to_va(base: u64, rva: u32, what: &str) -> Result<u64, PeError> {
    base.checked_add(u64::from(rva))
        .ok_or_else(|| PeError::Overflow {
            address: base,
            detail: format!("the {what} RVA {rva:#x} does not fit above the image base"),
        })
}

/// Read and prove the PE image loaded at `base`, and recover its CodeView
/// identity.
///
/// This is the function that decides "yes, the kernel is here". It reads the
/// DOS header, follows `e_lfanew` to the NT headers, checks the signature and
/// the optional-header magic, walks the debug data directory to the CodeView
/// record, and decodes the GUID, age and PDB name.
///
/// It does **not** decide whether the image is the *kernel*: that is
/// [`PdbIdentity::is_kernel`], applied by the caller, because a caller looking
/// for a driver wants the same reader with a different name list.
///
/// # Errors
///
/// - [`PeError::Unreadable`] when a header byte is not in the evidence. This is
///   the common case while scanning: most addresses are not images, and most
///   pages near one that is are paged out. A caller sweeping candidates treats
///   it as "not here", never as "no kernel exists".
/// - [`PeError::NotPe`] when the bytes are present and are not a PE.
/// - [`PeError::NoCodeView`] when the image is real but carries no RSDS record,
///   so no symbol file can be named for it.
pub fn read_pe_image(layer: &dyn MemoryLayer, base: u64) -> Result<KernelImage, PeError> {
    let dos = read_exact(layer, base, DOS_HEADER_BYTES, "IMAGE_DOS_HEADER")?;
    if dos[..2] != DOS_MAGIC {
        return Err(PeError::NotPe {
            address: base,
            detail: "no MZ signature".to_string(),
        });
    }
    let lfanew = u32_at(&dos, E_LFANEW_OFFSET).ok_or_else(|| PeError::NotPe {
        address: base,
        detail: "the DOS header is too short to hold e_lfanew".to_string(),
    })?;
    if lfanew < DOS_HEADER_BYTES as u32 || lfanew > MAX_E_LFANEW {
        return Err(PeError::NotPe {
            address: base,
            detail: format!("e_lfanew {lfanew:#x} is not a plausible NT header offset"),
        });
    }
    let nt_address = rva_to_va(base, lfanew, "e_lfanew")?;

    let nt = read_exact(
        layer,
        nt_address,
        OPTIONAL_HEADER_OFFSET,
        "IMAGE_NT_HEADERS signature and file header",
    )?;
    if nt[..4] != NT_SIGNATURE {
        return Err(PeError::NotPe {
            address: base,
            detail: format!("no PE\\0\\0 signature at e_lfanew {lfanew:#x}"),
        });
    }
    let machine =
        u16_at(&nt, FILE_HEADER_OFFSET + FILE_MACHINE_OFFSET).ok_or_else(|| PeError::NotPe {
            address: base,
            detail: "the file header is too short to hold Machine".to_string(),
        })?;
    let size_of_optional = u16_at(&nt, FILE_HEADER_OFFSET + FILE_SIZE_OF_OPTIONAL_OFFSET)
        .ok_or_else(|| PeError::NotPe {
            address: base,
            detail: "the file header is too short to hold SizeOfOptionalHeader".to_string(),
        })?;
    // Anything shorter than a PE32 data directory cannot carry a debug
    // directory, so there is nothing here to identify the image with.
    if usize::from(size_of_optional) < OPT32_DATA_DIRECTORY_OFFSET {
        return Err(PeError::NotPe {
            address: base,
            detail: format!(
                "SizeOfOptionalHeader {size_of_optional} is too small to hold a data directory"
            ),
        });
    }

    let optional_address = nt_address
        .checked_add(OPTIONAL_HEADER_OFFSET as u64)
        .ok_or_else(|| PeError::Overflow {
            address: base,
            detail: "the optional header does not fit above the NT headers".to_string(),
        })?;
    let optional = read_exact(
        layer,
        optional_address,
        usize::from(size_of_optional),
        "IMAGE_OPTIONAL_HEADER",
    )?;

    let magic = u16_at(&optional, 0).ok_or_else(|| PeError::NotPe {
        address: base,
        detail: "the optional header is too short to hold its magic".to_string(),
    })?;
    let pe32_plus = match magic {
        PE32_MAGIC => false,
        PE32_PLUS_MAGIC => true,
        other => {
            return Err(PeError::NotPe {
                address: base,
                detail: format!("optional header magic {other:#x} is neither PE32 nor PE32+"),
            })
        }
    };

    let os_major = u32::from(u16_at(&optional, OPT_OS_MAJOR_OFFSET).unwrap_or(0));
    let os_minor = u32::from(u16_at(&optional, OPT_OS_MINOR_OFFSET).unwrap_or(0));
    let size_of_image = u32_at(&optional, OPT_SIZE_OF_IMAGE_OFFSET).unwrap_or(0);

    let (rva_count_offset, data_directory_offset) = if pe32_plus {
        (OPT64_NUMBER_OF_RVA_OFFSET, OPT64_DATA_DIRECTORY_OFFSET)
    } else {
        (OPT32_NUMBER_OF_RVA_OFFSET, OPT32_DATA_DIRECTORY_OFFSET)
    };
    let rva_count = u32_at(&optional, rva_count_offset).ok_or_else(|| PeError::NotPe {
        address: base,
        detail: "the optional header is too short to hold NumberOfRvaAndSizes".to_string(),
    })?;

    let pdb = read_codeview(layer, base, &optional, data_directory_offset, rva_count)?;
    let export_name = read_export_name(layer, base, &optional, data_directory_offset, rva_count);

    Ok(KernelImage {
        base,
        pdb,
        machine,
        pe32_plus,
        size_of_image,
        os_major,
        os_minor,
        export_name,
    })
}

/// One `IMAGE_DATA_DIRECTORY`, if the optional header really declares it.
///
/// Returns `None` rather than zeros for a directory the header does not have:
/// `NumberOfRvaAndSizes` genuinely varies, and reading past it would take
/// whatever bytes follow the header as an RVA.
fn data_directory(
    optional: &[u8],
    data_directory_offset: usize,
    rva_count: u32,
    index: usize,
) -> Option<(u32, u32)> {
    if index as u64 >= u64::from(rva_count) {
        return None;
    }
    let entry =
        data_directory_offset.checked_add(index.checked_mul(DATA_DIRECTORY_ENTRY_BYTES)?)?;
    let rva = u32_at(optional, entry)?;
    let size = u32_at(optional, entry.checked_add(4)?)?;
    if rva == 0 {
        return None;
    }
    Some((rva, size))
}

/// Walk the debug directory to the CodeView record and decode it.
fn read_codeview(
    layer: &dyn MemoryLayer,
    base: u64,
    optional: &[u8],
    data_directory_offset: usize,
    rva_count: u32,
) -> Result<PdbIdentity, PeError> {
    let Some((debug_rva, debug_size)) = data_directory(
        optional,
        data_directory_offset,
        rva_count,
        DIRECTORY_ENTRY_DEBUG,
    ) else {
        return Err(PeError::NoCodeView { address: base });
    };

    let entries = (debug_size as usize / DEBUG_DIRECTORY_BYTES).min(MAX_DEBUG_ENTRIES);
    if entries == 0 {
        return Err(PeError::NoCodeView { address: base });
    }
    let table_address = rva_to_va(base, debug_rva, "debug directory")?;
    let table = read_exact(
        layer,
        table_address,
        entries.saturating_mul(DEBUG_DIRECTORY_BYTES),
        "IMAGE_DEBUG_DIRECTORY",
    )?;

    for index in 0..entries {
        let at = index * DEBUG_DIRECTORY_BYTES;
        let Some(kind) = u32_at(&table, at + DEBUG_TYPE_OFFSET) else {
            break;
        };
        if kind != DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let Some(raw_rva) = u32_at(&table, at + DEBUG_ADDRESS_OF_RAW_DATA_OFFSET) else {
            continue;
        };
        if raw_rva == 0 {
            continue;
        }
        let declared = u32_at(&table, at + DEBUG_SIZE_OF_DATA_OFFSET).unwrap_or(0) as usize;
        // Read what the entry declares, bounded: a corrupt SizeOfData must not
        // become an allocation, and a record longer than a fixed header plus a
        // maximum path is not a record.
        let want = declared.clamp(
            RSDS_FIXED_BYTES + 1,
            RSDS_FIXED_BYTES + MAX_PDB_NAME_BYTES + 1,
        );
        let record_address = rva_to_va(base, raw_rva, "CodeView record")?;
        let record = read_exact(layer, record_address, want, "CodeView record")?;
        if let Some(identity) = parse_rsds(&record) {
            return Ok(identity);
        }
    }
    Err(PeError::NoCodeView { address: base })
}

/// The module name in the export directory, when it is readable.
///
/// Deliberately infallible from the caller's point of view: this is
/// corroboration, and an export directory that is paged out says nothing about
/// whether the image is the kernel. Absence is reported as `None`, never as an
/// empty string that a report might render as a name.
fn read_export_name(
    layer: &dyn MemoryLayer,
    base: u64,
    optional: &[u8],
    data_directory_offset: usize,
    rva_count: u32,
) -> Option<String> {
    let (export_rva, _) = data_directory(
        optional,
        data_directory_offset,
        rva_count,
        DIRECTORY_ENTRY_EXPORT,
    )?;
    let directory_address = rva_to_va(base, export_rva, "export directory").ok()?;
    let directory = read_exact(
        layer,
        directory_address,
        EXPORT_DIRECTORY_BYTES,
        "IMAGE_EXPORT_DIRECTORY",
    )
    .ok()?;
    let name_rva = u32_at(&directory, EXPORT_NAME_RVA_OFFSET)?;
    if name_rva == 0 {
        return None;
    }
    let name_address = rva_to_va(base, name_rva, "export directory name").ok()?;
    let bytes = read_exact(
        layer,
        name_address,
        MAX_EXPORT_NAME_BYTES,
        "export directory name",
    )
    .ok()?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let name = bytes.get(..end)?;
    if name.is_empty() || !name.iter().all(|&b| b.is_ascii_graphic()) {
        return None;
    }
    std::str::from_utf8(name).ok().map(str::to_string)
}

/// Search backwards from `address` for the page holding an `MZ` signature.
///
/// The CodeView record lives in the image's debug section, some way above its
/// headers, and both are page-aligned in the space they were read through. So
/// the image base is the nearest page at or below the record that starts `MZ`.
///
/// Bounded twice, because both bounds guard a different failure:
///
/// - `max_pages` caps how far back the search goes at all, so a record that
///   belongs to no image cannot walk the reader to the bottom of the address
///   space.
/// - `max_unreadable` caps consecutive unreadable pages, so a search that has
///   left the image's mapped region stops instead of grinding through gigabytes
///   of holes.
///
/// Returns `None` when neither bound was reached and no `MZ` was found, and
/// when a bound fired — the caller cannot use a base it did not find either
/// way, and the distinction belongs to the log, not to the answer.
pub fn find_image_base_below(
    layer: &dyn MemoryLayer,
    address: u64,
    page_size: u64,
    max_pages: u64,
    max_unreadable: u64,
) -> Option<u64> {
    if page_size == 0 {
        return None;
    }
    let mut page = address - (address % page_size);
    let mut unreadable = 0u64;
    for _ in 0..max_pages {
        let mut magic = [0u8; 2];
        match read_exact_or_fail(layer.as_data_source(), page, &mut magic, "MZ probe") {
            Ok(()) => {
                unreadable = 0;
                if magic == DOS_MAGIC {
                    return Some(page);
                }
            }
            Err(_) => {
                unreadable = unreadable.saturating_add(1);
                if unreadable > max_unreadable {
                    return None;
                }
            }
        }
        page = page.checked_sub(page_size)?;
    }
    None
}

/// A memory layer as a [`seance_symbols::ImageProbe`], so symbol admission's
/// gate 4 can read typed fields out of the image it is being admitted against.
///
/// The one rule an implementor must not break is that an unbacked byte is an
/// error rather than a zero: gate 4's whole job is to falsify a wrong symbol
/// table, and fabricated zeros satisfy almost any sanity check.
#[derive(Debug)]
pub struct LayerProbe {
    layer: Arc<dyn MemoryLayer>,
    pointer_size: u8,
    identifier: Option<String>,
}

impl LayerProbe {
    /// A probe over `layer`, whose pointers are `pointer_size` bytes wide and
    /// whose kernel identified itself as `identifier`.
    pub fn new(layer: Arc<dyn MemoryLayer>, pointer_size: u8, identifier: Option<String>) -> Self {
        Self {
            layer,
            pointer_size,
            identifier,
        }
    }
}

impl seance_symbols::ImageProbe for LayerProbe {
    fn read_exact(&self, address: u64, buf: &mut [u8]) -> seance_symbols::probe::ProbeResult<()> {
        use seance_symbols::probe::ProbeError;
        if address.checked_add(buf.len() as u64).is_none() {
            return Err(ProbeError::Unavailable(format!(
                "reading {} byte(s) at {address:#x} runs past the top of the address space",
                buf.len()
            )));
        }
        read_exact_or_fail(
            self.layer.as_data_source(),
            address,
            buf,
            "symbol gate read",
        )
        .map_err(|err| match MemoryHole::from_io(&err) {
            Some(hole) => ProbeError::Unmapped {
                address: hole.address,
                length: hole.length,
                reason: hole.reason.as_str().to_string(),
            },
            None => ProbeError::Io(err.to_string()),
        })
    }

    fn pointer_size(&self) -> u8 {
        self.pointer_size
    }

    fn image_identifier(&self) -> Option<String> {
        self.identifier.clone()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Bytes of a synthetic loaded PE image: DOS header, NT headers, an
    /// optional header with a debug data directory, one CodeView debug entry
    /// and an RSDS record.
    ///
    /// Laid out as the loader would leave it — RVAs are offsets from the image
    /// base — so a layer serving these bytes at `base` behaves exactly as a
    /// mapped kernel does.
    pub(crate) struct PeBuilder {
        pub pe32_plus: bool,
        pub machine: u16,
        pub pdb_name: &'static str,
        pub guid_raw: [u8; 16],
        pub age: u32,
        pub os_major: u16,
        pub os_minor: u16,
        pub export_name: Option<&'static str>,
        pub debug_type: u32,
    }

    impl Default for PeBuilder {
        fn default() -> Self {
            Self {
                pe32_plus: true,
                machine: MACHINE_AMD64,
                pdb_name: "ntkrnlmp.pdb",
                guid_raw: [
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                    0xEE, 0xFF, 0x00,
                ],
                age: 1,
                os_major: 10,
                os_minor: 0,
                export_name: Some("ntoskrnl.exe"),
                debug_type: DEBUG_TYPE_CODEVIEW,
            }
        }
    }

    /// Fixed layout of the synthetic image, in RVAs.
    pub(crate) const NT_RVA: usize = 0x100;
    pub(crate) const DEBUG_TABLE_RVA: u32 = 0x400;
    pub(crate) const CODEVIEW_RVA: u32 = 0x500;
    pub(crate) const EXPORT_RVA: u32 = 0x600;
    pub(crate) const EXPORT_NAME_RVA: u32 = 0x640;
    pub(crate) const IMAGE_BYTES: usize = 0x1000;

    impl PeBuilder {
        pub(crate) fn build(&self) -> Vec<u8> {
            let mut image = vec![0u8; IMAGE_BYTES];
            image[0..2].copy_from_slice(&DOS_MAGIC);
            image[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4]
                .copy_from_slice(&(NT_RVA as u32).to_le_bytes());

            image[NT_RVA..NT_RVA + 4].copy_from_slice(&NT_SIGNATURE);
            let file = NT_RVA + FILE_HEADER_OFFSET;
            image[file..file + 2].copy_from_slice(&self.machine.to_le_bytes());

            let optional = NT_RVA + OPTIONAL_HEADER_OFFSET;
            let (magic, rva_count_offset, data_directory_offset) = if self.pe32_plus {
                (
                    PE32_PLUS_MAGIC,
                    OPT64_NUMBER_OF_RVA_OFFSET,
                    OPT64_DATA_DIRECTORY_OFFSET,
                )
            } else {
                (
                    PE32_MAGIC,
                    OPT32_NUMBER_OF_RVA_OFFSET,
                    OPT32_DATA_DIRECTORY_OFFSET,
                )
            };
            let optional_size = data_directory_offset + 16 * DATA_DIRECTORY_ENTRY_BYTES;
            image[file + FILE_SIZE_OF_OPTIONAL_OFFSET..file + FILE_SIZE_OF_OPTIONAL_OFFSET + 2]
                .copy_from_slice(&(optional_size as u16).to_le_bytes());

            image[optional..optional + 2].copy_from_slice(&magic.to_le_bytes());
            image[optional + OPT_OS_MAJOR_OFFSET..optional + OPT_OS_MAJOR_OFFSET + 2]
                .copy_from_slice(&self.os_major.to_le_bytes());
            image[optional + OPT_OS_MINOR_OFFSET..optional + OPT_OS_MINOR_OFFSET + 2]
                .copy_from_slice(&self.os_minor.to_le_bytes());
            image[optional + OPT_SIZE_OF_IMAGE_OFFSET..optional + OPT_SIZE_OF_IMAGE_OFFSET + 4]
                .copy_from_slice(&(IMAGE_BYTES as u32).to_le_bytes());
            image[optional + rva_count_offset..optional + rva_count_offset + 4]
                .copy_from_slice(&16u32.to_le_bytes());

            let debug_dir = optional
                + data_directory_offset
                + DIRECTORY_ENTRY_DEBUG * DATA_DIRECTORY_ENTRY_BYTES;
            image[debug_dir..debug_dir + 4].copy_from_slice(&DEBUG_TABLE_RVA.to_le_bytes());
            image[debug_dir + 4..debug_dir + 8]
                .copy_from_slice(&(DEBUG_DIRECTORY_BYTES as u32).to_le_bytes());

            let entry = DEBUG_TABLE_RVA as usize;
            image[entry + DEBUG_TYPE_OFFSET..entry + DEBUG_TYPE_OFFSET + 4]
                .copy_from_slice(&self.debug_type.to_le_bytes());
            let record_len = RSDS_FIXED_BYTES + self.pdb_name.len() + 1;
            image[entry + DEBUG_SIZE_OF_DATA_OFFSET..entry + DEBUG_SIZE_OF_DATA_OFFSET + 4]
                .copy_from_slice(&(record_len as u32).to_le_bytes());
            image[entry + DEBUG_ADDRESS_OF_RAW_DATA_OFFSET
                ..entry + DEBUG_ADDRESS_OF_RAW_DATA_OFFSET + 4]
                .copy_from_slice(&CODEVIEW_RVA.to_le_bytes());

            let record = CODEVIEW_RVA as usize;
            image[record..record + 4].copy_from_slice(&RSDS_MAGIC);
            image[record + 4..record + 20].copy_from_slice(&self.guid_raw);
            image[record + 20..record + 24].copy_from_slice(&self.age.to_le_bytes());
            let name = self.pdb_name.as_bytes();
            image[record + 24..record + 24 + name.len()].copy_from_slice(name);

            if let Some(export) = self.export_name {
                let export_dir = optional
                    + data_directory_offset
                    + DIRECTORY_ENTRY_EXPORT * DATA_DIRECTORY_ENTRY_BYTES;
                image[export_dir..export_dir + 4].copy_from_slice(&EXPORT_RVA.to_le_bytes());
                image[export_dir + 4..export_dir + 8]
                    .copy_from_slice(&(EXPORT_DIRECTORY_BYTES as u32).to_le_bytes());
                let dir = EXPORT_RVA as usize;
                image[dir + EXPORT_NAME_RVA_OFFSET..dir + EXPORT_NAME_RVA_OFFSET + 4]
                    .copy_from_slice(&EXPORT_NAME_RVA.to_le_bytes());
                let at = EXPORT_NAME_RVA as usize;
                image[at..at + export.len()].copy_from_slice(export.as_bytes());
            }
            image
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::PhysicalLayer;

    fn layer_of(bytes: Vec<u8>) -> Arc<dyn MemoryLayer> {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        Arc::new(PhysicalLayer::raw(source).expect("non-empty"))
    }

    #[test]
    fn a_codeview_guid_is_printed_in_symbol_server_order_not_raw_order() {
        // The first three GUID fields are little-endian integers and the fourth
        // is a byte array, so bytes 0..8 reorder and bytes 8..16 do not. A raw
        // hex dump of the same sixteen bytes matches nothing in any symbol
        // store, and looks exactly like a missing symbol pack.
        let raw = [
            0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        assert_eq!(format_pdb_guid(&raw), "123456789ABCDEF00102030405060708");
    }

    #[test]
    fn an_rsds_record_yields_the_pdb_name_guid_and_age() {
        let builder = PeBuilder::default();
        let image = builder.build();
        let record = &image[CODEVIEW_RVA as usize..];
        let identity = parse_rsds(record).expect("a well-formed record");
        assert_eq!(identity.pdb, "ntkrnlmp.pdb");
        assert_eq!(identity.age, 1);
        assert_eq!(identity.guid.len(), 32);
        assert!(identity.guid.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(identity.guid.chars().all(|c| !c.is_ascii_lowercase()));
        assert_eq!(
            identity.identifier(),
            format!("ntkrnlmp.pdb|{}|1", identity.guid)
        );
        assert!(identity.is_kernel());
    }

    #[test]
    fn an_rsds_record_keeps_only_the_file_name_of_a_build_machine_path() {
        let mut record = Vec::new();
        record.extend_from_slice(&RSDS_MAGIC);
        record.extend_from_slice(&[0u8; 16]);
        record.extend_from_slice(&7u32.to_le_bytes());
        record.extend_from_slice(br"d:\build\obj\amd64\ntkrnlmp.pdb");
        record.push(0);
        let identity = parse_rsds(&record).expect("a well-formed record");
        assert_eq!(identity.pdb, "ntkrnlmp.pdb");
        assert_eq!(identity.age, 7);
    }

    #[test]
    fn a_record_without_a_terminator_or_with_binary_in_its_name_is_not_a_record() {
        // Both of these appear constantly while sweeping memory for RSDS
        // magic. Half-decoding either would put a fabricated PDB name into the
        // symbol search and, if it happened to match a file, load the wrong
        // symbols.
        let mut unterminated = Vec::new();
        unterminated.extend_from_slice(&RSDS_MAGIC);
        unterminated.extend_from_slice(&[0u8; 16]);
        unterminated.extend_from_slice(&1u32.to_le_bytes());
        unterminated.extend_from_slice(b"ntoskrnl.pdb");
        assert!(parse_rsds(&unterminated).is_none());

        let mut binary = unterminated.clone();
        binary.truncate(RSDS_FIXED_BYTES);
        binary.extend_from_slice(&[0x01, 0x02, 0x03, 0x00]);
        assert!(parse_rsds(&binary).is_none());

        let mut empty_name = unterminated.clone();
        empty_name.truncate(RSDS_FIXED_BYTES);
        empty_name.push(0);
        assert!(parse_rsds(&empty_name).is_none());

        assert!(parse_rsds(b"RSDS").is_none());
        assert!(parse_rsds(b"NB10 and then some other bytes entirely").is_none());
    }

    #[test]
    fn a_synthetic_kernel_image_is_read_end_to_end() {
        let image = PeBuilder::default().build();
        let layer = layer_of(image);
        let found = read_pe_image(&*layer, 0).expect("the image is well-formed");
        assert_eq!(found.pdb.pdb, "ntkrnlmp.pdb");
        assert_eq!(found.pdb.age, 1);
        assert!(found.pdb.is_kernel());
        assert!(found.pe32_plus);
        assert!(found.is_64bit_machine());
        assert_eq!(found.os_major, 10);
        assert_eq!(found.os_minor, 0);
        assert_eq!(found.size_of_image, IMAGE_BYTES as u32);
        assert_eq!(found.export_name.as_deref(), Some("ntoskrnl.exe"));
        assert!(found.export_name_is_kernel());
    }

    #[test]
    fn a_thirty_two_bit_kernel_image_is_read_through_the_pe32_data_directory() {
        // The data directory sits at a different offset in a PE32 optional
        // header. A reader that assumed PE32+ would read the debug directory
        // RVA out of SizeOfHeapCommit and follow it somewhere arbitrary.
        let image = PeBuilder {
            pe32_plus: false,
            machine: MACHINE_I386,
            pdb_name: "ntkrpamp.pdb",
            os_major: 5,
            os_minor: 1,
            ..PeBuilder::default()
        }
        .build();
        let layer = layer_of(image);
        let found = read_pe_image(&*layer, 0).expect("the image is well-formed");
        assert_eq!(found.pdb.pdb, "ntkrpamp.pdb");
        assert!(!found.pe32_plus);
        assert!(!found.is_64bit_machine());
        assert_eq!((found.os_major, found.os_minor), (5, 1));
    }

    #[test]
    fn bytes_that_are_not_an_image_are_refused_rather_than_half_parsed() {
        let layer = layer_of(vec![0x00; 0x1000]);
        match read_pe_image(&*layer, 0) {
            Err(PeError::NotPe { detail, .. }) => assert!(detail.contains("MZ")),
            other => panic!("expected NotPe, got {other:?}"),
        }

        // MZ present, e_lfanew nonsense: the follow must not happen.
        let mut bytes = vec![0u8; 0x1000];
        bytes[0..2].copy_from_slice(&DOS_MAGIC);
        bytes[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let layer = layer_of(bytes);
        match read_pe_image(&*layer, 0) {
            Err(PeError::NotPe { detail, .. }) => assert!(detail.contains("e_lfanew")),
            other => panic!("expected NotPe, got {other:?}"),
        }
    }

    #[test]
    fn an_image_whose_debug_entry_is_not_codeview_yields_no_identity() {
        // A kernel with only a POGO or REPRO debug entry cannot be identified,
        // and saying so is different from saying no kernel was found.
        let image = PeBuilder {
            debug_type: 13,
            ..PeBuilder::default()
        }
        .build();
        let layer = layer_of(image);
        match read_pe_image(&*layer, 0) {
            Err(PeError::NoCodeView { address }) => assert_eq!(address, 0),
            other => panic!("expected NoCodeView, got {other:?}"),
        }
    }

    #[test]
    fn a_header_that_is_not_in_the_evidence_is_unreadable_not_absent() {
        // The distinction the whole crate rests on: "we could not read the
        // kernel header" and "there is no kernel here" are different findings.
        let layer = layer_of(PeBuilder::default().build());
        let err = read_pe_image(&*layer, 0x1000).expect_err("past the end of the layer");
        assert!(matches!(err, PeError::Unreadable { .. }), "{err:?}");
    }

    #[test]
    fn the_image_base_is_the_nearest_mz_page_at_or_below_a_record() {
        let mut bytes = vec![0u8; 0x8000];
        bytes[0x3000..0x3002].copy_from_slice(&DOS_MAGIC);
        let layer = layer_of(bytes);
        // A record at 0x3500 belongs to the image whose header is at 0x3000.
        assert_eq!(
            find_image_base_below(&*layer, 0x3500, 0x1000, 64, 8),
            Some(0x3000)
        );
        // A record below every header finds nothing rather than inventing one.
        assert_eq!(find_image_base_below(&*layer, 0x2500, 0x1000, 64, 8), None);
    }

    #[test]
    fn the_backward_search_stops_at_its_page_budget_rather_than_walking_to_zero() {
        let mut bytes = vec![0u8; 0x100000];
        bytes[0..2].copy_from_slice(&DOS_MAGIC);
        let layer = layer_of(bytes);
        // The only MZ is 255 pages below, and the budget is 4.
        assert_eq!(find_image_base_below(&*layer, 0xFF000, 0x1000, 4, 64), None);
        // With a budget that reaches it, the same search succeeds, which proves
        // the budget and not the data was what stopped it.
        assert_eq!(
            find_image_base_below(&*layer, 0xFF000, 0x1000, 256, 64),
            Some(0)
        );
    }

    #[test]
    fn a_page_size_of_zero_cannot_make_the_backward_search_divide_or_loop() {
        let layer = layer_of(vec![0u8; 0x1000]);
        assert_eq!(find_image_base_below(&*layer, 0x800, 0, 64, 8), None);
    }

    #[test]
    fn the_probe_reports_a_hole_as_unmapped_rather_than_filling_the_buffer() {
        use seance_symbols::ImageProbe;
        let layer = layer_of(vec![0xAB; 0x1000]);
        let probe = LayerProbe::new(layer, 8, Some("ntkrnlmp.pdb|A|1".to_string()));
        let mut buf = [0u8; 8];
        probe.read_exact(0, &mut buf).expect("mapped");
        assert!(buf.iter().all(|&b| b == 0xAB));

        let mut buf = [0u8; 8];
        let err = probe
            .read_exact(0x2000, &mut buf)
            .expect_err("above the layer");
        assert_eq!(err.class(), "io");
        assert!(buf.iter().all(|&b| b == 0), "the buffer must be untouched");
        assert_eq!(probe.pointer_size(), 8);
        assert_eq!(
            probe.image_identifier().as_deref(),
            Some("ntkrnlmp.pdb|A|1")
        );
    }
}
