//! Finding the kernel image in an address space that has only just started to
//! make sense.
//!
//! # The problem
//!
//! Once a directory table base is in hand there is a virtual address space, but
//! nothing in it is labelled. Symbol addresses in a Windows ISF are *relative*
//! to the kernel image's load address, so until that address is known the symbol
//! table cannot resolve a single global. Discovery therefore has to find one
//! specific PE image — `ntoskrnl.exe` — in a space whose contents it cannot yet
//! interpret.
//!
//! # What a wrong answer looks like
//!
//! A kernel base that is out by one page is not a crash. Every symbol resolves
//! to an address 4 KiB away from the structure it names, every structure read
//! there is unrelated memory, and every field parses. The process list comes
//! back full of processes that never existed. So each method below produces a
//! *candidate*, and a candidate becomes an answer only when
//! [`crate::automagic::pe::read_pe_image`] reads a complete PE header at it whose
//! CodeView record names one of the four kernel PDB files. Nothing here trusts a
//! pointer because of where it was found.
//!
//! # The four methods, strongest first
//!
//! | Method | Where it looks | What it rests on |
//! |---|---|---|
//! | [`find_low_stub`] | physical, below 1 MiB | the x64 boot `PROCESSOR_START_BLOCK`, which also publishes CR3 |
//! | [`scan_kdbg_tags`] | physical, whole image | the `KDBG` owner tag of the debugger data block, whose `KernBase` names the kernel |
//! | [`fixed_mapping_candidates`] | physical, whole image | the kernel's CodeView record, plus the boot-time identity mapping |
//! | [`virtual_scan_candidates`] | the kernel half of the virtual space | the kernel's CodeView record, found where it actually lives |
//!
//! Each is independent of the others, which is the point: an image where one
//! method fails — a hypervisor with no low stub, a build with the debugger block
//! paged out, a kernel that KASLR moved off the identity mapping — is usually an
//! image where another succeeds, and disagreement between two of them is
//! something an examiner should see rather than something to average away.

use std::collections::HashSet;
use std::ops::Range;

use seance_core::io::read_exact_or_fail;
use seance_memory::layer::MemoryLayer;
use seance_memory::scan::{scan_layer, scan_range, MultiStringScanner, ScanConfig, ScanError};
use seance_memory::translate::VirtualLayer;

use crate::automagic::pe::{find_image_base_below, read_pe_image, KernelImage, PeError, DOS_MAGIC};

/// Page size every structure here is aligned to.
pub const PAGE_SIZE: u64 = 4096;

/// CodeView PDB names a Windows kernel is built with, as scan needles.
///
/// The record embeds the name as a NUL-terminated ASCII string, so the name is
/// findable in memory even when the image's headers are paged out. Matching the
/// name alone proves nothing — a driver's import table can contain the same
/// bytes — which is why every hit is followed back to a PE header and proved
/// there.
pub const KERNEL_PDB_NEEDLES: [&[u8]; 4] = [
    b"ntkrnlmp.pdb",
    b"ntkrnlpa.pdb",
    b"ntkrpamp.pdb",
    b"ntoskrnl.pdb",
];

/// ASCII owner tag of the kernel debugger data block, as it sits in memory.
pub const KDBG_TAG: &[u8; 4] = b"KDBG";

/// Distance from the `KDBG` owner tag to the `KernBase` field that follows it.
///
/// The debugger data block is a *debugger interface* rather than an internal
/// kernel structure: `_DBGKD_DEBUG_DATA_HEADER64` is `{ LIST_ENTRY64 List;
/// ULONG OwnerTag; ULONG Size; }` and `_KDDEBUGGER_DATA64.KernBase` follows it,
/// so `KernBase` sits eight bytes past the tag. The 32-bit block uses
/// `LIST_ENTRY32` and a `ULONG` `KernBase`, and the distance from the tag works
/// out to the same eight bytes.
///
/// This is the only structure offset in the crate not taken from the symbol
/// table, and it is here because a Windows kernel PDB does not describe this
/// structure at all — Volatility ships a separate hand-written ISF for it, and
/// there is nothing to look the offset up in. Stating it is safe only because
/// nothing is believed on its account: the pointer read here is a *candidate*,
/// discarded unless a kernel PE header proves out at it.
pub const KDBG_TAG_TO_KERN_BASE: u64 = 8;

/// Distance from the `KDBG` owner tag back to the start of the 64-bit block.
pub const KDBG_TAG_TO_BLOCK_X64: u64 = 16;
/// Distance from the `KDBG` owner tag back to the start of the 32-bit block.
pub const KDBG_TAG_TO_BLOCK_X86: u64 = 8;

/// `PROCESSOR_START_BLOCK->Jmp->OpCode | Offset | CompletionFlag`, the
/// signature that identifies the x64 low stub.
pub const LOW_STUB_SIGNATURE: u64 = 0x0000_0001_0006_00E9;
/// Bits of the first low-stub quadword that are compared. The bits masked out
/// are the ones that vary between machines.
pub const LOW_STUB_SIGNATURE_MASK: u64 = 0xFFFF_FFFF_FFFF_00FF;
/// `PROCESSOR_START_BLOCK->LmTarget`, an address inside the kernel image.
pub const LOW_STUB_LM_TARGET_OFFSET: u64 = 0x70;
/// `PROCESSOR_START_BLOCK->ProcessorState->SpecialRegisters->Cr3`.
pub const LOW_STUB_CR3_OFFSET: u64 = 0xA0;
/// Top of the region the low stub is searched in. The stub lives in the first
/// megabyte of physical memory, from the second page onwards.
pub const LOW_STUB_SEARCH_TOP: u64 = 0x10_0000;
/// Size of the 2 MiB blocks the descent from a low-stub hint steps through.
pub const LOW_STUB_BLOCK: u64 = 0x20_0000;
/// How far below the hint the descent will go: 32 MiB, as upstream does.
pub const LOW_STUB_DESCENT_SPAN: u64 = 0x200_0000;

/// Physical-to-virtual displacement of the boot-time kernel mapping on x64.
///
/// Before the memory manager starts, the kernel is mapped at its physical
/// address plus this constant. It is an *assumption*, not a rule, and KASLR
/// breaks it on Windows 10 and later — so [`fixed_mapping_candidates`] proves
/// the mapping by translating the candidate and checking it lands back on the
/// physical page the header was found at.
pub const FIXED_MAPPING_X64: u64 = 0xFFFF_F800_0000_0000;
/// The same displacement on 32-bit Windows: the top half of the address space.
pub const FIXED_MAPPING_X86: u64 = 0x8000_0000;

/// Lowest kernel-half address on x64, in canonical form.
pub const KERNEL_HALF_START_X64: u64 = 0xFFFF_8000_0000_0000;
/// The address range Windows has actually loaded its kernel in on x64. A sweep
/// bounded to it costs a fraction of the full kernel half and has found the
/// kernel on every image tested.
pub const KERNEL_LIKELY_START_X64: u64 = 0xFFFF_F800_0000_0000;
/// Lowest kernel-half address on 32-bit Windows.
pub const KERNEL_HALF_START_X86: u64 = 0x8000_0000;

/// Which method produced a kernel-base candidate.
///
/// Recorded so a report can say *how* the kernel was found, not merely where.
/// The methods do not have equal standing: the low stub and the debugger block
/// are structures the machine itself wrote down, while the two scans are
/// searches that happened to succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KernelMethod {
    /// The examiner said where the kernel is.
    Supplied,
    /// `PROCESSOR_START_BLOCK.LmTarget` in the x64 low stub.
    LowStub,
    /// `_KDDEBUGGER_DATA64.KernBase`, found by its `KDBG` owner tag.
    KdbgTag,
    /// A CodeView record in physical memory, plus the boot identity mapping,
    /// verified by translating the result back to the same physical page.
    FixedMapping,
    /// A CodeView record found in the kernel virtual address space.
    VirtualScan,
}

impl KernelMethod {
    /// Stable identifier for artifact metadata and report columns.
    pub fn as_str(self) -> &'static str {
        match self {
            KernelMethod::Supplied => "supplied",
            KernelMethod::LowStub => "low_stub",
            KernelMethod::KdbgTag => "kdbg_tag",
            KernelMethod::FixedMapping => "fixed_mapping",
            KernelMethod::VirtualScan => "virtual_scan",
        }
    }
}

/// The x64 boot low stub, and the two facts it publishes.
///
/// An examiner reading this is reading the values the boot processor was started
/// with: the CR3 the kernel's own boot path installed, and an address inside the
/// kernel image. Both were written by the machine before any of the structures
/// discovery normally reads existed, which is why they corroborate a scan rather
/// than merely agreeing with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowStub {
    /// Physical address the `PROCESSOR_START_BLOCK` was found at.
    pub physical_offset: u64,
    /// `ProcessorState->SpecialRegisters->Cr3`.
    ///
    /// The boot processor's directory table base. The structure leaves the low
    /// bits clear, so a caller comparing it against a scanned candidate must
    /// compare page frames rather than whole values.
    pub cr3: u64,
    /// `LmTarget`, the long-mode entry point: an address inside the kernel
    /// image, in canonical form.
    pub lm_target: u64,
}

impl LowStub {
    /// Physical page frame of the boot CR3, for comparison against a scanned
    /// directory-table-base candidate.
    pub fn cr3_frame(self) -> u64 {
        self.cr3 & !(PAGE_SIZE - 1)
    }

    /// The 2 MiB-aligned address the descent for the PE header starts at.
    ///
    /// `LmTarget` points *into* the image, not at its base, and the image is
    /// loaded on a large-page boundary, so this is the first block to sweep.
    pub fn kernel_search_start(self) -> u64 {
        self.lm_target & !(LOW_STUB_BLOCK - 1)
    }
}

/// Sign-extend a 48-bit x64 address into canonical form.
///
/// A kernel address with its top sixteen bits cleared is not merely untidy: this
/// crate's page walker rejects a non-canonical address outright, exactly as the
/// processor would, so an address recovered from a structure that stores only 48
/// bits has to be put back into the form the machine issued before it can be
/// used for anything.
pub fn canonicalize_x64(address: u64) -> u64 {
    if (address >> 47) & 1 == 1 {
        address | 0xFFFF_0000_0000_0000
    } else {
        address & 0x0000_FFFF_FFFF_FFFF
    }
}

fn read_u64_le(layer: &dyn MemoryLayer, address: u64, what: &str) -> Option<u64> {
    address.checked_add(8)?;
    let mut buf = [0u8; 8];
    read_exact_or_fail(layer.as_data_source(), address, &mut buf, what).ok()?;
    Some(u64::from_le_bytes(buf))
}

fn read_u32_le(layer: &dyn MemoryLayer, address: u64, what: &str) -> Option<u32> {
    address.checked_add(4)?;
    let mut buf = [0u8; 4];
    read_exact_or_fail(layer.as_data_source(), address, &mut buf, what).ok()?;
    Some(u32::from_le_bytes(buf))
}

/// Search the first megabyte of physical memory for the x64 boot low stub.
///
/// Returns `None` on any image without one, which includes every 32-bit image
/// and every image from a machine whose firmware or hypervisor did not leave the
/// stub behind. That is an ordinary outcome, not a defect: the caller falls
/// through to the next method.
///
/// The search is bounded by `top` and steps a page at a time from the second
/// page, because the first page holds the real-mode interrupt vector table and
/// never the stub.
pub fn find_low_stub(physical: &dyn MemoryLayer, top: u64) -> Option<LowStub> {
    let mut offset = PAGE_SIZE;
    while offset < top {
        if let Some(word) = read_u64_le(physical, offset, "PROCESSOR_START_BLOCK signature") {
            if word & LOW_STUB_SIGNATURE_MASK == LOW_STUB_SIGNATURE {
                if let Some(stub) = decode_low_stub(physical, offset) {
                    return Some(stub);
                }
            }
        }
        offset = offset.checked_add(PAGE_SIZE)?;
    }
    None
}

fn decode_low_stub(physical: &dyn MemoryLayer, offset: u64) -> Option<LowStub> {
    let cr3 = read_u64_le(
        physical,
        offset.checked_add(LOW_STUB_CR3_OFFSET)?,
        "PROCESSOR_START_BLOCK CR3",
    )?;
    let lm_target = read_u64_le(
        physical,
        offset.checked_add(LOW_STUB_LM_TARGET_OFFSET)?,
        "PROCESSOR_START_BLOCK LmTarget",
    )?;
    // The entry point is an instruction address, so its low bits are clear. A
    // value with them set is not an entry point, and the eight-byte signature is
    // short enough that false matches are expected.
    if lm_target & 0x3 != 0 {
        return None;
    }
    let lm_target = canonicalize_x64(lm_target);
    // A kernel address is in the upper half. Anything else means these bytes
    // were not a start block.
    if lm_target < KERNEL_HALF_START_X64 {
        return None;
    }
    if cr3 == 0 {
        return None;
    }
    Some(LowStub {
        physical_offset: offset,
        cr3,
        lm_target,
    })
}

/// Caps on every search in this module.
///
/// Each exists because the value it bounds comes out of the image, and an image
/// is not trusted input. Reaching any of them is reported rather than silently
/// absorbed, because a truncated search that found nothing has not shown that
/// there was nothing to find.
#[derive(Debug, Clone, Copy)]
pub struct KernelSearchLimits {
    /// Top of the region the low-stub search covers.
    pub low_stub_top: u64,
    /// Pages a backward `MZ` search steps through from one CodeView hit.
    pub max_back_pages: u64,
    /// Consecutive unreadable pages a backward search tolerates before giving
    /// up on that hit.
    pub max_back_unreadable: u64,
    /// Candidates any one method will produce, and rejections it will record.
    pub max_candidates: usize,
    /// Pages the descent from a low-stub hint probes for an `MZ` header.
    pub max_low_stub_probe_pages: u64,
    /// Whether the virtual sweep covers the whole kernel half rather than the
    /// range Windows has been observed to load the kernel in.
    pub deep_virtual_scan: bool,
}

impl Default for KernelSearchLimits {
    fn default() -> Self {
        Self {
            low_stub_top: LOW_STUB_SEARCH_TOP,
            // A loaded kernel image is under 32 MiB, and its CodeView record is
            // in the debug section near the end of it.
            max_back_pages: 8192,
            max_back_unreadable: 64,
            max_candidates: 64,
            // 32 MiB of 4 KiB pages: the span upstream descends from the hint.
            max_low_stub_probe_pages: 8192,
            deep_virtual_scan: false,
        }
    }
}

/// One address that might be the kernel's load address, and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelCandidate {
    /// The candidate load address, in the kernel virtual address space.
    pub base: u64,
    /// Which method produced it.
    pub method: KernelMethod,
}

/// What a search for the kernel found, and everything it could not do.
#[derive(Debug, Clone, Default)]
pub struct KernelSearchOutcome {
    /// The proved image, if one was proved.
    pub image: Option<KernelImage>,
    /// Which method proved it.
    pub method: Option<KernelMethod>,
    /// Candidates that were read and refused, with the reason. An examiner
    /// looking at an image where discovery failed needs to see that eleven
    /// candidates were tested and why each was rejected, not an empty result.
    pub rejected: Vec<(u64, KernelMethod, String)>,
    /// Whether a cap stopped a search before it finished.
    pub truncated: bool,
    /// Methods that were attempted, in order.
    pub methods_tried: Vec<KernelMethod>,
}

impl KernelSearchOutcome {
    /// Serializable form for the discovery artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "found": self.image.is_some(),
            "method": self.method.map(KernelMethod::as_str),
            "rejected": self.rejected.len(),
            "truncated": self.truncated,
            "methods_tried": self
                .methods_tried
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>(),
        })
    }

    fn accept(&mut self, image: KernelImage, method: KernelMethod) {
        self.image = Some(image);
        self.method = Some(method);
    }

    fn reject(&mut self, address: u64, method: KernelMethod, why: String, cap: usize) {
        if self.rejected.len() < cap {
            self.rejected.push((address, method, why));
        }
    }
}

/// Read the PE image at `base` and decide whether it is the Windows kernel.
///
/// The single gate every candidate passes through. Returns the proved image, or
/// the reason it was refused in words an examiner can read — never a bare
/// boolean, because "the header was paged out" and "the header was there and
/// named a printer driver" are different findings about the same address.
pub fn prove_kernel_at(space: &dyn MemoryLayer, base: u64) -> Result<KernelImage, String> {
    match read_pe_image(space, base) {
        Ok(image) => {
            if image.pdb.is_kernel() {
                Ok(image)
            } else {
                Err(format!(
                    "the image here is identified by {}, which is not a kernel PDB",
                    image.pdb.pdb
                ))
            }
        }
        Err(PeError::Unreadable { what, .. }) => Err(format!("{what} is not in the evidence")),
        Err(err) => Err(err.to_string()),
    }
}

/// Whether the two bytes at `address` are an `MZ` signature.
///
/// A two-byte probe, so a descent over thousands of pages costs thousands of
/// tiny reads rather than thousands of full header parses.
fn looks_like_an_image(layer: &dyn MemoryLayer, address: u64) -> bool {
    let mut magic = [0u8; 2];
    read_exact_or_fail(layer.as_data_source(), address, &mut magic, "MZ probe").is_ok()
        && magic == DOS_MAGIC
}

/// Find the kernel using the x64 low stub's `LmTarget`.
///
/// `LmTarget` is an address inside the image, not its base, so the search sweeps
/// the 2 MiB block containing it and then successively lower blocks, a page at a
/// time within each. That shape is upstream's, and it matters: the header is at
/// or below the hint, and sweeping upward inside a block finds an image that
/// begins part-way through one.
///
/// Bounded by `limits.max_low_stub_probe_pages` and by
/// [`LOW_STUB_DESCENT_SPAN`]; exhausting either sets `truncated` on the outcome
/// rather than reporting a clean miss.
pub fn locate_from_low_stub(
    space: &dyn MemoryLayer,
    stub: &LowStub,
    limits: &KernelSearchLimits,
    outcome: &mut KernelSearchOutcome,
) {
    outcome.methods_tried.push(KernelMethod::LowStub);
    let hint = stub.lm_target;
    let mut block = stub.kernel_search_start();
    let mut probed = 0u64;

    loop {
        // Upstream's bound: stop once the block being swept is more than
        // `LOW_STUB_DESCENT_SPAN` below the hint.
        match block.checked_add(LOW_STUB_DESCENT_SPAN) {
            Some(top) if top > hint => {}
            _ => return,
        }
        let mut offset = 0u64;
        while offset < LOW_STUB_BLOCK {
            if probed >= limits.max_low_stub_probe_pages {
                outcome.truncated = true;
                return;
            }
            probed = probed.saturating_add(1);
            let Some(address) = block.checked_add(offset) else {
                return;
            };
            if looks_like_an_image(space, address) {
                match prove_kernel_at(space, address) {
                    Ok(image) => {
                        outcome.accept(image, KernelMethod::LowStub);
                        return;
                    }
                    Err(why) => {
                        outcome.reject(address, KernelMethod::LowStub, why, limits.max_candidates)
                    }
                }
            }
            offset = offset.saturating_add(PAGE_SIZE);
        }
        match block.checked_sub(LOW_STUB_BLOCK) {
            Some(next) if next >= KERNEL_HALF_START_X64 => block = next,
            _ => return,
        }
    }
}

/// Sweep physical memory for `KDBG` owner tags and read the `KernBase` beside
/// each one.
///
/// Scanning physical memory rather than the virtual space is deliberate: it
/// finds the debugger block even in an image whose kernel address space is
/// partly unreadable, which is precisely the situation where the other methods
/// are struggling.
///
/// Returns the candidates and whether a cap stopped the sweep.
///
/// # Errors
///
/// Only for a scan configuration or layer that cannot produce a correct walk. A
/// region that could not be read is not an error — it is recorded in the scan
/// outcome and the sweep continues.
pub fn scan_kdbg_tags(
    physical: &dyn MemoryLayer,
    is_64bit: bool,
    config: &ScanConfig,
    max_candidates: usize,
) -> Result<(Vec<KernelCandidate>, bool), ScanError> {
    let scanner = MultiStringScanner::new("windows.kdbg_tag", [KDBG_TAG.as_slice()])?;
    let scan = scan_layer(physical, &scanner, config)?;
    let floor = if is_64bit {
        KERNEL_HALF_START_X64
    } else {
        KERNEL_HALF_START_X86
    };

    let mut out: Vec<KernelCandidate> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for hit in &scan.hits {
        if out.len() >= max_candidates {
            return Ok((out, true));
        }
        let Some(at) = hit.address.checked_add(KDBG_TAG_TO_KERN_BASE) else {
            continue;
        };
        let raw = if is_64bit {
            read_u64_le(physical, at, "_KDDEBUGGER_DATA64.KernBase")
        } else {
            read_u32_le(physical, at, "_KDDEBUGGER_DATA32.KernBase").map(u64::from)
        };
        let Some(raw) = raw else { continue };
        let base = if is_64bit { canonicalize_x64(raw) } else { raw };
        // A kernel base is in the upper half and page-aligned. The four bytes
        // "KDBG" occur in ordinary data often enough that both checks earn
        // their keep.
        if base < floor || base % PAGE_SIZE != 0 {
            continue;
        }
        if !seen.insert(base) {
            continue;
        }
        out.push(KernelCandidate {
            base,
            method: KernelMethod::KdbgTag,
        });
    }
    Ok((out, scan.truncated))
}

/// The address of the block a `KDBG` tag at `tag_address` belongs to.
///
/// Reported so a profile can name the debugger data block itself, which is what
/// an examiner recognises, rather than the address of four bytes inside it.
pub fn kdbg_block_address(tag_address: u64, is_64bit: bool) -> Option<u64> {
    let back = if is_64bit {
        KDBG_TAG_TO_BLOCK_X64
    } else {
        KDBG_TAG_TO_BLOCK_X86
    };
    tag_address.checked_sub(back)
}

/// Candidates from CodeView records found in **physical** memory, mapped through
/// the boot-time identity mapping.
///
/// The mapping is an assumption and is treated as one. Every candidate is
/// translated back through the address space, and one that does not land on the
/// physical page its header was found at is discarded here rather than passed
/// on — which is what makes the method safe to attempt on a Windows 10 image,
/// where KASLR usually makes the assumption false.
pub fn fixed_mapping_candidates(
    physical: &dyn MemoryLayer,
    space: &VirtualLayer,
    is_64bit: bool,
    config: &ScanConfig,
    limits: &KernelSearchLimits,
) -> Result<(Vec<KernelCandidate>, bool), ScanError> {
    let scanner = MultiStringScanner::new("windows.kernel_pdb_name", KERNEL_PDB_NEEDLES)?;
    let scan = scan_layer(physical, &scanner, config)?;
    let displacement = if is_64bit {
        FIXED_MAPPING_X64
    } else {
        FIXED_MAPPING_X86
    };

    let mut out: Vec<KernelCandidate> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for hit in &scan.hits {
        if out.len() >= limits.max_candidates {
            return Ok((out, true));
        }
        let Some(mz) = find_image_base_below(
            physical,
            hit.address,
            PAGE_SIZE,
            limits.max_back_pages,
            limits.max_back_unreadable,
        ) else {
            continue;
        };
        let Some(base) = mz.checked_add(displacement) else {
            continue;
        };
        if !seen.insert(base) {
            continue;
        }
        // The whole point of the method: prove the mapping instead of assuming
        // it. A candidate whose translation lands anywhere but the page the
        // header was read from is not this kernel, whatever else is true.
        match space.translate(base) {
            Ok(translation) if translation.phys == mz => out.push(KernelCandidate {
                base,
                method: KernelMethod::FixedMapping,
            }),
            _ => continue,
        }
    }
    Ok((out, scan.truncated))
}

/// The virtual range a kernel-image sweep covers.
///
/// The narrow range is where every Windows tested has loaded its kernel; the
/// deep range is the whole kernel half, which is correct everywhere and costs
/// far more. Exposed rather than inlined so a report can state exactly what was
/// swept.
pub fn kernel_scan_range(is_64bit: bool, deep: bool) -> Range<u64> {
    if is_64bit {
        let start = if deep {
            KERNEL_HALF_START_X64
        } else {
            KERNEL_LIKELY_START_X64
        };
        // `u64::MAX` as an exclusive end leaves the single top byte unswept, and
        // no image header can begin there.
        start..u64::MAX
    } else {
        KERNEL_HALF_START_X86..0xFFFF_FFFF
    }
}

/// Candidates from CodeView records found in the kernel virtual address space.
///
/// The slowest method and the last resort, because it sweeps mapped kernel
/// memory rather than a bounded structure. It is also the only one that works
/// when the kernel is neither at its boot mapping nor reachable from a low stub
/// or a debugger block.
pub fn virtual_scan_candidates(
    space: &VirtualLayer,
    is_64bit: bool,
    config: &ScanConfig,
    limits: &KernelSearchLimits,
) -> Result<(Vec<KernelCandidate>, bool), ScanError> {
    let scanner = MultiStringScanner::new("windows.kernel_pdb_name", KERNEL_PDB_NEEDLES)?;
    let range = kernel_scan_range(is_64bit, limits.deep_virtual_scan);
    let scan = scan_range(space, &scanner, range, config)?;

    let mut out: Vec<KernelCandidate> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for hit in &scan.hits {
        if out.len() >= limits.max_candidates {
            return Ok((out, true));
        }
        let Some(base) = find_image_base_below(
            space,
            hit.address,
            PAGE_SIZE,
            limits.max_back_pages,
            limits.max_back_unreadable,
        ) else {
            continue;
        };
        if !seen.insert(base) {
            continue;
        }
        out.push(KernelCandidate {
            base,
            method: KernelMethod::VirtualScan,
        });
    }
    Ok((out, scan.truncated))
}

/// Prove a list of candidates in order, stopping at the first that is a kernel.
///
/// Returns whether one was proved. Every refusal is recorded on the outcome, up
/// to the cap, so a failed search says what it looked at.
pub fn prove_candidates(
    space: &dyn MemoryLayer,
    candidates: &[KernelCandidate],
    limits: &KernelSearchLimits,
    outcome: &mut KernelSearchOutcome,
) -> bool {
    for candidate in candidates {
        match prove_kernel_at(space, candidate.base) {
            Ok(image) => {
                outcome.accept(image, candidate.method);
                return true;
            }
            Err(why) => {
                outcome.reject(candidate.base, candidate.method, why, limits.max_candidates)
            }
        }
    }
    false
}

/// Find and prove the Windows kernel in `space`, trying every method in turn.
///
/// Returns an outcome rather than an `Option`, because a failed search is
/// evidence too: which methods ran, how many candidates were tested, why each
/// was refused, and whether a cap stopped the work before it finished. A caller
/// that reports "no kernel found" without that context is reporting a conclusion
/// it has not earned.
///
/// `low_stub` is passed in rather than searched for here because its CR3 is also
/// a directory-table-base candidate, so discovery finds it once, before it has
/// an address space at all.
pub fn locate_kernel(
    physical: &dyn MemoryLayer,
    space: &VirtualLayer,
    is_64bit: bool,
    low_stub: Option<&LowStub>,
    config: &ScanConfig,
    limits: &KernelSearchLimits,
) -> KernelSearchOutcome {
    let mut outcome = KernelSearchOutcome::default();

    if let Some(stub) = low_stub {
        locate_from_low_stub(space, stub, limits, &mut outcome);
        if outcome.image.is_some() {
            return outcome;
        }
    }

    outcome.methods_tried.push(KernelMethod::KdbgTag);
    match scan_kdbg_tags(physical, is_64bit, config, limits.max_candidates) {
        Ok((candidates, truncated)) => {
            outcome.truncated |= truncated;
            if prove_candidates(space, &candidates, limits, &mut outcome) {
                return outcome;
            }
        }
        Err(err) => outcome.reject(
            0,
            KernelMethod::KdbgTag,
            err.to_string(),
            limits.max_candidates,
        ),
    }

    outcome.methods_tried.push(KernelMethod::FixedMapping);
    match fixed_mapping_candidates(physical, space, is_64bit, config, limits) {
        Ok((candidates, truncated)) => {
            outcome.truncated |= truncated;
            if prove_candidates(space, &candidates, limits, &mut outcome) {
                return outcome;
            }
        }
        Err(err) => outcome.reject(
            0,
            KernelMethod::FixedMapping,
            err.to_string(),
            limits.max_candidates,
        ),
    }

    outcome.methods_tried.push(KernelMethod::VirtualScan);
    match virtual_scan_candidates(space, is_64bit, config, limits) {
        Ok((candidates, truncated)) => {
            outcome.truncated |= truncated;
            if prove_candidates(space, &candidates, limits, &mut outcome) {
                return outcome;
            }
        }
        Err(err) => outcome.reject(
            0,
            KernelMethod::VirtualScan,
            err.to_string(),
            limits.max_candidates,
        ),
    }

    outcome
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::automagic::dtb::test_support::Image;
    use crate::automagic::pe::test_support::PeBuilder;

    /// Physical address of the PML4 in every synthetic x64 fixture here.
    pub(crate) const PML4: u64 = 0x1AE000;
    pub(crate) const PDPT: u64 = 0x2000;
    pub(crate) const PD: u64 = 0x3000;
    pub(crate) const PT: u64 = 0x4000;
    /// Physical address the kernel image is written at.
    pub(crate) const KERNEL_PHYS: u64 = 0x20000;
    /// `PML4[0x1F0]`, `PDPT[0]`, `PD[0]`, `PT[0x20]` — the virtual address the
    /// kernel image is mapped at, which is also `KERNEL_PHYS + FIXED_MAPPING_X64`
    /// so the boot-mapping method has something to prove.
    pub(crate) const KERNEL_VA: u64 = 0xFFFF_F800_0002_0000;
    /// Bytes of the synthetic physical image.
    pub(crate) const IMAGE_SIZE: usize = 0x40_0000;

    /// A physical image with an x64 page-table hierarchy and 32 kernel pages
    /// mapped, but nothing written into them yet.
    pub(crate) fn empty_x64_image() -> Image {
        let mut image = Image::new(IMAGE_SIZE);
        image.put64(PML4, 0x1ED, PML4 | 1);
        image.put64(PML4, 0x1F0, PDPT | 1);
        image.put64(PDPT, 0, PD | 1);
        image.put64(PD, 0, PT | 1);
        for page in 0..32u64 {
            image.put64(PT, 0x20 + page, (KERNEL_PHYS + page * PAGE_SIZE) | 1);
        }
        image
    }

    /// The same image with a kernel PE written at `KERNEL_PHYS`.
    pub(crate) fn x64_image_with_kernel() -> Image {
        let mut image = empty_x64_image();
        image.write(KERNEL_PHYS, &PeBuilder::default().build());
        image
    }

    /// A virtual address space over `layer`, rooted at the fixture's PML4.
    pub(crate) fn space_over(layer: std::sync::Arc<dyn MemoryLayer>) -> VirtualLayer {
        use seance_memory::translate::{PagingMode, PagingSpec, PteSemantics};
        VirtualLayer::new(
            layer,
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows),
        )
        .expect("a usable directory table base")
    }

    /// A scan configuration sized for a four-megabyte fixture.
    pub(crate) fn small_scan_config() -> ScanConfig {
        ScanConfig {
            chunk_size: 0x10000,
            ..ScanConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::automagic::dtb::test_support::Image;
    use crate::automagic::pe::test_support::{PeBuilder, CODEVIEW_RVA};
    use std::sync::Arc;

    #[test]
    fn a_canonical_kernel_address_survives_the_round_trip_through_forty_eight_bits() {
        // A 48-bit-truncated kernel address is what the low stub and the
        // debugger block store, and this crate's page walker rejects it exactly
        // as the processor would. Failing to put the sign extension back turns
        // a correct pointer into an address the machine could never have
        // issued.
        assert_eq!(
            canonicalize_x64(0x0000_F800_2980_0000),
            0xFFFF_F800_2980_0000
        );
        assert_eq!(
            canonicalize_x64(0xFFFF_F800_2980_0000),
            0xFFFF_F800_2980_0000
        );
        // A user-half address must not gain a sign extension it never had.
        assert_eq!(
            canonicalize_x64(0x0000_0000_7FFE_0000),
            0x0000_0000_7FFE_0000
        );
    }

    #[test]
    fn a_kernel_image_in_the_virtual_space_is_proved_by_its_codeview_record() {
        let space = space_over(x64_image_with_kernel().layer());
        let image = prove_kernel_at(&space, KERNEL_VA).expect("a kernel image is mapped here");
        assert_eq!(image.base, KERNEL_VA);
        assert_eq!(image.pdb.pdb, "ntkrnlmp.pdb");
        assert!(image.pdb.is_kernel());
    }

    #[test]
    fn an_image_that_is_not_a_kernel_is_refused_by_name_rather_than_accepted() {
        // The failure this gate exists for: a well-formed PE with a complete
        // CodeView record that belongs to a driver. Anchoring the symbol table
        // on it would resolve every kernel global into the driver's memory, and
        // every structure read there would parse.
        let mut image = empty_x64_image();
        image.write(
            KERNEL_PHYS,
            &PeBuilder {
                pdb_name: "prnms003.pdb",
                ..PeBuilder::default()
            }
            .build(),
        );
        let space = space_over(image.layer());
        let why = prove_kernel_at(&space, KERNEL_VA).expect_err("a driver is not the kernel");
        assert!(why.contains("prnms003.pdb"), "{why}");
    }

    #[test]
    fn an_address_whose_header_is_not_in_the_evidence_is_refused_as_unreadable() {
        // "We could not read the header" and "there is no kernel here" are
        // different findings, and the second must not be reported when the
        // first is true.
        let space = space_over(x64_image_with_kernel().layer());
        let why = prove_kernel_at(&space, 0xFFFF_F800_0800_0000)
            .expect_err("nothing is mapped at this address");
        assert!(why.contains("not in the evidence"), "{why}");
    }

    fn with_low_stub(mut image: Image, cr3: u64, lm_target: u64) -> Image {
        let stub_at = 0x5000u64;
        image.write(stub_at, &LOW_STUB_SIGNATURE.to_le_bytes());
        image.write(stub_at + LOW_STUB_CR3_OFFSET, &cr3.to_le_bytes());
        image.write(
            stub_at + LOW_STUB_LM_TARGET_OFFSET,
            &lm_target.to_le_bytes(),
        );
        image
    }

    #[test]
    fn the_low_stub_yields_the_boot_cr3_and_an_address_inside_the_kernel() {
        let image = with_low_stub(x64_image_with_kernel(), PML4, KERNEL_VA + 0x800);
        let layer = image.layer();
        let stub = find_low_stub(&*layer, LOW_STUB_SEARCH_TOP).expect("the stub is present");
        assert_eq!(stub.physical_offset, 0x5000);
        assert_eq!(stub.cr3, PML4);
        assert_eq!(stub.cr3_frame(), PML4);
        assert_eq!(stub.lm_target, KERNEL_VA + 0x800);
        // The sweep starts at the 2 MiB boundary at or below the hint.
        assert_eq!(stub.kernel_search_start(), KERNEL_VA & !0x1F_FFFF);
    }

    #[test]
    fn a_low_stub_whose_long_mode_target_is_not_a_kernel_address_is_refused() {
        // The signature is eight bytes and appears in ordinary data. A match
        // whose LmTarget is a user address, or is unaligned, is not a start
        // block, and accepting it would send the descent into the user half.
        let user_half = with_low_stub(Image::new(IMAGE_SIZE), PML4, 0x1234_5678);
        assert!(find_low_stub(&*user_half.layer(), LOW_STUB_SEARCH_TOP).is_none());

        let unaligned = with_low_stub(Image::new(IMAGE_SIZE), PML4, KERNEL_VA | 0x1);
        assert!(find_low_stub(&*unaligned.layer(), LOW_STUB_SEARCH_TOP).is_none());

        let no_cr3 = with_low_stub(Image::new(IMAGE_SIZE), 0, KERNEL_VA);
        assert!(find_low_stub(&*no_cr3.layer(), LOW_STUB_SEARCH_TOP).is_none());
    }

    #[test]
    fn an_image_with_no_low_stub_reports_absence_rather_than_a_guess() {
        let layer = x64_image_with_kernel().layer();
        assert!(find_low_stub(&*layer, LOW_STUB_SEARCH_TOP).is_none());
    }

    #[test]
    fn the_low_stub_descent_finds_the_kernel_header_at_or_below_its_hint() {
        // The hint points into the image, and the header is above the 2 MiB
        // boundary the sweep starts at, so a descent that only walked downward
        // page by page would never reach it.
        let image = with_low_stub(x64_image_with_kernel(), PML4, KERNEL_VA + 0x800);
        let layer = image.layer();
        let stub = find_low_stub(&*layer, LOW_STUB_SEARCH_TOP).expect("the stub is present");
        let space = space_over(layer);
        let mut outcome = KernelSearchOutcome::default();
        locate_from_low_stub(&space, &stub, &KernelSearchLimits::default(), &mut outcome);
        let found = outcome.image.expect("the sweep reaches the header");
        assert_eq!(found.base, KERNEL_VA);
        assert_eq!(outcome.method, Some(KernelMethod::LowStub));
        assert!(!outcome.truncated);
    }

    #[test]
    fn the_low_stub_descent_stops_at_its_page_budget_rather_than_sweeping_the_kernel_half() {
        let image = with_low_stub(x64_image_with_kernel(), PML4, KERNEL_VA + 0x800);
        let layer = image.layer();
        let stub = find_low_stub(&*layer, LOW_STUB_SEARCH_TOP).expect("the stub is present");
        let space = space_over(layer);
        let mut outcome = KernelSearchOutcome::default();
        let limits = KernelSearchLimits {
            // Sixteen pages reaches 0x10000 into the block; the header is at
            // 0x20000 into it.
            max_low_stub_probe_pages: 16,
            ..KernelSearchLimits::default()
        };
        locate_from_low_stub(&space, &stub, &limits, &mut outcome);
        assert!(outcome.image.is_none());
        assert!(
            outcome.truncated,
            "a budget-limited sweep that found nothing must not read as an exhaustive one"
        );
    }

    #[test]
    fn a_kdbg_tag_yields_the_kernel_base_beside_it() {
        let mut image = x64_image_with_kernel();
        let tag_at = 0x30000u64;
        image.write(tag_at, KDBG_TAG);
        image.write(tag_at + KDBG_TAG_TO_KERN_BASE, &KERNEL_VA.to_le_bytes());
        let layer = image.layer();
        let (candidates, truncated) = scan_kdbg_tags(&*layer, true, &small_scan_config(), 16)
            .expect("the sweep is well-formed");
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(candidates[0].base, KERNEL_VA);
        assert_eq!(candidates[0].method, KernelMethod::KdbgTag);
        assert!(!truncated);
        // The block starts before the tag, and by a different distance in each
        // word size.
        assert_eq!(kdbg_block_address(tag_at, true), Some(tag_at - 16));
        assert_eq!(kdbg_block_address(tag_at, false), Some(tag_at - 8));
        assert_eq!(kdbg_block_address(4, true), None);
    }

    #[test]
    fn a_kdbg_tag_whose_kern_base_is_not_a_kernel_address_produces_no_candidate() {
        // The four bytes "KDBG" occur in ordinary data. A match whose KernBase
        // is a user address, or is not page-aligned, did not come from a
        // debugger data block.
        let mut image = x64_image_with_kernel();
        image.write(0x30000, KDBG_TAG);
        image.write(
            0x30000 + KDBG_TAG_TO_KERN_BASE,
            &0x4141_4141u64.to_le_bytes(),
        );
        image.write(0x31000, KDBG_TAG);
        image.write(
            0x31000 + KDBG_TAG_TO_KERN_BASE,
            &(KERNEL_VA + 0x10).to_le_bytes(),
        );
        let layer = image.layer();
        let (candidates, _) = scan_kdbg_tags(&*layer, true, &small_scan_config(), 16)
            .expect("the sweep is well-formed");
        assert!(candidates.is_empty(), "{candidates:?}");
    }

    #[test]
    fn the_fixed_mapping_method_proves_its_assumption_by_translating_the_candidate_back() {
        // The fixture maps the kernel at physical + 0xFFFFF80000000000, which is
        // what the boot mapping looks like, so the assumption holds and the
        // translation check passes.
        let layer = x64_image_with_kernel().layer();
        let space = space_over(Arc::clone(&layer));
        let (candidates, _) = fixed_mapping_candidates(
            &*layer,
            &space,
            true,
            &small_scan_config(),
            &KernelSearchLimits::default(),
        )
        .expect("the sweep is well-formed");
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(candidates[0].base, KERNEL_PHYS + FIXED_MAPPING_X64);
        assert_eq!(candidates[0].base, KERNEL_VA);
    }

    #[test]
    fn a_kernel_that_kaslr_moved_off_the_boot_mapping_yields_no_fixed_mapping_candidate() {
        // The Windows 10 case. The physical CodeView record is found, but the
        // address the assumption predicts translates somewhere else, so the
        // candidate is discarded instead of anchoring the case on an address
        // the kernel is not at.
        let mut image = Image::new(IMAGE_SIZE);
        image.put64(PML4, 0x1ED, PML4 | 1);
        image.put64(PML4, 0x1F0, PDPT | 1);
        image.put64(PDPT, 0, PD | 1);
        image.put64(PD, 0, PT | 1);
        // One page lower in the virtual space than the boot mapping would put it.
        for page in 0..32u64 {
            image.put64(PT, 0x1F + page, (KERNEL_PHYS + page * PAGE_SIZE) | 1);
        }
        image.write(KERNEL_PHYS, &PeBuilder::default().build());
        let layer = image.layer();
        let space = space_over(Arc::clone(&layer));
        let (candidates, _) = fixed_mapping_candidates(
            &*layer,
            &space,
            true,
            &small_scan_config(),
            &KernelSearchLimits::default(),
        )
        .expect("the sweep is well-formed");
        assert!(candidates.is_empty(), "{candidates:?}");
    }

    #[test]
    fn the_virtual_sweep_finds_the_kernel_where_it_actually_lives() {
        let space = space_over(x64_image_with_kernel().layer());
        let (candidates, _) = virtual_scan_candidates(
            &space,
            true,
            &small_scan_config(),
            &KernelSearchLimits::default(),
        )
        .expect("the sweep is well-formed");
        assert!(
            candidates.iter().any(|c| c.base == KERNEL_VA),
            "{candidates:?}"
        );
    }

    #[test]
    fn the_full_search_finds_the_kernel_and_names_the_method_that_found_it() {
        let layer = x64_image_with_kernel().layer();
        let space = space_over(Arc::clone(&layer));
        let outcome = locate_kernel(
            &*layer,
            &space,
            true,
            None,
            &small_scan_config(),
            &KernelSearchLimits::default(),
        );
        let image = outcome.image.as_ref().expect("the kernel is in this image");
        assert_eq!(image.base, KERNEL_VA);
        assert_eq!(outcome.method, Some(KernelMethod::FixedMapping));
        assert!(outcome.methods_tried.contains(&KernelMethod::KdbgTag));
        let json = outcome.to_json();
        assert_eq!(json["found"], true);
        assert_eq!(json["method"], "fixed_mapping");
    }

    #[test]
    fn a_search_of_an_image_with_no_kernel_reports_what_it_tried_rather_than_nothing() {
        // An address space that translates but holds no kernel. The outcome has
        // to say which methods ran: "no kernel found" from a search that never
        // ran a method is a different statement from one that ran them all.
        let layer = empty_x64_image().layer();
        let space = space_over(Arc::clone(&layer));
        let outcome = locate_kernel(
            &*layer,
            &space,
            true,
            None,
            &small_scan_config(),
            &KernelSearchLimits::default(),
        );
        assert!(outcome.image.is_none());
        assert_eq!(outcome.methods_tried.len(), 3);
        assert_eq!(outcome.to_json()["found"], false);
    }

    #[test]
    fn the_kernel_sweep_range_covers_the_kernel_half_of_each_word_size() {
        let narrow = kernel_scan_range(true, false);
        assert_eq!(narrow.start, KERNEL_LIKELY_START_X64);
        let deep = kernel_scan_range(true, true);
        assert_eq!(deep.start, KERNEL_HALF_START_X64);
        assert!(deep.start < narrow.start, "the deep sweep must be wider");
        let x86 = kernel_scan_range(false, false);
        assert_eq!(x86.start, KERNEL_HALF_START_X86);
        assert_eq!(x86.end, 0xFFFF_FFFF);
    }

    #[test]
    fn the_synthetic_kernel_carries_its_codeview_record_where_the_sweeps_look_for_it() {
        // Guards the fixture the sweeps depend on: if the record moved, a
        // passing sweep test would be proving nothing.
        let bytes = PeBuilder::default().build();
        let window = &bytes[CODEVIEW_RVA as usize..];
        assert!(window.starts_with(b"RSDS"));
        assert!(
            window[24..].starts_with(b"ntkrnlmp.pdb"),
            "the needle the sweeps search for must be in the fixture"
        );
    }
}
