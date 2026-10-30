//! [`PageWalk`]: the walk itself — a virtual address in, a physical address or
//! a *named reason there isn't one* out.
//!
//! # The shape of the walk
//!
//! Every mode is the same loop with different numbers. Starting from the
//! directory table base — or the TTBR of an ARM64 regime — each level takes a
//! slice of the virtual address, uses it to index a table of entries, and reads
//! the entry that describes the next level down. The walk ends when an entry
//! describes a page rather than a table, and *how that is told* is not this
//! file's knowledge: [`PagingSpec::classify`] applies the level's own
//! [`LeafRule`] — Intel's `PS` bit, ARM64's type bit — and hands back a frame
//! already masked to the width the entry carries. The walker never reads bit 7
//! or bit 1 itself.
//!
//! [`PagingSpec::classify`]: crate::translate::spec::PagingSpec::classify
//! [`LeafRule`]: crate::translate::spec::LeafRule
//!
//! The loop is bounded by the level count — at most five iterations, on LA57 —
//! which is why a self-referential or circular page table cannot hang it. That property
//! is structural, not a guard that could be forgotten: the walker never follows
//! a pointer it did not get from the level table.
//!
//! # What "no translation" means, precisely
//!
//! Volatility's walker raises one `PagingError` for everything and its callers
//! turn that into padded zeros. Here every way a walk can fail is a distinct
//! variant of [`TranslateError`] carrying the entry that caused it, because the
//! difference between them is the difference between "the suspect zeroed this
//! buffer", "this page is in the pagefile we do not have", "this shared page is
//! not in RAM and the section object cannot be reached", and "the acquisition
//! tool skipped this frame". Those are four different findings and no report may
//! render them alike.
//!
//! A prototype PTE is not one of them. The walk **follows** it into the
//! section's prototype array and reports the result as
//! [`TranslationPath::PrototypePte`], because that array is in paged pool, is
//! mapped into every address space, and very often says the page is resident.
//! Stopping there would lose a DLL's code and every mapped file from a process's
//! address space while reporting no problem.
//!
//! # `run_len` is not a detail
//!
//! Every success carries the size of the page it landed in, and every failure
//! carries the size of the region the failing entry governs. A not-present PML4
//! entry means 512 GiB of address space is absent, and a scanner that learns
//! that skips it in one step instead of probing 134 million pages. The same
//! number lets [`crate::translate::VirtualLayer::mapping`] describe a 2 MiB
//! large page as one run instead of 512.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use seance_core::io::read_exact_or_fail;

use crate::layer::{HoleReason, LayerError, MemoryHole, MemoryLayer};
use crate::translate::cache::{TableCache, TableShape};
use crate::translate::spec::{
    mask_bits, EntryKind, InvalidEntry, PagingMode, PagingSpec, NX_BIT, PAGE_OFFSET_BITS,
    PRESENT_BIT,
};

/// Size of a paging table that occupies a whole page, and therefore the only
/// table size the uniform-table heuristic is allowed to consider.
///
/// PAE's page-directory-pointer table is 32 bytes and is excluded: four
/// identical entries is a coincidence, not evidence of Windows' unused-page
/// mapping.
pub const UNIFORM_TABLE_BYTES: u64 = 4096;

/// Which structure held the entry that ended a walk.
///
/// An examiner reading "this virtual address is at physical `X`" is entitled to
/// know whether the process's own page tables said so, or whether the answer
/// came from a section object's prototype PTE array — because the second case
/// means the page is *shared*, and "this process wrote these bytes" is then a
/// claim the translation does not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationPath {
    /// The hardware page tables resolved the address outright.
    PageTables,
    /// A Windows prototype PTE was followed. The final entry was read from the
    /// prototype array at kernel virtual address `proto_va`, which lives at
    /// physical `proto_pa`; the page belongs to a section object (a mapped file
    /// or shared memory) and may be mapped into other processes as well.
    PrototypePte { proto_va: u64, proto_pa: u64 },
}

impl TranslationPath {
    /// Stable identifier for artifact metadata and log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            TranslationPath::PageTables => "page_tables",
            TranslationPath::PrototypePte { .. } => "prototype_pte",
        }
    }

    /// Whether the answer came from a section object rather than this
    /// process's page tables.
    pub fn is_shared(self) -> bool {
        matches!(self, TranslationPath::PrototypePte { .. })
    }
}

/// A successful translation: where the bytes are, and how far the answer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translation {
    /// The physical address of the requested byte, page offset included.
    pub phys: u64,
    /// Size of the page this address landed in: 4 KiB, 2 MiB, 4 MiB or 1 GiB.
    ///
    /// Everything from the start of that page to its end translates
    /// contiguously, which is what lets a caller read a large page in one go
    /// instead of walking the tables once per 4 KiB.
    pub run_len: u64,
    /// Index of the level whose entry ended the walk, `0` being the top table.
    /// Name it with [`PagingSpec::level_name`].
    pub level: u8,
    /// The no-execute bit of the entry that ended the walk, OR'd with the XD
    /// bit of every non-leaf entry above it (Intel SDM Vol. 3A 4.6: XD at any
    /// level forbids the fetch; a PAE PDPTE has no XD bit and 32-bit paging
    /// none at all), reported as observed.
    ///
    /// It is *not* interpreted: bit 63 only means "no execute" when the machine
    /// had `EFER.NXE` set, which an image does not record. It is surfaced
    /// because an examiner asking "was this page executable?" should get the
    /// evidence rather than silence, and because the frame mask stops at
    /// MAXPHYADDR precisely so this bit can never be mistaken for an address.
    ///
    /// On ARM64 it is the execute-never bit for the regime's own exception
    /// level — `PXN` (bit 53) in a TTBR1 layer, `UXN` (bit 54) in a TTBR0
    /// one — OR'd with the hierarchical `PXNTable` (bit 59) / `UXNTable`
    /// (bit 60) of every table descriptor above it (D8.4.2), unless the
    /// regime records `TCR_EL1.HPDn = 1`. See
    /// [`PagingSpec::table_execute_never`].
    ///
    /// Meaningful only for a **hardware** entry. Under Windows semantics a
    /// translation may come from a transition entry, whose bit 63 lies in
    /// `MMPTE_TRANSITION`'s unused range and carries no such meaning — the same
    /// overlap that made bit 7 unusable as a large-page test. Nothing reads
    /// this today; a consumer that starts to must gate on `via`.
    pub no_execute: bool,
    /// Which structure held the entry that ended the walk.
    ///
    /// [`TranslationPath::PrototypePte`] means the page tables stopped at a
    /// prototype PTE and the answer came from the section object's prototype
    /// array. The bytes are real and resident; what they are *not* is private
    /// to this process.
    pub via: TranslationPath,
}

impl Translation {
    /// First address of the page this translation landed in, in physical space.
    pub fn page_base(&self) -> u64 {
        self.phys & !(self.run_len.saturating_sub(1))
    }

    /// How many bytes from `phys` to the end of this page — the most a caller
    /// may read before it must translate again.
    pub fn bytes_to_page_end(&self) -> u64 {
        self.run_len - (self.phys & (self.run_len.saturating_sub(1)))
    }
}

/// How much the walker is allowed to assume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranslationPolicy {
    /// Treat a page-sized table whose entries are all byte-identical **and
    /// present** as absent.
    ///
    /// Windows 10 maps unused address ranges as present, filled with one
    /// repeated entry. Following those tables makes every `*scan` plugin walk
    /// hundreds of gigabytes of address space that holds nothing, turning
    /// minutes into hours. The heuristic is kept because it is load-bearing,
    /// with four conditions that make it an assumption with evidentiary
    /// weight rather than a silent one:
    ///
    /// 1. It only applies under [`PteSemantics::Windows`]. It is a *Windows*
    ///    convention, and outside it a page-sized table whose entries are all
    ///    identical and present is an ordinary, real mapping: a Linux region
    ///    of read-only anonymous pages all pointing at the shared zero page
    ///    has exactly this shape, and suppressing it would delete a genuine
    ///    large mapping from the address space with nothing to show for it.
    /// 2. It only applies to a table filled with a **present** entry. A table
    ///    of identical *absent* entries — an all-zero table, the commonest
    ///    structure in any image — is reported as ordinary
    ///    [`TranslateError::NotPresent`], not as a suppression, so the counter
    ///    below means what it says.
    /// 3. Every suppression is visible in the outcome, not only in a counter.
    ///    The walk fails with [`TranslateError::UniformTableSuppressed`],
    ///    carrying the table's address, its level and **the repeated entry
    ///    itself**; the layer renders that as a
    ///    [`crate::layer::HoleReason::TableSuppressed`] hole, which no caller
    ///    can confuse with [`crate::layer::HoleReason::NotPresent`]. This is
    ///    what an examiner gets unconditionally, because it travels on the read
    ///    that was refused and no consumer can fail to notice it. A running
    ///    total is kept as well
    ///    ([`crate::translate::VirtualLayer::uniform_tables_suppressed`]),
    ///    reachable from an address space held as `Arc<dyn MemoryLayer>` through
    ///    [`crate::layer::MemoryLayer::as_virtual`]. Nothing in this crate
    ///    builds an address space, so publishing that number is the duty of the
    ///    caller that does — an examiner asking "could this tool have hidden a
    ///    page from me?" gets one only from a record that carries it.
    /// 4. It can be switched off per run, and then nothing is suppressed.
    ///
    /// [`PteSemantics::Windows`]: crate::translate::spec::PteSemantics::Windows
    pub suppress_uniform_tables: bool,
}

impl Default for TranslationPolicy {
    fn default() -> Self {
        Self {
            suppress_uniform_tables: true,
        }
    }
}

/// Every way a virtual address can fail to have a physical address behind it.
#[derive(Debug, thiserror::Error)]
pub enum TranslateError {
    /// The address is not in canonical form, so no processor in this mode could
    /// ever have issued it. Distinct from an absent page: there is no such
    /// address, as opposed to an address whose page is missing.
    #[error("virtual address {va:#x} is not canonical for {mode} paging")]
    NonCanonical { va: u64, mode: PagingMode },

    /// The address is above the top of this mode's virtual address space.
    #[error("virtual address {va:#x} is above the {bits}-bit virtual address space")]
    OutOfRange { va: u64, bits: u32 },

    /// A paging entry says the region it governs is not resident.
    #[error(
        "{level_name} entry {entry:#x} at {entry_pa:#x} is not present: \
         {va:#x} and the {region} bytes its entry governs are not in RAM"
    )]
    NotPresent {
        va: u64,
        /// Index of the level whose entry was absent, `0` being the top table.
        level: u8,
        level_name: &'static str,
        /// The entry's value, verbatim, so an examiner can decode it further.
        entry: u64,
        /// Where that entry lives in physical memory.
        entry_pa: u64,
        /// Virtual-address bits the entry did not resolve, i.e.
        /// `log2(region)`.
        invalid_bits: u8,
        /// Size in bytes of the region the absent entry governs.
        region: u64,
    },

    /// A Windows software PTE naming a page in a pagefile. The page exists; it
    /// is on the suspect's disk and not in this evidence item. Supply a
    /// pagefile and it becomes readable — which is why this is a different
    /// finding from [`TranslateError::NotPresent`] and never renders as zeros.
    #[error(
        "virtual address {va:#x} is paged out to {} at offset {swap_offset:#x} (entry {entry:#x})",
        match swap_index {
            Some(index) => format!("pagefile {index}"),
            None => "a pagefile this build's layout could not identify".to_string(),
        }
    )]
    SwappedOut {
        va: u64,
        /// Which pagefile, from `MMPTE_SOFTWARE.PageFileLow`.
        ///
        /// `None` when the build was never established. That field sits at bits
        /// 4:1 up to Windows 7 and at bits 15:12 from Windows 8, where the
        /// earlier bits became `PageFileReserved`, `PageFileAllocated`,
        /// `ColdPage` and `SwizzleBit` — so reading the wrong ones does not
        /// fail, it yields a small plausible integer naming a DIFFERENT
        /// pagefile. Naming none beats naming the wrong one, and `entry`
        /// carries the bits verbatim either way.
        ///
        /// The offset below does not move between layouts and is always
        /// reported.
        swap_index: Option<u8>,
        /// Byte offset of the 4 KiB pagefile page named by
        /// `MMPTE_SOFTWARE.PageFileHigh`.
        ///
        /// When the failing entry is *not* the final level, that page holds the
        /// paged-out paging structure which would have described this address,
        /// not the address's own data — reading it needs the pagefile and
        /// another walk. The scale is 4 KiB either way, because that is the
        /// unit Windows pages in.
        swap_offset: u64,
        /// Virtual-address bits the entry did not resolve.
        invalid_bits: u8,
        entry: u64,
    },

    /// A Linux `swp_entry_t`: the kernel moved this page's contents out of its
    /// frame and wrote down where, in an encoding this crate will not decode.
    ///
    /// Distinct from [`TranslateError::NotPresent`] because the two are
    /// different findings about the machine — "this address was never mapped"
    /// against "this address was mapped and its contents are elsewhere" — and
    /// distinct from [`TranslateError::SwappedOut`] because that variant names
    /// a file and an offset, and no fact in a Linux image supports naming
    /// either. The same encoding also carries migration entries, hardware-
    /// poison markers and device-private entries, so even the word *swap* would
    /// be more than the bits prove.
    ///
    /// The entry travels verbatim, which is what an examiner who knows the
    /// kernel needs in order to decode it themselves. See
    /// [`PteSemantics::Linux`] for why this crate does not do it for them.
    ///
    /// [`PteSemantics::Linux`]: crate::translate::spec::PteSemantics::Linux
    #[error(
        "virtual address {va:#x} has a non-empty, non-present {level_name} entry {entry:#x} at \
         {entry_pa:#x}: the Linux kernel moved this page's contents out of memory and recorded \
         where in a swap-entry layout that is a property of the kernel source, not of the \
         machine, so no swap area and no offset is claimed. The {region} bytes the entry governs \
         are not in this image"
    )]
    LinuxSwapEntry {
        va: u64,
        /// Index of the level whose entry held it, `0` being the top table.
        level: u8,
        level_name: &'static str,
        /// The entry's value, verbatim.
        entry: u64,
        /// Where that entry lives in physical memory.
        entry_pa: u64,
        /// Virtual-address bits the entry did not resolve.
        invalid_bits: u8,
        /// Size in bytes of the region the entry governs.
        region: u64,
    },

    /// A Windows prototype PTE that could **not** be followed to a resident
    /// page.
    ///
    /// The walker does follow prototype PTEs — see
    /// [`PagingSpec::prototype_address`] and [`TranslationPath::PrototypePte`]
    /// — so this variant means the chain ran out, and `detail` says where.
    /// Either the entry does not state a usable prototype address, or the
    /// prototype `_MMPTE` itself describes a page that is not in RAM (a
    /// subsection-backed page still on disk in the mapped file, or one written
    /// to the pagefile). "Shared page we could not reach" and "absent page" are
    /// different facts and this keeps them apart.
    ///
    /// [`PagingSpec::prototype_address`]: crate::translate::spec::PagingSpec::prototype_address
    #[error(
        "virtual address {va:#x} is described by a prototype PTE {entry:#x} \
         (prototype array at {}): {detail}",
        match proto_va {
            Some(va) => format!("{va:#x}"),
            None => "an address this entry does not state".to_string(),
        }
    )]
    PrototypePte {
        va: u64,
        entry: u64,
        entry_pa: u64,
        invalid_bits: u8,
        /// Kernel virtual address of the prototype `_MMPTE`, when the entry
        /// stated one this spec can decode. `None` is not "there is no array":
        /// it is "this entry does not say where it is", which is the
        /// `MI_PTE_LOOKUP_NEEDED` case and the 32-bit non-PAE layout.
        proto_va: Option<u64>,
        /// Why the chain stopped, in the words a report needs.
        detail: &'static str,
    },

    /// The page table itself could not be read out of the acquisition. The
    /// address may well have been mapped; the evidence needed to prove it is
    /// missing, and that is a different statement from "not mapped".
    #[error("page table at {table_pa:#x} could not be read (entry {entry_pa:#x}): {source}")]
    TableUnreadable {
        table_pa: u64,
        entry_pa: u64,
        /// Virtual-address bits below the unreadable table's level, so a caller
        /// can still skip the whole region it would have described.
        invalid_bits: u8,
        #[source]
        source: io::Error,
    },

    /// A page-sized table of identical present entries was treated as absent by
    /// the Windows 10 heuristic. Never silent: see
    /// [`TranslationPolicy::suppress_uniform_tables`].
    ///
    /// The repeated entry is carried verbatim, because the whole risk of this
    /// heuristic is that the table was *not* a decoy. An examiner who can see
    /// the entry can decode the frame it names, re-run with the policy off and
    /// compare — none of which is possible from a bare "something was hidden
    /// here".
    #[error(
        "{level_name} at {table_pa:#x} holds the entry {entry:#x} repeated in every \
         slot and was suppressed as unused (Windows 10 heuristic); {region} bytes \
         skipped. Re-run with suppress_uniform_tables off to read it"
    )]
    UniformTableSuppressed {
        table_pa: u64,
        /// Index of the level whose table was suppressed, `0` being the top.
        level: u8,
        level_name: &'static str,
        /// The entry every slot of the table held.
        entry: u64,
        invalid_bits: u8,
        region: u64,
    },

    /// The directory table base cannot be used. A DTB is a claim about where a
    /// process's address space begins; an unusable one is rejected at
    /// construction rather than producing translations from address zero.
    #[error("directory table base {dtb:#x} is not usable: {detail}")]
    InvalidDtb { dtb: u64, detail: &'static str },

    /// Arithmetic derived from an image byte left the addressable range. Only
    /// reachable from a corrupt or hostile table, and an error rather than a
    /// wrapped address because a wrapped address is a confident wrong answer.
    #[error("address arithmetic for {va:#x} left the addressable range: {detail}")]
    AddressOverflow { va: u64, detail: &'static str },
}

impl TranslateError {
    /// Virtual-address bits the failing entry did not resolve, when the failure
    /// is one that governs a region of address space.
    ///
    /// This is what lets a caller skip a whole absent directory in one step
    /// instead of re-walking every 4 KiB inside it.
    pub fn invalid_bits(&self) -> Option<u8> {
        match self {
            TranslateError::NotPresent { invalid_bits, .. }
            | TranslateError::SwappedOut { invalid_bits, .. }
            | TranslateError::LinuxSwapEntry { invalid_bits, .. }
            | TranslateError::PrototypePte { invalid_bits, .. }
            | TranslateError::TableUnreadable { invalid_bits, .. }
            | TranslateError::UniformTableSuppressed { invalid_bits, .. } => Some(*invalid_bits),
            TranslateError::NonCanonical { .. }
            | TranslateError::OutOfRange { .. }
            | TranslateError::InvalidDtb { .. }
            | TranslateError::AddressOverflow { .. } => None,
        }
    }

    /// How this failure renders as a hole in a memory layer's address space, if
    /// it does at all.
    ///
    /// A prototype PTE reports as [`HoleReason::NotPresent`]: the page-table
    /// entry genuinely is not present, and the finer fact — that a section
    /// object would resolve it — survives on this error, which
    /// [`crate::translate::VirtualLayer::translate`] hands back unflattened.
    ///
    /// A Linux swap-family entry reports the same way and for the same reason.
    /// [`HoleReason::SwappedOut`] is defined as "the bytes exist on the
    /// suspect's disk, in a swap file, and are simply not in this evidence
    /// item", and that sentence is not proved by the entry: the same encoding
    /// carries migration and hardware-poison entries, whose pages are in RAM or
    /// gone rather than on a disk. `not_present` is true of every one of them,
    /// and the precise statement rides on this error for the callers that read
    /// it.
    ///
    /// An unreadable table is only a hole when the *reason* it was unreadable
    /// was itself a hole in the acquisition. A genuine I/O failure is not a
    /// hole and must not be dressed as one.
    pub fn hole_reason(&self) -> Option<HoleReason> {
        match self {
            TranslateError::NotPresent { .. }
            | TranslateError::LinuxSwapEntry { .. }
            | TranslateError::PrototypePte { .. } => Some(HoleReason::NotPresent),
            TranslateError::SwappedOut { .. } => Some(HoleReason::SwappedOut),
            TranslateError::UniformTableSuppressed { .. } => Some(HoleReason::TableSuppressed),
            TranslateError::TableUnreadable { source, .. } => {
                MemoryHole::from_io(source).map(|_| HoleReason::Unmapped)
            }
            TranslateError::NonCanonical { .. }
            | TranslateError::OutOfRange { .. }
            | TranslateError::InvalidDtb { .. }
            | TranslateError::AddressOverflow { .. } => None,
        }
    }

    /// Render this failure into the layer vocabulary, for `mapping()`.
    ///
    /// `va` is the address that was being translated and `max_address` the top
    /// of the layer's space. The hole produced is always in **virtual** space:
    /// a physical-space hole recovered from an unreadable table is deliberately
    /// re-expressed as the virtual region it made unreadable, never passed
    /// through with its physical address, because a caller indexing by virtual
    /// address would then record the wrong range.
    pub fn into_layer_error(self, va: u64, max_address: u64) -> LayerError {
        if let (Some(reason), Some(bits)) = (self.hole_reason(), self.invalid_bits()) {
            return LayerError::Hole(MemoryHole {
                address: va,
                length: unresolved_span(va, bits),
                reason,
            });
        }
        match self {
            TranslateError::NonCanonical { .. } | TranslateError::OutOfRange { .. } => {
                LayerError::OutOfRange {
                    address: va,
                    max_address,
                }
            }
            TranslateError::TableUnreadable { source, .. } => LayerError::Io(source),
            other => LayerError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                other.to_string(),
            )),
        }
    }
}

/// Why a prototype chain stopped when the array's own page is itself described
/// by a prototype PTE. One string, reported by the inner walk and re-reported
/// by the outer one, so a caller sees the same sentence either way.
const PROTOTYPE_HOP_BOUND: &str = "the prototype array's own page is itself described by a \
     prototype PTE; the chain is not followed past one hop";

/// Bytes from `va` to the end of the region a failing entry governs.
///
/// Not the whole region: the part of it at and after `va`, so a caller that
/// records the hole records a range it actually asked about.
pub fn unresolved_span(va: u64, invalid_bits: u8) -> u64 {
    let bits = u32::from(invalid_bits);
    if bits >= 64 {
        return u64::MAX;
    }
    let size = 1u64 << bits;
    size - (va & (size - 1))
}

/// One table, read whole, with the uniformity of the bytes that were read.
///
/// Returned by [`PageWalk::read_table`] for a caller that will use every
/// entry. `shape` is derived from `entries` and is therefore free — it is not a
/// second read, and it is deliberately a fact about the bytes rather than a
/// verdict about them, exactly as [`TableShape`] is in the memo.
pub(in crate::translate) struct TableRead {
    /// Every entry of the table, in index order, decoded at this spec's width.
    pub entries: Vec<u64>,
    /// Whether those entries are all identical, and to what.
    pub shape: TableShape,
    /// How many bytes were read, so a caller can publish the I/O it spent.
    pub bytes: u64,
}

/// A paging table's size and entry width, derived from the spec's own level
/// declaration rather than assumed to be 4 KiB of eight-byte entries.
struct TableGeometry {
    bytes: usize,
    entry_size: usize,
}

/// One page-table walk over a physical layer.
///
/// Cheap to construct — it borrows everything — so a layer builds one per
/// translation rather than holding mutable state.
pub struct PageWalk<'a> {
    physical: &'a dyn MemoryLayer,
    spec: &'a PagingSpec,
    cache: &'a TableCache,
    policy: TranslationPolicy,
    suppressed: &'a AtomicU64,
}

impl<'a> PageWalk<'a> {
    /// Prepare a walk over `physical` under `spec`, memoising entries in
    /// `cache` and counting uniform-table suppressions into `suppressed`.
    pub fn new(
        physical: &'a dyn MemoryLayer,
        spec: &'a PagingSpec,
        cache: &'a TableCache,
        policy: TranslationPolicy,
        suppressed: &'a AtomicU64,
    ) -> Self {
        Self {
            physical,
            spec,
            cache,
            policy,
            suppressed,
        }
    }

    /// Translate `va` through the tables rooted at `dtb`.
    ///
    /// The result describes only the page tables. It does **not** assert that
    /// the physical frame is present in the acquisition — a page can be
    /// perfectly mapped and still have been skipped or smeared by the capture
    /// tool. That check belongs to the layer, which knows how many bytes were
    /// actually asked for, and reports it as an unmapped hole.
    pub fn translate(&self, dtb: u64, va: u64) -> Result<Translation, TranslateError> {
        self.translate_inner(dtb, va, true)
    }

    /// The walk proper.
    ///
    /// `follow_prototype` is `false` for the inner walk that locates a
    /// prototype `_MMPTE`, which is what bounds the recursion at one hop: a
    /// prototype array whose own page is described by another prototype PTE
    /// reports that fact instead of recursing.
    fn translate_inner(
        &self,
        dtb: u64,
        va: u64,
        follow_prototype: bool,
    ) -> Result<Translation, TranslateError> {
        let spec = self.spec;
        if !spec.is_canonical(va) {
            return Err(if spec.bits_per_register() >= 64 {
                TranslateError::NonCanonical {
                    va,
                    mode: spec.mode(),
                }
            } else {
                TranslateError::OutOfRange {
                    va,
                    bits: spec.max_virt_addr_bits(),
                }
            });
        }
        let index_source = spec.index_source(va);

        // The directory table base is a control register, not a table entry, so
        // it has no present bit of its own, and the walker must not demand one.
        // Setting bit 0 says so explicitly and the table mask strips it again,
        // so a DTB recorded with its low control flags and one recorded without
        // them translate identically. Every *other* entry the loop follows was
        // read from memory and proved present before it was used.
        let mut entry = dtb | PRESENT_BIT;
        let mut remaining = spec.max_virt_addr_bits();
        let levels = spec.levels();
        // Hierarchical execute-never: an Intel non-leaf entry's XD bit, or an
        // ARM64 table descriptor's XNTable bit for this regime, governs every
        // leaf below it.
        let mut inherited_no_execute = false;

        for (depth, level) in levels.iter().enumerate() {
            // Where this level's table begins. The alignment is the table's own
            // size: 4 KiB for a 512- or 1024-entry table, but only 32 bytes for
            // PAE's four-entry pointer table, which is the case a hardcoded
            // 12-bit mask gets wrong on PAE images alone.
            let table_pa = match if depth == 0 {
                self.root_pa_of(dtb)
            } else {
                self.table_pa_of(entry, depth)
            } {
                Some(table_pa) => table_pa,
                None => {
                    return Err(TranslateError::AddressOverflow {
                        va,
                        detail: "paging spec declares a table this walk cannot address",
                    })
                }
            };

            let Some(next_remaining) = remaining.checked_sub(level.index_bits) else {
                return Err(TranslateError::AddressOverflow {
                    va,
                    detail: "level table indexes more bits than the mode translates",
                });
            };
            remaining = next_remaining;

            let table_bytes = 1u64 << (level.index_bits + spec.entry_size_log2());
            if self.policy.suppress_uniform_tables
                && spec.uniform_table_heuristic_applies()
                && table_bytes == UNIFORM_TABLE_BYTES
            {
                if let Some(repeated) = self.uniform_present_entry(table_pa) {
                    self.suppressed.fetch_add(1, Ordering::Relaxed);
                    let invalid_bits = saturating_u8(remaining + level.index_bits);
                    return Err(TranslateError::UniformTableSuppressed {
                        table_pa,
                        level: saturating_u8(depth as u32),
                        level_name: level.name,
                        entry: repeated,
                        invalid_bits,
                        region: unresolved_span(0, invalid_bits),
                    });
                }
            }

            let index = (index_source >> remaining) & ((1u64 << level.index_bits) - 1);
            let Some(entry_pa) = index
                .checked_mul(u64::from(spec.entry_size()))
                .and_then(|offset| table_pa.checked_add(offset))
            else {
                return Err(TranslateError::AddressOverflow {
                    va,
                    detail: "page-table entry address left the 64-bit space",
                });
            };

            let raw = self.read_entry(table_pa, entry_pa, saturating_u8(remaining))?;

            // What the entry is — table, page, block, or nothing — is the
            // spec's decision, made by the level's own rule. This walker no
            // longer knows that Intel's bit 7 is a size flag or that ARM64's
            // bit 1 is a type bit: it asks, and the enumeration asks the same
            // function, so the two cannot disagree.
            let Some(kind) = spec.classify(raw, depth) else {
                return Err(TranslateError::AddressOverflow {
                    va,
                    detail: "paging spec declares a level it cannot classify",
                });
            };
            match kind {
                EntryKind::Invalid => {
                    return self.resolve_invalid(
                        dtb,
                        va,
                        raw,
                        entry_pa,
                        depth,
                        level.name,
                        remaining,
                        follow_prototype,
                    );
                }
                EntryKind::Unnameable { detail } => {
                    return Err(TranslateError::AddressOverflow { va, detail });
                }
                EntryKind::Leaf {
                    frame,
                    size_log2,
                    no_execute,
                } => {
                    if size_log2 >= 64 {
                        return Err(TranslateError::AddressOverflow {
                            va,
                            detail: "paging spec declares a page wider than the address space",
                        });
                    }
                    let page_mask = (1u64 << size_log2) - 1;
                    return Ok(Translation {
                        phys: frame | (va & page_mask),
                        run_len: 1u64 << size_log2,
                        level: saturating_u8(depth as u32),
                        no_execute: no_execute || inherited_no_execute,
                        via: TranslationPath::PageTables,
                    });
                }
                EntryKind::Table => {
                    inherited_no_execute |= spec.table_execute_never(raw, depth);
                }
            }

            entry = raw;
        }

        // Unreachable for every spec in this crate, because the final level
        // always returns. Failing closed rather than looping or panicking keeps
        // that true for any spec added later.
        Err(TranslateError::InvalidDtb {
            dtb,
            detail: "paging spec declares no final level",
        })
    }

    /// Read one entry, through the memo.
    fn read_entry(
        &self,
        table_pa: u64,
        entry_pa: u64,
        invalid_bits: u8,
    ) -> Result<u64, TranslateError> {
        if let Some(value) = self.cache.entry(entry_pa) {
            return Ok(value);
        }
        let size = self.spec.entry_size() as usize;
        let mut buf = [0u8; 8];
        let slice = match buf.get_mut(..size) {
            Some(slice) => slice,
            None => {
                return Err(TranslateError::AddressOverflow {
                    va: entry_pa,
                    detail: "paging spec declares an entry wider than 8 bytes",
                })
            }
        };
        // `read_exact_or_fail`, not a best-effort read: a partially read entry
        // is not an entry, and a zero-padded one would translate to physical
        // address zero — a real, readable address holding someone else's bytes.
        read_exact_or_fail(
            self.physical.as_data_source(),
            entry_pa,
            slice,
            "page-table entry",
        )
        .map_err(|source| TranslateError::TableUnreadable {
            table_pa,
            entry_pa,
            invalid_bits,
            source,
        })?;
        let value = decode_entry(&buf, size);
        self.cache.store_entry(entry_pa, value);
        Ok(value)
    }

    /// The entry a page-sized table at `table_pa` repeats in every slot, when
    /// that entry is *present* — the Windows 10 unused-address pattern.
    ///
    /// `None` means "do not suppress": the table is mixed, its repeated entry
    /// is not present, or it could not be read.
    ///
    /// Returning the entry rather than a bare `true` is what lets the
    /// suppression name what it hid. Two separations keep it honest. The memo
    /// stores what the bytes were ([`TableShape`]), not what to do about them,
    /// so an address space read under different OS conventions cannot inherit
    /// this one's judgement. And a probe that cannot be read returns `None`
    /// while remembering nothing: the heuristic may only ever suppress a table
    /// it has actually seen, so an unreadable table falls through to the
    /// per-entry read, which reports the precise failure instead.
    fn uniform_present_entry(&self, table_pa: u64) -> Option<u64> {
        let shape = match self.cache.table_shape(table_pa) {
            Some(shape) => shape,
            None => {
                let shape = self.probe_table(table_pa)?;
                self.cache.store_table_shape(table_pa, shape);
                shape
            }
        };
        match shape {
            TableShape::Mixed => None,
            // An all-zero table is `Repeated(0)`, and zero is not present, so
            // the commonest structure in any image is reported as ordinarily
            // absent rather than counted as a suppression.
            TableShape::Repeated(entry) if self.spec.entry_is_present(entry) => Some(entry),
            TableShape::Repeated(_) => None,
        }
    }

    /// The paging spec this walk is reading under.
    ///
    /// For the downward enumeration, which asks the same spec the same
    /// questions the upward walk does rather than carrying a second copy of
    /// it.
    pub(in crate::translate) fn spec(&self) -> &PagingSpec {
        self.spec
    }

    /// The physical address of the table that level `level`'s entry points at.
    ///
    /// The alignment mask is the **child table's own size** — 4 KiB for a 512-
    /// or 1024-entry table, but only 32 bytes for PAE's four-entry
    /// page-directory-pointer table. A hardcoded 12-bit mask is the one
    /// transcription mistake that goes wrong on PAE images alone, and it goes
    /// wrong quietly: the address it produces is a real, readable address
    /// holding somebody else's bytes.
    ///
    /// Shared by the upward walk and the downward enumeration so the two
    /// cannot mask differently. The directory table base is passed through it
    /// as well, which is what strips the low control flags a DTB may have been
    /// recorded with.
    ///
    /// `None` for a level this mode has not, or a spec whose table could not
    /// be addressed at all.
    pub(in crate::translate) fn table_pa_of(&self, entry: u64, level: usize) -> Option<u64> {
        self.spec.table_pa_of_entry(entry, level)
    }

    /// The physical address of the root table a recorded directory table base
    /// names. For every mode but an ARM64 LPA2 regime this is
    /// [`PageWalk::table_pa_of`] at level 0 with the base taken as an entry; an
    /// LPA2 `TTBRn_EL1` has its address bits 51:48 elsewhere than a descriptor
    /// does (see [`PagingSpec::root_table_pa`]).
    pub(in crate::translate) fn root_pa_of(&self, dtb: u64) -> Option<u64> {
        self.spec.root_table_pa(dtb)
    }

    /// One whole table in one read, for a caller that will use every entry.
    ///
    /// `level` indexes [`PagingSpec::levels`] and fixes both the table's byte
    /// size and its entry count: `1 << (index_bits + entry_size_log2)`, which
    /// is 4 KiB for a 512- or 1024-entry table and **32 bytes** for PAE's
    /// four-entry page-directory-pointer table. A hardcoded 4 KiB here is the
    /// mistake that reads 127 neighbouring tables as one on a PAE image.
    ///
    /// # Why this exists beside [`PageWalk::read_entry`]
    ///
    /// The upward walk reads one entry per level and memoises it, which is
    /// right for a walk that will come back for the same three tables
    /// thousands of times. A downward enumeration is the opposite shape: it
    /// touches every entry of a table exactly once and never returns to it.
    /// Through the per-entry path that is 512 reads of eight bytes per table,
    /// and it would cycle the 65,536-entry memo many times over for a hit rate
    /// of zero while evicting every other stage's working set. So this reads
    /// the table whole and writes **nothing** to either memo.
    ///
    /// The shape is computed from the bytes already in hand rather than by
    /// [`PageWalk::probe_table`], which reads its own 4 KiB and then discards
    /// all 512 entries: paying that before a bulk read would double the I/O of
    /// a whole enumeration.
    ///
    /// # Errors
    ///
    /// [`TranslateError::TableUnreadable`] when the table could not be read
    /// whole. The caller may then fall back to the per-entry path, which
    /// reports precisely which entries were unreachable instead of losing the
    /// table — a table straddling the end of a truncated acquisition still has
    /// entries in it.
    pub(in crate::translate) fn read_table(
        &self,
        table_pa: u64,
        level: usize,
        invalid_bits: u8,
    ) -> Result<TableRead, TranslateError> {
        let shape = self
            .table_shape_bytes(level)
            .ok_or(TranslateError::AddressOverflow {
                va: table_pa,
                detail: "paging spec declares a table this walk cannot size",
            })?;
        let mut bytes = vec![0u8; shape.bytes];
        read_exact_or_fail(
            self.physical.as_data_source(),
            table_pa,
            &mut bytes,
            "page table",
        )
        .map_err(|source| TranslateError::TableUnreadable {
            table_pa,
            entry_pa: table_pa,
            invalid_bits,
            source,
        })?;
        let entries: Vec<u64> = bytes
            .chunks_exact(shape.entry_size)
            .map(|chunk| {
                let mut widened = [0u8; 8];
                widened[..shape.entry_size].copy_from_slice(chunk);
                decode_entry(&widened, shape.entry_size)
            })
            .collect();
        let uniform = match entries.split_first() {
            Some((first, rest)) if rest.iter().all(|entry| entry == first) => {
                TableShape::Repeated(*first)
            }
            // An empty table cannot be uniform, and no shipped spec declares
            // one; `Mixed` is the answer that claims nothing.
            _ => TableShape::Mixed,
        };
        Ok(TableRead {
            entries,
            shape: uniform,
            bytes: shape.bytes as u64,
        })
    }

    /// The byte size and entry width of level `level`'s table, or `None` for a
    /// level this mode has not or a spec whose entries are wider than 8 bytes.
    fn table_shape_bytes(&self, level: usize) -> Option<TableGeometry> {
        let index_bits = self.spec.levels().get(level)?.index_bits;
        let entry_size = self.spec.entry_size() as usize;
        if entry_size == 0 || entry_size > 8 {
            return None;
        }
        let low = index_bits.checked_add(self.spec.entry_size_log2())?;
        if low >= 32 {
            return None;
        }
        Some(TableGeometry {
            bytes: 1usize << low,
            entry_size,
        })
    }

    /// Read whether this level's table is the Windows unused-address filler,
    /// from a shape already in hand.
    ///
    /// The four conditions are [`PageWalk::translate`]'s own, in the same
    /// order: the policy is on, the semantics are Windows', the table is
    /// page-sized — PAE's 32-byte pointer table is excluded, because four
    /// identical entries is a coincidence — and the repeated entry is
    /// *present*. An all-zero table is `Repeated(0)`, which is not present, so
    /// the commonest structure in any image is ordinary absence and not a
    /// suppression.
    pub(in crate::translate) fn uniform_filler(
        &self,
        level: usize,
        shape: TableShape,
    ) -> Option<u64> {
        if !self.policy.suppress_uniform_tables || !self.spec.uniform_table_heuristic_applies() {
            return None;
        }
        let geometry = self.table_shape_bytes(level)?;
        if geometry.bytes as u64 != UNIFORM_TABLE_BYTES {
            return None;
        }
        match shape {
            TableShape::Repeated(entry) if self.spec.entry_is_present(entry) => Some(entry),
            _ => None,
        }
    }

    /// Read a whole page-sized table and say whether its entries are identical.
    /// `None` when the table could not be read, which must never be recorded.
    fn probe_table(&self, table_pa: u64) -> Option<TableShape> {
        let size = self.spec.entry_size() as usize;
        if size == 0 || size > 8 {
            return None;
        }
        let mut table = [0u8; UNIFORM_TABLE_BYTES as usize];
        read_exact_or_fail(
            self.physical.as_data_source(),
            table_pa,
            &mut table,
            "page table",
        )
        .ok()?;
        let mut chunks = table.chunks_exact(size);
        let first = chunks.next()?;
        if !chunks.all(|chunk| chunk == first) {
            return Some(TableShape::Mixed);
        }
        let mut widened = [0u8; 8];
        widened[..size].copy_from_slice(first);
        Some(TableShape::Repeated(decode_entry(&widened, size)))
    }

    /// Turn an entry the hardware would reject into a translation, if the
    /// convention in force can still reach the page, or into the most specific
    /// honest statement it supports if it cannot.
    #[allow(clippy::too_many_arguments)]
    fn resolve_invalid(
        &self,
        dtb: u64,
        va: u64,
        entry: u64,
        entry_pa: u64,
        depth: usize,
        level_name: &'static str,
        remaining: u32,
        follow_prototype: bool,
    ) -> Result<Translation, TranslateError> {
        let invalid_bits = saturating_u8(remaining);
        let not_present = || TranslateError::NotPresent {
            va,
            level: saturating_u8(depth as u32),
            level_name,
            entry,
            entry_pa,
            invalid_bits,
            region: unresolved_span(0, invalid_bits),
        };
        Err(match self.spec.classify_invalid(entry) {
            InvalidEntry::NotPresent => not_present(),
            // The kernel put a `swp_entry_t` here, so the region this entry
            // governs was mapped and its contents are elsewhere. Reporting it
            // as plain absence would erase that, and reporting it as
            // `SwappedOut` would name a file and an offset the bits do not
            // prove — see `PteSemantics::Linux`.
            InvalidEntry::LinuxSwapEntry => TranslateError::LinuxSwapEntry {
                va,
                level: saturating_u8(depth as u32),
                level_name,
                entry,
                entry_pa,
                invalid_bits,
                region: unresolved_span(0, invalid_bits),
            },
            InvalidEntry::Prototype => {
                return self.resolve_prototype(
                    dtb,
                    va,
                    entry,
                    entry_pa,
                    depth,
                    remaining,
                    follow_prototype,
                )
            }
            InvalidEntry::PageFile { index, page_number } => {
                // `MMPTE_SOFTWARE.PageFileHigh` counts 4 KiB pagefile pages at
                // every level, because what Windows writes to the pagefile is
                // always a 4 KiB page: when a *page table* is paged out, the
                // page-directory entry names that one 4 KiB table, not the
                // 2 MiB of address space the table described. Scaling by the
                // failing level's region size would multiply the disk offset by
                // up to 512 and send an examiner to the wrong place in the
                // pagefile. An offset that will not fit is not reported at all,
                // for the same reason: a truncated disk offset is a wrong one.
                match page_number.checked_mul(1u64 << PAGE_OFFSET_BITS) {
                    Some(swap_offset) => TranslateError::SwappedOut {
                        va,
                        swap_index: index,
                        swap_offset,
                        invalid_bits,
                        entry,
                    },
                    None => not_present(),
                }
            }
        })
    }

    /// Follow a Windows prototype PTE to the page it describes.
    ///
    /// # What an examiner learns
    ///
    /// A prototype PTE is not a statement that the page is gone. It says the
    /// page belongs to a section object — a mapped file, a shared memory
    /// region, the image of every DLL in the process — and that its real state
    /// is held once, in the section's prototype PTE array, rather than in each
    /// process's own tables. That array lives in paged pool, is mapped into
    /// every address space, and is reachable through the very page tables this
    /// walk is already using. Very often the entry there is *valid or in
    /// transition*, which means the frame is in RAM and in the acquisition.
    ///
    /// Stopping at the prototype PTE and calling the address a hole therefore
    /// throws away recoverable evidence in precisely the region an examiner
    /// cares most about: module code and mapped data.
    ///
    /// # What a wrong answer would look like
    ///
    /// A page of unrelated memory attributed to this virtual address, parsing
    /// perfectly. Three refusals keep that from happening:
    ///
    /// - Only a **final-level** entry is followed. Windows does not put a
    ///   prototype PTE in a page directory; one that appears there is corrupt
    ///   or hostile, and decoding its `ProtoAddress` would be decoding noise.
    /// - Only an address [`PagingSpec::prototype_address`] can state without
    ///   guessing is used — see there for the layouts it refuses.
    /// - Only a prototype `_MMPTE` the spec calls **present** yields a
    ///   translation. A subsection-backed entry (the page is still on disk in
    ///   the mapped file) and a software entry in the prototype array are not
    ///   distinguishable from one another without the control area, so neither
    ///   is decoded: both report as an unreached prototype, which is true.
    ///
    /// The recursion is bounded at one hop by `follow_prototype`.
    ///
    /// # Why the inner walk's failure is not re-labelled
    ///
    /// "The prototype array is not resident" is a claim about the acquisition,
    /// and [`TranslateError::PrototypePte`] renders as an absent page. Neither
    /// is true when the walk to the array failed because the evidence file
    /// would not read, or because this tool's own uniform-table heuristic
    /// declined to look. Those come back as themselves — an unreadable table
    /// stays [`TranslateError::TableUnreadable`], a suppression stays
    /// [`TranslateError::UniformTableSuppressed`] — narrowed to the single page
    /// whose translation they actually stopped, so the hole an examiner sees is
    /// the right size and names the right cause.
    ///
    /// [`PagingSpec::prototype_address`]: crate::translate::spec::PagingSpec::prototype_address
    #[allow(clippy::too_many_arguments)]
    fn resolve_prototype(
        &self,
        dtb: u64,
        va: u64,
        entry: u64,
        entry_pa: u64,
        depth: usize,
        remaining: u32,
        follow_prototype: bool,
    ) -> Result<Translation, TranslateError> {
        let invalid_bits = saturating_u8(remaining);
        let unreached =
            |proto_va: Option<u64>, detail: &'static str| TranslateError::PrototypePte {
                va,
                entry,
                entry_pa,
                invalid_bits,
                proto_va,
                detail,
            };

        if !follow_prototype {
            return Err(unreached(
                self.spec.prototype_address(entry),
                PROTOTYPE_HOP_BOUND,
            ));
        }
        if remaining != PAGE_OFFSET_BITS {
            return Err(unreached(
                None,
                "the prototype bit is set on an entry above the final level, where Windows \
                 never puts one; its ProtoAddress field is not decoded",
            ));
        }
        let Some(proto_va) = self.spec.prototype_address(entry) else {
            return Err(unreached(
                None,
                "the entry does not state a prototype address this paging mode can decode \
                 (MI_PTE_LOOKUP_NEEDED, a zero address, or the 32-bit non-PAE split layout)",
            ));
        };

        // The prototype array is kernel paged pool, mapped in every address
        // space, so the same directory table base reaches it.
        let located = match self.translate_inner(dtb, proto_va, false) {
            Ok(located) => located,
            // The array's own page is described by another prototype PTE. The
            // hop bound is what the caller needs to see, not "not resident",
            // which would be a different and untrue statement.
            Err(TranslateError::PrototypePte { .. }) => {
                return Err(unreached(Some(proto_va), PROTOTYPE_HOP_BOUND))
            }
            // A table on the way to the array was hidden by this tool's own
            // heuristic. Saying "not resident" would blame the acquisition for
            // something the tool did, and would report the page as absent
            // rather than as suppressed, so the suppression is re-reported —
            // narrowed to the one page whose translation it actually stopped.
            Err(TranslateError::UniformTableSuppressed {
                table_pa,
                level,
                level_name,
                entry: repeated,
                ..
            }) => {
                return Err(TranslateError::UniformTableSuppressed {
                    table_pa,
                    level,
                    level_name,
                    entry: repeated,
                    invalid_bits,
                    region: unresolved_span(0, invalid_bits),
                })
            }
            // Not a hole: the evidence file would not give up the array's page
            // tables, or the walk left the addressable range. "We could not
            // read this" and "this page is not in RAM" are different findings,
            // and only the second is a fact about the suspect's machine — so
            // the failure is passed through as itself, narrowed to the page it
            // stopped, instead of being flattened into an absent page.
            Err(err) if err.hole_reason().is_none() => {
                return Err(match err {
                    TranslateError::TableUnreadable {
                        table_pa,
                        entry_pa: table_entry_pa,
                        source,
                        ..
                    } => TranslateError::TableUnreadable {
                        table_pa,
                        entry_pa: table_entry_pa,
                        invalid_bits,
                        source,
                    },
                    other => other,
                })
            }
            Err(_) => {
                return Err(unreached(
                    Some(proto_va),
                    "the prototype array itself is not resident in this acquisition, so the \
                     page's real state could not be read",
                ))
            }
        };
        // The array entry is read through the same memo and the same
        // fail-closed helper as any other entry: a short read is not an entry.
        let proto = self.read_entry(located.page_base(), located.phys, PAGE_OFFSET_BITS as u8)?;

        if !self.spec.entry_is_present(proto) {
            return Err(unreached(
                Some(proto_va),
                "the prototype PTE describes a page that is not in RAM: it is still in the \
                 mapped file or in a pagefile, and which of those cannot be told apart \
                 without the section's control area",
            ));
        }
        let phys_high = self.spec.max_phys_addr_bits().saturating_sub(1);
        let frame = mask_bits(proto, phys_high, PAGE_OFFSET_BITS);
        let page_mask = (1u64 << PAGE_OFFSET_BITS) - 1;
        Ok(Translation {
            phys: frame | (va & page_mask),
            run_len: 1u64 << PAGE_OFFSET_BITS,
            // The level the process's own walk reached before handing over.
            level: saturating_u8(depth as u32),
            no_execute: (proto & NX_BIT) != 0,
            via: TranslationPath::PrototypePte {
                proto_va,
                proto_pa: located.phys,
            },
        })
    }
}

/// Decode `size` little-endian bytes of `buf` into an entry value.
///
/// Explicit indices rather than a slice conversion, so there is no fallible
/// path to get wrong and nothing to unwrap.
fn decode_entry(buf: &[u8; 8], size: usize) -> u64 {
    if size <= 4 {
        u64::from(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
    } else {
        u64::from_le_bytes(*buf)
    }
}

/// Narrow a bit count to `u8`. Every caller passes a value from a level table,
/// all of which are far below 255; the saturation exists so no arithmetic here
/// can panic on a spec added later.
fn saturating_u8(value: u32) -> u8 {
    if value > u8::MAX as u32 {
        u8::MAX
    } else {
        value as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physical::PhysicalLayer;
    use crate::translate::spec::{
        PteSemantics, LARGE_PAGE_BIT, LINUX_PROTNONE_BIT, PAT_LARGE_BIT, WINDOWS_PROTOTYPE_BIT,
        WINDOWS_TRANSITION_BIT, WINDOWS_X64_PROTO_ADDRESS_SHIFT,
    };
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use std::sync::Arc;

    use crate::translate::test_image::{Harness, Image};

    /// A four-level x64 hierarchy: PML4 0x1000, PDPT 0x2000, PD 0x3000,
    /// PT 0x4000, and one data page at 0x5000.
    fn x64_image() -> Image {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 2, 0x4000 | PRESENT_BIT);
        image.entry64(0x4000, 1, 0x5000 | PRESENT_BIT);
        image.fill(0x5000, 0x1000, 0xAB);
        image
    }

    #[test]
    fn a_four_kilobyte_page_translates_through_all_four_x64_levels() {
        let harness = Harness::new(x64_image(), PagingMode::Intel32e, PteSemantics::Bare);
        // 0x401000: PML4 0, PDPT 0, PD 2, PT 1.
        let t = harness
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect("a fully mapped page");
        assert_eq!(t.phys, 0x5000);
        assert_eq!(t.run_len, 0x1000);
        assert_eq!(t.level, 3);
        assert!(!t.no_execute);

        // The page offset is carried, not dropped.
        let t = harness.walk().translate(0x1000, 0x0040_1ABC).unwrap();
        assert_eq!(t.phys, 0x5ABC);
        assert_eq!(t.bytes_to_page_end(), 0x1000 - 0xABC);
        assert_eq!(t.page_base(), 0x5000);
    }

    /// A five-level (LA57) hierarchy: PML5 0x1000, PML4 0x2000, PDPT 0x3000,
    /// PD 0x4000, PT 0x5000, and one data page at 0x6000.
    ///
    /// Indexed so that every level below the PML5 takes the same index as
    /// [`x64_image`] does, which is what makes the two fixtures comparable: the
    /// only difference between them is the extra table on top.
    fn la57_image() -> Image {
        let mut image = Image::new();
        image.entry64(0x1000, 256, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 0, 0x4000 | PRESENT_BIT);
        image.entry64(0x4000, 2, 0x5000 | PRESENT_BIT);
        image.entry64(0x5000, 1, 0x6000 | PRESENT_BIT);
        image.fill(0x6000, 0x1000, 0xCD);
        image
    }

    /// The first address of the LA57 upper canonical half, plus the offset the
    /// four-level fixtures use. PML5 256, PML4 0, PDPT 0, PD 2, PT 1.
    const LA57_KERNEL_VA: u64 = 0xFF00_0000_0040_1000;

    #[test]
    fn a_five_level_walk_reaches_an_address_four_level_paging_cannot_express() {
        // The defect: there was no five-level mode, so an LA57 machine's kernel
        // addresses had no translation at all — `is_canonical` refused every
        // one of them against bit 47, which is the second assertion here and
        // was the *only* behaviour available before.
        let harness = Harness::new(la57_image(), PagingMode::Intel32eLa57, PteSemantics::Linux);
        let t = harness
            .walk()
            .translate(0x1000, LA57_KERNEL_VA)
            .expect("a fully mapped page in a 57-bit space");
        assert_eq!(t.phys, 0x6000);
        assert_eq!(t.run_len, 0x1000);
        assert_eq!(t.level, 4, "the fifth level is the one that ended the walk");

        // The page offset is carried through the extra level, not dropped.
        let t = harness
            .walk()
            .translate(0x1000, LA57_KERNEL_VA + 0xABC)
            .unwrap();
        assert_eq!(t.phys, 0x6ABC);
        assert_eq!(t.page_base(), 0x6000);

        // Four-level rules cannot even state this address.
        let four = Harness::new(la57_image(), PagingMode::Intel32e, PteSemantics::Linux);
        let err = four
            .walk()
            .translate(0x1000, LA57_KERNEL_VA)
            .expect_err("a 57-bit address is not canonical for four-level paging");
        assert!(
            matches!(err, TranslateError::NonCanonical { .. }),
            "{err:?}"
        );
        // And it is refused rather than masked down to 48 bits, which would
        // have invented a translation for an address the mode cannot hold.
        assert_eq!(err.hole_reason(), None);
    }

    #[test]
    fn a_five_level_walk_names_the_level_that_failed_by_its_own_name() {
        // A depth error has to be readable as one. An absent PML5 entry governs
        // the whole 128 PiB below it, and calling that level "page map level 4"
        // would send an examiner looking one table down.
        let mut image = la57_image();
        image.entry64(0x1000, 256, 0);
        let harness = Harness::new(image, PagingMode::Intel32eLa57, PteSemantics::Linux);
        let err = harness
            .walk()
            .translate(0x1000, LA57_KERNEL_VA)
            .expect_err("an absent top-level entry");
        match &err {
            TranslateError::NotPresent {
                level,
                level_name,
                invalid_bits,
                ..
            } => {
                assert_eq!(*level, 0);
                assert_eq!(*level_name, "page map level 5");
                // 57 virtual bits less the PML5's own nine.
                assert_eq!(*invalid_bits, 48);
            }
            other => panic!("expected an absent top-level entry, got {other:?}"),
        }
    }

    #[test]
    fn the_kernel_half_of_the_canonical_space_translates() {
        // The upper canonical half is where every operating system puts its
        // kernel, so a walker that only handles the lower half is useless.
        let mut image = Image::new();
        image.entry64(0x1000, 256, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 0, 0x4000 | PRESENT_BIT);
        image.entry64(0x4000, 3, 0x6000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let t = harness
            .walk()
            .translate(0x1000, 0xFFFF_8000_0000_3000)
            .expect("kernel space must translate");
        assert_eq!(t.phys, 0x6000);
    }

    #[test]
    fn a_one_gigabyte_page_terminates_the_walk_at_the_pdpt() {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        // A 1 GiB frame at physical 0x4000_0000, with the PAT bit set to prove
        // it is cleared before the frame is extracted.
        image.entry64(
            0x2000,
            1,
            0x4000_0000 | LARGE_PAGE_BIT | PAT_LARGE_BIT | PRESENT_BIT,
        );
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let t = harness
            .walk()
            .translate(0x1000, 0x4000_2000)
            .expect("a 1 GiB page");
        assert_eq!(t.run_len, 1 << 30);
        assert_eq!(t.level, 1);
        assert_eq!(t.phys, 0x4000_0000 + 0x2000);
    }

    #[test]
    fn a_two_megabyte_page_terminates_the_walk_at_the_page_directory() {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 2, 0x20_0000 | LARGE_PAGE_BIT | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let t = harness
            .walk()
            .translate(0x1000, 0x0040_1234)
            .expect("a 2 MiB page");
        assert_eq!(t.run_len, 1 << 21);
        assert_eq!(t.level, 2);
        assert_eq!(t.phys, 0x20_0000 + 0x1234);
    }

    #[test]
    fn a_four_megabyte_page_terminates_the_walk_in_thirty_two_bit_paging() {
        let mut image = Image::new();
        // PD index for 0x00C0_1234 is 3; a 4 MiB frame at physical 0x0080_0000.
        image.entry32(
            0x1000,
            3,
            (0x0080_0000 | LARGE_PAGE_BIT | PRESENT_BIT) as u32,
        );
        let harness = Harness::new(image, PagingMode::Intel32, PteSemantics::Bare);
        let t = harness
            .walk()
            .translate(0x1000, 0x00C0_1234)
            .expect("a 4 MiB page");
        assert_eq!(t.run_len, 1 << 22);
        assert_eq!(t.level, 0);
        // The low 22 bits of the address are the offset inside the 4 MiB page.
        assert_eq!(t.phys, 0x0080_0000 + 0x1234);
    }

    #[test]
    fn a_four_megabyte_entry_naming_a_frame_above_four_gigabytes_is_refused() {
        // PSE-36 carries physical bits 39:32 in a 4 MiB entry's own bits 20:13.
        // This mode declares a 32-bit physical space, so masking them off would
        // answer with an address at least 4 GiB from the truth and look no
        // different from any other successful translation.
        let mut image = Image::new();
        image.entry32(
            0x1000,
            3,
            (0x0080_0000 | (1u64 << 13) | LARGE_PAGE_BIT | PRESENT_BIT) as u32,
        );
        let harness = Harness::new(image, PagingMode::Intel32, PteSemantics::Bare);
        let err = harness
            .walk()
            .translate(0x1000, 0x00C0_1234)
            .expect_err("an inexpressible frame must not translate");
        assert!(
            matches!(err, TranslateError::AddressOverflow { .. }),
            "{err:?}"
        );
        // And it says nothing about the acquisition: the bytes may well be
        // there, it is the address that cannot be stated.
        assert_eq!(err.hole_reason(), None);
        assert_eq!(err.invalid_bits(), None);
    }

    #[test]
    fn bit_seven_of_a_final_level_entry_is_the_pat_index_and_not_a_large_page() {
        // The single most damaging level confusion available. Bit 7 of a 4 KiB
        // PTE selects a memory type; reading it as PS would end the walk one
        // level early, return a 2 MiB run over a frame the tables never
        // described, and every byte read through it would come from the wrong
        // place while parsing perfectly.
        let mut image = x64_image();
        image.entry64(0x4000, 1, 0x5000 | LARGE_PAGE_BIT | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let t = harness
            .walk()
            .translate(0x1000, 0x0040_1234)
            .expect("a write-combining page is still an ordinary 4 KiB page");
        assert_eq!(t.phys, 0x5234);
        assert_eq!(t.run_len, 0x1000);
        assert_eq!(t.level, 3);
    }

    #[test]
    fn bit_seven_of_a_top_level_entry_is_ignored_rather_than_ending_the_walk() {
        // No architecture defines a 512 GiB page, so bit 7 of a PML4E is
        // ignored by the hardware. A walker that honoured it would resolve half
        // a terabyte of address space to one fabricated frame.
        let mut image = x64_image();
        image.entry64(0x1000, 0, 0x2000 | LARGE_PAGE_BIT | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let t = harness
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect("the walk continues past a PML4E with bit 7 set");
        assert_eq!(t.phys, 0x5000);
        assert_eq!(t.run_len, 0x1000);
        assert_eq!(t.level, 3);
    }

    #[test]
    fn bit_seven_of_a_pae_pointer_table_entry_is_reserved_and_not_a_large_page() {
        // PAE's PDPTE has no PS bit at all; the bit is reserved and the walk
        // must go on to the page directory.
        let mut image = Image::new();
        let pdpt = 0x1020u64;
        image.entry64(pdpt, 3, 0x2000 | LARGE_PAGE_BIT | PRESENT_BIT);
        image.entry64(0x2000, 1, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 4, 0x8000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::IntelPae, PteSemantics::Bare);
        let va = (3u64 << 30) | (1u64 << 21) | (4u64 << 12) | 0x10;
        let t = harness.walk().translate(pdpt, va).expect("mapped");
        assert_eq!(t.phys, 0x8010);
        assert_eq!(t.run_len, 0x1000);
        assert_eq!(t.level, 2);
    }

    #[test]
    fn thirty_two_bit_paging_walks_two_levels_of_four_byte_entries() {
        let mut image = Image::new();
        image.entry32(0x1000, 1, (0x2000 | PRESENT_BIT) as u32);
        image.entry32(0x2000, 2, (0x7000 | PRESENT_BIT) as u32);
        let harness = Harness::new(image, PagingMode::Intel32, PteSemantics::Bare);
        // PD index 1 (bits 31:22), PT index 2 (bits 21:12).
        let va = (1u64 << 22) | (2u64 << 12) | 0x40;
        let t = harness.walk().translate(0x1000, va).expect("mapped");
        assert_eq!(t.phys, 0x7040);
        assert_eq!(t.run_len, 0x1000);
        assert_eq!(t.level, 1);
    }

    #[test]
    fn pae_indexes_a_thirty_two_byte_pointer_table() {
        // The PAE PDPT is 32 bytes and only 32-byte aligned. A walker that
        // masks the DTB to a page boundary reads the wrong table here — and
        // only here, which is why PAE images fail alone.
        let mut image = Image::new();
        let pdpt = 0x1020u64;
        image.entry64(pdpt, 3, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 1, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 4, 0x8000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::IntelPae, PteSemantics::Bare);
        // PDPT index 3 (bits 31:30), PD index 1 (bits 29:21), PT index 4.
        let va = (3u64 << 30) | (1u64 << 21) | (4u64 << 12) | 0x10;
        let t = harness.walk().translate(pdpt, va).expect("mapped");
        assert_eq!(t.phys, 0x8010);
        assert_eq!(t.level, 2);
    }

    #[test]
    fn a_pae_two_megabyte_page_translates() {
        let mut image = Image::new();
        let pdpt = 0x1020u64;
        image.entry64(pdpt, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 1, 0x20_0000 | LARGE_PAGE_BIT | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::IntelPae, PteSemantics::Bare);
        let va = (1u64 << 21) | 0x1234;
        let t = harness.walk().translate(pdpt, va).expect("a 2 MiB page");
        assert_eq!(t.run_len, 1 << 21);
        assert_eq!(t.phys, 0x20_0000 + 0x1234);
    }

    #[test]
    fn the_directory_table_base_needs_no_present_bit_of_its_own() {
        // CR3 holds flags in its low bits, never a present bit. A DTB of
        // 0x1000 must work exactly as 0x1001 does.
        let harness = Harness::new(x64_image(), PagingMode::Intel32e, PteSemantics::Bare);
        let plain = harness.walk().translate(0x1000, 0x0040_1000).unwrap();
        let flagged = harness.walk().translate(0x1018, 0x0040_1000).unwrap();
        assert_eq!(plain.phys, flagged.phys);
    }

    #[test]
    fn a_non_present_entry_names_the_region_it_governs_rather_than_reading_as_zero() {
        let mut image = x64_image();
        // Clear the page-directory entry: 2 MiB of address space goes absent.
        image.entry64(0x3000, 2, 0);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let err = harness
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect_err("an absent page must not translate");
        match err {
            TranslateError::NotPresent {
                level,
                invalid_bits,
                region,
                entry,
                ..
            } => {
                assert_eq!(level, 2, "the page directory is level 2");
                assert_eq!(invalid_bits, 21);
                assert_eq!(region, 1 << 21);
                assert_eq!(entry, 0);
            }
            other => panic!("expected NotPresent, got {other:?}"),
        }
        assert_eq!(err.hole_reason(), Some(HoleReason::NotPresent));
        assert_eq!(err.invalid_bits(), Some(21));
    }

    #[test]
    fn an_absent_top_level_entry_reports_the_whole_half_terabyte_it_covers() {
        // The skip that makes scanning a sparse address space finite.
        let harness = Harness::new(Image::new(), PagingMode::Intel32e, PteSemantics::Bare);
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        assert_eq!(err.invalid_bits(), Some(39));
        assert_eq!(unresolved_span(0x0040_1000, 39), (1 << 39) - 0x0040_1000);
    }

    #[test]
    fn a_non_canonical_address_is_rejected_before_any_table_is_read() {
        let harness = Harness::new(x64_image(), PagingMode::Intel32e, PteSemantics::Bare);
        let err = harness
            .walk()
            .translate(0x1000, 0x0000_8000_0000_0000)
            .expect_err("a non-canonical address has no translation");
        assert!(matches!(err, TranslateError::NonCanonical { .. }));
        // Nothing was read, so nothing was memoised.
        assert!(harness.cache.is_empty());
        assert!(err.hole_reason().is_none(), "not a hole: no such address");
    }

    #[test]
    fn an_address_above_a_thirty_two_bit_space_is_out_of_range() {
        let harness = Harness::new(Image::new(), PagingMode::Intel32, PteSemantics::Bare);
        let err = harness.walk().translate(0x1000, 0x1_0000_0000).unwrap_err();
        assert!(matches!(err, TranslateError::OutOfRange { bits: 32, .. }));
    }

    #[test]
    fn a_self_referential_page_table_cannot_hang_the_walker() {
        // The classic Windows self-map: an entry in the top table pointing at
        // the table itself, so every level reads the same page. The walk is
        // bounded by the level count, so it terminates with an answer derived
        // entirely from those bytes rather than looping.
        let mut image = Image::new();
        for index in 0..512u64 {
            image.entry64(0x1000, index, 0x1000 | PRESENT_BIT);
        }
        // Break uniformity so the heuristic does not pre-empt the point.
        image.entry64(0x1000, 511, 0x1000 | PRESENT_BIT | (1 << 5));
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let t = harness
            .walk()
            .translate(0x1000, 0x0000_7FFF_FFFF_F123)
            .expect("a self-referential chain still terminates");
        assert_eq!(t.phys, 0x1123);
        assert_eq!(t.run_len, 0x1000);
        assert_eq!(t.level, 3);
    }

    /// **A transition entry at a large-page level must not be read as a large
    /// page.**
    ///
    /// `MMPTE_TRANSITION` carries `Protection` in bits 5..9. Bit 7 of the entry
    /// is therefore bit 2 of that field — set by every protection value from
    /// `MM_READWRITE` (4) upward, which is most of them. Bit 7 is also
    /// `LARGE_PAGE_BIT` in a *hardware* entry.
    ///
    /// Windows pages out page tables, and a page table on the standby list
    /// leaves its page-directory entry in transition state. Such a PDE, for a
    /// writable region, has bit 7 set for a reason that has nothing to do with
    /// page size — and the page directory is a level where large pages are
    /// legal, so a walker that tests bit 7 without asking whether the entry is
    /// a hardware entry stops there and reads bits 21 and up as a 2 MiB frame.
    /// The real frame number starts at bit 12. The address returned is wrong by
    /// gigabytes and looks entirely ordinary.
    #[test]
    fn a_transition_entry_at_a_large_page_level_is_not_read_as_a_large_page() {
        // MM_READWRITE = 4, which occupies bit 2 of Protection, i.e. bit 7 of
        // the entry — the same bit a hardware entry uses for "large page".
        const PROTECTION_READWRITE: u64 = 4 << 5;
        assert_eq!(
            PROTECTION_READWRITE & LARGE_PAGE_BIT,
            LARGE_PAGE_BIT,
            "the premise: MM_READWRITE sets the bit a hardware entry reads as large-page"
        );

        let mut image = x64_image();
        // The page directory entry is in transition: its page table is on the
        // standby list, still in RAM at 0x4000.
        image.entry64(
            0x3000,
            2,
            0x4000 | WINDOWS_TRANSITION_BIT | PROTECTION_READWRITE,
        );
        let windows = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);

        let t = windows
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect("the page table is in RAM, so the walk can continue through it");
        assert_eq!(
            t.phys, 0x5000,
            "the walk must follow the transition PDE to its page table and finish at the \
             final level; reading it as a 2 MiB page yields an address gigabytes away"
        );
        assert_eq!(t.run_len, 0x1000, "a 4 KiB page, not a 2 MiB one");
        assert_eq!(
            t.level, 3,
            "the walk reached the page table, not stopped at the directory"
        );
    }

    #[test]
    fn a_windows_transition_pte_recovers_a_standby_page() {
        let mut image = x64_image();
        // Valid clear, transition set, prototype clear: the frame is still RAM.
        image.entry64(0x4000, 1, 0x5000 | WINDOWS_TRANSITION_BIT);
        let windows = Harness::new(
            Image {
                bytes: image.bytes.clone(),
            },
            PagingMode::Intel32e,
            PteSemantics::Windows,
        );
        let t = windows
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect("a transition PTE is readable evidence");
        assert_eq!(t.phys, 0x5000);

        // A bare walker makes no such claim.
        let bare = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let err = bare.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        assert!(matches!(err, TranslateError::NotPresent { .. }));
    }

    #[test]
    fn a_windows_pagefile_pte_is_reported_as_swapped_not_as_absent() {
        let mut image = x64_image();
        // PageFileLow = 5, PageFileHigh = 0x9AB, valid/transition/prototype all
        // clear: this page is on disk, not gone.
        image.entry64(0x4000, 1, (5u64 << 1) | (0x9ABu64 << 32));
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        match err {
            TranslateError::SwappedOut {
                swap_index,
                swap_offset,
                invalid_bits,
                ..
            } => {
                assert_eq!(swap_index, Some(5));
                assert_eq!(invalid_bits, 12);
                // The page number is scaled by the failing level's page size.
                assert_eq!(swap_offset, 0x9AB << 12);
            }
            other => panic!("expected SwappedOut, got {other:?}"),
        }
        assert_eq!(err.hole_reason(), Some(HoleReason::SwappedOut));
    }

    /// A `swp_entry_t` in the Linux 4.x pre-L1TF x86-64 layout: swap type 2 at
    /// bits 13:9 and offset 0x9ABC above bit 14, with the present bit and
    /// `_PAGE_PROTNONE` both clear.
    ///
    /// Which layout it is written in does not matter to anything asserted
    /// below, and that is the point being made: the classification is the part
    /// that holds across every kernel, and the numbers inside are the part that
    /// does not.
    const LINUX_SWAPPED_PTE: u64 = (2u64 << 9) | (0x9ABCu64 << 14);

    /// [`x64_image`] with the final page swapped out and its neighbour empty.
    fn linux_swap_image() -> Image {
        let mut image = x64_image();
        image.entry64(0x4000, 1, LINUX_SWAPPED_PTE);
        image.entry64(0x4000, 2, 0);
        image
    }

    #[test]
    fn a_linux_swapped_page_is_not_the_same_answer_as_a_page_that_never_existed() {
        // The defect: Linux ran under `PteSemantics::Bare`, whose only answer
        // for a non-present entry is `NotPresent`. A page the kernel wrote out
        // of memory and a page that was never mapped produced the identical
        // finding, so nothing in a Linux case could tell an examiner that a
        // region had held something.
        let harness = Harness::new(
            linux_swap_image(),
            PagingMode::Intel32e,
            PteSemantics::Linux,
        );

        let err = harness
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect_err("a page whose contents the kernel moved out is not in this image");
        match &err {
            TranslateError::LinuxSwapEntry {
                entry,
                level,
                level_name,
                invalid_bits,
                region,
                ..
            } => {
                assert_eq!(
                    *entry, LINUX_SWAPPED_PTE,
                    "the entry travels verbatim, which is what a hand decode needs"
                );
                assert_eq!(*level, 3);
                assert_eq!(*level_name, "page table");
                assert_eq!(*invalid_bits, 12);
                assert_eq!(*region, 0x1000);
            }
            other => panic!("expected a Linux swap-family entry, got {other:?}"),
        }
        // It renders as an absent page and not as `swapped_out`: naming a swap
        // area would be more than these bits prove, since migration and
        // hardware-poison entries share the encoding.
        assert_eq!(err.hole_reason(), Some(HoleReason::NotPresent));
        assert_eq!(err.invalid_bits(), Some(12));
        let text = err.to_string();
        assert!(
            text.contains("no swap area and no offset is claimed"),
            "the refusal has to be readable on the error itself: {text}"
        );

        // The empty neighbour keeps saying it is empty. If everything
        // non-present became a swap-family entry, the distinction would be
        // worthless.
        let empty = harness
            .walk()
            .translate(0x1000, 0x0040_2000)
            .expect_err("an empty entry maps nothing");
        assert!(
            matches!(empty, TranslateError::NotPresent { .. }),
            "{empty:?}"
        );

        // And an image whose OS was never established does not acquire the
        // Linux reading: `Bare` still answers plain absence for both.
        let bare = Harness::new(linux_swap_image(), PagingMode::Intel32e, PteSemantics::Bare);
        let err = bare.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        assert!(matches!(err, TranslateError::NotPresent { .. }), "{err:?}");
    }

    #[test]
    fn a_linux_prot_none_page_is_never_counted_as_a_swapped_one() {
        // `pte_present()` on x86 is `_PAGE_PRESENT | _PAGE_PROTNONE`, so an
        // entry with bit 8 set is a page the kernel holds a frame for — a
        // `PROT_NONE` region or a NUMA-balancing hint. Nothing was written to
        // any swap area, and reporting it beside genuinely swapped pages would
        // put a mapping that never left RAM into the wrong bucket.
        let mut image = x64_image();
        image.entry64(0x4000, 1, LINUX_PROTNONE_BIT | 0x5000);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Linux);
        let err = harness
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect_err("the hardware faults on a PROT_NONE entry");
        assert!(
            matches!(err, TranslateError::NotPresent { .. }),
            "a PROT_NONE entry is not a swap-family entry: {err:?}"
        );
    }

    #[test]
    fn a_paged_out_page_table_is_located_in_four_kilobyte_pagefile_pages() {
        // A software entry above the final level: the *page table* is in the
        // pagefile. `PageFileHigh` counts 4 KiB pagefile pages there exactly as
        // it does in a PTE, because 4 KiB is what Windows writes out. Scaling
        // it by the 2 MiB the entry governs would put the offset 512 times too
        // far into the pagefile — a confident, wrong disk location.
        let mut image = x64_image();
        image.entry64(0x3000, 2, (3u64 << 1) | (0x40u64 << 32));
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        match err {
            TranslateError::SwappedOut {
                swap_index,
                swap_offset,
                invalid_bits,
                ..
            } => {
                assert_eq!(swap_index, Some(3));
                assert_eq!(
                    invalid_bits, 21,
                    "2 MiB of address space went with the page table"
                );
                assert_eq!(swap_offset, 0x40 << 12, "4 KiB pages, not 2 MiB regions");
            }
            other => panic!("expected SwappedOut, got {other:?}"),
        }
        // The region is still reported in full, so a scanner skips all of it.
        assert_eq!(err.hole_reason(), Some(HoleReason::SwappedOut));
        assert_eq!(err.invalid_bits(), Some(21));
    }

    // ── Prototype PTEs ──────────────────────────────────────────────────────

    /// Kernel virtual address of the prototype `_MMPTE` in the fixtures below.
    /// Chosen inside the upper canonical half, which is where paged pool — and
    /// therefore every prototype array — actually lives.
    const PROTO_VA: u64 = 0xFFFF_8000_0000_0008;

    /// Encode a prototype PTE naming `proto_va`, exactly as `MMPTE_PROTOTYPE`
    /// does on x64: `ProtoAddress` is a signed 48-bit field at bits 63:16.
    fn prototype_entry(proto_va: u64) -> u64 {
        (((proto_va as i64) << WINDOWS_X64_PROTO_ADDRESS_SHIFT) as u64) | WINDOWS_PROTOTYPE_BIT
    }

    /// `x64_image` where `0x401000`'s PTE is a prototype PTE, the prototype
    /// array is mapped in kernel space at [`PROTO_VA`] (physical `0xA008`), and
    /// the array entry is `proto_entry`.
    fn prototype_image(proto_entry: u64) -> Image {
        let mut image = x64_image();
        // The process PTE hands over to the section object.
        image.entry64(0x4000, 1, prototype_entry(PROTO_VA));
        // Kernel-space tables reaching the prototype array: PML4 index 256 is
        // the first index of the upper canonical half.
        image.entry64(0x1000, 256, 0x6000 | PRESENT_BIT);
        image.entry64(0x6000, 0, 0x7000 | PRESENT_BIT);
        image.entry64(0x7000, 0, 0x8000 | PRESENT_BIT);
        image.entry64(0x8000, 0, 0xA000 | PRESENT_BIT);
        // The prototype `_MMPTE` itself, and the page it describes.
        image.entry64(0xA000, 1, proto_entry);
        image.fill(0xB000, 0x1000, 0xEE);
        image
    }

    #[test]
    fn a_resident_shared_page_is_recovered_through_its_prototype_pte() {
        // The defect this guards: the walk stopped at every prototype PTE and
        // reported the address as absent. A prototype PTE means the page
        // belongs to a section object — a DLL's code, a mapped file, shared
        // memory — and its real state lives once, in the section's prototype
        // array, which is in paged pool and reachable through these very
        // tables. Very often it is resident. Calling it a hole threw away real,
        // recoverable evidence in the region an examiner cares most about.
        let harness = Harness::new(
            prototype_image(0xB000 | PRESENT_BIT),
            PagingMode::Intel32e,
            PteSemantics::Windows,
        );
        let t = harness
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect("the prototype array says the page is resident");
        assert_eq!(t.phys, 0xB000);
        assert_eq!(t.run_len, 0x1000, "a prototype PTE describes a 4 KiB page");
        // The provenance travels with the answer: these bytes are shared, so
        // "this process wrote them" is not a claim the translation supports.
        assert_eq!(
            t.via,
            TranslationPath::PrototypePte {
                proto_va: PROTO_VA,
                proto_pa: 0xA008,
            }
        );
        assert!(t.via.is_shared());
        assert_eq!(t.via.as_str(), "prototype_pte");

        // The page offset is carried through the hand-over.
        let t = harness.walk().translate(0x1000, 0x0040_1ABC).unwrap();
        assert_eq!(t.phys, 0xBABC);
    }

    #[test]
    fn a_standby_shared_page_is_recovered_through_its_prototype_pte() {
        // The prototype entry is in transition rather than valid: the frame is
        // on the standby list, still in RAM, still evidence.
        let harness = Harness::new(
            prototype_image(0xB000 | WINDOWS_TRANSITION_BIT),
            PagingMode::Intel32e,
            PteSemantics::Windows,
        );
        let t = harness.walk().translate(0x1000, 0x0040_1000).unwrap();
        assert_eq!(t.phys, 0xB000);
        assert!(t.via.is_shared());
    }

    #[test]
    fn an_ordinary_translation_never_claims_to_have_come_from_a_section() {
        let harness = Harness::new(x64_image(), PagingMode::Intel32e, PteSemantics::Windows);
        let t = harness.walk().translate(0x1000, 0x0040_1000).unwrap();
        assert_eq!(t.via, TranslationPath::PageTables);
        assert!(!t.via.is_shared());
        assert_eq!(t.via.as_str(), "page_tables");
    }

    #[test]
    fn a_prototype_page_that_is_not_in_ram_is_reported_and_never_guessed_at() {
        // The array resolves, and says the page is not resident: a
        // subsection-backed page still on disk in the mapped file, or one
        // written to the pagefile. Those two are not distinguishable without
        // the control area, so neither is decoded — and the address is
        // certainly not resolved to whatever frame number the bits happen to
        // spell.
        let harness = Harness::new(
            prototype_image(0),
            PagingMode::Intel32e,
            PteSemantics::Windows,
        );
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        match err {
            TranslateError::PrototypePte {
                proto_va, detail, ..
            } => {
                assert_eq!(proto_va, Some(PROTO_VA), "the chain WAS followed this far");
                assert!(detail.contains("not in RAM"), "{detail}");
            }
            other => panic!("expected PrototypePte, got {other:?}"),
        }
        assert_eq!(err.hole_reason(), Some(HoleReason::NotPresent));
    }

    #[test]
    fn a_prototype_array_outside_the_acquisition_is_reported_rather_than_resolved() {
        // The prototype PTE names an address nothing maps. Nothing is known
        // about the page, and the error says which array could not be reached.
        let mut image = x64_image();
        image.entry64(0x4000, 1, prototype_entry(PROTO_VA));
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        match err {
            TranslateError::PrototypePte {
                proto_va, detail, ..
            } => {
                assert_eq!(proto_va, Some(PROTO_VA));
                assert!(detail.contains("not resident"), "{detail}");
            }
            other => panic!("expected PrototypePte, got {other:?}"),
        }
    }

    #[test]
    fn a_prototype_pte_whose_address_cannot_be_stated_is_never_decoded() {
        // `MI_PTE_LOOKUP_NEEDED`: Windows does not keep the array's address in
        // the entry at all and recomputes it from the VAD's subsection chain,
        // which the page tables cannot supply. Decoding the all-ones field as
        // an address would send the walk to a kernel address that means
        // nothing.
        let mut image = x64_image();
        image.entry64(0x4000, 1, !PRESENT_BIT & !WINDOWS_TRANSITION_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        match err {
            TranslateError::PrototypePte {
                proto_va, detail, ..
            } => {
                assert_eq!(proto_va, None, "no address is claimed");
                assert!(detail.contains("MI_PTE_LOOKUP_NEEDED"), "{detail}");
            }
            other => panic!("expected PrototypePte, got {other:?}"),
        }
    }

    #[test]
    fn a_prototype_bit_above_the_final_level_is_refused_rather_than_decoded() {
        // Windows never puts a prototype PTE in a page directory. One that
        // appears there is corrupt or hostile, and its ProtoAddress field is
        // whatever the corruption spells — so it is not decoded at all.
        let mut image = x64_image();
        image.entry64(0x3000, 2, prototype_entry(PROTO_VA));
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        match err {
            TranslateError::PrototypePte {
                proto_va,
                detail,
                invalid_bits,
                ..
            } => {
                assert_eq!(proto_va, None);
                assert_eq!(invalid_bits, 21, "the 2 MiB the entry governed");
                assert!(detail.contains("above the final level"), "{detail}");
            }
            other => panic!("expected PrototypePte, got {other:?}"),
        }
    }

    #[test]
    fn a_prototype_chain_is_bounded_at_one_hop() {
        // The prototype array's own page described by a second prototype PTE.
        // Following it would recurse; refusing terminates and says so.
        let mut image = prototype_image(0xB000 | PRESENT_BIT);
        image.entry64(0x8000, 0, prototype_entry(PROTO_VA));
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        for va in [0x0040_1000u64, PROTO_VA] {
            let err = harness.walk().translate(0x1000, va).unwrap_err();
            match err {
                TranslateError::PrototypePte { detail, .. } => {
                    assert!(detail.contains("one hop"), "{va:#x}: {detail}")
                }
                other => panic!("{va:#x}: expected PrototypePte, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_unreadable_prototype_array_is_not_reported_as_an_absent_page() {
        // The defect this guards: every failure on the way to the prototype
        // array was collapsed into one sentence — "the array is not resident" —
        // carried on an error whose hole reason is `NotPresent`. So an
        // evidence file that would not read became a positive statement about
        // the suspect's machine: this page was not in RAM. "We could not
        // determine" and "it was not there" must never render alike.
        #[derive(Debug)]
        struct Unreadable {
            inner: ByteSliceDataSource,
            at: u64,
        }
        impl DataSource for Unreadable {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
                if offset == self.at {
                    return Err(io::Error::other("the disk gave up"));
                }
                self.inner.read_at(offset, buf)
            }
            fn size(&self) -> u64 {
                self.inner.size()
            }
        }

        let image = prototype_image(0xB000 | PRESENT_BIT);
        // The kernel-space page DIRECTORY on the way to the prototype array, so
        // the failure happens at a level that governs 2 MiB. What it stopped is
        // one page of the process's space, and that is what must be reported.
        let physical = PhysicalLayer::raw(Arc::new(Unreadable {
            inner: ByteSliceDataSource::new(image.bytes),
            at: 0x7000,
        }))
        .unwrap();
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
            .with_win8_pagefile_layout(false);
        let cache = TableCache::new();
        let suppressed = AtomicU64::new(0);
        let walk = PageWalk::new(
            &physical,
            &spec,
            &cache,
            TranslationPolicy::default(),
            &suppressed,
        );

        let err = walk.translate(0x1000, 0x0040_1000).unwrap_err();
        match err {
            TranslateError::TableUnreadable {
                table_pa,
                invalid_bits,
                ..
            } => {
                assert_eq!(table_pa, 0x7000, "the table that would not read");
                assert_eq!(
                    invalid_bits, 12,
                    "narrowed to the one page it stopped, not the 2 MiB the \
                     kernel directory it failed in governs"
                );
            }
            other => panic!("expected TableUnreadable, got {other:?}"),
        }
        assert_eq!(
            err.hole_reason(),
            None,
            "an I/O failure is not a hole in the acquisition"
        );
        assert!(matches!(
            err.into_layer_error(0x0040_1000, u64::MAX),
            LayerError::Io(_)
        ));
    }

    #[test]
    fn a_suppressed_table_on_the_way_to_a_prototype_array_says_so() {
        // Blaming the acquisition — "not resident" — for a page this tool's own
        // heuristic declined to look at would send an examiner to the wrong
        // question entirely. The suppression is re-reported, so the hole is
        // `table_suppressed` and re-running with the policy off is the obvious
        // next step.
        let mut image = prototype_image(0xB000 | PRESENT_BIT);
        // The page table that locates the prototype array, given the shape the
        // heuristic suppresses.
        for index in 0..512u64 {
            image.entry64(0x8000, index, 0xA000 | PRESENT_BIT);
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        match err {
            TranslateError::UniformTableSuppressed {
                table_pa,
                entry,
                invalid_bits,
                region,
                ..
            } => {
                assert_eq!(table_pa, 0x8000, "the prototype array's own page table");
                assert_eq!(entry, 0xA000 | PRESENT_BIT);
                assert_eq!(
                    invalid_bits, 12,
                    "one page, not the suppressed table's 2 MiB"
                );
                assert_eq!(region, 0x1000);
            }
            other => panic!("expected UniformTableSuppressed, got {other:?}"),
        }
        assert_eq!(err.hole_reason(), Some(HoleReason::TableSuppressed));
        assert_eq!(harness.suppressed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_bare_walker_never_follows_a_prototype_pte() {
        // Under bare semantics bit 10 is not a prototype flag at all; it is an
        // ignored bit. Reading it as one would invent a section object.
        let harness = Harness::new(
            prototype_image(0xB000 | PRESENT_BIT),
            PagingMode::Intel32e,
            PteSemantics::Bare,
        );
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        assert!(matches!(err, TranslateError::NotPresent { .. }), "{err:?}");
    }

    #[test]
    fn the_no_execute_bit_is_reported_and_never_folded_into_the_address() {
        let mut image = x64_image();
        image.entry64(0x4000, 1, NX_BIT | 0x5000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let t = harness.walk().translate(0x1000, 0x0040_1000).unwrap();
        assert_eq!(t.phys, 0x5000, "bit 63 is not part of the frame");
        assert!(t.no_execute);
    }

    #[test]
    fn windows_x64_ignores_entry_bits_above_its_narrowed_maxphyaddr() {
        // Windows stores software state in x64 entry bits 45..51. A 52-bit
        // mask folds that state into the physical address, which is how a
        // transition PTE silently resolves to a wrong frame.
        let mut image = x64_image();
        image.entry64(0x4000, 1, (1u64 << 46) | 0x5000 | PRESENT_BIT);
        let windows = Harness::new(
            Image {
                bytes: image.bytes.clone(),
            },
            PagingMode::Intel32e,
            PteSemantics::Windows,
        );
        assert_eq!(
            windows.walk().translate(0x1000, 0x0040_1000).unwrap().phys,
            0x5000
        );
        // A bare 52-bit walker does include that bit, which is the correct
        // architectural answer and the reason the override is per cell.
        let bare = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        assert_eq!(
            bare.walk().translate(0x1000, 0x0040_1000).unwrap().phys,
            (1u64 << 46) | 0x5000
        );
    }

    #[test]
    fn an_unreadable_page_table_is_an_error_rather_than_a_zero_entry() {
        // A DTB pointing past the end of the acquisition. Reading it as zeros
        // would translate every address to physical zero — a real, readable
        // address holding someone else's bytes.
        let harness = Harness::new(Image::new(), PagingMode::Intel32e, PteSemantics::Bare);
        let err = harness
            .walk()
            .translate(0x10_0000_0000, 0x0040_1000)
            .expect_err("an unreadable table must fail closed");
        match err {
            TranslateError::TableUnreadable {
                table_pa,
                invalid_bits,
                ..
            } => {
                assert_eq!(table_pa, 0x10_0000_0000);
                assert_eq!(invalid_bits, 39);
            }
            other => panic!("expected TableUnreadable, got {other:?}"),
        }
        // An EOF is not a hole in the acquisition, and must not be dressed as
        // one.
        assert_eq!(err.hole_reason(), None);
    }

    #[test]
    fn a_repeated_walk_is_served_from_the_memo_without_rereading() {
        /// Counts every read the walker makes of the underlying image.
        #[derive(Debug)]
        struct Counting {
            inner: ByteSliceDataSource,
            reads: AtomicU64,
        }
        impl DataSource for Counting {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                self.inner.read_at(offset, buf)
            }
            fn size(&self) -> u64 {
                self.inner.size()
            }
        }

        let image = x64_image();
        let counting = Arc::new(Counting {
            inner: ByteSliceDataSource::new(image.bytes),
            reads: AtomicU64::new(0),
        });
        let physical = PhysicalLayer::raw(counting.clone()).unwrap();
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        let cache = TableCache::new();
        let policy = TranslationPolicy {
            suppress_uniform_tables: false,
        };
        let suppressed = AtomicU64::new(0);
        let walk = PageWalk::new(&physical, &spec, &cache, policy, &suppressed);

        assert_eq!(walk.translate(0x1000, 0x0040_1000).unwrap().phys, 0x5000);
        let after_first = counting.reads.load(Ordering::SeqCst);
        assert_eq!(after_first, 4, "one read per level");

        for _ in 0..50 {
            assert_eq!(walk.translate(0x1000, 0x0040_1000).unwrap().phys, 0x5000);
        }
        assert_eq!(
            counting.reads.load(Ordering::SeqCst),
            after_first,
            "a memoised walk must not touch the acquisition again"
        );

        // A different page in the same page table re-reads only the entry that
        // differs.
        let _ = walk.translate(0x1000, 0x0040_2000);
        assert_eq!(counting.reads.load(Ordering::SeqCst), after_first + 1);
    }

    /// A page table filled with one repeated present entry — the shape
    /// Windows 10 gives address space that holds nothing.
    fn uniform_table_image() -> Image {
        let mut image = x64_image();
        for index in 0..512u64 {
            image.entry64(0x4000, index, 0x9000 | PRESENT_BIT);
        }
        image
    }

    #[test]
    fn a_uniform_present_table_is_suppressed_and_names_what_it_hid() {
        let harness = Harness::new(
            uniform_table_image(),
            PagingMode::Intel32e,
            PteSemantics::Windows,
        );
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        match err {
            TranslateError::UniformTableSuppressed {
                table_pa,
                level,
                level_name,
                entry,
                invalid_bits,
                region,
            } => {
                assert_eq!(table_pa, 0x4000);
                assert_eq!(level, 3);
                assert_eq!(level_name, "page table");
                assert_eq!(
                    entry,
                    0x9000 | PRESENT_BIT,
                    "the repeated entry is carried verbatim, so an examiner can \
                     decode the frame the heuristic declined to follow"
                );
                assert_eq!(invalid_bits, 21, "the whole page table's 2 MiB is skipped");
                assert_eq!(region, 1 << 21);
            }
            other => panic!("expected UniformTableSuppressed, got {other:?}"),
        }
        // A suppressed table and an absent one are different holes.
        assert_eq!(err.hole_reason(), Some(HoleReason::TableSuppressed));
        assert!(err.to_string().contains("0x9001"), "{err}");
        assert!(err.to_string().contains("suppress_uniform_tables"), "{err}");
        assert_eq!(harness.suppressed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_uniform_heuristic_is_a_windows_convention_and_stays_off_elsewhere() {
        // The defect this guards: the heuristic was applied under every set of
        // semantics. A Linux region of read-only anonymous pages all pointing
        // at the shared zero page has exactly this shape and is a REAL mapping,
        // so suppressing it deleted a large genuine mapping from the address
        // space — the "silent absence of large VA ranges" the policy was
        // supposed to be exempt from.
        let harness = Harness::new(
            uniform_table_image(),
            PagingMode::Intel32e,
            PteSemantics::Bare,
        );
        assert!(
            harness.policy.suppress_uniform_tables,
            "the policy is on; only the semantics gate it"
        );
        let t = harness
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect("a bare walker must not hide a table of identical present entries");
        assert_eq!(t.phys, 0x9000);
        assert_eq!(harness.suppressed.load(Ordering::SeqCst), 0);

        // And the case the paragraph above is actually about, now that Linux
        // has semantics of its own: naming the OS must not hand it a Windows
        // heuristic.
        let linux = Harness::new(
            uniform_table_image(),
            PagingMode::Intel32e,
            PteSemantics::Linux,
        );
        let t = linux
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect("a shared-zero-page region is a real mapping and must not be hidden");
        assert_eq!(t.phys, 0x9000);
        assert_eq!(linux.suppressed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn suppression_can_be_switched_off_and_then_hides_nothing() {
        let harness = Harness::new(
            uniform_table_image(),
            PagingMode::Intel32e,
            PteSemantics::Windows,
        )
        .without_uniform_suppression();
        let t = harness.walk().translate(0x1000, 0x0040_1000).unwrap();
        assert_eq!(t.phys, 0x9000);
        assert_eq!(harness.suppressed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_all_zero_table_is_reported_absent_rather_than_suppressed() {
        // The commonest structure in any image. Counting it as a suppression
        // would make the published counter meaningless, and would relabel
        // ordinary unmapped memory as a tool decision.
        let mut image = x64_image();
        for index in 0..512u64 {
            image.entry64(0x4000, index, 0);
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        assert!(matches!(err, TranslateError::NotPresent { .. }), "{err:?}");
        assert_eq!(harness.suppressed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn suppression_never_applies_to_paes_thirty_two_byte_pointer_table() {
        // Four identical entries in a 32-byte table is a coincidence, not the
        // Windows unused-page pattern.
        let mut image = Image::new();
        let pdpt = 0x1000u64;
        for index in 0..4u64 {
            image.entry64(pdpt, index, 0x2000 | PRESENT_BIT);
        }
        image.entry64(0x2000, 1, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 4, 0x8000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::IntelPae, PteSemantics::Windows);
        let va = (3u64 << 30) | (1u64 << 21) | (4u64 << 12);
        let t = harness.walk().translate(pdpt, va).expect("mapped");
        assert_eq!(t.phys, 0x8000);
        assert_eq!(harness.suppressed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_unreadable_uniform_probe_never_suppresses_a_table() {
        // The probe is an optimisation; failing to read it must change nothing
        // about what the walk concludes.
        let mut image = Image::new();
        image.bytes.truncate(0x4800);
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 2, 0x4000 | PRESENT_BIT);
        image.entry64(0x4000, 1, 0x2_0000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        // The final table starts at 0x4000 and the image ends at 0x4800, so the
        // 4 KiB probe cannot complete, but the entry itself is readable.
        let t = harness
            .walk()
            .translate(0x1000, 0x0040_1000)
            .expect("the entry is readable even though the probe is not");
        assert_eq!(t.phys, 0x2_0000);
        assert_eq!(harness.suppressed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unresolved_span_measures_from_the_address_to_the_end_of_the_region() {
        assert_eq!(unresolved_span(0, 12), 0x1000);
        assert_eq!(unresolved_span(0x400, 12), 0xC00);
        assert_eq!(unresolved_span(0xFFF, 12), 1);
        assert_eq!(unresolved_span(u64::MAX, 12), 1);
        assert_eq!(unresolved_span(0, 0), 1);
        assert_eq!(unresolved_span(0x1234, 64), u64::MAX);
    }

    #[test]
    fn errors_render_into_the_layer_vocabulary_without_changing_spaces() {
        let mut image = x64_image();
        image.entry64(0x3000, 2, 0);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let err = harness.walk().translate(0x1000, 0x0040_1000).unwrap_err();
        let layer_err = err.into_layer_error(0x0040_1000, u64::MAX);
        let hole = layer_err.hole().expect("an absent page is a hole");
        assert_eq!(hole.address, 0x0040_1000, "the hole is in virtual space");
        assert_eq!(hole.length, (1 << 21) - 0x1000, "to the end of the 2 MiB");
        assert_eq!(hole.reason, HoleReason::NotPresent);

        // A non-canonical address is not a hole: there is no such address.
        let err = harness
            .walk()
            .translate(0x1000, 0x0000_8000_0000_0000)
            .unwrap_err();
        let layer_err = err.into_layer_error(0x0000_8000_0000_0000, u64::MAX);
        assert!(layer_err.hole().is_none());
        assert!(matches!(layer_err, LayerError::OutOfRange { .. }));
    }

    #[test]
    fn a_hostile_entry_full_of_ones_fails_closed_without_panicking() {
        // Every bit set at every level: reserved bits, NX, the lot. The walk
        // must produce an answer or an error, never a panic and never an
        // arithmetic wrap.
        let mut image = Image::new();
        for index in 0..512u64 {
            image.entry64(0x1000, index, u64::MAX);
        }
        image.entry64(0x1000, 0, u64::MAX - 1);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        for va in [0u64, 0x1000, 0x0040_1000, 0x0000_7FFF_FFFF_F000, u64::MAX] {
            let _ = harness.walk().translate(0x1000, va);
        }
        for dtb in [0u64, u64::MAX, 0xFFFF_FFFF_FFFF_F000] {
            let _ = harness.walk().translate(dtb, 0x0040_1000);
        }
    }

    #[test]
    fn the_classifier_reproduces_the_large_page_bool_and_fixed_mask_on_every_intel_mode() {
        // The classifier replaces one line that held the Intel assumption:
        // `level.large_page && present && bit 7`, then a frame mask from
        // MAXPHYADDR down to the level's remaining bits with bit 12 cleared on
        // a large page, and the PSE-36 refusal. That line is restated here as
        // an oracle -- with the old per-mode `large_page` table written out
        // literally -- and the classifier must agree with it on every entry of
        // the shared fixtures and on a spread of synthetic entries at every
        // level of every Intel mode. If they ever disagree, an ARM64 change
        // has moved an Intel translation.
        use crate::translate::spec::EntryKind;

        fn old_large_page_table(mode: PagingMode) -> Vec<bool> {
            match mode {
                PagingMode::Intel32 => vec![true, false],
                PagingMode::IntelPae => vec![false, true, false],
                PagingMode::Intel32e => vec![false, true, true, false],
                PagingMode::Intel32eLa57 => vec![false, false, true, true, false],
                PagingMode::Arm64(_) => unreachable!("an Intel oracle"),
            }
        }

        fn oracle(spec: &PagingSpec, entry: u64, level: usize) -> EntryKind {
            if !spec.entry_is_present(entry) {
                return EntryKind::Invalid;
            }
            let levels = spec.levels();
            let large_capable = old_large_page_table(spec.mode())[level];
            let large =
                large_capable && (entry & PRESENT_BIT) != 0 && (entry & LARGE_PAGE_BIT) != 0;
            if !large && level + 1 != levels.len() {
                return EntryKind::Table;
            }
            if large
                && spec.mode() == PagingMode::Intel32
                && mask_bits(entry, 21, PAGE_OFFSET_BITS + 1) != 0
            {
                return EntryKind::Unnameable {
                    detail: "a 4 MiB page-directory entry names a frame above \
                             the 32-bit physical address space (PSE-36)",
                };
            }
            let remaining = spec.region_bits_at(level).unwrap();
            let phys_high = spec.max_phys_addr_bits() - 1;
            let frame_source = if large { entry & !PAT_LARGE_BIT } else { entry };
            EntryKind::Leaf {
                frame: mask_bits(frame_source, phys_high, remaining),
                size_log2: remaining,
                no_execute: (entry & NX_BIT) != 0,
            }
        }

        // 32-bit and PAE hierarchies in the shape the enumeration fixtures use.
        let mut intel32 = Image::new();
        intel32.entry32(0x1000, 0, 0x2000 | PRESENT_BIT as u32);
        intel32.entry32(0x2000, 1, 0x3000 | PRESENT_BIT as u32);
        intel32.entry32(
            0x1000,
            2,
            0x0080_0000 | PRESENT_BIT as u32 | LARGE_PAGE_BIT as u32,
        );
        let mut pae = Image::new();
        pae.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        pae.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        pae.entry64(0x2000, 1, 0x20_0000 | PRESENT_BIT | LARGE_PAGE_BIT);
        pae.entry64(0x3000, 1, 0x5000 | PRESENT_BIT);

        let synthetic: Vec<u64> = vec![
            0,
            PRESENT_BIT,
            LARGE_PAGE_BIT,
            PRESENT_BIT | LARGE_PAGE_BIT,
            0x5000 | PRESENT_BIT | LARGE_PAGE_BIT | PAT_LARGE_BIT,
            0x20_0000 | PRESENT_BIT | LARGE_PAGE_BIT,
            0x4000_0000 | PRESENT_BIT | LARGE_PAGE_BIT | PAT_LARGE_BIT,
            0x0080_0000 | PRESENT_BIT | LARGE_PAGE_BIT | (1 << 13),
            0x0080_0000 | PRESENT_BIT | LARGE_PAGE_BIT | (1 << 21),
            WINDOWS_TRANSITION_BIT | 0x5000,
            WINDOWS_TRANSITION_BIT | LARGE_PAGE_BIT | 0x5000,
            WINDOWS_TRANSITION_BIT | WINDOWS_PROTOTYPE_BIT | 0x5000,
            NX_BIT | PRESENT_BIT | 0x7000,
            NX_BIT | PRESENT_BIT | LARGE_PAGE_BIT | 0x20_0000,
            (1u64 << 52) | PRESENT_BIT | 0x7000,
            (1u64 << 45) | PRESENT_BIT | 0x7000,
            u64::MAX,
            u64::MAX - 1,
            0xFFFF_FFFF,
        ];

        for (mode, image) in [
            (PagingMode::Intel32, intel32),
            (PagingMode::IntelPae, pae),
            (PagingMode::Intel32e, x64_image()),
            (PagingMode::Intel32eLa57, la57_image()),
        ] {
            let mut entries: Vec<u64> = image
                .bytes
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| u64::from_le_bytes(*c))
                .filter(|e| *e != 0)
                .collect();
            if mode == PagingMode::Intel32 {
                entries = image
                    .bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u64::from(u32::from_le_bytes(*c)))
                    .filter(|e| *e != 0)
                    .collect();
            }
            entries.extend(synthetic.iter().copied());
            for semantics in [
                PteSemantics::Bare,
                PteSemantics::Linux,
                PteSemantics::Windows,
            ] {
                let spec = PagingSpec::new(mode, semantics);
                for level in 0..spec.levels().len() {
                    for &entry in &entries {
                        assert_eq!(
                            spec.classify(entry, level),
                            Some(oracle(&spec, entry, level)),
                            "{mode}/{semantics} level {level} entry {entry:#x}"
                        );
                    }
                }
                assert_eq!(spec.classify(PRESENT_BIT, spec.levels().len()), None);
            }
        }
    }
}
