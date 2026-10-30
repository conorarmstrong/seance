//! [`VirtualLayer`]: a process or kernel address space, as an ordinary
//! [`DataSource`].
//!
//! # Why this is the whole point
//!
//! A `VirtualLayer` is a physical memory layer plus a directory table base, and
//! it implements [`MemoryLayer`] — so it implements [`DataSource`], and every
//! primitive Séance already has works over a suspect's virtual memory with no
//! memory-specific code: `read_exact_or_fail` refuses to parse a structure that
//! straddles an absent page, `SourceCursor` walks a heap, the hasher hashes a
//! process image, the carving engine carves out of a process's address space,
//! and the registry plugin parses an in-memory hive by being handed a window
//! over this layer rather than reimplementing anything.
//!
//! # Every answer, kept apart from every other
//!
//! | The address... | ...reads as |
//! |---|---|
//! | translates, and the frame was acquired | the acquired bytes |
//! | translates only through a section's prototype PTE, and that page is resident | the acquired bytes — the fact that they are **shared** is on the typed answer, not on the bytes; see below |
//! | is above the top of the space | `Ok(0)` — genuine end of the space |
//! | translates, but the frame was never captured | [`MemoryHole`] `unmapped` |
//! | has no present page-table entry | [`MemoryHole`] `not_present` |
//! | is in a pagefile Windows named | [`MemoryHole`] `swapped_out` |
//! | has a Linux `swp_entry_t` behind it | [`MemoryHole`] `not_present`, with the finer fact on [`TranslateError::LinuxSwapEntry`] — the encoding also carries migration and hardware-poison entries, so `swapped_out` would name a file the bits do not prove |
//! | is behind a table the uniform heuristic suppressed | [`MemoryHole`] `table_suppressed` |
//! | is not canonical | [`LayerError::OutOfRange`] — no such address exists |
//!
//! None of them is zeros. A page the suspect wiped and a page nobody captured
//! must never render alike, and every row above is a different sentence in a
//! report.
//!
//! # Where the shared/private distinction lives, and where it does not
//!
//! A page reached through a section object's prototype PTE is **shared**: it may
//! be mapped into other processes, so "this process wrote these bytes" is not a
//! claim the translation supports. That distinction is carried on
//! [`crate::translate::walk::Translation::via`], which is what
//! [`VirtualLayer::translate`] returns.
//!
//! It is deliberately **not** carried by [`MemoryLayer::mapping`] or
//! [`DataSource::read_at`]. Those speak the layer vocabulary — a
//! [`MappedRange`] is `(offset, length, mapped_offset, mapped_length,
//! encoding)`, the same 5-tuple for every layer in this crate — and there is no
//! field in it that could hold provenance without every other layer having to
//! answer for one. So a caller that needs to keep "resident" apart from "private
//! to this process" — anything that dumps a process's memory, or reports where a
//! scan hit — must call `translate` for the page and read `via`, rather than
//! inferring it from a successful read. Nothing in this crate does that: no
//! `seance_memory` product path builds a `VirtualLayer` at all, and the analysis
//! plugin that does is where the distinction has to reach an artifact.
//!
//! A plugin holding the address space as `Arc<dyn MemoryLayer>` — which is how
//! all of them hold it — reaches `translate` through
//! [`MemoryLayer::as_virtual`]. There is no other route: `read_at` succeeding
//! says the bytes were acquired and nothing whatever about whose bytes they are.
//!
//! # Scatter is preserved
//!
//! [`VirtualLayer::mapping`] returns one run per page actually walked, in
//! ascending virtual order, each naming the physical address behind it. Three
//! virtual pages that happen to be physically adjacent still come back as three
//! runs; a 2 MiB large page comes back as one. Nothing is coalesced across a
//! translation, because "these bytes are contiguous in RAM" is a claim only the
//! page tables can make.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use seance_core::data_source::{DataSource, ExtentPrecision, PhysicalExtent, PhysicalMap};
use seance_core::io::{read_full, IncompleteReason};

use crate::layer::{
    backed_len, BackingSource, Encoding, LayerError, MappedRange, MemoryHole, MemoryLayer,
};
use crate::meta::LayerMeta;
use crate::translate::cache::TableCache;
use crate::translate::spec::PagingSpec;
use crate::translate::walk::{
    unresolved_span, PageWalk, TranslateError, Translation, TranslationPolicy,
};

/// One virtual address space: a physical layer read through page tables.
#[derive(Debug)]
pub struct VirtualLayer {
    physical: Arc<dyn MemoryLayer>,
    spec: PagingSpec,
    dtb: u64,
    policy: TranslationPolicy,
    cache: Arc<TableCache>,
    suppressed: AtomicU64,
    max_address: u64,
    meta: LayerMeta,
    /// Pagefiles attached to this address space, by the index a software PTE
    /// names. Empty unless a caller supplied one.
    swap: Vec<SwapFile>,
    /// Indices `swap` holds more than one file for, which is a question this
    /// layer cannot answer — see [`VirtualLayer::with_swap`]. Every PTE naming
    /// one of them stays a hole.
    swap_ambiguous: Vec<u8>,
    /// For each attached file, the Linux swap-area header parsed from its first
    /// page, or `None` when it is not a Linux swap area (a Windows pagefile, or
    /// an unrecognised blob). Parallel to [`Self::swap`], by slot. This is what
    /// lets a Linux `swp_entry_t` be resolved to a byte offset and bounds-checked
    /// — the same corroboration the standalone resolver does, applied inline so
    /// every read through this layer resolves a swapped page transparently.
    swap_linux: Vec<Option<crate::formats::linux_swap::LinuxSwapHeader>>,
    /// For each attached Linux swap area, a bounded survey of whether its body
    /// holds anything at all. Parallel to [`Self::swap`], by slot; `None` for a
    /// file that is not a Linux swap area.
    ///
    /// A swap *file* copied through the filesystem returns zeros for its body
    /// while its `mkswap`-written header page copies faithfully, so the area
    /// parses, attaches, and corroborates a slot — and hands back a page of
    /// zeros the acquisition invented. Without this, every stage reading a
    /// swapped address would be given those zeros as the process's own memory,
    /// tagged `swap` as though they had been recovered. See
    /// [`crate::formats::linux_swap::BODY_READS_AS_ZEROS`].
    swap_body: Vec<Option<crate::formats::linux_swap::SwapBodySurvey>>,
}

/// One pagefile or swap device attached to an address space.
///
/// A page the kernel swapped out lives here rather than in the memory image.
/// Reading it is possible and often valuable — but the bytes are not what was
/// in RAM at acquisition, and may predate it by a long way, so the name travels
/// with the source rather than being left to whoever attached it.
#[derive(Debug, Clone)]
pub struct SwapFile {
    /// The index a software PTE's `PageFileLow` names, matching Windows'
    /// registry order of `PagingFiles`.
    pub index: u8,
    /// What to call it in a report — normally the file's own name.
    pub label: String,
    /// The bytes.
    pub source: Arc<dyn DataSource>,
}

impl VirtualLayer {
    /// Build an address space over `physical`, rooted at `dtb`, under `spec`.
    ///
    /// The DTB is a *claim* — that this physical address holds the top of a
    /// page-table hierarchy — and it is the caller's to prove, normally with a
    /// crash dump's published `DirectoryTableBase` or a self-referential-entry
    /// test. It is recorded in this layer's metadata so a report can say where
    /// the address space came from.
    ///
    /// # Errors
    ///
    /// [`TranslateError::InvalidDtb`] if the base cannot name a page-table
    /// hierarchy at all. Refusing here rather than translating from physical
    /// address zero matters: a walk rooted at zero reads whatever happens to
    /// live at the bottom of the image and produces confident nonsense.
    pub fn new(
        physical: Arc<dyn MemoryLayer>,
        dtb: u64,
        spec: PagingSpec,
    ) -> Result<Self, TranslateError> {
        Self::with_cache(
            physical,
            dtb,
            spec,
            TranslationPolicy::default(),
            Arc::new(TableCache::new()),
        )
    }

    /// As [`VirtualLayer::new`], with an explicit policy and a **shared** entry
    /// memo.
    ///
    /// Page-table entries are keyed by physical address and mean the same thing
    /// in every address space, so one `Arc<TableCache>` should be handed to
    /// every layer built over the same physical memory. That is what keeps a
    /// case with four hundred processes to one bounded cache instead of four
    /// hundred.
    pub fn with_cache(
        physical: Arc<dyn MemoryLayer>,
        dtb: u64,
        spec: PagingSpec,
        policy: TranslationPolicy,
        cache: Arc<TableCache>,
    ) -> Result<Self, TranslateError> {
        if dtb == 0 {
            return Err(TranslateError::InvalidDtb {
                dtb,
                detail: "a directory table base of zero names no page table",
            });
        }
        if spec.levels().is_empty() {
            return Err(TranslateError::InvalidDtb {
                dtb,
                detail: "paging spec declares no levels",
            });
        }
        if spec.root_table_pa(dtb) == Some(0) {
            return Err(TranslateError::InvalidDtb {
                dtb,
                detail: "resolves to physical address zero, which holds no page table",
            });
        }

        let mut meta = LayerMeta::default()
            .with_parent(Arc::new(physical.layer_meta().clone()))
            .with_note("paging_mode", spec.mode().as_str())
            .with_note("pte_semantics", spec.semantics().as_str())
            .with_note("directory_table_base", dtb)
            .with_note("max_phys_addr_bits", u64::from(spec.max_phys_addr_bits()))
            .with_note("suppress_uniform_tables", policy.suppress_uniform_tables);
        if let Some(regime) = spec.mode().arm64() {
            // The mode name carries the granule and the register; the width
            // is `TCR_EL1.TxSZ` and is not one of a fixed set, so it is its
            // own note. An ARM64 space is one regime: the report has to say
            // which, and how wide, or a re-run cannot rebuild the same space.
            meta = meta
                .with_note("arm64_va_bits", u64::from(regime.va_bits()))
                .with_note("arm64_granule", regime.granule().as_str())
                .with_note(
                    "arm64_ttbr",
                    match regime.ttbr() {
                        crate::translate::spec::Ttbr::Ttbr0 => "ttbr0",
                        crate::translate::spec::Ttbr::Ttbr1 => "ttbr1",
                    },
                )
                .with_note("min_virtual_address", spec.min_virtual_address());
        }

        Ok(Self {
            physical,
            spec,
            dtb,
            policy,
            cache,
            suppressed: AtomicU64::new(0),
            max_address: spec.max_virtual_address(),
            meta,
            swap: Vec::new(),
            swap_ambiguous: Vec::new(),
            swap_linux: Vec::new(),
            swap_body: Vec::new(),
        })
    }

    /// Attach pagefiles, so a swapped-out page resolves to bytes instead of a
    /// hole.
    ///
    /// Windows numbers its paging files in the order `PagingFiles` lists them
    /// under `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory
    /// Management`, and a software PTE names one by that index. Supplying the
    /// wrong file under an index does not fail: it returns bytes, from the
    /// wrong file, which then get reported as the process's memory. So an index
    /// with no attached file stays a hole rather than falling back to any other
    /// — there is no "the only one we have" rule here.
    ///
    /// Attaching none leaves the layer exactly as it was: `swapped_out` holes,
    /// which is the honest answer when the pagefile was not collected.
    ///
    /// # Two files under one index
    ///
    /// An index is a name, and a name that points at two files names neither.
    /// Taking the first — which is what a `find` over the list does — is the
    /// same failure as attaching the wrong file, and the paragraph above is
    /// about exactly how bad that is: it returns bytes, from a file the PTE did
    /// not name, and they are then reported as the process's memory.
    ///
    /// So a repeated index disables *all* of its entries: every PTE naming it
    /// stays a `swapped_out` hole, and the layer records an incompleteness
    /// saying which index was ambiguous. Nothing is dropped in silence, and no
    /// page is answered for by a file that may not be the one the kernel wrote
    /// it to.
    #[must_use]
    pub fn with_swap(mut self, files: Vec<SwapFile>) -> Self {
        let mut seen: Vec<u8> = Vec::new();
        let mut ambiguous: Vec<u8> = Vec::new();
        for file in &files {
            if seen.contains(&file.index) {
                if !ambiguous.contains(&file.index) {
                    ambiguous.push(file.index);
                }
            } else {
                seen.push(file.index);
            }
        }
        for index in &ambiguous {
            let labels: Vec<&str> = files
                .iter()
                .filter(|f| f.index == *index)
                .map(|f| f.label.as_str())
                .collect();
            self.meta.push_incomplete(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "pagefile index {index} was attached {} times ({}), so a software PTE \
                     naming it identifies no single file; every page it names is left a \
                     swapped_out hole rather than answered from whichever file was listed first",
                    labels.len(),
                    labels.join(", ")
                ),
            );
        }
        // Probe each attached file for a Linux swap-area header. A Windows
        // pagefile has no `SWAPSPACE2` signature and parses as `None`, so this is
        // safe to run for every attached file regardless of the OS: it is what
        // distinguishes "resolve this as a Linux swap slot" from "resolve this as
        // a Windows pagefile offset", read from the file itself rather than
        // declared. The largest page size a swap area may use bounds the read.
        self.swap_linux = files
            .iter()
            .map(|file| {
                let mut head = vec![0u8; 65536];
                let n = file.source.read_at(0, &mut head).unwrap_or(0);
                crate::formats::linux_swap::LinuxSwapHeader::parse(&head[..n], None).ok()
            })
            .collect();
        // Survey each Linux area's body once, here, rather than per page: the
        // survey reads a bounded, fixed number of pages however large the area
        // is, and doing it at attach time is also the only place the layer can
        // record an incompleteness about it — `with_swap` takes `self` by value
        // and the per-page path has only `&self`.
        self.swap_body = files
            .iter()
            .zip(self.swap_linux.iter())
            .map(|(file, header)| {
                header
                    .as_ref()
                    .map(|header| header.survey_body(file.source.as_ref()))
            })
            .collect();
        // An attachment with no swap header at all, under Linux PTE semantics.
        //
        // The `None` case cannot be read as a defect in general: a Windows
        // pagefile carries no `SWAPSPACE2` signature and is *supposed* to parse
        // as `None` here, which is how this one function serves both tiers. It
        // is the semantics that make it a finding — under
        // `PteSemantics::Linux`, an attached file that is not a swap area is a
        // file no `swp_entry_t` can ever be answered from, so every page naming
        // its index stays a hole for a reason the operator can fix. Gating on
        // the semantics rather than on the file is what keeps a normal Windows
        // analysis from growing an incompleteness for doing exactly the right
        // thing.
        if self.spec.semantics() == crate::translate::PteSemantics::Linux {
            for (file, header) in files.iter().zip(self.swap_linux.iter()) {
                if header.is_some() {
                    continue;
                }
                self.meta.push_incomplete(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "'{}' was attached as swap area index {}, but no Linux swap header was \
                         read from it. Every swap entry naming that index stays a hole.",
                        file.label, file.index
                    ),
                );
            }
        }
        for (file, survey) in files.iter().zip(self.swap_body.iter()) {
            let Some(survey) = survey else { continue };
            if !survey.reads_as_all_zero() {
                continue;
            }
            self.meta.push_incomplete(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "swap area '{}' attached, but {} of {} sampled body pages read back as \
                     nothing but zeros. {}",
                    file.label,
                    survey.pages_read,
                    survey.pages_sampled,
                    crate::formats::linux_swap::BODY_READS_AS_ZEROS
                ),
            );
        }
        self.swap = files;
        self.swap_ambiguous = ambiguous;
        self
    }

    /// Turn a swapped-out translation failure into a run over a pagefile, when
    /// one is attached under the index the PTE names.
    ///
    /// `None` for every other failure, and for a swapped page whose pagefile
    /// was not supplied or whose index the build's layout could not read — all
    /// of which stay holes. A hole is the honest answer for a page whose bytes
    /// are on a disk nobody collected.
    fn swap_run(&self, va: u64, err: &TranslateError, remaining: u64) -> Option<MappedRange> {
        /// A swapped page is always a small page. Windows does not page out
        /// large pages, so a software PTE always describes 4 KiB however the
        /// surrounding address space is mapped.
        const SWAP_PAGE: u64 = 4096;

        // A Linux `swp_entry_t` is resolved on its own path: the entry is decoded
        // and corroborated against an attached swap area's bounds, rather than
        // carrying a ready byte offset the way a Windows software PTE does.
        if let TranslateError::LinuxSwapEntry { entry, .. } = err {
            return self.linux_swap_run(va, *entry, remaining);
        }

        let TranslateError::SwappedOut {
            swap_index,
            swap_offset,
            ..
        } = err
        else {
            return None;
        };
        // `None` means this build's layout could not say which pagefile. The
        // field moved between Windows 7 and 8, so reading the wrong bits yields
        // a small plausible integer naming a *different* file — and an offset
        // applied to the wrong file returns bytes rather than failing. Naming
        // none is the safe answer, and it keeps the page a hole.
        let (slot, _) = self.swap_file((*swap_index)?)?;

        // `swap_offset` addresses the start of the page in the pagefile, and
        // `va` may be part-way into it. Reading from the page start would
        // return the right page's bytes at the wrong alignment, which is the
        // kind of error that produces plausible output.
        let in_page = va & (SWAP_PAGE - 1);
        let take = (SWAP_PAGE - in_page).min(remaining);

        Some(
            MappedRange {
                offset: va,
                length: take,
                mapped_offset: swap_offset.saturating_add(in_page),
                mapped_length: take,
                encoding: Encoding::Identity,
                source: BackingSource::Auxiliary(slot),
                via: None,
            }
            // Not RAM. A page read from a pagefile was written there at some
            // earlier point and may predate the capture considerably, so the
            // run says where it came from rather than passing as memory.
            .reached_via("pagefile"),
        )
    }

    /// Resolve a Linux `swp_entry_t` to a run over an attached swap area, when
    /// the evidence corroborates where the page went.
    ///
    /// The x86-64 swap-entry bit layout changed once (the L1TF mitigation), and a
    /// single PTE does not say which layout wrote it. So both are decoded and a
    /// candidate is kept only when its swap type names an attached area and its
    /// offset lands inside that area's bounds — the inversion sends the wrong
    /// layout wildly out of range, so exactly one survives and the evidence
    /// selects it. `None` (the page stays a hole) when no area corroborates it,
    /// when more than one does — guessing is exactly what this refuses — or on an
    /// architecture whose layout this build does not decode.
    fn linux_swap_run(&self, va: u64, entry: u64, remaining: u64) -> Option<MappedRange> {
        use crate::formats::linux_swap::{decode_x86_64, X86SwapLayout};
        use crate::translate::PagingMode;

        const SWAP_PAGE: u64 = 4096;
        let layouts: &[X86SwapLayout] = match self.spec.mode() {
            PagingMode::Intel32e | PagingMode::Intel32eLa57 => {
                &[X86SwapLayout::PostL1tf, X86SwapLayout::PreL1tf]
            }
            _ => return None,
        };

        // Keep the single (slot, byte-offset) that any layout corroborates. Two
        // layouts agreeing on the same location is one candidate; two different
        // corroborated locations is an ambiguity that resolves to nothing.
        let mut hit: Option<(u16, u64)> = None;
        for &layout in layouts {
            let decoded = decode_x86_64(entry, layout);
            let Some((slot, _file)) = self.swap_file(decoded.swap_type) else {
                continue;
            };
            let Some(Some(header)) = self.swap_linux.get(slot as usize) else {
                continue;
            };
            let Some(byte) = header.slot_byte_offset(decoded.offset) else {
                continue;
            };
            match hit {
                Some(existing) if existing == (slot, byte) => {}
                Some(_) => return None,
                None => hit = Some((slot, byte)),
            }
        }
        let (slot, byte) = hit?;

        // The area corroborated the entry, but corroboration is about *where*
        // the page is, not about whether its bytes were ever acquired. When the
        // area's body sampled as nothing but zeros, a page of zeros from it is
        // far more likely to be the acquisition trap than the process's memory,
        // so this layer will not vouch for it: the page stays a hole, which the
        // address space already reports as `swapped_out`, rather than becoming
        // 4,096 invented zeros tagged as recovered from swap.
        //
        // BOTH conditions are required, and the second is what keeps the guard
        // from costing real evidence. On the ground-truth corpus — a genuine
        // block-device acquisition — only one of sixty-four sampled pages holds
        // data, because most of a swap area is legitimately unused. Refusing on
        // the area-level verdict alone would sit one unlucky sample away from
        // discarding every recoverable page. A slot that holds bytes is answered
        // whatever the survey found.
        if self
            .swap_body
            .get(slot as usize)
            .and_then(|s| s.as_ref())
            .is_some_and(|survey| survey.reads_as_all_zero())
        {
            let file = self.swap.get(slot as usize)?;
            let mut page = vec![0u8; SWAP_PAGE as usize];
            // A slot that cannot be read at all is not a slot of zeros; leave it
            // to the ordinary unread path rather than deciding on no evidence.
            if let Ok(n) = file.source.read_at(byte, &mut page) {
                if n == page.len() && page.iter().all(|b| *b == 0) {
                    return None;
                }
            }
        }

        let in_page = va & (SWAP_PAGE - 1);
        let take = (SWAP_PAGE - in_page).min(remaining);
        Some(
            MappedRange {
                offset: va,
                length: take,
                mapped_offset: byte.saturating_add(in_page),
                mapped_length: take,
                encoding: Encoding::Identity,
                source: BackingSource::Auxiliary(slot),
                via: None,
            }
            // Swap, not RAM: the bytes were written to the area at some earlier
            // point and may predate the capture, so the run says where it came
            // from rather than passing as memory.
            .reached_via("swap"),
        )
    }

    /// Describe a swapped-out page as an extent in its pagefile, appending it to
    /// `map`, and return how many bytes it covered.
    ///
    /// `None` when this is not a swapped page, when the PTE names no pagefile
    /// this build can identify, or when the pagefile it names is not attached —
    /// in each of which cases the caller falls back to treating it as a hole.
    /// The distinction matters: an offset applied to a pagefile the PTE did not
    /// name does not fail, it returns bytes.
    fn swap_extent(
        &self,
        va: u64,
        err: &TranslateError,
        remaining: u64,
        map: &mut PhysicalMap,
    ) -> Option<u64> {
        let run = self.swap_run(va, err, remaining)?;
        let BackingSource::Auxiliary(slot) = run.source else {
            return None;
        };
        let label = self.auxiliary_label(slot)?.to_string();
        // A full source table means this projection cannot name the file, and
        // an unnamed offset is one an examiner would read against the image.
        let index = map.intern_auxiliary(&label)?;
        map.extents.push(PhysicalExtent::auxiliary(
            index,
            run.mapped_offset,
            run.length,
        ));
        Some(run.length)
    }

    /// The pagefile a software PTE's index names, if exactly one is attached.
    ///
    /// An index attached twice names nothing this layer can resolve, so it
    /// answers `None` and the page stays a hole — see [`VirtualLayer::with_swap`].
    fn swap_file(&self, index: u8) -> Option<(u16, &SwapFile)> {
        if self.swap_ambiguous.contains(&index) {
            return None;
        }
        self.swap
            .iter()
            .enumerate()
            .find(|(_, file)| file.index == index)
            .map(|(slot, file)| (slot as u16, file))
    }

    /// The directory table base this space is rooted at.
    pub fn dtb(&self) -> u64 {
        self.dtb
    }

    /// The paging parameters in force.
    pub fn spec(&self) -> &PagingSpec {
        &self.spec
    }

    /// What this layer is allowed to assume.
    pub fn policy(&self) -> TranslationPolicy {
        self.policy
    }

    /// The physical layer underneath.
    pub fn physical(&self) -> &Arc<dyn MemoryLayer> {
        &self.physical
    }

    /// The shared page-table entry memo, so a caller can hand the same one to
    /// the next address space it builds.
    pub fn table_cache(&self) -> &Arc<TableCache> {
        &self.cache
    }

    /// How many **translations** this layer has refused under the uniform-table
    /// heuristic.
    ///
    /// Not a count of distinct tables: the walker counts each refusal, so a
    /// thousand addresses behind one suppressed table are a thousand here. That
    /// is the number the counter can produce without holding a set of table
    /// addresses for the life of the layer, and it is stated rather than dressed
    /// up, because "1483 tables were hidden" and "1483 reads were refused" are
    /// different claims and only the second one is true. Zero always means the
    /// heuristic never fired — a run with the policy off reports zero.
    ///
    /// # Who publishes it
    ///
    /// Not this crate: no product path here builds a [`VirtualLayer`], so the
    /// OS-analysis plugin that builds one is what stamps this number onto the
    /// records it emits. It reaches that plugin through
    /// [`MemoryLayer::as_virtual`], which is why an address space held as
    /// `Arc<dyn MemoryLayer>` — the only form the plugins hold — can still
    /// answer the question. A record that names an address space and omits this
    /// number is claiming a completeness it has not checked.
    ///
    /// Independently of any of that, the per-refusal evidence always reaches the
    /// examiner: a [`crate::layer::HoleReason::TableSuppressed`] hole no caller
    /// can confuse with `not_present`, and a
    /// [`TranslateError::UniformTableSuppressed`] carrying the repeated entry
    /// itself. That part travels on the read that was refused and cannot be
    /// dropped by a consumer that forgets to look.
    ///
    /// # Per address space, not per case
    ///
    /// Each layer counts its own refusals. Processes get one layer each, so a
    /// case-wide figure is the sum over the spaces a run actually built, and a
    /// process record should carry its own process's count rather than a total
    /// that includes address spaces the record is not about.
    pub fn uniform_tables_suppressed(&self) -> u64 {
        self.suppressed.load(Ordering::Relaxed)
    }

    /// Walk the page tables for one address.
    ///
    /// The full typed outcome, unflattened: a caller that wants to know *which*
    /// pagefile a page went to, or that a prototype PTE points at a section
    /// object, uses this rather than reading and catching a hole.
    ///
    /// Success means the page tables map the address. It does **not** mean the
    /// bytes are in the evidence: a frame the acquisition never captured still
    /// translates, and only [`VirtualLayer::mapping`] and
    /// [`DataSource::read_at`], which know how many bytes are wanted, can say
    /// so. That separation is deliberate — "the OS had this page mapped" and
    /// "we have this page" are different findings, and the second one is a
    /// statement about the acquisition, not about the suspect.
    pub fn translate(&self, va: u64) -> Result<Translation, TranslateError> {
        PageWalk::new(
            &*self.physical,
            &self.spec,
            &self.cache,
            self.policy,
            &self.suppressed,
        )
        .translate(self.dtb, va)
    }

    /// Assert that the physical layer really holds `len` bytes at `phys`.
    ///
    /// A translated frame that is not in the acquisition is an **acquisition**
    /// defect, not an operating-system state, and it is the strongest smearing
    /// or tearing signal available: the page tables said the page was resident,
    /// and the capture tool did not bring it back. Reported in *virtual* space,
    /// because that is what the caller indexed by.
    ///
    /// Three distinctions are kept, because collapsing any of them puts a false
    /// sentence in a report:
    ///
    /// - A frame the layer beneath only *partly* holds makes a hole where its
    ///   bytes stop, not one covering the acquired part as well.
    /// - A frame the layer beneath reports as a hole keeps **its** reason. A
    ///   virtual layer can sit on another one, and "the page under this page is
    ///   in a pagefile" must not be rewritten into "nobody captured it".
    /// - A read that simply failed is [`LayerError::Io`] and stays one. "The
    ///   evidence file would not read" and "the acquisition never contained
    ///   these bytes" are statements about different things, and only the
    ///   second one is a fact about the acquisition's coverage.
    fn require_acquired(&self, va: u64, phys: u64, len: u64) -> Result<(), LayerError> {
        match self.physical.mapping(phys, len) {
            // Coverage of the *requested interval*, not the sum of the run
            // lengths. Summing is wrong in both directions against a layer whose
            // runs are not clipped to the request, and a compressed acquisition
            // is exactly that: an encoded run describes the whole frame it
            // decodes from, so it may begin below `phys` and end above
            // `phys + len`. `covered_len` then over-reports, the equality below
            // fails for a frame that is entirely present, and the read is
            // refused as a hole.
            //
            // That is not hypothetical. It made every Linux discovery against a
            // Snappy-compressed AVML capture fail: reading `linux_banner` back
            // through the proved page tables — the last step of the proof —
            // asked for 64 bytes inside a 64 KiB compressed frame, was told the
            // run covered 65,536 of the 64 wanted, and reported a hole 64 KiB
            // further on. The capture was whole; the arithmetic was not. The
            // AVML layer documents this and says to use `is_valid` rather than
            // `covered_len`; this is what that warning was about.
            Ok(runs) if backed_len(&runs, phys, len) == len => Ok(()),
            // Genuinely short: the frame runs off the end of the acquisition, or
            // a gap opens inside it.
            Ok(runs) => {
                let covered = backed_len(&runs, phys, len);
                Err(LayerError::Hole(MemoryHole::unmapped(
                    va.saturating_add(covered),
                    len.saturating_sub(covered),
                )))
            }
            // Above the top of the layer beneath: the frame is outside the
            // acquisition entirely, which is exactly an unmapped hole here.
            Err(LayerError::OutOfRange { .. }) => {
                Err(LayerError::Hole(MemoryHole::unmapped(va, len)))
            }
            Err(err) => {
                let reason = err.hole().map(|hole| hole.reason);
                match reason {
                    Some(reason) => Err(LayerError::Hole(MemoryHole {
                        address: va,
                        length: len,
                        reason,
                    })),
                    None => Err(err),
                }
            }
        }
    }

    /// Bytes from `offset` to the top of this address space.
    fn span_from(&self, offset: u64) -> u64 {
        // `offset <= max_address` is checked by every caller, and the
        // saturation covers a space whose top is `u64::MAX`.
        (self.max_address - offset).saturating_add(1)
    }
}

impl DataSource for VirtualLayer {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || offset > self.max_address {
            // Above the top of the address space: genuine end, never a hole.
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.span_from(offset));
        // Deliberately routed through `mapping`, so a read and a projection can
        // never disagree about where a page lives or whether it is there.
        let runs = self.mapping(offset, want)?;

        let mut written = 0usize;
        for run in &runs {
            let remaining = buf.len() - written;
            // `remaining` is a usize, so the minimum of the two is exactly
            // representable and the cast cannot truncate.
            let take = run.length.min(remaining as u64) as usize;
            // Which file the offset indexes. A run over a pagefile carries an
            // offset into *that* file, and reading it out of the memory image
            // would return unrelated bytes that parse perfectly well.
            let backing = match run.source {
                BackingSource::Primary => self.physical.as_data_source(),
                BackingSource::Auxiliary(slot) => match self.swap.get(slot as usize) {
                    Some(file) => file.source.as_ref(),
                    // A run this layer produced naming a source it does not
                    // have is a bug here, not something a caller can resolve.
                    // Report the page as a hole rather than reading the wrong
                    // file at that offset.
                    None => return Err(MemoryHole::unmapped(run.offset, run.length).into_io()),
                },
            };
            let got = read_full(
                backing,
                run.mapped_offset,
                &mut buf[written..written + take],
            );
            written += got;
            if got < take {
                // The acquisition is shorter than its own structures claim: the
                // layer beneath projected these bytes and then could not
                // produce them. A short count says so honestly — except at
                // `written == 0`, where `Ok(0)` is reserved for the top of the
                // address space and would tell the caller the evidence simply
                // ends here. That address is well inside the space, so the
                // failure is a hole and is reported as one.
                if written == 0 {
                    return Err(MemoryHole::unmapped(run.offset, run.length).into_io());
                }
                return Ok(written);
            }
        }
        Ok(written)
    }

    fn size(&self) -> u64 {
        // The span of the address space. On x86-64 the true span is 2^64 and
        // does not fit in a `u64`, so this saturates: the single highest byte
        // of the 64-bit space is reachable through `mapping` but not through a
        // `size`-bounded read. No operating system maps it, and the alternative
        // — reporting a size of zero — would make the whole space unreadable.
        self.max_address.saturating_add(1)
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.physical.get_underlying_path()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        // Kept reachable so a caller can find the pagefile beside the memory
        // image, which is what turns a `swapped_out` hole into bytes.
        self.physical.open_sibling(suffix)
    }

    /// Project this virtual range onto the backing device image.
    ///
    /// # What an examiner learns
    ///
    /// "Which offset in the evidence file holds this process's PEB" — resolved
    /// through the page tables and then down through E01, QCOW2 and partition
    /// windows, with no memory-specific API.
    ///
    /// # What the answer never claims
    ///
    /// [`PhysicalMap`] has no error channel, so this method cannot refuse. What
    /// it can do — and does — is decline to invent. Two outcomes are kept apart
    /// from a located extent and from each other:
    ///
    /// - **A hole.** The address exists and has no bytes behind it: not
    ///   present, never acquired, in a pagefile, or behind a table the uniform
    ///   heuristic suppressed. It contributes an extent with no device offset,
    ///   which is what every other layer in this crate does for a gap, so the
    ///   extents stay in logical order and
    ///   [`PhysicalMap::located_len`](seance_core::data_source::PhysicalMap::located_len)
    ///   excludes it. Which of the four it was is not expressible here and is
    ///   *not* guessed at: [`VirtualLayer::translate`] states it exactly.
    /// - **No answer at all.** The address is not canonical, the walk hit
    ///   arithmetic that left the addressable range, or the page tables
    ///   themselves could not be read out of the evidence. None of those is a
    ///   hole — the first two mean there is no such address, the third means
    ///   the tool does not know — and an extent covering them would assert a
    ///   region of the address space that was never established. The projection
    ///   stops instead, so
    ///   [`total_len`](seance_core::data_source::PhysicalMap::total_len) comes
    ///   back short of `len` and the caller can see the request was not fully
    ///   answered.
    ///
    /// The distinction matters because the previous behaviour — one synthetic
    /// extent spanning everything left in the request — turned "this address
    /// does not exist" and "the evidence file would not read" into a confident
    /// statement about the shape of the process's memory.
    ///
    /// # A swapped page attached to a pagefile is deliberately not projected
    ///
    /// This walks the tables itself rather than going through
    /// [`MemoryLayer::mapping`], so a page resolved out of an attached pagefile
    /// is *readable* and still projects as no device backing. That is not an
    /// oversight and the two answers do not contradict each other: the question
    /// here is "where in this evidence image do these bytes live", and for a
    /// swapped page the answer is that they do not. They live in a different
    /// file.
    ///
    /// Reporting the pagefile's offset as a plain `device_offset` would be
    /// worse than the hole it replaced — an examiner would seek to that offset
    /// in the memory image and find unrelated bytes, with nothing to say they
    /// were the wrong ones.
    ///
    /// Since [`PhysicalExtent`](seance_core::data_source::PhysicalExtent)
    /// carries a source label, that is no longer the choice. A swapped page is
    /// reported at its real offset in the pagefile, with
    /// [`ExtentSource::Auxiliary`] naming which file the offset belongs to, and
    /// the name itself on
    /// [`PhysicalMap::auxiliary_sources`](seance_core::data_source::PhysicalMap::auxiliary_sources).
    /// A projection can now say "4 KiB at offset 0x3F2000 of `pagefile.sys`"
    /// instead of "4 KiB, location unknown".
    ///
    /// A page whose PTE names a pagefile that is not attached stays a hole:
    /// `swap_run` returns `None` for it, deliberately, because a smeared
    /// capture yields plausible-looking indices for files that do not exist.
    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        let mut map = PhysicalMap::empty(ExtentPrecision::Exact);
        if len == 0 || offset > self.max_address {
            return map;
        }
        let total = len.min(self.span_from(offset));
        let mut pos = offset;
        let mut done = 0u64;
        while done < total {
            match self.translate(pos) {
                Ok(translation) => {
                    let take = translation.bytes_to_page_end().min(total - done);
                    let sub = self.physical.physical_map(translation.phys, take);
                    // `absorb` rather than `extend`: the inner map's auxiliary
                    // indices are meaningful only against its own table.
                    map.absorb(sub);
                    done += take;
                    pos = pos.saturating_add(take);
                }
                Err(err) => {
                    // A page the kernel swapped out is not a hole. It has bytes,
                    // at a known offset, in a file we can name — so it is
                    // described rather than skipped.
                    if let Some(located) = self.swap_extent(pos, &err, total - done, &mut map) {
                        done += located;
                        pos = pos.saturating_add(located);
                        continue;
                    }
                    // Only a genuine hole is described. Everything else stops
                    // the projection rather than being papered over — see the
                    // method doc.
                    let Some(bits) = err.hole_reason().and(err.invalid_bits()) else {
                        break;
                    };
                    let skip = unresolved_span(pos, bits).min(total - done);
                    map.extents.push(PhysicalExtent::hole(skip));
                    map.precision = map.precision.worst(ExtentPrecision::Synthetic);
                    done += skip;
                    pos = pos.saturating_add(skip);
                }
            }
        }
        map
    }
}

impl MemoryLayer for VirtualLayer {
    /// Zero for every mode but an ARM64 TTBR1 regime, whose space is the top
    /// `2^va_bits` bytes of the 64-bit space: below its base every address
    /// is TTBR0's, and a layer that claimed them would answer for a space it
    /// does not hold. See [`PagingSpec::min_virtual_address`].
    fn min_address(&self) -> u64 {
        self.spec.min_virtual_address()
    }

    fn max_address(&self) -> u64 {
        self.max_address
    }

    /// Jumps the non-addressable middle of a sign-extending space.
    ///
    /// The kernel's half is **above** that gap, so an enumeration that stopped
    /// at it would report the lower canonical half as the whole space. See
    /// [`MemoryLayer::next_addressable`].
    fn next_addressable(&self, address: u64) -> Option<u64> {
        let next = self.spec.next_canonical(address)?;
        (next <= self.max_address).then_some(next)
    }

    fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        if offset > self.max_address {
            return Err(LayerError::OutOfRange {
                address: offset,
                max_address: self.max_address,
            });
        }
        let total = length.min(self.span_from(offset));

        let mut runs: Vec<MappedRange> = Vec::new();
        let mut pos = offset;
        let mut done = 0u64;
        while done < total {
            let translation = match self.translate(pos) {
                Ok(translation) => translation,
                Err(err) => {
                    // A swapped-out page is readable when its pagefile was
                    // collected and attached. Resolving it here, in `mapping`,
                    // rather than in `read_at` keeps the invariant this layer
                    // is built on: a read and a projection agree about where a
                    // page lives, because they ask the same function.
                    if let Some(run) = self.swap_run(pos, &err, total - done) {
                        done += run.length;
                        pos = pos.saturating_add(run.length);
                        runs.push(run);
                        continue;
                    }
                    return Err(err.into_layer_error(pos, self.max_address));
                }
            };
            // One run per page walked. A large page yields one run for the
            // whole of it; two physically adjacent 4 KiB pages still yield two,
            // because only the tables can say they are contiguous.
            let take = translation.bytes_to_page_end().min(total - done);
            self.require_acquired(pos, translation.phys, take)?;
            runs.push(
                MappedRange::identity(pos, take, translation.phys)
                    .reached_via(translation.via.as_str()),
            );
            done += take;
            // Unobservable when `done == total`; the loop ends first.
            pos = pos.saturating_add(take);
        }
        Ok(runs)
    }

    fn auxiliary_source(&self, index: u16) -> Option<&dyn DataSource> {
        self.swap.get(index as usize).map(|f| f.source.as_ref())
    }

    fn auxiliary_label(&self, index: u16) -> Option<&str> {
        self.swap.get(index as usize).map(|f| f.label.as_str())
    }

    fn layer_meta(&self) -> &LayerMeta {
        &self.meta
    }

    fn as_data_source(&self) -> &dyn DataSource {
        self
    }

    /// The one implementation that returns anything: this layer translates, so
    /// [`VirtualLayer::translate`] and
    /// [`VirtualLayer::uniform_tables_suppressed`] are reachable from a caller
    /// that only holds `Arc<dyn MemoryLayer>` — which is how every OS-analysis
    /// plugin holds an address space.
    fn as_virtual(&self) -> Option<&VirtualLayer> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{covered_len, HoleReason};
    use crate::meta::Architecture;
    use crate::physical::PhysicalLayer;
    use crate::translate::spec::{
        PagingMode, PteSemantics, LARGE_PAGE_BIT, PRESENT_BIT, WINDOWS_PROTOTYPE_BIT,
        WINDOWS_X64_PROTO_ADDRESS_SHIFT,
    };
    use seance_core::data_source::{
        ByteSliceDataSource, DeviceImageSource, ExtentSource, SiblingBundleSource, WindowSource,
    };
    use seance_core::io::read_exact_or_fail;
    use seance_core::test_support::TruncatedSource;
    use std::collections::HashMap;

    const IMAGE_SIZE: usize = 0x40_0000;
    const PML4: u64 = 0x1000;
    const PDPT: u64 = 0x2000;
    const PD: u64 = 0x3000;
    const PT: u64 = 0x4000;

    fn put64(bytes: &mut [u8], table: u64, index: u64, value: u64) {
        let at = (table + index * 8) as usize;
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// A small x86-64 address space with every interesting outcome in it.
    ///
    /// | virtual | outcome |
    /// |---|---|
    /// | `0x401000` | physical `0x5000`, filled `0xAA` |
    /// | `0x402000` | physical `0x9000`, filled `0xBB` — deliberately not adjacent |
    /// | `0x403000` | physical `0x6000`, filled `0xCC` |
    /// | `0x404000` | no present entry |
    /// | `0x405000` | physical `0x7000`, filled `0xDD` |
    /// | `0x406000` | a Windows software PTE: pagefile 2, page `0x33` |
    /// | `0x407000` | physical `0x100_0000`, past the end of the acquisition |
    fn image() -> Vec<u8> {
        let mut bytes = vec![0u8; IMAGE_SIZE];
        put64(&mut bytes, PML4, 0, PDPT | PRESENT_BIT);
        put64(&mut bytes, PDPT, 0, PD | PRESENT_BIT);
        put64(&mut bytes, PD, 2, PT | PRESENT_BIT);
        put64(&mut bytes, PT, 1, 0x5000 | PRESENT_BIT);
        put64(&mut bytes, PT, 2, 0x9000 | PRESENT_BIT);
        put64(&mut bytes, PT, 3, 0x6000 | PRESENT_BIT);
        put64(&mut bytes, PT, 4, 0);
        put64(&mut bytes, PT, 5, 0x7000 | PRESENT_BIT);
        put64(&mut bytes, PT, 6, (2u64 << 1) | (0x33u64 << 32));
        put64(&mut bytes, PT, 7, 0x100_0000 | PRESENT_BIT);
        bytes[0x5000..0x6000].fill(0xAA);
        bytes[0x6000..0x7000].fill(0xCC);
        bytes[0x7000..0x8000].fill(0xDD);
        bytes[0x9000..0xA000].fill(0xBB);
        bytes
    }

    fn physical_from(bytes: Vec<u8>) -> Arc<dyn MemoryLayer> {
        Arc::new(
            PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes)))
                .expect("a non-empty image"),
        )
    }

    fn layer_with(semantics: PteSemantics) -> VirtualLayer {
        VirtualLayer::new(
            physical_from(image()),
            PML4,
            // Pre-Windows-8 PageFileLow position; see walk.rs's harness.
            PagingSpec::new(PagingMode::Intel32e, semantics).with_win8_pagefile_layout(false),
        )
        .expect("a usable directory table base")
    }

    fn layer() -> VirtualLayer {
        layer_with(PteSemantics::Bare)
    }

    #[test]
    fn a_page_reads_through_the_page_tables() {
        let l = layer();
        let mut page = vec![0u8; 0x1000];
        assert_eq!(l.read_at(0x40_1000, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0xAA));
        assert_eq!(l.min_address(), 0);
        assert_eq!(l.max_address(), u64::MAX);
    }

    /// **The non-addressable middle is jumped, not treated as the end.**
    ///
    /// On x86-64 the kernel's whole half of the address space is above that
    /// gap. A walk that stopped at it would enumerate the lower canonical half
    /// and report the space as covered.
    #[test]
    fn next_addressable_jumps_the_non_addressable_middle() {
        let l = layer();
        // A canonical address answers with itself.
        assert_eq!(l.next_addressable(0x40_1000), Some(0x40_1000));
        assert_eq!(l.next_addressable(0), Some(0));
        // The last canonical address of the lower half, and the first address
        // past it.
        assert_eq!(
            l.next_addressable(0x0000_7FFF_FFFF_FFFF),
            Some(0x0000_7FFF_FFFF_FFFF)
        );
        assert_eq!(
            l.next_addressable(0x0000_8000_0000_0000),
            Some(0xFFFF_8000_0000_0000),
            "the base of the upper canonical half, which is where the kernel is"
        );
        // Anywhere in the gap answers the same way.
        assert_eq!(
            l.next_addressable(0x1234_5678_9ABC_DEF0),
            Some(0xFFFF_8000_0000_0000)
        );
        // And the upper half answers with itself, to the very top.
        assert_eq!(
            l.next_addressable(0xFFFF_8000_0000_0000),
            Some(0xFFFF_8000_0000_0000)
        );
        assert_eq!(l.next_addressable(u64::MAX), Some(u64::MAX));
    }

    #[test]
    fn a_read_spanning_a_page_boundary_produces_two_ranges() {
        let l = layer();
        let runs = l.mapping(0x40_1800, 0x1000).expect("both pages are mapped");
        assert_eq!(runs.len(), 2, "a page boundary is a run boundary");
        assert_eq!(
            runs[0],
            MappedRange::identity(0x40_1800, 0x800, 0x5800).reached_via("page_tables")
        );
        assert_eq!(
            runs[1],
            MappedRange::identity(0x40_2000, 0x800, 0x9000).reached_via("page_tables")
        );
        assert_eq!(covered_len(&runs), 0x1000);
    }

    #[test]
    fn five_thousand_bytes_across_three_pages_produce_three_ranges() {
        // The scatter is the answer. Flattening it into one run would tell a
        // caller that 5000 bytes of physical memory are contiguous when they
        // are three unrelated frames.
        let l = layer();
        let runs = l.mapping(0x40_1F00, 5000).expect("three mapped pages");
        assert_eq!(runs.len(), 3);
        assert_eq!(
            runs[0],
            MappedRange::identity(0x40_1F00, 0x100, 0x5F00).reached_via("page_tables")
        );
        assert_eq!(
            runs[1],
            MappedRange::identity(0x40_2000, 0x1000, 0x9000).reached_via("page_tables")
        );
        assert_eq!(
            runs[2],
            MappedRange::identity(0x40_3000, 5000 - 0x1100, 0x6000).reached_via("page_tables")
        );
        assert_eq!(covered_len(&runs), 5000);
        assert!(l.is_valid(0x40_1F00, 5000));

        // And the bytes come back in that order, from three unrelated frames.
        let mut buf = vec![0u8; 5000];
        assert_eq!(l.read_at(0x40_1F00, &mut buf).unwrap(), 5000);
        assert!(buf[..0x100].iter().all(|&b| b == 0xAA));
        assert!(buf[0x100..0x1100].iter().all(|&b| b == 0xBB));
        assert!(buf[0x1100..].iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn scattered_frames_read_back_in_virtual_order() {
        let l = layer();
        let mut buf = vec![0u8; 0x2000];
        assert_eq!(l.read_at(0x40_1000, &mut buf).unwrap(), 0x2000);
        assert!(buf[..0x1000].iter().all(|&b| b == 0xAA));
        assert!(buf[0x1000..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn a_missing_middle_page_is_a_hole_rather_than_a_silent_skip() {
        // Three pages, the middle one absent. Returning runs for the two live
        // pages would present 0x403000 and 0x405000 as contiguous memory, which
        // is how a scanner reports a hit at an address that does not hold it.
        let l = layer();
        let err = l
            .mapping(0x40_3000, 0x3000)
            .expect_err("a gap must not be skipped");
        let hole = err.hole().expect("a typed hole");
        assert_eq!(hole.address, 0x40_4000);
        assert_eq!(hole.length, 0x1000);
        assert_eq!(hole.reason, HoleReason::NotPresent);
        assert!(!l.is_valid(0x40_3000, 0x3000));

        // And the same fact reaches an ordinary reader.
        let mut buf = vec![0u8; 0x3000];
        let err = l
            .read_at(0x40_3000, &mut buf)
            .expect_err("an absent page must not read as zeros");
        assert_eq!(
            MemoryHole::from_io(&err).map(|h| h.reason),
            Some(HoleReason::NotPresent)
        );
        assert!(buf.iter().all(|&b| b == 0), "nothing was fabricated");
    }

    #[test]
    fn a_structure_straddling_an_absent_page_refuses_to_parse() {
        // The invariant the whole crate exists for, now over virtual memory.
        let l = layer();
        let mut buf = [0u8; 64];
        let err = read_exact_or_fail(l.as_data_source(), 0x40_3FF0, &mut buf, "_EPROCESS")
            .expect_err("a structure in a hole must not parse");
        let hole = MemoryHole::from_io(&err).expect("the hole reaches the caller");
        assert_eq!(hole.address, 0x40_4000);
        assert_eq!(hole.reason, HoleReason::NotPresent);
    }

    #[test]
    fn a_frame_the_acquisition_never_captured_is_an_unmapped_hole() {
        // The page tables map it; the capture tool did not bring it back. That
        // is a defect in the evidence, not a state of the suspect's machine,
        // and it is the strongest smear signal there is.
        let l = layer();
        let err = l
            .mapping(0x40_7000, 0x1000)
            .expect_err("an uncaptured frame is not readable");
        let hole = err.hole().expect("a typed hole");
        assert_eq!(hole.address, 0x40_7000);
        assert_eq!(hole.reason, HoleReason::Unmapped);
        // The translation itself still succeeds: the OS really did map it.
        let t = l.translate(0x40_7000).expect("the tables map this page");
        assert_eq!(t.phys, 0x100_0000);
    }

    /// A physical layer whose projection fails with a plain I/O error rather
    /// than a hole, for the frame at `0x5000`.
    ///
    /// Nothing in phase 1 produces one, but a `VirtualLayer` stacked on another
    /// `VirtualLayer` does, and the distinction it tests for is the one the
    /// whole crate exists to keep.
    #[derive(Debug)]
    struct UnreadablePhysical {
        inner: PhysicalLayer,
    }

    impl DataSource for UnreadablePhysical {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.inner.size()
        }
    }

    impl MemoryLayer for UnreadablePhysical {
        fn min_address(&self) -> u64 {
            self.inner.min_address()
        }
        fn max_address(&self) -> u64 {
            self.inner.max_address()
        }
        fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
            if (0x5000..0x6000).contains(&offset) {
                return Err(LayerError::Io(io::Error::other("the evidence file broke")));
            }
            self.inner.mapping(offset, length)
        }
        fn layer_meta(&self) -> &LayerMeta {
            self.inner.layer_meta()
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    #[test]
    fn a_read_that_simply_failed_is_never_relabelled_as_a_frame_nobody_captured() {
        // "The evidence file would not read" and "the acquisition never held
        // these bytes" are different sentences in a report, and only the second
        // is a statement about what the capture tool did.
        let physical: Arc<dyn MemoryLayer> = Arc::new(UnreadablePhysical {
            inner: PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(image())))
                .expect("a non-empty image"),
        });
        let l = VirtualLayer::new(
            physical,
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare),
        )
        .unwrap();
        let err = l
            .mapping(0x40_1000, 0x1000)
            .expect_err("the layer beneath could not project this frame");
        assert!(
            err.hole().is_none(),
            "an I/O failure claims nothing about the acquisition's coverage"
        );
        assert!(matches!(err, LayerError::Io(_)), "{err}");
        // The neighbouring frame is untouched by the failure.
        assert!(l.mapping(0x40_2000, 0x1000).is_ok());
    }

    #[test]
    fn a_frame_the_acquisition_only_half_holds_makes_a_hole_where_the_bytes_stop() {
        // The acquisition ends inside the frame at physical 0x5000. The first
        // half really was captured, so claiming the whole page is missing would
        // overstate the loss in exactly the direction that hides evidence.
        let mut bytes = image();
        bytes.truncate(0x5800);
        let l = VirtualLayer::new(
            physical_from(bytes),
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare),
        )
        .unwrap();
        let err = l
            .mapping(0x40_1000, 0x1000)
            .expect_err("half the frame is not in the evidence");
        let hole = err.hole().expect("a typed hole");
        assert_eq!(hole.address, 0x40_1800, "the acquired half is not claimed");
        assert_eq!(hole.length, 0x800);
        assert_eq!(hole.reason, HoleReason::Unmapped);
    }
    #[test]
    fn a_frame_the_evidence_file_cannot_produce_is_a_hole_and_never_end_of_space() {
        // `Ok(0)` is reserved for the top of the address space. Returning it
        // here would tell every caller the process's memory simply ends at
        // 0x401000, when what happened is that the capture stopped.
        let mut bytes = image();
        bytes.truncate(0x5000);
        let source: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, IMAGE_SIZE as u64));
        let physical: Arc<dyn MemoryLayer> =
            Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"));
        let l = VirtualLayer::new(
            physical,
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare),
        )
        .unwrap();

        // The projection cannot tell: the layer beneath still claims the frame.
        assert!(l.mapping(0x40_1000, 0x1000).is_ok());
        let mut buf = vec![0u8; 0x1000];
        let err = l
            .read_at(0x40_1000, &mut buf)
            .expect_err("a frame the file never held is not the end of the space");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!(hole.address, 0x40_1000);
        assert_eq!(hole.reason, HoleReason::Unmapped);
        assert!(buf.iter().all(|&b| b == 0), "nothing was fabricated");
    }

    #[test]
    fn a_pagefile_backed_page_reads_as_swapped_out_under_windows_semantics() {
        let windows = layer_with(PteSemantics::Windows);
        let err = windows
            .mapping(0x40_6000, 0x100)
            .expect_err("a paged-out page has no bytes here");
        let hole = err.hole().expect("a typed hole");
        assert_eq!(hole.reason, HoleReason::SwappedOut);
        assert_eq!(hole.address, 0x40_6000);
        assert_eq!(hole.length, 0x1000, "to the end of the absent page");

        // The precise finding survives on the typed error.
        match windows.translate(0x40_6000).unwrap_err() {
            TranslateError::SwappedOut {
                swap_index,
                swap_offset,
                ..
            } => {
                assert_eq!(swap_index, Some(2));
                assert_eq!(swap_offset, 0x33 << 12);
            }
            other => panic!("expected SwappedOut, got {other:?}"),
        }

        // A bare walker says only that the page is absent, and never invents a
        // pagefile location.
        let bare = layer();
        assert_eq!(
            bare.mapping(0x40_6000, 0x100)
                .unwrap_err()
                .hole()
                .map(|h| h.reason),
            Some(HoleReason::NotPresent)
        );
    }

    /// A pagefile turns that hole into bytes — and only when it is the right
    /// pagefile.
    ///
    /// The page at `0x40_6000` is swapped to pagefile 2 at `0x33 << 12`. With
    /// that file attached the bytes are readable; without it, or under any
    /// other index, the page stays a hole. Nothing falls back to "the only
    /// pagefile we have": an offset applied to the wrong file returns bytes,
    /// and those bytes would be reported as this process's memory.
    #[test]
    fn an_attached_pagefile_resolves_a_swapped_page_and_a_wrong_index_does_not() {
        // A pagefile whose swapped page holds a recognisable pattern, so a read
        // at the wrong offset or out of the wrong file is visible rather than
        // merely wrong.
        const AT: usize = 0x33 << 12;
        let mut bytes = vec![0u8; AT + 0x1000];
        for (i, slot) in bytes[AT..AT + 0x1000].iter_mut().enumerate() {
            *slot = (i % 251) as u8;
        }
        let pagefile: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));

        let attached = layer_with(PteSemantics::Windows).with_swap(vec![SwapFile {
            index: 2,
            label: "pagefile.sys".to_string(),
            source: Arc::clone(&pagefile),
        }]);

        let mut buf = [0u8; 16];
        let read = attached.read_at(0x40_6000, &mut buf).expect("readable");
        assert_eq!(read, 16);
        assert_eq!(buf, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        // Part-way into the page: the pagefile offset has to advance with the
        // virtual address, or the right page is read at the wrong alignment.
        let mut mid = [0u8; 4];
        attached
            .read_at(0x40_6000 + 0x40, &mut mid)
            .expect("readable");
        assert_eq!(mid, [0x40, 0x41, 0x42, 0x43]);

        // The run says where the bytes came from. A page recovered from a
        // pagefile is not a page that was in RAM at acquisition.
        let runs = attached.mapping(0x40_6000, 0x100).expect("mapped");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].source, BackingSource::Auxiliary(0));
        assert_eq!(runs[0].via, Some("pagefile"));
        assert_eq!(runs[0].mapped_offset, AT as u64);
        assert_eq!(attached.auxiliary_label(0), Some("pagefile.sys"));

        // A pagefile attached under an index this PTE does not name leaves the
        // page exactly as it was.
        let wrong = layer_with(PteSemantics::Windows).with_swap(vec![SwapFile {
            index: 1,
            label: "pagefile.sys".to_string(),
            source: pagefile,
        }]);
        assert_eq!(
            wrong
                .mapping(0x40_6000, 0x100)
                .unwrap_err()
                .hole()
                .map(|h| h.reason),
            Some(HoleReason::SwappedOut),
            "the wrong pagefile must not answer for this page"
        );

        // And with none attached, unchanged from before this feature existed.
        assert_eq!(
            layer_with(PteSemantics::Windows)
                .mapping(0x40_6000, 0x100)
                .unwrap_err()
                .hole()
                .map(|h| h.reason),
            Some(HoleReason::SwappedOut)
        );
    }

    /// An index that names two files names neither.
    ///
    /// `SEANCE_PAGEFILES` is operator input and a repeated index is an ordinary
    /// typo. Resolving it by taking the first entry — which is what a `find`
    /// over the list does — reads the page out of a file the PTE may not have
    /// named and reports those bytes as this process's memory. That is the same
    /// harm as attaching the wrong pagefile outright, arrived at without anyone
    /// having chosen it.
    #[test]
    fn two_pagefiles_under_one_index_leave_the_page_a_hole_rather_than_taking_the_first() {
        const AT: usize = 0x33 << 12;
        let mut first_bytes = vec![0u8; AT + 0x1000];
        first_bytes[AT..AT + 0x1000].fill(0x11);
        let mut second_bytes = vec![0u8; AT + 0x1000];
        second_bytes[AT..AT + 0x1000].fill(0x22);
        let first: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(first_bytes));
        let second: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(second_bytes));

        let attached = layer_with(PteSemantics::Windows).with_swap(vec![
            SwapFile {
                index: 2,
                label: "pagefile.sys".to_string(),
                source: first,
            },
            SwapFile {
                index: 2,
                label: "D-pagefile.sys".to_string(),
                source: second,
            },
        ]);

        let mut buf = [0xEEu8; 16];
        let err = attached
            .read_at(0x40_6000, &mut buf)
            .expect_err("neither file may answer for an index that names both");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!(hole.reason, HoleReason::SwappedOut);
        assert!(
            buf.iter().all(|&b| b == 0xEE),
            "no bytes reached the caller"
        );

        // Absent from the output is not enough: the examiner supplied a
        // pagefile that was not used, and has to be told which one and why.
        let incomplete = attached.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::UnresolvedStructure);
        assert!(incomplete[0].detail.contains("pagefile index 2"));
        assert!(incomplete[0].detail.contains("D-pagefile.sys"));

        // A distinct index alongside a duplicated one still resolves: the
        // refusal is scoped to the ambiguous name, not to the whole attachment.
        let mixed = layer_with(PteSemantics::Windows).with_swap(vec![
            SwapFile {
                index: 1,
                label: "one.sys".to_string(),
                source: Arc::new(ByteSliceDataSource::new(vec![0u8; 0x1000])),
            },
            SwapFile {
                index: 1,
                label: "one-again.sys".to_string(),
                source: Arc::new(ByteSliceDataSource::new(vec![0u8; 0x1000])),
            },
            SwapFile {
                index: 2,
                label: "two.sys".to_string(),
                source: Arc::new(ByteSliceDataSource::new(vec![0x77u8; AT + 0x1000])),
            },
        ]);
        let runs = mixed
            .mapping(0x40_6000, 0x100)
            .expect("index 2 is unambiguous");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].source, BackingSource::Auxiliary(2));
        assert_eq!(mixed.auxiliary_label(2), Some("two.sys"));
    }

    /// The provenance a plugin can actually reach.
    ///
    /// Both facts below live on `VirtualLayer` and every OS-analysis plugin
    /// holds its address spaces as `Arc<dyn MemoryLayer>`. Before
    /// [`MemoryLayer::as_virtual`] there was no route from one to the other, so
    /// `via` was set on every translation and read by nobody, and the
    /// suppression counter was a number no record could carry: a report could
    /// not say that a page was shared rather than private to the process, and an
    /// examiner asking "could this tool have hidden a page from me?" had nothing
    /// to be given.

    #[test]
    fn translation_provenance_is_reachable_through_a_layer_trait_object() {
        const PROTO_VA: u64 = 0xFFFF_8000_0000_0008;
        let mut bytes = image();
        put64(
            &mut bytes,
            PT,
            1,
            (((PROTO_VA as i64) << WINDOWS_X64_PROTO_ADDRESS_SHIFT) as u64) | WINDOWS_PROTOTYPE_BIT,
        );
        put64(&mut bytes, PML4, 256, 0x1_0000 | PRESENT_BIT);
        put64(&mut bytes, 0x1_0000, 0, 0x1_1000 | PRESENT_BIT);
        put64(&mut bytes, 0x1_1000, 0, 0x1_2000 | PRESENT_BIT);
        put64(&mut bytes, 0x1_2000, 0, 0x1_3000 | PRESENT_BIT);
        put64(&mut bytes, 0x1_3000, 1, 0x1_4000 | PRESENT_BIT);
        bytes[0x1_4000..0x1_5000].fill(0x77);
        // A page-sized table of one repeated present entry, for the heuristic.
        for index in 0..512u64 {
            put64(&mut bytes, 0x2_0000, index, 0x9000 | PRESENT_BIT);
        }
        put64(&mut bytes, PD, 3, 0x2_0000 | PRESENT_BIT);

        let space: Arc<dyn MemoryLayer> = Arc::new(
            VirtualLayer::new(
                physical_from(bytes),
                PML4,
                PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
                    .with_win8_pagefile_layout(false),
            )
            .unwrap(),
        );

        let virt = space
            .as_virtual()
            .expect("a translating layer must own up to being one");

        // 1. Shared versus private, per page, from the trait object.
        let shared = virt.translate(0x40_1000).expect("through the section");
        assert!(shared.via.is_shared());
        assert_eq!(shared.via.as_str(), "prototype_pte");
        let private = virt.translate(0x40_2000).expect("through the tables");
        assert!(!private.via.is_shared());
        assert_eq!(private.via.as_str(), "page_tables");

        // 1b. And the same fact survives into the run list, which is what a
        //     physical-backing view attributes to this process. Until this was
        //     carried, `via` had no consumer outside these asserts, so a page
        //     of a mapped file was presented as the process's own bytes.
        let shared_runs = space.mapping(0x40_1000, 0x1000).expect("a mapped page");
        assert_eq!(shared_runs.len(), 1);
        assert_eq!(shared_runs[0].via, Some("prototype_pte"));
        let private_runs = space.mapping(0x40_2000, 0x1000).expect("a mapped page");
        assert_eq!(private_runs.len(), 1);
        assert_eq!(private_runs[0].via, Some("page_tables"));

        // 2. The suppression count, from the same trait object, for a record to
        //    carry. Zero before the heuristic fires, and a number afterwards.
        assert_eq!(virt.uniform_tables_suppressed(), 0);
        assert!(space.mapping(0x60_0000, 0x1000).is_err());
        assert_eq!(virt.uniform_tables_suppressed(), 1);

        // A layer that performs no translation says so rather than pretending
        // to a provenance it cannot have: the caller's address is already
        // physical there, and nothing about it is shared or suppressed.
        let physical = physical_from(vec![0u8; 0x2000]);
        assert!(physical.as_virtual().is_none());
    }

    /// The projection names the pagefile rather than reporting a hole.
    ///
    /// Before `PhysicalExtent` carried a source label this method had only two
    /// options for a swapped page, and both were wrong in different ways:
    /// report the pagefile offset as a `device_offset`, which sends an examiner
    /// to that offset in the *memory image* and hands them unrelated bytes; or
    /// report no location at all, which understates what was actually
    /// recovered. It chose the second. This asserts the third option now exists.
    /// Attaching something that is not a Linux swap area is a finding under
    /// Linux semantics, and is the normal case under Windows semantics.
    ///
    /// `with_swap` serves both tiers from one function: a Windows pagefile
    /// carries no `SWAPSPACE2` signature and is *supposed* to leave
    /// `swap_linux` as `None`. So the absence of a swap header cannot be a
    /// defect in itself, and an incompleteness raised on the file alone would
    /// appear on every Windows analysis that correctly attached a pagefile.
    ///
    /// Under `PteSemantics::Linux` the same absence means something else
    /// entirely: an attachment no `swp_entry_t` can ever be answered from, so
    /// every page naming its index stays a hole for a reason the operator can
    /// still fix. The ledger has to say so while they can still act on it.
    #[test]
    fn an_attachment_that_is_not_a_swap_area_is_a_finding_only_under_linux_semantics() {
        let not_a_swap_area: Arc<dyn DataSource> =
            Arc::new(ByteSliceDataSource::new(vec![0x7Fu8; 0x2000]));
        let attach = |semantics| {
            layer_with(semantics).with_swap(vec![SwapFile {
                index: 0,
                label: "definitely-not-swap.bin".to_string(),
                source: Arc::clone(&not_a_swap_area),
            }])
        };

        let linux = attach(PteSemantics::Linux);
        let noted: Vec<&str> = linux
            .layer_meta()
            .incomplete()
            .iter()
            .map(|i| i.detail.as_str())
            .filter(|d| d.contains("definitely-not-swap.bin"))
            .collect();
        assert_eq!(
            noted.len(),
            1,
            "under Linux semantics an attachment with no swap header must be on the \
             record exactly once: {:?}",
            linux.layer_meta().incomplete()
        );
        assert!(
            noted[0].contains("no Linux swap header was read from it"),
            "the note has to say what was looked for and not found: {:?}",
            noted[0]
        );

        let windows = attach(PteSemantics::Windows);
        assert!(
            windows
                .layer_meta()
                .incomplete()
                .iter()
                .all(|i| !i.detail.contains("definitely-not-swap.bin")),
            "a Windows pagefile has no SWAPSPACE2 signature by design; flagging it \
             would put a finding on every correct Windows attachment: {:?}",
            windows.layer_meta().incomplete()
        );
    }

    #[test]
    fn a_swapped_page_is_projected_into_the_pagefile_that_holds_it() {
        const AT: usize = 0x33 << 12;
        let bytes = vec![0u8; AT + 0x1000];
        let pagefile: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));

        let attached = layer_with(PteSemantics::Windows).with_swap(vec![SwapFile {
            index: 2,
            label: "pagefile.sys".to_string(),
            source: Arc::clone(&pagefile),
        }]);

        let map = attached.physical_map(0x40_6000, 0x100);
        assert_eq!(map.extents.len(), 1, "one swapped page, one extent");

        let extent = map.extents[0];
        assert!(
            extent.is_auxiliary(),
            "the page has bytes in a named file; it is not a hole"
        );
        assert_eq!(
            extent.device_offset,
            Some(AT as u64),
            "the offset is the page's real location IN THE PAGEFILE"
        );
        assert_eq!(extent.length, 0x100);
        let ExtentSource::Auxiliary(index) = extent.source else {
            panic!("a swapped page must name an auxiliary source");
        };
        assert_eq!(
            map.auxiliary_sources
                .get(index as usize)
                .map(String::as_str),
            Some("pagefile.sys"),
            "the index must resolve to the file an examiner can go and read"
        );

        // Part-way into the page, the projected offset advances with the
        // virtual address -- the same alignment bug the read path guards.
        let mid = attached.physical_map(0x40_6000 + 0x40, 0x10);
        assert_eq!(mid.extents[0].device_offset, Some(AT as u64 + 0x40));
    }

    #[test]
    fn a_shared_page_behind_a_prototype_pte_reads_through_the_layer() {
        // End to end, over the same primitives every plugin uses: the process's
        // page tables stop at a prototype PTE, the walk follows it into the
        // section's prototype array in kernel space, and an ordinary `read_at`
        // returns the page that was resident all along.
        //
        // Before prototype PTEs were followed this read was a hole, which is
        // how a DLL's code, a mapped data file and any shared section went
        // missing from a process's address space while the tool reported no
        // problem.
        const PROTO_VA: u64 = 0xFFFF_8000_0000_0008;
        let mut bytes = image();
        put64(
            &mut bytes,
            PT,
            1,
            (((PROTO_VA as i64) << WINDOWS_X64_PROTO_ADDRESS_SHIFT) as u64) | WINDOWS_PROTOTYPE_BIT,
        );
        // Kernel-space tables reaching the prototype array. PML4 index 256 is
        // the first index of the upper canonical half.
        put64(&mut bytes, PML4, 256, 0x1_0000 | PRESENT_BIT);
        put64(&mut bytes, 0x1_0000, 0, 0x1_1000 | PRESENT_BIT);
        put64(&mut bytes, 0x1_1000, 0, 0x1_2000 | PRESENT_BIT);
        put64(&mut bytes, 0x1_2000, 0, 0x1_3000 | PRESENT_BIT);
        // The prototype `_MMPTE` at PROTO_VA (physical 0x13008), naming a
        // resident frame.
        put64(&mut bytes, 0x1_3000, 1, 0x1_4000 | PRESENT_BIT);
        bytes[0x1_4000..0x1_5000].fill(0x77);

        let l = VirtualLayer::new(
            physical_from(bytes),
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
                .with_win8_pagefile_layout(false),
        )
        .unwrap();

        let mut page = vec![0u8; 0x1000];
        assert_eq!(l.read_at(0x40_1000, &mut page).unwrap(), 0x1000);
        assert!(
            page.iter().all(|&b| b == 0x77),
            "the section's page, not a hole"
        );
        assert!(l.is_valid(0x40_1000, 0x1000));

        let t = l
            .translate(0x40_1000)
            .expect("resolved through the section");
        assert_eq!(t.phys, 0x1_4000);
        assert!(
            t.via.is_shared(),
            "the layer records that these bytes are shared, so 'this process \
             wrote them' is not a claim the translation supports"
        );

        // And the boundary of that claim, pinned: the 5-tuple `mapping`
        // returns has no field for provenance, so the shared/private
        // distinction now rides on the run as well as on `translate`, so a
        // process-memory dump or a scan report can attribute the bytes without
        // walking every page again — and cannot infer "private" from a
        // successful read, which is what it did while `via` had no consumer.
        let runs = l.mapping(0x40_1000, 0x1000).expect("the page is backed");
        assert_eq!(
            runs,
            vec![MappedRange::identity(0x40_1000, 0x1000, 0x1_4000).reached_via("prototype_pte")]
        );

        // And a bare walker, which has no notion of a prototype PTE, still
        // reports the page as absent rather than inventing a section object.
        let bare = layer();
        assert_eq!(
            bare.mapping(0x40_1000, 0x10).unwrap()[0].mapped_offset,
            0x5000,
            "the bare fixture is unchanged"
        );
    }

    #[test]
    fn a_prototype_pte_that_cannot_be_followed_is_a_hole_and_never_zeros() {
        // The other half of following prototype PTEs: when the section's array
        // is not reachable, the page's state is unknown, and unknown must not
        // read as a page of zeros. A wiped page and a page whose section object
        // we could not reach are opposite findings.
        const PROTO_VA: u64 = 0xFFFF_8000_0000_0008;
        let mut bytes = image();
        put64(
            &mut bytes,
            PT,
            1,
            (((PROTO_VA as i64) << WINDOWS_X64_PROTO_ADDRESS_SHIFT) as u64) | WINDOWS_PROTOTYPE_BIT,
        );
        // No kernel-space tables: nothing maps the prototype array.
        let l = VirtualLayer::new(
            physical_from(bytes),
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
                .with_win8_pagefile_layout(false),
        )
        .unwrap();

        let mut page = vec![0x11u8; 0x1000];
        let err = l
            .read_at(0x40_1000, &mut page)
            .expect_err("a page whose section object cannot be reached has no bytes");
        let hole = MemoryHole::from_io(&err).expect("reported as a hole in the address space");
        assert_eq!(hole.address, 0x40_1000);
        assert_eq!(hole.reason, HoleReason::NotPresent);
        assert!(
            page.iter().all(|&b| b == 0x11),
            "the buffer is left alone: nothing was fabricated into it"
        );
        assert!(!l.is_valid(0x40_1000, 0x1000));

        // And the finer fact — which array, and why the chain stopped — survives
        // on the typed error rather than being flattened into "absent".
        match l.translate(0x40_1000).unwrap_err() {
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
    fn a_non_canonical_address_is_out_of_range_rather_than_a_hole() {
        let l = layer();
        let err = l
            .mapping(0x0000_8000_0000_0000, 0x10)
            .expect_err("no such address exists");
        assert!(
            err.hole().is_none(),
            "a hole would imply the address exists"
        );
        assert!(matches!(err, LayerError::OutOfRange { .. }));
        // A read of it is an error too, not a silent zero-length answer.
        let mut buf = [0u8; 8];
        assert!(l.read_at(0x0000_8000_0000_0000, &mut buf).is_err());
    }

    #[test]
    fn a_read_above_a_thirty_two_bit_space_is_end_of_space_not_an_error() {
        let mut bytes = vec![0u8; IMAGE_SIZE];
        // 32-bit paging: the table at PML4 is the page directory, and index 1
        // covers virtual 0x0040_0000 with a 4 MiB page at physical zero.
        let entry = (LARGE_PAGE_BIT | PRESENT_BIT) as u32;
        bytes[(PML4 + 4) as usize..(PML4 + 8) as usize].copy_from_slice(&entry.to_le_bytes());
        bytes[0..0x1000].fill(0xEE);
        let l = VirtualLayer::new(
            physical_from(bytes),
            PML4,
            PagingSpec::new(PagingMode::Intel32, PteSemantics::Bare),
        )
        .unwrap();

        assert_eq!(l.max_address(), 0xFFFF_FFFF);
        assert_eq!(l.size(), 0x1_0000_0000);
        let mut buf = [0u8; 16];
        assert_eq!(l.read_at(0x0040_0000, &mut buf).unwrap(), 16);
        assert!(buf.iter().all(|&b| b == 0xEE));
        // Past the top of the space is end-of-space, never a hole.
        assert_eq!(l.read_at(0x1_0000_0000, &mut buf).unwrap(), 0);
        assert!(matches!(
            l.mapping(0x1_0000_0000, 16),
            Err(LayerError::OutOfRange { .. })
        ));
        // A 4 MiB page is one run, not 1024.
        let runs = l.mapping(0x0040_0000, 0x10_0000).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].mapped_offset, 0);
    }

    #[test]
    fn a_large_page_is_one_run_and_reads_across_its_whole_extent() {
        let mut bytes = vec![0u8; IMAGE_SIZE];
        put64(&mut bytes, PML4, 0, PDPT | PRESENT_BIT);
        put64(&mut bytes, PDPT, 0, PD | PRESENT_BIT);
        // A 2 MiB page at physical 0x20_0000, which the acquisition holds...
        put64(&mut bytes, PD, 0, 0x20_0000 | LARGE_PAGE_BIT | PRESENT_BIT);
        // ...and a second one at 0x60_0000, which is past the end of it.
        put64(&mut bytes, PD, 1, 0x60_0000 | LARGE_PAGE_BIT | PRESENT_BIT);
        bytes[0x20_0000..0x40_0000].fill(0x5A);
        let l = VirtualLayer::new(
            physical_from(bytes),
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare),
        )
        .unwrap();

        let runs = l.mapping(0x1000, 0x4000).expect("inside the large page");
        assert_eq!(runs.len(), 1, "a large page does not fragment");
        assert_eq!(
            runs[0],
            MappedRange::identity(0x1000, 0x4000, 0x20_1000).reached_via("page_tables")
        );
        let mut buf = vec![0u8; 0x4000];
        assert_eq!(l.read_at(0x1000, &mut buf).unwrap(), 0x4000);
        assert!(buf.iter().all(|&b| b == 0x5A));

        // A large page the acquisition never captured is a hole, not zeros.
        assert!(l
            .mapping(0x20_0000, 0x4000)
            .unwrap_err()
            .hole()
            .is_some_and(|h| h.reason == HoleReason::Unmapped));
    }

    #[test]
    fn a_uniform_page_table_is_suppressed_visibly_and_counted() {
        let mut bytes = image();
        for index in 0..512u64 {
            put64(&mut bytes, PT, index, 0x9000 | PRESENT_BIT);
        }
        // Windows semantics: the heuristic is a Windows convention and is
        // inert outside it (see `walk.rs`).
        let l = VirtualLayer::new(
            physical_from(bytes.clone()),
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows),
        )
        .unwrap();
        let hole = l
            .mapping(0x40_1000, 0x100)
            .unwrap_err()
            .hole()
            .expect("a suppressed table is still a hole");
        assert_eq!(hole.reason, HoleReason::TableSuppressed);
        assert_eq!(
            hole.length,
            (1 << 21) - 0x1000,
            "the whole 2 MiB it covered"
        );
        assert_eq!(l.uniform_tables_suppressed(), 1);

        // With the policy off, nothing is hidden and nothing is counted.
        let honest = VirtualLayer::with_cache(
            physical_from(bytes),
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows),
            TranslationPolicy {
                suppress_uniform_tables: false,
            },
            Arc::new(TableCache::new()),
        )
        .unwrap();
        assert_eq!(honest.translate(0x40_1000).unwrap().phys, 0x9000);
        assert_eq!(honest.uniform_tables_suppressed(), 0);
    }

    #[test]
    fn the_suppression_counter_counts_refusals_and_not_distinct_tables() {
        // Pinned because the number is quoted to examiners and the two readings
        // are different claims. One table is suppressed here; three addresses
        // behind it are refused, and the counter reads three. Anything that
        // reports this as "three page tables were hidden" is overstating what
        // the tool knows by a factor it cannot bound.
        let mut bytes = image();
        for index in 0..512u64 {
            put64(&mut bytes, PT, index, 0x9000 | PRESENT_BIT);
        }
        let l = VirtualLayer::new(
            physical_from(bytes),
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows),
        )
        .unwrap();

        for va in [0x40_1000u64, 0x40_2000, 0x40_1000] {
            assert!(l.translate(va).is_err(), "the table is suppressed");
        }
        assert_eq!(
            l.uniform_tables_suppressed(),
            3,
            "one table, three refused translations"
        );
    }

    #[test]
    fn a_directory_table_base_that_names_no_table_is_refused() {
        let physical = physical_from(image());
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert!(matches!(
            VirtualLayer::new(physical.clone(), 0, spec),
            Err(TranslateError::InvalidDtb { .. })
        ));
        // Low control-register flags with no table address behind them.
        assert!(matches!(
            VirtualLayer::new(physical, 0x18, spec),
            Err(TranslateError::InvalidDtb { .. })
        ));
    }

    /// A layer that projects whole frames, as one over a compressed
    /// acquisition must: its runs begin at a frame boundary and run a full
    /// frame, whatever was asked for.
    #[derive(Debug)]
    struct FramedPhysical {
        inner: Arc<dyn MemoryLayer>,
        frame: u64,
    }

    impl DataSource for FramedPhysical {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.as_data_source().read_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.inner.as_data_source().size()
        }
    }

    impl MemoryLayer for FramedPhysical {
        fn min_address(&self) -> u64 {
            self.inner.min_address()
        }
        fn max_address(&self) -> u64 {
            self.inner.max_address()
        }
        fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
            if length == 0 {
                return Ok(Vec::new());
            }
            if offset > self.max_address() {
                return Err(LayerError::OutOfRange {
                    address: offset,
                    max_address: self.max_address(),
                });
            }
            let end = offset.saturating_add(length);
            let mut runs = Vec::new();
            let mut at = offset - (offset % self.frame);
            while at < end {
                if at > self.max_address() {
                    break;
                }
                runs.push(MappedRange::identity(at, self.frame, at));
                at += self.frame;
            }
            Ok(runs)
        }
        fn layer_meta(&self) -> &crate::meta::LayerMeta {
            self.inner.layer_meta()
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    /// **The regression.** A page the evidence fully holds reads through the
    /// page tables even when the layer beneath describes it with a run wider
    /// than the request.
    ///
    /// A compressed acquisition has no choice about that: an encoded run names
    /// the whole frame it decodes from, because one clipped to a sub-range
    /// would claim to decode to a different length. `require_acquired` used to
    /// ask whether the run lengths summed to the request, which for a 64-byte
    /// read inside a 64 KiB frame answered 65,536, refused the page, and
    /// reported a hole 64 KiB past the address wanted. Every Linux discovery
    /// against a Snappy-compressed AVML capture failed on it, at the final
    /// read-back of `linux_banner` through the tables it had just proved.
    ///
    /// Driven through `read_at` rather than through the coverage helper, so it
    /// fails if the arithmetic is right and the wiring is not.
    #[test]
    fn a_page_reads_through_tables_over_a_layer_that_projects_whole_frames() {
        // Virtual 0x401000 maps to physical 0x5000 in this fixture.
        let mut bytes = image();
        bytes[0x5000..0x5010].copy_from_slice(b"banner-goes-here");

        let framed: Arc<dyn MemoryLayer> = Arc::new(FramedPhysical {
            inner: physical_from(bytes),
            frame: 0x1_0000,
        });
        let l = VirtualLayer::new(
            framed,
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare),
        )
        .expect("tables are valid");

        let mut buf = [0u8; 16];
        let read = l
            .read_at(0x40_1000, &mut buf)
            .expect("the frame is wholly present, so this is not a hole");
        assert_eq!(read, 16);
        assert_eq!(&buf, b"banner-goes-here");

        assert!(
            l.is_valid(0x40_1000, 16),
            "a 16-byte request inside a present frame must validate"
        );
    }

    /// The same layer shape must still report a genuinely absent frame.
    ///
    /// Otherwise the fix would have bought correctness on the present case by
    /// giving up the detection that makes a hole a hole.
    #[test]
    fn a_frame_beyond_the_acquisition_is_still_a_hole_through_whole_frame_runs() {
        let framed: Arc<dyn MemoryLayer> = Arc::new(FramedPhysical {
            inner: physical_from(image()),
            frame: 0x1_0000,
        });
        let l = VirtualLayer::new(
            framed,
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare),
        )
        .expect("tables are valid");

        // Virtual 0x407000 translates to physical 0x100_0000, past the end of
        // the acquisition: the tables map it, the evidence does not hold it.
        let mut buf = [0u8; 16];
        let err = l
            .read_at(0x40_7000, &mut buf)
            .expect_err("nothing backs this address");
        assert!(
            MemoryHole::from_io(&err).is_some() || err.kind() == io::ErrorKind::InvalidData,
            "an unbacked address must report as a hole, got {err:?}"
        );
        assert!(!l.is_valid(0x40_7000, 16));
    }

    #[test]
    fn a_zero_length_mapping_is_an_empty_run_list() {
        let l = layer();
        assert!(l.mapping(0x40_1000, 0).unwrap().is_empty());
        assert_eq!(l.read_at(0x40_1000, &mut []).unwrap(), 0);
    }

    #[test]
    fn a_mapping_is_clipped_at_the_top_of_the_space_rather_than_extended() {
        let mut bytes = vec![0u8; IMAGE_SIZE];
        let entry = (LARGE_PAGE_BIT | PRESENT_BIT) as u32;
        // The last 4 MiB of the 32-bit space: page-directory index 1023.
        let at = (PML4 + 1023 * 4) as usize;
        bytes[at..at + 4].copy_from_slice(&entry.to_le_bytes());
        let l = VirtualLayer::new(
            physical_from(bytes),
            PML4,
            PagingSpec::new(PagingMode::Intel32, PteSemantics::Bare),
        )
        .unwrap();
        let runs = l.mapping(0xFFFF_F000, 0x8000).expect("starts in range");
        assert_eq!(covered_len(&runs), 0x1000, "clipped, not extended");
        assert!(!l.is_valid(0xFFFF_F000, 0x8000));
    }

    #[test]
    fn metadata_records_the_claim_this_address_space_rests_on() {
        let physical: Arc<dyn MemoryLayer> = Arc::new(
            PhysicalLayer::new(
                Arc::new(ByteSliceDataSource::new(image())),
                LayerMeta::new(crate::format::MemoryImageFormat::WindowsCrashDump64)
                    .with_architecture(Architecture::X64),
            )
            .unwrap(),
        );
        let l = VirtualLayer::new(
            physical,
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
                .with_win8_pagefile_layout(false),
        )
        .unwrap();

        let meta = l.layer_meta();
        // Identity does not inherit: a virtual space is not a crash dump.
        assert_eq!(meta.format(), None);
        // Discovered facts do.
        assert_eq!(meta.architecture(), Some(Architecture::X64));
        assert_eq!(meta.chain_depth(), 2);
        let json = meta.to_json();
        assert_eq!(json["notes"]["paging_mode"], "intel32e");
        assert_eq!(json["notes"]["pte_semantics"], "windows");
        assert_eq!(json["notes"]["directory_table_base"], PML4);
        assert_eq!(json["notes"]["max_phys_addr_bits"], 45);
        assert_eq!(json["notes"]["suppress_uniform_tables"], true);
    }

    #[test]
    fn a_virtual_address_projects_onto_the_acquisition_file() {
        // "Which offset in the evidence file holds this process's page?" — the
        // existing API answers it, through the page tables and then through the
        // container windows below, with no memory-specific plumbing.
        // The memory image sits at offset 0x20_0000 inside the device image, so
        // a frame at physical 0x5000 is at device offset 0x20_5000.
        let mut device_bytes = vec![0u8; 0x80_0000];
        device_bytes[0x20_0000..0x20_0000 + IMAGE_SIZE].copy_from_slice(&image());
        let device: Arc<dyn DataSource> = Arc::new(DeviceImageSource::new(Arc::new(
            ByteSliceDataSource::new(device_bytes),
        )));
        let window: Arc<dyn DataSource> =
            Arc::new(WindowSource::new(device, 0x20_0000, IMAGE_SIZE as u64));
        let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(window).unwrap());
        let l = VirtualLayer::new(
            physical,
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare),
        )
        .unwrap();

        let map = l.physical_map(0x40_1400, 0x200);
        assert_eq!(map.precision, ExtentPrecision::Exact);
        assert_eq!(map.extents.len(), 1);
        assert_eq!(map.extents[0].device_offset, Some(0x20_5400));
        assert_eq!(map.extents[0].length, 0x200);

        // An absent page has no device backing, and says so rather than
        // pointing somewhere plausible.
        let map = l.physical_map(0x40_4000, 0x200);
        assert_eq!(map.precision, ExtentPrecision::Synthetic);
        assert_eq!(map.extents[0].device_offset, None);
        assert_eq!(map.located_len(), 0, "a hole is located nowhere");
        assert_eq!(
            map.total_len(),
            0x200,
            "but it keeps its place in the logical order"
        );
    }

    #[test]
    fn an_address_that_does_not_exist_gets_no_extent_at_all() {
        // The defect this guards: every untranslatable outcome was rendered as
        // one synthetic extent spanning the rest of the request. A
        // non-canonical address is not a hole in a process's memory — it is an
        // address no processor could issue — and describing a region of the
        // address space for it asserts a shape that was never established.
        let l = layer();
        let map = l.physical_map(0x0000_8000_0000_0000, 0x1000);
        assert!(
            map.extents.is_empty(),
            "nothing is claimed about an address that does not exist: {:?}",
            map.extents
        );
        assert_eq!(
            map.total_len(),
            0,
            "a short projection is how the caller learns the request was not answered"
        );
    }

    #[test]
    fn a_projection_stops_where_the_page_tables_themselves_cannot_be_read() {
        // "The page tables could not be read out of this evidence" is not
        // "these bytes are reconstructed content". The projection stops rather
        // than covering the rest of the request with a synthetic extent that a
        // consumer ignoring precision would read as the shape of the process's
        // memory.
        let l = VirtualLayer::new(
            physical_from(image()),
            // A directory table base past the end of the acquisition: the top
            // table cannot be read, and an EOF is not a hole.
            0x10_0000_0000,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare),
        )
        .unwrap();
        assert_eq!(
            l.translate(0x40_1000)
                .expect_err("the table is not there")
                .hole_reason(),
            None,
            "the premise of this test: an unreadable table is not a hole"
        );
        let map = l.physical_map(0x40_1000, 0x1000);
        assert!(map.extents.is_empty(), "{:?}", map.extents);
        assert_eq!(map.total_len(), 0);
    }

    /// With **no pagefile attached**, a swapped page stays a hole.
    ///
    /// Renamed when `PhysicalExtent` gained a source label: the old name said a
    /// swapped page is never a location, which is no longer true — with the
    /// right pagefile attached it is projected into that file, see
    /// `a_swapped_page_is_projected_into_the_pagefile_that_holds_it`. What
    /// remains true, and is what this test pins, is that a page whose bytes we
    /// do not have is not given a location on the strength of a guess.
    #[test]
    fn a_swapped_page_with_no_pagefile_attached_is_a_hole_and_not_a_location() {
        // A hole must contribute an unlocated extent — never a device offset,
        // and never a silent skip that would slide the extents after it into
        // the wrong place.
        let windows = layer_with(PteSemantics::Windows);
        let map = windows.physical_map(0x40_6000, 0x200);
        assert_eq!(map.located_len(), 0);
        assert_eq!(map.total_len(), 0x200);
        assert_eq!(map.extents[0].device_offset, None);
        assert!(
            map.extents.iter().all(|e| !e.is_auxiliary()),
            "with no pagefile attached nothing may claim an auxiliary source"
        );
        assert!(
            map.auxiliary_sources.is_empty(),
            "no file was read, so none may be named"
        );

        // The reason is not expressible in a `PhysicalMap`, and is not guessed
        // at: the typed walk states it exactly.
        assert_eq!(
            windows
                .mapping(0x40_6000, 0x200)
                .unwrap_err()
                .hole()
                .map(|h| h.reason),
            Some(HoleReason::SwappedOut)
        );
    }

    #[test]
    fn the_pagefile_beside_the_image_stays_reachable() {
        let mut siblings = HashMap::new();
        let pagefile: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![1, 2, 3]));
        siblings.insert(".pagefile".to_string(), pagefile);
        let bundled: Arc<dyn DataSource> = Arc::new(SiblingBundleSource::new(
            Arc::new(ByteSliceDataSource::new(image())),
            siblings,
        ));
        let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(bundled).unwrap());
        let l = VirtualLayer::new(
            physical,
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
                .with_win8_pagefile_layout(false),
        )
        .unwrap();
        assert!(l.open_sibling(".pagefile").is_some());
        assert!(l.open_sibling(".missing").is_none());
        assert!(l.get_underlying_path().is_none());
    }

    #[test]
    fn address_spaces_share_one_bounded_entry_memo() {
        // Two processes over the same physical memory. Their tables differ;
        // the memo is keyed by physical address, so sharing it is correct and
        // is what keeps four hundred address spaces to one cache.
        let mut bytes = image();
        // A second hierarchy rooted at 0xB000, sharing the page directory.
        put64(&mut bytes, 0xB000, 0, PDPT | PRESENT_BIT);
        let physical = physical_from(bytes);
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        let cache = Arc::new(TableCache::new());
        let first = VirtualLayer::with_cache(
            physical.clone(),
            PML4,
            spec,
            TranslationPolicy::default(),
            Arc::clone(&cache),
        )
        .unwrap();
        let second = VirtualLayer::with_cache(
            physical,
            0xB000,
            spec,
            TranslationPolicy::default(),
            Arc::clone(&cache),
        )
        .unwrap();

        assert_eq!(first.translate(0x40_1000).unwrap().phys, 0x5000);
        assert_eq!(second.translate(0x40_1000).unwrap().phys, 0x5000);
        assert!(Arc::ptr_eq(first.table_cache(), second.table_cache()));
        assert!(!cache.is_empty());
    }

    #[test]
    fn the_layer_is_usable_as_a_memory_layer_trait_object() {
        let l: Arc<dyn MemoryLayer> = Arc::new(layer());
        assert_eq!(l.min_address(), 0);
        assert!(l.is_valid(0x40_1000, 0x1000));
        let mut buf = [0u8; 4];
        assert_eq!(l.as_data_source().read_at(0x40_1000, &mut buf).unwrap(), 4);
        assert_eq!(buf, [0xAA; 4]);
    }

    #[test]
    fn accessors_report_what_the_layer_was_built_from() {
        let l = layer();
        assert_eq!(l.dtb(), PML4);
        assert_eq!(l.spec().mode(), PagingMode::Intel32e);
        assert!(l.policy().suppress_uniform_tables);
        assert_eq!(l.physical().max_address(), (IMAGE_SIZE - 1) as u64);
    }
}
