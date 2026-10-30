//! [`ReverseMap`]: which address spaces map a given **physical** offset, and
//! at what virtual address in each.
//!
//! # The question this answers
//!
//! An examiner runs `strings -t d` over a raw memory image and gets a list of
//! byte offsets into the file. Each offset is a physical address, and on its own
//! it says nothing: "the machine held this text somewhere". The finding is
//! *whose* memory it was in — and that is a question about every process's page
//! tables at once, not about any one of them.
//!
//! So each declared address space is enumerated downward (see
//! [`crate::translate::enumerate`]) and every mapping that covers a wanted
//! frame is recorded against that frame. Asking about an offset then names
//! every space that reaches it, each with the virtual address it has *there*.
//!
//! # Two processes mapping one frame must name both
//!
//! That is the criterion this route is graded against, and it is structural
//! rather than tested-for: [`Attribution::owners`] is a list, there is no
//! `owner()` accessor anywhere that could return the first one, and
//! [`Attribution::owners_total`] is counted separately from the list so that a
//! cap on how many are *listed* never touches how many are *reported*.
//!
//! # What a negative answer is allowed to mean
//!
//! Upstream prints `FREE MEMORY` for an offset it found no owner for. This will
//! not: [`Verdict::NoMappingAndEverySpaceAssessed`] can be constructed only
//! where every declared space was enumerated whole, and even then it says only
//! what it means — no page table walked here reaches this frame. It is not a
//! statement that the frame is free, because the free and standby lists are the
//! PFN database's business and nothing here reads it, and a frame on the free
//! list still holds the last bytes written to it. Where any space fell short the
//! verdict is [`Verdict::NotAssessed`], with [`Attribution::not_assessed_in`]
//! naming each space and why.
//!
//! # The physical side and the virtual side are never the same column
//!
//! Upstream's own strings plugin renders a virtual address for kernel rows and
//! a physical one for process rows in one column, because its two branches
//! unpack the same tuple in different orders. Here the physical offset is on
//! [`Attribution`] and the virtual address is on [`Owner`], one level down,
//! and there is no field on either that could hold the other.

use std::cell::OnceCell;
use std::collections::HashMap;

use seance_core::io::IncompleteReason;

use crate::translate::enumerate::{Blindness, EnumerateOutcome, MappingRun, MappingSink, SinkFlow};
use crate::translate::spec::{PagingSpec, PAGE_OFFSET_BITS};
use crate::translate::RunVia;

/// Owners listed for one frame before the list is cut.
///
/// A frame mapped by sixty-four address spaces is `KUSER_SHARED_DATA` or a
/// system DLL's text, and the sixty-fifth row does not make it more
/// informative. The *count* is never cut — see [`Attribution::owners_total`] —
/// so this loses virtual addresses and never the fact of who maps it.
pub const MAX_OWNERS_LISTED: usize = 64;

/// The size of the frame this index is keyed on.
///
/// 4 KiB, because that is the granularity every paging mode shares. A mapping
/// reached through a 2 MiB or 1 GiB entry covers many of these keys, and the
/// owner it produces carries its own [`Owner::page_bytes`] — printing a frame
/// without that number beside it understates what the owner maps.
pub const FRAME_BYTES: u64 = 1 << PAGE_OFFSET_BITS;

/// The frames a caller wants attributed.
///
/// Mandatory rather than optional. Indexing every mapping of every process is
/// tens of millions of rows for an answer about a few thousand offsets, and a
/// caller that genuinely wants the whole image can say so by passing every
/// frame in it — which is then a decision on the record rather than a default
/// nobody chose.
#[derive(Debug, Clone, Default)]
pub struct FrameSet {
    /// Frame numbers, sorted and deduplicated.
    frames: Vec<u64>,
}

impl FrameSet {
    /// The frames the given physical byte offsets fall in.
    pub fn from_offsets(offsets: impl IntoIterator<Item = u64>) -> Self {
        let mut frames: Vec<u64> = offsets
            .into_iter()
            .map(|offset| offset >> PAGE_OFFSET_BITS)
            .collect();
        frames.sort_unstable();
        frames.dedup();
        Self { frames }
    }

    /// Every 4 KiB frame of an image `bytes` long.
    pub fn whole_image(bytes: u64) -> Self {
        let count = bytes.div_ceil(FRAME_BYTES);
        Self {
            frames: (0..count).collect(),
        }
    }

    /// How many distinct frames are wanted.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether no frame is wanted, in which case nothing will be indexed.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Whether `frame` is wanted.
    pub fn contains(&self, frame: u64) -> bool {
        self.frames.binary_search(&frame).is_ok()
    }

    /// The wanted frames inside `[first, last]`, inclusive at both ends.
    fn between(&self, first: u64, last: u64) -> &[u64] {
        if last < first {
            return &[];
        }
        let start = self.frames.partition_point(|&frame| frame < first);
        let end = self.frames.partition_point(|&frame| frame <= last);
        &self.frames[start..end]
    }
}

/// One address space in the map, and what its enumeration cost.
#[derive(Debug, Clone)]
pub struct Space {
    /// How a report names it: `"kernel"`, `"explorer.exe (4312)"`.
    pub label: String,
    /// The directory table base it was walked from, so the answer can be
    /// re-derived by hand.
    pub dtb: u64,
    /// What the enumeration measured, or `None` where the space was declared
    /// and never walked — which is itself a shortfall, not an empty space.
    pub outcome: Option<EnumerateOutcome>,
    /// Top-level indices this space did not walk because another space had
    /// already walked the identical subtree, and which space that was.
    pub shared_from: Vec<(usize, usize)>,
}

impl Space {
    /// Whether everything this space holds was enumerated.
    fn is_complete(&self) -> bool {
        self.outcome
            .as_ref()
            .is_some_and(EnumerateOutcome::is_complete)
    }

    /// Why this space's coverage fell short, or `None` where it did not.
    fn shortfall(&self) -> Option<NotAssessed> {
        let Some(outcome) = self.outcome.as_ref() else {
            return Some(NotAssessed {
                label: self.label.clone(),
                reason: IncompleteReason::UnresolvedStructure,
                detail: "this address space was declared and never walked, so nothing here \
                         states whether it maps the frame"
                    .to_string(),
            });
        };
        if outcome.is_complete() {
            return None;
        }
        let detail = if outcome.root_unreadable {
            "the top-level page table would not read, so the address space was not assessed \
             at all"
                .to_string()
        } else if !outcome.caps_reached.is_empty() {
            let caps: Vec<&str> = outcome
                .caps_reached
                .iter()
                .map(|cap| cap.as_str())
                .collect();
            format!(
                "the walk stopped at a ceiling ({}), so mappings past that point were never \
                 enumerated",
                caps.join(", ")
            )
        } else if outcome.stopped_by_sink {
            "the walk was stopped before it finished".to_string()
        } else {
            format!(
                "{} bytes of this address space were not assessed: {} unreadable table(s), \
                 {} suppressed uniform table(s), {} unresolved prototype PTE(s)",
                outcome.blind_bytes,
                outcome.tables_unreadable,
                outcome.uniform_tables_suppressed,
                outcome.prototypes_unresolved,
            )
        };
        let reason = if outcome.root_unreadable || outcome.tables_unreadable > 0 {
            IncompleteReason::ShortRead
        } else if !outcome.caps_reached.is_empty() {
            IncompleteReason::CapReached
        } else {
            IncompleteReason::UnresolvedStructure
        };
        Some(NotAssessed {
            label: self.label.clone(),
            reason,
            detail,
        })
    }
}

/// One address space that maps a frame, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    /// Which declared space, as [`ReverseMap::space`] resolves it.
    pub space: usize,
    /// The virtual address the requested **byte** has in that space.
    ///
    /// The index is keyed on 4 KiB frames, so what is stored is the frame's
    /// own virtual address and the byte's offset within it is added when the
    /// offset is looked up. That is why one indexed mapping answers every
    /// offset inside its frame without holding a row per byte.
    pub virtual_address: u64,
    /// The first address of the page the byte falls in.
    pub page_virtual_base: u64,
    /// The size of that page: 4 KiB, 2 MiB, 4 MiB or 1 GiB. Printed beside the
    /// frame, because a frame number without it understates a large mapping.
    pub page_bytes: u64,
    /// What named the frame — and in particular whether it was reached through
    /// a section object, which means the page is shared and "this process
    /// wrote these bytes" is not a claim the mapping supports.
    pub via: RunVia,
    /// Whether the virtual address was **enumerated** or inferred.
    ///
    /// `false` where the mapping came from a table the uniform-table heuristic
    /// declined: its 512 byte-identical entries name one frame at 512
    /// addresses, and only the first of those is stated. The frame is a fact;
    /// which of the 512 addresses the examiner wants is not.
    pub virtual_address_enumerated: bool,
    /// Other declared spaces whose own top-level entry was byte-identical here,
    /// so that they reach this same mapping through the same tables without
    /// having been walked through it.
    ///
    /// This is how the kernel's half is reported: one owner, with the spaces
    /// that share it named, rather than one hundred and thirty owners that
    /// would read as one hundred and thirty separate findings.
    pub also_reached_from: Vec<usize>,
}

/// Why one space's coverage was short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAssessed {
    /// The space's label.
    pub label: String,
    /// The vocabulary term for a record.
    pub reason: IncompleteReason,
    /// The sentence a report puts beside it.
    pub detail: String,
}

/// What the map is entitled to say about one physical offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// At least one walked address space maps it, and every declared space was
    /// enumerated whole.
    Mapped,
    /// At least one space maps it, and at least one space's coverage was short
    /// — so the owners named are a floor and not the whole list.
    MappedAndCoverageShort,
    /// No page table this build walked reaches this frame, and every declared
    /// space was enumerated whole.
    ///
    /// The strongest negative available, and it is narrower than it looks: see
    /// [`Verdict::statement`].
    NoMappingAndEverySpaceAssessed,
    /// Nothing is claimed. No space maps it *and* at least one space's coverage
    /// was short, so "no owner" would be a conclusion drawn from silence.
    NotAssessed,
}

impl Verdict {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Mapped => "mapped",
            Verdict::MappedAndCoverageShort => "mapped_coverage_short",
            Verdict::NoMappingAndEverySpaceAssessed => "no_mapping_every_space_assessed",
            Verdict::NotAssessed => "not_assessed",
        }
    }

    /// The sentence a report puts on the row, including what it does *not*
    /// claim.
    pub fn statement(self) -> &'static str {
        match self {
            Verdict::Mapped => {
                "every address space named below has this physical frame mapped, at the virtual \
                 address given for each; every declared address space was enumerated whole, so \
                 this list is complete"
            }
            Verdict::MappedAndCoverageShort => {
                "the address spaces named below have this physical frame mapped. At least one \
                 address space could not be enumerated whole, so this is the list of owners \
                 that were FOUND and not necessarily all of them"
            }
            Verdict::NoMappingAndEverySpaceAssessed => {
                "no page table this build walked reaches this physical frame, and every declared \
                 address space was enumerated whole. That is NOT a finding that the frame is \
                 free or unused: the PFN database was not read, a frame on the free or standby \
                 list still holds the last bytes written to it, and a mapping that existed at \
                 any other instant is not in this image"
            }
            Verdict::NotAssessed => {
                "nothing is claimed about this offset. No walked address space maps it, and at \
                 least one address space could not be enumerated whole -- so \"no owner\" here \
                 would be a conclusion drawn from what could not be looked at"
            }
        }
    }
}

/// What the map is entitled to say about one physical offset, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    /// The offset asked about, verbatim.
    pub physical_offset: u64,
    /// The 4 KiB frame it falls in.
    pub frame: u64,
    /// Every space found to map it, capped at [`MAX_OWNERS_LISTED`].
    pub owners: Vec<Owner>,
    /// How many owners were found, whether or not they are all listed.
    ///
    /// Counted apart from the list precisely so that a cap on the list can
    /// never make this number smaller.
    pub owners_total: u64,
    /// Whether [`Attribution::owners`] was cut.
    pub owners_listed_capped: bool,
    /// What the map is entitled to say.
    pub verdict: Verdict,
    /// Every space whose coverage was short, and why.
    ///
    /// Present whether or not an owner was found: an offset with two owners and
    /// a third space that would not walk has two owners *and* an unassessed
    /// space, and a row that showed only the first would read as a complete
    /// answer.
    pub not_assessed_in: Vec<NotAssessed>,
    /// Whether the offset is past the end of the frames this map was asked to
    /// index, in which case it was never looked up at all.
    pub outside_the_wanted_set: bool,
}

/// The owners of one frame, with the exact count kept apart from the list.
#[derive(Debug, Clone, Default)]
struct FrameOwners {
    listed: Vec<Owner>,
    total: u64,
}

/// A physical-frame index built from one or more address spaces.
///
/// Build it by declaring each space, enumerating into the sink it hands out,
/// and recording what that enumeration measured. Then ask it about offsets.
#[derive(Debug, Clone)]
pub struct ReverseMap {
    spec: PagingSpec,
    wanted: FrameSet,
    spaces: Vec<Space>,
    owners: HashMap<u64, FrameOwners>,
    /// Mappings recorded, whether or not they were listed.
    recorded: u64,
    /// The shortfall list, computed on first use. Cleared by every method that
    /// can change what it would say.
    shortfalls: OnceCell<Vec<NotAssessed>>,
}

impl ReverseMap {
    /// An empty map over `spec`, indexing only the frames in `wanted`.
    pub fn new(spec: PagingSpec, wanted: FrameSet) -> Self {
        Self {
            spec,
            wanted,
            spaces: Vec::new(),
            owners: HashMap::new(),
            recorded: 0,
            shortfalls: OnceCell::new(),
        }
    }

    /// Declare an address space, returning the handle its owners will carry.
    ///
    /// Declared *before* it is walked, deliberately: a space that is declared
    /// and then fails to walk shortens every answer this map gives, and one
    /// that was never declared at all cannot.
    pub fn declare_space(&mut self, label: impl Into<String>, dtb: u64) -> usize {
        // Anything that changes the spaces changes what the shortfall list
        // would say, so the cache cannot outlive it.
        self.shortfalls.take();
        self.spaces.push(Space {
            label: label.into(),
            dtb,
            outcome: None,
            shared_from: Vec::new(),
        });
        self.spaces.len() - 1
    }

    /// The spaces declared, in handle order.
    pub fn spaces(&self) -> &[Space] {
        &self.spaces
    }

    /// One declared space.
    pub fn space(&self, handle: usize) -> Option<&Space> {
        self.spaces.get(handle)
    }

    /// The frames this map was asked to index.
    pub fn wanted(&self) -> &FrameSet {
        &self.wanted
    }

    /// How many mappings were recorded against a wanted frame.
    pub fn recorded(&self) -> u64 {
        self.recorded
    }

    /// How many wanted frames have at least one owner.
    pub fn frames_with_an_owner(&self) -> usize {
        self.owners.len()
    }

    /// Record what one space's enumeration measured.
    ///
    /// Without this the space reads as declared-and-never-walked, which is a
    /// shortfall on every answer — so forgetting it makes the map more
    /// cautious rather than less.
    pub fn record_outcome(&mut self, space: usize, outcome: EnumerateOutcome) {
        // Anything that changes the spaces changes what the shortfall list
        // would say, so the cache cannot outlive it.
        self.shortfalls.take();
        if let Some(slot) = self.spaces.get_mut(space) {
            slot.outcome = Some(outcome);
        }
    }

    /// Record the directory table base a declared space turned out to have.
    ///
    /// For a caller that must declare the space *before* it can read the base
    /// — because a space that is declared and never walked shortens every
    /// answer, and one that was never declared cannot.
    pub fn set_space_dtb(&mut self, space: usize, dtb: u64) {
        if let Some(slot) = self.spaces.get_mut(space) {
            slot.dtb = dtb;
        }
    }

    /// Note that `space` declined a top-level subtree because `reference` had
    /// already walked the identical entry.
    pub fn record_shared_subtree(&mut self, space: usize, index: usize, reference: usize) {
        // Anything that changes the spaces changes what the shortfall list
        // would say, so the cache cannot outlive it.
        self.shortfalls.take();
        if let Some(slot) = self.spaces.get_mut(space) {
            slot.shared_from.push((index, reference));
        }
    }

    /// Record one mapping.
    ///
    /// Only the wanted frames inside it are indexed, so a 1 GiB run costs one
    /// binary search rather than 262,144 rows.
    pub fn record_run(&mut self, space: usize, run: &MappingRun) {
        if run.len == 0 {
            return;
        }
        let first = run.phys_start >> PAGE_OFFSET_BITS;
        let last = (run.phys_start.saturating_add(run.len - 1)) >> PAGE_OFFSET_BITS;
        // Collected first: the wanted set and the owner table are both fields
        // of this map, and iterating one while writing the other is not a
        // borrow the compiler will allow. A run covering many wanted frames is
        // the uncommon case, so the allocation is not on the hot path.
        let frames: Vec<u64> = self.wanted.between(first, last).to_vec();
        for frame in frames {
            let frame_base = frame << PAGE_OFFSET_BITS;
            let into_run = frame_base.saturating_sub(run.phys_start);
            // The frame's own virtual address. The byte's offset inside it is
            // added at lookup, so one row answers every offset in the frame.
            let virtual_address = run.va_start.wrapping_add(into_run);
            let page_index = into_run / run.page_bytes.max(1);
            let page_virtual_base = run
                .va_start
                .wrapping_add(page_index.saturating_mul(run.page_bytes));
            self.push_owner(
                frame,
                Owner {
                    space,
                    virtual_address,
                    page_virtual_base,
                    page_bytes: run.page_bytes,
                    via: run.via,
                    virtual_address_enumerated: true,
                    also_reached_from: Vec::new(),
                },
            );
        }
    }

    /// Record the one frame a declined uniform table still names.
    ///
    /// 512 byte-identical present entries name a single frame at 512
    /// addresses. The frame is a fact and is recorded; which of the 512
    /// addresses is wanted is not, so only the region's own base address is
    /// stated and the owner says the address was not enumerated.
    pub fn record_uniform_leaf(&mut self, space: usize, blindness: &Blindness) {
        let Blindness::UniformTableSuppressed {
            va_start,
            level,
            leaf_frame: Some(frame_base),
            ..
        } = blindness
        else {
            return;
        };
        let frame = frame_base >> PAGE_OFFSET_BITS;
        if !self.wanted.contains(frame) {
            return;
        }
        // The page size, NOT the declined table's span.
        //
        // `Blindness::UniformTableSuppressed.bytes` is the whole region the
        // table covers, because that is the address space an examiner loses.
        // The *page* the repeated entry names is one level down from that, and
        // `leaf_frame` is `Some` only where the entry terminates the walk, so
        // the level's own region width is the page size. Copying the table
        // span here instead published a 2 MiB page for a 4 KiB frame — and, at
        // a large-page level, a 512 GiB page, which no Intel mode defines.
        // `PagingSpec::region_bits_at`'s own doc warns about exactly this
        // caller.
        let page_bytes = self
            .spec
            .region_bits_at(*level as usize)
            .filter(|bits| *bits < 64)
            .map(|bits| 1u64 << bits)
            .unwrap_or(FRAME_BYTES);
        self.push_owner(
            frame,
            Owner {
                space,
                virtual_address: *va_start,
                page_virtual_base: *va_start,
                page_bytes,
                via: RunVia::PageTables,
                virtual_address_enumerated: false,
                also_reached_from: Vec::new(),
            },
        );
    }

    fn push_owner(&mut self, frame: u64, owner: Owner) {
        self.recorded += 1;
        let entry = self.owners.entry(frame).or_default();
        entry.total += 1;
        if entry.listed.len() < MAX_OWNERS_LISTED {
            entry.listed.push(owner);
        }
    }

    /// A sink that records this space's mappings into the map.
    pub fn sink_for(&mut self, space: usize) -> SpaceSink<'_> {
        SpaceSink {
            map: self,
            space,
            reference: None,
        }
    }

    /// A sink for a space being walked with `reference`'s top table as its
    /// parity, so each subtree the walk declines is recorded against the space
    /// that did walk it.
    ///
    /// The walk reports the *index* it declined and does not know whose parity
    /// it was handed; the caller knows the reference and not the indices. This
    /// is where the two meet, and it is the only place they do — deriving the
    /// set afterwards by re-reading both top tables got the 32-bit modes'
    /// entry count wrong and counted every index absent from both spaces as a
    /// shared subtree.
    pub fn sink_for_pruned_against(&mut self, space: usize, reference: usize) -> SpaceSink<'_> {
        SpaceSink {
            map: self,
            space,
            reference: Some(reference),
        }
    }

    /// Whether every declared space was enumerated whole.
    ///
    /// The one thing that makes a negative answer sayable.
    pub fn every_space_complete(&self) -> bool {
        !self.spaces.is_empty() && self.spaces.iter().all(Space::is_complete)
    }

    /// Every declared space whose coverage was short, and why.
    ///
    /// Recomputed from the spaces each call, which is what a caller asking
    /// once wants. [`ReverseMap::attribute`] does **not** use it: a strings
    /// file can name five million offsets, and formatting 131 spaces'
    /// shortfall sentences per offset is 655 million string allocations for
    /// one answer. It reads [`ReverseMap::shortfalls_cached`] instead.
    pub fn shortfalls(&self) -> Vec<NotAssessed> {
        self.spaces.iter().filter_map(Space::shortfall).collect()
    }

    /// The shortfall list, computed once and reused.
    ///
    /// Safe to cache because the spaces cannot change after they are walked:
    /// `declare_space`, `record_outcome` and `record_shared_subtree` all take
    /// `&mut self` and all clear the cache, so a stale list cannot be served.
    fn shortfalls_cached(&self) -> &[NotAssessed] {
        self.shortfalls
            .get_or_init(|| self.spaces.iter().filter_map(Space::shortfall).collect())
    }

    /// Which spaces share `space`'s top-level subtree at the index `va` falls
    /// in, so a mapping found there can name them.
    fn sharers_of(&self, space: usize, va: u64) -> Vec<usize> {
        let Some(index) = self.spec.index_at(va, 0) else {
            return Vec::new();
        };
        let index = index as usize;
        self.spaces
            .iter()
            .enumerate()
            .filter(|(handle, other)| {
                *handle != space
                    && other.shared_from.iter().any(|&(shared_index, reference)| {
                        shared_index == index && reference == space
                    })
            })
            .map(|(handle, _)| handle)
            .collect()
    }

    /// What this map is entitled to say about one physical offset.
    pub fn attribute(&self, physical_offset: u64) -> Attribution {
        let frame = physical_offset >> PAGE_OFFSET_BITS;
        let outside = !self.wanted.contains(frame);
        let found = self.owners.get(&frame);
        let mut owners: Vec<Owner> = found.map(|f| f.listed.clone()).unwrap_or_default();
        let into_frame = physical_offset & (FRAME_BYTES - 1);
        for owner in &mut owners {
            owner.also_reached_from = self
                .sharers_of(owner.space, owner.page_virtual_base)
                .to_vec();
            // The stored address is the frame's; this is the byte's.
            owner.virtual_address = owner.virtual_address.wrapping_add(into_frame);
        }
        let owners_total = found.map(|f| f.total).unwrap_or(0);
        let shortfalls = self.shortfalls_cached();
        let complete = shortfalls.is_empty() && !self.spaces.is_empty();
        let verdict = match (owners_total > 0, complete, outside) {
            // An offset outside the wanted set was never looked up, so nothing
            // about it was assessed however complete the walks were.
            (_, _, true) => Verdict::NotAssessed,
            (true, true, _) => Verdict::Mapped,
            (true, false, _) => Verdict::MappedAndCoverageShort,
            (false, true, _) => Verdict::NoMappingAndEverySpaceAssessed,
            (false, false, _) => Verdict::NotAssessed,
        };
        Attribution {
            physical_offset,
            frame,
            owners_listed_capped: owners_total > owners.len() as u64,
            owners,
            owners_total,
            verdict,
            not_assessed_in: shortfalls.to_vec(),
            outside_the_wanted_set: outside,
        }
    }
}

/// The [`MappingSink`] one space's enumeration reports to.
///
/// It records mappings and the one frame a declined uniform table still names,
/// and it never stops the walk: a reverse map wants every mapping there is, and
/// the walk's own ceilings are what bound it.
#[derive(Debug)]
pub struct SpaceSink<'m> {
    map: &'m mut ReverseMap,
    space: usize,
    /// The space whose top table this walk prunes against, when it prunes.
    reference: Option<usize>,
}

impl MappingSink for SpaceSink<'_> {
    fn run(&mut self, run: &MappingRun) -> SinkFlow {
        self.map.record_run(self.space, run);
        SinkFlow::Continue
    }

    fn blind(&mut self, blindness: &Blindness) -> SinkFlow {
        // The only blindness that still carries a fact. Everything else is
        // accounted for by the space's own outcome, which shortens every
        // answer this map gives.
        self.map.record_uniform_leaf(self.space, blindness);
        SinkFlow::Continue
    }

    fn shared_subtree(
        &mut self,
        index: usize,
        _entry: u64,
        _va_start: u64,
        _bytes: u64,
    ) -> SinkFlow {
        // The walk reports which index it declined; the reference came from
        // the caller when this sink was made. Recording it here means the set
        // is exactly what the walk declined -- no re-derivation, and no
        // assumption about how many entries a top-level table has.
        if let Some(reference) = self.reference {
            self.map.record_shared_subtree(self.space, index, reference);
        }
        SinkFlow::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translate::enumerate::{EnumerateLimits, RootParity};
    use crate::translate::spec::{PagingMode, PteSemantics, PRESENT_BIT};
    use crate::translate::test_image::{Harness, Image};

    const SPEC: PagingSpec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);

    /// Two processes and a kernel half.
    ///
    /// Space A (dtb 0x1000) maps frame 0x9000 at virtual 0x1000, and frame
    /// 0xA000 at 0x2000 which nobody else has.
    /// Space B (dtb 0x10000) maps the same frame 0x9000 at virtual 0x20_2000.
    /// Both share the upper-half top-level entry, which maps frame 0xB000 at
    /// 0xFFFF_8000_0000_0000.
    fn two_processes() -> Image {
        let mut image = Image::new();
        // Space A, lower half.
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 0, 0x4000 | PRESENT_BIT);
        image.entry64(0x4000, 1, 0x9000 | PRESENT_BIT);
        image.entry64(0x4000, 2, 0xA000 | PRESENT_BIT);
        // Space B, lower half: the same frame at a different address.
        image.entry64(0x10000, 0, 0x11000 | PRESENT_BIT);
        image.entry64(0x11000, 0, 0x12000 | PRESENT_BIT);
        image.entry64(0x12000, 1, 0x13000 | PRESENT_BIT);
        image.entry64(0x13000, 2, 0x9000 | PRESENT_BIT);
        // The shared kernel half: the same top-level entry in both.
        image.entry64(0x1000, 256, 0x20000 | PRESENT_BIT);
        image.entry64(0x10000, 256, 0x20000 | PRESENT_BIT);
        image.entry64(0x20000, 0, 0x21000 | PRESENT_BIT);
        image.entry64(0x21000, 0, 0x22000 | PRESENT_BIT);
        image.entry64(0x22000, 0, 0xB000 | PRESENT_BIT);
        image
    }

    /// Declare and walk each space, with no pruning.
    fn mapped(harness: &Harness, wanted: FrameSet, spaces: &[(&str, u64)]) -> ReverseMap {
        let mut map = ReverseMap::new(SPEC, wanted);
        for &(label, dtb) in spaces {
            let handle = map.declare_space(label, dtb);
            let outcome = {
                let walk = harness.walk();
                let mut sink = map.sink_for(handle);
                walk.enumerate(dtb, &EnumerateLimits::default(), &mut sink)
            };
            map.record_outcome(handle, outcome);
        }
        map
    }

    #[test]
    fn a_physical_offset_inside_a_page_mapped_by_two_processes_names_both() {
        // The roadmap's own grading criterion for this route, and the thing
        // upstream's plugin gets wrong: its per-process branch keys the
        // reverse map by the VIRTUAL page number, so a genuine physical
        // offset never matches a process at all.
        let harness = Harness::new(two_processes(), PagingMode::Intel32e, PteSemantics::Bare);
        let wanted = FrameSet::from_offsets([0x9040]);
        let map = mapped(
            &harness,
            wanted,
            &[
                ("explorer.exe (4312)", 0x1000),
                ("lsass.exe (968)", 0x10000),
            ],
        );

        let answer = map.attribute(0x9040);
        assert_eq!(answer.owners_total, 2, "both processes, not one");
        assert_eq!(answer.verdict, Verdict::Mapped);
        assert_eq!(
            answer
                .owners
                .iter()
                .map(|o| (
                    map.space(o.space).unwrap().label.as_str(),
                    o.virtual_address
                ))
                .collect::<Vec<_>>(),
            vec![
                ("explorer.exe (4312)", 0x1040),
                ("lsass.exe (968)", 0x20_2040),
            ],
            "each names the virtual address the byte has in ITS OWN space"
        );
        assert!(!answer.owners_listed_capped);
        assert!(answer.not_assessed_in.is_empty());
    }

    #[test]
    fn the_physical_offset_and_the_virtual_address_are_never_the_same_column() {
        // Upstream renders a virtual address for kernel rows and a physical
        // one for process rows in one column, because its two branches unpack
        // the same tuple in different orders. There is no field here that
        // could hold the other kind.
        let harness = Harness::new(two_processes(), PagingMode::Intel32e, PteSemantics::Bare);
        let map = mapped(
            &harness,
            FrameSet::from_offsets([0x9040]),
            &[("explorer.exe (4312)", 0x1000)],
        );
        let answer = map.attribute(0x9040);
        assert_eq!(answer.physical_offset, 0x9040, "the physical side, once");
        assert_eq!(answer.frame, 0x9);
        assert_eq!(answer.owners[0].virtual_address, 0x1040, "the virtual side");
        assert_eq!(answer.owners[0].page_virtual_base, 0x1000);
        assert_eq!(answer.owners[0].page_bytes, 0x1000);
    }

    #[test]
    fn a_frame_only_one_process_maps_names_only_that_one() {
        let harness = Harness::new(two_processes(), PagingMode::Intel32e, PteSemantics::Bare);
        let map = mapped(
            &harness,
            FrameSet::from_offsets([0x9000, 0xA000]),
            &[("a", 0x1000), ("b", 0x10000)],
        );
        assert_eq!(map.attribute(0xA000).owners_total, 1);
        assert_eq!(map.attribute(0x9000).owners_total, 2);
    }

    #[test]
    fn an_offset_no_walked_space_maps_says_only_what_that_means() {
        // "FREE MEMORY" is what upstream prints. This says the one thing the
        // page tables support and then says what it is not: the PFN database
        // was not read, and a frame on the free list still holds its last
        // contents.
        let harness = Harness::new(two_processes(), PagingMode::Intel32e, PteSemantics::Bare);
        let map = mapped(
            &harness,
            FrameSet::from_offsets([0x5_0000]),
            &[("a", 0x1000), ("b", 0x10000)],
        );
        let answer = map.attribute(0x5_0000);
        assert_eq!(answer.owners_total, 0);
        assert_eq!(answer.verdict, Verdict::NoMappingAndEverySpaceAssessed);
        let said = answer.verdict.statement();
        assert!(
            said.contains("NOT a finding that the frame is free"),
            "{said}"
        );
        assert!(said.contains("PFN database was not read"), "{said}");
    }

    #[test]
    fn one_space_that_would_not_walk_shortens_every_answer_the_map_gives() {
        // Including the answers that DID find an owner: an offset with one
        // owner and a second space that would not walk has one owner *and* an
        // unassessed space, and a row showing only the first reads as
        // complete.
        let mut image = two_processes();
        // The acquisition stops above every table space A uses, and space B's
        // directory table base names a frame past the end of it -- a process
        // whose page tables the capture did not reach.
        image.bytes.truncate(0x24000);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let map = mapped(
            &harness,
            FrameSet::from_offsets([0x9000, 0x5_0000]),
            &[("a", 0x1000), ("b", 0x30000)],
        );

        let found = map.attribute(0x9000);
        assert_eq!(found.owners_total, 1, "only the space that walked");
        assert_eq!(found.verdict, Verdict::MappedAndCoverageShort);
        assert_eq!(found.not_assessed_in.len(), 1);
        assert_eq!(found.not_assessed_in[0].label, "b");
        assert_eq!(found.not_assessed_in[0].reason, IncompleteReason::ShortRead);
        assert!(
            found.not_assessed_in[0]
                .detail
                .contains("not assessed at all"),
            "{}",
            found.not_assessed_in[0].detail
        );

        let missing = map.attribute(0x5_0000);
        assert_eq!(
            missing.verdict,
            Verdict::NotAssessed,
            "no owner and an unassessed space is not a negative finding"
        );
        assert!(!map.every_space_complete());
    }

    #[test]
    fn a_space_declared_and_never_walked_is_a_shortfall_and_not_an_empty_space() {
        // Forgetting to record an outcome makes the map MORE cautious, never
        // less: the failure mode of the API is a hedged answer, not a false
        // one.
        let harness = Harness::new(two_processes(), PagingMode::Intel32e, PteSemantics::Bare);
        let mut map = ReverseMap::new(SPEC, FrameSet::from_offsets([0x9000]));
        let a = map.declare_space("a", 0x1000);
        let outcome = {
            let walk = harness.walk();
            let mut sink = map.sink_for(a);
            walk.enumerate(0x1000, &EnumerateLimits::default(), &mut sink)
        };
        map.record_outcome(a, outcome);
        map.declare_space("never walked", 0x10000);

        let answer = map.attribute(0x9000);
        assert_eq!(answer.verdict, Verdict::MappedAndCoverageShort);
        assert_eq!(answer.not_assessed_in.len(), 1);
        assert!(answer.not_assessed_in[0]
            .detail
            .contains("declared and never walked"));
    }

    #[test]
    fn an_offset_the_map_was_never_asked_about_is_not_reported_as_unmapped() {
        // The wanted set bounds what was indexed, so an offset outside it was
        // never looked up -- which is not the same as having been looked up
        // and found to have no owner.
        let harness = Harness::new(two_processes(), PagingMode::Intel32e, PteSemantics::Bare);
        let map = mapped(&harness, FrameSet::from_offsets([0x9000]), &[("a", 0x1000)]);
        let answer = map.attribute(0xA000);
        assert!(answer.outside_the_wanted_set);
        assert_eq!(answer.verdict, Verdict::NotAssessed);
        assert_eq!(answer.owners_total, 0);
        // And the frame that WAS wanted answers normally.
        assert_eq!(map.attribute(0x9000).verdict, Verdict::Mapped);
    }

    #[test]
    fn a_shared_kernel_subtree_is_one_owner_naming_the_spaces_that_reach_it() {
        // Not one hundred and thirty owners. A frame mapped once in the
        // kernel's half is one mapping seen from every context, and listing it
        // per process would read as that many separate findings -- which is
        // exactly the shape upstream produced when it attributed
        // KUSER_SHARED_DATA's virtual page to 123 processes at once.
        let harness = Harness::new(two_processes(), PagingMode::Intel32e, PteSemantics::Bare);
        let mut map = ReverseMap::new(SPEC, FrameSet::from_offsets([0xB000]));
        let kernel = map.declare_space("kernel", 0x1000);
        let parity = RootParity::of(&harness.walk(), 0x1000).expect("the reference top table");
        let outcome = {
            let walk = harness.walk();
            let mut sink = map.sink_for(kernel);
            walk.enumerate(0x1000, &EnumerateLimits::default(), &mut sink)
        };
        map.record_outcome(kernel, outcome);

        let process = map.declare_space("lsass.exe (968)", 0x10000);
        let limits = EnumerateLimits {
            prune_against: Some(&parity),
            ..EnumerateLimits::default()
        };
        let outcome = {
            let walk = harness.walk();
            // The sink is told whose parity this is, so the walk's own
            // declined index is what gets recorded.
            let mut sink = map.sink_for_pruned_against(process, kernel);
            walk.enumerate(0x10000, &limits, &mut sink)
        };
        assert_eq!(outcome.shared_subtrees, 1, "index 256, and only that one");
        map.record_outcome(process, outcome);
        assert_eq!(
            map.space(process).map(|s| s.shared_from.as_slice()),
            Some([(256usize, kernel)].as_slice()),
            "the 510 top-level indices absent from BOTH spaces are not shared subtrees: \
             there is nothing under them to have been walked elsewhere"
        );

        let answer = map.attribute(0xB000);
        assert_eq!(answer.owners_total, 1, "one mapping, not two findings");
        assert_eq!(answer.owners[0].space, kernel);
        assert_eq!(answer.owners[0].virtual_address, 0xFFFF_8000_0000_0000);
        assert_eq!(
            answer.owners[0].also_reached_from,
            vec![process],
            "and it names the space that reaches it through the same tables"
        );
    }

    #[test]
    fn the_frame_a_declined_uniform_table_names_is_still_attributed() {
        // 512 byte-identical present entries name one frame at 512 addresses.
        // Dropping it would report as unknown something knowable with no
        // further reading -- and it may be the very frame the offset is in.
        let mut image = two_processes();
        for index in 0..512 {
            image.entry64(0x4000, index, 0xE000 | PRESENT_BIT);
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        let mut map = ReverseMap::new(spec, FrameSet::from_offsets([0xE040]));
        let handle = map.declare_space("a", 0x1000);
        let outcome = {
            let walk = harness.walk();
            let mut sink = map.sink_for(handle);
            walk.enumerate(0x1000, &EnumerateLimits::default(), &mut sink)
        };
        map.record_outcome(handle, outcome);

        let answer = map.attribute(0xE040);
        assert_eq!(answer.owners_total, 1);
        assert!(
            !answer.owners[0].virtual_address_enumerated,
            "the frame is a fact; which of its 512 addresses is wanted is not"
        );
        assert_eq!(
            answer.owners[0].page_bytes,
            1 << 12,
            "the page the repeated entry names, not the 2 MiB of address space the declined \
             table covers -- a 4 KiB frame published as a 2 MiB page claims contiguity the \
             tables do not provide, and 2 MiB is itself a real page size, so nothing on the \
             record would betray it"
        );
        assert_eq!(
            answer.verdict,
            Verdict::MappedAndCoverageShort,
            "a suppressed table is still a gap in the space, even here"
        );
    }

    #[test]
    fn a_declined_uniform_table_of_large_pages_names_a_page_size_that_exists() {
        // The absurd form of the same defect, and the one that makes it
        // obvious: a page-directory-pointer table whose 512 entries are all
        // the same 1 GiB large page covers 512 GiB of address space. Reporting
        // that span as the owner's page size claims a 512 GiB page, which no
        // Intel paging mode defines.
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        for index in 0..512 {
            image.entry64(
                0x2000,
                index,
                0x4000_0000 | PRESENT_BIT | crate::translate::spec::LARGE_PAGE_BIT,
            );
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        let offset = 0x4000_0040u64;
        let mut map = ReverseMap::new(spec, FrameSet::from_offsets([offset]));
        let handle = map.declare_space("a", 0x1000);
        let outcome = {
            let walk = harness.walk();
            let mut sink = map.sink_for(handle);
            walk.enumerate(0x1000, &EnumerateLimits::default(), &mut sink)
        };
        assert_eq!(outcome.uniform_tables_suppressed, 1);
        assert_eq!(outcome.uniform_leaf_frames, 1);
        map.record_outcome(handle, outcome);

        let answer = map.attribute(offset);
        assert_eq!(answer.owners_total, 1);
        assert_eq!(
            answer.owners[0].page_bytes,
            1 << 30,
            "a 1 GiB page, which is what the repeated entry names -- not the 512 GiB the \
             declined table covers"
        );
        assert!(!answer.owners[0].virtual_address_enumerated);
    }

    #[test]
    fn a_large_page_names_the_page_size_beside_the_frame() {
        // A frame number without the owner's page size beside it understates
        // what that owner maps: a 1 GiB mapping and a 4 KiB one look the same
        // in the frame column.
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(
            0x2000,
            1,
            0x4000_0000 | PRESENT_BIT | crate::translate::spec::LARGE_PAGE_BIT,
        );
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let offset = 0x4000_0000 + 0x12_3456;
        let map = mapped(&harness, FrameSet::from_offsets([offset]), &[("a", 0x1000)]);
        let answer = map.attribute(offset);
        assert_eq!(answer.owners_total, 1);
        assert_eq!(answer.owners[0].page_bytes, 1 << 30, "a 1 GiB page");
        assert_eq!(answer.owners[0].virtual_address, 0x4000_0000 + 0x12_3456);
        assert_eq!(answer.owners[0].page_virtual_base, 0x4000_0000);
    }

    #[test]
    fn a_frame_more_spaces_map_than_are_listed_still_reports_how_many() {
        // The cap loses virtual addresses, never the count -- because the
        // count is kept apart from the list.
        let harness = Harness::new(two_processes(), PagingMode::Intel32e, PteSemantics::Bare);
        let mut map = ReverseMap::new(SPEC, FrameSet::from_offsets([0x9000]));
        // The same space declared and walked many times over stands in for
        // many processes mapping one frame; what is being pinned is the cap.
        for index in 0..MAX_OWNERS_LISTED + 10 {
            let handle = map.declare_space(format!("process {index}"), 0x1000);
            let outcome = {
                let walk = harness.walk();
                let mut sink = map.sink_for(handle);
                walk.enumerate(0x1000, &EnumerateLimits::default(), &mut sink)
            };
            map.record_outcome(handle, outcome);
        }
        let answer = map.attribute(0x9000);
        assert_eq!(answer.owners_total, MAX_OWNERS_LISTED as u64 + 10);
        assert_eq!(answer.owners.len(), MAX_OWNERS_LISTED);
        assert!(answer.owners_listed_capped);
    }

    #[test]
    fn a_run_covering_many_wanted_frames_indexes_each_of_them() {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 0, 0x4000 | PRESENT_BIT);
        // Four physically and virtually contiguous pages, which coalesce into
        // one run of 16 KiB.
        for index in 0..4u64 {
            image.entry64(0x4000, index, (0x30000 + index * 0x1000) | PRESENT_BIT);
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let offsets = [0x30000, 0x31000 + 8, 0x33000 + 0xFFF];
        let map = mapped(&harness, FrameSet::from_offsets(offsets), &[("a", 0x1000)]);
        assert_eq!(
            map.frames_with_an_owner(),
            3,
            "each wanted frame in the run"
        );
        assert_eq!(
            offsets
                .iter()
                .map(|&o| map.attribute(o).owners[0].virtual_address)
                .collect::<Vec<_>>(),
            vec![0x0, 0x1008, 0x3FFF],
            "each offset's own virtual address inside the run"
        );
    }

    #[test]
    fn a_map_with_no_space_declared_claims_nothing() {
        // The degenerate case, and the one where a naive implementation says
        // "no process maps this" most confidently.
        let map = ReverseMap::new(SPEC, FrameSet::from_offsets([0x9000]));
        assert!(!map.every_space_complete());
        assert_eq!(map.attribute(0x9000).verdict, Verdict::NotAssessed);
    }

    #[test]
    fn the_wanted_set_is_the_frames_the_offsets_fall_in() {
        let set = FrameSet::from_offsets([0, 0xFFF, 0x1000, 0x1001, 0x9_8765]);
        assert_eq!(set.len(), 3, "0, 1 and 0x98");
        assert!(set.contains(0));
        assert!(set.contains(1));
        assert!(set.contains(0x98));
        assert!(!set.contains(2));
        let whole = FrameSet::whole_image(0x2001);
        assert_eq!(
            whole.len(),
            3,
            "a partial frame at the end is still a frame"
        );
    }
}
