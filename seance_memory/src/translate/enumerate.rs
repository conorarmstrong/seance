//! [`PageWalk::enumerate`]: every mapping an address space holds, walked
//! **downward** through the tables rather than probed address by address.
//!
//! # Why a second direction exists
//!
//! [`PageWalk::translate`] answers "where is this virtual address?". It cannot
//! answer "who maps this physical frame?", and no number of calls to it can:
//! the question has no virtual address to start from. Sweeping the space
//! instead — translate, step by the run length, translate again — costs one
//! walk per page of a 128 TiB space, and 99.99% of those walks find nothing
//! because nothing was ever mapped there.
//!
//! So this walks the other way. Starting at the directory table base it reads
//! each table whole and descends only into entries that are present, which
//! means the cost is proportional to what the process actually mapped and not
//! to the size of the space it could have. Along the way it reconstructs each
//! mapping's virtual address from the indices it took to get there — see
//! [`PagingSpec::virtual_address_from_indices`], which is the inverse of the
//! decomposition the upward walk does, and the one piece of new arithmetic in
//! the whole route.
//!
//! # The two walkers may not disagree
//!
//! They read the same bytes with the same spec, so they must agree, and
//! everything that could make them differ is shared rather than restated:
//! [`PageWalk::table_pa_of`] masks a table's address for both,
//! [`PagingSpec::classify`] decides what an entry is — table, page, block or
//! nothing — and which bits of it are the frame, for both, and
//! [`PagingSpec::classify_invalid`] says what more an absent one means.
//! `enumerate_agrees_with_translate_on_every_mapping_it_reports` pins the
//! agreement on a hierarchy holding every shape at once.
//!
//! # What it declines to see, it says
//!
//! A downward walk has three ways to miss a mapping that is really there, and
//! each is reported as a [`Blindness`] carrying the span of address space it
//! covers rather than left as silence:
//!
//! * a **table that would not read** — the acquisition is short, smeared or
//!   holed there, and every mapping under that table is unknown;
//! * a **uniform table** the Windows unused-address heuristic declines, which
//!   at a terminating level still names one frame and says so, because 512
//!   byte-identical present entries name a single frame at 512 addresses;
//! * a **prototype PTE** — the page belongs to a section object, and where the
//!   hop is not taken the shared page is not seen.
//!
//! Plus the caps. Each is reported with the number it hit and the address the
//! walk had reached, because an enumeration that stopped at a ceiling and reads
//! as one that finished is the defect this crate is written against.
//!
//! An entry that is simply **not present**, or names a pagefile, or is a Linux
//! swap entry, is *not* blindness: there is no frame behind it in this image, so
//! it cannot hide the owner of a physical offset. Those are counted, and the
//! counts are on [`EnumerateOutcome`].

use seance_core::io::IncompleteReason;

use crate::translate::spec::{
    EntryKind, InvalidEntry, PAGE_OFFSET_BITS, PRESENT_BIT, WINDOWS_TRANSITION_BIT,
};
use crate::translate::walk::{PageWalk, TranslateError};

/// Tables one address space may be read before the walk stops and says so.
///
/// 65,536 page-sized tables is 256 MiB of table reads for one space. A Windows
/// process's own half is one to two thousand tables and the kernel's shared
/// half is of the order of ten thousand, so this is more than thirty times the
/// ordinary cost — and it is what stops one process with a decoy-filled
/// hierarchy from spending a whole case's budget.
pub const MAX_TABLES_PER_SPACE: u64 = 65_536;

/// Mapping runs one address space may report.
///
/// A run is a *coalesced* range, so four million of them is far beyond any
/// real space: a process mapping two gigabytes in 4 KiB pages with no two
/// physically adjacent is half a million.
pub const MAX_RUNS_PER_SPACE: u64 = 4_000_000;

/// Prototype-PTE hops one address space may take.
///
/// Each hop is a second walk into paged pool, so this is the cap that bounds
/// the one piece of work quadratic in the evidence.
///
/// **Measured**, not guessed: on this project's Windows 11 corpus — a 10 GiB
/// capture of a machine with 130 processes — the whole run takes 328,132 hops,
/// almost all of them in the kernel's own space, which holds the file cache.
/// Two million is roughly seven times that, which leaves room for a far busier
/// machine while still bounding a hostile hierarchy. Past it the pages are
/// counted as unresolved rather than silently skipped.
pub const MAX_PROTOTYPE_HOPS_PER_SPACE: u64 = 2_000_000;

/// Which ceiling an enumeration reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumerateCap {
    /// [`MAX_TABLES_PER_SPACE`], or the caller's own figure.
    Tables,
    /// [`MAX_RUNS_PER_SPACE`], or the caller's own figure.
    Runs,
    /// [`MAX_PROTOTYPE_HOPS_PER_SPACE`], or the caller's own figure.
    PrototypeHops,
}

impl EnumerateCap {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            EnumerateCap::Tables => "tables_per_space",
            EnumerateCap::Runs => "runs_per_space",
            EnumerateCap::PrototypeHops => "prototype_hops_per_space",
        }
    }

    /// The sentence a report puts beside the count.
    pub fn statement(self) -> &'static str {
        match self {
            EnumerateCap::Tables => {
                "the walk stopped after reading its ceiling of page tables in this address \
                 space, so mappings beyond the address named were never enumerated"
            }
            EnumerateCap::Runs => {
                "the walk stopped after reporting its ceiling of mapping runs in this address \
                 space, so mappings beyond the address named were never reported"
            }
            EnumerateCap::PrototypeHops => {
                "the walk stopped following prototype PTEs after its ceiling of hops, so \
                 section-backed pages beyond that point were not resolved to a frame"
            }
        }
    }
}

/// Which structure named the frame a run reports.
///
/// The distinction [`crate::translate::TranslationPath`] draws, plus the one it
/// does not: a **transition** entry is a page on the standby list, still in RAM
/// and still holding its bytes, which the walker legitimately follows.
/// [`PagingSpec::entry_is_present`] calls it present and `translate` therefore
/// reports it as an ordinary page-table answer; here it is kept apart, because
/// "this page was still mapped" and "this page had been trimmed and its frame
/// not yet reused" are different sentences about how the bytes came to be
/// there.
///
/// [`PagingSpec::entry_is_present`]: crate::translate::PagingSpec::entry_is_present
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunVia {
    /// A present hardware entry resolved it.
    PageTables,
    /// A Windows transition entry: the page is on the standby or modified list,
    /// its frame is still in RAM, and the hardware would have faulted.
    Transition,
    /// A Windows prototype PTE was followed into a section object's prototype
    /// array at `proto_va` (physical `proto_pa`). The page is **shared** and
    /// may be mapped by other processes as well, so "this process wrote these
    /// bytes" is not a claim the mapping supports.
    PrototypePte { proto_va: u64, proto_pa: u64 },
}

impl RunVia {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            RunVia::PageTables => "page_tables",
            RunVia::Transition => "transition",
            RunVia::PrototypePte { .. } => "prototype_pte",
        }
    }

    /// Whether the page is reached through a section object, and therefore may
    /// belong to more address spaces than the one that was walked.
    pub fn is_shared(self) -> bool {
        matches!(self, RunVia::PrototypePte { .. })
    }
}

/// A range of virtual addresses that translate contiguously to physical.
///
/// One run per page, or one per adjacent group of pages where the tables put
/// them contiguously in both spaces and nothing about them differs — see
/// [`EnumerateLimits::coalesce`]. A run never spans a gap, a page size or a
/// change of [`RunVia`], so every byte of it is backed by the same kind of
/// evidence as its first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingRun {
    /// Canonical virtual address of the run's first byte, sign extension
    /// included.
    pub va_start: u64,
    /// Physical address of the run's first byte.
    pub phys_start: u64,
    /// How many bytes the run covers, in both spaces.
    pub len: u64,
    /// The size of the pages it is made of: 4 KiB, 2 MiB, 4 MiB or 1 GiB.
    pub page_bytes: u64,
    /// Index of the level whose entry described the page, `0` being the top
    /// table.
    pub level: u8,
    /// The no-execute bit as observed, not interpreted — bit 63 only means "no
    /// execute" when the machine had `EFER.NXE` set, which an image does not
    /// record. It includes the XD of every Intel non-leaf entry above the
    /// leaf. On ARM64 it is the regime's own execute-never bit, read the
    /// same way the upward walk reads it: see
    /// [`Translation::no_execute`](crate::translate::Translation::no_execute).
    pub no_execute: bool,
    /// What named the frame.
    pub via: RunVia,
}

impl MappingRun {
    /// How many pages the run is made of.
    pub fn pages(&self) -> u64 {
        if self.page_bytes == 0 {
            return 0;
        }
        self.len / self.page_bytes
    }

    /// Whether `physical` falls inside this run.
    pub fn holds(&self, physical: u64) -> bool {
        physical >= self.phys_start && physical - self.phys_start < self.len
    }

    /// The virtual address `physical` has in this run, or `None` when the run
    /// does not hold it.
    pub fn virtual_address_of(&self, physical: u64) -> Option<u64> {
        self.holds(physical)
            .then(|| self.va_start.wrapping_add(physical - self.phys_start))
    }
}

/// A mapping the walk could not see, and the span of address space it covers.
///
/// Every variant carries a span because that is what makes it usable: "this
/// address space has an unreadable table" is not actionable, and "these 2 MiB
/// of this address space were not assessed" is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blindness {
    /// The Windows unused-address heuristic declined a table every one of whose
    /// entries was the same present entry.
    ///
    /// `leaf_frame` is `Some` when the repeated entry *terminated* the walk —
    /// a final-level table, or a large-page entry — because 512 byte-identical
    /// entries then name exactly **one** frame, at 512 virtual addresses. That
    /// frame is knowable with no further reading, and a caller attributing
    /// physical offsets may use it. `None` when the repeated entry pointed at
    /// another table, where the frames beneath it are genuinely unknown.
    UniformTableSuppressed {
        va_start: u64,
        bytes: u64,
        table_pa: u64,
        level: u8,
        level_name: &'static str,
        entry: u64,
        leaf_frame: Option<u64>,
    },
    /// A table would not read, so every mapping under it is unknown.
    TableUnreadable {
        va_start: u64,
        bytes: u64,
        table_pa: u64,
        level: u8,
        level_name: &'static str,
        detail: String,
        /// Whether the read failed because the acquisition never held those
        /// bytes, as distinct from the evidence file failing to read. The two
        /// are different findings and only the first is a statement about the
        /// capture tool.
        unmapped: bool,
    },
    /// A prototype PTE was not resolved to a frame, so a section-backed page
    /// was not seen.
    PrototypeUnresolved {
        va_start: u64,
        bytes: u64,
        entry: u64,
        detail: String,
    },
    /// An entry whose frame this build will not state: a 4 MiB PSE-36 entry
    /// naming a frame above the 32-bit physical space, or arithmetic that left
    /// the address space.
    ///
    /// A limitation of this tool, never a fact about the acquisition — which is
    /// why it is its own variant and not an unreadable table.
    Unnameable {
        va_start: u64,
        bytes: u64,
        entry: u64,
        detail: &'static str,
    },
    /// The walk reached a ceiling and stopped.
    Capped {
        va_start: u64,
        cap: EnumerateCap,
        hit: u64,
    },
}

impl Blindness {
    /// The address the blindness starts at, and how many bytes of address
    /// space it covers.
    ///
    /// A cap covers the rest of the space from where it fired, which is not a
    /// number this type can state — the caller knows the space's own extent —
    /// so it reports `0`, and [`Blindness::covers_the_rest`] says so.
    pub fn span(&self) -> (u64, u64) {
        match self {
            Blindness::UniformTableSuppressed {
                va_start, bytes, ..
            }
            | Blindness::TableUnreadable {
                va_start, bytes, ..
            }
            | Blindness::PrototypeUnresolved {
                va_start, bytes, ..
            }
            | Blindness::Unnameable {
                va_start, bytes, ..
            } => (*va_start, *bytes),
            Blindness::Capped { va_start, .. } => (*va_start, 0),
        }
    }

    /// Whether this blindness covers everything from its address onward rather
    /// than a bounded span.
    pub fn covers_the_rest(&self) -> bool {
        matches!(self, Blindness::Capped { .. })
    }

    /// Which vocabulary term a record should carry for it.
    pub fn reason(&self) -> IncompleteReason {
        match self {
            Blindness::UniformTableSuppressed { .. }
            | Blindness::PrototypeUnresolved { .. }
            | Blindness::Unnameable { .. } => IncompleteReason::UnresolvedStructure,
            Blindness::TableUnreadable { unmapped, .. } => {
                if *unmapped {
                    IncompleteReason::Unmapped
                } else {
                    IncompleteReason::ShortRead
                }
            }
            Blindness::Capped { .. } => IncompleteReason::CapReached,
        }
    }

    /// The sentence a report puts on the row.
    pub fn statement(&self) -> String {
        match self {
            Blindness::UniformTableSuppressed {
                va_start,
                bytes,
                level_name,
                leaf_frame,
                ..
            } => match leaf_frame {
                Some(frame) => format!(
                    "every entry of the {level_name} covering {bytes} bytes at {va_start:#x} was \
                     the same present entry, which names the single frame at {frame:#x} at every \
                     one of those addresses; the addresses themselves were not enumerated"
                ),
                None => format!(
                    "every entry of the {level_name} covering {bytes} bytes at {va_start:#x} was \
                     the same present entry -- the Windows unused-address pattern -- so the \
                     mappings beneath it were not enumerated and any frame they hold is unknown"
                ),
            },
            Blindness::TableUnreadable {
                va_start,
                bytes,
                table_pa,
                level_name,
                detail,
                unmapped,
                ..
            } => {
                let cause = if *unmapped {
                    "the acquisition does not hold"
                } else {
                    "the evidence file would not read"
                };
                format!(
                    "the {level_name} at physical {table_pa:#x} could not be read ({cause} it: \
                     {detail}), so the {bytes} bytes of address space at {va_start:#x} were not \
                     assessed"
                )
            }
            Blindness::PrototypeUnresolved {
                va_start,
                bytes,
                detail,
                ..
            } => format!(
                "the {bytes} bytes at {va_start:#x} are described by a section object's prototype \
                 PTE that was not resolved to a frame ({detail}), so a shared page there was not \
                 seen"
            ),
            Blindness::Unnameable {
                va_start,
                bytes,
                detail,
                ..
            } => format!(
                "the entry covering the {bytes} bytes at {va_start:#x} names a frame this build \
                 will not state: {detail}"
            ),
            Blindness::Capped { va_start, cap, hit } => {
                format!("{} ({hit} reached, at {va_start:#x})", cap.statement())
            }
        }
    }
}

/// Whether the caller wants the walk to carry on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkFlow {
    /// Keep walking.
    Continue,
    /// Stop. The outcome records that the caller stopped it, so a short result
    /// is never read as a complete one.
    Stop,
}

impl SinkFlow {
    fn stops(self) -> bool {
        matches!(self, SinkFlow::Stop)
    }
}

/// What an enumeration reports to.
///
/// A sink rather than a returned collection: an address space can hold tens of
/// millions of mappings, and a caller building a reverse index wants each run
/// as it is found rather than a vector of all of them.
pub trait MappingSink {
    /// One range of virtual addresses that translate contiguously.
    fn run(&mut self, run: &MappingRun) -> SinkFlow;

    /// One mapping, or region of mappings, the walk could not see.
    fn blind(&mut self, blindness: &Blindness) -> SinkFlow;

    /// A top-level entry byte-identical to the reference space's, whose
    /// subtree was therefore not walked again — see [`RootParity`].
    ///
    /// `bytes` is the whole span that entry governs. The default does nothing:
    /// a caller that has not asked for pruning cannot receive one.
    fn shared_subtree(&mut self, index: usize, entry: u64, va_start: u64, bytes: u64) -> SinkFlow {
        let _ = (index, entry, va_start, bytes);
        SinkFlow::Continue
    }
}

/// The top table of one address space, for recognising the subtrees another
/// space shares with it byte for byte.
///
/// # What this is for
///
/// Every process on Windows maps the same kernel through the same top-level
/// entries, so enumerating 130 processes enumerates the kernel's ten thousand
/// tables 130 times and reports every kernel mapping 130 times. Comparing a
/// process's top-level entry against the reference space's and declining to
/// descend where they are byte-identical is what makes the route affordable,
/// and it is exact rather than heuristic: identical entries point at the same
/// table, and the same table describes the same mappings.
///
/// # Why an entry can be `None`
///
/// Only a subtree the reference space **fully enumerated** may be pruned. If
/// the reference walk was capped under that index, or hit an unreadable table,
/// the mappings there were never reported, and pruning a process against it
/// would drop every owner beneath it while reporting nothing amiss. So an index
/// the reference walk did not finish is marked with
/// [`RootParity::mark_incomplete`] and every space is walked through it.
#[derive(Debug, Clone)]
pub struct RootParity {
    dtb: u64,
    entries: Vec<Option<u64>>,
}

impl RootParity {
    /// Read the top table of the space rooted at `dtb`.
    ///
    /// # Errors
    ///
    /// Whatever [`PageWalk`] reports for a table it cannot read. A parity that
    /// could not be established is not an empty one: the caller must walk every
    /// space whole instead.
    pub fn of(walk: &PageWalk<'_>, dtb: u64) -> Result<Self, TranslateError> {
        let table_pa = walk.root_pa_of(dtb).ok_or(TranslateError::InvalidDtb {
            dtb,
            detail: "paging spec declares no top level",
        })?;
        let read = walk.read_table(table_pa, 0, 63)?;
        Ok(Self {
            dtb,
            entries: read.entries.into_iter().map(Some).collect(),
        })
    }

    /// The directory table base this parity was read from.
    pub fn dtb(&self) -> u64 {
        self.dtb
    }

    /// Declare that the reference space's own walk did not finish this index,
    /// so nothing may be pruned against it.
    pub fn mark_incomplete(&mut self, index: usize) {
        if let Some(slot) = self.entries.get_mut(index) {
            *slot = None;
        }
    }

    /// Whether `entry` at top-level `index` is the reference space's own entry
    /// there, and the reference walk finished it.
    pub fn shares(&self, index: usize, entry: u64) -> bool {
        matches!(self.entries.get(index), Some(Some(reference)) if *reference == entry)
    }

    /// The entry at top-level `index`, or `None` where the reference walk did
    /// not finish it.
    pub fn entry(&self, index: usize) -> Option<u64> {
        self.entries.get(index).copied().flatten()
    }

    /// How many top-level entries this table holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table held no entries at all, which no shipped spec
    /// produces.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many top-level indices are marked as not fully enumerated.
    pub fn incomplete_indices(&self) -> usize {
        self.entries.iter().filter(|slot| slot.is_none()).count()
    }
}

/// What an enumeration is allowed to do, and how much of it.
#[derive(Debug, Clone, Copy)]
pub struct EnumerateLimits<'p> {
    /// Tables this space may read. See [`MAX_TABLES_PER_SPACE`].
    pub max_tables: u64,
    /// Runs this space may report. See [`MAX_RUNS_PER_SPACE`].
    pub max_runs: u64,
    /// Prototype hops this space may take. See
    /// [`MAX_PROTOTYPE_HOPS_PER_SPACE`].
    pub max_prototype_hops: u64,
    /// Whether to follow a prototype PTE into the section object's array.
    ///
    /// On by default, because a great deal of what a process has mapped — a
    /// DLL's code, a mapped data file, a shared section — is reached no other
    /// way, and turning it off makes a shared page look absent. Off costs
    /// nothing but coverage, and the coverage it costs is counted.
    pub resolve_prototypes: bool,
    /// Whether to merge adjacent pages into one run.
    ///
    /// On by default. Merging requires that the pages be adjacent in **both**
    /// spaces and identical in page size, path and no-execute bit, so a
    /// coalesced run says exactly what its pages said.
    pub coalesce: bool,
    /// The reference space's top table, when the caller wants shared subtrees
    /// declined rather than walked again.
    pub prune_against: Option<&'p RootParity>,
}

impl Default for EnumerateLimits<'_> {
    fn default() -> Self {
        Self {
            max_tables: MAX_TABLES_PER_SPACE,
            max_runs: MAX_RUNS_PER_SPACE,
            max_prototype_hops: MAX_PROTOTYPE_HOPS_PER_SPACE,
            resolve_prototypes: true,
            coalesce: true,
            prune_against: None,
        }
    }
}

/// What one enumeration cost, saw and could not see.
///
/// Every count here is the enumeration's own measurement. A zero means the walk
/// looked and found none; it never means the walk did not look, which is what
/// the cap and blindness fields are for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnumerateOutcome {
    /// Tables read whole.
    pub tables_read: u64,
    /// Bytes of table read, so a caller can publish the I/O it spent.
    pub table_bytes_read: u64,
    /// Entries examined across all of them.
    pub entries_examined: u64,
    /// Runs reported.
    pub runs: u64,
    /// Pages those runs cover.
    pub pages: u64,
    /// Bytes those runs cover.
    pub bytes_mapped: u64,
    /// Entries that were simply not present. Not blindness: there is no frame
    /// behind them in this image.
    pub absent_entries: u64,
    /// Entries naming a location in a pagefile.
    pub pagefile_entries: u64,
    /// Linux swap-family entries.
    pub linux_swap_entries: u64,
    /// Entries that were prototype PTEs.
    pub prototype_entries: u64,
    /// Hops actually taken into a prototype array.
    pub prototype_hops: u64,
    /// Prototype PTEs that did not resolve to a frame.
    pub prototypes_unresolved: u64,
    /// Tables declined by the uniform-table heuristic.
    pub uniform_tables_suppressed: u64,
    /// Of those, the ones whose repeated entry named a frame outright.
    pub uniform_leaf_frames: u64,
    /// Tables that would not read.
    pub tables_unreadable: u64,
    /// Subtrees not walked because the reference space had already walked them.
    pub shared_subtrees: u64,
    /// Bytes of address space behind a bounded blindness, saturating.
    ///
    /// A cap contributes nothing here, because what a cap costs is "everything
    /// after this address" and adding a number for that would understate it.
    /// [`EnumerateOutcome::caps_reached`] is where that is read.
    pub blind_bytes: u64,
    /// Ceilings reached, in the order they fired.
    pub caps_reached: Vec<EnumerateCap>,
    /// Top-level indices this walk stopped short of **for want of budget**.
    ///
    /// What [`RootParity::mark_incomplete`] is fed, so that no other space is
    /// pruned against a subtree this walk had more to say about.
    ///
    /// Deliberately *not* every index something was blind under. The two cases
    /// are different:
    ///
    /// * a **cap** — this walk had mappings left to report and stopped. Another
    ///   space walking the identical subtree has its own budget and would see
    ///   more, so pruning there would drop owners that could have been found.
    /// * a **blind spot** — an unreadable table, a suppressed uniform table, an
    ///   unresolved prototype PTE. These are properties of the *tables
    ///   themselves*, and a byte-identical subtree is the same tables: another
    ///   space walking it would be blind in exactly the same places and see
    ///   nothing more. Pruning loses nothing, and the blindness is still
    ///   reported on this walk's own outcome, which is what shortens the
    ///   answer.
    ///
    /// Marking the second case would make the parity useless on any real
    /// Windows image — every space has suppressed tables and trimmed shared
    /// pages in it — and would buy no coverage at all.
    pub incomplete_top_indices: Vec<usize>,
    /// Whether the caller's sink stopped the walk.
    pub stopped_by_sink: bool,
    /// Whether the top table itself would not read, in which case the space was
    /// not assessed at all and holds no claim of emptiness.
    pub root_unreadable: bool,
}

impl EnumerateOutcome {
    /// Whether everything this space holds was enumerated: nothing blind,
    /// nothing capped, nothing stopped, and the root read.
    ///
    /// The only thing that makes a negative answer about a physical frame
    /// sayable. A caller that publishes "no address space maps this frame"
    /// without this being true for every space walked has published a
    /// conclusion from silence.
    pub fn is_complete(&self) -> bool {
        !self.root_unreadable
            && !self.stopped_by_sink
            && self.caps_reached.is_empty()
            && self.blind_bytes == 0
            && self.tables_unreadable == 0
            && self.uniform_tables_suppressed == 0
            && self.prototypes_unresolved == 0
    }

    fn note_cap(&mut self, cap: EnumerateCap) {
        if !self.caps_reached.contains(&cap) {
            self.caps_reached.push(cap);
        }
    }

    /// Every top-level index from `from` up, because a walk that stopped at a
    /// ceiling never reached any of them.
    ///
    /// Marking only the index the cap fired *under* left every later index
    /// looking fully enumerated, so another space's byte-identical subtree
    /// there would be pruned against a subtree the reference walk never
    /// entered. The harm was bounded — a cap makes every answer declare itself
    /// short — but the parity would have been wrong, and a bound that depends
    /// on another mechanism reporting correctly is not one to leave in place.
    fn note_incomplete_from(&mut self, from: usize, levels: usize) {
        for index in from..levels {
            self.note_incomplete(index);
        }
    }

    fn note_incomplete(&mut self, index: usize) {
        if !self.incomplete_top_indices.contains(&index) {
            self.incomplete_top_indices.push(index);
        }
    }
}

/// The state one enumeration carries as it descends.
struct Descent<'w, 'l, 's> {
    walk: &'w PageWalk<'w>,
    /// The directory table base this space is rooted at. The prototype hop is
    /// the only thing that needs it, and it must be the base the outer walk
    /// used: the prototype array is mapped into *this* space.
    dtb: u64,
    limits: &'l EnumerateLimits<'l>,
    sink: &'s mut dyn MappingSink,
    outcome: EnumerateOutcome,
    /// The path of indices to the table being read, for reconstructing an
    /// address. Never longer than the level count.
    indices: Vec<u64>,
    /// The run being built, held back so the next page can extend it.
    pending: Option<MappingRun>,
    /// Which top-level index the descent is under, so incompleteness can be
    /// attributed to it.
    top_index: usize,
    stop: bool,
    /// Hierarchical execute-never (Intel non-leaf XD; ARM64 `PXNTable` /
    /// `UXNTable`) inherited from the entries above the table being read. Set on the way into a subtree and restored
    /// on the way out, so a sibling subtree never inherits it.
    inherited_no_execute: bool,
}

impl<'a> PageWalk<'a> {
    /// Every mapping the space rooted at `dtb` holds, reported to `sink`.
    ///
    /// The walk descends only into present entries, so it costs what the space
    /// actually maps rather than what it could address. It reads each table
    /// once, whole, and writes nothing to the entry memo — a downward walk
    /// touches each entry exactly once, so memoising them would evict every
    /// other stage's working set for a hit rate of zero.
    ///
    /// Mappings are reported in ascending virtual-address order, which is what
    /// lets adjacent pages coalesce and what makes the output of two runs over
    /// the same image byte-identical.
    ///
    /// It does not fail. A space whose top table will not read is an outcome
    /// with [`EnumerateOutcome::root_unreadable`] set and one
    /// [`Blindness::TableUnreadable`] covering the whole space — never an empty
    /// result, which would read as an address space that maps nothing.
    pub fn enumerate(
        &self,
        dtb: u64,
        limits: &EnumerateLimits<'_>,
        sink: &mut dyn MappingSink,
    ) -> EnumerateOutcome {
        let mut descent = Descent {
            walk: self,
            dtb,
            limits,
            sink,
            outcome: EnumerateOutcome::default(),
            indices: Vec::with_capacity(8),
            pending: None,
            top_index: 0,
            stop: false,
            inherited_no_execute: false,
        };
        descent.run(dtb);
        descent.finish()
    }
}

impl Descent<'_, '_, '_> {
    /// The whole walk of one space.
    fn run(&mut self, dtb: u64) {
        let Some(table_pa) = self.walk.root_pa_of(dtb) else {
            self.outcome.root_unreadable = true;
            let blindness = Blindness::Unnameable {
                va_start: 0,
                bytes: 0,
                entry: dtb,
                detail: "the paging spec declares no top level, so this directory table base \
                         names no table",
            };
            self.blind(blindness);
            return;
        };
        self.descend(table_pa, 0);
    }

    /// Read one table and act on every entry of it.
    fn descend(&mut self, table_pa: u64, level: usize) {
        if self.stop {
            return;
        }
        let Some(level_info) = self.walk.spec().levels().get(level).copied() else {
            return;
        };
        let Some(region_bits) = self.walk.spec().region_bits_at(level) else {
            return;
        };
        // The span the whole table covers, which is the span an examiner loses
        // if it cannot be read: this level's region times its entry count.
        let table_bits = region_bits.saturating_add(level_info.index_bits);
        let table_bytes = if table_bits >= 64 {
            u64::MAX
        } else {
            1u64 << table_bits
        };
        let table_va = self.region_base();

        if self.outcome.tables_read >= self.limits.max_tables {
            self.outcome.note_cap(EnumerateCap::Tables);
            self.outcome
                .note_incomplete_from(self.top_index, self.top_level_entries());
            let blindness = Blindness::Capped {
                va_start: table_va,
                cap: EnumerateCap::Tables,
                hit: self.outcome.tables_read,
            };
            self.blind(blindness);
            self.stop = true;
            return;
        }

        let read = match self.walk.read_table(table_pa, level, 63) {
            Ok(read) => read,
            Err(err) => {
                self.outcome.tables_unreadable += 1;
                if level == 0 {
                    // The space was not assessed at all, and holds no claim
                    // that it maps nothing.
                    self.outcome.root_unreadable = true;
                }
                // Not an incomplete top index: the same physical table is
                // unreadable from every address space, so a byte-identical
                // subtree walked again is blind in the same place.
                let blindness = Blindness::TableUnreadable {
                    va_start: table_va,
                    bytes: table_bytes,
                    table_pa,
                    level: level as u8,
                    level_name: level_info.name,
                    detail: err.to_string(),
                    unmapped: err.hole_reason() == Some(crate::layer::HoleReason::Unmapped),
                };
                self.blind(blindness);
                return;
            }
        };
        self.outcome.tables_read += 1;
        self.outcome.table_bytes_read = self.outcome.table_bytes_read.saturating_add(read.bytes);

        // The Windows unused-address filler, decided from the bytes already in
        // hand. At a terminating level the repeated entry names one frame, and
        // that frame is reported rather than lost.
        if let Some(repeated) = self.walk.uniform_filler(level, read.shape) {
            // Deliberately not the layer's own suppression counter:
            // `VirtualLayer::uniform_tables_suppressed` counts refused
            // *translations* and is published on other records, so writing a
            // count of declined *tables* into it would make a live claim
            // elsewhere false.
            self.outcome.uniform_tables_suppressed += 1;
            let leaf_frame = self.terminating_frame(repeated, level, region_bits);
            if leaf_frame.is_some() {
                self.outcome.uniform_leaf_frames += 1;
            }
            let blindness = Blindness::UniformTableSuppressed {
                va_start: table_va,
                bytes: table_bytes,
                table_pa,
                level: level as u8,
                level_name: level_info.name,
                entry: repeated,
                leaf_frame,
            };
            self.blind(blindness);
            return;
        }

        for (index, &entry) in read.entries.iter().enumerate() {
            if self.stop {
                return;
            }
            self.outcome.entries_examined += 1;
            if level == 0 {
                self.top_index = index;
            }
            self.indices.push(index as u64);
            self.entry(entry, level, region_bits);
            self.indices.pop();
        }
    }

    /// One entry of one table.
    fn entry(&mut self, entry: u64, level: usize, region_bits: u32) {
        let spec = self.walk.spec();
        let region_bytes = if region_bits >= 64 {
            u64::MAX
        } else {
            1u64 << region_bits
        };

        // A shared subtree, declined because the reference space walked it.
        //
        // Only a *present* entry: an absent one has no subtree to decline, and
        // counting the 510 empty top-level entries every space shares with
        // every other as "declined because it was walked elsewhere" would put
        // 510 meaningless rows on each process and bury the handful that
        // matter.
        if level == 0 && spec.entry_is_present(entry) {
            if let Some(parity) = self.limits.prune_against {
                if parity.shares(self.top_index, entry) {
                    self.outcome.shared_subtrees += 1;
                    let va = self.region_base();
                    let flow = self
                        .sink
                        .shared_subtree(self.top_index, entry, va, region_bytes);
                    if flow.stops() {
                        self.outcome.stopped_by_sink = true;
                        self.outcome
                            .note_incomplete_from(self.top_index, self.top_level_entries());
                        self.stop = true;
                    }
                    return;
                }
            }
        }

        // The same classifier the upward walk uses, so the two cannot
        // disagree about what an entry is or which bits of it are the frame.
        let (frame, size_log2, no_execute) = match spec.classify(entry, level) {
            None => return,
            Some(EntryKind::Invalid) => {
                self.invalid(entry, level, region_bits, region_bytes);
                return;
            }
            Some(EntryKind::Table) => {
                let Some(child) = self.walk.table_pa_of(entry, level + 1) else {
                    let blindness = Blindness::Unnameable {
                        va_start: self.region_base(),
                        bytes: region_bytes,
                        entry,
                        detail: "the paging spec declares a child table this walk cannot address",
                    };
                    self.blind(blindness);
                    return;
                };
                let outer = self.inherited_no_execute;
                self.inherited_no_execute |= spec.table_execute_never(entry, level);
                self.descend(child, level + 1);
                self.inherited_no_execute = outer;
                return;
            }
            Some(EntryKind::Unnameable { detail }) => {
                let blindness = Blindness::Unnameable {
                    va_start: self.region_base(),
                    bytes: region_bytes,
                    entry,
                    detail,
                };
                self.blind(blindness);
                return;
            }
            Some(EntryKind::Leaf {
                frame,
                size_log2,
                no_execute,
            }) => (frame, size_log2, no_execute || self.inherited_no_execute),
        };
        debug_assert_eq!(
            size_log2, region_bits,
            "the classifier and the level table agree"
        );

        let via = if (entry & PRESENT_BIT) == 0 && (entry & WINDOWS_TRANSITION_BIT) != 0 {
            RunVia::Transition
        } else {
            RunVia::PageTables
        };
        let va = self.region_base();
        self.emit(MappingRun {
            va_start: va,
            phys_start: frame,
            len: region_bytes,
            page_bytes: region_bytes,
            level: level as u8,
            no_execute,
            via,
        });
    }

    /// An entry the hardware would reject.
    fn invalid(&mut self, entry: u64, level: usize, region_bits: u32, region_bytes: u64) {
        let spec = self.walk.spec();
        match spec.classify_invalid(entry) {
            InvalidEntry::NotPresent => self.outcome.absent_entries += 1,
            InvalidEntry::PageFile { .. } => self.outcome.pagefile_entries += 1,
            InvalidEntry::LinuxSwapEntry => self.outcome.linux_swap_entries += 1,
            InvalidEntry::Prototype => {
                self.outcome.prototype_entries += 1;
                self.prototype(entry, level, region_bits, region_bytes);
            }
        }
    }

    /// A prototype PTE: the page belongs to a section object.
    fn prototype(&mut self, entry: u64, level: usize, region_bits: u32, region_bytes: u64) {
        let va = self.region_base();
        let refuse = |detail: String, outcome: &mut EnumerateOutcome| {
            outcome.prototypes_unresolved += 1;
            Blindness::PrototypeUnresolved {
                va_start: va,
                bytes: region_bytes,
                entry,
                detail,
            }
        };
        if !self.limits.resolve_prototypes {
            let blindness = refuse(
                "this walk was asked not to follow prototype PTEs".to_string(),
                &mut self.outcome,
            );
            self.blind(blindness);
            return;
        }
        // The upward walk refuses to decode `ProtoAddress` above the final
        // level, so the downward one does not ask there either.
        if region_bits != PAGE_OFFSET_BITS || level + 1 != self.walk.spec().levels().len() {
            let blindness = refuse(
                "a prototype PTE above the final level names no array this build will decode"
                    .to_string(),
                &mut self.outcome,
            );
            self.blind(blindness);
            return;
        }
        if self.outcome.prototype_hops >= self.limits.max_prototype_hops {
            self.outcome.note_cap(EnumerateCap::PrototypeHops);
            self.outcome
                .note_incomplete_from(self.top_index, self.top_level_entries());
            let blindness = Blindness::Capped {
                va_start: va,
                cap: EnumerateCap::PrototypeHops,
                hit: self.outcome.prototype_hops,
            };
            self.blind(blindness);
            return;
        }
        self.outcome.prototype_hops += 1;
        // Resolved through the shipped upward walk, with its one-hop bound and
        // its three refusals, rather than by a second decoder here: the
        // prototype array is paged pool, reachable through this same directory
        // table base, and two resolvers for one fact is how they come to
        // disagree.
        match self.walk.translate(self.dtb, va) {
            Ok(translation) => {
                let via = match translation.via {
                    crate::translate::TranslationPath::PrototypePte { proto_va, proto_pa } => {
                        RunVia::PrototypePte { proto_va, proto_pa }
                    }
                    crate::translate::TranslationPath::PageTables => RunVia::PageTables,
                };
                self.emit(MappingRun {
                    va_start: va,
                    phys_start: translation.page_base(),
                    len: translation.run_len,
                    page_bytes: translation.run_len,
                    level: translation.level,
                    no_execute: translation.no_execute,
                    via,
                });
            }
            Err(err) => {
                let blindness = refuse(err.to_string(), &mut self.outcome);
                self.blind(blindness);
            }
        }
    }

    /// How many entries this mode's top-level table has — 512, 1024 or 4,
    /// from the spec's own declaration and never a constant.
    fn top_level_entries(&self) -> usize {
        self.walk
            .spec()
            .levels()
            .first()
            .map(|level| {
                if level.index_bits >= 32 {
                    usize::MAX
                } else {
                    1usize << level.index_bits
                }
            })
            .unwrap_or(0)
    }

    /// The base address of the region the current index path describes.
    fn region_base(&self) -> u64 {
        if self.indices.is_empty() {
            return 0;
        }
        self.walk
            .spec()
            .virtual_address_from_indices(&self.indices, 0)
            .unwrap_or(0)
    }

    /// The frame a repeated entry names, when that entry terminates the walk at
    /// this level and can therefore only mean one frame.
    fn terminating_frame(&self, entry: u64, level: usize, region_bits: u32) -> Option<u64> {
        match self.walk.spec().classify(entry, level)? {
            EntryKind::Leaf {
                frame, size_log2, ..
            } if size_log2 == region_bits => Some(frame),
            _ => None,
        }
    }

    /// Report a run, extending the pending one where the tables put the two
    /// together.
    fn emit(&mut self, run: MappingRun) {
        if self.limits.coalesce {
            if let Some(pending) = self.pending.as_mut() {
                // Adjacent in BOTH spaces, same page size, same path, same
                // no-execute bit. Virtual adjacency is checked directly rather
                // than inferred from the indices, because finishing the table
                // under one parent index and resuming under a later one skips
                // whole gigabytes of address space without either table seeing
                // a gap.
                if pending.va_start.wrapping_add(pending.len) == run.va_start
                    && pending.phys_start + pending.len == run.phys_start
                    && pending.page_bytes == run.page_bytes
                    && pending.via == run.via
                    && pending.no_execute == run.no_execute
                {
                    pending.len = pending.len.saturating_add(run.len);
                    return;
                }
            }
        }
        let previous = self.pending.replace(run);
        if let Some(previous) = previous {
            self.flush(previous);
        }
    }

    /// Hand one finished run to the sink.
    fn flush(&mut self, run: MappingRun) {
        if self.outcome.runs >= self.limits.max_runs {
            self.outcome.note_cap(EnumerateCap::Runs);
            self.outcome
                .note_incomplete_from(self.top_index, self.top_level_entries());
            let blindness = Blindness::Capped {
                va_start: run.va_start,
                cap: EnumerateCap::Runs,
                hit: self.outcome.runs,
            };
            self.blind(blindness);
            self.stop = true;
            return;
        }
        self.outcome.runs += 1;
        self.outcome.pages = self.outcome.pages.saturating_add(run.pages());
        self.outcome.bytes_mapped = self.outcome.bytes_mapped.saturating_add(run.len);
        if self.sink.run(&run).stops() {
            self.outcome.stopped_by_sink = true;
            self.outcome
                .note_incomplete_from(self.top_index, self.top_level_entries());
            self.stop = true;
        }
    }

    /// Hand one blindness to the sink, and account for the span it covers.
    fn blind(&mut self, blindness: Blindness) {
        if !blindness.covers_the_rest() {
            let (_, bytes) = blindness.span();
            self.outcome.blind_bytes = self.outcome.blind_bytes.saturating_add(bytes);
        }
        if self.sink.blind(&blindness).stops() {
            self.outcome.stopped_by_sink = true;
            self.outcome
                .note_incomplete_from(self.top_index, self.top_level_entries());
            self.stop = true;
        }
    }

    /// Flush the last run and hand back what the walk measured.
    ///
    /// A sink that asked to stop is handed nothing further, including the run
    /// held back for coalescing: "stop" means stop. The mapping is not lost
    /// silently — [`EnumerateOutcome::stopped_by_sink`] is set, and a caller
    /// that stopped the walk knows its own answer is short.
    fn finish(mut self) -> EnumerateOutcome {
        if let Some(pending) = self.pending.take() {
            if !self.stop {
                self.flush(pending);
            }
        }
        self.outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translate::spec::{
        PagingMode, PteSemantics, LARGE_PAGE_BIT, WINDOWS_PROTOTYPE_BIT,
        WINDOWS_X64_PROTO_ADDRESS_SHIFT,
    };
    use crate::translate::test_image::{Harness, Image};

    /// A sink that keeps everything, for a test to assert on.
    #[derive(Default)]
    struct Collect {
        runs: Vec<MappingRun>,
        blind: Vec<Blindness>,
        shared: Vec<(usize, u64, u64, u64)>,
        stop_after: Option<usize>,
    }

    impl MappingSink for Collect {
        fn run(&mut self, run: &MappingRun) -> SinkFlow {
            self.runs.push(*run);
            match self.stop_after {
                Some(limit) if self.runs.len() >= limit => SinkFlow::Stop,
                _ => SinkFlow::Continue,
            }
        }
        fn blind(&mut self, blindness: &Blindness) -> SinkFlow {
            self.blind.push(blindness.clone());
            SinkFlow::Continue
        }
        fn shared_subtree(
            &mut self,
            index: usize,
            entry: u64,
            va_start: u64,
            bytes: u64,
        ) -> SinkFlow {
            self.shared.push((index, entry, va_start, bytes));
            SinkFlow::Continue
        }
    }

    /// The hierarchy most of these tests run over: PML4 at 0x1000 with two
    /// present top-level entries, one in each canonical half.
    ///
    /// Lower half (PML4 0) -> PDPT 0x2000 -> PD 0x3000 -> PT 0x4000, which
    /// maps three 4 KiB pages: indices 1, 2 and 4. Indices 1 and 2 are
    /// physically adjacent (0x5000, 0x6000) so they coalesce; index 4 is not.
    ///
    /// Upper half (PML4 256) -> PDPT 0x7000 -> a 1 GiB large page at
    /// 0x4000_0000.
    fn two_halves() -> Image {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 0, 0x4000 | PRESENT_BIT);
        image.entry64(0x4000, 1, 0x5000 | PRESENT_BIT);
        image.entry64(0x4000, 2, 0x6000 | PRESENT_BIT);
        image.entry64(0x4000, 4, 0x8000 | PRESENT_BIT);
        image.entry64(0x1000, 256, 0x7000 | PRESENT_BIT);
        image.entry64(0x7000, 1, 0x4000_0000 | PRESENT_BIT | LARGE_PAGE_BIT);
        image
    }

    fn enumerate(harness: &Harness, dtb: u64) -> (Collect, EnumerateOutcome) {
        let mut sink = Collect::default();
        let outcome = harness
            .walk()
            .enumerate(dtb, &EnumerateLimits::default(), &mut sink);
        (sink, outcome)
    }

    #[test]
    fn every_mapping_the_tables_hold_is_reported_with_the_address_it_is_mapped_at() {
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        // Three lower-half pages, two of which coalesce, plus the 1 GiB page.
        assert_eq!(
            sink.runs
                .iter()
                .map(|r| (r.va_start, r.phys_start, r.len, r.page_bytes))
                .collect::<Vec<_>>(),
            vec![
                (0x1000, 0x5000, 0x2000, 0x1000),
                (0x4000, 0x8000, 0x1000, 0x1000),
                (0xFFFF_8000_4000_0000, 0x4000_0000, 0x4000_0000, 0x4000_0000),
            ],
            "the mappings, in ascending virtual-address order"
        );
        assert_eq!(outcome.runs, 3);
        assert_eq!(outcome.pages, 3 + 1, "the 1 GiB page is one page");
        assert!(
            outcome.is_complete(),
            "nothing was blind or capped: {outcome:?}"
        );
        assert!(sink.blind.is_empty(), "{:?}", sink.blind);
    }

    #[test]
    fn a_kernel_mapping_is_reported_at_its_sign_extended_address() {
        // The whole reason the reconstruction exists. Reported without the
        // extension, 0xFFFF_8000_4000_0000 would read as 0x4000_0000 -- an
        // ordinary user-space address that no examiner would question.
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let (sink, _) = enumerate(&harness, 0x1000);
        let kernel = sink
            .runs
            .iter()
            .find(|r| r.phys_start == 0x4000_0000)
            .expect("the large page");
        assert_eq!(kernel.va_start, 0xFFFF_8000_4000_0000);
        assert!(
            harness.spec_is_canonical(kernel.va_start),
            "a reported address the hardware could not issue is not an address"
        );
    }

    #[test]
    fn enumerate_agrees_with_translate_on_every_mapping_it_reports() {
        // The two walkers read the same bytes with the same spec, so they must
        // agree; if they ever do not, one of them is publishing an address the
        // other would contradict, and nothing on the row would say which.
        for (mode, image, dtb) in [
            (PagingMode::Intel32e, two_halves(), 0x1000u64),
            (PagingMode::Intel32, intel32_image(), 0x1000),
            (PagingMode::IntelPae, pae_image(), 0x1000),
            // A 2 MiB page and a PAE 2 MiB page: the module doc claims every
            // shape, and the three above hold a 4 KiB page, a 4 MiB page and
            // a 1 GiB page but no 2 MiB one.
            (PagingMode::Intel32e, two_megabyte_image(), 0x1000),
            (PagingMode::IntelPae, pae_large_image(), 0x1000),
            // And the five-level mode, whose extra level is the one place the
            // index reconstruction has a different sign bit.
            (PagingMode::Intel32eLa57, la57_two_halves(), 0x1000),
        ] {
            let harness = Harness::new(image, mode, PteSemantics::Bare);
            let (sink, _) = enumerate(&harness, dtb);
            assert!(!sink.runs.is_empty(), "{mode} mapped nothing to check");
            for run in &sink.runs {
                // Both ends of the run, and one byte inside it.
                for offset in [0, run.len / 2, run.len - 1] {
                    let va = run.va_start.wrapping_add(offset);
                    let translation = harness
                        .walk()
                        .translate(dtb, va)
                        .unwrap_or_else(|err| panic!("{mode}: {va:#x} did not translate: {err}"));
                    assert_eq!(
                        translation.phys,
                        run.phys_start + offset,
                        "{mode}: the two walkers disagree about {va:#x}"
                    );
                    assert_eq!(translation.run_len, run.page_bytes, "{mode}: page size");
                    assert_eq!(translation.level, run.level, "{mode}: level");
                    assert_eq!(translation.no_execute, run.no_execute, "{mode}: nx");
                }
            }
        }
    }

    /// A 2 MiB page: PML4 0 -> PDPT 0 -> a large page-directory entry.
    fn two_megabyte_image() -> Image {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 1, 0x20_0000 | PRESENT_BIT | LARGE_PAGE_BIT);
        image
    }

    /// PAE's own 2 MiB page, through its 32-byte pointer table.
    fn pae_large_image() -> Image {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 1, 0x20_0000 | PRESENT_BIT | LARGE_PAGE_BIT);
        image
    }

    /// Five levels, with one mapping in each canonical half. The upper half is
    /// reached through PML5 index 256, where LA57's sign bit is bit 56 rather
    /// than bit 47.
    fn la57_two_halves() -> Image {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 0, 0x4000 | PRESENT_BIT);
        image.entry64(0x4000, 0, 0x5000 | PRESENT_BIT);
        image.entry64(0x5000, 1, 0x9000 | PRESENT_BIT);
        image.entry64(0x1000, 256, 0x6000 | PRESENT_BIT);
        image.entry64(0x6000, 0, 0x7000 | PRESENT_BIT);
        image.entry64(0x7000, 0, 0x8000 | PRESENT_BIT);
        image.entry64(0x8000, 0, 0xA000 | PRESENT_BIT);
        image.entry64(0xA000, 2, 0xB000 | PRESENT_BIT);
        image
    }

    #[test]
    fn a_five_level_walk_reports_its_kernel_half_at_the_address_la57_gives_it() {
        // LA57's sign bit is bit 56, not bit 47, so an address rebuilt with
        // the four-level rule would be 0xFFFF_FE00_0000_0000 out -- and still
        // canonical, which is what makes it dangerous.
        let harness = Harness::new(
            la57_two_halves(),
            PagingMode::Intel32eLa57,
            PteSemantics::Bare,
        );
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert!(outcome.is_complete(), "{outcome:?}");
        assert_eq!(
            sink.runs
                .iter()
                .map(|r| (r.va_start, r.phys_start))
                .collect::<Vec<_>>(),
            vec![(0x1000, 0x9000), (0xFF00_0000_0000_2000, 0xB000)],
        );
        for run in &sink.runs {
            assert!(
                harness.spec_is_canonical(run.va_start),
                "{:#x} is not an address the hardware could issue",
                run.va_start
            );
        }
    }

    /// 32-bit non-PAE: a page directory at 0x1000 with a 4 KiB page through
    /// a page table at 0x2000, and a 4 MiB page at directory index 2.
    fn intel32_image() -> Image {
        let mut image = Image::new();
        image.entry32(0x1000, 0, 0x2000 | PRESENT_BIT as u32);
        image.entry32(0x2000, 1, 0x3000 | PRESENT_BIT as u32);
        image.entry32(
            0x1000,
            2,
            0x0080_0000 | PRESENT_BIT as u32 | LARGE_PAGE_BIT as u32,
        );
        image
    }

    /// PAE: a 32-byte pointer table at 0x1000, a page directory at 0x2000 and
    /// a page table at 0x3000 mapping one page.
    fn pae_image() -> Image {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 1, 0x5000 | PRESENT_BIT);
        image
    }

    #[test]
    fn a_pae_pointer_table_is_read_at_its_own_size_and_not_as_a_page() {
        // PAE's pointer table is 32 bytes. Reading 4 KiB there would take 127
        // neighbouring tables into it and report 508 mappings that do not
        // exist.
        let harness = Harness::new(pae_image(), PagingMode::IntelPae, PteSemantics::Bare);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(
            sink.runs.iter().map(|r| r.va_start).collect::<Vec<_>>(),
            vec![0x1000],
            "one mapping, not five hundred"
        );
        assert_eq!(outcome.entries_examined, 4 + 512 + 512, "4 + 512 + 512");
    }

    #[test]
    fn a_table_that_will_not_read_is_a_named_span_rather_than_an_absence() {
        // "The walk could not look here" and "nothing is mapped here" are
        // different findings, and an enumeration that reported the first as
        // the second would let a report say a process mapped nothing in 2 MiB
        // it was never able to examine.
        let mut image = two_halves();
        // Short of the upper half's pointer table at 0x7000, and no shorter:
        // the lower half's tables are all below it and must still be walked.
        image.bytes.truncate(0x7000);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(outcome.tables_unreadable, 1, "the upper half's PDPT");
        let unreadable = sink
            .blind
            .iter()
            .find_map(|b| match b {
                Blindness::TableUnreadable {
                    va_start,
                    bytes,
                    table_pa,
                    level_name,
                    ..
                } => Some((*va_start, *bytes, *table_pa, *level_name)),
                _ => None,
            })
            .expect("the unreadable table is reported");
        assert_eq!(unreadable.2, 0x7000, "the table that would not read");
        assert_eq!(unreadable.3, "page directory pointer table");
        assert_eq!(
            unreadable.0, 0xFFFF_8000_0000_0000,
            "the span begins at the kernel half's base"
        );
        assert_eq!(unreadable.1, 1 << 39, "a PDPT covers 512 GiB");
        assert!(
            !outcome.is_complete(),
            "a space with an unreadable table is not fully enumerated"
        );
        assert!(
            outcome.incomplete_top_indices.is_empty(),
            "an unreadable table is not a reason to walk another space's identical subtree: \
             the same physical table is unreadable from every address space, so a second walk \
             is blind in the same place and sees nothing more"
        );
        // And the lower half is still reported: one unreadable table loses its
        // own subtree and nothing else.
        assert_eq!(outcome.runs, 2);
    }

    #[test]
    fn an_unreadable_top_table_leaves_the_space_unassessed_rather_than_empty() {
        let mut image = Image::new();
        image.bytes.truncate(0x800);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert!(outcome.root_unreadable, "the space was never assessed");
        assert_eq!(outcome.runs, 0);
        assert!(!outcome.is_complete());
        assert_eq!(sink.blind.len(), 1);
        assert_eq!(
            sink.blind[0].reason(),
            IncompleteReason::ShortRead,
            "the evidence file would not read; the acquisition claims nothing"
        );
    }

    #[test]
    fn a_uniform_windows_table_at_the_final_level_still_names_its_one_frame() {
        // 512 byte-identical present PTEs name exactly one frame, at 512
        // virtual addresses. Reporting that table as pure blindness throws
        // away a frame that is knowable with no further reading -- and it is
        // the frame an examiner asking "who maps this offset?" may be asking
        // about.
        let mut image = two_halves();
        for index in 0..512 {
            image.entry64(0x4000, index, 0x9000 | PRESENT_BIT);
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(outcome.uniform_tables_suppressed, 1);
        assert_eq!(outcome.uniform_leaf_frames, 1);
        let (bytes, frame) = sink
            .blind
            .iter()
            .find_map(|b| match b {
                Blindness::UniformTableSuppressed {
                    bytes, leaf_frame, ..
                } => Some((*bytes, *leaf_frame)),
                _ => None,
            })
            .expect("the suppression is reported");
        assert_eq!(frame, Some(0x9000), "the one frame those 512 entries name");
        assert_eq!(bytes, 1 << 21, "a page table covers 2 MiB");
        assert!(
            sink.blind[0].statement().contains("0x9000"),
            "the sentence names the frame: {}",
            sink.blind[0].statement()
        );
    }

    #[test]
    fn a_uniform_table_above_the_final_level_names_no_frame_because_it_has_none() {
        // Identical page-directory entries point at the same page *table*, and
        // the frames beneath it are genuinely unknown. Naming one would be an
        // invention.
        let mut image = two_halves();
        for index in 0..512 {
            image.entry64(0x3000, index, 0x4000 | PRESENT_BIT);
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(outcome.uniform_tables_suppressed, 1);
        assert_eq!(outcome.uniform_leaf_frames, 0);
        assert!(sink.blind.iter().any(|b| matches!(
            b,
            Blindness::UniformTableSuppressed {
                leaf_frame: None,
                bytes,
                ..
            } if *bytes == 1 << 30
        )));
    }

    #[test]
    fn an_all_zero_table_is_ordinary_absence_and_not_a_suppression() {
        // The commonest structure in any image. Counting it as a suppression
        // would put a blind-spot row on every process in the case.
        let mut image = two_halves();
        for index in 0..512 {
            image.entry64(0x4000, index, 0);
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let (_, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(outcome.uniform_tables_suppressed, 0);
        // PML4 510, the lower PDPT 511, the PD 511, the zeroed PT 512, the
        // upper PDPT 511.
        assert_eq!(outcome.absent_entries, 510 + 511 + 511 + 512 + 511);
    }

    #[test]
    fn the_uniform_heuristic_is_a_windows_convention_and_does_not_fire_elsewhere() {
        let mut image = two_halves();
        for index in 0..512 {
            image.entry64(0x4000, index, 0x9000 | PRESENT_BIT);
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(outcome.uniform_tables_suppressed, 0);
        assert_eq!(
            sink.runs.iter().filter(|r| r.phys_start == 0x9000).count(),
            512,
            "512 identical entries are 512 virtual pages of ONE frame, and they do \
             not coalesce: coalescing needs the frames to be adjacent too"
        );
        assert_eq!(outcome.runs, 512 + 1, "512 pages plus the large page");
    }

    #[test]
    fn a_not_present_entry_is_counted_and_is_not_a_blind_spot() {
        // There is no frame behind it in this image, so it cannot hide the
        // owner of a physical offset. Reporting it as blindness would bury
        // every real gap under 100,000 rows.
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert!(outcome.absent_entries > 1000);
        assert!(sink.blind.is_empty());
        assert_eq!(outcome.blind_bytes, 0);
    }

    #[test]
    fn a_pagefile_entry_is_counted_apart_from_a_page_that_was_never_mapped() {
        let mut image = two_halves();
        // MMPTE_SOFTWARE: not present, no prototype or transition bit, a
        // non-zero PageFileHigh above bit 32.
        image.entry64(0x4000, 6, 0x0000_0007_0000_0000);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let (_, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(outcome.pagefile_entries, 1);
    }

    #[test]
    fn a_prototype_pte_is_followed_into_the_section_and_reported_as_shared() {
        // A DLL's pages are reached this way and no other. An enumeration that
        // stopped here would report a mapped system library as absent from
        // every process that had it open.
        let mut image = two_halves();
        // A prototype PTE at PT index 8, naming a prototype array entry whose
        // own address is reachable through the same tables.
        let proto_va = 0x3000u64;
        let entry = (proto_va << WINDOWS_X64_PROTO_ADDRESS_SHIFT) | WINDOWS_PROTOTYPE_BIT;
        image.entry64(0x4000, 8, entry);
        // 0x3000 translates through PML4 0 / PDPT 0 / PD 0 / PT 3, so put a
        // page there, and make its contents the prototype _MMPTE.
        image.entry64(0x4000, 3, 0xA000 | PRESENT_BIT);
        image.entry64(0xA000, 0, 0xB000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(outcome.prototype_entries, 1);
        assert_eq!(outcome.prototype_hops, 1);
        assert_eq!(outcome.prototypes_unresolved, 0);
        let shared = sink
            .runs
            .iter()
            .find(|r| r.via.is_shared())
            .expect("the section-backed page is reported");
        assert_eq!(shared.va_start, 0x8000);
        assert_eq!(shared.phys_start, 0xB000);
        assert!(
            matches!(shared.via, RunVia::PrototypePte { proto_va: v, .. } if v == proto_va),
            "the array entry it came from travels with it: {:?}",
            shared.via
        );
    }

    #[test]
    fn a_prototype_pte_this_build_will_not_decode_is_a_stated_gap() {
        let mut image = two_halves();
        // MI_PTE_LOOKUP_NEEDED: `ProtoAddress` (bits 63:16) is all ones, and
        // Windows itself recomputes the address from the subsection chain. The
        // present bit stays clear, or this would not be a prototype entry at
        // all.
        image.entry64(0x4000, 8, 0xFFFF_FFFF_FFFF_0000 | WINDOWS_PROTOTYPE_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(outcome.prototype_entries, 1);
        assert_eq!(outcome.prototypes_unresolved, 1);
        assert!(!outcome.is_complete());
        let gap = sink
            .blind
            .iter()
            .find(|b| matches!(b, Blindness::PrototypeUnresolved { .. }))
            .expect("the unresolved prototype is reported");
        assert_eq!(gap.reason(), IncompleteReason::UnresolvedStructure);
        assert_eq!(gap.span(), (0x8000, 0x1000));
    }

    #[test]
    fn a_walk_told_not_to_follow_prototypes_says_what_that_cost() {
        let mut image = two_halves();
        let entry = (0x3000u64 << WINDOWS_X64_PROTO_ADDRESS_SHIFT) | WINDOWS_PROTOTYPE_BIT;
        image.entry64(0x4000, 8, entry);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let mut sink = Collect::default();
        let limits = EnumerateLimits {
            resolve_prototypes: false,
            ..EnumerateLimits::default()
        };
        let outcome = harness.walk().enumerate(0x1000, &limits, &mut sink);
        assert_eq!(outcome.prototype_hops, 0, "none was taken");
        assert_eq!(outcome.prototypes_unresolved, 1);
        assert!(sink.blind.iter().any(|b| b
            .statement()
            .contains("prototype PTE that was not resolved")));
    }

    #[test]
    fn a_transition_page_is_reported_as_one_rather_than_as_an_ordinary_mapping() {
        // A page on the standby list: its frame is still in RAM and still
        // holds the bytes, and the hardware would have faulted. Both facts
        // belong on the row, and `translate` cannot carry the second.
        let mut image = two_halves();
        image.entry64(0x4000, 9, 0xC000 | WINDOWS_TRANSITION_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let (sink, _) = enumerate(&harness, 0x1000);
        let transition = sink
            .runs
            .iter()
            .find(|r| r.va_start == 0x9000)
            .expect("the standby page is reported");
        assert_eq!(transition.via, RunVia::Transition);
        assert_eq!(transition.phys_start, 0xC000);
        // And the upward walk agrees about where it is, even though it cannot
        // say that it was a transition entry.
        let translation = harness.walk().translate(0x1000, 0x9000).expect("resident");
        assert_eq!(translation.phys, 0xC000);
    }

    #[test]
    fn a_subtree_the_reference_space_already_walked_is_declined_and_named() {
        // The whole kernel half is the same tables in every process. Walking
        // it 130 times reports every kernel mapping 130 times and costs 130
        // times the reads; declining it is exact rather than heuristic,
        // because identical entries point at the same table.
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let parity = RootParity::of(&harness.walk(), 0x1000).expect("the reference top table");
        let mut sink = Collect::default();
        let limits = EnumerateLimits {
            prune_against: Some(&parity),
            ..EnumerateLimits::default()
        };
        let outcome = harness.walk().enumerate(0x1000, &limits, &mut sink);
        assert_eq!(outcome.runs, 0, "every subtree was the reference's own");
        assert_eq!(outcome.shared_subtrees, 2);
        assert_eq!(
            sink.shared
                .iter()
                .map(|&(index, _, va, bytes)| (index, va, bytes))
                .collect::<Vec<_>>(),
            vec![(0, 0, 1 << 39), (256, 0xFFFF_8000_0000_0000, 1 << 39)],
            "each declined subtree names the span it covers"
        );
    }

    #[test]
    fn a_subtree_the_reference_walk_did_not_finish_is_walked_again_rather_than_pruned() {
        // The one way parity can hide an owner. If the reference space's own
        // descent of an index was capped or blind, the mappings under it were
        // never reported -- and pruning another space against it would drop
        // every owner beneath while the record still said the subtree was
        // "named once elsewhere".
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let mut parity = RootParity::of(&harness.walk(), 0x1000).expect("the top table");
        parity.mark_incomplete(0);
        assert_eq!(parity.incomplete_indices(), 1);
        let mut sink = Collect::default();
        let limits = EnumerateLimits {
            prune_against: Some(&parity),
            ..EnumerateLimits::default()
        };
        let outcome = harness.walk().enumerate(0x1000, &limits, &mut sink);
        assert_eq!(outcome.shared_subtrees, 1, "only the upper half was pruned");
        assert_eq!(
            sink.runs.iter().map(|r| r.va_start).collect::<Vec<_>>(),
            vec![0x1000, 0x4000],
            "the lower half was walked, so its mappings are still attributable"
        );
    }

    #[test]
    fn only_a_budget_that_ran_out_stops_another_space_from_pruning_a_shared_subtree() {
        // The distinction the parity's correctness rests on, in both
        // directions.
        //
        // A **cap** is a property of this walk: it had mappings left to report
        // and stopped, and another space walking the identical subtree has its
        // own budget and would see more. Pruning there would drop owners that
        // could have been found.
        //
        // A **blind spot** is a property of the tables: an unreadable table, a
        // suppressed uniform table, an unresolved prototype PTE. A
        // byte-identical subtree is the same tables, so a second walk is blind
        // in exactly the same places. Marking these would make the parity
        // useless on any real Windows image -- every space has suppressed
        // tables and trimmed shared pages in it -- and would buy no coverage.
        let mut image = two_halves();
        for index in 0..512 {
            image.entry64(0x4000, index, 0x9000 | PRESENT_BIT);
        }
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Windows);
        let (_, blind) = enumerate(&harness, 0x1000);
        assert_eq!(
            blind.uniform_tables_suppressed, 1,
            "the walk was blind here"
        );
        assert!(
            blind.incomplete_top_indices.is_empty(),
            "and blindness in shared tables is reproduced, not recovered, by walking again"
        );

        let mut sink = Collect::default();
        let limits = EnumerateLimits {
            max_tables: 2,
            ..EnumerateLimits::default()
        };
        let capped = harness.walk().enumerate(0x1000, &limits, &mut sink);
        assert_eq!(capped.caps_reached, vec![EnumerateCap::Tables]);
        // Every index from the one it stopped under, not just that one: the
        // walk abandons the rest of the top-level table, so those subtrees
        // were never entered either. Marking only the stop index left them
        // looking fully enumerated, and another space's byte-identical subtree
        // there would have been pruned against a subtree nothing had walked.
        assert_eq!(
            capped.incomplete_top_indices.len(),
            512,
            "a walk that ran out of budget had more to say about everything it did not reach"
        );
        assert_eq!(capped.incomplete_top_indices[0], 0);
        assert_eq!(capped.incomplete_top_indices[511], 511);
    }

    #[test]
    fn a_cap_under_one_index_does_not_leave_the_indices_after_it_looking_finished() {
        // The specific hole: the walk stops at index 0's subtree, so index 256
        // is never entered at all. If the parity thought 256 was complete, a
        // process sharing that entry would have its kernel-half mappings
        // dropped with nothing saying so.
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let mut sink = Collect::default();
        let limits = EnumerateLimits {
            max_tables: 3,
            ..EnumerateLimits::default()
        };
        let outcome = harness.walk().enumerate(0x1000, &limits, &mut sink);
        assert!(!outcome.caps_reached.is_empty());
        assert!(
            outcome.incomplete_top_indices.contains(&256),
            "the upper half was never reached, so nothing may be pruned against it"
        );

        let mut parity = RootParity::of(&harness.walk(), 0x1000).expect("the top table");
        for &index in &outcome.incomplete_top_indices {
            parity.mark_incomplete(index);
        }
        assert_eq!(parity.incomplete_indices(), 512);
        // And a space compared against that parity is walked whole rather
        // than pruned.
        let mut sink = Collect::default();
        let pruned = EnumerateLimits {
            prune_against: Some(&parity),
            ..EnumerateLimits::default()
        };
        let again = harness.walk().enumerate(0x1000, &pruned, &mut sink);
        assert_eq!(again.shared_subtrees, 0);
        assert_eq!(again.runs, 3, "every mapping is found again");
    }

    #[test]
    fn a_walk_that_stopped_at_its_table_ceiling_says_so_with_the_number_it_hit() {
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let mut sink = Collect::default();
        let limits = EnumerateLimits {
            max_tables: 2,
            ..EnumerateLimits::default()
        };
        let outcome = harness.walk().enumerate(0x1000, &limits, &mut sink);
        assert_eq!(outcome.tables_read, 2);
        assert_eq!(outcome.caps_reached, vec![EnumerateCap::Tables]);
        assert!(!outcome.is_complete());
        let capped = sink
            .blind
            .iter()
            .find(|b| matches!(b, Blindness::Capped { .. }))
            .expect("the ceiling is reported");
        assert_eq!(capped.reason(), IncompleteReason::CapReached);
        assert!(
            capped.covers_the_rest(),
            "a ceiling costs everything after it, which is not a span"
        );
        assert_eq!(
            outcome.blind_bytes, 0,
            "and so contributes no number that would understate it"
        );
    }

    #[test]
    fn a_walk_the_caller_stopped_is_never_reported_as_one_that_finished() {
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let mut sink = Collect {
            stop_after: Some(1),
            ..Collect::default()
        };
        let outcome = harness
            .walk()
            .enumerate(0x1000, &EnumerateLimits::default(), &mut sink);
        assert!(outcome.stopped_by_sink);
        assert!(!outcome.is_complete());
        assert_eq!(sink.runs.len(), 1);
    }

    #[test]
    fn adjacent_pages_coalesce_only_where_the_tables_put_them_together() {
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let mut sink = Collect::default();
        let limits = EnumerateLimits {
            coalesce: false,
            ..EnumerateLimits::default()
        };
        let outcome = harness.walk().enumerate(0x1000, &limits, &mut sink);
        assert_eq!(
            outcome.runs, 4,
            "uncoalesced: three pages and the large one"
        );
        assert_eq!(
            sink.runs.iter().map(|r| r.len).collect::<Vec<_>>(),
            vec![0x1000, 0x1000, 0x1000, 0x4000_0000]
        );
    }

    #[test]
    fn a_run_never_spans_a_gap_in_either_space() {
        // Two pages adjacent in physical memory but a gigabyte apart
        // virtually, and two adjacent virtually whose frames are not. Merging
        // either would name bytes that are not there.
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x2000, 1, 0x6000 | PRESENT_BIT);
        image.entry64(0x3000, 0, 0x4000 | PRESENT_BIT);
        image.entry64(0x4000, 0, 0x8000 | PRESENT_BIT);
        // Virtually adjacent, physically not.
        image.entry64(0x4000, 1, 0xF000 | PRESENT_BIT);
        // Physically adjacent to the first, but a gigabyte away in the space.
        image.entry64(0x6000, 0, 0x7000 | PRESENT_BIT);
        image.entry64(0x7000, 0, 0x9000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let (sink, _) = enumerate(&harness, 0x1000);
        assert_eq!(
            sink.runs
                .iter()
                .map(|r| (r.va_start, r.phys_start, r.len))
                .collect::<Vec<_>>(),
            vec![
                (0x0, 0x8000, 0x1000),
                (0x1000, 0xF000, 0x1000),
                (0x4000_0000, 0x9000, 0x1000),
            ],
            "three runs: neither pair merged"
        );
    }

    #[test]
    fn a_frame_two_address_spaces_map_is_found_from_both_of_them() {
        // The roadmap's grading criterion, at the level the enumeration can be
        // held to it: the same frame reached through two different directory
        // table bases, at two different virtual addresses, and both walks find
        // it. Nothing here chooses one of them.
        let mut image = Image::new();
        // Space A: dtb 0x1000, maps frame 0x9000 at 0x1000.
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 0, 0x4000 | PRESENT_BIT);
        image.entry64(0x4000, 1, 0x9000 | PRESENT_BIT);
        // Space B: dtb 0x10000, maps the same frame at 0x20_2000.
        image.entry64(0x10000, 0, 0x11000 | PRESENT_BIT);
        image.entry64(0x11000, 0, 0x12000 | PRESENT_BIT);
        image.entry64(0x12000, 1, 0x13000 | PRESENT_BIT);
        image.entry64(0x13000, 2, 0x9000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let (a, _) = enumerate(&harness, 0x1000);
        let (b, _) = enumerate(&harness, 0x10000);
        let owners: Vec<u64> = [&a, &b]
            .iter()
            .flat_map(|sink| {
                sink.runs
                    .iter()
                    .filter(|r| r.holds(0x9040))
                    .filter_map(|r| r.virtual_address_of(0x9040))
            })
            .collect();
        assert_eq!(
            owners,
            vec![0x1040, 0x20_2040],
            "both spaces name the frame, each at its own virtual address"
        );
    }

    #[test]
    fn a_self_referential_table_terminates_because_the_level_count_bounds_it() {
        // The classic hostile hierarchy: a top-level entry pointing at its own
        // table. The descent is bounded by the level count, which is a
        // structural property rather than a guard that could be forgotten.
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x1000 | PRESENT_BIT);
        let harness = Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert_eq!(outcome.tables_read, 4, "one per level, and then it ends");
        assert_eq!(sink.runs.len(), 1, "the final level names a frame");
        assert_eq!(sink.runs[0].phys_start, 0x1000);
    }

    #[test]
    fn a_four_megabyte_entry_naming_a_frame_above_the_space_is_refused_not_masked() {
        // PSE-36 puts physical bits 39:32 in bits 20:13 of a 4 MiB
        // page-directory entry. Masking them away names an address 4 GiB or
        // more from the truth while looking entirely ordinary.
        let mut image = intel32_image();
        image.entry32(
            0x1000,
            2,
            0x0080_0000 | PRESENT_BIT as u32 | LARGE_PAGE_BIT as u32 | (1 << 13),
        );
        let harness = Harness::new(image, PagingMode::Intel32, PteSemantics::Bare);
        let (sink, outcome) = enumerate(&harness, 0x1000);
        assert!(sink.blind.iter().any(|b| matches!(
            b,
            Blindness::Unnameable { detail, .. } if detail.contains("PSE-36")
        )));
        assert_eq!(
            outcome.runs, 1,
            "the 4 KiB page is still reported; only the unnameable entry is refused"
        );
        assert_eq!(
            sink.blind[0].reason(),
            IncompleteReason::UnresolvedStructure,
            "a limit of this build, never a claim about the acquisition"
        );
    }

    #[test]
    fn the_downward_walk_writes_nothing_to_the_entry_memo() {
        // A downward walk touches each entry once and never returns to it, so
        // memoising them would cycle the whole 65,536-entry memo many times
        // over for a hit rate of zero -- evicting every other stage's working
        // set to do it.
        let harness = Harness::new(two_halves(), PagingMode::Intel32e, PteSemantics::Bare);
        let (_, outcome) = enumerate(&harness, 0x1000);
        assert!(outcome.entries_examined > 1000);
        assert!(
            harness.cache.is_empty(),
            "the enumeration left the shared memo alone"
        );
    }

    #[test]
    fn every_blindness_says_which_vocabulary_term_a_record_should_carry() {
        // A record's `incomplete` reason is read by the UI and by the report,
        // so a blindness with no term is a row that cannot be rendered.
        let cases = [
            (
                Blindness::UniformTableSuppressed {
                    va_start: 0,
                    bytes: 1 << 21,
                    table_pa: 0x4000,
                    level: 3,
                    level_name: "page table",
                    entry: PRESENT_BIT,
                    leaf_frame: None,
                },
                IncompleteReason::UnresolvedStructure,
            ),
            (
                Blindness::TableUnreadable {
                    va_start: 0,
                    bytes: 1 << 21,
                    table_pa: 0x4000,
                    level: 3,
                    level_name: "page table",
                    detail: "short".into(),
                    unmapped: true,
                },
                IncompleteReason::Unmapped,
            ),
            (
                Blindness::PrototypeUnresolved {
                    va_start: 0,
                    bytes: 0x1000,
                    entry: 0,
                    detail: "no".into(),
                },
                IncompleteReason::UnresolvedStructure,
            ),
            (
                Blindness::Unnameable {
                    va_start: 0,
                    bytes: 0x1000,
                    entry: 0,
                    detail: "no",
                },
                IncompleteReason::UnresolvedStructure,
            ),
            (
                Blindness::Capped {
                    va_start: 0,
                    cap: EnumerateCap::Runs,
                    hit: 4,
                },
                IncompleteReason::CapReached,
            ),
        ];
        for (blindness, reason) in cases {
            assert_eq!(blindness.reason(), reason, "{blindness:?}");
            assert!(
                !blindness.statement().is_empty(),
                "every blindness has a sentence: {blindness:?}"
            );
        }
    }
}
