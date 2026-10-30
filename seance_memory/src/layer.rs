//! The memory-layer contract: [`MemoryLayer`], the mapping 5-tuple, and the
//! [`MemoryHole`] error that makes unmapped memory impossible to confuse with
//! captured zeros.

use seance_core::data_source::DataSource;
use seance_core::io::IncompleteReason;
use std::io;

/// Hard cap on the number of segments a format reader may declare.
///
/// A hostile or corrupt header can claim millions of runs; building the index
/// for them is an allocation the examiner never asked for. Readers that hit
/// this must fail closed, not truncate silently.
pub const MAX_SEGMENTS: usize = 1_048_576;

/// Why a memory address has no bytes behind it.
///
/// Each variant is a *different forensic fact*, and collapsing them (or
/// rendering any of them as zeros) destroys the distinction an examiner needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoleReason {
    /// The address falls outside every segment of the acquisition. The
    /// acquisition tool never captured these bytes; nothing is known about
    /// them. This is the common case for LiME, ELF core and crash dumps, whose
    /// segment lists skip MMIO windows and reserved physical ranges.
    Unmapped,
    /// A page-table walk reached a not-present entry: the page is not resident
    /// in RAM at all.
    NotPresent,
    /// A page-table walk reached a software PTE describing a page that lives in
    /// a swap file or pagefile, and no swap layer was supplied. The bytes exist
    /// on the suspect's disk; they are simply not in this evidence item.
    SwappedOut,
    /// A page table that would have described this address was suppressed by
    /// the Windows 10 uniform-table heuristic. Recorded rather than silent, so
    /// an examiner asking "could the tool have hidden a page from me?" gets an
    /// answer.
    TableSuppressed,
}

impl HoleReason {
    /// Stable identifier for artifact metadata and log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            HoleReason::Unmapped => "unmapped",
            HoleReason::NotPresent => "not_present",
            HoleReason::SwappedOut => "swapped_out",
            HoleReason::TableSuppressed => "table_suppressed",
        }
    }
}

impl std::fmt::Display for HoleReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A read touched a region of a memory layer that has no bytes behind it.
///
/// # Why this is an error and not zeros
///
/// Volatility 3 exposes `read(..., pad=True)`, which **fabricates zero bytes**
/// for unmapped regions, and its plugins use it liberally. Under Séance's
/// invariants that is evidence fabrication, and the failure mode is not
/// theoretical:
///
/// - A page that was swapped out, smeared during acquisition, or simply never
///   captured becomes byte-identical to a page the suspect's machine genuinely
///   zeroed. "This buffer was wiped" and "we never had this buffer" are
///   opposite conclusions.
/// - The fabricated bytes then flow into hashes, carving, string search and
///   reports, where they are indistinguishable from acquired evidence. The
///   image hashes as if complete.
/// - Nothing downstream can undo it. Once the zeros exist there is no record
///   that they were invented.
///
/// So a memory layer's [`DataSource::read_at`] never zero-fills. The three
/// outcomes are kept distinct:
///
/// | Condition | `read_at` returns |
/// |---|---|
/// | Range fully mapped | `Ok(n)` with acquired bytes |
/// | `offset` past the top of the address space | `Ok(0)` — genuine EOF |
/// | Any unmapped byte inside the requested range | `Err` carrying a `MemoryHole` |
///
/// `Err` rather than `Ok(0)` is deliberate: `Ok(0)` would conflate a hole with
/// EOF. With `Err`, the existing Séance helpers already do the right thing with
/// no changes at all — [`seance_core::io::read_exact_or_fail`] refuses to parse
/// a padded structural header, [`seance_core::io::read_full`] stops at the
/// hole, and [`seance_core::io::read_capped`] truncates there. A memory-aware
/// caller recovers the exact unmapped range with [`MemoryHole::from_io`] and
/// stamps [`IncompleteReason::ShortRead`] plus that range onto the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("memory hole: {length} byte(s) at {address:#x} are {reason}")]
pub struct MemoryHole {
    /// First address in this layer's space with no bytes behind it.
    pub address: u64,
    /// How many consecutive bytes from `address` are unbacked.
    pub length: u64,
    /// Why those bytes are absent.
    pub reason: HoleReason,
}

impl MemoryHole {
    /// An unmapped gap in a segment list.
    pub fn unmapped(address: u64, length: u64) -> Self {
        Self {
            address,
            length,
            reason: HoleReason::Unmapped,
        }
    }

    /// The `IncompleteReason` a caller stamps onto an artifact whose content
    /// this hole truncated. A hole is always a short read from the consumer's
    /// point of view: the bytes the structure needed were not there.
    pub fn incomplete_reason(self) -> IncompleteReason {
        IncompleteReason::ShortRead
    }

    /// Wrap this hole in an [`io::Error`] so it travels through the ordinary
    /// [`DataSource`] contract. `InvalidData` (not `UnexpectedEof`) because the
    /// address space genuinely extends past the hole — this is not the end of
    /// the evidence.
    pub fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
    }

    /// Recover a `MemoryHole` from an [`io::Error`] produced by a memory layer,
    /// so a memory-aware caller can record the exact unmapped range instead of
    /// only knowing that "a read failed".
    pub fn from_io(err: &io::Error) -> Option<MemoryHole> {
        err.get_ref()
            .and_then(|e| e.downcast_ref::<MemoryHole>())
            .copied()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "length": self.length,
            "reason": self.reason.as_str(),
        })
    }
}

impl From<MemoryHole> for io::Error {
    fn from(hole: MemoryHole) -> Self {
        hole.into_io()
    }
}

/// Everything that can go wrong constructing or querying a memory layer.
#[derive(Debug, thiserror::Error)]
pub enum LayerError {
    /// The requested range includes bytes with nothing behind them.
    #[error(transparent)]
    Hole(#[from] MemoryHole),

    /// The address is above the top of this layer's address space. Distinct
    /// from [`LayerError::Hole`]: there is no address here at all, as opposed
    /// to an address whose bytes were not captured.
    #[error("address {address:#x} is above the layer's maximum address {max_address:#x}")]
    OutOfRange { address: u64, max_address: u64 },

    /// A read of the underlying source failed.
    #[error("underlying source read failed: {0}")]
    Io(io::Error),

    /// A format reader produced no segments. Refusing to build an empty layer
    /// keeps `min_address`/`max_address` total instead of panicking later.
    #[error("no memory segments: {0}")]
    NoSegments(String),

    /// A segment list exceeded [`MAX_SEGMENTS`].
    #[error("segment list of {count} exceeds the cap of {cap}")]
    TooManySegments { count: usize, cap: usize },

    /// A segment is individually invalid (zero length, or an end address that
    /// overflows `u64`).
    #[error("segment {index} is malformed: {detail}")]
    MalformedSegment { index: usize, detail: String },

    /// Two segments claim the same memory address. One of them is wrong and
    /// there is no principled way to choose, so the layer refuses to exist.
    #[error(
        "segments {first} and {second} overlap in the memory address space \
         (a memory address cannot have two sets of bytes behind it)"
    )]
    OverlappingSegments { first: usize, second: usize },

    /// The source is empty, so it has no address space to describe.
    #[error("cannot build a memory layer over an empty source")]
    EmptySource,
}

impl LayerError {
    /// Convert an [`io::Error`] raised by an underlying source, preserving a
    /// [`MemoryHole`] payload if one is present rather than flattening it into
    /// an opaque I/O failure.
    pub fn from_io(err: io::Error) -> Self {
        match MemoryHole::from_io(&err) {
            Some(hole) => LayerError::Hole(hole),
            None => LayerError::Io(err),
        }
    }

    /// The hole this error carries, if any.
    pub fn hole(&self) -> Option<MemoryHole> {
        match self {
            LayerError::Hole(h) => Some(*h),
            _ => None,
        }
    }
}

impl From<LayerError> for io::Error {
    fn from(err: LayerError) -> Self {
        match err {
            LayerError::Hole(hole) => hole.into_io(),
            LayerError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

/// How the bytes underneath a mapped run are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Byte-for-byte. `mapped_length == length`, and byte `n` of the run is
    /// byte `mapped_offset + n` of the underlying source.
    Identity,
    /// The run is backed by an encoded blob of `mapped_length` bytes at
    /// `mapped_offset` that decodes, as a single unit, to `length` bytes. A
    /// caller cannot address into it without decoding the whole blob.
    ///
    /// No phase-1 reader produces this; it exists because the mapping contract
    /// has to be able to express it, and AVML's snappy frames and QEMU's
    /// compressed pages will.
    Encoded,
}

impl Encoding {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Identity => "identity",
            Encoding::Encoded => "encoded",
        }
    }
}

/// One contiguous run of a logical range projected onto the layer beneath.
///
/// This is Volatility's mapping 5-tuple
/// `(offset, length, mapped_offset, mapped_length, layer)` with the layer name
/// replaced by [`Encoding`], because in Séance the underlying source is already
/// held by the layer that produced the run.
///
/// `mapped_length != length` is the signal that the region is encoded and must
/// be decoded as a unit. Flattening the two lengths into one silently corrupts
/// reads over compressed formats.
/// Which source of a layer a [`MappedRange`] refers to.
///
/// A layer normally has exactly one, reached through
/// [`MemoryLayer::as_data_source`]. Some carry more: a Windows address space
/// with a pagefile attached resolves a swapped-out page to bytes that are not
/// in the memory image at all.
///
/// The distinction is not cosmetic. `mapped_offset` means nothing without
/// knowing which file it indexes, and an offset applied to the wrong file does
/// not fail — it returns bytes, which then get reported as the process's
/// memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackingSource {
    /// The layer's own source, [`MemoryLayer::as_data_source`].
    Primary,
    /// An auxiliary source the layer carries, by index. Resolve it with
    /// [`MemoryLayer::auxiliary_source`] and name it with
    /// [`MemoryLayer::auxiliary_label`].
    Auxiliary(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappedRange {
    /// First address of this run in the *layer's* address space.
    pub offset: u64,
    /// Length of the run in the layer's address space.
    pub length: u64,
    /// Offset of the backing bytes in the *underlying* source.
    pub mapped_offset: u64,
    /// Length of the backing region in the underlying source.
    pub mapped_length: u64,
    /// How those backing bytes are stored.
    pub encoding: Encoding,
    /// Which of the layer's sources holds the backing bytes.
    ///
    /// Almost always [`BackingSource::Primary`], the layer's own
    /// [`DataSource`]. A Windows virtual layer with a pagefile attached is the
    /// exception: a page the kernel swapped out is backed by a *different file*
    /// from the memory image, and `mapped_offset` is an offset into that file.
    /// Reading it as an offset into the image would return whatever bytes
    /// happen to live there — plausible, unrelated, and impossible to notice.
    pub source: BackingSource,
    /// How the layer reached these backing bytes, when that is a fact about the
    /// run rather than about the layer.
    ///
    /// `None` for a layer where the question does not arise: a physical or
    /// segmented layer reaches its bytes one way only. A *virtual* layer does
    /// not. A run resolved through a Windows prototype PTE is a page of a
    /// section object -- a mapped file, or memory shared with another process --
    /// and presenting those bytes as this process's own is the attribution
    /// error this field exists to prevent. The VAD reports the same distinction
    /// for a whole region; this reports it for the run actually read, which is
    /// what a physical-backing view attributes.
    pub via: Option<&'static str>,
}

impl MappedRange {
    /// A linear, byte-for-byte run, with no claim about how it was reached.
    pub fn identity(offset: u64, length: u64, mapped_offset: u64) -> Self {
        Self {
            offset,
            length,
            mapped_offset,
            mapped_length: length,
            encoding: Encoding::Identity,
            source: BackingSource::Primary,
            via: None,
        }
    }

    /// The same run, recording the path the layer took to reach it.
    pub fn reached_via(mut self, via: &'static str) -> Self {
        self.via = Some(via);
        self
    }

    /// One past the last address of this run in the layer's address space.
    /// Saturating: a run is validated at construction, so this only saturates
    /// on a run that could not have been built by this crate.
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }
}

/// Total number of layer-space bytes described by a run list.
///
/// This is a property of the **runs**, not of any request: it says how much
/// address space they describe, wherever that space lies.
///
/// # This is not how to ask whether a request was backed
///
/// Use [`backed_len`] for that, or [`MemoryLayer::is_valid`]. A layer is
/// entitled to return runs that extend beyond what was asked for — an encoded
/// run has to describe the whole block it decodes from, because one clipped to
/// a sub-range would name a blob that decodes to a different length than it
/// claims. Against such a layer this sum exceeds the request while saying
/// nothing about *which* bytes are present, so `covered_len(&runs) == length`
/// is false for ranges that are entirely there and could be true for ranges
/// with a gap in the middle.
///
/// That comparison is what broke every Linux discovery against a compressed
/// capture: a 64-byte request inside a 64 KiB frame was told the coverage was
/// 65,536, refused for not being 64, and reported as a hole 64 KiB further on.
pub fn covered_len(runs: &[MappedRange]) -> u64 {
    runs.iter()
        .fold(0u64, |acc, r| acc.saturating_add(r.length))
}

/// Bytes of `[start, start + len)` that `runs` back without a gap.
///
/// The answer to "was this request satisfied", and the counterpart to
/// [`covered_len`], which answers a different question and is the wrong tool
/// here — see its documentation for what that cost.
///
/// Walks the requested interval rather than summing the runs, so a run that
/// begins below `start` or ends above `start + len` backs the part of the
/// request it covers, and a gap stops the walk **where the gap starts**. That
/// second property is what lets a caller report a hole at the first byte
/// nothing accounts for instead of at a position implied by arithmetic.
///
/// Runs are required to be ascending and non-overlapping, which
/// [`MemoryLayer::mapping`] guarantees.
pub fn backed_len(runs: &[MappedRange], start: u64, len: u64) -> u64 {
    let end = start.saturating_add(len);
    let mut reached = start;
    for run in runs {
        // Ascending order means the first run starting past the point already
        // reached leaves a gap, and nothing later can fill it.
        if run.offset > reached {
            break;
        }
        let run_end = run.end();
        if run_end <= reached {
            continue;
        }
        reached = run_end.min(end);
        if reached >= end {
            break;
        }
    }
    reached.saturating_sub(start)
}

/// A [`DataSource`] whose offsets are *memory addresses*.
///
/// Every memory layer is a `DataSource`, which is the whole point: the moment a
/// raw memory image is wrapped in a layer, every primitive Séance already has
/// composes with it for free — `read_capped`, `read_full`, `read_exact_or_fail`,
/// `SourceCursor`, `CachingDataSource`, the hasher, the carving engine, the
/// search indexer and the API content resolver. Nothing needs a memory-specific
/// variant.
///
/// `MemoryLayer` adds the one thing `DataSource` cannot express: how a logical
/// range projects onto the layer beneath, including where it does not project
/// at all.
///
/// # Address-space semantics
///
/// - [`min_address`](MemoryLayer::min_address) and
///   [`max_address`](MemoryLayer::max_address) are **inclusive** bounds, as in
///   Volatility. `max_address` is the highest addressable byte, so a layer
///   always contains at least one byte; constructors reject empty sources
///   rather than leave the bounds undefined.
/// - [`DataSource::size`] is `max_address + 1`, i.e. the *span* of the address
///   space. For a layer with holes that is larger than the number of bytes
///   actually acquired — deliberately, because addresses are what callers index
///   by.
/// - A request that starts inside the space but runs past `max_address` is
///   clipped, exactly like any other `DataSource`. A request that starts above
///   `max_address` is `Ok(0)` for `read_at` and
///   [`LayerError::OutOfRange`] for [`mapping`](MemoryLayer::mapping).
/// - A request touching an address inside the space with no bytes behind it is
///   [`MemoryHole`]. See that type for why this is not zeros.
///
/// The trait is object safe: `Arc<dyn MemoryLayer>` is the intended way to hold
/// a layer stack.
pub trait MemoryLayer: DataSource {
    /// Lowest addressable byte. Inclusive.
    fn min_address(&self) -> u64;

    /// Highest addressable byte. Inclusive.
    fn max_address(&self) -> u64;

    /// Project `[offset, offset + length)` onto the layer beneath.
    ///
    /// Returns ascending, non-overlapping runs. The result is clipped at
    /// `max_address`; use [`covered_len`] to detect that.
    ///
    /// # Errors
    ///
    /// - [`LayerError::Hole`] if any byte in the requested range is unmapped.
    ///   Gaps are **never** silently skipped: a caller that received a run list
    ///   with a gap elided would read the far side of the gap believing it was
    ///   contiguous, which is how a scanner reports a hit at an address that
    ///   does not hold it.
    /// - [`LayerError::OutOfRange`] if `offset` is above `max_address`.
    fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError>;

    /// Whether every byte of `[offset, offset + length)` is backed.
    ///
    /// Defined in terms of [`mapping`](MemoryLayer::mapping) so a layer cannot
    /// drift out of agreement with its own projection, and measured with
    /// [`backed_len`] rather than [`covered_len`] so that a layer whose runs are
    /// wider than the request — every layer over a compressed acquisition — is
    /// answered correctly by this default instead of having to override it.
    ///
    /// An override is an optimisation, not a correction: a layer that can
    /// answer from its own index without building a run list may do so, and
    /// [`backed_len`] over `mapping` remains the definition it must agree with.
    fn is_valid(&self, offset: u64, length: u64) -> bool {
        match self.mapping(offset, length) {
            Ok(runs) => backed_len(&runs, offset, length) == length,
            Err(_) => false,
        }
    }

    /// The lowest address at or above `address` this layer could translate at
    /// all, or `None` when there is none.
    ///
    /// Almost every layer's address space is contiguous from
    /// [`min_address`](MemoryLayer::min_address) to
    /// [`max_address`](MemoryLayer::max_address), and the default says exactly
    /// that. **A sign-extending 64-bit virtual space is the exception**, and it
    /// is the important one: on x86-64 the addresses between `2^47` and
    /// `0xFFFF_8000_0000_0000` are not addresses at all — the CPU faults on
    /// them — and the *kernel's whole half of the space lies above that gap*.
    ///
    /// Without this, an enumeration walking upward from zero meets the gap,
    /// receives [`LayerError::OutOfRange`] — which is also what the top of the
    /// space returns — and stops, having covered the lower canonical half and
    /// nothing else. That is how a sweep of a kernel address space came to
    /// report eleven mapped regions totalling 156 KiB, and to report the
    /// enumeration as complete.
    fn next_addressable(&self, address: u64) -> Option<u64> {
        (address <= self.max_address()).then_some(address.max(self.min_address()))
    }

    /// The lowest address at or above `address` that acquired bytes back, or
    /// `None` when nothing above it is backed.
    ///
    /// A different question from [`next_addressable`](MemoryLayer::next_addressable),
    /// which is about whether an address *exists*: an address can exist and
    /// hold nothing because the acquisition never covered it. Both default to
    /// "the space is contiguous and all of it is backed", which is what a flat
    /// image is.
    ///
    /// **Why a layer needs to be asked.** [`mapping`](MemoryLayer::mapping) is
    /// documented to refuse at a hole, and most layers do — but
    /// [`crate::physical::PhysicalLayer`] over a declared geometry deliberately
    /// answers `Ok` with the runs it *does* cover, which for a window entirely
    /// inside a hole is no runs at all. A walk cannot tell that apart from a
    /// layer that cannot describe itself, and failing closed on it made a scan
    /// of every sparse image — hibernation, LiME, a crash dump that skips page
    /// zero — end at its first hole with "the layer made no progress". This is
    /// how such a layer says where to resume.
    fn next_backed(&self, address: u64) -> Option<u64> {
        (address <= self.max_address()).then_some(address.max(self.min_address()))
    }

    /// Metadata for this layer, which inherits from its parent up the chain.
    fn layer_meta(&self) -> &crate::meta::LayerMeta;

    /// This layer viewed as a plain [`DataSource`].
    ///
    /// Needed because the shared helpers take `&dyn DataSource`, and going from
    /// `&dyn MemoryLayer` to `&dyn DataSource` otherwise relies on trait
    /// upcasting. One line per implementor removes the dependency on the
    /// toolchain version entirely.
    fn as_data_source(&self) -> &dyn DataSource;

    /// An auxiliary source this layer carries, by index.
    ///
    /// `None` for every layer that has only its own — which is all of them
    /// except a Windows address space with a pagefile attached. A
    /// [`MappedRange`] whose `source` is [`BackingSource::Auxiliary`] indexes
    /// into this, and its `mapped_offset` is an offset into *that* file.
    ///
    /// Default `None`, so a layer that never produces an auxiliary run need not
    /// implement it — and one that returns `None` for an index it did produce
    /// is a bug in that layer, not a case a caller must paper over.
    fn auxiliary_source(&self, _index: u16) -> Option<&dyn DataSource> {
        None
    }

    /// What to call an auxiliary source in a report.
    ///
    /// A page recovered from `pagefile.sys` is not a page that was in RAM when
    /// the machine was captured; it may be considerably older. An examiner
    /// reading a byte has to be able to find out which, so the name is part of
    /// the layer's contract rather than a detail of whoever attached the file.
    fn auxiliary_label(&self, _index: u16) -> Option<&str> {
        None
    }

    /// This layer as a translating address space, if that is what it is.
    ///
    /// # What an examiner learns
    ///
    /// Two things that exist only on a
    /// [`VirtualLayer`](crate::translate::VirtualLayer) and are lost the moment
    /// it is held as `Arc<dyn MemoryLayer>`, which is how every OS-analysis
    /// plugin holds an address space:
    ///
    /// - [`VirtualLayer::translate`](crate::translate::VirtualLayer::translate)
    ///   → [`Translation::via`](crate::translate::Translation::via), which says
    ///   whether a page was reached through this process's own page tables or
    ///   through a section object's prototype PTE. The second is **shared**, so
    ///   "this process wrote these bytes" is not a claim the translation
    ///   supports, and a report that merges "resident" with "private to this
    ///   process" is making one the evidence does not carry.
    /// - [`VirtualLayer::uniform_tables_suppressed`](crate::translate::VirtualLayer::uniform_tables_suppressed),
    ///   the count of translations refused by the uniform-table heuristic — the
    ///   answer to "could this tool have hidden a page from me?".
    ///
    /// # What a wrong answer would look like
    ///
    /// `None` where the layer really does translate: the caller would then
    /// report every page as if it were private to the process, and would have
    /// no number to publish for the suppression heuristic. So this is
    /// implemented by exactly one type and returns `Some(self)` there; the
    /// default is for layers that perform no translation at all, where the
    /// caller's address *is* the physical address and neither question has a
    /// meaning to answer.
    ///
    /// It exists as an accessor rather than as extra fields on
    /// [`MappedRange`] deliberately: a mapped run is the same five-tuple for
    /// every layer in this crate, and provenance that only one layer can supply
    /// does not belong in a vocabulary every layer has to answer for.
    fn as_virtual(&self) -> Option<&crate::translate::VirtualLayer> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::io::{read_capped, read_exact_or_fail, read_full};

    /// A source that always reports a hole, to prove the shared Séance helpers
    /// behave correctly against one with no changes of their own.
    #[derive(Debug)]
    struct HoleSource;

    impl DataSource for HoleSource {
        fn read_at(&self, offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Err(MemoryHole::unmapped(offset, 0x1000).into_io())
        }
        fn size(&self) -> u64 {
            0x2000
        }
    }

    #[test]
    fn hole_survives_the_round_trip_through_io_error() {
        let hole = MemoryHole {
            address: 0xdead_0000,
            length: 0x2000,
            reason: HoleReason::SwappedOut,
        };
        let err = hole.into_io();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let recovered = MemoryHole::from_io(&err).expect("hole must be recoverable");
        assert_eq!(recovered, hole);
        assert_eq!(recovered.reason.as_str(), "swapped_out");
    }

    #[test]
    fn a_plain_io_error_is_not_mistaken_for_a_hole() {
        let err = io::Error::other("disk on fire");
        assert!(MemoryHole::from_io(&err).is_none());
    }

    #[test]
    fn read_exact_or_fail_refuses_to_parse_across_a_hole() {
        // The invariant that makes the whole design work: a structural header
        // that lands in a hole must NOT be parsed as zeros.
        let ds = HoleSource;
        let mut buf = [0u8; 64];
        let err = read_exact_or_fail(&ds, 0x1000, &mut buf, "_EPROCESS")
            .expect_err("a header in a hole must not parse");
        let hole = MemoryHole::from_io(&err).expect("the hole must reach the caller");
        assert_eq!(hole.address, 0x1000);
        assert_eq!(hole.length, 0x1000);
        assert_eq!(hole.reason, HoleReason::Unmapped);
        // And the buffer was left untouched rather than "filled" with zeros
        // that a parser would read as content.
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn best_effort_helpers_stop_at_a_hole_rather_than_padding() {
        let ds = HoleSource;
        assert_eq!(read_full(&ds, 0, &mut [0u8; 32]), 0);
        assert!(read_capped(&ds, 0x2000).is_empty());
    }

    #[test]
    fn hole_maps_onto_an_honest_incomplete_reason() {
        let hole = MemoryHole::unmapped(0x4000, 0x1000);
        assert_eq!(hole.incomplete_reason(), IncompleteReason::ShortRead);
        assert_eq!(hole.to_json()["reason"], "unmapped");
        assert_eq!(hole.to_json()["address"], 0x4000);
    }

    #[test]
    fn layer_error_from_io_preserves_a_hole_payload() {
        let hole = MemoryHole::unmapped(0x8000, 0x1000);
        let err = LayerError::from_io(hole.into_io());
        assert_eq!(err.hole(), Some(hole));

        let plain = LayerError::from_io(io::Error::other("boom"));
        assert!(plain.hole().is_none());
    }

    #[test]
    fn layer_error_converts_back_into_a_hole_bearing_io_error() {
        let hole = MemoryHole::unmapped(0x1_0000, 0x1000);
        let err: io::Error = LayerError::Hole(hole).into();
        assert_eq!(MemoryHole::from_io(&err), Some(hole));

        // A structural error is not a hole and must not pretend to be one.
        let err: io::Error = LayerError::EmptySource.into();
        assert!(MemoryHole::from_io(&err).is_none());
    }

    #[test]
    fn mapped_range_helpers_report_coverage() {
        let runs = vec![
            MappedRange::identity(0, 0x1000, 0x400),
            MappedRange::identity(0x1000, 0x800, 0x1400),
        ];
        assert_eq!(covered_len(&runs), 0x1800);
        assert_eq!(runs[0].end(), 0x1000);
        assert_eq!(runs[1].encoding, Encoding::Identity);
        assert_eq!(Encoding::Encoded.as_str(), "encoded");
    }

    /// A layer whose runs describe whole frames, as a compressed acquisition's
    /// must: an encoded run names the block it decodes from, so it can begin
    /// below the request and end above it.
    #[derive(Debug)]
    struct FramedLayer {
        /// Frame size. Every frame in `present` is fully backed.
        frame: u64,
        present: Vec<u64>,
        meta: crate::meta::LayerMeta,
    }

    impl FramedLayer {
        fn new(frame: u64, present: Vec<u64>) -> Self {
            Self {
                frame,
                present,
                meta: crate::meta::LayerMeta::default(),
            }
        }
    }

    impl DataSource for FramedLayer {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn size(&self) -> u64 {
            self.max_address().saturating_add(1)
        }
    }

    impl MemoryLayer for FramedLayer {
        fn min_address(&self) -> u64 {
            0
        }
        fn max_address(&self) -> u64 {
            self.present.iter().copied().max().unwrap_or(0) + self.frame - 1
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
                if !self.present.contains(&at) {
                    return Err(LayerError::Hole(MemoryHole::unmapped(at, self.frame)));
                }
                // The whole frame, not the clipped request. This is the shape
                // the bug was found in.
                runs.push(MappedRange::identity(at, self.frame, at));
                at += self.frame;
            }
            Ok(runs)
        }
        fn layer_meta(&self) -> &crate::meta::LayerMeta {
            &self.meta
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    /// `backed_len` answers about the requested interval, not about the runs.
    #[test]
    fn backed_len_measures_the_request_not_the_run_lengths() {
        let runs = [
            MappedRange::identity(0x1000, 0x1000, 0x1000),
            MappedRange::identity(0x2000, 0x1000, 0x2000),
        ];
        // A small request inside one wide run is fully backed.
        assert_eq!(backed_len(&runs, 0x1400, 0x40), 0x40);
        // A request spanning two adjacent wide runs is fully backed.
        assert_eq!(backed_len(&runs, 0x1800, 0x1000), 0x1000);
        // The whole of both runs.
        assert_eq!(backed_len(&runs, 0x1000, 0x2000), 0x2000);
        // Summing says something different, and that difference is the defect
        // this function exists to remove.
        assert!(covered_len(&runs) > 0x40);
    }

    /// A gap stops the count where the gap starts, so the caller can name it.
    #[test]
    fn backed_len_stops_at_the_first_unbacked_byte() {
        let runs = [
            MappedRange::identity(0x1000, 0x1000, 0x1000),
            // 0x2000..0x3000 missing.
            MappedRange::identity(0x3000, 0x1000, 0x3000),
        ];
        assert_eq!(backed_len(&runs, 0x1000, 0x3000), 0x1000);
        assert_eq!(backed_len(&[], 0x1000, 0x40), 0);
        // Summing would claim two thirds were present and imply the shortfall
        // was at the end.
        assert_eq!(covered_len(&runs), 0x2000);
    }

    /// A request beginning before the first run is not backed from its start.
    #[test]
    fn backed_len_does_not_credit_coverage_that_starts_late() {
        let runs = [MappedRange::identity(0x1000, 0x1000, 0x1000)];
        assert_eq!(backed_len(&runs, 0x0800, 0x1000), 0);
    }

    /// **The defect, at the trait's default.** A layer that returns whole-frame
    /// runs must still report a fully-backed request as valid.
    ///
    /// Every layer over a compressed acquisition returns runs of this shape,
    /// because an encoded run has to describe the block it decodes from. The
    /// default asked whether the run lengths summed to the request, which they
    /// never do, so `is_valid` was false for pages the evidence fully held.
    /// `VirtualLayer::require_acquired` made the same mistake against a real
    /// capture and refused every page of it.
    #[test]
    fn the_default_is_valid_holds_for_a_layer_whose_runs_are_wider_than_the_request() {
        let layer = FramedLayer::new(0x10000, vec![0, 0x10000, 0x20000]);

        assert!(
            layer.is_valid(0x9e0, 0x40),
            "64 bytes inside a present 64 KiB frame are backed; the default must \
             not answer by summing run lengths"
        );
        assert!(layer.is_valid(0, 0x30000), "every frame is present");
        assert!(
            layer.is_valid(0xfff0, 0x20),
            "a request crossing a frame boundary into another present frame"
        );
    }

    /// The default still refuses what is genuinely absent.
    #[test]
    fn the_default_is_valid_refuses_a_frame_the_acquisition_does_not_hold() {
        // Frame at 0x10000 is missing.
        let layer = FramedLayer::new(0x10000, vec![0, 0x20000]);
        assert!(!layer.is_valid(0x10000, 0x40), "the frame is not present");
        assert!(
            !layer.is_valid(0xfff0, 0x20),
            "a request crossing from a present frame into an absent one"
        );
        assert!(!layer.is_valid(0x30000, 0x40), "above the top of the space");
    }

    #[test]
    fn byte_slice_source_is_still_a_plain_data_source() {
        // Sanity: nothing in this module changes ordinary DataSource behaviour.
        let ds = ByteSliceDataSource::new(vec![1, 2, 3]);
        let mut buf = [0u8; 3];
        assert_eq!(ds.read_at(0, &mut buf).unwrap(), 3);
    }
}
