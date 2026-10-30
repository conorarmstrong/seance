//! Extraction: turning a region of a memory image back into bytes an examiner
//! can hash, carve, scan or hand to another tool.
//!
//! Five capabilities live here, and they are all the same operation seen from
//! different angles: *these addresses held these bytes, and these addresses
//! held nothing we ever acquired*.
//!
//! | Capability | The question it answers |
//! |---|---|
//! | [`dump_vad`] | what was in this one allocation |
//! | [`memory_map`] / [`memory_dump`] | what is mapped in this process, and what is in it |
//! | [`dump_pe`] | what executable was loaded here, laid back out as a file |
//! | [`read_imports`] | which function does each import slot really point at |
//! | [`file_cache_map`] / [`dump_file_cache`] | what of this file was still cached in RAM |
//!
//! # The rule the whole module exists to enforce
//!
//! **A page that was never acquired is never written as zeroes.**
//!
//! Volatility's extraction plugins read with `pad=True`, which fabricates zero
//! bytes for every unmapped, paged-out or never-captured page and writes them
//! into the output file. The resulting artifact is byte-identical to a file
//! that never existed on the suspect's machine. An examiner who hashes it, or
//! carves it, or puts its length in a report, is working from an object the
//! tool invented — and nothing downstream records that it did.
//!
//! So every extraction here returns two things: the bytes it actually has, as
//! [`Extract::chunks`], and the ranges it could not read, as [`Extract::gaps`].
//! There is no code path that fills a gap. [`Extract::contiguous`] hands back a
//! single buffer **only** when there are no gaps at all; a caller that wants
//! padding must ask for it by name through [`Extract::padded_with`], which says
//! in its own documentation that the result is not evidence.
//!
//! Nothing here touches the filesystem. Writing an artifact — with its gap map
//! attached — is the caller's decision, because the caller is the one that
//! knows whether the case can carry a partial object.
//!
//! # Offsets and addresses are two different spaces
//!
//! Every extracted artifact has its own *offset space*, which is where a byte
//! sits in the produced file. That is not the same as the *address* the byte
//! came from, and conflating them is how a dump ends up shifted:
//!
//! * [`ExtractLayout::Sparse`] — offset is `address − start`. A hole in the
//!   middle leaves a hole in the artifact at the same place. Used by
//!   [`dump_vad`], by [`dump_pe`] and by the file-cache reconstruction, where
//!   the offset space is the file's own.
//! * [`ExtractLayout::Packed`] — offsets run consecutively over the mapped
//!   regions only, so nothing is reserved for what is missing. Used by
//!   [`memory_dump`], and it is why [`MemoryRegion::file_offset`] exists: it is
//!   the only way to say which address a byte of that dump came from.
//!
//! [`Chunk`] carries both numbers for exactly this reason.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::sync::Arc;

use seance_core::io::{read_exact_or_fail, IncompleteReason};
use seance_memory::layer::{LayerError, MemoryHole};
use seance_memory::object::{Obj, ObjError, StructReader};
use seance_memory::{backed_len, HoleReason, Incomplete, MappedRange, MemoryLayer};
use seance_symbols::SymbolError;

use crate::profile::WindowsProfile;
use crate::vad::{Vad, PAGE_SIZE};

// ── Caps ────────────────────────────────────────────────────────────────────

/// Ceiling on the bytes one extraction will return.
///
/// One gibibyte, which is the size above which upstream's `vaddump` declines a
/// region. A request above this is refused by name rather than silently
/// truncated, because a truncated dump and a short region look identical once
/// the bytes are in a file.
pub const DEFAULT_MAX_EXTRACT_BYTES: u64 = 1 << 30;

/// How many bytes one read of the layer asks for at a time.
pub const DEFAULT_BLOCK_BYTES: u64 = 1 << 20;

/// Hardest ceiling on a single buffered read, whatever a caller configures.
pub const MAX_BLOCK_BYTES: u64 = 1 << 24;

/// Ceiling on separately recorded acquired runs in one extraction.
pub const MAX_CHUNKS: usize = 1 << 16;

/// Ceiling on individually recorded gaps. The *count* and the *byte total* stay
/// exact past it.
pub const MAX_RECORDED_GAPS: usize = 1024;

/// Ceiling on regions one address-space scan will report.
pub const MAX_REGIONS: usize = 1 << 18;

/// Ceiling on probes one address-space scan will make.
///
/// A scan skips a whole absent page directory in one step, so a 64-bit user
/// space costs thousands of probes, not billions. Reaching this means the layer
/// is refusing addresses in a way the scan could not classify.
pub const MAX_SCAN_STEPS: usize = 1 << 20;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops an extraction before it can produce bytes worth
/// hashing.
///
/// Note what is *not* here: a page that could not be read. That is a fact about
/// one range, and it lands in [`Extract::gaps`], where it survives into the
/// artifact instead of aborting the whole extraction.
#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    /// This build, or this image, cannot support the extraction that was asked
    /// for, and no partial answer would be honest. The message names what is
    /// missing.
    #[error("this extraction cannot be made: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// The request is larger than the cap. Refused rather than truncated: a
    /// truncated dump is a file that looks whole.
    #[error("{what} of {requested} byte(s) exceeds the cap of {cap}")]
    TooLarge {
        /// What was being extracted.
        what: &'static str,
        /// How many bytes it would have taken.
        requested: u64,
        /// The cap that refused it.
        cap: u64,
    },

    /// Address or offset arithmetic left the addressable range. Always an
    /// error: a wrapped address is a wrong address.
    #[error("address arithmetic overflowed: {0}")]
    Overflow(String),

    /// Bytes a structural header needed are not in the evidence.
    #[error("{what} at {address:#x} could not be read: {detail}")]
    Unreadable {
        /// What was being read, in the examiner's terms.
        what: String,
        /// Where the read started.
        address: u64,
        /// Why it failed.
        detail: String,
    },

    /// The bytes were readable and are not a PE image, or not one this reader
    /// will follow.
    #[error("the image at {base:#x} is not a usable PE: {detail}")]
    NotPe {
        /// Where the image was expected.
        base: u64,
        /// Which specific check failed.
        detail: String,
    },

    /// A typed read failed for a reason that invalidates the whole extraction.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the extraction depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),
}

impl DumpError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            DumpError::Unsupported { .. } => "unsupported_build",
            DumpError::TooLarge { .. } => "too_large",
            DumpError::Overflow(_) => "overflow",
            DumpError::Unreadable { .. } => "unreadable",
            DumpError::NotPe { .. } => "not_pe",
            DumpError::Object(err) => err.class(),
            DumpError::Symbols(_) => "symbols",
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            DumpError::TooLarge { .. } => IncompleteReason::CapReached,
            DumpError::Unreadable { .. } => IncompleteReason::ShortRead,
            DumpError::Object(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this cannot be extracted" refusal.
    pub fn unsupported(detail: impl Into<String>) -> DumpError {
        DumpError::Unsupported {
            detail: detail.into(),
        }
    }

    /// Shorthand for arithmetic that would have wrapped.
    pub fn overflow(detail: impl Into<String>) -> DumpError {
        DumpError::Overflow(detail.into())
    }
}

// ── Gaps ────────────────────────────────────────────────────────────────────

/// Why a range of an extracted artifact has no bytes behind it.
///
/// Each variant is a different forensic fact, and the whole point of the type
/// is that none of them renders as zeroes. "The suspect wiped this buffer" and
/// "we never captured this buffer" are opposite conclusions that a padded dump
/// makes indistinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    /// The acquisition never captured these bytes.
    Unmapped,
    /// A page-table walk reached a not-present entry: the page is not in RAM.
    NotPresent,
    /// The page lives in a pagefile that is not part of this evidence item.
    SwappedOut,
    /// A page table was suppressed by the Windows 10 uniform-table heuristic.
    TableSuppressed,
    /// There is no such address: above the top of the space, or non-canonical.
    Unaddressable,
    /// The bytes are described by the structure but were never in memory at
    /// all — file-alignment padding in a reconstructed PE, or a region of a
    /// cached file that was never resident. Distinct from an acquisition
    /// failure: nothing went wrong, those bytes simply are not recoverable from
    /// RAM.
    NotInMemory,
    /// The read failed for an ordinary I/O reason.
    ReadFailed,
    /// The extraction declined to write these bytes — a cap fired, or a
    /// structure would have overlapped one already written.
    Refused,
}

impl GapReason {
    /// The gap reason a memory-layer [`HoleReason`] names.
    pub fn from_hole(reason: HoleReason) -> GapReason {
        match reason {
            HoleReason::Unmapped => GapReason::Unmapped,
            HoleReason::NotPresent => GapReason::NotPresent,
            HoleReason::SwappedOut => GapReason::SwappedOut,
            HoleReason::TableSuppressed => GapReason::TableSuppressed,
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            GapReason::Unmapped => "unmapped",
            GapReason::NotPresent => "not_present",
            GapReason::SwappedOut => "swapped_out",
            GapReason::TableSuppressed => "table_suppressed",
            GapReason::Unaddressable => "unaddressable",
            GapReason::NotInMemory => "not_in_memory",
            GapReason::ReadFailed => "read_failed",
            GapReason::Refused => "refused",
        }
    }

    /// How a report records this gap.
    pub fn incomplete_reason(self) -> IncompleteReason {
        match self {
            GapReason::Refused => IncompleteReason::CapReached,
            GapReason::NotInMemory => IncompleteReason::UnresolvedStructure,
            _ => IncompleteReason::ShortRead,
        }
    }
}

/// A range of an artifact that has no bytes behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// Where the missing bytes would have been in the artifact.
    pub offset: u64,
    /// The address they would have come from.
    pub address: u64,
    /// How many bytes are missing.
    pub length: u64,
    /// Why they are missing.
    pub reason: GapReason,
    /// The underlying failure, in the examiner's terms.
    pub detail: String,
}

impl Gap {
    /// One past the last missing offset. Saturating; a gap is built from
    /// checked arithmetic, so this only saturates on one that could not exist.
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "offset": self.offset,
            "address": self.address,
            "length": self.length,
            "reason": self.reason.as_str(),
            "detail": self.detail,
        })
    }
}

/// A run of bytes that really was acquired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Where this run starts in the artifact.
    pub offset: u64,
    /// The address it was read from.
    pub address: u64,
    /// The bytes, exactly as acquired.
    pub bytes: Vec<u8>,
}

impl Chunk {
    /// How many bytes this run holds.
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Whether the run is empty. A builder never produces one.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// One past the last offset this run covers.
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.len())
    }

    /// Serializable form for artifact metadata. Deliberately without the bytes:
    /// metadata describes the extraction, it is not the extraction.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "offset": self.offset,
            "address": self.address,
            "length": self.len(),
        })
    }
}

/// Why an extraction stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractStop {
    /// Everything the caller asked for was attempted.
    Exhausted,
    /// A cap fired. The extraction stopped; the data did not end.
    CapReached {
        /// What was being bounded.
        what: &'static str,
        /// The cap that fired.
        cap: u64,
    },
}

impl ExtractStop {
    /// Whether the extraction ran to the end of what was asked for.
    pub fn is_complete(&self) -> bool {
        matches!(self, ExtractStop::Exhausted)
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ExtractStop::Exhausted => "exhausted",
            ExtractStop::CapReached { .. } => "cap_reached",
        }
    }
}

/// How an artifact's offset space relates to the addresses it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractLayout {
    /// Offset is `address − start`: an unreadable range leaves a hole in the
    /// artifact at the place it belongs.
    Sparse,
    /// Offsets run consecutively over the acquired regions only.
    Packed,
}

impl ExtractLayout {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ExtractLayout::Sparse => "sparse",
            ExtractLayout::Packed => "packed",
        }
    }
}

/// The bytes an extraction has, and the ranges it does not.
///
/// The two together are the whole result. A caller that looks only at
/// [`Extract::chunks`] and concatenates them has silently closed every gap and
/// produced an object that never existed.
#[derive(Debug, Clone)]
pub struct Extract {
    /// Length of the artifact's offset space: what a complete extraction would
    /// occupy. Not the number of bytes acquired — see
    /// [`Extract::acquired_bytes`].
    pub length: u64,
    /// How offsets relate to addresses.
    pub layout: ExtractLayout,
    /// The acquired runs, ascending by offset and non-overlapping.
    pub chunks: Vec<Chunk>,
    /// The ranges with nothing behind them, ascending and non-overlapping,
    /// capped by [`ExtractConfig::max_recorded_gaps`].
    pub gaps: Vec<Gap>,
    /// How many distinct gaps there were in total. Exact even when the list
    /// above was capped.
    pub gap_total: usize,
    /// How many bytes are missing in total. Exact even when the list was
    /// capped.
    pub gap_bytes: u64,
    /// How many bytes were really acquired.
    pub acquired_bytes: u64,
    /// Why the extraction stopped.
    pub stop: ExtractStop,
    /// Everything odd about the extraction that did not stop it.
    pub notes: Vec<String>,
}

impl Extract {
    /// Whether every byte the caller asked for was acquired.
    ///
    /// The question a report must ask before writing a hash: a dump that is not
    /// complete hashes as itself, not as the object it was taken from.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete() && self.gap_total == 0 && self.acquired_bytes == self.length
    }

    /// The single contiguous buffer this extraction represents, when it really
    /// is one.
    ///
    /// `None` whenever anything is missing. That is the entire safety property:
    /// a caller cannot get a buffer out of an incomplete extraction by
    /// accident, only by asking for [`Extract::padded_with`] on purpose.
    pub fn contiguous(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut out = Vec::with_capacity(usize::try_from(self.length).ok()?);
        for chunk in &self.chunks {
            if chunk.offset != out.len() as u64 {
                return None;
            }
            out.extend_from_slice(&chunk.bytes);
        }
        if out.len() as u64 == self.length {
            Some(out)
        } else {
            None
        }
    }

    /// The artifact with every gap filled by `fill`.
    ///
    /// **The result is not evidence.** Its bytes at every offset covered by
    /// [`Extract::gaps`] were invented by this function, and once written to a
    /// file nothing distinguishes them from acquired bytes: it hashes as a
    /// complete object, carves as a complete object and reads as a complete
    /// object. A caller that uses this must carry the gap map alongside it into
    /// the record, and must never present the hash of the result as the hash of
    /// the original.
    ///
    /// It exists because some downstream tools take nothing but a dense buffer,
    /// and refusing to produce one at all would push callers into writing their
    /// own padding loop with no gap map attached.
    pub fn padded_with(&self, fill: u8) -> Vec<u8> {
        let length = usize::try_from(self.length).unwrap_or(usize::MAX);
        let mut out = vec![fill; length];
        for chunk in &self.chunks {
            let Ok(start) = usize::try_from(chunk.offset) else {
                continue;
            };
            let Some(end) = start.checked_add(chunk.bytes.len()) else {
                continue;
            };
            if end > out.len() {
                continue;
            }
            out[start..end].copy_from_slice(&chunk.bytes);
        }
        out
    }

    /// Overwrite `bytes` at `offset`, in place, inside an acquired run.
    ///
    /// `false` when the range is not entirely inside one acquired run, which
    /// means the patch was not applied. Used only by [`dump_pe`], and only for
    /// changes it records in [`PeDump::patches`]: a byte changed without a
    /// record of the change is the one thing an extracted artifact must never
    /// contain.
    pub fn patch(&mut self, offset: u64, bytes: &[u8]) -> bool {
        let length = bytes.len() as u64;
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        for chunk in &mut self.chunks {
            if chunk.offset <= offset && end <= chunk.end() {
                let Ok(within) = usize::try_from(offset - chunk.offset) else {
                    return false;
                };
                let Some(stop) = within.checked_add(bytes.len()) else {
                    return false;
                };
                if stop > chunk.bytes.len() {
                    return false;
                }
                chunk.bytes[within..stop].copy_from_slice(bytes);
                return true;
            }
        }
        false
    }

    /// The bytes at `offset`, when they are all inside one acquired run.
    pub fn bytes_at(&self, offset: u64, length: u64) -> Option<&[u8]> {
        let end = offset.checked_add(length)?;
        for chunk in &self.chunks {
            if chunk.offset <= offset && end <= chunk.end() {
                let within = usize::try_from(offset - chunk.offset).ok()?;
                let stop = within.checked_add(usize::try_from(length).ok()?)?;
                return chunk.bytes.get(within..stop);
            }
        }
        None
    }

    /// Everything a report must declare about this extraction.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let ExtractStop::CapReached { what, cap } = &self.stop {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!("the extraction stopped at its cap of {cap} {what}; the region continues"),
            ));
        }
        if self.gap_total > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} byte(s) of this {}-byte extraction, in {} range(s), were never acquired \
                     and are absent from it rather than written as zeroes",
                    self.gap_bytes, self.length, self.gap_total
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "length": self.length,
            "layout": self.layout.as_str(),
            "acquired_bytes": self.acquired_bytes,
            "gap_bytes": self.gap_bytes,
            "gap_total": self.gap_total,
            "chunks": self.chunks.iter().map(Chunk::to_json).collect::<Vec<_>>(),
            "chunk_count": self.chunks.len(),
            "gaps": self.gaps.iter().map(Gap::to_json).collect::<Vec<_>>(),
            "stop": self.stop.as_str(),
            "complete": self.is_complete(),
            "notes": self.notes,
        })
    }
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Caps for one extraction.
#[derive(Debug, Clone)]
pub struct ExtractConfig {
    /// Ceiling on the artifact's offset space. A larger request is
    /// [`DumpError::TooLarge`], never a shortened dump.
    pub max_bytes: u64,
    /// How many bytes one read asks the layer for.
    pub block_bytes: u64,
    /// Granularity at which a failed block is re-probed, so a gap names the
    /// pages that are missing rather than the megabyte around them.
    pub page_bytes: u64,
    /// Ceiling on separately recorded acquired runs.
    pub max_chunks: usize,
    /// Ceiling on individually recorded gaps.
    pub max_recorded_gaps: usize,
    /// Ceiling on regions one address-space scan reports.
    pub max_regions: usize,
    /// Ceiling on probes one address-space scan makes.
    pub max_scan_steps: usize,
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_EXTRACT_BYTES,
            block_bytes: DEFAULT_BLOCK_BYTES,
            page_bytes: PAGE_SIZE,
            max_chunks: MAX_CHUNKS,
            max_recorded_gaps: MAX_RECORDED_GAPS,
            max_regions: MAX_REGIONS,
            max_scan_steps: MAX_SCAN_STEPS,
        }
    }
}

impl ExtractConfig {
    /// The re-probe granularity, sanitised. Never zero, because a zero step
    /// would be a loop that does not advance.
    pub fn page(&self) -> u64 {
        if self.page_bytes == 0 {
            PAGE_SIZE
        } else {
            self.page_bytes
        }
    }

    /// The bulk read size, sanitised: at least one page, never above
    /// [`MAX_BLOCK_BYTES`], so no configuration can ask for an allocation the
    /// examiner did not.
    pub fn block(&self) -> u64 {
        self.block_bytes.max(self.page()).min(MAX_BLOCK_BYTES)
    }

    /// Refuse a length above [`ExtractConfig::max_bytes`].
    ///
    /// # Errors
    ///
    /// [`DumpError::TooLarge`] naming the request and the cap.
    pub fn admit(&self, what: &'static str, length: u64) -> Result<(), DumpError> {
        if length > self.max_bytes {
            return Err(DumpError::TooLarge {
                what,
                requested: length,
                cap: self.max_bytes,
            });
        }
        Ok(())
    }
}

// ── Building an extraction ──────────────────────────────────────────────────

/// Accumulates acquired runs and gaps under the configured caps.
///
/// Merging is not cosmetic: without it, a fully mapped gibibyte produces a
/// quarter of a million single-page chunks and trips the chunk cap, which would
/// report a complete extraction as capped.
struct ExtractBuilder<'a> {
    config: &'a ExtractConfig,
    layout: ExtractLayout,
    chunks: Vec<Chunk>,
    gaps: Vec<Gap>,
    gap_total: usize,
    gap_bytes: u64,
    acquired: u64,
    /// End of the last gap in both spaces plus its reason, tracked separately
    /// from `gaps` so merging stays correct after the record cap has fired and
    /// `gap_total` stays exact.
    last_gap: Option<(u64, u64, GapReason)>,
    stop: ExtractStop,
    notes: Vec<String>,
}

impl<'a> ExtractBuilder<'a> {
    fn new(config: &'a ExtractConfig, layout: ExtractLayout) -> Self {
        Self {
            config,
            layout,
            chunks: Vec::new(),
            gaps: Vec::new(),
            gap_total: 0,
            gap_bytes: 0,
            acquired: 0,
            last_gap: None,
            stop: ExtractStop::Exhausted,
            notes: Vec::new(),
        }
    }

    /// Whether a cap has fired and the caller should stop feeding this builder.
    fn capped(&self) -> bool {
        !self.stop.is_complete()
    }

    fn cap(&mut self, what: &'static str, cap: u64) {
        if self.stop.is_complete() {
            self.stop = ExtractStop::CapReached { what, cap };
        }
    }

    fn note(&mut self, note: impl Into<String>) {
        if self.notes.len() < self.config.max_recorded_gaps {
            self.notes.push(note.into());
        }
    }

    /// Record acquired bytes at `offset`, read from `address`.
    fn add_bytes(&mut self, offset: u64, address: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let length = data.len() as u64;
        if let Some(last) = self.chunks.last_mut() {
            let contiguous = last.offset.checked_add(last.len()) == Some(offset)
                && last.address.checked_add(last.len()) == Some(address);
            if contiguous {
                last.bytes.extend_from_slice(data);
                self.acquired = self.acquired.saturating_add(length);
                return;
            }
        }
        if self.chunks.len() >= self.config.max_chunks {
            self.cap("acquired runs", self.config.max_chunks as u64);
            // These bytes were acquired and will not be written. Dropping them
            // silently would leave the range in neither the chunk list nor the
            // gap map, so the extract would cover less than its own declared
            // length with nothing saying which bytes went missing — an examiner
            // reading the gap map would conclude those addresses were never in
            // the capture.
            self.refuse_remaining(offset, address, length);
            return;
        }
        self.chunks.push(Chunk {
            offset,
            address,
            bytes: data.to_vec(),
        });
        self.acquired = self.acquired.saturating_add(length);
    }

    /// Account for a range the extraction stopped short of, so that every byte
    /// of the declared length is either in a chunk or in the gap map.
    ///
    /// The reason is [`GapReason::Refused`] and never an acquisition reason:
    /// "we did not look" and "the capture does not hold these pages" support
    /// opposite conclusions, and only one of them is true here.
    fn refuse_remaining(&mut self, offset: u64, address: u64, length: u64) {
        if length == 0 {
            return;
        }
        let detail = match self.stop {
            ExtractStop::CapReached { what, cap } => format!(
                "the extraction stopped at its cap of {cap} {what}, so these bytes were not \
                 written; this says nothing about whether they were in the capture"
            ),
            _ => "the extraction stopped before these bytes were written; this says nothing \
                  about whether they were in the capture"
                .to_string(),
        };
        self.add_gap(offset, address, length, GapReason::Refused, detail);
    }

    /// Record a range with nothing behind it.
    fn add_gap(
        &mut self,
        offset: u64,
        address: u64,
        length: u64,
        reason: GapReason,
        detail: impl Into<String>,
    ) {
        if length == 0 {
            return;
        }
        self.gap_bytes = self.gap_bytes.saturating_add(length);
        let mergeable = match self.last_gap {
            Some((end_offset, end_address, last_reason)) => {
                end_offset == offset && end_address == address && last_reason == reason
            }
            None => false,
        };
        let next = (
            offset.saturating_add(length),
            address.saturating_add(length),
            reason,
        );
        self.last_gap = Some(next);
        if mergeable {
            if let Some(last) = self.gaps.last_mut() {
                if last.end() == offset && last.reason == reason {
                    last.length = last.length.saturating_add(length);
                    return;
                }
            }
            // The record list was capped before this run began, so the merge has
            // nowhere to land. The count and the byte total are still right,
            // which is what a report needs.
            return;
        }
        self.gap_total += 1;
        if self.gaps.len() < self.config.max_recorded_gaps {
            self.gaps.push(Gap {
                offset,
                address,
                length,
                reason,
                detail: detail.into(),
            });
        }
    }

    fn finish(self, length: u64) -> Extract {
        Extract {
            length,
            layout: self.layout,
            chunks: self.chunks,
            gaps: self.gaps,
            gap_total: self.gap_total,
            gap_bytes: self.gap_bytes,
            acquired_bytes: self.acquired,
            stop: self.stop,
            notes: self.notes,
        }
    }
}

/// Read exactly `length` bytes, classifying a failure into a gap reason rather
/// than losing why it happened.
fn read_exact_bytes(
    layer: &dyn MemoryLayer,
    address: u64,
    length: u64,
) -> Result<Vec<u8>, (GapReason, String)> {
    if length == 0 {
        return Ok(Vec::new());
    }
    if address.checked_add(length).is_none() {
        return Err((
            GapReason::Unaddressable,
            format!("{address:#x}+{length:#x} runs past the end of the 64-bit address space"),
        ));
    }
    let Ok(size) = usize::try_from(length) else {
        return Err((
            GapReason::Refused,
            format!("{length} byte(s) is more than this host can hold in one buffer"),
        ));
    };
    let mut buf = vec![0u8; size];
    match read_exact_or_fail(
        layer.as_data_source(),
        address,
        &mut buf,
        "an extracted memory range",
    ) {
        Ok(()) => Ok(buf),
        Err(err) => {
            if let Some(hole) = MemoryHole::from_io(&err) {
                return Err((GapReason::from_hole(hole.reason), hole.to_string()));
            }
            if err.kind() == io::ErrorKind::UnexpectedEof {
                return Err((
                    GapReason::Unaddressable,
                    format!("the address space ends before {address:#x}+{length:#x}"),
                ));
            }
            Err((GapReason::ReadFailed, err.to_string()))
        }
    }
}

/// Read `[address, address + length)` into the builder at `offset`, splitting a
/// failed block down to page granularity so a gap names the pages that are
/// missing rather than the block one of them happened to be in.
fn read_into(
    builder: &mut ExtractBuilder<'_>,
    layer: &dyn MemoryLayer,
    address: u64,
    length: u64,
    offset: u64,
) {
    let block = builder.config.block();
    let page = builder.config.page();
    let mut done = 0u64;
    while done < length {
        if builder.capped() {
            builder.refuse_remaining(
                offset.saturating_add(done),
                address.saturating_add(done),
                length - done,
            );
            return;
        }
        let take = block.min(length - done);
        let at = address.saturating_add(done);
        let out = offset.saturating_add(done);
        match read_exact_bytes(layer, at, take) {
            Ok(bytes) => builder.add_bytes(out, at, &bytes),
            Err(_) if take > page => {
                let mut inner = 0u64;
                while inner < take {
                    if builder.capped() {
                        builder.refuse_remaining(
                            out.saturating_add(inner),
                            at.saturating_add(inner),
                            (length - done) - inner,
                        );
                        return;
                    }
                    let step = page.min(take - inner);
                    let page_at = at.saturating_add(inner);
                    let page_out = out.saturating_add(inner);
                    match read_exact_bytes(layer, page_at, step) {
                        Ok(bytes) => builder.add_bytes(page_out, page_at, &bytes),
                        Err((reason, detail)) => {
                            builder.add_gap(page_out, page_at, step, reason, detail)
                        }
                    }
                    inner += step;
                }
            }
            Err((reason, detail)) => builder.add_gap(out, at, take, reason, detail),
        }
        done += take;
    }
}

// ── Scanning an address space ───────────────────────────────────────────────

/// What one step of an address-space scan found.
enum WalkEvent {
    /// Runs the layer mapped, ascending.
    Mapped(Vec<MappedRange>),
    /// A range with nothing behind it.
    Missing {
        address: u64,
        length: u64,
        reason: GapReason,
        detail: String,
    },
}

/// Walk `[start, end)` of a layer, reporting mapped runs and missing ranges.
///
/// The efficiency of the whole module rests here. `mapping` fails on the first
/// unmapped byte, and the [`MemoryHole`] it fails with carries the *length* of
/// the region the failing page-table entry governs — a whole absent page
/// directory, not one page — so an unmapped 512 GiB of a 64-bit user space
/// costs one probe rather than 134 million.
///
/// `sink` returns `false` to stop the walk, which is how a cap fires.
fn walk_space(
    layer: &dyn MemoryLayer,
    start: u64,
    end: u64,
    config: &ExtractConfig,
    mut sink: impl FnMut(WalkEvent) -> bool,
) -> ExtractStop {
    let page = config.page();
    let block = config.block();
    let regions_cap = ExtractStop::CapReached {
        what: "regions",
        cap: config.max_regions as u64,
    };
    let mut pos = start;
    let mut steps = 0usize;

    while pos < end {
        steps += 1;
        if steps > config.max_scan_steps {
            return ExtractStop::CapReached {
                what: "address-space probes",
                cap: config.max_scan_steps as u64,
            };
        }
        let want = block.min(end - pos);
        let before = pos;

        match layer.mapping(pos, want) {
            Ok(runs) => {
                // Of the request, not of the runs. This walk is driven over a
                // `VirtualLayer`, whose runs are clipped to what was asked for,
                // so the two agree today — but the question being asked is "how
                // much of my request came back", and `covered_len` answers a
                // different one. A layer whose runs are wider would advance
                // `pos` past memory the walk never emitted and would defeat the
                // `covered < want` test for the top of the address space. There
                // is no bespoke regression test here because no layer this walk
                // can currently be given produces that shape; the arithmetic
                // itself is covered by `backed_len`'s own tests.
                let covered = backed_len(&runs, pos, want);
                let empty = runs.is_empty();
                if !empty && !sink(WalkEvent::Mapped(runs)) {
                    return regions_cap;
                }
                pos = pos.saturating_add(covered);
                if covered < want {
                    // `mapping` clips at the top of the address space, so the
                    // remainder of the request is above it. That is not a hole
                    // in the acquisition; there is no such address.
                    let length = end.saturating_sub(pos);
                    if length > 0
                        && !sink(WalkEvent::Missing {
                            address: pos,
                            length,
                            reason: GapReason::Unaddressable,
                            detail: format!("the address space ends at {:#x}", layer.max_address()),
                        })
                    {
                        return regions_cap;
                    }
                    pos = end;
                }
            }
            Err(LayerError::Hole(hole)) if hole.address > pos && hole.address < end => {
                // The block began mapped and ran into a hole partway. Ask again
                // for exactly the mapped prefix rather than losing it.
                if let Ok(runs) = layer.mapping(pos, hole.address - pos) {
                    if !runs.is_empty() {
                        let covered = backed_len(&runs, pos, hole.address - pos);
                        if !sink(WalkEvent::Mapped(runs)) {
                            return regions_cap;
                        }
                        pos = pos.saturating_add(covered);
                    }
                }
            }
            Err(LayerError::Hole(hole)) => {
                let length = hole.length.max(page).min(end - pos);
                if !sink(WalkEvent::Missing {
                    address: pos,
                    length,
                    reason: GapReason::from_hole(hole.reason),
                    detail: hole.to_string(),
                }) {
                    return regions_cap;
                }
                pos = pos.saturating_add(length);
            }
            Err(LayerError::OutOfRange { max_address, .. }) => {
                // Either past the top of the space, or — on x86-64 — inside the
                // non-canonical middle, which no address lies in. Either way
                // there is nothing here to scan, and the rest of this range is
                // declared rather than walked address by address.
                let length = end - pos;
                if !sink(WalkEvent::Missing {
                    address: pos,
                    length,
                    reason: GapReason::Unaddressable,
                    detail: format!(
                        "there is no address {pos:#x} in this space, whose highest is \
                         {max_address:#x} and whose middle may be non-canonical, so the scan of \
                         this range ends here"
                    ),
                }) {
                    return regions_cap;
                }
                pos = end;
            }
            Err(other) => {
                let length = page.min(end - pos);
                if !sink(WalkEvent::Missing {
                    address: pos,
                    length,
                    reason: GapReason::ReadFailed,
                    detail: other.to_string(),
                }) {
                    return regions_cap;
                }
                pos = pos.saturating_add(length);
            }
        }

        if pos <= before {
            // Nothing above advanced the cursor, which means the layer refused
            // this address in a way the scan could not classify. Step one page
            // and say so, rather than spin.
            let length = page.min(end - before);
            if !sink(WalkEvent::Missing {
                address: before,
                length,
                reason: GapReason::ReadFailed,
                detail: format!(
                    "the layer would not describe {before:#x}, so the scan stepped over it"
                ),
            }) {
                return regions_cap;
            }
            pos = before.saturating_add(length);
        }
    }
    ExtractStop::Exhausted
}

/// Whether a run of an address space is backed, and where it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanState {
    /// Every byte of the run has bytes behind it.
    Mapped,
    /// No byte of the run does.
    Missing {
        /// Why.
        reason: GapReason,
        /// The underlying failure, in the examiner's terms.
        detail: String,
    },
}

/// One contiguous run of an address space that is entirely mapped or entirely
/// missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// First address of the run.
    pub address: u64,
    /// How long it is.
    pub length: u64,
    /// Whether it is backed.
    pub state: SpanState,
}

/// Which parts of a requested range an address space can actually answer for.
#[derive(Debug, Clone)]
pub struct Coverage {
    /// First address asked about.
    pub start: u64,
    /// How many bytes were asked about.
    pub length: u64,
    /// The runs, ascending and non-overlapping: together they cover
    /// `[start, start + length)` exactly, unless [`Coverage::stop`] says a cap
    /// fired.
    pub spans: Vec<Span>,
    /// How many bytes are backed.
    pub mapped_bytes: u64,
    /// How many of `mapped_bytes` were reached through a prototype PTE.
    ///
    /// Those pages belong to a section object -- a mapped file, or memory
    /// shared with another process -- so the bytes are backed, but they are not
    /// necessarily this process's own. A dump that is 90% section-backed is a
    /// different piece of evidence from one that is entirely private, and
    /// nothing else in this summary distinguishes them.
    pub shared_bytes: u64,
    /// How many bytes are not.
    pub missing_bytes: u64,
    /// Why the scan ended.
    pub stop: ExtractStop,
}

impl Coverage {
    /// Whether every byte of the request is backed.
    pub fn is_fully_mapped(&self) -> bool {
        self.stop.is_complete() && self.missing_bytes == 0 && self.mapped_bytes == self.length
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "start": self.start,
            "length": self.length,
            "mapped_bytes": self.mapped_bytes,
            "shared_bytes": self.shared_bytes,
            "shared_bytes_meaning": "of mapped_bytes, how many were reached through a prototype \
                                     PTE and so belong to a section object (a mapped file, or \
                                     memory shared with another process) rather than to this \
                                     process alone",
            "missing_bytes": self.missing_bytes,
            "span_count": self.spans.len(),
            "stop": self.stop.as_str(),
            "fully_mapped": self.is_fully_mapped(),
        })
    }
}

/// Which parts of `[start, start + length)` this layer has bytes for.
///
/// The answer an extraction needs before it reads anything: it is what lets a
/// dump say "these twelve pages were never acquired" instead of returning
/// twelve pages of zeroes that look exactly like acquired zeroes.
///
/// # Errors
///
/// [`DumpError::TooLarge`] above [`ExtractConfig::max_bytes`], and
/// [`DumpError::Overflow`] when the range would leave the 64-bit space.
pub fn coverage(
    layer: &dyn MemoryLayer,
    start: u64,
    length: u64,
    config: &ExtractConfig,
) -> Result<Coverage, DumpError> {
    config.admit("a coverage scan", length)?;
    let end = start.checked_add(length).ok_or_else(|| {
        DumpError::overflow(format!(
            "{start:#x}+{length:#x} runs past the end of the 64-bit address space"
        ))
    })?;

    let mut spans: Vec<Span> = Vec::new();
    let mut mapped_bytes = 0u64;
    let mut shared_bytes = 0u64;
    let mut missing_bytes = 0u64;
    if length == 0 {
        return Ok(Coverage {
            start,
            length,
            spans,
            mapped_bytes,
            shared_bytes,
            missing_bytes,
            stop: ExtractStop::Exhausted,
        });
    }

    let stop = walk_space(layer, start, end, config, |event| {
        // Adjacent runs of the same kind merge: a fully mapped gibibyte is one
        // span, not a quarter of a million.
        let mut push = |address: u64, length: u64, state: SpanState| -> bool {
            if let Some(last) = spans.last_mut() {
                if last.state == state && last.address.saturating_add(last.length) == address {
                    last.length = last.length.saturating_add(length);
                    return true;
                }
            }
            if spans.len() >= config.max_regions {
                return false;
            }
            spans.push(Span {
                address,
                length,
                state,
            });
            true
        };
        match event {
            WalkEvent::Mapped(runs) => {
                for run in &runs {
                    mapped_bytes = mapped_bytes.saturating_add(run.length);
                    if run.via == Some("prototype_pte") {
                        shared_bytes = shared_bytes.saturating_add(run.length);
                    }
                    if !push(run.offset, run.length, SpanState::Mapped) {
                        return false;
                    }
                }
                true
            }
            WalkEvent::Missing {
                address,
                length,
                reason,
                detail,
            } => {
                missing_bytes = missing_bytes.saturating_add(length);
                push(address, length, SpanState::Missing { reason, detail })
            }
        }
    });

    Ok(Coverage {
        start,
        length,
        spans,
        mapped_bytes,
        shared_bytes,
        missing_bytes,
        stop,
    })
}

// ── vaddump: one region's bytes ─────────────────────────────────────────────

/// Extract `[start, start + length)` of an address space.
///
/// `space` must be the address space the range belongs to — for a VAD, the
/// process's own, not the kernel's. Reading a user address through the kernel's
/// page tables does not fail; it returns bytes from whatever the kernel has
/// mapped there, and those bytes parse.
///
/// Every unreadable page becomes a [`Gap`], never a zero.
///
/// # Errors
///
/// [`DumpError::TooLarge`] above the configured cap, [`DumpError::Overflow`]
/// when the range leaves the address space. A page that could not be read is
/// not an error.
pub fn dump_range(
    space: &dyn MemoryLayer,
    start: u64,
    length: u64,
    config: &ExtractConfig,
) -> Result<Extract, DumpError> {
    let cover = coverage(space, start, length, config)?;
    let mut builder = ExtractBuilder::new(config, ExtractLayout::Sparse);
    // No `break` on the cap: see `memory_dump`. Every span is still accounted
    // for, as a chunk, a gap, or a refusal.
    for span in &cover.spans {
        let offset = span.address.saturating_sub(start);
        match &span.state {
            SpanState::Mapped => read_into(&mut builder, space, span.address, span.length, offset),
            SpanState::Missing { reason, detail } => {
                builder.add_gap(offset, span.address, span.length, *reason, detail.clone())
            }
        }
    }
    if let ExtractStop::CapReached { what, cap } = cover.stop {
        builder.cap(what, cap);
    }
    Ok(builder.finish(length))
}

/// Extract the bytes of one virtual address descriptor's range.
///
/// This is upstream's `vaddump`. The range comes from [`crate::vad`], whose
/// `end` is the **last accessible byte**, so the length extracted is
/// `end − start + 1` and the last page of the allocation is included. Dropping
/// that `+ 1` loses a page of every region in the process, and a finding in
/// that page then belongs to nothing.
///
/// # Errors
///
/// As [`dump_range`].
pub fn dump_vad(
    space: &dyn MemoryLayer,
    vad: &Vad,
    config: &ExtractConfig,
) -> Result<Extract, DumpError> {
    dump_range(space, vad.start, vad.size(), config)
}

// ── memmap / memdump ────────────────────────────────────────────────────────

/// One mapped run of an address space, and where it would land in a dump of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    /// First address of the run.
    pub address: u64,
    /// How long it is.
    pub length: u64,
    /// Where its bytes are in the layer beneath — the physical offset, for a
    /// process address space over a physical image.
    pub mapped_offset: u64,
    /// Where this run starts in a [`memory_dump`] of the same range. The only
    /// thing that lets a caller say which address a byte of that dump came
    /// from, because a packed dump reserves nothing for what is missing.
    pub file_offset: u64,
}

impl MemoryRegion {
    /// One past the last address this run covers.
    pub fn end(&self) -> u64 {
        self.address.saturating_add(self.length)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            // Exact beside the number: these are 64-bit addresses and offsets,
            // JSON numbers are IEEE doubles, and anything above 2^53 reaches a
            // client rounded — by up to a kilobyte at kernel addresses, which
            // is several pages of somebody else's memory.
            "address_hex": format!("{:#x}", self.address),
            "length": self.length,
            "mapped_offset": self.mapped_offset,
            "mapped_offset_hex": format!("{:#x}", self.mapped_offset),
            "file_offset": self.file_offset,
            "file_offset_hex": format!("{:#x}", self.file_offset),
            "end": self.end(),
            "end_hex": format!("{:#x}", self.end()),
        })
    }
}

/// What a process — or any address space — has mapped.
#[derive(Debug, Clone)]
pub struct MemoryMap {
    /// First address scanned.
    pub start: u64,
    /// How many bytes were scanned.
    pub length: u64,
    /// The mapped runs, ascending by address.
    pub regions: Vec<MemoryRegion>,
    /// The ranges with nothing behind them, capped by
    /// [`ExtractConfig::max_recorded_gaps`]. Their `offset` is `address − start`.
    pub gaps: Vec<Gap>,
    /// How many distinct missing ranges there were. Exact past the cap.
    pub gap_total: usize,
    /// How many bytes are mapped.
    pub mapped_bytes: u64,
    /// How many bytes are not.
    pub missing_bytes: u64,
    /// Why the scan ended.
    pub stop: ExtractStop,
}

impl MemoryMap {
    /// Whether the whole requested range was scanned.
    ///
    /// Missing ranges do not make a map incomplete — an address space with
    /// nothing at 0x2000 is a fact about the process. A *cap* does, because
    /// then there is mapped memory the map does not mention.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete()
    }

    /// The region containing an address, if any.
    pub fn containing(&self, address: u64) -> Option<&MemoryRegion> {
        self.regions
            .iter()
            .find(|region| region.address <= address && address < region.end())
    }

    /// Everything a report must declare about this map.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let ExtractStop::CapReached { what, cap } = &self.stop {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the address-space scan from {:#x} stopped at its cap of {cap} {what}; the \
                     space continues",
                    self.start
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "start": self.start,
            "length": self.length,
            "regions": self.regions.iter().map(MemoryRegion::to_json).collect::<Vec<_>>(),
            "region_count": self.regions.len(),
            "mapped_bytes": self.mapped_bytes,
            "missing_bytes": self.missing_bytes,
            "gap_total": self.gap_total,
            "gaps": self.gaps.iter().map(Gap::to_json).collect::<Vec<_>>(),
            "stop": self.stop.as_str(),
            "complete": self.is_complete(),
        })
    }
}

/// Enumerate everything mapped in `[start, start + length)`.
///
/// This is upstream's `memmap`, minus its `ignore_errors` silence: a range with
/// nothing behind it is reported, with the reason, rather than skipped.
///
/// The scan is bounded by [`ExtractConfig::max_regions`] and
/// [`ExtractConfig::max_scan_steps`], and it skips an absent page directory in
/// one step rather than probing every page inside it.
///
/// # Errors
///
/// [`DumpError::Overflow`] when the range would leave the 64-bit space. There
/// is deliberately no size cap: a map is a list of ranges, not the bytes in
/// them, so scanning a whole address space costs nothing to hold.
pub fn memory_map(
    layer: &dyn MemoryLayer,
    start: u64,
    length: u64,
    config: &ExtractConfig,
) -> Result<MemoryMap, DumpError> {
    let end = start.checked_add(length).ok_or_else(|| {
        DumpError::overflow(format!(
            "{start:#x}+{length:#x} runs past the end of the 64-bit address space"
        ))
    })?;

    let mut regions: Vec<MemoryRegion> = Vec::new();
    let mut gaps: Vec<Gap> = Vec::new();
    let mut gap_total = 0usize;
    let mut mapped_bytes = 0u64;
    let mut missing_bytes = 0u64;
    let mut file_offset = 0u64;
    // End of the last missing range and its reason, tracked separately from
    // `gaps` so that merging stays correct — and `gap_total` therefore stays
    // exact — after the record cap has fired and there is no last entry to
    // merge into.
    let mut last_gap: Option<(u64, GapReason)> = None;

    let stop = if length == 0 {
        ExtractStop::Exhausted
    } else {
        walk_space(layer, start, end, config, |event| match event {
            WalkEvent::Mapped(runs) => {
                for run in &runs {
                    // Runs merge only when they are contiguous in *both* spaces.
                    // Two physically scattered pages are two rows, because only
                    // the page tables can say they are adjacent, and a map that
                    // claimed otherwise would point a caller at the wrong bytes
                    // of the acquisition file.
                    if let Some(last) = regions.last_mut() {
                        let virt = last.address.checked_add(last.length) == Some(run.offset);
                        let phys =
                            last.mapped_offset.checked_add(last.length) == Some(run.mapped_offset);
                        if virt && phys {
                            last.length = last.length.saturating_add(run.length);
                            mapped_bytes = mapped_bytes.saturating_add(run.length);
                            file_offset = file_offset.saturating_add(run.length);
                            continue;
                        }
                    }
                    if regions.len() >= config.max_regions {
                        return false;
                    }
                    regions.push(MemoryRegion {
                        address: run.offset,
                        length: run.length,
                        mapped_offset: run.mapped_offset,
                        file_offset,
                    });
                    mapped_bytes = mapped_bytes.saturating_add(run.length);
                    file_offset = file_offset.saturating_add(run.length);
                }
                true
            }
            WalkEvent::Missing {
                address,
                length,
                reason,
                detail,
            } => {
                missing_bytes = missing_bytes.saturating_add(length);
                let mergeable = last_gap == Some((address, reason));
                last_gap = Some((address.saturating_add(length), reason));
                if mergeable {
                    if let Some(last) = gaps.last_mut() {
                        if last.reason == reason
                            && last.address.saturating_add(last.length) == address
                        {
                            last.length = last.length.saturating_add(length);
                            return true;
                        }
                    }
                    // The record list was capped before this run began, so the
                    // merge has nowhere to land. The count and the byte total
                    // are still right, which is what a report needs.
                    return true;
                }
                gap_total += 1;
                if gaps.len() < config.max_recorded_gaps {
                    gaps.push(Gap {
                        offset: address.saturating_sub(start),
                        address,
                        length,
                        reason,
                        detail,
                    });
                }
                true
            }
        })
    };

    Ok(MemoryMap {
        start,
        length,
        regions,
        gaps,
        gap_total,
        mapped_bytes,
        missing_bytes,
        stop,
    })
}

/// Extract everything mapped in `[start, start + length)`, region by region.
///
/// This is upstream's `memmap --dump`. The artifact is
/// [`ExtractLayout::Packed`]: only mapped bytes are written, in ascending
/// address order, and nothing is reserved for what is not mapped. That is the
/// honest layout for a whole address space — reserving the unmapped parts of a
/// 128 TiB user space would produce a 128 TiB file of invented zeroes — and it
/// is why every chunk carries the address its bytes came from.
///
/// The [`MemoryMap`] the extraction was built from is returned with it, because
/// without the region table the packed bytes cannot be attributed to addresses.
///
/// # Errors
///
/// [`DumpError::TooLarge`] when the mapped bytes exceed the cap, which is
/// checked *before* any of them are read.
pub fn memory_dump(
    layer: &dyn MemoryLayer,
    start: u64,
    length: u64,
    config: &ExtractConfig,
) -> Result<(MemoryMap, Extract), DumpError> {
    let map = memory_map(layer, start, length, config)?;
    config.admit("a memory dump", map.mapped_bytes)?;

    let mut builder = ExtractBuilder::new(config, ExtractLayout::Packed);
    // No `break` on the cap: `read_into` accounts for a range it will not
    // write as a refused gap, so every byte of the declared length stays either
    // in a chunk or in the gap map. Breaking out here left the remaining
    // regions in neither, and a gap map that omits them reads as a capture that
    // never held those pages.
    for region in &map.regions {
        read_into(
            &mut builder,
            layer,
            region.address,
            region.length,
            region.file_offset,
        );
    }
    if let ExtractStop::CapReached { what, cap } = map.stop {
        builder.cap(what, cap);
    }
    let extract = builder.finish(map.mapped_bytes);
    Ok((map, extract))
}

// ── PE headers ──────────────────────────────────────────────────────────────

/// `IMAGE_DOS_HEADER.e_magic`.
const DOS_MAGIC: [u8; 2] = *b"MZ";
/// `IMAGE_NT_HEADERS.Signature`.
const NT_SIGNATURE: [u8; 4] = *b"PE\0\0";
/// Bytes of DOS header read to reach `e_lfanew`.
const DOS_HEADER_BYTES: u64 = 0x40;
/// Offset of `IMAGE_DOS_HEADER.e_lfanew`.
const E_LFANEW_OFFSET: usize = 0x3C;
/// Largest `e_lfanew` this reader will follow. Far beyond every real DOS stub.
const MAX_E_LFANEW: u32 = 0x1_0000;
/// Offset of `IMAGE_FILE_HEADER` inside `IMAGE_NT_HEADERS`.
const FILE_HEADER_OFFSET: u64 = 4;
/// Size of `IMAGE_FILE_HEADER`.
const FILE_HEADER_BYTES: u64 = 20;
/// Offset of `IMAGE_FILE_HEADER.NumberOfSections`.
const FILE_NUMBER_OF_SECTIONS: usize = 2;
/// Offset of `IMAGE_FILE_HEADER.SizeOfOptionalHeader`.
const FILE_SIZE_OF_OPTIONAL: usize = 16;
/// Offset of `IMAGE_OPTIONAL_HEADER` inside `IMAGE_NT_HEADERS`.
const OPTIONAL_HEADER_OFFSET: u64 = FILE_HEADER_OFFSET + FILE_HEADER_BYTES;
/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`.
const PE32_MAGIC: u16 = 0x010B;
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
const PE32_PLUS_MAGIC: u16 = 0x020B;
/// Offset of `ImageBase` in a PE32+ optional header.
const OPT64_IMAGE_BASE: usize = 0x18;
/// Offset of `ImageBase` in a PE32 optional header: four bytes later, after
/// `BaseOfData`, and four bytes wide rather than eight.
const OPT32_IMAGE_BASE: usize = 0x1C;
/// Offset of `SectionAlignment`, identical in both optional-header shapes.
const OPT_SECTION_ALIGNMENT: usize = 0x20;
/// Offset of `FileAlignment`.
const OPT_FILE_ALIGNMENT: usize = 0x24;
/// Offset of `SizeOfImage`.
const OPT_SIZE_OF_IMAGE: usize = 0x38;
/// Offset of `SizeOfHeaders`.
const OPT_SIZE_OF_HEADERS: usize = 0x3C;
/// Offset of `NumberOfRvaAndSizes` in a PE32 optional header.
const OPT32_NUMBER_OF_RVA: usize = 0x5C;
/// Offset of `NumberOfRvaAndSizes` in a PE32+ optional header.
const OPT64_NUMBER_OF_RVA: usize = 0x6C;
/// Offset of `DataDirectory[0]` in a PE32 optional header.
const OPT32_DATA_DIRECTORY: usize = 0x60;
/// Offset of `DataDirectory[0]` in a PE32+ optional header.
const OPT64_DATA_DIRECTORY: usize = 0x70;
/// Size of one `IMAGE_DATA_DIRECTORY`.
const DATA_DIRECTORY_BYTES: usize = 8;
/// Largest `NumberOfRvaAndSizes` the format defines.
const MAX_DATA_DIRECTORIES: u32 = 16;
/// Size of one `IMAGE_SECTION_HEADER`.
const SECTION_HEADER_BYTES: u64 = 40;
/// Offset of `IMAGE_SECTION_HEADER.Misc.VirtualSize`.
const SECTION_VIRTUAL_SIZE: usize = 8;
/// Offset of `IMAGE_SECTION_HEADER.VirtualAddress`.
const SECTION_VIRTUAL_ADDRESS: usize = 12;
/// Offset of `IMAGE_SECTION_HEADER.SizeOfRawData`.
const SECTION_SIZE_OF_RAW_DATA: usize = 16;
/// Offset of `IMAGE_SECTION_HEADER.PointerToRawData`.
const SECTION_POINTER_TO_RAW_DATA: usize = 20;
/// Offset of `IMAGE_SECTION_HEADER.Characteristics`.
const SECTION_CHARACTERISTICS: usize = 36;
/// Largest optional header this reader will read.
const MAX_OPTIONAL_HEADER_BYTES: u64 = 0x1000;
/// Largest number of sections this reader will follow, which is the format's
/// own limit for an image that has a section table.
const MAX_SECTIONS: u16 = 96;

/// `IMAGE_DIRECTORY_ENTRY_EXPORT`.
pub const DIRECTORY_ENTRY_EXPORT: usize = 0;
/// `IMAGE_DIRECTORY_ENTRY_IMPORT`.
pub const DIRECTORY_ENTRY_IMPORT: usize = 1;

/// Largest image this reader will reconstruct, in bytes.
///
/// Matches upstream's `PE_MAX_EXTRACTION_SIZE`. A `SizeOfImage` above it is not
/// a large program, it is a corrupt or hostile header, and allocating for it is
/// not something the examiner asked for.
pub const MAX_PE_IMAGE_BYTES: u64 = 1 << 30;

/// Little-endian `u16` at `at`, or `None` past the end of the buffer.
fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

/// Little-endian `u32` at `at`.
fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Little-endian `u64` at `at`.
fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let slice = bytes.get(at..at.checked_add(8)?)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(slice);
    Some(u64::from_le_bytes(raw))
}

/// Round `value` up to a multiple of `alignment`, refusing to wrap.
fn round_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment <= 1 {
        return Some(value);
    }
    let remainder = value % alignment;
    if remainder == 0 {
        return Some(value);
    }
    value.checked_add(alignment - remainder)
}

/// One entry of the optional header's data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataDirectory {
    /// Relative virtual address of the table, or 0 when there is none.
    pub virtual_address: u32,
    /// Its size in bytes.
    pub size: u32,
}

impl DataDirectory {
    /// Whether this directory names anything at all.
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// One `IMAGE_SECTION_HEADER`, as read out of memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    /// The eight-byte name, NUL-trimmed, with non-printable bytes replaced. A
    /// section name is attacker-controlled: it is rendered, never used to
    /// decide anything.
    pub name: String,
    /// `Misc.VirtualSize`: how much of the section the loader maps.
    pub virtual_size: u32,
    /// Where the section is once loaded, relative to the image base.
    pub virtual_address: u32,
    /// How many bytes the section occupies in the on-disk file.
    pub size_of_raw_data: u32,
    /// Where those bytes are in the on-disk file.
    pub pointer_to_raw_data: u32,
    /// Section characteristics, unaltered.
    pub characteristics: u32,
    /// Offset of this header from the image base, so a rewrite of it can be
    /// placed without re-deriving the section table's position.
    pub header_offset: u64,
}

impl SectionHeader {
    /// How many bytes of this section a *memory* image holds.
    ///
    /// The loader maps `SizeOfRawData` bytes and zero-fills the rest of the
    /// section up to `SectionAlignment`, so what is present at
    /// `base + VirtualAddress` is the aligned virtual size and no more. A
    /// `SizeOfRawData` larger than that is file padding whose bytes were never
    /// in memory; reading it would take the *next* section's bytes and file
    /// them under this one.
    ///
    /// A `VirtualSize` of zero is the old linker convention for "as big as
    /// `SizeOfRawData`", so it is read that way rather than as an empty section.
    pub fn mapped_bytes(&self, section_alignment: u32) -> Option<u64> {
        let declared = if self.virtual_size == 0 {
            u64::from(self.size_of_raw_data)
        } else {
            u64::from(self.virtual_size)
        };
        round_up(declared, u64::from(section_alignment))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "virtual_size": self.virtual_size,
            "virtual_address": self.virtual_address,
            "size_of_raw_data": self.size_of_raw_data,
            "pointer_to_raw_data": self.pointer_to_raw_data,
            "characteristics": self.characteristics,
            "header_offset": self.header_offset,
        })
    }
}

/// The headers of one PE image, read from the address it is loaded at.
#[derive(Debug, Clone)]
pub struct PeHeaders {
    /// Where the image is loaded, in the space it was read through.
    pub base: u64,
    /// Whether the optional header is PE32+.
    pub pe32_plus: bool,
    /// `IMAGE_FILE_HEADER.Machine`.
    pub machine: u16,
    /// Offset of the NT headers from the image base (`e_lfanew`).
    pub nt_offset: u64,
    /// Offset of the optional header from the image base.
    pub optional_offset: u64,
    /// `IMAGE_FILE_HEADER.SizeOfOptionalHeader`.
    pub size_of_optional_header: u16,
    /// Offset of the section table from the image base.
    pub section_table_offset: u64,
    /// `OptionalHeader.ImageBase`: where the linker expected the image to load.
    /// A value different from [`PeHeaders::base`] means it was relocated.
    pub image_base: u64,
    /// `OptionalHeader.SectionAlignment`.
    pub section_alignment: u32,
    /// `OptionalHeader.FileAlignment`.
    pub file_alignment: u32,
    /// `OptionalHeader.SizeOfImage`: the span the loaded image occupies.
    pub size_of_image: u32,
    /// `OptionalHeader.SizeOfHeaders`: how much of the file the headers take,
    /// and equally how much of memory they occupy at the base.
    pub size_of_headers: u32,
    /// The data directory, in declaration order.
    pub directories: Vec<DataDirectory>,
    /// The section table.
    pub sections: Vec<SectionHeader>,
    /// Everything odd about the headers that did not disqualify them.
    pub notes: Vec<String>,
}

impl PeHeaders {
    /// Whether the image is loaded where its linker expected.
    ///
    /// `false` means the loader relocated it, which matters to any comparison
    /// against the file on disk: every absolute address inside it was rewritten,
    /// so the two will not hash alike however complete the extraction is.
    pub fn loaded_at_preferred_base(&self) -> bool {
        self.image_base == self.base
    }

    /// One entry of the data directory, or an all-zero entry when this image
    /// declares fewer than `index + 1` of them.
    pub fn directory(&self, index: usize) -> DataDirectory {
        self.directories.get(index).copied().unwrap_or_default()
    }

    /// Address of a relative virtual address, in the space the image was read
    /// through.
    pub fn address_of(&self, rva: u32) -> Option<u64> {
        self.base.checked_add(u64::from(rva))
    }

    /// The section containing an RVA, if any.
    pub fn section_at(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections.iter().find(|section| {
            let span = u64::from(section.virtual_size.max(section.size_of_raw_data));
            rva >= section.virtual_address
                && u64::from(rva) < u64::from(section.virtual_address) + span
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "base": self.base,
            "pe32_plus": self.pe32_plus,
            "machine": self.machine,
            "image_base": self.image_base,
            "relocated": !self.loaded_at_preferred_base(),
            "section_alignment": self.section_alignment,
            "file_alignment": self.file_alignment,
            "size_of_image": self.size_of_image,
            "size_of_headers": self.size_of_headers,
            "sections": self.sections.iter().map(SectionHeader::to_json).collect::<Vec<_>>(),
            "notes": self.notes,
        })
    }
}

/// Read a fixed-size structural header, naming it if the bytes are not there.
fn read_header(
    layer: &dyn MemoryLayer,
    address: u64,
    length: u64,
    what: &str,
) -> Result<Vec<u8>, DumpError> {
    read_exact_bytes(layer, address, length).map_err(|(_, detail)| DumpError::Unreadable {
        what: what.to_string(),
        address,
        detail,
    })
}

/// Read and validate one PE image's headers from the address it is loaded at.
///
/// Every field is taken from the image itself; nothing is defaulted. A header
/// whose magic, section count, alignments or `SizeOfImage` is not one a loader
/// would have accepted is [`DumpError::NotPe`] naming the check that failed,
/// because a reconstruction from a header that never loaded is a file that
/// never existed.
///
/// # Errors
///
/// [`DumpError::Unreadable`] when the header bytes were not acquired — the
/// ordinary case for a paged-out DLL, and reported rather than papered over —
/// and [`DumpError::NotPe`] when they were acquired and are not a PE.
pub fn read_pe_headers(layer: &dyn MemoryLayer, base: u64) -> Result<PeHeaders, DumpError> {
    let mut notes = Vec::new();

    let dos = read_header(layer, base, DOS_HEADER_BYTES, "the DOS header")?;
    if dos.get(..2) != Some(&DOS_MAGIC[..]) {
        return Err(DumpError::NotPe {
            base,
            detail: "the first two bytes are not 'MZ'".to_string(),
        });
    }
    let e_lfanew = u32_at(&dos, E_LFANEW_OFFSET).ok_or_else(|| DumpError::NotPe {
        base,
        detail: "the DOS header is too short to hold e_lfanew".to_string(),
    })?;
    if e_lfanew > MAX_E_LFANEW {
        return Err(DumpError::NotPe {
            base,
            detail: format!(
                "e_lfanew is {e_lfanew:#x}, beyond the {MAX_E_LFANEW:#x} this reader will follow"
            ),
        });
    }
    let nt_offset = u64::from(e_lfanew);
    let nt_address = base.checked_add(nt_offset).ok_or_else(|| {
        DumpError::overflow(format!("{base:#x}+{nt_offset:#x} leaves the address space"))
    })?;

    let fixed = read_header(
        layer,
        nt_address,
        OPTIONAL_HEADER_OFFSET,
        "the NT file header",
    )?;
    if fixed.get(..4) != Some(&NT_SIGNATURE[..]) {
        return Err(DumpError::NotPe {
            base,
            detail: format!("the four bytes at e_lfanew ({nt_address:#x}) are not 'PE\\0\\0'"),
        });
    }
    let file_header = &fixed[FILE_HEADER_OFFSET as usize..];
    let machine = u16_at(file_header, 0).unwrap_or(0);
    let number_of_sections = u16_at(file_header, FILE_NUMBER_OF_SECTIONS).unwrap_or(0);
    let size_of_optional_header = u16_at(file_header, FILE_SIZE_OF_OPTIONAL).unwrap_or(0);
    if number_of_sections > MAX_SECTIONS {
        return Err(DumpError::NotPe {
            base,
            detail: format!(
                "the file header declares {number_of_sections} sections, above the {MAX_SECTIONS} \
                 a PE may have"
            ),
        });
    }
    if u64::from(size_of_optional_header) > MAX_OPTIONAL_HEADER_BYTES {
        return Err(DumpError::NotPe {
            base,
            detail: format!(
                "the optional header is declared {size_of_optional_header} byte(s), which no \
                 loader would accept"
            ),
        });
    }

    let optional_offset = nt_offset
        .checked_add(OPTIONAL_HEADER_OFFSET)
        .ok_or_else(|| DumpError::overflow("the optional header's offset leaves the image"))?;
    let optional_address = base.checked_add(optional_offset).ok_or_else(|| {
        DumpError::overflow("the optional header's address leaves the address space")
    })?;
    let optional = read_header(
        layer,
        optional_address,
        u64::from(size_of_optional_header),
        "the optional header",
    )?;

    let magic = u16_at(&optional, 0).ok_or_else(|| DumpError::NotPe {
        base,
        detail: "the optional header is empty".to_string(),
    })?;
    let pe32_plus = match magic {
        PE32_MAGIC => false,
        PE32_PLUS_MAGIC => true,
        other => {
            return Err(DumpError::NotPe {
                base,
                detail: format!(
                    "the optional header magic is {other:#06x}, neither PE32 nor PE32+"
                ),
            })
        }
    };

    let missing = |field: &str| DumpError::NotPe {
        base,
        detail: format!("the optional header is too short to hold {field}"),
    };
    let image_base = if pe32_plus {
        u64_at(&optional, OPT64_IMAGE_BASE).ok_or_else(|| missing("ImageBase"))?
    } else {
        u64::from(u32_at(&optional, OPT32_IMAGE_BASE).ok_or_else(|| missing("ImageBase"))?)
    };
    let section_alignment =
        u32_at(&optional, OPT_SECTION_ALIGNMENT).ok_or_else(|| missing("SectionAlignment"))?;
    let file_alignment =
        u32_at(&optional, OPT_FILE_ALIGNMENT).ok_or_else(|| missing("FileAlignment"))?;
    let size_of_image =
        u32_at(&optional, OPT_SIZE_OF_IMAGE).ok_or_else(|| missing("SizeOfImage"))?;
    let size_of_headers =
        u32_at(&optional, OPT_SIZE_OF_HEADERS).ok_or_else(|| missing("SizeOfHeaders"))?;

    if section_alignment == 0 {
        return Err(DumpError::NotPe {
            base,
            detail: "SectionAlignment is zero, so no section has a place in memory".to_string(),
        });
    }
    if file_alignment == 0 {
        return Err(DumpError::NotPe {
            base,
            detail: "FileAlignment is zero, so no section has a place in the file".to_string(),
        });
    }
    if section_alignment < file_alignment {
        notes.push(format!(
            "SectionAlignment ({section_alignment:#x}) is below FileAlignment \
             ({file_alignment:#x}), which no linker produces"
        ));
    }
    if size_of_image == 0 {
        // A zero here is the one value that must not be carried forward: a
        // memory-aligned reconstruction of it is a zero-length artifact with no
        // gaps, which reports itself as a complete and faithful copy of an
        // image that occupies no memory and that no loader ever mapped.
        return Err(DumpError::NotPe {
            base,
            detail: "SizeOfImage is zero, so this header describes an image that occupies no \
                     memory and could not have been loaded"
                .to_string(),
        });
    }
    if u64::from(size_of_image) > MAX_PE_IMAGE_BYTES {
        return Err(DumpError::TooLarge {
            what: "the image SizeOfImage claims",
            requested: u64::from(size_of_image),
            cap: MAX_PE_IMAGE_BYTES,
        });
    }
    if size_of_headers > size_of_image {
        notes.push(format!(
            "SizeOfHeaders ({size_of_headers:#x}) is larger than SizeOfImage ({size_of_image:#x})"
        ));
    }

    let (rva_count_offset, directory_offset) = if pe32_plus {
        (OPT64_NUMBER_OF_RVA, OPT64_DATA_DIRECTORY)
    } else {
        (OPT32_NUMBER_OF_RVA, OPT32_DATA_DIRECTORY)
    };
    // A header too short to hold NumberOfRvaAndSizes is not a header that
    // declares none: silently reading zero turns "could not be read" into
    // "there are no data directories", and the caller cannot tell a module with
    // no exports from one whose header never arrived. The over-large case below
    // pushes a note; so does this.
    let declared = match u32_at(&optional, rva_count_offset) {
        Some(declared) => declared,
        None => {
            notes.push(format!(
                "the optional header is {} byte(s), too short to hold NumberOfRvaAndSizes at \
                 {rva_count_offset:#x}, so no data directory could be read; this is not the \
                 same as the module declaring none",
                optional.len()
            ));
            0
        }
    };
    let count = declared.min(MAX_DATA_DIRECTORIES) as usize;
    if declared > MAX_DATA_DIRECTORIES {
        notes.push(format!(
            "NumberOfRvaAndSizes is {declared}, above the {MAX_DATA_DIRECTORIES} the format \
             defines; the extra entries are not read"
        ));
    }
    let mut directories = Vec::new();
    for index in 0..count {
        let at = directory_offset + index * DATA_DIRECTORY_BYTES;
        let Some(virtual_address) = u32_at(&optional, at) else {
            notes.push(format!(
                "the optional header declares {count} data directories and holds {index}"
            ));
            break;
        };
        let size = u32_at(&optional, at + 4).unwrap_or(0);
        directories.push(DataDirectory {
            virtual_address,
            size,
        });
    }

    let section_table_offset = optional_offset
        .checked_add(u64::from(size_of_optional_header))
        .ok_or_else(|| DumpError::overflow("the section table's offset leaves the image"))?;
    let section_table_address = base
        .checked_add(section_table_offset)
        .ok_or_else(|| DumpError::overflow("the section table's address leaves the space"))?;
    let table_bytes = u64::from(number_of_sections)
        .checked_mul(SECTION_HEADER_BYTES)
        .ok_or_else(|| DumpError::overflow("the section table's size leaves the image"))?;
    let table = if table_bytes == 0 {
        Vec::new()
    } else {
        read_header(
            layer,
            section_table_address,
            table_bytes,
            "the section table",
        )?
    };

    let mut sections = Vec::new();
    for index in 0..number_of_sections as usize {
        let at = index * SECTION_HEADER_BYTES as usize;
        let Some(raw) = table.get(at..at + SECTION_HEADER_BYTES as usize) else {
            notes.push(format!(
                "the section table holds fewer than the {number_of_sections} headers it declares"
            ));
            break;
        };
        let name = raw
            .iter()
            .take(8)
            .take_while(|&&byte| byte != 0)
            .map(|&byte| {
                if (0x20..0x7F).contains(&byte) {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect::<String>();
        sections.push(SectionHeader {
            name,
            virtual_size: u32_at(raw, SECTION_VIRTUAL_SIZE).unwrap_or(0),
            virtual_address: u32_at(raw, SECTION_VIRTUAL_ADDRESS).unwrap_or(0),
            size_of_raw_data: u32_at(raw, SECTION_SIZE_OF_RAW_DATA).unwrap_or(0),
            pointer_to_raw_data: u32_at(raw, SECTION_POINTER_TO_RAW_DATA).unwrap_or(0),
            characteristics: u32_at(raw, SECTION_CHARACTERISTICS).unwrap_or(0),
            header_offset: section_table_offset.saturating_add(at as u64),
        });
    }

    // Upstream raises on each of these part-way through writing the output
    // file. Checking them here means a caller learns the header is wrong before
    // any bytes have been attributed to it.
    for section in &sections {
        let name = &section.name;
        if u64::from(section.virtual_address) > u64::from(size_of_image) {
            return Err(DumpError::NotPe {
                base,
                detail: format!(
                    "section {name:?} starts at RVA {:#x}, past the image's own SizeOfImage \
                     ({size_of_image:#x})",
                    section.virtual_address
                ),
            });
        }
        if u64::from(section.virtual_size) > u64::from(size_of_image) {
            return Err(DumpError::NotPe {
                base,
                detail: format!(
                    "section {name:?} declares a VirtualSize of {:#x}, larger than the whole image",
                    section.virtual_size
                ),
            });
        }
        if u64::from(section.size_of_raw_data) > u64::from(size_of_image) {
            return Err(DumpError::NotPe {
                base,
                detail: format!(
                    "section {name:?} declares a SizeOfRawData of {:#x}, larger than the whole \
                     image",
                    section.size_of_raw_data
                ),
            });
        }
    }

    Ok(PeHeaders {
        base,
        pe32_plus,
        machine,
        nt_offset,
        optional_offset,
        size_of_optional_header,
        section_table_offset,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        directories,
        sections,
        notes,
    })
}

// ── pedump ──────────────────────────────────────────────────────────────────

/// How a PE extracted from memory is laid back out.
///
/// A loaded image and its file are not the same object. The loader places each
/// section at `VirtualAddress`, aligned to `SectionAlignment` (a page), while
/// the file places it at `PointerToRawData`, aligned to `FileAlignment`
/// (usually 512 bytes). Copying `SizeOfImage` bytes verbatim therefore does not
/// produce the file; it produces the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeLayout {
    /// Re-lay the sections out at their **file** offsets, so the artifact has
    /// the shape the on-disk file had. Nothing in the headers is altered, so
    /// what comes out is directly comparable with a copy of the file taken from
    /// the disk image — as far as the loader's own edits to the mapped pages
    /// allow, which for a relocated image is not very far.
    ///
    /// The alignment padding *between* sections exists only in the file and was
    /// never in memory, so it is reported as [`GapReason::NotInMemory`] rather
    /// than filled with the zeroes it almost certainly was.
    FileAligned,
    /// Copy `[base, base + SizeOfImage)` as it sits in memory and rewrite each
    /// section header so `PointerToRawData` equals `VirtualAddress`. This is
    /// what upstream's `pedump` produces: not the original file, but a file a
    /// disassembler will load at the right addresses.
    ///
    /// Every rewritten field is recorded in [`PeDump::patches`].
    MemoryAligned,
}

impl PeLayout {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            PeLayout::FileAligned => "file_aligned",
            PeLayout::MemoryAligned => "memory_aligned",
        }
    }
}

/// One field of the extracted image that this module changed.
///
/// Every byte of an extracted artifact that does not come from the evidence has
/// a record here. There is no path that alters a byte without producing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PePatch {
    /// Where in the artifact the change was made.
    pub offset: u64,
    /// Which field, in the examiner's terms.
    pub field: String,
    /// The bytes as acquired.
    pub was: Vec<u8>,
    /// The bytes written over them.
    pub now: Vec<u8>,
    /// Whether the change was actually applied. `false` means the field landed
    /// in a gap, so the artifact still holds nothing there.
    pub applied: bool,
}

impl PePatch {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "offset": self.offset,
            "field": self.field,
            "was": self.was.iter().map(|b| u64::from(*b)).collect::<Vec<_>>(),
            "now": self.now.iter().map(|b| u64::from(*b)).collect::<Vec<_>>(),
            "applied": self.applied,
        })
    }
}

/// Caps and choices for one PE reconstruction.
#[derive(Debug, Clone)]
pub struct PeDumpConfig {
    /// How the sections are laid out.
    pub layout: PeLayout,
    /// Whether to rewrite `OptionalHeader.ImageBase` to the address the image
    /// was actually found at.
    ///
    /// Off by default, and deliberately so. Upstream always rewrites it, which
    /// makes the artifact easier to disassemble and makes it *not the bytes
    /// that were in memory*. When it is on, the change is recorded in
    /// [`PeDump::patches`] like any other.
    pub rewrite_image_base: bool,
    /// Ceiling on the reconstructed file's length.
    pub max_image_bytes: u64,
    /// Caps for the underlying reads.
    pub extract: ExtractConfig,
}

impl Default for PeDumpConfig {
    fn default() -> Self {
        Self {
            layout: PeLayout::FileAligned,
            rewrite_image_base: false,
            max_image_bytes: MAX_PE_IMAGE_BYTES,
            extract: ExtractConfig::default(),
        }
    }
}

/// A PE image reconstructed from memory.
#[derive(Debug, Clone)]
pub struct PeDump {
    /// Where the image was found.
    pub base: u64,
    /// The headers it was reconstructed from.
    pub headers: PeHeaders,
    /// How it was laid out.
    pub layout: PeLayout,
    /// The bytes, and everything missing from them.
    pub extract: Extract,
    /// Every field this module changed.
    pub patches: Vec<PePatch>,
}

impl PeDump {
    /// Whether the artifact is byte-for-byte what the evidence held.
    ///
    /// `false` when anything was missing **or** when any field was rewritten.
    /// The two are different failures of fidelity and both disqualify a hash of
    /// the artifact from standing for the original.
    pub fn is_faithful(&self) -> bool {
        self.extract.is_complete() && self.patches.iter().all(|patch| !patch.applied)
    }

    /// Everything a report must declare about this reconstruction.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.extract.incomplete();
        let applied = self.patches.iter().filter(|patch| patch.applied).count();
        if applied > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{applied} header field(s) of the image at {:#x} were rewritten during \
                     reconstruction, so its bytes are not those the evidence held",
                    self.base
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "base": self.base,
            "layout": self.layout.as_str(),
            "headers": self.headers.to_json(),
            "extract": self.extract.to_json(),
            "patches": self.patches.iter().map(PePatch::to_json).collect::<Vec<_>>(),
            "faithful": self.is_faithful(),
        })
    }
}

/// One piece of the reconstructed file, planned before anything is read.
///
/// Planning the whole layout first is what lets the length be checked against
/// the cap before a single byte is extracted, and what keeps the chunks and the
/// gaps both ascending by offset.
enum Piece {
    /// Bytes to be read from `address` into the artifact at `offset`.
    Region {
        offset: u64,
        address: u64,
        length: u64,
    },
    /// A range of the file that memory does not hold.
    Hole {
        offset: u64,
        address: u64,
        length: u64,
        reason: GapReason,
        detail: String,
    },
}

impl Piece {
    /// Where this piece starts in the artifact, for ordering.
    fn offset(&self) -> u64 {
        match self {
            Piece::Region { offset, .. } | Piece::Hole { offset, .. } => *offset,
        }
    }
}

/// Reconstruct a PE image from the address it is loaded at.
///
/// This is upstream's `pedump`, and `dlllist --dump`, and the reconstruction
/// step `iat` performs before parsing. The difference from upstream is what
/// happens to the pages that are not there: upstream reads the whole image with
/// `pad=True` and writes zeroes for them, so the file it produces is a complete
/// PE that was never on the suspect's disk. Here they are [`Extract::gaps`].
///
/// # Errors
///
/// [`DumpError::NotPe`] when the headers are not a loadable PE,
/// [`DumpError::Unreadable`] when the headers themselves were never acquired,
/// and [`DumpError::TooLarge`] when the reconstructed file would exceed
/// [`PeDumpConfig::max_image_bytes`].
pub fn dump_pe(
    layer: &dyn MemoryLayer,
    base: u64,
    config: &PeDumpConfig,
) -> Result<PeDump, DumpError> {
    let headers = read_pe_headers(layer, base)?;
    let mut builder = ExtractBuilder::new(&config.extract, ExtractLayout::Sparse);
    let mut pieces: Vec<Piece> = Vec::new();

    let length = match config.layout {
        PeLayout::MemoryAligned => {
            let length = u64::from(headers.size_of_image);
            pieces.push(Piece::Region {
                offset: 0,
                address: base,
                length,
            });
            length
        }
        PeLayout::FileAligned => {
            // Headers first: the loader maps them verbatim at the image base,
            // so the file's first `SizeOfHeaders` bytes are exactly the memory's.
            let header_bytes = u64::from(headers.size_of_headers);
            let mut end = header_bytes;
            if header_bytes > 0 {
                pieces.push(Piece::Region {
                    offset: 0,
                    address: base,
                    length: header_bytes,
                });
            }

            // Ascending by file offset, so an overlap is detectable against the
            // region already placed rather than against all of them.
            let mut ordered: Vec<&SectionHeader> = headers.sections.iter().collect();
            ordered.sort_by_key(|section| section.pointer_to_raw_data);

            for section in ordered {
                let raw_size = u64::from(section.size_of_raw_data);
                if raw_size == 0 {
                    // Uninitialised data: the file holds nothing for it, so the
                    // reconstruction holds nothing for it either.
                    continue;
                }
                let pointer = u64::from(section.pointer_to_raw_data);
                if pointer == 0 {
                    builder.note(format!(
                        "section {:?} declares {raw_size:#x} byte(s) of raw data at file offset 0, \
                         which is inside the headers, so it is not placed",
                        section.name
                    ));
                    continue;
                }
                let Some(section_end) = pointer.checked_add(raw_size) else {
                    builder.note(format!(
                        "section {:?} runs past the end of the 64-bit offset space, so it is not \
                         placed",
                        section.name
                    ));
                    continue;
                };
                if pointer < end {
                    // Two sections claiming the same file bytes is a malformed
                    // or deliberately overlapped image. Writing the second over
                    // the first would silently pick a winner.
                    builder.note(format!(
                        "section {:?} claims file offsets {pointer:#x}..{section_end:#x}, which \
                         overlap what is already placed, so it is not written",
                        section.name
                    ));
                    continue;
                }
                let Some(address) = headers.address_of(section.virtual_address) else {
                    builder.note(format!(
                        "section {:?} maps at an address outside the 64-bit space",
                        section.name
                    ));
                    continue;
                };
                let available = section
                    .mapped_bytes(headers.section_alignment)
                    .unwrap_or(raw_size);
                let take = raw_size.min(available);

                if pointer > end {
                    // File-alignment padding. It exists in the file and never
                    // existed in memory, so it is a gap: writing the zeroes it
                    // almost certainly held is exactly the fabrication this
                    // module refuses.
                    pieces.push(Piece::Hole {
                        offset: end,
                        address: 0,
                        length: pointer - end,
                        reason: GapReason::NotInMemory,
                        detail: format!(
                            "file-alignment padding before section {:?}; these bytes exist only \
                             in the on-disk file and were never in memory",
                            section.name
                        ),
                    });
                }
                pieces.push(Piece::Region {
                    offset: pointer,
                    address,
                    length: take,
                });
                if take < raw_size {
                    pieces.push(Piece::Hole {
                        offset: pointer.saturating_add(take),
                        address: address.saturating_add(take),
                        length: raw_size - take,
                        reason: GapReason::NotInMemory,
                        detail: format!(
                            "section {:?} declares {raw_size:#x} file byte(s) and the loader maps \
                             only {available:#x} of them; the remainder is file padding that was \
                             never in memory",
                            section.name
                        ),
                    });
                }
                end = section_end;
            }
            end
        }
    };

    if length > config.max_image_bytes {
        return Err(DumpError::TooLarge {
            what: "the reconstructed PE file",
            requested: length,
            cap: config.max_image_bytes,
        });
    }
    config.extract.admit("a reconstructed PE file", length)?;

    // Ascending by offset, so the builder's chunks and its gaps both come out
    // ascending, which is what every consumer of an `Extract` relies on.
    pieces.sort_by_key(Piece::offset);
    // No `break` on the cap: see `memory_dump`. A piece that will not be
    // written is still accounted for.
    for piece in pieces {
        match piece {
            Piece::Region {
                offset,
                address,
                length,
            } => read_into(&mut builder, layer, address, length, offset),
            Piece::Hole {
                offset,
                address,
                length,
                reason,
                detail,
            } => builder.add_gap(offset, address, length, reason, detail),
        }
    }

    let mut extract = builder.finish(length);
    let mut patches = Vec::new();

    if config.layout == PeLayout::MemoryAligned {
        for section in &headers.sections {
            let aligned = section
                .mapped_bytes(headers.section_alignment)
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or(section.size_of_raw_data);
            apply_patch(
                &mut extract,
                &mut patches,
                section
                    .header_offset
                    .saturating_add(SECTION_SIZE_OF_RAW_DATA as u64),
                &format!("section {:?} SizeOfRawData", section.name),
                &aligned.to_le_bytes(),
            );
            apply_patch(
                &mut extract,
                &mut patches,
                section
                    .header_offset
                    .saturating_add(SECTION_POINTER_TO_RAW_DATA as u64),
                &format!("section {:?} PointerToRawData", section.name),
                &section.virtual_address.to_le_bytes(),
            );
        }
    }

    if config.rewrite_image_base {
        let (within, bytes) = if headers.pe32_plus {
            (OPT64_IMAGE_BASE as u64, base.to_le_bytes().to_vec())
        } else {
            match u32::try_from(base) {
                Ok(narrow) => (OPT32_IMAGE_BASE as u64, narrow.to_le_bytes().to_vec()),
                Err(_) => {
                    extract.notes.push(format!(
                        "the image at {base:#x} is PE32, whose ImageBase is four bytes wide, so \
                         the load address does not fit and was left as acquired"
                    ));
                    (0, Vec::new())
                }
            }
        };
        if !bytes.is_empty() {
            apply_patch(
                &mut extract,
                &mut patches,
                headers.optional_offset.saturating_add(within),
                "OptionalHeader.ImageBase",
                &bytes,
            );
        }
    }

    Ok(PeDump {
        base,
        headers,
        layout: config.layout,
        extract,
        patches,
    })
}

/// Overwrite a header field and record that it was overwritten.
fn apply_patch(
    extract: &mut Extract,
    patches: &mut Vec<PePatch>,
    offset: u64,
    field: &str,
    now: &[u8],
) {
    let was = extract
        .bytes_at(offset, now.len() as u64)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    let applied = extract.patch(offset, now);
    patches.push(PePatch {
        offset,
        field: field.to_string(),
        was,
        now: now.to_vec(),
        applied,
    });
}

// ── Imports and exports ─────────────────────────────────────────────────────

/// Size of one `IMAGE_IMPORT_DESCRIPTOR`.
const IMPORT_DESCRIPTOR_BYTES: u64 = 20;
/// Offset of `IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk`, the import name
/// table.
const IMPORT_ORIGINAL_FIRST_THUNK: usize = 0;
/// Offset of `IMAGE_IMPORT_DESCRIPTOR.TimeDateStamp`.
const IMPORT_TIME_DATE_STAMP: usize = 4;
/// Offset of `IMAGE_IMPORT_DESCRIPTOR.Name`.
const IMPORT_NAME: usize = 12;
/// Offset of `IMAGE_IMPORT_DESCRIPTOR.FirstThunk`, the import address table.
const IMPORT_FIRST_THUNK: usize = 16;
/// Size of `IMAGE_EXPORT_DIRECTORY`.
const EXPORT_DIRECTORY_BYTES: u64 = 40;
/// Offset of `IMAGE_EXPORT_DIRECTORY.Base`, the first ordinal.
const EXPORT_ORDINAL_BASE: usize = 16;
/// Offset of `IMAGE_EXPORT_DIRECTORY.NumberOfFunctions`.
const EXPORT_NUMBER_OF_FUNCTIONS: usize = 20;
/// Offset of `IMAGE_EXPORT_DIRECTORY.NumberOfNames`.
const EXPORT_NUMBER_OF_NAMES: usize = 24;
/// Offset of `IMAGE_EXPORT_DIRECTORY.AddressOfFunctions`.
const EXPORT_ADDRESS_OF_FUNCTIONS: usize = 28;
/// Offset of `IMAGE_EXPORT_DIRECTORY.AddressOfNames`.
const EXPORT_ADDRESS_OF_NAMES: usize = 32;
/// Offset of `IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals`.
const EXPORT_ADDRESS_OF_NAME_ORDINALS: usize = 36;
/// How many bytes of a NUL-terminated name are read at a time.
const NAME_CHUNK_BYTES: u64 = 64;

/// Ceiling on the length of a name read out of a PE.
///
/// `MAX_PATH`. A longer one is not a name a linker wrote; it is a corrupt or
/// hostile table, and the string it would produce is not usable evidence.
pub const MAX_PE_NAME_BYTES: u64 = 260;

/// Read a NUL-terminated ASCII name out of an image.
///
/// Bytes outside printable ASCII are replaced rather than dropped, so a
/// deliberately odd import name is visible as odd instead of silently
/// normalised into something that matches an ordinary module.
fn read_name(
    layer: &dyn MemoryLayer,
    address: u64,
    max_bytes: u64,
) -> Result<String, (GapReason, String)> {
    let mut out = String::new();
    let mut read = 0u64;
    while read < max_bytes {
        let take = NAME_CHUNK_BYTES.min(max_bytes - read);
        let at = address
            .checked_add(read)
            .ok_or((GapReason::Unaddressable, "the name leaves the space".into()))?;
        let bytes = read_exact_bytes(layer, at, take)?;
        for byte in bytes {
            if byte == 0 {
                return Ok(out);
            }
            out.push(if (0x20..0x7F).contains(&byte) {
                byte as char
            } else {
                '.'
            });
        }
        read += take;
    }
    Err((
        GapReason::Refused,
        format!("the name at {address:#x} is longer than the {max_bytes} bytes a name may be"),
    ))
}

/// Where one exported symbol lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportTarget {
    /// The exported address, relative to the exporting module's base.
    pub rva: u32,
    /// When the export is a forwarder, the `Module.Function` string it names.
    ///
    /// A forwarded export does not live in this module at all: the loader
    /// resolves it in another. An import bound to a forwarder therefore points
    /// somewhere else *legitimately*, and reporting that as a hook would be a
    /// false finding on `kernel32!HeapAlloc` in every process on the machine.
    pub forwarder: Option<String>,
}

/// One module's export directory.
#[derive(Debug, Clone)]
pub struct ExportTable {
    /// The module's load address.
    pub base: u64,
    /// The export data directory as the optional header declares it.
    pub directory: DataDirectory,
    /// `IMAGE_EXPORT_DIRECTORY.Base`: the ordinal the first function has.
    pub ordinal_base: u32,
    /// One entry per function slot, in ordinal order from `ordinal_base`.
    pub functions: Vec<ExportTarget>,
    /// Exported name to function index.
    pub names: BTreeMap<String, usize>,
    /// Whether a cap stopped the table being read in full. A lookup that misses
    /// a truncated table is *unknown*, not absent.
    pub truncated: bool,
    /// Everything odd that did not stop the parse.
    pub notes: Vec<String>,
}

impl ExportTable {
    /// The export a name refers to.
    pub fn by_name(&self, name: &str) -> Option<&ExportTarget> {
        self.names
            .get(name)
            .and_then(|index| self.functions.get(*index))
    }

    /// The export an ordinal refers to.
    ///
    /// Ordinals are offset by `Base`, so ordinal 1 of a table whose `Base` is 1
    /// is function index 0. Forgetting the subtraction shifts every ordinal
    /// import by one function.
    pub fn by_ordinal(&self, ordinal: u32) -> Option<&ExportTarget> {
        let index = ordinal.checked_sub(self.ordinal_base)?;
        self.functions.get(usize::try_from(index).ok()?)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "base": self.base,
            "ordinal_base": self.ordinal_base,
            "function_count": self.functions.len(),
            "name_count": self.names.len(),
            "truncated": self.truncated,
            "notes": self.notes,
        })
    }
}

/// Caps for reading imports and exports.
#[derive(Debug, Clone)]
pub struct ImportConfig {
    /// Ceiling on import descriptors followed in one image.
    pub max_libraries: usize,
    /// Ceiling on thunks read for one library.
    pub max_thunks_per_library: usize,
    /// Ceiling on imports reported for one image.
    pub max_imports: usize,
    /// Ceiling on export slots read from one module.
    pub max_exports: u32,
    /// Ceiling on the length of a name.
    pub max_name_bytes: u64,
    /// Ceiling on individually recorded notes.
    pub max_recorded_notes: usize,
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            max_libraries: 1024,
            max_thunks_per_library: 65_536,
            max_imports: 262_144,
            max_exports: 65_536,
            max_name_bytes: MAX_PE_NAME_BYTES,
            max_recorded_notes: 256,
        }
    }
}

/// Read one module's export directory.
///
/// # Errors
///
/// [`DumpError::Unreadable`] when the directory's own bytes were not acquired.
/// A module whose optional header declares no export directory is not an error:
/// it is a module that exports nothing, and the table comes back empty.
pub fn read_exports(
    layer: &dyn MemoryLayer,
    headers: &PeHeaders,
    config: &ImportConfig,
) -> Result<ExportTable, DumpError> {
    let base = headers.base;
    let directory = headers.directory(DIRECTORY_ENTRY_EXPORT);
    let mut table = ExportTable {
        base,
        directory,
        ordinal_base: 0,
        functions: Vec::new(),
        names: BTreeMap::new(),
        truncated: false,
        notes: Vec::new(),
    };
    if !directory.is_present() {
        table.notes.push(format!(
            "the image at {base:#x} declares no export directory, so it exports nothing"
        ));
        return Ok(table);
    }

    let directory_address = headers
        .address_of(directory.virtual_address)
        .ok_or_else(|| DumpError::overflow("the export directory's address leaves the space"))?;
    let raw = read_header(
        layer,
        directory_address,
        EXPORT_DIRECTORY_BYTES,
        "the export directory",
    )?;

    table.ordinal_base = u32_at(&raw, EXPORT_ORDINAL_BASE).unwrap_or(0);
    let declared_functions = u32_at(&raw, EXPORT_NUMBER_OF_FUNCTIONS).unwrap_or(0);
    let declared_names = u32_at(&raw, EXPORT_NUMBER_OF_NAMES).unwrap_or(0);
    let functions_rva = u32_at(&raw, EXPORT_ADDRESS_OF_FUNCTIONS).unwrap_or(0);
    let names_rva = u32_at(&raw, EXPORT_ADDRESS_OF_NAMES).unwrap_or(0);
    let ordinals_rva = u32_at(&raw, EXPORT_ADDRESS_OF_NAME_ORDINALS).unwrap_or(0);

    let function_count = declared_functions.min(config.max_exports);
    let name_count = declared_names.min(config.max_exports);
    if declared_functions > function_count || declared_names > name_count {
        table.truncated = true;
        table.notes.push(format!(
            "the export directory declares {declared_functions} function(s) and \
             {declared_names} name(s), above the cap of {}; a name this table does not hold is \
             unknown rather than absent",
            config.max_exports
        ));
    }

    // The three parallel arrays, read as blocks rather than per entry: a
    // per-entry read of a 20,000-export ntdll is 60,000 layer round trips.
    let read_array = |rva: u32, count: u32, width: u64| -> Option<Vec<u8>> {
        if rva == 0 || count == 0 {
            return Some(Vec::new());
        }
        let address = headers.address_of(rva)?;
        let length = u64::from(count).checked_mul(width)?;
        read_exact_bytes(layer, address, length).ok()
    };

    let functions = match read_array(functions_rva, function_count, 4) {
        Some(bytes) => bytes,
        None => {
            table.truncated = true;
            table.notes.push(format!(
                "the export address table of the image at {base:#x} was not acquired, so no \
                 export of it can be located"
            ));
            return Ok(table);
        }
    };

    let export_start = u64::from(directory.virtual_address);
    let export_end = export_start.saturating_add(u64::from(directory.size));
    for index in 0..function_count as usize {
        let rva = u32_at(&functions, index * 4).unwrap_or(0);
        // An RVA inside the export directory itself is not code: it is the
        // address of a `Module.Function` string the loader resolves elsewhere.
        let forwarder = if rva != 0 && u64::from(rva) >= export_start && u64::from(rva) < export_end
        {
            headers
                .address_of(rva)
                .and_then(|address| read_name(layer, address, config.max_name_bytes).ok())
        } else {
            None
        };
        table.functions.push(ExportTarget { rva, forwarder });
    }

    // The name array and the ordinal array are read as a pair: without both,
    // no export can be matched to its name, and an empty name map must read as
    // *unknown* rather than as a module that exports nothing by name.
    let names = read_array(names_rva, name_count, 4);
    let ordinals = read_array(ordinals_rva, name_count, 2);
    let (Some(names), Some(ordinals)) = (names, ordinals) else {
        table.truncated = true;
        table.notes.push(format!(
            "the export name table of the image at {base:#x} was not acquired, so no export of it \
             can be matched to a name"
        ));
        return Ok(table);
    };

    for index in 0..name_count as usize {
        let Some(name_rva) = u32_at(&names, index * 4) else {
            break;
        };
        let Some(ordinal) = u16_at(&ordinals, index * 2) else {
            break;
        };
        let Some(address) = headers.address_of(name_rva) else {
            continue;
        };
        match read_name(layer, address, config.max_name_bytes) {
            Ok(name) => {
                table.names.insert(name, usize::from(ordinal));
            }
            Err(_) => {
                table.truncated = true;
                if table.notes.len() < config.max_recorded_notes {
                    table.notes.push(format!(
                        "the name of export {index} of the image at {base:#x} was not acquired"
                    ));
                }
            }
        }
    }

    Ok(table)
}

/// Which module is loaded where, for resolving an import to its export.
///
/// Keys are the module's **base name**, lower-cased, because an import
/// descriptor writes `KERNEL32.dll` and a loader list writes the full path in
/// whatever case the disk held.
#[derive(Debug, Clone, Default)]
pub struct ModuleMap {
    by_name: BTreeMap<String, u64>,
}

impl ModuleMap {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a module. The first base recorded for a name wins, because a
    /// second module with the same name is either a different session's copy or
    /// a masquerade, and silently replacing the first would change every
    /// verdict that depends on it.
    pub fn insert(&mut self, name: &str, base: u64) {
        let key = Self::key(name);
        if key.is_empty() {
            return;
        }
        self.by_name.entry(key).or_insert(base);
    }

    /// Where the module a name refers to is loaded.
    pub fn base_of(&self, name: &str) -> Option<u64> {
        self.by_name.get(&Self::key(name)).copied()
    }

    /// How many modules the map holds.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the map holds nothing, in which case every verdict will be
    /// [`ImportVerdict::ModuleNotLoaded`] and none of them is a finding.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// The lookup key for a module name: its base name, lower-cased.
    fn key(name: &str) -> String {
        name.rsplit(['\\', '/'])
            .next()
            .unwrap_or(name)
            .to_ascii_lowercase()
    }
}

/// How one library is named in an import descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibraryName {
    /// The name, as the descriptor writes it.
    Name(String),
    /// The name could not be read, for the reason given. Never an empty string:
    /// a nameless library and an unreadable one support different conclusions.
    Unavailable(String),
}

impl LibraryName {
    /// The name, when there is one.
    pub fn name(&self) -> Option<&str> {
        match self {
            LibraryName::Name(name) => Some(name),
            LibraryName::Unavailable(_) => None,
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            LibraryName::Name(name) => serde_json::json!({"kind": "name", "name": name}),
            LibraryName::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
        }
    }
}

/// How one function is named in an import name table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportName {
    /// Imported by name.
    Named(String),
    /// Imported by ordinal: the image never names the function at all.
    Ordinal(u32),
    /// The entry names a function whose name could not be read.
    Unavailable(String),
}

impl ImportName {
    /// The name, when the import has one and it was readable.
    pub fn name(&self) -> Option<&str> {
        match self {
            ImportName::Named(name) => Some(name),
            _ => None,
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            ImportName::Named(name) => serde_json::json!({"kind": "name", "name": name}),
            ImportName::Ordinal(ordinal) => {
                serde_json::json!({"kind": "ordinal", "ordinal": ordinal})
            }
            ImportName::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
        }
    }
}

/// Whether an import slot points where the export it names actually lives.
///
/// The whole point of the type is that "checked and it matches" and "could not
/// be checked" are different answers. Upstream's `iat` reports the slot's value
/// and stops; a tool that then rendered a blank verdict column as "clean" would
/// clear a hooked process because its `ntdll` happened to be paged out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportVerdict {
    /// The slot holds exactly the address the named export occupies.
    Matches,
    /// The slot holds something else. This is an IAT hook: calls through it go
    /// somewhere the exporting module does not.
    Diverted {
        /// Where the export the import names actually lives.
        expected: u64,
    },
    /// The export is a forwarder, so the loader resolves it in another module
    /// and the slot legitimately points elsewhere. Not a finding.
    Forwarded {
        /// The `Module.Function` string the export forwards to.
        target: String,
    },
    /// The slot still holds its import-name-table value, so the loader had not
    /// bound this import when the image was acquired.
    Unbound,
    /// The module the import names is not in the map the caller supplied, so
    /// there is nothing to compare against.
    ModuleNotLoaded,
    /// The module was found and does not export that name or ordinal.
    ExportMissing,
    /// The comparison could not be made, for the reason given.
    Unavailable(String),
}

impl ImportVerdict {
    /// Whether this verdict is a finding an examiner should look at.
    ///
    /// Only [`ImportVerdict::Diverted`]. Everything else is either clean or
    /// unknown, and unknown is never a finding.
    pub fn is_hook(&self) -> bool {
        matches!(self, ImportVerdict::Diverted { .. })
    }

    /// Whether the comparison was actually made.
    pub fn was_checked(&self) -> bool {
        matches!(
            self,
            ImportVerdict::Matches
                | ImportVerdict::Diverted { .. }
                | ImportVerdict::Forwarded { .. }
        )
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ImportVerdict::Matches => "matches",
            ImportVerdict::Diverted { .. } => "diverted",
            ImportVerdict::Forwarded { .. } => "forwarded",
            ImportVerdict::Unbound => "unbound",
            ImportVerdict::ModuleNotLoaded => "module_not_loaded",
            ImportVerdict::ExportMissing => "export_missing",
            ImportVerdict::Unavailable(_) => "unavailable",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            ImportVerdict::Diverted { expected } => {
                serde_json::json!({"kind": "diverted", "expected": expected})
            }
            ImportVerdict::Forwarded { target } => {
                serde_json::json!({"kind": "forwarded", "target": target})
            }
            ImportVerdict::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
            other => serde_json::json!({"kind": other.as_str()}),
        }
    }
}

/// One library an image imports from.
#[derive(Debug, Clone)]
pub struct ImportedLibrary {
    /// Address of the `IMAGE_IMPORT_DESCRIPTOR`.
    pub descriptor: u64,
    /// The library's name.
    pub name: LibraryName,
    /// `TimeDateStamp`: non-zero means the linker pre-bound the imports, so the
    /// slots held addresses before the loader ever ran.
    pub bound: bool,
    /// Where the module was found, when it was.
    pub resolved_base: Option<u64>,
    /// How many functions were reported for it.
    pub import_count: usize,
    /// Everything odd about this library that did not stop the walk.
    pub notes: Vec<String>,
}

impl ImportedLibrary {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "descriptor": self.descriptor,
            "name": self.name.to_json(),
            "bound": self.bound,
            "resolved_base": self.resolved_base,
            "import_count": self.import_count,
            "notes": self.notes,
        })
    }
}

/// One imported function, and whether its slot points where it should.
#[derive(Debug, Clone)]
pub struct ImportedFunction {
    /// The library it comes from, as the descriptor names it.
    pub library: LibraryName,
    /// The function.
    pub name: ImportName,
    /// Address of the import address table slot in the importing image.
    pub slot: u64,
    /// What the slot holds. `None` when the slot itself was not acquired —
    /// which is why a verdict of [`ImportVerdict::Unavailable`] exists.
    pub target: Option<u64>,
    /// Whether it points where the export lives.
    pub verdict: ImportVerdict,
}

impl ImportedFunction {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "library": self.library.to_json(),
            "name": self.name.to_json(),
            "slot": self.slot,
            "target": self.target,
            "verdict": self.verdict.to_json(),
            "hook": self.verdict.is_hook(),
        })
    }
}

/// Everything one image imports, checked against where those exports live.
#[derive(Debug, Clone)]
pub struct ImportTable {
    /// The importing image's base.
    pub base: u64,
    /// The import data directory as the optional header declares it.
    pub directory: DataDirectory,
    /// The libraries, in descriptor order.
    pub libraries: Vec<ImportedLibrary>,
    /// The functions, in descriptor and then thunk order.
    pub imports: Vec<ImportedFunction>,
    /// Why the walk ended.
    pub stop: ExtractStop,
    /// Everything odd that did not stop the walk.
    pub notes: Vec<String>,
}

impl ImportTable {
    /// Every import whose slot points somewhere the exporting module does not.
    pub fn hooks(&self) -> Vec<&ImportedFunction> {
        self.imports
            .iter()
            .filter(|import| import.verdict.is_hook())
            .collect()
    }

    /// How many imports were actually compared against an export.
    ///
    /// A report that says "no hooks found" must say this too: no hooks found
    /// among four checked imports out of nine hundred is not a clean process.
    pub fn checked(&self) -> usize {
        self.imports
            .iter()
            .filter(|import| import.verdict.was_checked())
            .count()
    }

    /// Everything a report must declare about this table.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let ExtractStop::CapReached { what, cap } = &self.stop {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the import walk of {:#x} stopped at its cap of {cap} {what}; the table \
                     continues",
                    self.base
                ),
            ));
        }
        let unchecked = self.imports.len().saturating_sub(self.checked());
        if unchecked > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{unchecked} of {} import(s) of {:#x} could not be compared against the \
                     export they name, so nothing is claimed about them",
                    self.imports.len(),
                    self.base
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "base": self.base,
            "libraries": self.libraries.iter().map(ImportedLibrary::to_json).collect::<Vec<_>>(),
            "imports": self.imports.iter().map(ImportedFunction::to_json).collect::<Vec<_>>(),
            "import_count": self.imports.len(),
            "checked": self.checked(),
            "hook_count": self.hooks().len(),
            "stop": self.stop.as_str(),
            "notes": self.notes,
        })
    }
}

/// Read one image's import table and check every slot against its export.
///
/// This is upstream's `iat` plus the comparison upstream does not make. The
/// import address table is what every call to an imported function goes
/// through, so a single overwritten slot silently redirects every call to
/// `CreateFileW` in the process. The only way to see it is to ask where the
/// export really lives and compare, which needs `modules` — the map of what is
/// loaded where, from `dlllist` or `ldrmodules`.
///
/// An empty `modules` is not an error and produces no findings: every verdict
/// is [`ImportVerdict::ModuleNotLoaded`], which is honest.
///
/// # Errors
///
/// [`DumpError::Unreadable`] when the descriptor array itself was not acquired.
/// An image that declares no import directory is not an error.
pub fn read_imports(
    layer: &dyn MemoryLayer,
    headers: &PeHeaders,
    modules: &ModuleMap,
    config: &ImportConfig,
) -> Result<ImportTable, DumpError> {
    let base = headers.base;
    let directory = headers.directory(DIRECTORY_ENTRY_IMPORT);
    let mut table = ImportTable {
        base,
        directory,
        libraries: Vec::new(),
        imports: Vec::new(),
        stop: ExtractStop::Exhausted,
        notes: Vec::new(),
    };
    if !directory.is_present() {
        table.notes.push(format!(
            "the image at {base:#x} declares no import directory, so it imports nothing"
        ));
        return Ok(table);
    }

    let thunk_width: u64 = if headers.pe32_plus { 8 } else { 4 };
    let ordinal_flag: u64 = if headers.pe32_plus {
        1u64 << 63
    } else {
        1u64 << 31
    };
    let descriptor_base = headers
        .address_of(directory.virtual_address)
        .ok_or_else(|| DumpError::overflow("the import directory's address leaves the space"))?;

    // Exports are read once per module however many imports come from it: an
    // image importing 900 functions from 12 DLLs must not parse 900 export
    // directories.
    let mut exports: BTreeMap<u64, Result<ExportTable, String>> = BTreeMap::new();

    'libraries: for index in 0..config.max_libraries {
        let descriptor = descriptor_base
            .checked_add((index as u64).saturating_mul(IMPORT_DESCRIPTOR_BYTES))
            .ok_or_else(|| DumpError::overflow("an import descriptor leaves the space"))?;
        let raw = match read_exact_bytes(layer, descriptor, IMPORT_DESCRIPTOR_BYTES) {
            Ok(raw) => raw,
            Err((_, detail)) => {
                table.notes.push(format!(
                    "import descriptor {index} at {descriptor:#x} was not acquired, so the \
                     libraries after it are not listed: {detail}"
                ));
                break;
            }
        };
        // The array is terminated by an all-zero descriptor.
        if raw.iter().all(|byte| *byte == 0) {
            break;
        }

        let original_first_thunk = u32_at(&raw, IMPORT_ORIGINAL_FIRST_THUNK).unwrap_or(0);
        let time_date_stamp = u32_at(&raw, IMPORT_TIME_DATE_STAMP).unwrap_or(0);
        let name_rva = u32_at(&raw, IMPORT_NAME).unwrap_or(0);
        let first_thunk = u32_at(&raw, IMPORT_FIRST_THUNK).unwrap_or(0);

        let name = match headers.address_of(name_rva) {
            Some(address) if name_rva != 0 => {
                match read_name(layer, address, config.max_name_bytes) {
                    Ok(name) => LibraryName::Name(name),
                    Err((_, detail)) => LibraryName::Unavailable(detail),
                }
            }
            _ => LibraryName::Unavailable(
                "the descriptor's Name field is null, so the library is not named".to_string(),
            ),
        };

        let resolved_base = name.name().and_then(|name| modules.base_of(name));
        let mut library = ImportedLibrary {
            descriptor,
            name: name.clone(),
            bound: time_date_stamp != 0,
            resolved_base,
            import_count: 0,
            notes: Vec::new(),
        };

        // The import *name* table is what says which function each slot is for.
        // Some linkers omit it, in which case the address table doubles as it
        // before binding; reading names from the address table of a *bound*
        // image would read addresses as if they were RVAs.
        let name_table = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            library.notes.push(
                "this descriptor has no OriginalFirstThunk, so the names are taken from the \
                 import address table, which only holds them until the loader binds them"
                    .to_string(),
            );
            first_thunk
        };
        if name_table == 0 {
            library.notes.push(
                "this descriptor names neither a name table nor an address table, so none of its \
                 imports can be listed"
                    .to_string(),
            );
            table.libraries.push(library);
            continue;
        }

        for thunk in 0..config.max_thunks_per_library {
            if table.imports.len() >= config.max_imports {
                table.stop = ExtractStop::CapReached {
                    what: "imports",
                    cap: config.max_imports as u64,
                };
                table.libraries.push(library);
                break 'libraries;
            }
            let within = (thunk as u64)
                .checked_mul(thunk_width)
                .ok_or_else(|| DumpError::overflow("a thunk index leaves the space"))?;
            let name_slot = headers
                .address_of(name_table)
                .and_then(|address| address.checked_add(within))
                .ok_or_else(|| DumpError::overflow("an import thunk leaves the space"))?;

            let name_entry = match read_thunk(layer, name_slot, thunk_width) {
                Ok(value) => value,
                Err((_, detail)) => {
                    library.notes.push(format!(
                        "thunk {thunk} at {name_slot:#x} was not acquired, so the imports after \
                         it are not listed: {detail}"
                    ));
                    break;
                }
            };
            // A null thunk terminates the list.
            if name_entry == 0 {
                break;
            }

            let function = if name_entry & ordinal_flag != 0 {
                ImportName::Ordinal((name_entry & 0xFFFF) as u32)
            } else {
                // The low bits are an RVA to an `IMAGE_IMPORT_BY_NAME`, whose
                // first two bytes are the hint and whose name follows it.
                match u32::try_from(name_entry & !ordinal_flag)
                    .ok()
                    .and_then(|rva| headers.address_of(rva))
                    .and_then(|address| address.checked_add(2))
                {
                    Some(address) => match read_name(layer, address, config.max_name_bytes) {
                        Ok(name) => ImportName::Named(name),
                        Err((_, detail)) => ImportName::Unavailable(detail),
                    },
                    None => ImportName::Unavailable(format!(
                        "the name table entry {name_entry:#x} is not an RVA inside this image"
                    )),
                }
            };

            let slot = if first_thunk == 0 {
                name_slot
            } else {
                headers
                    .address_of(first_thunk)
                    .and_then(|address| address.checked_add(within))
                    .ok_or_else(|| DumpError::overflow("an import slot leaves the space"))?
            };
            let target = read_thunk(layer, slot, thunk_width).ok();

            let verdict = verdict_for(
                layer,
                &function,
                target,
                name_entry,
                resolved_base,
                &mut exports,
                config,
            );

            library.import_count += 1;
            table.imports.push(ImportedFunction {
                library: name.clone(),
                name: function,
                slot,
                target,
                verdict,
            });
        }

        table.libraries.push(library);
    }

    // The loop is bounded by the same cap, and every iteration that did not
    // `break` placed exactly one library, so a full count means the descriptor
    // array had not reached its null terminator. Checked here rather than
    // inside the loop because a descriptor that named no thunk table `continue`s
    // past an in-loop check, and a truncated library list that reports itself
    // as the whole list is a process whose remaining imports were never looked
    // at and never said to be missing.
    if table.libraries.len() >= config.max_libraries && table.stop.is_complete() {
        table.stop = ExtractStop::CapReached {
            what: "import libraries",
            cap: config.max_libraries as u64,
        };
    }

    Ok(table)
}

/// Read one import thunk, at the width this image's optional header implies.
fn read_thunk(
    layer: &dyn MemoryLayer,
    address: u64,
    width: u64,
) -> Result<u64, (GapReason, String)> {
    let bytes = read_exact_bytes(layer, address, width)?;
    if width == 8 {
        u64_at(&bytes, 0).ok_or((GapReason::ReadFailed, "a thunk was short".to_string()))
    } else {
        u32_at(&bytes, 0)
            .map(u64::from)
            .ok_or((GapReason::ReadFailed, "a thunk was short".to_string()))
    }
}

/// Decide whether one import slot points where its export lives.
fn verdict_for(
    layer: &dyn MemoryLayer,
    function: &ImportName,
    target: Option<u64>,
    name_entry: u64,
    module_base: Option<u64>,
    exports: &mut BTreeMap<u64, Result<ExportTable, String>>,
    config: &ImportConfig,
) -> ImportVerdict {
    let Some(target) = target else {
        return ImportVerdict::Unavailable(
            "the import address table slot itself was not acquired".to_string(),
        );
    };
    // Before the loader binds an import, the address table is a copy of the
    // name table. Reporting that as a diversion would flag every image caught
    // mid-creation, and every image whose IAT the loader has not touched.
    if target == name_entry {
        return ImportVerdict::Unbound;
    }
    let Some(module_base) = module_base else {
        return ImportVerdict::ModuleNotLoaded;
    };

    let table = exports.entry(module_base).or_insert_with(|| {
        read_pe_headers(layer, module_base)
            .and_then(|headers| read_exports(layer, &headers, config))
            .map_err(|err| err.to_string())
    });
    let table = match table {
        Ok(table) => table,
        Err(detail) => {
            return ImportVerdict::Unavailable(format!(
                "the exports of the module at {module_base:#x} could not be read: {detail}"
            ))
        }
    };

    let export = match function {
        ImportName::Named(name) => table.by_name(name),
        ImportName::Ordinal(ordinal) => table.by_ordinal(*ordinal),
        ImportName::Unavailable(detail) => {
            return ImportVerdict::Unavailable(format!(
                "the imported function is not named in the evidence: {detail}"
            ))
        }
    };
    let Some(export) = export else {
        if table.truncated {
            return ImportVerdict::Unavailable(
                "the exporting module's export table was not read in full, so the absence of \
                 this export is not established"
                    .to_string(),
            );
        }
        return ImportVerdict::ExportMissing;
    };
    if let Some(forward) = &export.forwarder {
        return ImportVerdict::Forwarded {
            target: forward.clone(),
        };
    }
    let Some(expected) = module_base.checked_add(u64::from(export.rva)) else {
        return ImportVerdict::Unavailable(
            "the export's address does not fit in the 64-bit address space".to_string(),
        );
    };
    if expected == target {
        ImportVerdict::Matches
    } else {
        ImportVerdict::Diverted { expected }
    }
}

// ── dumpfiles: reconstructing a cached file ─────────────────────────────────

/// The object every cached file hangs off.
pub const TYPE_FILE_OBJECT: &str = "_FILE_OBJECT";
/// The three caches a file object points at.
pub const TYPE_SECTION_OBJECT_POINTERS: &str = "_SECTION_OBJECT_POINTERS";
/// The section object behind the data and image caches.
pub const TYPE_CONTROL_AREA: &str = "_CONTROL_AREA";
/// One run of prototype PTEs inside a control area.
pub const TYPE_SUBSECTION: &str = "_SUBSECTION";
/// The segment a control area points back through, used to validate it.
pub const TYPE_SEGMENT: &str = "_SEGMENT";
/// A prototype page table entry.
pub const TYPE_MMPTE: &str = "_MMPTE";
/// The cache manager's view of a file.
pub const TYPE_SHARED_CACHE_MAP: &str = "_SHARED_CACHE_MAP";
/// One 256 KiB view of a file in the system cache.
pub const TYPE_VACB: &str = "_VACB";
/// The device a file object belongs to.
pub const TYPE_DEVICE_OBJECT: &str = "_DEVICE_OBJECT";

/// `FILE_DEVICE_DISK`.
pub const FILE_DEVICE_DISK: u64 = 0x7;
/// `FILE_DEVICE_NETWORK_FILE_SYSTEM`.
pub const FILE_DEVICE_NETWORK_FILE_SYSTEM: u64 = 0x14;

/// How large one virtual address control block's view of a file is: 256 KiB.
pub const VACB_BLOCK: u64 = 0x40000;
/// Entries in one level of the sparse VACB index array.
pub const VACB_ARRAY: u64 = 0x80;
/// How far a file offset is shifted per level of the VACB index.
pub const VACB_OFFSET_SHIFT: u32 = 18;
/// How many index bits one level of the VACB array consumes.
pub const VACB_LEVEL_SHIFT: u32 = 7;
/// Largest file a single-level VACB index array describes: 32 MiB.
pub const VACB_SIZE_OF_FIRST_LEVEL: u64 = 1 << (VACB_OFFSET_SHIFT + VACB_LEVEL_SHIFT);
/// Mask that strips the reference count out of a VACB's file offset.
///
/// All views are 256 KiB, so the low sixteen bits of `Overlay.FileOffset` are
/// free and the cache manager keeps the view's reference count in them. Using
/// the value unmasked places every view up to 65535 bytes into the wrong part
/// of the reconstructed file.
pub const VACB_FILE_OFFSET_MASK: u64 = 0xFFFF_FFFF_FFFF_0000;

/// Multiplier applied to a subsection's `StartingSector` for an image section:
/// disk sectors.
pub const IMAGE_SECTOR_SIZE: u64 = 0x200;
/// Multiplier applied for a data section: pages.
pub const DATA_SECTOR_SIZE: u64 = 0x1000;

/// Ceiling on subsections one control area walk will follow.
pub const MAX_SUBSECTIONS: usize = 4096;
/// Ceiling on prototype PTEs read from one subsection.
pub const MAX_PTES_PER_SUBSECTION: u64 = 1 << 20;
/// Ceiling on pages one cache reconstruction will report.
pub const MAX_CACHED_PAGES: usize = 1 << 20;
/// Ceiling on VACB index arrays one walk will visit.
pub const MAX_VACB_ARRAYS: usize = 4096;
/// Ceiling on individually recorded notes in a cache walk.
pub const MAX_CACHE_NOTES: usize = 256;

/// Resolve the first of `candidates` that this build's `type_name` has.
///
/// Asking the symbol table which member exists, rather than branching on a
/// build number, means a build nobody has catalogued reads the right member or
/// fails naming every candidate that was tried.
/// This module used to carry its own copy, which returned a bare `Option` built
/// from `member_offset(..).is_ok()` and so reported "the symbol table could not
/// answer" as "this build has no such member". Those are opposite claims and the
/// shared helper keeps them apart; there is one definition of it so the two
/// cannot drift.
use seance_memory::binding::first_member;

/// A symbol-table failure as the one sentence the layout resolvers return.
///
/// Kept distinct from "this build has no such member": the first says the
/// evidence about layout is damaged, the second is a claim about the machine.
fn unreadable_table(err: ObjError) -> String {
    format!("the symbol table could not be read, so this build's layout is unknown: {err}")
}

/// Where a file object's three caches hang off it.
#[derive(Debug, Clone)]
pub struct FileObjectLayout {
    /// Path to the `_SECTION_OBJECT_POINTERS` pointer on `_FILE_OBJECT`.
    pub section_object_pointers: String,
    /// Path to the data cache's control area pointer.
    pub data_section_object: Option<String>,
    /// Path to the image cache's control area pointer.
    pub image_section_object: Option<String>,
    /// Path to the shared cache map pointer.
    pub shared_cache_map: Option<String>,
    /// Path to the device object, which says whether this "file" is a file.
    pub device_object: Option<String>,
    /// Path to `_DEVICE_OBJECT.DeviceType`.
    pub device_type: Option<String>,
    /// Path to the file's name.
    pub file_name: Option<String>,
}

/// What a control area's prototype PTEs are read through.
#[derive(Debug, Clone)]
pub struct SectionLayout {
    /// Size of `_CONTROL_AREA`, which is how far past it the first
    /// `_SUBSECTION` sits. Taken from the symbol table, never written down: the
    /// structure has grown between builds, and a stale size reads the middle of
    /// the first subsection as its first member.
    pub control_area_size: u64,
    /// Path to the flag saying whether this section is an image.
    pub image_flag: Option<String>,
    /// The self-consistency check a control area can be held to.
    pub segment: Option<SegmentCheck>,
    /// Path to `_SUBSECTION.ControlArea`.
    pub subsection_control_area: String,
    /// Path to `_SUBSECTION.SubsectionBase`, the prototype PTE array.
    pub subsection_base: String,
    /// Path to `_SUBSECTION.PtesInSubsection`.
    pub subsection_ptes: String,
    /// Path to `_SUBSECTION.StartingSector`.
    pub subsection_starting_sector: String,
    /// Path to `_SUBSECTION.NextSubsection`.
    pub subsection_next: String,
    /// Size of one `_MMPTE`.
    pub mmpte_size: u64,
    /// Path to the hardware PTE's valid bit.
    pub pte_valid: String,
    /// Path to the hardware PTE's page frame number.
    pub pte_page_frame: String,
    /// Path to the transition PTE's transition bit.
    pub pte_transition: String,
    /// Path to the transition PTE's page frame number.
    pub pte_transition_frame: String,
}

/// The pointers a control area can be checked against itself with.
#[derive(Debug, Clone)]
pub struct SegmentCheck {
    /// Path to `_CONTROL_AREA.Segment`.
    pub segment: String,
    /// Path to `_SEGMENT.ControlArea`, which must point back.
    pub control_area: String,
    /// Path to `_SEGMENT.SizeOfSegment`.
    pub size_of_segment: String,
    /// Path to `_SEGMENT.TotalNumberOfPtes`.
    pub total_ptes: String,
}

/// What the cache manager's view of a file is read through.
#[derive(Debug, Clone)]
pub struct CacheLayout {
    /// Path to `_SHARED_CACHE_MAP.FileSize`'s value.
    pub file_size: String,
    /// Path to `_SHARED_CACHE_MAP.ValidDataLength`'s value.
    pub valid_data_length: String,
    /// Path to `_SHARED_CACHE_MAP.SectionSize`'s value.
    pub section_size: String,
    /// Path to the four inline VACB pointers.
    pub initial_vacbs: String,
    /// How many of them this build declares.
    pub initial_vacb_count: u64,
    /// Path to the pointer to the allocated VACB index array.
    pub vacbs: String,
    /// Path to `_VACB.BaseAddress`, where the view is mapped.
    pub vacb_base_address: String,
    /// Path to `_VACB.SharedCacheMap`, which must point back.
    pub vacb_shared_cache_map: String,
    /// Path to the view's file offset.
    pub vacb_file_offset: String,
    /// Guest pointer width, for stepping the index arrays.
    pub pointer_size: u64,
}

/// Everything the file-cache reconstruction needs from this build's symbols.
///
/// The two routes are resolved independently, because a build can describe one
/// and not the other, and refusing both because one is missing would lose
/// evidence that is right there. Each refusal carries the reason, so a caller
/// that asks for the route this build does not have gets told which member is
/// absent rather than an empty result.
#[derive(Debug, Clone)]
pub struct DumpSymbols {
    /// Where the caches hang off a file object.
    pub file: FileObjectLayout,
    /// The control-area route, or why this build cannot support it.
    pub sections: Result<SectionLayout, String>,
    /// The shared-cache-map route, or why this build cannot support it.
    pub cache: Result<CacheLayout, String>,
}

impl DumpSymbols {
    /// Resolve every layout fact a file-cache reconstruction of this image
    /// needs.
    ///
    /// # Errors
    ///
    /// [`DumpError::Unsupported`] naming what is missing when the file object
    /// itself cannot be described, which means no cache of any kind can be
    /// reached. A route this build does not describe is not an error here; it
    /// is an error when it is asked for.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, DumpError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        if !profile.symbols.has_type(TYPE_FILE_OBJECT) {
            return Err(DumpError::unsupported(format!(
                "the symbol table has no '{TYPE_FILE_OBJECT}', so no cached file can be reached"
            )));
        }
        let section_object_pointers =
            first_member(&reader, TYPE_FILE_OBJECT, &["SectionObjectPointer"])?
                .ok_or_else(|| {
                    DumpError::unsupported(format!(
                        "'{TYPE_FILE_OBJECT}' has no SectionObjectPointer, so its caches cannot be \
                         reached"
                    ))
                })?
                .to_string();
        if !profile.symbols.has_type(TYPE_SECTION_OBJECT_POINTERS) {
            return Err(DumpError::unsupported(format!(
                "the symbol table has no '{TYPE_SECTION_OBJECT_POINTERS}', so a file object's \
                 caches cannot be told apart"
            )));
        }

        let file = FileObjectLayout {
            section_object_pointers,
            data_section_object: first_member(
                &reader,
                TYPE_SECTION_OBJECT_POINTERS,
                &["DataSectionObject"],
            )?
            .map(str::to_string),
            image_section_object: first_member(
                &reader,
                TYPE_SECTION_OBJECT_POINTERS,
                &["ImageSectionObject"],
            )?
            .map(str::to_string),
            shared_cache_map: first_member(
                &reader,
                TYPE_SECTION_OBJECT_POINTERS,
                &["SharedCacheMap"],
            )?
            .map(str::to_string),
            device_object: first_member(&reader, TYPE_FILE_OBJECT, &["DeviceObject"])?
                .map(str::to_string),
            device_type: if profile.symbols.has_type(TYPE_DEVICE_OBJECT) {
                first_member(&reader, TYPE_DEVICE_OBJECT, &["DeviceType"])?.map(str::to_string)
            } else {
                None
            },
            file_name: first_member(&reader, TYPE_FILE_OBJECT, &["FileName"])?.map(str::to_string),
        };

        Ok(Self {
            file,
            sections: resolve_section_layout(profile, &reader),
            cache: resolve_cache_layout(profile, &reader),
        })
    }

    /// The control-area route, or a refusal naming what this build lacks.
    ///
    /// # Errors
    ///
    /// [`DumpError::Unsupported`] carrying the reason recorded at resolution.
    pub fn require_sections(&self) -> Result<&SectionLayout, DumpError> {
        self.sections
            .as_ref()
            .map_err(|detail| DumpError::unsupported(detail.clone()))
    }

    /// The shared-cache-map route, or a refusal naming what this build lacks.
    ///
    /// # Errors
    ///
    /// [`DumpError::Unsupported`] carrying the reason recorded at resolution.
    pub fn require_cache(&self) -> Result<&CacheLayout, DumpError> {
        self.cache
            .as_ref()
            .map_err(|detail| DumpError::unsupported(detail.clone()))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "section_object_pointers": self.file.section_object_pointers,
            "data_section_object": self.file.data_section_object,
            "image_section_object": self.file.image_section_object,
            "shared_cache_map": self.file.shared_cache_map,
            "device_type": self.file.device_type,
            "sections": match &self.sections {
                Ok(_) => serde_json::json!({"available": true}),
                Err(detail) => serde_json::json!({"available": false, "detail": detail}),
            },
            "cache": match &self.cache {
                Ok(_) => serde_json::json!({"available": true}),
                Err(detail) => serde_json::json!({"available": false, "detail": detail}),
            },
        })
    }
}

/// Resolve the control-area route, or say what stops it.
fn resolve_section_layout(
    profile: &WindowsProfile,
    reader: &StructReader,
) -> Result<SectionLayout, String> {
    for type_name in [TYPE_CONTROL_AREA, TYPE_SUBSECTION, TYPE_MMPTE] {
        if !profile.symbols.has_type(type_name) {
            return Err(format!(
                "the symbol table has no '{type_name}', so the pages a section object caches \
                 cannot be located"
            ));
        }
    }
    let control_area_size = reader
        .size_of(TYPE_CONTROL_AREA)
        .map_err(|err| format!("'{TYPE_CONTROL_AREA}' has no size in this table: {err}"))?
        .bytes();
    let mmpte_size = reader
        .size_of(TYPE_MMPTE)
        .map_err(|err| format!("'{TYPE_MMPTE}' has no size in this table: {err}"))?
        .bytes();
    if mmpte_size == 0 {
        return Err(format!(
            "'{TYPE_MMPTE}' is zero bytes wide in this table, so a prototype PTE array cannot be \
             stepped"
        ));
    }

    let need = |type_name: &str, candidates: &[&str]| -> Result<String, String> {
        Ok(first_member(reader, type_name, candidates)
            .map_err(unreadable_table)?
            .ok_or_else(|| {
                format!(
                    "'{type_name}' has none of {candidates:?}, so a cached file's pages cannot be \
                     located"
                )
            })?
            .to_string())
    };

    Ok(SectionLayout {
        control_area_size,
        image_flag: first_member(
            reader,
            TYPE_CONTROL_AREA,
            &["u.Flags.Image", "u1.Flags.Image", "Flags.Image"],
        )
        .map_err(unreadable_table)?
        .map(str::to_string),
        segment: resolve_segment_check(profile, reader)?,
        subsection_control_area: need(TYPE_SUBSECTION, &["ControlArea"])?,
        subsection_base: need(TYPE_SUBSECTION, &["SubsectionBase"])?,
        subsection_ptes: need(TYPE_SUBSECTION, &["PtesInSubsection"])?,
        subsection_starting_sector: need(TYPE_SUBSECTION, &["StartingSector", "StartingSector1"])?,
        subsection_next: need(TYPE_SUBSECTION, &["NextSubsection"])?,
        mmpte_size,
        pte_valid: need(TYPE_MMPTE, &["u.Hard.Valid"])?,
        pte_page_frame: need(TYPE_MMPTE, &["u.Hard.PageFrameNumber"])?,
        pte_transition: need(TYPE_MMPTE, &["u.Trans.Transition"])?,
        pte_transition_frame: need(TYPE_MMPTE, &["u.Trans.PageFrameNumber"])?,
    })
}

/// Resolve the control area's self-consistency check, when this build has it.
///
/// `Ok(None)` is a build that does not describe the check, which costs the
/// cross-check and nothing else. `Err` is a symbol table that could not answer,
/// which must not be reported as the first.
fn resolve_segment_check(
    profile: &WindowsProfile,
    reader: &StructReader,
) -> Result<Option<SegmentCheck>, String> {
    if !profile.symbols.has_type(TYPE_SEGMENT) {
        return Ok(None);
    }
    let (Some(segment), Some(control_area), Some(size_of_segment), Some(total_ptes)) = (
        first_member(reader, TYPE_CONTROL_AREA, &["Segment"]).map_err(unreadable_table)?,
        first_member(reader, TYPE_SEGMENT, &["ControlArea"]).map_err(unreadable_table)?,
        first_member(reader, TYPE_SEGMENT, &["SizeOfSegment"]).map_err(unreadable_table)?,
        first_member(reader, TYPE_SEGMENT, &["TotalNumberOfPtes"]).map_err(unreadable_table)?,
    ) else {
        return Ok(None);
    };
    Ok(Some(SegmentCheck {
        segment: segment.to_string(),
        control_area: control_area.to_string(),
        size_of_segment: size_of_segment.to_string(),
        total_ptes: total_ptes.to_string(),
    }))
}

/// Resolve the shared-cache-map route, or say what stops it.
fn resolve_cache_layout(
    profile: &WindowsProfile,
    reader: &StructReader,
) -> Result<CacheLayout, String> {
    for type_name in [TYPE_SHARED_CACHE_MAP, TYPE_VACB] {
        if !profile.symbols.has_type(type_name) {
            return Err(format!(
                "the symbol table has no '{type_name}', so the cache manager's views of a file \
                 cannot be located"
            ));
        }
    }
    let need = |type_name: &str, candidates: &[&str]| -> Result<String, String> {
        Ok(first_member(reader, type_name, candidates)
            .map_err(unreadable_table)?
            .ok_or_else(|| {
                format!(
                    "'{type_name}' has none of {candidates:?}, so the cache manager's views of a \
                     file cannot be located"
                )
            })?
            .to_string())
    };
    let initial_vacbs = need(TYPE_SHARED_CACHE_MAP, &["InitialVacbs"])?;
    let initial_vacb_count = reader
        .object(0, TYPE_SHARED_CACHE_MAP)
        .and_then(|object| object.array_len(&initial_vacbs))
        .map_err(|err| {
            format!("'{TYPE_SHARED_CACHE_MAP}.{initial_vacbs}' is not an array: {err}")
        })?;
    let pointer_size = u64::from(
        reader
            .pointer_size()
            .map_err(|err| format!("this table declares no usable pointer width: {err}"))?,
    );

    Ok(CacheLayout {
        file_size: need(TYPE_SHARED_CACHE_MAP, &["FileSize.QuadPart", "FileSize"])?,
        valid_data_length: need(
            TYPE_SHARED_CACHE_MAP,
            &["ValidDataLength.QuadPart", "ValidDataLength"],
        )?,
        section_size: need(
            TYPE_SHARED_CACHE_MAP,
            &["SectionSize.QuadPart", "SectionSize"],
        )?,
        initial_vacbs,
        initial_vacb_count,
        vacbs: need(TYPE_SHARED_CACHE_MAP, &["Vacbs"])?,
        vacb_base_address: need(TYPE_VACB, &["BaseAddress"])?,
        vacb_shared_cache_map: need(TYPE_VACB, &["SharedCacheMap"])?,
        vacb_file_offset: need(
            TYPE_VACB,
            &[
                "Overlay.FileOffset.QuadPart",
                "Overlay.FileOffset",
                "FileOffset.QuadPart",
            ],
        )?,
        pointer_size,
    })
}

/// Which of a file object's three caches a reconstruction is reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCache {
    /// `DataSectionObject`: the file's contents as a data section.
    DataSection,
    /// `ImageSectionObject`: the file's contents as a mapped executable. Its
    /// subsections are aligned to disk sectors rather than to pages, which is
    /// the one thing that must not be got wrong: using the page multiplier
    /// places every page eight times too far into the reconstructed file.
    ImageSection,
    /// `SharedCacheMap`: the cache manager's 256 KiB views.
    SharedCacheMap,
}

impl FileCache {
    /// Stable identifier for artifact metadata, matching upstream's names.
    pub fn as_str(self) -> &'static str {
        match self {
            FileCache::DataSection => "DataSectionObject",
            FileCache::ImageSection => "ImageSectionObject",
            FileCache::SharedCacheMap => "SharedCacheMap",
        }
    }

    /// The extension upstream gives this cache's output file.
    pub fn extension(self) -> &'static str {
        match self {
            FileCache::DataSection => "dat",
            FileCache::ImageSection => "img",
            FileCache::SharedCacheMap => "vacb",
        }
    }
}

/// Which address space a cached page's source address belongs to.
///
/// Named rather than implied, because the two routes differ and reading one
/// through the other's layer does not fail: a physical frame number read as a
/// kernel virtual address translates to *something*, and those bytes go into
/// the reconstructed file looking exactly like the file's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSpace {
    /// Physical: a prototype PTE names a page frame.
    Physical,
    /// Kernel virtual: a VACB names where its view is mapped.
    KernelVirtual,
}

impl CacheSpace {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            CacheSpace::Physical => "physical",
            CacheSpace::KernelVirtual => "kernel_virtual",
        }
    }
}

/// One run of a cached file that is still in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedPage {
    /// Where this run belongs in the file.
    pub file_offset: u64,
    /// Where its bytes are, in the space [`FileCacheMap::space`] names.
    pub source: u64,
    /// How many bytes it holds.
    pub length: u64,
}

impl CachedPage {
    /// One past the last file offset this run covers.
    pub fn end(&self) -> u64 {
        self.file_offset.saturating_add(self.length)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "file_offset": self.file_offset,
            "source": self.source,
            "length": self.length,
        })
    }
}

/// Which parts of a cached file are still in memory, and where.
#[derive(Debug, Clone)]
pub struct FileCacheMap {
    /// The `_FILE_OBJECT` this came from.
    pub file_object: u64,
    /// Which cache was read.
    pub cache: FileCache,
    /// The `_CONTROL_AREA` or `_SHARED_CACHE_MAP` the pages were found through.
    pub object: u64,
    /// Which space the runs' `source` addresses belong to.
    pub space: CacheSpace,
    /// The runs, ascending by file offset and non-overlapping.
    pub pages: Vec<CachedPage>,
    /// The file's size, when the structures state it. `None` means the length
    /// of the original file is not established, so a reconstruction ends at the
    /// last cached page and says nothing about what came after.
    pub declared_size: Option<u64>,
    /// How many pages the walk found and did not report, because they were not
    /// resident or their entry could not be read.
    pub skipped_total: usize,
    /// Why the walk ended.
    pub stop: ExtractStop,
    /// Everything odd that did not stop the walk.
    pub notes: Vec<String>,
}

impl FileCacheMap {
    /// How many bytes of the file are cached.
    pub fn cached_bytes(&self) -> u64 {
        self.pages
            .iter()
            .fold(0u64, |acc, page| acc.saturating_add(page.length))
    }

    /// Whether the whole file was found in memory.
    ///
    /// A cached file is almost never complete, which is exactly why the gap map
    /// matters: upstream writes a file of the declared size with zeroes wherever
    /// a page was not resident, and that file hashes as something that never
    /// existed.
    pub fn is_complete(&self) -> bool {
        match self.declared_size {
            Some(size) => {
                self.stop.is_complete() && self.skipped_total == 0 && self.cached_bytes() == size
            }
            None => false,
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "file_object": self.file_object,
            "cache": self.cache.as_str(),
            "object": self.object,
            "space": self.space.as_str(),
            "pages": self.pages.iter().map(CachedPage::to_json).collect::<Vec<_>>(),
            "page_count": self.pages.len(),
            "cached_bytes": self.cached_bytes(),
            "declared_size": self.declared_size,
            "skipped_total": self.skipped_total,
            "stop": self.stop.as_str(),
            "notes": self.notes,
        })
    }
}

/// What a file object's caches are, before any of them is read.
#[derive(Debug, Clone)]
pub struct FileObjectCaches {
    /// Where the file object is.
    pub file_object: u64,
    /// The file's name, when it was readable.
    pub name: Option<String>,
    /// `_DEVICE_OBJECT.DeviceType`, when it was readable.
    pub device_type: Option<u64>,
    /// Whether the device is one that holds files.
    ///
    /// `None` means the device could not be read, which is *not* the same as
    /// "not a file": upstream skips a file object whose device type it cannot
    /// read, and a skipped file is one an examiner never learns existed.
    pub is_file_backed: Option<bool>,
    /// Which caches this file object has, and the object behind each.
    pub available: Vec<(FileCache, u64)>,
    /// Everything odd that did not stop the read.
    pub notes: Vec<String>,
}

impl FileObjectCaches {
    /// Whether a given cache is present.
    pub fn address_of(&self, cache: FileCache) -> Option<u64> {
        self.available
            .iter()
            .find(|(kind, _)| *kind == cache)
            .map(|(_, address)| *address)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "file_object": self.file_object,
            "name": self.name,
            "device_type": self.device_type,
            "is_file_backed": self.is_file_backed,
            "available": self
                .available
                .iter()
                .map(|(cache, address)| serde_json::json!({
                    "cache": cache.as_str(),
                    "object": address,
                }))
                .collect::<Vec<_>>(),
            "notes": self.notes,
        })
    }
}

/// Which of a file object's three caches exist, and what device it is on.
///
/// # Errors
///
/// [`DumpError::Object`] when the file object itself could not be read, which
/// is a fact about the evidence rather than about the file.
pub fn file_object_caches(
    profile: &WindowsProfile,
    symbols: &DumpSymbols,
    file_object: u64,
) -> Result<FileObjectCaches, DumpError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let object = reader.object(file_object, TYPE_FILE_OBJECT)?;
    let mut notes = Vec::new();

    let name = match &symbols.file.file_name {
        Some(path) => match crate::poolscan::unicode_string(&object, path) {
            Ok(name) => name,
            Err(err) => {
                notes.push(format!("the file's name could not be read: {err}"));
                None
            }
        },
        None => None,
    };

    let (device_type, is_file_backed) =
        match (&symbols.file.device_object, &symbols.file.device_type) {
            (Some(device_path), Some(type_path)) => match object.follow(device_path) {
                Ok(Some(device)) => match device.int(type_path) {
                    Ok(value) => {
                        let raw = value.as_u64();
                        let backed = raw.map(|raw| {
                            raw == FILE_DEVICE_DISK || raw == FILE_DEVICE_NETWORK_FILE_SYSTEM
                        });
                        (raw, backed)
                    }
                    Err(err) => {
                        notes.push(format!(
                        "the device type could not be read, so whether this object is a file on \
                         disk is unknown: {err}"
                    ));
                        (None, None)
                    }
                },
                Ok(None) => {
                    notes.push(
                    "the file object has a null DeviceObject, so whether it is a file on disk is \
                     unknown"
                        .to_string(),
                );
                    (None, None)
                }
                Err(err) => {
                    notes.push(format!("the device object could not be read: {err}"));
                    (None, None)
                }
            },
            _ => {
                notes.push(
                "this build does not describe a file object's device, so whether this object is a \
                 file on disk is unknown"
                    .to_string(),
            );
                (None, None)
            }
        };

    let mut available = Vec::new();
    match object.follow(&symbols.file.section_object_pointers) {
        Ok(Some(pointers)) => {
            for (cache, member) in [
                (FileCache::DataSection, &symbols.file.data_section_object),
                (FileCache::ImageSection, &symbols.file.image_section_object),
                (FileCache::SharedCacheMap, &symbols.file.shared_cache_map),
            ] {
                let Some(member) = member else {
                    notes.push(format!(
                        "this build's '{TYPE_SECTION_OBJECT_POINTERS}' has no {} member",
                        cache.as_str()
                    ));
                    continue;
                };
                match pointers.pointer(member) {
                    Ok(0) => {}
                    Ok(address) => available.push((cache, address)),
                    Err(err) => notes.push(format!(
                        "the {} pointer could not be read, so it is not known whether that cache \
                         exists: {err}",
                        cache.as_str()
                    )),
                }
            }
        }
        Ok(None) => notes.push(
            "the file object's SectionObjectPointer is null, so none of its contents is cached"
                .to_string(),
        ),
        Err(err) => notes.push(format!(
            "the file object's SectionObjectPointer could not be read: {err}"
        )),
    }

    Ok(FileObjectCaches {
        file_object,
        name,
        device_type,
        is_file_backed,
        available,
        notes,
    })
}

/// Caps for one cached-file reconstruction.
#[derive(Debug, Clone)]
pub struct FileCacheConfig {
    /// Ceiling on subsections one control area walk follows.
    pub max_subsections: usize,
    /// Ceiling on prototype PTEs read from one subsection.
    pub max_ptes_per_subsection: u64,
    /// Ceiling on runs one reconstruction reports.
    pub max_pages: usize,
    /// Ceiling on VACB index arrays one walk visits.
    pub max_vacb_arrays: usize,
    /// Ceiling on individually recorded notes.
    pub max_recorded_notes: usize,
    /// Whether to hold a control area to its own `Segment` back-pointer.
    ///
    /// On by default. A control area that fails it is not a control area, and
    /// walking it anyway produces file offsets from whatever the bytes happen to
    /// say.
    pub validate: bool,
    /// Caps for the underlying reads.
    pub extract: ExtractConfig,
}

impl Default for FileCacheConfig {
    fn default() -> Self {
        Self {
            max_subsections: MAX_SUBSECTIONS,
            max_ptes_per_subsection: MAX_PTES_PER_SUBSECTION,
            max_pages: MAX_CACHED_PAGES,
            max_vacb_arrays: MAX_VACB_ARRAYS,
            max_recorded_notes: MAX_CACHE_NOTES,
            validate: true,
            extract: ExtractConfig::default(),
        }
    }
}

/// Accumulates cached runs under the configured caps.
struct CacheWalk {
    pages: Vec<CachedPage>,
    skipped: usize,
    notes: Vec<String>,
    stop: ExtractStop,
}

impl CacheWalk {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            skipped: 0,
            notes: Vec::new(),
            stop: ExtractStop::Exhausted,
        }
    }

    fn note(&mut self, config: &FileCacheConfig, note: impl Into<String>) {
        if self.notes.len() < config.max_recorded_notes {
            self.notes.push(note.into());
        }
    }

    /// Record a run; `false` when the page cap has fired.
    fn push(&mut self, config: &FileCacheConfig, page: CachedPage) -> bool {
        if page.length == 0 {
            return true;
        }
        if self.pages.len() >= config.max_pages {
            if self.stop.is_complete() {
                self.stop = ExtractStop::CapReached {
                    what: "cached pages",
                    cap: config.max_pages as u64,
                };
            }
            return false;
        }
        self.pages.push(page);
        true
    }
}

/// Where the pages of one of a file object's caches are.
///
/// This is upstream's `dumpfiles`, split so that *finding* the pages and
/// *reading* them are separate steps: the map alone answers "how much of this
/// file was still in RAM", which is often the question, and it answers it
/// without holding the file's bytes.
///
/// # Errors
///
/// [`DumpError::Unsupported`] when this build does not describe the route the
/// requested cache needs, naming the member that is missing, and
/// [`DumpError::Object`] when the cache's own structure could not be read.
pub fn file_cache_map(
    profile: &WindowsProfile,
    symbols: &DumpSymbols,
    file_object: u64,
    cache: FileCache,
    object: u64,
    config: &FileCacheConfig,
) -> Result<FileCacheMap, DumpError> {
    match cache {
        FileCache::DataSection | FileCache::ImageSection => {
            control_area_pages(profile, symbols, file_object, cache, object, config)
        }
        FileCache::SharedCacheMap => {
            shared_cache_pages(profile, symbols, file_object, object, config)
        }
    }
}

/// Walk a control area's subsections and their prototype PTEs.
fn control_area_pages(
    profile: &WindowsProfile,
    symbols: &DumpSymbols,
    file_object: u64,
    cache: FileCache,
    control_area: u64,
    config: &FileCacheConfig,
) -> Result<FileCacheMap, DumpError> {
    let layout = symbols.require_sections()?;
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let control = reader.object(control_area, TYPE_CONTROL_AREA)?;
    let mut walk = CacheWalk::new();
    let mut declared_size = None;

    if let Some(check) = &layout.segment {
        match validate_control_area(&reader, &control, control_area, check) {
            Ok(size) => declared_size = size,
            Err(detail) => {
                return Err(DumpError::unsupported(format!(
                    "the control area at {control_area:#x} is not self-consistent, so the file \
                     offsets it would give are not the file's: {detail}"
                )))
            }
        }
    }

    // An image section's subsections are aligned to 512-byte disk sectors and a
    // data section's to 4096-byte pages. Using the wrong multiplier does not
    // fail: it places every page of the reconstruction eight times too far in,
    // or an eighth of the way, and the file that comes out is plausible rubbish.
    let sector_size = match &layout.image_flag {
        Some(path) => match control.int(path) {
            Ok(value) => {
                if value.as_u64() == Some(1) {
                    IMAGE_SECTOR_SIZE
                } else {
                    DATA_SECTOR_SIZE
                }
            }
            Err(err) => {
                let fallback = default_sector_size(cache);
                walk.note(
                    config,
                    format!(
                        "the control area's image flag could not be read ({err}), so the \
                         {sector} multiplier the {kind} cache implies is used instead",
                        sector = fallback,
                        kind = cache.as_str()
                    ),
                );
                fallback
            }
        },
        None => {
            let fallback = default_sector_size(cache);
            walk.note(
                config,
                format!(
                    "this build's '{TYPE_CONTROL_AREA}' has no image flag, so the {fallback} \
                     multiplier the {} cache implies is used instead",
                    cache.as_str()
                ),
            );
            fallback
        }
    };

    let mut subsection = control_area
        .checked_add(layout.control_area_size)
        .ok_or_else(|| {
            DumpError::overflow("the first subsection's address leaves the address space")
        })?;
    let mut seen: HashSet<u64> = HashSet::new();

    'subsections: for _ in 0..config.max_subsections {
        if subsection == 0 {
            break;
        }
        if !seen.insert(subsection) {
            walk.note(
                config,
                format!(
                    "the subsection at {subsection:#x} was already visited, so the list does not \
                     terminate and the walk stops here"
                ),
            );
            break;
        }
        let object = match reader.object(subsection, TYPE_SUBSECTION) {
            Ok(object) => object,
            Err(err) => {
                walk.note(
                    config,
                    format!("the subsection at {subsection:#x} could not be read: {err}"),
                );
                break;
            }
        };
        // A subsection whose ControlArea is not this one is not this file's.
        match object.pointer(&layout.subsection_control_area) {
            Ok(owner) if owner == control_area => {}
            Ok(owner) => {
                walk.note(
                    config,
                    format!(
                        "the subsection at {subsection:#x} belongs to the control area at \
                         {owner:#x}, not to {control_area:#x}, so the list ends here"
                    ),
                );
                break;
            }
            Err(err) => {
                walk.note(
                    config,
                    format!(
                        "the subsection at {subsection:#x} does not say which control area it \
                         belongs to, so the list ends here: {err}"
                    ),
                );
                break;
            }
        }

        // Where in the file this subsection begins, and how many pages it
        // covers. Both come out of the structure or the subsection is not
        // walked at all. Defaulting the starting sector to zero would file
        // every one of these pages at the front of the reconstruction, on top
        // of the first subsection's, and the file that came out would be
        // plausible and wrong; defaulting the count to zero would make a
        // subsection whose size could not be read indistinguishable from one
        // that really holds nothing.
        let starting_sector = object
            .int(&layout.subsection_starting_sector)
            .ok()
            .and_then(|value| value.as_u64());
        let declared_ptes = object
            .int(&layout.subsection_ptes)
            .ok()
            .and_then(|value| value.as_u64());
        let placement = match (starting_sector, declared_ptes) {
            (Some(sector), Some(count)) => Some((sector.saturating_mul(sector_size), count)),
            (sector, count) => {
                let missing = match (sector.is_none(), count.is_none()) {
                    (true, true) => {
                        "neither which sector of the file it begins at nor how many pages it covers"
                    }
                    (true, false) => "which sector of the file it begins at",
                    _ => "how many pages it covers",
                };
                walk.note(
                    config,
                    format!(
                        "the subsection at {subsection:#x} does not say {missing}, so none of its \
                         pages can be placed in the file and none of them is reported"
                    ),
                );
                walk.skipped = walk.skipped.saturating_add(1);
                None
            }
        };

        if let Some((subsection_offset, declared_ptes)) = placement {
            let ptes = declared_ptes.min(config.max_ptes_per_subsection);
            let uncounted = usize::try_from(ptes).unwrap_or(usize::MAX);
            if declared_ptes > ptes {
                walk.note(
                    config,
                    format!(
                        "the subsection at {subsection:#x} declares {declared_ptes} prototype \
                         PTEs, above the cap of {ptes}; the pages past it are not listed"
                    ),
                );
                if walk.stop.is_complete() {
                    walk.stop = ExtractStop::CapReached {
                        what: "prototype PTEs in one subsection",
                        cap: config.max_ptes_per_subsection,
                    };
                }
            }
            let base = match object.pointer(&layout.subsection_base) {
                Ok(0) => {
                    walk.note(
                        config,
                        format!(
                            "the subsection at {subsection:#x} has a null prototype PTE array, so \
                             none of its {ptes} page(s) can be located"
                        ),
                    );
                    walk.skipped = walk.skipped.saturating_add(uncounted);
                    0
                }
                Ok(base) => base,
                Err(err) => {
                    walk.note(
                        config,
                        format!(
                            "the subsection at {subsection:#x} does not say where its prototype \
                             PTEs are, so whether its {ptes} page(s) are cached is unknown: {err}"
                        ),
                    );
                    walk.skipped = walk.skipped.saturating_add(uncounted);
                    0
                }
            };

            if base != 0 {
                for index in 0..ptes {
                    let Some(within) = index.checked_mul(layout.mmpte_size) else {
                        break;
                    };
                    let Some(pte_address) = base.checked_add(within) else {
                        break;
                    };
                    let Some(file_offset) = index
                        .checked_mul(PAGE_SIZE)
                        .and_then(|within| subsection_offset.checked_add(within))
                    else {
                        break;
                    };
                    match prototype_page(&reader, layout, pte_address) {
                        Ok(Some(physical)) => {
                            if !walk.push(
                                config,
                                CachedPage {
                                    file_offset,
                                    source: physical,
                                    length: PAGE_SIZE,
                                },
                            ) {
                                break 'subsections;
                            }
                        }
                        // Not resident. Not an error, and emphatically not
                        // zeroes: this page of the file simply was not in RAM.
                        Ok(None) => walk.skipped += 1,
                        Err(err) => {
                            walk.skipped += 1;
                            walk.note(
                                config,
                                format!(
                                    "the prototype PTE at {pte_address:#x} could not be read, so \
                                     whether file offset {file_offset:#x} is cached is unknown: \
                                     {err}"
                                ),
                            );
                        }
                    }
                }
            }
        }

        subsection = match object.pointer(&layout.subsection_next) {
            Ok(next) => next,
            Err(err) => {
                walk.note(
                    config,
                    format!(
                        "the subsection list could not be followed past {subsection:#x}: {err}"
                    ),
                );
                break;
            }
        };
    }

    finish_cache_map(
        file_object,
        cache,
        control_area,
        CacheSpace::Physical,
        declared_size,
        walk,
        config,
    )
}

/// The sector multiplier a cache implies when the image flag is unreadable.
fn default_sector_size(cache: FileCache) -> u64 {
    match cache {
        FileCache::ImageSection => IMAGE_SECTOR_SIZE,
        _ => DATA_SECTOR_SIZE,
    }
}

/// Hold a control area to its own segment, and take the file's size from it.
fn validate_control_area(
    reader: &StructReader,
    control: &Obj,
    control_area: u64,
    check: &SegmentCheck,
) -> Result<Option<u64>, String> {
    let segment_address = control
        .pointer(&check.segment)
        .map_err(|err| format!("its Segment pointer could not be read: {err}"))?;
    if segment_address == 0 {
        return Err("its Segment pointer is null".to_string());
    }
    let segment = reader
        .object(segment_address, TYPE_SEGMENT)
        .map_err(|err| format!("its segment at {segment_address:#x} could not be read: {err}"))?;
    let back = segment
        .pointer(&check.control_area)
        .map_err(|err| format!("its segment does not point back to a control area: {err}"))?;
    if back != control_area {
        return Err(format!(
            "its segment at {segment_address:#x} points back to {back:#x}"
        ));
    }
    let size = segment
        .int(&check.size_of_segment)
        .ok()
        .and_then(|value| value.as_u64());
    let total_ptes = segment
        .int(&check.total_ptes)
        .ok()
        .and_then(|value| value.as_u64());
    if let (Some(size), Some(total)) = (size, total_ptes) {
        // The segment covers exactly one page per prototype PTE. A pair that
        // does not agree means these bytes are not a segment.
        if size != total.saturating_mul(PAGE_SIZE) {
            return Err(format!(
                "its segment declares {size} byte(s) for {total} page table entries, which is not \
                 {} byte(s) per page",
                PAGE_SIZE
            ));
        }
    }
    Ok(size)
}

/// The physical page one prototype PTE names, if it names one.
///
/// Two entries yield a page. A **valid** entry is a page in RAM. A
/// **transition** entry is a page on the standby or modified list: the hardware
/// would fault on it, but the frame still holds the page's bytes, and refusing
/// it would lose exactly the recently-closed file content a cache dump is for.
///
/// `Ok(None)` means one thing only: the entry names no page. An entry that
/// cannot be read, or whose frame number is not a physical address, is an
/// error — a caller counts those as *unknown*, not as *was not in RAM*.
fn prototype_page(
    reader: &StructReader,
    layout: &SectionLayout,
    address: u64,
) -> Result<Option<u64>, ObjError> {
    let pte = reader.object(address, TYPE_MMPTE)?;
    let valid = pte
        .int(&layout.pte_valid)?
        .as_u64()
        .ok_or_else(|| SymbolError::malformed("a PTE's valid bit is negative"))?;
    if valid == 1 {
        let frame = pte
            .int(&layout.pte_page_frame)?
            .as_u64()
            .ok_or_else(|| SymbolError::malformed("a PTE's page frame number is negative"))?;
        return frame.checked_mul(PAGE_SIZE).map(Some).ok_or_else(|| {
            // `None` here would mean "this page was not resident", which is the
            // opposite of what a frame number too large to be an address says.
            ObjError::from(SymbolError::malformed(format!(
                "a PTE names page frame {frame}, whose physical address does not fit in 64 bits"
            )))
        });
    }
    let transition = pte
        .int(&layout.pte_transition)?
        .as_u64()
        .ok_or_else(|| SymbolError::malformed("a PTE's transition bit is negative"))?;
    if transition == 1 {
        let frame = pte
            .int(&layout.pte_transition_frame)?
            .as_u64()
            .ok_or_else(|| SymbolError::malformed("a PTE's page frame number is negative"))?;
        // Windows 10 stores a flag in the high bits of a transition entry's
        // frame field; upstream masks it to 33 bits and so does this. The mask
        // is what makes the multiply below unable to overflow.
        let frame = frame & ((1u64 << 33) - 1);
        return Ok(Some(frame.saturating_mul(PAGE_SIZE)));
    }
    Ok(None)
}

/// Walk the cache manager's views of a file.
fn shared_cache_pages(
    profile: &WindowsProfile,
    symbols: &DumpSymbols,
    file_object: u64,
    shared_cache_map: u64,
    config: &FileCacheConfig,
) -> Result<FileCacheMap, DumpError> {
    let layout = symbols.require_cache()?;
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let scm = reader.object(shared_cache_map, TYPE_SHARED_CACHE_MAP)?;
    let mut walk = CacheWalk::new();

    let signed = |path: &str| -> Result<i64, DumpError> {
        scm.int(path)?.as_i64().ok_or_else(|| {
            DumpError::unsupported(format!(
                "'{TYPE_SHARED_CACHE_MAP}.{path}' does not fit in a signed 64-bit value"
            ))
        })
    };
    let file_size = signed(&layout.file_size)?;
    let valid_data_length = signed(&layout.valid_data_length)?;
    let section_size = signed(&layout.section_size)?;

    // Upstream's `is_valid`, kept as a refusal rather than a silent skip: a
    // shared cache map that fails these is not one, and the views it would name
    // are whatever the bytes at those offsets happen to be.
    if config.validate {
        if file_size <= 0 || valid_data_length <= 0 {
            return Err(DumpError::unsupported(format!(
                "the shared cache map at {shared_cache_map:#x} declares a file of {file_size} \
                 byte(s) with {valid_data_length} valid, which is not a cached file"
            )));
        }
        if section_size < 0 {
            return Err(DumpError::unsupported(format!(
                "the shared cache map at {shared_cache_map:#x} declares a section of \
                 {section_size} byte(s)"
            )));
        }
        // 0x7FFFFFFFFFFFFFFF is the sentinel the cache manager uses for "valid
        // to the end", so it is not a contradiction of a smaller file size.
        if file_size < valid_data_length && valid_data_length != i64::MAX {
            return Err(DumpError::unsupported(format!(
                "the shared cache map at {shared_cache_map:#x} declares {valid_data_length} valid \
                 byte(s) in a file of {file_size}"
            )));
        }
    }

    let file_size = u64::try_from(file_size).unwrap_or(0);
    let section_size = u64::try_from(section_size).unwrap_or(0);
    let full_blocks = section_size / VACB_BLOCK;
    let left_over = section_size % VACB_BLOCK;

    // The first four views are inline in the shared cache map itself, which
    // covers a file up to 1 MiB with no allocation at all.
    let inline = layout.initial_vacb_count;
    if full_blocks <= inline {
        for index in 0..full_blocks.min(inline) {
            match scm.element_int(&layout.initial_vacbs, index) {
                Ok(value) => {
                    if let Some(address) = value.as_u64().filter(|value| *value != 0) {
                        if !save_vacb(
                            &reader,
                            layout,
                            shared_cache_map,
                            address,
                            file_size,
                            &mut walk,
                            config,
                        ) {
                            return finish_shared(
                                file_object,
                                shared_cache_map,
                                file_size,
                                walk,
                                config,
                            );
                        }
                    }
                }
                Err(err) => walk.note(
                    config,
                    format!("inline view {index} could not be read: {err}"),
                ),
            }
        }
        if left_over > 0 && full_blocks < inline {
            if let Ok(value) = scm.element_int(&layout.initial_vacbs, full_blocks) {
                if let Some(address) = value.as_u64().filter(|value| *value != 0) {
                    if !save_vacb(
                        &reader,
                        layout,
                        shared_cache_map,
                        address,
                        file_size,
                        &mut walk,
                        config,
                    ) {
                        return finish_shared(
                            file_object,
                            shared_cache_map,
                            file_size,
                            walk,
                            config,
                        );
                    }
                }
            }
        }
    }

    let array = match scm.pointer(&layout.vacbs) {
        Ok(array) => array,
        Err(err) => {
            walk.note(
                config,
                format!("the allocated view index could not be read: {err}"),
            );
            0
        }
    };
    if array == 0 {
        return finish_shared(file_object, shared_cache_map, file_size, walk, config);
    }
    // A `Vacbs` that points at the inline array is the inline array, already
    // read. Reading it again would double every view.
    if let Ok(inline_address) = scm.member_address(&layout.initial_vacbs) {
        if array == inline_address {
            return finish_shared(file_object, shared_cache_map, file_size, walk, config);
        }
    }

    if section_size <= VACB_SIZE_OF_FIRST_LEVEL {
        // One flat array, one entry per 256 KiB of the file.
        let entries = full_blocks.saturating_add(u64::from(left_over > 0));
        for index in 0..entries {
            let Some(at) = index
                .checked_mul(layout.pointer_size)
                .and_then(|within| array.checked_add(within))
            else {
                break;
            };
            match reader.read_pointer_at(at) {
                Ok(0) => {}
                Ok(address) => {
                    if !save_vacb(
                        &reader,
                        layout,
                        shared_cache_map,
                        address,
                        file_size,
                        &mut walk,
                        config,
                    ) {
                        break;
                    }
                }
                Err(err) => walk.note(
                    config,
                    format!("view index entry {index} at {at:#x} could not be read: {err}"),
                ),
            }
        }
        return finish_shared(file_object, shared_cache_map, file_size, walk, config);
    }

    // Above 32 MiB the index is a sparse tree of 128-entry arrays. The depth is
    // derived from the file's own size rather than assumed, and bounded, and
    // cycle-safe: the arrays are pointers taken from the image.
    // ceil(log2(section_size)), then (that − 18) / 7 rounded up, which is
    // upstream's arithmetic done in integers so no rounding of a float can
    // shorten the tree by a level and hide the views below it.
    let bits = 64 - section_size.leading_zeros();
    let limit = if bits > VACB_OFFSET_SHIFT {
        let above = bits - VACB_OFFSET_SHIFT;
        above.div_ceil(VACB_LEVEL_SHIFT).max(1)
    } else {
        1
    };
    let mut stack = vec![(array, 1u32)];
    let mut visited: HashSet<u64> = HashSet::new();
    let mut arrays = 0usize;

    while let Some((at, level)) = stack.pop() {
        arrays += 1;
        if arrays > config.max_vacb_arrays {
            if walk.stop.is_complete() {
                walk.stop = ExtractStop::CapReached {
                    what: "view index arrays",
                    cap: config.max_vacb_arrays as u64,
                };
            }
            break;
        }
        if level > limit {
            walk.note(
                config,
                format!(
                    "the view index at {at:#x} is more than {limit} level(s) deep, which a file \
                     of {section_size} byte(s) does not have"
                ),
            );
            continue;
        }
        if !visited.insert(at) {
            walk.note(
                config,
                format!("the view index at {at:#x} was already visited, so it contains a cycle"),
            );
            continue;
        }
        for index in 0..VACB_ARRAY {
            let Some(slot) = index
                .checked_mul(layout.pointer_size)
                .and_then(|within| at.checked_add(within))
            else {
                break;
            };
            let entry = match reader.read_pointer_at(slot) {
                Ok(0) => continue,
                Ok(entry) => entry,
                Err(err) => {
                    walk.note(
                        config,
                        format!("view index entry at {slot:#x} could not be read: {err}"),
                    );
                    continue;
                }
            };
            // An entry is either a view of this file or the next level down.
            // Which one it is, is settled by whether it points back at us.
            let owns = match reader.object(entry, TYPE_VACB) {
                Ok(vacb) => {
                    vacb.pointer(&layout.vacb_shared_cache_map).ok() == Some(shared_cache_map)
                }
                Err(_) => false,
            };
            if owns {
                if !save_vacb(
                    &reader,
                    layout,
                    shared_cache_map,
                    entry,
                    file_size,
                    &mut walk,
                    config,
                ) {
                    stack.clear();
                    break;
                }
            } else if let Some(next) = level.checked_add(1) {
                stack.push((entry, next));
            }
        }
    }

    finish_shared(file_object, shared_cache_map, file_size, walk, config)
}

/// Record one view of a file, clipped to the file's own declared size.
///
/// Every view is 256 KiB whatever the file's length, so the last one runs past
/// the end. Upstream writes the whole view, producing a reconstruction up to
/// 256 KiB longer than the file it claims to be.
fn save_vacb(
    reader: &StructReader,
    layout: &CacheLayout,
    shared_cache_map: u64,
    vacb: u64,
    file_size: u64,
    walk: &mut CacheWalk,
    config: &FileCacheConfig,
) -> bool {
    let object = match reader.object(vacb, TYPE_VACB) {
        Ok(object) => object,
        Err(err) => {
            walk.note(
                config,
                format!("the view at {vacb:#x} could not be read: {err}"),
            );
            walk.skipped += 1;
            return true;
        }
    };
    match object.pointer(&layout.vacb_shared_cache_map) {
        Ok(owner) if owner == shared_cache_map => {}
        Ok(owner) => {
            walk.note(
                config,
                format!(
                    "the view at {vacb:#x} belongs to the shared cache map at {owner:#x}, not to \
                     {shared_cache_map:#x}, so it is not this file's"
                ),
            );
            walk.skipped += 1;
            return true;
        }
        Err(err) => {
            walk.note(
                config,
                format!("the view at {vacb:#x} does not say which file it belongs to: {err}"),
            );
            walk.skipped += 1;
            return true;
        }
    }
    let source = match object.int(&layout.vacb_base_address) {
        Ok(value) => match value.as_u64() {
            Some(0) | None => {
                walk.skipped += 1;
                return true;
            }
            Some(address) => address,
        },
        Err(err) => {
            walk.note(
                config,
                format!("the view at {vacb:#x} does not say where it is mapped: {err}"),
            );
            walk.skipped += 1;
            return true;
        }
    };
    let file_offset = match object.int(&layout.vacb_file_offset) {
        Ok(value) => match value.as_u64() {
            Some(raw) => raw & VACB_FILE_OFFSET_MASK,
            None => {
                walk.note(
                    config,
                    format!("the view at {vacb:#x} declares a negative file offset"),
                );
                walk.skipped += 1;
                return true;
            }
        },
        Err(err) => {
            walk.note(
                config,
                format!("the view at {vacb:#x} does not say where in the file it is: {err}"),
            );
            walk.skipped += 1;
            return true;
        }
    };
    let length = if file_size > file_offset {
        VACB_BLOCK.min(file_size - file_offset)
    } else if file_size == 0 {
        VACB_BLOCK
    } else {
        walk.note(
            config,
            format!(
                "the view at {vacb:#x} begins at file offset {file_offset:#x}, past the end of a \
                 file of {file_size} byte(s), so it is not part of it"
            ),
        );
        walk.skipped += 1;
        return true;
    };
    walk.push(
        config,
        CachedPage {
            file_offset,
            source,
            length,
        },
    )
}

/// Finish a shared-cache-map walk.
fn finish_shared(
    file_object: u64,
    shared_cache_map: u64,
    file_size: u64,
    walk: CacheWalk,
    config: &FileCacheConfig,
) -> Result<FileCacheMap, DumpError> {
    finish_cache_map(
        file_object,
        FileCache::SharedCacheMap,
        shared_cache_map,
        CacheSpace::KernelVirtual,
        Some(file_size).filter(|size| *size > 0),
        walk,
        config,
    )
}

/// Sort a walk's runs, drop the ones that would overlap, and produce the map.
fn finish_cache_map(
    file_object: u64,
    cache: FileCache,
    object: u64,
    space: CacheSpace,
    declared_size: Option<u64>,
    walk: CacheWalk,
    config: &FileCacheConfig,
) -> Result<FileCacheMap, DumpError> {
    let CacheWalk {
        mut pages,
        mut skipped,
        mut notes,
        stop,
    } = walk;
    // Length descending within an offset. Two runs starting at the same place
    // overlap, so exactly one survives the sweep below — and ascending length
    // made that the shorter one, recovering less of the file than the image
    // actually held, for no reason beyond sort order.
    pages.sort_by_key(|page| (page.file_offset, std::cmp::Reverse(page.length)));

    // Two structures claiming the same bytes of the file is a corrupt or
    // deliberately overlapped cache. Letting the later one win would silently
    // choose which of two candidate contents the file had.
    let mut kept: Vec<CachedPage> = Vec::with_capacity(pages.len());
    let mut end = 0u64;
    for page in pages {
        if page.file_offset < end {
            skipped += 1;
            if notes.len() < config.max_recorded_notes {
                notes.push(format!(
                    "a cached run at file offset {:#x} overlaps one already recorded, so it is \
                     not used",
                    page.file_offset
                ));
            }
            continue;
        }
        end = page.end();
        kept.push(page);
    }

    Ok(FileCacheMap {
        file_object,
        cache,
        object,
        space,
        pages: kept,
        declared_size,
        skipped_total: skipped,
        stop,
        notes,
    })
}

/// Extract the cached parts of a file.
///
/// The artifact's offset space is the **file's own**: a run cached at file
/// offset 0x3000 lands at 0x3000. Everything between the cached runs is a
/// [`Gap`] with [`GapReason::NotInMemory`] — those pages of the file were not
/// in RAM, and upstream writes zeroes for them, producing a file of the right
/// length whose contents are part evidence and part invention.
///
/// The runs are read from the layer their space names: physical for a section
/// object's prototype PTEs, kernel virtual for the cache manager's views.
///
/// # Errors
///
/// [`DumpError::TooLarge`] when the file is larger than the configured cap.
pub fn dump_file_cache(
    profile: &WindowsProfile,
    map: &FileCacheMap,
    config: &FileCacheConfig,
) -> Result<Extract, DumpError> {
    let layer: &dyn MemoryLayer = match map.space {
        CacheSpace::Physical => profile.physical.as_ref(),
        CacheSpace::KernelVirtual => profile.kernel_space.as_ref(),
    };
    let covered = map.pages.last().map(CachedPage::end).unwrap_or(0);
    let length = map.declared_size.unwrap_or(covered).max(covered);
    config.extract.admit("a reconstructed file", length)?;

    let mut builder = ExtractBuilder::new(&config.extract, ExtractLayout::Sparse);
    let mut at = 0u64;
    // No `break` on the cap: see `memory_dump`. Every page keeps its place in
    // the reconstructed file, whether it was written or refused.
    for page in &map.pages {
        if page.file_offset > at {
            builder.add_gap(
                at,
                0,
                page.file_offset - at,
                GapReason::NotInMemory,
                "this part of the file was not resident, so nothing is written for it",
            );
        }
        read_into(
            &mut builder,
            layer,
            page.source,
            page.length,
            page.file_offset,
        );
        at = page.end();
    }
    if at < length {
        builder.add_gap(
            at,
            0,
            length - at,
            GapReason::NotInMemory,
            "the end of the file was not resident, so nothing is written for it",
        );
    }
    if let ExtractStop::CapReached { what, cap } = map.stop {
        builder.cap(what, cap);
    }
    for note in &map.notes {
        builder.note(note.clone());
    }
    Ok(builder.finish(length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{profile, table, Image};
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::{Architecture, LayerMeta, Segment, SegmentedLayer};

    // ── Fixtures ────────────────────────────────────────────────────────────

    /// First mapped window of the holed fixture.
    const LOW_BASE: u64 = 0x1000;
    /// The unacquired window between the two.
    const HOLE_BASE: u64 = 0x2000;
    /// Second mapped window.
    const HIGH_BASE: u64 = 0x3000;
    /// How long each of them is.
    const WINDOW: u64 = 0x1000;

    /// A distinct byte per backing offset, so a test that asserts a byte landed
    /// at an offset is asserting against a value only that offset holds.
    fn pattern(offset: u64) -> u8 {
        (offset % 251) as u8
    }

    /// A layer with two acquired windows and a genuine unacquired window
    /// between them.
    ///
    /// The whole module exists for what happens across that middle window, so
    /// nothing about these tests may be built on a layer that quietly returns
    /// zeroes for it.
    fn holed_layer() -> Arc<dyn MemoryLayer> {
        let bytes: Vec<u8> = (0..(WINDOW * 2)).map(pattern).collect();
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let segments = vec![
            Segment::new(0, LOW_BASE, WINDOW),
            Segment::new(WINDOW, HIGH_BASE, WINDOW),
        ];
        Arc::new(
            SegmentedLayer::new(
                source,
                segments,
                LayerMeta::default().with_declared_size(HIGH_BASE + WINDOW),
            )
            .expect("a valid fixture layer"),
        )
    }

    /// A fully acquired layer over a hand-written image.
    fn dense_layer(image: Image) -> Arc<dyn MemoryLayer> {
        image.layer()
    }

    fn config() -> ExtractConfig {
        ExtractConfig::default()
    }

    // ── The rule: gaps are never zeroes ─────────────────────────────────────

    #[test]
    fn bytes_after_an_unacquired_window_keep_their_own_offset_rather_than_sliding_up() {
        // The single most important property in this module. If the extraction
        // dropped the missing window instead of leaving a hole for it, every
        // byte after it would be attributed to an address 4096 too low, and the
        // dump would still look like a well-formed 8 KiB object.
        let layer = holed_layer();
        let extract =
            dump_range(layer.as_ref(), LOW_BASE, WINDOW * 3, &config()).expect("a runnable dump");

        assert_eq!(extract.length, WINDOW * 3);
        assert_eq!(extract.acquired_bytes, WINDOW * 2);
        assert_eq!(extract.gap_bytes, WINDOW);
        assert_eq!(extract.chunks.len(), 2);

        assert_eq!(extract.chunks[0].offset, 0);
        assert_eq!(extract.chunks[0].address, LOW_BASE);
        assert_eq!(extract.chunks[1].offset, WINDOW * 2);
        assert_eq!(extract.chunks[1].address, HIGH_BASE);

        // The first byte of the second window is the first byte of the second
        // backing segment, and it is at offset 0x2000 of the artifact.
        assert_eq!(
            extract.bytes_at(WINDOW * 2, 1),
            Some(&[pattern(WINDOW)][..]),
            "the second window must not have moved up into the hole"
        );
    }

    #[test]
    fn an_unacquired_window_is_reported_as_a_gap_with_its_reason_and_its_address() {
        let layer = holed_layer();
        let extract =
            dump_range(layer.as_ref(), LOW_BASE, WINDOW * 3, &config()).expect("a runnable dump");
        assert_eq!(extract.gap_total, 1);
        let gap = &extract.gaps[0];
        assert_eq!(gap.offset, WINDOW);
        assert_eq!(gap.address, HOLE_BASE);
        assert_eq!(gap.length, WINDOW);
        assert_eq!(gap.reason, GapReason::Unmapped);
        assert!(!gap.detail.is_empty(), "a gap must say why");
    }

    #[test]
    fn bytes_the_chunk_cap_refuses_are_still_accounted_for_in_the_gap_map() {
        // The cap stops the extraction writing more runs. What it must not do
        // is drop the range out of both lists: an examiner reads the gap map to
        // learn which addresses are not in the artifact, and a range that is in
        // neither the chunks nor the gaps reads as a capture that never held
        // those pages. Every byte of the declared length is in exactly one of
        // the two.
        let layer = holed_layer();
        let capped = ExtractConfig {
            max_chunks: 1,
            ..config()
        };
        let extract =
            dump_range(layer.as_ref(), LOW_BASE, WINDOW * 3, &capped).expect("a runnable dump");

        assert_eq!(extract.chunks.len(), 1, "the cap held");
        assert!(!extract.stop.is_complete(), "the cap is declared");
        assert_eq!(
            extract.acquired_bytes + extract.gap_bytes,
            extract.length,
            "every byte is either written or declared missing: {extract:?}"
        );
        // The second window was acquired and was not written. That is a
        // refusal, not an acquisition failure, and the two support opposite
        // conclusions.
        let refused = extract
            .gaps
            .iter()
            .find(|gap| gap.reason == GapReason::Refused)
            .expect("the refused range is in the gap map");
        assert_eq!(refused.address, HIGH_BASE);
        assert_eq!(refused.length, WINDOW);
        assert!(
            refused.detail.contains("cap"),
            "the gap must name the cap: {}",
            refused.detail
        );
    }

    #[test]
    fn an_incomplete_extraction_refuses_to_render_as_a_contiguous_buffer() {
        let layer = holed_layer();
        let extract =
            dump_range(layer.as_ref(), LOW_BASE, WINDOW * 3, &config()).expect("a runnable dump");
        assert!(!extract.is_complete());
        assert!(
            extract.contiguous().is_none(),
            "a caller must not be able to get a dense buffer out of a holed dump by accident"
        );
    }

    #[test]
    fn padding_happens_only_when_the_caller_asks_for_it_by_name() {
        let layer = holed_layer();
        let extract =
            dump_range(layer.as_ref(), LOW_BASE, WINDOW * 3, &config()).expect("a runnable dump");
        let padded = extract.padded_with(0);
        assert_eq!(padded.len() as u64, extract.length);
        // The acquired bytes are where they belong...
        assert_eq!(padded[0], pattern(0));
        assert_eq!(padded[(WINDOW * 2) as usize], pattern(WINDOW));
        // ...and the invented ones are exactly the gap the map declares, which
        // is the only reason this is usable at all.
        assert!(padded[WINDOW as usize..(WINDOW * 2) as usize]
            .iter()
            .all(|byte| *byte == 0));
        assert_eq!(extract.gap_bytes, WINDOW);
    }

    #[test]
    fn a_fully_acquired_range_comes_back_as_one_run_and_hashes_as_itself() {
        let layer = holed_layer();
        let extract =
            dump_range(layer.as_ref(), LOW_BASE, WINDOW, &config()).expect("a runnable dump");
        assert!(extract.is_complete());
        assert_eq!(extract.chunks.len(), 1, "adjacent pages merge into one run");
        let bytes = extract.contiguous().expect("a complete dump is contiguous");
        assert_eq!(bytes.len() as u64, WINDOW);
        assert_eq!(bytes[0], pattern(0));
        assert_eq!(bytes[(WINDOW - 1) as usize], pattern(WINDOW - 1));
        assert!(extract.incomplete().is_empty());
    }

    #[test]
    fn a_zero_length_extraction_is_an_empty_result_and_not_a_failure() {
        let layer = holed_layer();
        let extract = dump_range(layer.as_ref(), LOW_BASE, 0, &config()).expect("a runnable dump");
        assert_eq!(extract.length, 0);
        assert!(extract.chunks.is_empty());
        assert!(extract.is_complete());
        assert_eq!(extract.contiguous(), Some(Vec::new()));
    }

    #[test]
    fn a_request_above_the_cap_is_refused_by_name_rather_than_shortened() {
        // A shortened dump is a file that looks whole, which is the failure
        // mode the cap exists to prevent.
        let layer = holed_layer();
        let capped = ExtractConfig {
            max_bytes: 0x800,
            ..config()
        };
        let err = dump_range(layer.as_ref(), LOW_BASE, WINDOW, &capped)
            .expect_err("a request above the cap must be refused");
        assert_eq!(err.class(), "too_large");
        assert_eq!(err.incomplete_reason(), IncompleteReason::CapReached);
        assert!(err.to_string().contains("2048"), "{err}");
    }

    #[test]
    fn a_range_that_leaves_the_address_space_is_an_error_not_a_wrapped_address() {
        let layer = holed_layer();
        let err = dump_range(layer.as_ref(), u64::MAX - 4, 16, &config())
            .expect_err("wrapping arithmetic must be refused");
        assert_eq!(err.class(), "overflow");
    }

    #[test]
    fn a_gap_reason_maps_onto_an_honest_incomplete_reason() {
        assert_eq!(
            GapReason::from_hole(HoleReason::SwappedOut),
            GapReason::SwappedOut
        );
        assert_eq!(
            GapReason::SwappedOut.incomplete_reason(),
            IncompleteReason::ShortRead
        );
        assert_eq!(
            GapReason::Refused.incomplete_reason(),
            IncompleteReason::CapReached
        );
        assert_eq!(
            GapReason::NotInMemory.incomplete_reason(),
            IncompleteReason::UnresolvedStructure
        );
        assert_eq!(GapReason::Unaddressable.as_str(), "unaddressable");
    }

    #[test]
    fn adjacent_gaps_merge_and_the_totals_stay_exact_past_the_record_cap() {
        let config = ExtractConfig {
            max_recorded_gaps: 2,
            ..config()
        };
        let mut builder = ExtractBuilder::new(&config, ExtractLayout::Sparse);
        // Two runs of the same reason that touch: one recorded gap.
        builder.add_gap(0, 0x1000, 0x100, GapReason::NotPresent, "first");
        builder.add_gap(0x100, 0x1100, 0x100, GapReason::NotPresent, "second");
        // A different reason breaks the run.
        builder.add_gap(0x200, 0x1200, 0x100, GapReason::SwappedOut, "third");
        // Past the record cap: still counted, still measured.
        builder.add_gap(0x400, 0x1400, 0x100, GapReason::Unmapped, "fourth");
        builder.add_gap(0x500, 0x1500, 0x100, GapReason::Unmapped, "fifth");
        let extract = builder.finish(0x600);

        assert_eq!(extract.gaps.len(), 2, "the record list honours its cap");
        assert_eq!(extract.gaps[0].length, 0x200, "touching gaps merged");
        assert_eq!(extract.gap_total, 3, "the count is exact past the cap");
        assert_eq!(extract.gap_bytes, 0x500, "the byte total is exact too");
    }

    #[test]
    fn acquired_runs_merge_only_when_they_are_adjacent_in_both_spaces() {
        let config = config();
        let mut builder = ExtractBuilder::new(&config, ExtractLayout::Packed);
        builder.add_bytes(0, 0x1000, &[1, 2, 3, 4]);
        // Adjacent in the artifact and in memory: one run.
        builder.add_bytes(4, 0x1004, &[5, 6]);
        // Adjacent in the artifact only: two runs, because the addresses are
        // not contiguous and a merged run would misattribute the second.
        builder.add_bytes(6, 0x9000, &[7]);
        let extract = builder.finish(7);
        assert_eq!(extract.chunks.len(), 2);
        assert_eq!(extract.chunks[0].bytes, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(extract.chunks[1].address, 0x9000);
        assert_eq!(extract.acquired_bytes, 7);
    }

    // ── vaddump ─────────────────────────────────────────────────────────────

    /// A descriptor over `[start, end]`, with `end` the last accessible byte as
    /// [`crate::vad`] defines it.
    fn vad_over(start: u64, end: u64) -> Vad {
        Vad {
            address: 0x9000,
            depth: 0,
            tag: "VadS".to_string(),
            kind: crate::vad::VadKind::Short,
            start,
            end,
            parent: None,
            commit_charge: None,
            private_memory: None,
            protection: None,
            protection_names: None,
            file: crate::vad::MappedFile::NotApplicable,
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_vad_dump_includes_the_last_byte_of_the_range_because_the_end_is_inclusive() {
        // A VAD's `end` names the last accessible byte. Extracting `end - start`
        // bytes instead of `end - start + 1` loses the final page of every
        // allocation, and anything found in it belongs to nothing.
        let layer = holed_layer();
        let vad = vad_over(LOW_BASE, LOW_BASE + WINDOW - 1);
        let extract = dump_vad(layer.as_ref(), &vad, &config()).expect("a runnable dump");
        assert_eq!(extract.length, WINDOW);
        assert_eq!(vad.size(), WINDOW);
        let bytes = extract.contiguous().expect("this range is fully acquired");
        assert_eq!(
            bytes[(WINDOW - 1) as usize],
            pattern(WINDOW - 1),
            "the last byte of the last page is part of the range"
        );
    }

    #[test]
    fn a_vad_that_straddles_an_unacquired_window_reports_it_rather_than_shrinking() {
        let layer = holed_layer();
        let vad = vad_over(LOW_BASE, HIGH_BASE + WINDOW - 1);
        let extract = dump_vad(layer.as_ref(), &vad, &config()).expect("a runnable dump");
        assert_eq!(extract.length, WINDOW * 3);
        assert_eq!(extract.gap_total, 1);
        assert!(!extract.is_complete());
        let declared = extract.incomplete();
        assert_eq!(declared.len(), 1);
        assert_eq!(declared[0].reason, IncompleteReason::ShortRead);
    }

    // ── memmap / memdump ────────────────────────────────────────────────────

    #[test]
    fn the_memory_map_lists_only_mapped_regions_and_gives_each_its_file_offset() {
        let layer = holed_layer();
        let map =
            memory_map(layer.as_ref(), LOW_BASE, WINDOW * 3, &config()).expect("a runnable scan");
        assert_eq!(map.regions.len(), 2);
        assert_eq!(map.regions[0].address, LOW_BASE);
        assert_eq!(map.regions[0].file_offset, 0);
        assert_eq!(map.regions[0].mapped_offset, 0);
        assert_eq!(map.regions[1].address, HIGH_BASE);
        assert_eq!(
            map.regions[1].file_offset, WINDOW,
            "a packed dump reserves nothing for the window it does not have"
        );
        assert_eq!(map.regions[1].mapped_offset, WINDOW);
        assert_eq!(map.mapped_bytes, WINDOW * 2);
        assert_eq!(map.missing_bytes, WINDOW);
        assert!(map.is_complete(), "nothing was capped");
    }

    #[test]
    fn the_map_records_the_window_it_could_not_read_rather_than_passing_over_it() {
        let layer = holed_layer();
        let map =
            memory_map(layer.as_ref(), LOW_BASE, WINDOW * 3, &config()).expect("a runnable scan");
        assert_eq!(map.gap_total, 1);
        assert_eq!(map.gaps[0].address, HOLE_BASE);
        assert_eq!(map.gaps[0].length, WINDOW);
        assert!(map.containing(HOLE_BASE).is_none());
        assert_eq!(
            map.containing(HIGH_BASE).map(|r| r.file_offset),
            Some(WINDOW)
        );
    }

    /// A layer that reports a hole as **one page**, however many pages of it
    /// are missing.
    ///
    /// Real layers report a hole as the whole region one page-table entry
    /// governs, so a scan sees a multi-page hole once. This is the pathological
    /// shape the gap accounting has to survive, and the only way to reach the
    /// merge path after the record cap has fired. It still keeps the layer
    /// contract: a request touching an unmapped byte is an error naming where,
    /// never a short run.
    #[derive(Debug)]
    struct PageAtATime {
        /// Page addresses that have bytes behind them.
        mapped: Vec<u64>,
        /// One past the last addressable byte.
        top: u64,
        meta: LayerMeta,
    }

    impl PageAtATime {
        fn page_of(address: u64) -> u64 {
            address & !(PAGE_SIZE - 1)
        }

        /// First unmapped page at or after `offset`, within `length` bytes.
        fn first_hole(&self, offset: u64, length: u64) -> Option<u64> {
            let mut at = Self::page_of(offset);
            while at < offset.saturating_add(length) {
                if !self.mapped.contains(&at) {
                    return Some(at.max(offset));
                }
                at = at.saturating_add(PAGE_SIZE);
            }
            None
        }
    }

    impl DataSource for PageAtATime {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            if offset >= self.top {
                return Ok(0);
            }
            if !self.mapped.contains(&Self::page_of(offset)) {
                return Err(MemoryHole::unmapped(offset, PAGE_SIZE).into_io());
            }
            let end = Self::page_of(offset) + PAGE_SIZE;
            let take = buf.len().min((end - offset) as usize);
            buf[..take].fill(0xEE);
            Ok(take)
        }

        fn size(&self) -> u64 {
            self.top
        }
    }

    impl MemoryLayer for PageAtATime {
        fn min_address(&self) -> u64 {
            0
        }

        fn max_address(&self) -> u64 {
            self.top - 1
        }

        fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
            if offset > self.max_address() {
                return Err(LayerError::OutOfRange {
                    address: offset,
                    max_address: self.max_address(),
                });
            }
            let clipped = length.min(self.top - offset);
            if let Some(hole) = self.first_hole(offset, clipped) {
                return Err(LayerError::Hole(MemoryHole::unmapped(hole, PAGE_SIZE)));
            }
            Ok(vec![MappedRange::identity(offset, clipped, offset)])
        }

        fn layer_meta(&self) -> &LayerMeta {
            &self.meta
        }

        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    #[test]
    fn the_number_of_distinct_missing_ranges_stays_exact_after_the_record_cap_fires() {
        // Two multi-page holes with a mapped page between them, seen one page
        // at a time, and room to record only the first. The second hole is two
        // adjacent events; counting them as two distinct gaps would tell a
        // report there were three missing ranges when there were two, and a
        // report that overstates what it could not read is as wrong as one that
        // understates it.
        let layer = PageAtATime {
            mapped: vec![0x1000, 0x4000],
            top: 0x7000,
            meta: LayerMeta::default(),
        };
        let capped = ExtractConfig {
            max_recorded_gaps: 1,
            ..config()
        };
        let map = memory_map(&layer, 0x1000, 0x6000, &capped).expect("a runnable scan");

        assert_eq!(map.mapped_bytes, PAGE_SIZE * 2);
        assert_eq!(map.missing_bytes, PAGE_SIZE * 4);
        assert_eq!(
            map.gap_total, 2,
            "0x2000..0x4000 and 0x5000..0x7000 are two ranges, however many probes found them"
        );
        assert_eq!(map.gaps.len(), 1, "only the first is recorded");
        assert_eq!(map.gaps[0].address, 0x2000);
        assert_eq!(
            map.gaps[0].length,
            PAGE_SIZE * 2,
            "the recorded gap covers the whole first hole and no more"
        );
    }

    #[test]
    fn a_packed_dump_puts_each_region_at_the_file_offset_its_map_promised() {
        let layer = holed_layer();
        let (map, extract) =
            memory_dump(layer.as_ref(), LOW_BASE, WINDOW * 3, &config()).expect("a runnable dump");
        assert_eq!(extract.layout, ExtractLayout::Packed);
        assert_eq!(extract.length, map.mapped_bytes);
        assert_eq!(extract.length, WINDOW * 2);
        assert!(
            extract.is_complete(),
            "a packed dump of only the mapped regions has nothing missing from it"
        );
        for region in &map.regions {
            let first = extract
                .bytes_at(region.file_offset, 1)
                .expect("every region's first byte is in the dump");
            let expected = pattern(region.mapped_offset);
            assert_eq!(
                first[0], expected,
                "the region at {:#x} did not land at file offset {:#x}",
                region.address, region.file_offset
            );
        }
    }

    #[test]
    fn a_packed_dump_larger_than_the_cap_is_refused_before_any_byte_is_read() {
        let layer = holed_layer();
        let capped = ExtractConfig {
            max_bytes: WINDOW,
            ..config()
        };
        let err = memory_dump(layer.as_ref(), LOW_BASE, WINDOW * 3, &capped)
            .expect_err("a dump above the cap must be refused");
        assert_eq!(err.class(), "too_large");
    }

    #[test]
    fn coverage_reports_what_is_backed_without_reading_any_of_it() {
        let layer = holed_layer();
        let cover =
            coverage(layer.as_ref(), LOW_BASE, WINDOW * 3, &config()).expect("a runnable scan");
        assert_eq!(cover.spans.len(), 3);
        assert_eq!(cover.spans[0].state, SpanState::Mapped);
        assert!(matches!(
            cover.spans[1].state,
            SpanState::Missing {
                reason: GapReason::Unmapped,
                ..
            }
        ));
        assert_eq!(cover.spans[2].state, SpanState::Mapped);
        assert_eq!(cover.mapped_bytes, WINDOW * 2);
        assert_eq!(cover.missing_bytes, WINDOW);
        assert!(!cover.is_fully_mapped());
    }

    // ── PE fixtures ─────────────────────────────────────────────────────────

    /// Offset of the NT headers from the image base in every PE fixture here.
    const NT_OFFSET: u64 = 0x80;
    /// Size of the optional header in every PE fixture: through
    /// `DataDirectory[15]`.
    const OPTIONAL_SIZE: u16 = 0xF0;

    struct SectionSpec {
        name: &'static str,
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
    }

    struct PeSpec {
        base: u64,
        size_of_image: u32,
        size_of_headers: u32,
        section_alignment: u32,
        file_alignment: u32,
        image_base: u64,
        sections: Vec<SectionSpec>,
        directories: Vec<(usize, u32, u32)>,
    }

    /// Write a PE32+ image into the fixture, member by member at the offsets
    /// the format declares, and return the address of its section table.
    fn put_pe(image: &mut Image, spec: &PeSpec) -> u64 {
        let base = spec.base;
        image.write(base, b"MZ");
        image.put_u32(base + 0x3C, NT_OFFSET as u32);
        let nt = base + NT_OFFSET;
        image.write(nt, b"PE\0\0");
        let file_header = nt + 4;
        image.put_u16(file_header, 0x8664);
        image.put_u16(file_header + 2, spec.sections.len() as u16);
        image.put_u16(file_header + 16, OPTIONAL_SIZE);
        let optional = file_header + 20;
        image.put_u16(optional, 0x020B);
        image.put_u64(optional + 0x18, spec.image_base);
        image.put_u32(optional + 0x20, spec.section_alignment);
        image.put_u32(optional + 0x24, spec.file_alignment);
        image.put_u32(optional + 0x38, spec.size_of_image);
        image.put_u32(optional + 0x3C, spec.size_of_headers);
        image.put_u32(optional + 0x6C, 16);
        for (index, rva, size) in &spec.directories {
            let at = optional + 0x70 + (*index as u64) * 8;
            image.put_u32(at, *rva);
            image.put_u32(at + 4, *size);
        }
        let table = optional + u64::from(OPTIONAL_SIZE);
        for (index, section) in spec.sections.iter().enumerate() {
            let at = table + (index as u64) * SECTION_HEADER_BYTES;
            let mut name = [0u8; 8];
            let bytes = section.name.as_bytes();
            let take = bytes.len().min(8);
            name[..take].copy_from_slice(&bytes[..take]);
            image.write(at, &name);
            image.put_u32(at + 8, section.virtual_size);
            image.put_u32(at + 12, section.virtual_address);
            image.put_u32(at + 16, section.size_of_raw_data);
            image.put_u32(at + 20, section.pointer_to_raw_data);
        }
        table
    }

    /// The importing image every PE test uses: two sections, headers of 0x400.
    fn simple_pe(base: u64) -> PeSpec {
        PeSpec {
            base,
            size_of_image: 0x3000,
            size_of_headers: 0x400,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            image_base: 0x1_4000_0000,
            sections: vec![
                SectionSpec {
                    name: ".text",
                    virtual_size: 0x120,
                    virtual_address: 0x1000,
                    size_of_raw_data: 0x200,
                    pointer_to_raw_data: 0x400,
                },
                SectionSpec {
                    name: ".data",
                    virtual_size: 0x80,
                    virtual_address: 0x2000,
                    size_of_raw_data: 0x200,
                    pointer_to_raw_data: 0x600,
                },
            ],
            directories: Vec::new(),
        }
    }

    /// Where every PE fixture is loaded.
    const PE_BASE: u64 = 0x8000;

    /// Fill a run of the image with a byte, so a test can say which section a
    /// byte of the reconstruction came from.
    fn fill(image: &mut Image, address: u64, length: u64, byte: u8) {
        let run = vec![byte; length as usize];
        image.write(address, &run);
    }

    fn pe_image(spec: &PeSpec) -> Image {
        let mut image = Image::new();
        put_pe(&mut image, spec);
        image
    }

    // ── pedump ──────────────────────────────────────────────────────────────

    #[test]
    fn the_headers_come_out_of_the_image_rather_than_out_of_a_constant() {
        let spec = simple_pe(PE_BASE);
        let layer = dense_layer(pe_image(&spec));
        let headers = read_pe_headers(layer.as_ref(), PE_BASE).expect("a readable PE");
        assert!(headers.pe32_plus);
        assert_eq!(headers.machine, 0x8664);
        assert_eq!(headers.size_of_image, 0x3000);
        assert_eq!(headers.section_alignment, 0x1000);
        assert_eq!(headers.file_alignment, 0x200);
        assert_eq!(headers.sections.len(), 2);
        assert_eq!(headers.sections[0].name, ".text");
        assert_eq!(headers.sections[1].virtual_address, 0x2000);
        assert_eq!(headers.image_base, 0x1_4000_0000);
        assert!(
            !headers.loaded_at_preferred_base(),
            "the fixture is loaded away from its linked base, as a relocated DLL is"
        );
    }

    #[test]
    fn an_image_without_the_pe_signature_is_refused_by_name() {
        let mut image = Image::new();
        image.write(PE_BASE, b"MZ");
        image.put_u32(PE_BASE + 0x3C, NT_OFFSET as u32);
        // No 'PE\0\0' at e_lfanew.
        let layer = dense_layer(image);
        let err = read_pe_headers(layer.as_ref(), PE_BASE).expect_err("not a PE");
        assert_eq!(err.class(), "not_pe");
        assert!(err.to_string().contains("PE"), "{err}");
    }

    #[test]
    fn bytes_that_are_not_an_image_at_all_are_refused_before_anything_is_extracted() {
        let layer = dense_layer(Image::new());
        let err = read_pe_headers(layer.as_ref(), PE_BASE).expect_err("not a PE");
        assert!(err.to_string().contains("MZ"), "{err}");
    }

    #[test]
    fn a_section_that_claims_more_than_the_whole_image_is_refused() {
        let mut spec = simple_pe(PE_BASE);
        spec.sections[1].size_of_raw_data = 0x9000;
        let layer = dense_layer(pe_image(&spec));
        let err = read_pe_headers(layer.as_ref(), PE_BASE).expect_err("a malformed section table");
        assert_eq!(err.class(), "not_pe");
        assert!(err.to_string().contains("SizeOfRawData"), "{err}");
    }

    #[test]
    fn a_file_aligned_dump_puts_each_section_at_its_pointer_to_raw_data() {
        let spec = simple_pe(PE_BASE);
        let mut image = pe_image(&spec);
        fill(&mut image, PE_BASE + 0x1000, 0x200, 0xAA);
        fill(&mut image, PE_BASE + 0x2000, 0x200, 0xBB);
        let layer = dense_layer(image);

        let dump = dump_pe(layer.as_ref(), PE_BASE, &PeDumpConfig::default())
            .expect("a reconstructable image");
        assert_eq!(dump.layout, PeLayout::FileAligned);
        assert_eq!(dump.extract.length, 0x800, "the file ends after .data");
        assert_eq!(dump.extract.bytes_at(0, 2), Some(&b"MZ"[..]));
        assert_eq!(dump.extract.bytes_at(0x400, 1), Some(&[0xAAu8][..]));
        assert_eq!(dump.extract.bytes_at(0x600, 1), Some(&[0xBBu8][..]));
        assert!(dump.patches.is_empty(), "nothing was rewritten");
        assert!(dump.is_faithful());
    }

    #[test]
    fn file_alignment_padding_between_sections_is_a_gap_and_not_zeroes() {
        // The bytes between the end of the headers and the first section exist
        // only in the on-disk file. Writing the zeroes they almost certainly
        // held would make the artifact hash as a file we never saw.
        let mut spec = simple_pe(PE_BASE);
        spec.size_of_headers = 0x200;
        let layer = dense_layer(pe_image(&spec));
        let dump = dump_pe(layer.as_ref(), PE_BASE, &PeDumpConfig::default())
            .expect("a reconstructable image");
        let pad = dump
            .extract
            .gaps
            .iter()
            .find(|gap| gap.offset == 0x200)
            .expect("the padding before .text is declared");
        assert_eq!(pad.length, 0x200);
        assert_eq!(pad.reason, GapReason::NotInMemory);
        assert!(!dump.extract.is_complete());
    }

    #[test]
    fn file_bytes_a_section_claims_beyond_what_the_loader_maps_are_a_gap() {
        // A section whose SizeOfRawData exceeds its aligned VirtualSize has file
        // bytes that were never in memory. Reading them anyway would take the
        // *next* section's bytes and file them under this one.
        let mut spec = simple_pe(PE_BASE);
        spec.sections[1].size_of_raw_data = 0x2000;
        spec.sections[1].virtual_size = 0x80;
        let layer = dense_layer(pe_image(&spec));
        let dump = dump_pe(layer.as_ref(), PE_BASE, &PeDumpConfig::default())
            .expect("a reconstructable image");
        assert_eq!(dump.extract.length, 0x2600);
        let tail = dump
            .extract
            .gaps
            .iter()
            .find(|gap| gap.offset == 0x600 + 0x1000)
            .expect("the unmapped tail of .data is declared");
        assert_eq!(tail.length, 0x1000);
        assert_eq!(tail.reason, GapReason::NotInMemory);
    }

    #[test]
    fn sections_that_overlap_in_the_file_are_not_written_over_one_another() {
        let mut spec = simple_pe(PE_BASE);
        spec.sections[1].pointer_to_raw_data = 0x500;
        let layer = dense_layer(pe_image(&spec));
        let dump = dump_pe(layer.as_ref(), PE_BASE, &PeDumpConfig::default())
            .expect("a reconstructable image");
        assert!(
            dump.extract
                .notes
                .iter()
                .any(|note| note.contains("overlap")),
            "an overlap must be said out loud rather than resolved silently: {:?}",
            dump.extract.notes
        );
        assert_eq!(dump.extract.length, 0x600, "only .text was placed");
    }

    #[test]
    fn a_memory_aligned_dump_rewrites_the_section_table_and_records_every_change() {
        let spec = simple_pe(PE_BASE);
        let mut image = pe_image(&spec);
        fill(&mut image, PE_BASE + 0x1000, 0x200, 0xAA);
        let layer = dense_layer(image);
        let config = PeDumpConfig {
            layout: PeLayout::MemoryAligned,
            ..PeDumpConfig::default()
        };
        let dump = dump_pe(layer.as_ref(), PE_BASE, &config).expect("a reconstructable image");

        assert_eq!(dump.extract.length, 0x3000);
        assert_eq!(dump.patches.len(), 4, "two fields per section");
        assert!(dump.patches.iter().all(|patch| patch.applied));
        assert!(
            !dump.is_faithful(),
            "an artifact with rewritten fields is not what the evidence held"
        );

        let text = &dump.headers.sections[0];
        let pointer = text.header_offset + SECTION_POINTER_TO_RAW_DATA as u64;
        let size = text.header_offset + SECTION_SIZE_OF_RAW_DATA as u64;
        assert_eq!(
            dump.extract.bytes_at(pointer, 4),
            Some(&0x1000u32.to_le_bytes()[..]),
            "PointerToRawData now names where the section really is"
        );
        assert_eq!(
            dump.extract.bytes_at(size, 4),
            Some(&0x1000u32.to_le_bytes()[..]),
            "SizeOfRawData is the section-aligned virtual size"
        );
        assert!(dump
            .incomplete()
            .iter()
            .any(|note| note.detail.contains("rewritten")));
    }

    #[test]
    fn the_image_base_is_left_as_acquired_unless_the_caller_asks_for_the_rewrite() {
        let spec = simple_pe(PE_BASE);
        let layer = dense_layer(pe_image(&spec));
        let offset = NT_OFFSET + OPTIONAL_HEADER_OFFSET + OPT64_IMAGE_BASE as u64;

        let untouched = dump_pe(layer.as_ref(), PE_BASE, &PeDumpConfig::default())
            .expect("a reconstructable image");
        assert_eq!(
            untouched.extract.bytes_at(offset, 8),
            Some(&0x1_4000_0000u64.to_le_bytes()[..]),
            "by default the acquired ImageBase survives into the artifact"
        );

        let rewriting = PeDumpConfig {
            rewrite_image_base: true,
            ..PeDumpConfig::default()
        };
        let patched =
            dump_pe(layer.as_ref(), PE_BASE, &rewriting).expect("a reconstructable image");
        assert_eq!(
            patched.extract.bytes_at(offset, 8),
            Some(&PE_BASE.to_le_bytes()[..])
        );
        let record = patched
            .patches
            .iter()
            .find(|patch| patch.field.contains("ImageBase"))
            .expect("the rewrite is recorded");
        assert!(record.applied);
        assert_eq!(record.was, 0x1_4000_0000u64.to_le_bytes().to_vec());
    }

    #[test]
    fn a_reconstruction_larger_than_its_cap_is_refused() {
        let spec = simple_pe(PE_BASE);
        let layer = dense_layer(pe_image(&spec));
        let config = PeDumpConfig {
            max_image_bytes: 0x100,
            ..PeDumpConfig::default()
        };
        let err = dump_pe(layer.as_ref(), PE_BASE, &config).expect_err("above the cap");
        assert_eq!(err.class(), "too_large");
    }

    #[test]
    fn a_size_of_image_beyond_what_a_pe_can_be_is_refused_before_allocating_for_it() {
        let mut spec = simple_pe(PE_BASE);
        spec.size_of_image = u32::MAX;
        let layer = dense_layer(pe_image(&spec));
        let err = read_pe_headers(layer.as_ref(), PE_BASE).expect_err("above the format's cap");
        assert_eq!(err.class(), "too_large");
    }

    #[test]
    fn an_image_that_claims_to_occupy_no_memory_is_refused_rather_than_dumped_as_complete() {
        // The failure this prevents: a memory-aligned reconstruction of a
        // zero-`SizeOfImage` header is a zero-length artifact with no gaps,
        // which reports itself as a complete and faithful copy of the image.
        // A hash of nothing must never be offered as the hash of a module.
        let mut spec = simple_pe(PE_BASE);
        spec.size_of_image = 0;
        spec.sections.clear();
        let layer = dense_layer(pe_image(&spec));
        let err = read_pe_headers(layer.as_ref(), PE_BASE)
            .expect_err("an image that occupies no memory was never loaded");
        assert_eq!(err.class(), "not_pe");
        assert!(err.to_string().contains("SizeOfImage"), "{err}");
    }

    // ── Imports and exports ─────────────────────────────────────────────────

    /// Where the exporting module in the import fixtures is loaded.
    const EXPORT_BASE: u64 = 0xC000;
    /// RVA of the import directory in the importing image.
    const IMPORT_DIR_RVA: u32 = 0x2000;
    /// RVA of the export directory in the exporting module.
    const EXPORT_DIR_RVA: u32 = 0x1000;
    /// Size of that export directory, which is what makes an RVA inside it a
    /// forwarder rather than code.
    const EXPORT_DIR_SIZE: u32 = 0x400;
    /// RVA the exported function really lives at.
    const EXPORT_FUNCTION_RVA: u32 = 0x1500;
    /// RVA of the forwarder string, inside the export directory's own range.
    const EXPORT_FORWARDER_RVA: u32 = 0x1300;

    /// What the exporting module's single export looks like.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ExportShape {
        /// An ordinary export at [`EXPORT_FUNCTION_RVA`].
        Direct,
        /// A forwarder to another module.
        Forwarder,
        /// An export under a name nothing imports.
        OtherName,
    }

    /// Build an image that imports one function and a module that exports it.
    fn import_fixture(shape: ExportShape, iat_value: u64, by_ordinal: bool) -> Image {
        let mut spec = simple_pe(PE_BASE);
        spec.directories
            .push((DIRECTORY_ENTRY_IMPORT, IMPORT_DIR_RVA, 0x100));
        let mut image = pe_image(&spec);

        // One descriptor, then the all-zero terminator the format requires.
        let descriptor = PE_BASE + u64::from(IMPORT_DIR_RVA);
        image.put_u32(descriptor, 0x2100); // OriginalFirstThunk
        image.put_u32(descriptor + 4, 0); // TimeDateStamp: not pre-bound
        image.put_u32(descriptor + 12, 0x2200); // Name
        image.put_u32(descriptor + 16, 0x2300); // FirstThunk

        let name_entry: u64 = if by_ordinal { (1u64 << 63) | 1 } else { 0x2400 };
        image.put_u64(PE_BASE + 0x2100, name_entry);
        image.put_u64(PE_BASE + 0x2108, 0);
        image.write(PE_BASE + 0x2200, b"test.dll\0");
        image.put_u64(PE_BASE + 0x2300, iat_value);
        image.put_u16(PE_BASE + 0x2400, 0); // the hint
        image.write(PE_BASE + 0x2402, b"DoWork\0");

        // The exporting module.
        let mut exporter = PeSpec {
            base: EXPORT_BASE,
            size_of_image: 0x2000,
            size_of_headers: 0x400,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            image_base: EXPORT_BASE,
            sections: vec![SectionSpec {
                name: ".text",
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                size_of_raw_data: 0x200,
                pointer_to_raw_data: 0x400,
            }],
            directories: Vec::new(),
        };
        exporter
            .directories
            .push((DIRECTORY_ENTRY_EXPORT, EXPORT_DIR_RVA, EXPORT_DIR_SIZE));
        put_pe(&mut image, &exporter);

        let directory = EXPORT_BASE + u64::from(EXPORT_DIR_RVA);
        image.put_u32(directory + 16, 1); // Base: ordinals start at 1
        image.put_u32(directory + 20, 1); // NumberOfFunctions
        image.put_u32(directory + 24, 1); // NumberOfNames
        image.put_u32(directory + 28, 0x1100); // AddressOfFunctions
        image.put_u32(directory + 32, 0x1180); // AddressOfNames
        image.put_u32(directory + 36, 0x1190); // AddressOfNameOrdinals

        let function_rva = match shape {
            ExportShape::Forwarder => EXPORT_FORWARDER_RVA,
            _ => EXPORT_FUNCTION_RVA,
        };
        image.put_u32(EXPORT_BASE + 0x1100, function_rva);
        image.put_u32(EXPORT_BASE + 0x1180, 0x11A0);
        image.put_u16(EXPORT_BASE + 0x1190, 0);
        let exported_name: &[u8] = match shape {
            ExportShape::OtherName => b"SomethingElse\0",
            _ => b"DoWork\0",
        };
        image.write(EXPORT_BASE + 0x11A0, exported_name);
        if shape == ExportShape::Forwarder {
            image.write(
                EXPORT_BASE + u64::from(EXPORT_FORWARDER_RVA),
                b"other.dll.Thing\0",
            );
        }
        image
    }

    /// The address the export really occupies once loaded.
    const EXPORT_ADDRESS: u64 = EXPORT_BASE + EXPORT_FUNCTION_RVA as u64;

    fn loaded_modules() -> ModuleMap {
        let mut modules = ModuleMap::new();
        modules.insert("C:\\Windows\\System32\\TEST.DLL", EXPORT_BASE);
        modules
    }

    fn imports_of(image: Image, modules: &ModuleMap) -> ImportTable {
        let layer = dense_layer(image);
        let headers = read_pe_headers(layer.as_ref(), PE_BASE).expect("a readable PE");
        read_imports(layer.as_ref(), &headers, modules, &ImportConfig::default())
            .expect("a runnable import walk")
    }

    #[test]
    fn a_module_map_matches_on_the_base_name_whatever_case_the_path_used() {
        let modules = loaded_modules();
        assert_eq!(modules.base_of("test.dll"), Some(EXPORT_BASE));
        assert_eq!(modules.base_of("TEST.DLL"), Some(EXPORT_BASE));
        assert_eq!(modules.base_of("kernel32.dll"), None);
        assert_eq!(modules.len(), 1);
    }

    #[test]
    fn an_import_whose_slot_holds_the_export_address_matches() {
        let table = imports_of(
            import_fixture(ExportShape::Direct, EXPORT_ADDRESS, false),
            &loaded_modules(),
        );
        assert_eq!(table.imports.len(), 1);
        let import = &table.imports[0];
        assert_eq!(import.library.name(), Some("test.dll"));
        assert_eq!(import.name, ImportName::Named("DoWork".to_string()));
        assert_eq!(import.target, Some(EXPORT_ADDRESS));
        assert_eq!(import.verdict, ImportVerdict::Matches);
        assert!(table.hooks().is_empty());
        assert_eq!(table.checked(), 1);
    }

    #[test]
    fn an_import_diverted_elsewhere_is_a_hook_and_says_where_it_should_have_pointed() {
        let table = imports_of(
            import_fixture(ExportShape::Direct, 0x1_9000, false),
            &loaded_modules(),
        );
        let import = &table.imports[0];
        assert_eq!(
            import.verdict,
            ImportVerdict::Diverted {
                expected: EXPORT_ADDRESS
            }
        );
        assert!(import.verdict.is_hook());
        assert_eq!(table.hooks().len(), 1);
    }

    #[test]
    fn an_import_from_a_module_that_is_not_loaded_is_unresolved_and_not_a_hook() {
        // The failure this prevents: reporting every import of a process whose
        // module list was not supplied as a hook.
        let table = imports_of(
            import_fixture(ExportShape::Direct, 0x1_9000, false),
            &ModuleMap::new(),
        );
        let import = &table.imports[0];
        assert_eq!(import.verdict, ImportVerdict::ModuleNotLoaded);
        assert!(!import.verdict.is_hook());
        assert!(!import.verdict.was_checked());
        assert_eq!(table.checked(), 0);
        assert!(
            table
                .incomplete()
                .iter()
                .any(|note| note.detail.contains("could not be compared")),
            "a report must not read as clean when nothing was checked"
        );
    }

    #[test]
    fn a_forwarded_export_is_not_reported_as_a_hook() {
        // `kernel32!HeapAlloc` forwards to `ntdll`. A check that did not know
        // this would report a hook in every process on the machine.
        let table = imports_of(
            import_fixture(ExportShape::Forwarder, 0x1_9000, false),
            &loaded_modules(),
        );
        let import = &table.imports[0];
        assert_eq!(
            import.verdict,
            ImportVerdict::Forwarded {
                target: "other.dll.Thing".to_string()
            }
        );
        assert!(!import.verdict.is_hook());
        assert!(import.verdict.was_checked());
    }

    #[test]
    fn an_import_the_module_does_not_export_is_reported_as_missing_not_as_a_hook() {
        let table = imports_of(
            import_fixture(ExportShape::OtherName, 0x1_9000, false),
            &loaded_modules(),
        );
        assert_eq!(table.imports[0].verdict, ImportVerdict::ExportMissing);
        assert!(!table.imports[0].verdict.is_hook());
    }

    #[test]
    fn an_import_the_loader_had_not_bound_is_reported_as_unbound() {
        // Before binding, the address table is a copy of the name table.
        // Reporting that as a diversion would flag every image caught during
        // creation.
        let table = imports_of(
            import_fixture(ExportShape::Direct, 0x2400, false),
            &loaded_modules(),
        );
        assert_eq!(table.imports[0].verdict, ImportVerdict::Unbound);
        assert!(!table.imports[0].verdict.is_hook());
    }

    #[test]
    fn an_ordinal_import_resolves_through_the_export_tables_ordinal_base() {
        // Ordinal 1 of a table whose Base is 1 is function index 0. Forgetting
        // the subtraction shifts every ordinal import by one function.
        let table = imports_of(
            import_fixture(ExportShape::Direct, EXPORT_ADDRESS, true),
            &loaded_modules(),
        );
        let import = &table.imports[0];
        assert_eq!(import.name, ImportName::Ordinal(1));
        assert_eq!(import.verdict, ImportVerdict::Matches);
    }

    #[test]
    fn the_export_table_reads_its_ordinal_base_and_its_names_out_of_the_module() {
        let image = import_fixture(ExportShape::Direct, EXPORT_ADDRESS, false);
        let layer = dense_layer(image);
        let headers = read_pe_headers(layer.as_ref(), EXPORT_BASE).expect("a readable module");
        let exports =
            read_exports(layer.as_ref(), &headers, &ImportConfig::default()).expect("readable");
        assert_eq!(exports.ordinal_base, 1);
        assert_eq!(exports.functions.len(), 1);
        assert_eq!(
            exports.by_name("DoWork").map(|target| target.rva),
            Some(EXPORT_FUNCTION_RVA)
        );
        assert_eq!(
            exports.by_ordinal(1).map(|target| target.rva),
            Some(EXPORT_FUNCTION_RVA)
        );
        assert!(
            exports.by_ordinal(0).is_none(),
            "ordinal 0 is below this table's base and names no function"
        );
        assert!(!exports.truncated);
    }

    #[test]
    fn an_image_that_imports_nothing_is_an_empty_table_and_not_a_failure() {
        let spec = simple_pe(PE_BASE);
        let layer = dense_layer(pe_image(&spec));
        let headers = read_pe_headers(layer.as_ref(), PE_BASE).expect("a readable PE");
        let table = read_imports(
            layer.as_ref(),
            &headers,
            &loaded_modules(),
            &ImportConfig::default(),
        )
        .expect("a runnable walk");
        assert!(table.imports.is_empty());
        assert!(table.stop.is_complete());
        assert!(table
            .notes
            .iter()
            .any(|note| note.contains("imports nothing")));
    }

    #[test]
    fn the_import_walk_stops_at_its_cap_and_says_so_rather_than_appearing_to_end() {
        let image = import_fixture(ExportShape::Direct, EXPORT_ADDRESS, false);
        let layer = dense_layer(image);
        let headers = read_pe_headers(layer.as_ref(), PE_BASE).expect("a readable PE");
        let config = ImportConfig {
            max_imports: 0,
            ..ImportConfig::default()
        };
        let table = read_imports(layer.as_ref(), &headers, &loaded_modules(), &config)
            .expect("a runnable walk");
        assert!(table.imports.is_empty());
        assert!(!table.stop.is_complete());
        assert!(table
            .incomplete()
            .iter()
            .any(|note| note.reason == IncompleteReason::CapReached));
    }

    #[test]
    fn the_library_cap_is_reported_even_when_the_last_descriptor_named_no_thunk_table() {
        // A descriptor with neither a name table nor an address table takes the
        // path that skips straight to the next library. If the cap were only
        // checked after the thunk loop, a truncated library list would come
        // back reporting itself as the whole list, and every import of every
        // library past it would be neither examined nor declared unexamined.
        let mut spec = simple_pe(PE_BASE);
        spec.directories
            .push((DIRECTORY_ENTRY_IMPORT, IMPORT_DIR_RVA, 0x100));
        let mut image = pe_image(&spec);
        let descriptor = PE_BASE + u64::from(IMPORT_DIR_RVA);
        // Neither OriginalFirstThunk nor FirstThunk, so the descriptor names no
        // imports at all — and no null terminator follows it either.
        image.put_u32(descriptor + 12, 0x2200);
        image.write(PE_BASE + 0x2200, b"test.dll\0");
        image.put_u32(descriptor + IMPORT_DESCRIPTOR_BYTES + 12, 0x2200);

        let layer = dense_layer(image);
        let headers = read_pe_headers(layer.as_ref(), PE_BASE).expect("a readable PE");
        let config = ImportConfig {
            max_libraries: 1,
            ..ImportConfig::default()
        };
        let table = read_imports(layer.as_ref(), &headers, &loaded_modules(), &config)
            .expect("a runnable walk");

        assert_eq!(table.libraries.len(), 1);
        assert!(
            !table.stop.is_complete(),
            "the descriptor array had not terminated: {:?}",
            table.stop
        );
        assert!(table
            .incomplete()
            .iter()
            .any(|note| note.reason == IncompleteReason::CapReached));
    }

    // ── dumpfiles fixtures ──────────────────────────────────────────────────

    const FILE_OBJECT_AT: u64 = 0x1000;
    const SECTION_POINTERS_AT: u64 = 0x1100;
    const DEVICE_OBJECT_AT: u64 = 0x1200;
    const FILE_NAME_AT: u64 = 0x1300;
    const CONTROL_AREA_AT: u64 = 0x2000;
    const SEGMENT_AT: u64 = 0x2200;
    const PTE_ARRAY_AT: u64 = 0x2400;
    const SECOND_SUBSECTION_AT: u64 = 0x2600;
    const SCM_AT: u64 = 0x3000;
    const VACB_AT: u64 = 0x3100;
    const VACB_TWO_AT: u64 = 0x3200;
    /// Physical frames the prototype PTEs name.
    const FRAME_ONE: u64 = 0x1_0000;
    const FRAME_TWO: u64 = 0x1_1000;
    /// Where a cache-manager view is mapped in kernel space.
    const VIEW_AT: u64 = 0x1_4000;
    /// Size of `_CONTROL_AREA` in the fixture ISF, and so where the first
    /// `_SUBSECTION` sits.
    const CONTROL_AREA_SIZE: u64 = 64;

    /// A synthetic 64-bit ISF describing everything a cached file hangs off.
    fn cache_isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "EE1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}
  },
  "base_types": "#,
            crate::image_fixture::BASE_TYPES_X64,
            r#",
  "user_types": {
    "_LARGE_INTEGER": {"size": 8, "kind": "union", "fields": {
      "QuadPart": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_UNICODE_STRING": {"size": 16, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 8, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_DEVICE_OBJECT": {"size": 16, "kind": "struct", "fields": {
      "DeviceType": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_SECTION_OBJECT_POINTERS": {"size": 24, "kind": "struct", "fields": {
      "DataSectionObject": {"offset": 0, "type": {"kind": "pointer",
                            "subtype": {"kind": "struct", "name": "_CONTROL_AREA"}}},
      "SharedCacheMap": {"offset": 8, "type": {"kind": "pointer",
                         "subtype": {"kind": "struct", "name": "_SHARED_CACHE_MAP"}}},
      "ImageSectionObject": {"offset": 16, "type": {"kind": "pointer",
                             "subtype": {"kind": "struct", "name": "_CONTROL_AREA"}}}
    }},
    "_FILE_OBJECT": {"size": 64, "kind": "struct", "fields": {
      "DeviceObject": {"offset": 8, "type": {"kind": "pointer",
                       "subtype": {"kind": "struct", "name": "_DEVICE_OBJECT"}}},
      "SectionObjectPointer": {"offset": 16, "type": {"kind": "pointer",
                               "subtype": {"kind": "struct",
                                           "name": "_SECTION_OBJECT_POINTERS"}}},
      "FileName": {"offset": 24, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_SEGMENT": {"size": 32, "kind": "struct", "fields": {
      "ControlArea": {"offset": 0, "type": {"kind": "pointer",
                      "subtype": {"kind": "struct", "name": "_CONTROL_AREA"}}},
      "TotalNumberOfPtes": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}},
      "SizeOfSegment": {"offset": 16, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_MMSECTION_FLAGS": {"size": 4, "kind": "struct", "fields": {
      "Image": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 5, "bit_length": 1,
                "type": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_CONTROL_AREA_U": {"size": 4, "kind": "union", "fields": {
      "Flags": {"offset": 0, "type": {"kind": "struct", "name": "_MMSECTION_FLAGS"}}
    }},
    "_CONTROL_AREA": {"size": 64, "kind": "struct", "fields": {
      "Segment": {"offset": 0, "type": {"kind": "pointer",
                  "subtype": {"kind": "struct", "name": "_SEGMENT"}}},
      "u": {"offset": 8, "type": {"kind": "union", "name": "_CONTROL_AREA_U"}}
    }},
    "_MMPTE_HARDWARE": {"size": 8, "kind": "struct", "fields": {
      "Valid": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0, "bit_length": 1,
                "type": {"kind": "base", "name": "unsigned long long"}}},
      "PageFrameNumber": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 12,
                          "bit_length": 36,
                          "type": {"kind": "base", "name": "unsigned long long"}}}
    }},
    "_MMPTE_TRANSITION": {"size": 8, "kind": "struct", "fields": {
      "Valid": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0, "bit_length": 1,
                "type": {"kind": "base", "name": "unsigned long long"}}},
      "Transition": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 11,
                     "bit_length": 1,
                     "type": {"kind": "base", "name": "unsigned long long"}}},
      "PageFrameNumber": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 12,
                          "bit_length": 36,
                          "type": {"kind": "base", "name": "unsigned long long"}}}
    }},
    "_MMPTE_SOFTWARE": {"size": 8, "kind": "struct", "fields": {
      "Valid": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0, "bit_length": 1,
                "type": {"kind": "base", "name": "unsigned long long"}}},
      "Prototype": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 10,
                    "bit_length": 1,
                    "type": {"kind": "base", "name": "unsigned long long"}}}
    }},
    "_MMPTE_U": {"size": 8, "kind": "union", "fields": {
      "Hard": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_HARDWARE"}},
      "Trans": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_TRANSITION"}},
      "Soft": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_SOFTWARE"}}
    }},
    "_MMPTE": {"size": 8, "kind": "struct", "fields": {
      "u": {"offset": 0, "type": {"kind": "union", "name": "_MMPTE_U"}}
    }},
    "_SUBSECTION": {"size": 48, "kind": "struct", "fields": {
      "ControlArea": {"offset": 0, "type": {"kind": "pointer",
                      "subtype": {"kind": "struct", "name": "_CONTROL_AREA"}}},
      "SubsectionBase": {"offset": 8, "type": {"kind": "pointer",
                         "subtype": {"kind": "struct", "name": "_MMPTE"}}},
      "NextSubsection": {"offset": 16, "type": {"kind": "pointer",
                         "subtype": {"kind": "struct", "name": "_SUBSECTION"}}},
      "PtesInSubsection": {"offset": 24, "type": {"kind": "base", "name": "unsigned long"}},
      "StartingSector": {"offset": 28, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_VACB_OVERLAY": {"size": 8, "kind": "union", "fields": {
      "FileOffset": {"offset": 0, "type": {"kind": "struct", "name": "_LARGE_INTEGER"}}
    }},
    "_VACB": {"size": 32, "kind": "struct", "fields": {
      "BaseAddress": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}},
      "SharedCacheMap": {"offset": 8, "type": {"kind": "pointer",
                         "subtype": {"kind": "struct", "name": "_SHARED_CACHE_MAP"}}},
      "Overlay": {"offset": 16, "type": {"kind": "union", "name": "_VACB_OVERLAY"}}
    }},
    "_SHARED_CACHE_MAP": {"size": 128, "kind": "struct", "fields": {
      "FileSize": {"offset": 0, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ValidDataLength": {"offset": 8, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "SectionSize": {"offset": 16, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "InitialVacbs": {"offset": 24, "type": {"kind": "array", "count": 4,
                       "subtype": {"kind": "pointer",
                                   "subtype": {"kind": "struct", "name": "_VACB"}}}},
      "Vacbs": {"offset": 56, "type": {"kind": "pointer",
                "subtype": {"kind": "base", "name": "unsigned long long"}}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#,
        ]
        .concat()
    }

    /// An ISF that describes a file object and neither of the two cache routes.
    fn cacheless_isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "FF1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}
  },
  "base_types": "#,
            crate::image_fixture::BASE_TYPES_X64,
            r#",
  "user_types": {
    "_SECTION_OBJECT_POINTERS": {"size": 24, "kind": "struct", "fields": {
      "DataSectionObject": {"offset": 0, "type": {"kind": "pointer",
                            "subtype": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_FILE_OBJECT": {"size": 64, "kind": "struct", "fields": {
      "SectionObjectPointer": {"offset": 16, "type": {"kind": "pointer",
                               "subtype": {"kind": "struct",
                                           "name": "_SECTION_OBJECT_POINTERS"}}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#,
        ]
        .concat()
    }

    fn cache_profile(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&cache_isf()),
            Architecture::X64,
            10,
            0,
            Some(19041),
        )
    }

    /// A valid hardware prototype PTE naming a frame.
    fn valid_pte(frame: u64) -> u64 {
        (frame << 12) | 1
    }

    /// A transition prototype PTE: not valid to the hardware, and its frame
    /// still holds the page's bytes.
    fn transition_pte(frame: u64) -> u64 {
        (frame << 12) | (1 << 11)
    }

    /// A software prototype PTE for a page that is simply not resident.
    fn absent_pte() -> u64 {
        1 << 10
    }

    /// Write the file object and its three cache pointers.
    fn put_file_object(image: &mut Image, data_section: u64, shared_cache_map: u64) {
        image.put_u64(FILE_OBJECT_AT + 8, DEVICE_OBJECT_AT);
        image.put_u64(FILE_OBJECT_AT + 16, SECTION_POINTERS_AT);
        image.put_u16(FILE_OBJECT_AT + 24, 8);
        image.put_u16(FILE_OBJECT_AT + 26, 8);
        image.put_u64(FILE_OBJECT_AT + 32, FILE_NAME_AT);
        image.put_utf16(FILE_NAME_AT, "note");
        image.put_u32(DEVICE_OBJECT_AT, FILE_DEVICE_DISK as u32);
        image.put_u64(SECTION_POINTERS_AT, data_section);
        image.put_u64(SECTION_POINTERS_AT + 8, shared_cache_map);
    }

    /// Write a control area, its segment and one subsection of three prototype
    /// PTEs: resident, absent, in transition.
    fn put_control_area(image: &mut Image, is_image: bool, starting_sector: u32) {
        image.put_u64(CONTROL_AREA_AT, SEGMENT_AT);
        image.put_u32(CONTROL_AREA_AT + 8, if is_image { 1 << 5 } else { 0 });
        image.put_u64(SEGMENT_AT, CONTROL_AREA_AT);
        image.put_u32(SEGMENT_AT + 8, 3);
        image.put_u64(SEGMENT_AT + 16, 3 * PAGE_SIZE);

        let subsection = CONTROL_AREA_AT + CONTROL_AREA_SIZE;
        image.put_u64(subsection, CONTROL_AREA_AT);
        image.put_u64(subsection + 8, PTE_ARRAY_AT);
        image.put_u64(subsection + 16, 0);
        image.put_u32(subsection + 24, 3);
        image.put_u32(subsection + 28, starting_sector);

        image.put_u64(PTE_ARRAY_AT, valid_pte(FRAME_ONE / PAGE_SIZE));
        image.put_u64(PTE_ARRAY_AT + 8, absent_pte());
        image.put_u64(PTE_ARRAY_AT + 16, transition_pte(FRAME_TWO / PAGE_SIZE));

        let first = vec![0xC1u8; PAGE_SIZE as usize];
        let second = vec![0xC2u8; PAGE_SIZE as usize];
        image.write(FRAME_ONE, &first);
        image.write(FRAME_TWO, &second);
    }

    /// Write one cache-manager view of a file.
    fn put_vacb(image: &mut Image, at: u64, owner: u64, base_address: u64, raw_offset: u64) {
        image.put_u64(at, base_address);
        image.put_u64(at + 8, owner);
        image.put_u64(at + 16, raw_offset);
    }

    // ── DumpSymbols ─────────────────────────────────────────────────────────

    #[test]
    fn dump_symbols_resolves_both_routes_when_the_build_describes_them() {
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, SCM_AT);
        let profile = cache_profile(image);
        let symbols = DumpSymbols::from_profile(&profile).expect("a describable build");

        assert_eq!(symbols.file.section_object_pointers, "SectionObjectPointer");
        assert_eq!(
            symbols.file.data_section_object.as_deref(),
            Some("DataSectionObject")
        );
        let sections = symbols.require_sections().expect("this build has them");
        assert_eq!(sections.control_area_size, CONTROL_AREA_SIZE);
        assert_eq!(sections.mmpte_size, 8);
        assert_eq!(sections.pte_valid, "u.Hard.Valid");
        assert!(sections.segment.is_some(), "the self-check is available");
        let cache = symbols.require_cache().expect("this build has them");
        assert_eq!(cache.initial_vacb_count, 4);
        assert_eq!(cache.pointer_size, 8);
        assert_eq!(cache.vacb_file_offset, "Overlay.FileOffset.QuadPart");
    }

    #[test]
    fn a_build_without_the_cache_structures_refuses_by_naming_them() {
        // The failure this prevents: a build whose symbols are missing a
        // structure producing an empty reconstruction that reads exactly like a
        // file with nothing cached.
        let image = Image::new();
        let profile = profile(
            image.layer(),
            table(&cacheless_isf()),
            Architecture::X64,
            10,
            0,
            Some(19041),
        );
        let symbols = DumpSymbols::from_profile(&profile).expect("the file object is describable");

        let sections = symbols
            .require_sections()
            .expect_err("this build describes no control area");
        assert_eq!(sections.class(), "unsupported_build");
        assert!(sections.to_string().contains("_CONTROL_AREA"), "{sections}");

        let cache = symbols
            .require_cache()
            .expect_err("this build describes no shared cache map");
        assert!(cache.to_string().contains("_SHARED_CACHE_MAP"), "{cache}");
    }

    #[test]
    fn a_build_without_a_file_object_cannot_reach_any_cache_at_all() {
        let image = Image::new();
        let profile = profile(
            image.layer(),
            table(&crate::poolscan::test_support::windows32_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        );
        let err = DumpSymbols::from_profile(&profile)
            .expect_err("without a file object nothing can be dumped");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("_FILE_OBJECT"), "{err}");
    }

    // ── The caches a file object has ────────────────────────────────────────

    #[test]
    fn a_file_objects_caches_are_listed_with_the_device_that_says_it_is_a_file() {
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, SCM_AT);
        let profile = cache_profile(image);
        let symbols = DumpSymbols::from_profile(&profile).expect("a describable build");
        let caches = file_object_caches(&profile, &symbols, FILE_OBJECT_AT).expect("readable");

        assert_eq!(caches.name.as_deref(), Some("note"));
        assert_eq!(caches.device_type, Some(FILE_DEVICE_DISK));
        assert_eq!(caches.is_file_backed, Some(true));
        assert_eq!(
            caches.address_of(FileCache::DataSection),
            Some(CONTROL_AREA_AT)
        );
        assert_eq!(caches.address_of(FileCache::SharedCacheMap), Some(SCM_AT));
        assert_eq!(
            caches.address_of(FileCache::ImageSection),
            None,
            "a null pointer is a cache that does not exist"
        );
    }

    #[test]
    fn a_device_that_is_not_a_disk_is_reported_rather_than_the_file_being_dropped() {
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, 0);
        // \Device\NamedPipe and \Device\Tcp use the File object type too.
        image.put_u32(DEVICE_OBJECT_AT, 0x11);
        let profile = cache_profile(image);
        let symbols = DumpSymbols::from_profile(&profile).expect("a describable build");
        let caches = file_object_caches(&profile, &symbols, FILE_OBJECT_AT).expect("readable");
        assert_eq!(caches.device_type, Some(0x11));
        assert_eq!(caches.is_file_backed, Some(false));
    }

    // ── The control-area route ──────────────────────────────────────────────

    fn control_area_map(image: Image) -> (WindowsProfile, DumpSymbols, FileCacheMap) {
        let profile = cache_profile(image);
        let symbols = DumpSymbols::from_profile(&profile).expect("a describable build");
        let map = file_cache_map(
            &profile,
            &symbols,
            FILE_OBJECT_AT,
            FileCache::DataSection,
            CONTROL_AREA_AT,
            &FileCacheConfig::default(),
        )
        .expect("a runnable walk");
        (profile, symbols, map)
    }

    #[test]
    fn a_resident_prototype_pte_names_the_frame_that_holds_that_page_of_the_file() {
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, 0);
        put_control_area(&mut image, false, 0);
        let (_, _, map) = control_area_map(image);

        assert_eq!(map.space, CacheSpace::Physical);
        assert_eq!(map.declared_size, Some(3 * PAGE_SIZE));
        assert_eq!(map.pages.len(), 2);
        assert_eq!(
            map.pages[0],
            CachedPage {
                file_offset: 0,
                source: FRAME_ONE,
                length: PAGE_SIZE,
            }
        );
        assert_eq!(
            map.pages[1],
            CachedPage {
                file_offset: 2 * PAGE_SIZE,
                source: FRAME_TWO,
                length: PAGE_SIZE,
            },
            "a transition entry still names the frame that holds the page"
        );
        assert_eq!(
            map.skipped_total, 1,
            "the absent page is counted, not filled"
        );
    }

    #[test]
    fn a_page_that_was_not_resident_is_a_gap_in_the_reconstructed_file_and_never_zeroes() {
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, 0);
        put_control_area(&mut image, false, 0);
        let (profile, _, map) = control_area_map(image);
        let extract =
            dump_file_cache(&profile, &map, &FileCacheConfig::default()).expect("a runnable dump");

        assert_eq!(extract.length, 3 * PAGE_SIZE);
        assert_eq!(extract.acquired_bytes, 2 * PAGE_SIZE);
        assert_eq!(extract.bytes_at(0, 1), Some(&[0xC1u8][..]));
        assert_eq!(
            extract.bytes_at(2 * PAGE_SIZE, 1),
            Some(&[0xC2u8][..]),
            "the third page of the file kept its own offset"
        );
        assert_eq!(extract.gap_total, 1);
        assert_eq!(extract.gaps[0].offset, PAGE_SIZE);
        assert_eq!(extract.gaps[0].length, PAGE_SIZE);
        assert_eq!(extract.gaps[0].reason, GapReason::NotInMemory);
        assert!(!extract.is_complete());
        assert!(extract.contiguous().is_none());
    }

    #[test]
    fn an_image_section_multiplies_the_starting_sector_by_the_disk_sector_size() {
        // An image section's subsections are sector-aligned and a data
        // section's are page-aligned. Using the wrong multiplier does not fail:
        // it places every page eight times too far into the file.
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, 0);
        put_control_area(&mut image, true, 8);
        let profile = cache_profile(image);
        let symbols = DumpSymbols::from_profile(&profile).expect("a describable build");
        let map = file_cache_map(
            &profile,
            &symbols,
            FILE_OBJECT_AT,
            FileCache::ImageSection,
            CONTROL_AREA_AT,
            &FileCacheConfig::default(),
        )
        .expect("a runnable walk");
        assert_eq!(
            map.pages[0].file_offset,
            8 * IMAGE_SECTOR_SIZE,
            "sector 8 of an image section is 0x1000 into the file"
        );
    }

    #[test]
    fn a_data_section_multiplies_the_starting_sector_by_the_page_size() {
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, 0);
        put_control_area(&mut image, false, 8);
        let (_, _, map) = control_area_map(image);
        assert_eq!(map.pages[0].file_offset, 8 * DATA_SECTOR_SIZE);
    }

    #[test]
    fn a_subsection_owned_by_another_control_area_ends_the_walk_rather_than_being_followed() {
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, 0);
        put_control_area(&mut image, false, 0);
        // A second subsection that belongs to somebody else. Following it would
        // file another file's pages under this one.
        let first = CONTROL_AREA_AT + CONTROL_AREA_SIZE;
        image.put_u64(first + 16, SECOND_SUBSECTION_AT);
        image.put_u64(SECOND_SUBSECTION_AT, CONTROL_AREA_AT + 0x1000);
        image.put_u64(SECOND_SUBSECTION_AT + 8, PTE_ARRAY_AT);
        image.put_u32(SECOND_SUBSECTION_AT + 24, 3);
        image.put_u32(SECOND_SUBSECTION_AT + 28, 0x40);

        let (_, _, map) = control_area_map(image);
        assert_eq!(map.pages.len(), 2, "only the first subsection's pages");
        assert!(
            map.notes.iter().any(|note| note.contains("belongs to")),
            "the walk must say why it stopped: {:?}",
            map.notes
        );
    }

    #[test]
    fn a_subsection_that_will_not_say_where_it_begins_is_skipped_rather_than_filed_at_offset_zero()
    {
        // The failure this prevents: an unreadable `StartingSector` defaulting
        // to sector 0 files every page of this subsection at the front of the
        // reconstruction, on top of the first subsection's, and the file that
        // comes out is plausible and wrong.
        //
        // The second subsection is placed so that its ControlArea,
        // SubsectionBase and PtesInSubsection are inside the image and its
        // StartingSector runs off the end of it.
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, 0);
        put_control_area(&mut image, false, 0);
        let truncated = crate::poolscan::test_support::IMAGE_SIZE as u64 - 28;
        let first = CONTROL_AREA_AT + CONTROL_AREA_SIZE;
        image.put_u64(first + 16, truncated);
        image.put_u64(truncated, CONTROL_AREA_AT);
        image.put_u64(truncated + 8, PTE_ARRAY_AT);
        image.put_u32(truncated + 24, 3);

        let (_, _, map) = control_area_map(image);
        assert_eq!(
            map.pages.len(),
            2,
            "only the first subsection's pages, and none of them displaced"
        );
        assert_eq!(map.pages[0].file_offset, 0);
        assert_eq!(map.pages[1].file_offset, 2 * PAGE_SIZE);
        assert!(
            map.notes
                .iter()
                .any(|note| note.contains("which sector of the file it begins at")),
            "the walk must name what it could not read: {:?}",
            map.notes
        );
        assert!(
            map.skipped_total > 1,
            "the unplaceable subsection is counted, not forgotten"
        );
        assert!(!map.is_complete());
    }

    #[test]
    fn a_control_area_whose_segment_does_not_point_back_is_refused() {
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, 0);
        put_control_area(&mut image, false, 0);
        image.put_u64(SEGMENT_AT, CONTROL_AREA_AT + 0x40);
        let profile = cache_profile(image);
        let symbols = DumpSymbols::from_profile(&profile).expect("a describable build");
        let err = file_cache_map(
            &profile,
            &symbols,
            FILE_OBJECT_AT,
            FileCache::DataSection,
            CONTROL_AREA_AT,
            &FileCacheConfig::default(),
        )
        .expect_err("these bytes are not a control area");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("self-consistent"), "{err}");
    }

    #[test]
    fn a_segment_whose_size_disagrees_with_its_page_count_is_refused() {
        let mut image = Image::new();
        put_file_object(&mut image, CONTROL_AREA_AT, 0);
        put_control_area(&mut image, false, 0);
        image.put_u64(SEGMENT_AT + 16, 3 * PAGE_SIZE + 1);
        let profile = cache_profile(image);
        let symbols = DumpSymbols::from_profile(&profile).expect("a describable build");
        let err = file_cache_map(
            &profile,
            &symbols,
            FILE_OBJECT_AT,
            FileCache::DataSection,
            CONTROL_AREA_AT,
            &FileCacheConfig::default(),
        )
        .expect_err("a segment must cover one page per prototype PTE");
        assert!(err.to_string().contains("per page"), "{err}");
    }

    // ── The shared-cache-map route ──────────────────────────────────────────

    /// A file whose whole 4 KiB is in one cache-manager view.
    fn scm_image(file_size: u64, section_size: u64) -> Image {
        let mut image = Image::new();
        put_file_object(&mut image, 0, SCM_AT);
        image.put_u64(SCM_AT, file_size);
        image.put_u64(SCM_AT + 8, file_size);
        image.put_u64(SCM_AT + 16, section_size);
        let view = vec![0xD1u8; PAGE_SIZE as usize];
        image.write(VIEW_AT, &view);
        image
    }

    fn scm_map(image: Image) -> (WindowsProfile, FileCacheMap) {
        let profile = cache_profile(image);
        let symbols = DumpSymbols::from_profile(&profile).expect("a describable build");
        let map = file_cache_map(
            &profile,
            &symbols,
            FILE_OBJECT_AT,
            FileCache::SharedCacheMap,
            SCM_AT,
            &FileCacheConfig::default(),
        )
        .expect("a runnable walk");
        (profile, map)
    }

    #[test]
    fn a_cache_manager_view_lands_at_the_file_offset_its_overlay_names() {
        let mut image = scm_image(PAGE_SIZE, PAGE_SIZE);
        image.put_u64(SCM_AT + 24, VACB_AT);
        put_vacb(&mut image, VACB_AT, SCM_AT, VIEW_AT, 0);
        let (profile, map) = scm_map(image);

        assert_eq!(map.space, CacheSpace::KernelVirtual);
        assert_eq!(map.declared_size, Some(PAGE_SIZE));
        assert_eq!(map.pages.len(), 1);
        assert_eq!(map.pages[0].source, VIEW_AT);
        assert_eq!(
            map.pages[0].length, PAGE_SIZE,
            "a 256 KiB view is clipped to the file it belongs to"
        );

        let extract =
            dump_file_cache(&profile, &map, &FileCacheConfig::default()).expect("a runnable dump");
        assert_eq!(extract.length, PAGE_SIZE);
        assert!(extract.is_complete());
        assert_eq!(extract.bytes_at(0, 1), Some(&[0xD1u8][..]));
    }

    #[test]
    fn the_reference_count_in_a_views_low_bits_is_not_part_of_its_file_offset() {
        // Every view is 256 KiB, so the cache manager keeps the view's
        // reference count in the low sixteen bits of its file offset. Using the
        // value unmasked puts the view up to 65535 bytes into the wrong place.
        const VIEW_OFFSET: u64 = 0x4_0000;
        let mut image = scm_image(VIEW_OFFSET + PAGE_SIZE, VIEW_OFFSET + PAGE_SIZE);
        // InitialVacbs[0] is null; the spill-over view is the second slot.
        image.put_u64(SCM_AT + 24 + 8, VACB_TWO_AT);
        put_vacb(
            &mut image,
            VACB_TWO_AT,
            SCM_AT,
            VIEW_AT,
            VIEW_OFFSET | 0x0007,
        );
        let (_, map) = scm_map(image);

        assert_eq!(map.pages.len(), 1);
        assert_eq!(
            map.pages[0].file_offset, VIEW_OFFSET,
            "the seven references are not part of where the view is in the file"
        );
        assert_eq!(map.pages[0].length, PAGE_SIZE);
    }

    #[test]
    fn a_view_belonging_to_another_file_is_not_taken_for_this_ones() {
        let mut image = scm_image(PAGE_SIZE, PAGE_SIZE);
        image.put_u64(SCM_AT + 24, VACB_AT);
        put_vacb(&mut image, VACB_AT, SCM_AT + 0x80, VIEW_AT, 0);
        let (_, map) = scm_map(image);
        assert!(map.pages.is_empty());
        assert_eq!(map.skipped_total, 1);
        assert!(map.notes.iter().any(|note| note.contains("belongs to")));
    }

    #[test]
    fn a_shared_cache_map_that_fails_its_own_consistency_check_is_refused_by_name() {
        // A structure that is not a shared cache map would still yield views:
        // whatever the bytes at those offsets happen to say.
        let image = scm_image(0, PAGE_SIZE);
        let profile = cache_profile(image);
        let symbols = DumpSymbols::from_profile(&profile).expect("a describable build");
        let err = file_cache_map(
            &profile,
            &symbols,
            FILE_OBJECT_AT,
            FileCache::SharedCacheMap,
            SCM_AT,
            &FileCacheConfig::default(),
        )
        .expect_err("a file of zero bytes with valid data is not a cached file");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("not a cached file"), "{err}");
    }

    #[test]
    fn the_tail_of_a_file_that_was_never_cached_is_declared_rather_than_written() {
        // The file is two pages long and only its first page is in a view. A
        // reconstruction that padded would produce an 8 KiB file whose second
        // half was invented.
        let mut image = scm_image(2 * PAGE_SIZE, 2 * PAGE_SIZE);
        image.put_u64(SCM_AT + 24, VACB_AT);
        put_vacb(&mut image, VACB_AT, SCM_AT, VIEW_AT, 0);
        let (profile, map) = scm_map(image);
        // The single view covers the whole 8 KiB the file declares, but only
        // the first page of it was written into the fixture; the rest reads as
        // the zero bytes the fixture holds, which is why the length is what is
        // asserted here rather than the contents.
        assert_eq!(map.declared_size, Some(2 * PAGE_SIZE));

        let mut trimmed = map.clone();
        trimmed.pages[0].length = PAGE_SIZE;
        let extract = dump_file_cache(&profile, &trimmed, &FileCacheConfig::default())
            .expect("a runnable dump");
        assert_eq!(extract.length, 2 * PAGE_SIZE);
        assert_eq!(extract.gap_total, 1);
        assert_eq!(extract.gaps[0].offset, PAGE_SIZE);
        assert_eq!(extract.gaps[0].reason, GapReason::NotInMemory);
        assert!(!extract.is_complete());
    }

    #[test]
    fn a_cache_map_is_only_complete_when_every_byte_of_the_file_was_in_memory() {
        let mut image = scm_image(PAGE_SIZE, PAGE_SIZE);
        image.put_u64(SCM_AT + 24, VACB_AT);
        put_vacb(&mut image, VACB_AT, SCM_AT, VIEW_AT, 0);
        let (_, complete) = scm_map(image);
        assert!(complete.is_complete());

        let mut short = complete.clone();
        short.pages[0].length = PAGE_SIZE / 2;
        assert!(
            !short.is_complete(),
            "half a file in memory is not a complete file"
        );
    }

    #[test]
    fn runs_that_claim_the_same_bytes_of_a_file_are_not_both_used() {
        // A section size above one 256 KiB block is what makes the walk read
        // both inline slots: the first as a full block, the second as the
        // spill-over.
        let mut image = scm_image(PAGE_SIZE, VACB_BLOCK + PAGE_SIZE);
        // Two views claiming file offset 0. There is no principled way to pick
        // a winner, so the second is dropped and counted.
        image.put_u64(SCM_AT + 24, VACB_AT);
        image.put_u64(SCM_AT + 24 + 8, VACB_TWO_AT);
        put_vacb(&mut image, VACB_AT, SCM_AT, VIEW_AT, 0);
        put_vacb(&mut image, VACB_TWO_AT, SCM_AT, VIEW_AT, 0);
        let (_, map) = scm_map(image);
        assert_eq!(map.pages.len(), 1);
        assert!(map.skipped_total >= 1);
        assert!(map.notes.iter().any(|note| note.contains("overlaps")));
    }

    #[test]
    fn a_reconstructed_file_above_the_cap_is_refused_rather_than_shortened() {
        let mut image = scm_image(PAGE_SIZE, PAGE_SIZE);
        image.put_u64(SCM_AT + 24, VACB_AT);
        put_vacb(&mut image, VACB_AT, SCM_AT, VIEW_AT, 0);
        let (profile, map) = scm_map(image);
        let config = FileCacheConfig {
            extract: ExtractConfig {
                max_bytes: 16,
                ..ExtractConfig::default()
            },
            ..FileCacheConfig::default()
        };
        let err = dump_file_cache(&profile, &map, &config).expect_err("above the cap");
        assert_eq!(err.class(), "too_large");
    }
}
