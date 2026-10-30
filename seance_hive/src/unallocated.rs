//! Recovering `nk`/`vk`-shaped cells from a hive's unallocated space.
//!
//! Every other structure in this crate refuses a cell whose size field marks
//! it free — `Hive::cell_data` returns [`HiveError::CellNotAllocated`] for
//! exactly that reason, because the live key/value tree must never wander
//! into a freed cell and report its bytes as though they were still in use.
//! This module is the deliberate exception: it walks a hive's unallocated
//! space *because* it is unallocated, looking for `nk`/`vk` cells that a
//! deletion marked free but never physically overwrote — the cell's own
//! four-byte size field is the same sign the allocated walk already reads
//! (`docs/SPEC_CROSSCHECK.md`: "the size is positive if a cell is unallocated
//! or negative if a cell is" allocated), read the other way.
//!
//! A recovered cell is never handed back through [`crate::key_node::KeyNode`]
//! or [`crate::key_value::KeyValue`]'s own iterators
//! ([`crate::key_node::SubKeyNodes`], [`crate::key_value::KeyValues`]) — it is
//! always wrapped in [`RecoveredCell`] inside an [`UnallocatedCell`], so a
//! caller cannot merge recovered-from-free-space evidence into a live listing
//! by forgetting to check a flag. That is the same discipline
//! [`crate::key_value::KeyValue::is_tombstoned`] exists for: recovered
//! evidence and current evidence are different sentences, and this reader
//! keeps them apart by type rather than by convention.
//!
//! Decoding reuses the exact `nk`/`vk` field parsing this crate already
//! trusts for the live tree — `KeyNode::from_cell_bytes` and
//! `KeyValue::from_cell_bytes` — rather than a second parser that could
//! disagree with it on what a valid cell looks like.

use crate::error::HiveError;
use crate::hive::{Hive, BIN_ALIGNMENT, CELL_ALIGNMENT};
use crate::key_node::KeyNode;
use crate::key_value::KeyValue;

/// Bytes at the head of every hive bin: signature, this-bin offset, size, then
/// reserved fields, before the first cell.
const HBIN_HEADER_BYTES: usize = 0x20;

/// Offset within a bin header of the bin's own declared size.
const HBIN_SIZE_FIELD: usize = 0x08;

/// Hard ceiling on how many **unallocated** cells one walk will examine.
///
/// The scan is already bounded by the buffer's own length — it cannot loop,
/// because every step either consumes at least `CELL_ALIGNMENT` bytes or
/// stops — but a hive crafted or corrupted into an unreasonable amount of
/// free space should not cost a walk of all of it. Set at the same order as
/// `seance_plugin_registry`'s own per-hive cell ceiling (`MAX_NK_CELLS`,
/// 200,000) — the allocated-cell walk this module is written to eventually
/// let that crate retire. Hit, it is reported through
/// [`UnallocatedCells::is_capped`], never silently.
///
/// Allocated cells are stepped over and **not counted**: a 37 MB `SOFTWARE`
/// hive holds more than 200,000 of them before its first free cell, and a
/// ceiling that counted those was reached before anything was recovered on
/// the hive most worth walking.
pub const MAX_UNALLOCATED_CELLS: usize = 200_000;

/// One cell recovered from a hive's unallocated space, decoded as far as it
/// would go.
#[derive(Debug)]
pub enum RecoveredCell<'a> {
    /// An `nk`-shaped cell that parsed as a key node.
    Key(KeyNode<'a>),
    /// A `vk`-shaped cell that parsed as a key value.
    Value(KeyValue<'a>),
    /// The cell's first two bytes are `nk` or `vk`, but the structure did not
    /// hold up past that — a name length running past the cell, or a data
    /// size the cell cannot back. Reported rather than dropped: a cell that
    /// carved this far into a key- or value-shaped signature is still worth
    /// an examiner's look, even though this reader will not guess the rest of
    /// it. This is the partial-result-with-a-note this crate uses elsewhere
    /// (`UnresolvedSublist`) rather than an all-or-nothing `Option`/`Result`.
    Undecodable {
        /// The two signature bytes that made this cell a candidate.
        signature: [u8; 2],
        /// Why it did not decode further.
        error: HiveError,
    },
}

/// One cell found in a hive's unallocated space, labelled with where it sits.
///
/// Never produced by, and never mixed into, [`crate::key_node::SubKeyNodes`]
/// or [`crate::key_value::KeyValues`] — this type itself is the label that a
/// cell came from free space, not from the live tree.
#[derive(Debug)]
pub struct UnallocatedCell<'a> {
    /// This cell's own offset, relative to the start of hive-bin data — the
    /// same coordinate [`crate::key_node::KeyNode::cell_offset`] and
    /// [`crate::key_value::KeyValue::cell_offset`] already report a live
    /// cell's location in, so a caller resolving a recovered node's parent or
    /// value offsets can look them up the same way it would for a live one.
    pub bin_offset: u32,
    /// What decoded, or how far decoding got.
    pub cell: RecoveredCell<'a>,
}

/// A hive's unallocated space, walked for `nk`/`vk`-shaped cells one at a
/// time. Built by [`Hive::unallocated_cells`].
pub struct UnallocatedCells<'a> {
    hive: Hive<'a>,
    data: &'a [u8],
    /// How many bytes of bins the base block declares. Bins past this are
    /// not promised, and the slack Windows leaves there (it grows a hive in
    /// 256 KiB steps) is the ordinary end of the walk, not a broken chain.
    declared: usize,
    /// Where the next bin header starts, once the current bin is exhausted.
    bin_pos: usize,
    /// End of the current bin's cell area (its declared size, bounded by what
    /// the buffer actually holds).
    bin_end: usize,
    /// Where the next cell starts within the current bin.
    cell_pos: usize,
    /// Unallocated cells examined so far — what [`MAX_UNALLOCATED_CELLS`]
    /// bounds.
    examined: usize,
    capped: bool,
    structure_stopped: bool,
    done: bool,
}

impl<'a> UnallocatedCells<'a> {
    pub(crate) fn new(hive: Hive<'a>) -> Self {
        Self {
            hive,
            data: hive.data(),
            declared: hive.declared_data_size(),
            bin_pos: 0,
            bin_end: 0,
            cell_pos: 0,
            examined: 0,
            capped: false,
            structure_stopped: false,
            done: false,
        }
    }

    /// Whether the walk stopped because it hit [`MAX_UNALLOCATED_CELLS`]
    /// rather than because it ran out of hive-bin data to look at.
    pub fn is_capped(&self) -> bool {
        self.capped
    }

    /// Whether the walk stopped on hive-bin data it could not make sense of —
    /// a broken `hbin` chain, rather than the true end of the hive's data.
    /// Free space beyond that point was never examined, and that must not be
    /// read as "there was nothing left to recover" — the same distinction
    /// [`crate::key_node::SubKeyNodes::is_incomplete`] draws for a subkey
    /// index the allocated walk could not fully resolve.
    pub fn is_incomplete(&self) -> bool {
        self.structure_stopped
    }

    /// Move to the next bin. Returns `false` when there is nothing more to
    /// scan, whether that is a clean end of the hive-bin data or a broken
    /// chain (distinguished by [`Self::structure_stopped`] on return).
    fn advance_bin(&mut self) -> bool {
        let pos = self.bin_pos;
        if pos >= self.data.len() {
            return false;
        }
        if pos + HBIN_HEADER_BYTES > self.data.len() || &self.data[pos..pos + 4] != b"hbin" {
            // Past the declared size this is slack, and every bin the base
            // block promised has been walked. Inside it, a bin is missing.
            self.structure_stopped = pos < self.declared;
            return false;
        }
        let hbin_size = u32::from_le_bytes([
            self.data[pos + HBIN_SIZE_FIELD],
            self.data[pos + HBIN_SIZE_FIELD + 1],
            self.data[pos + HBIN_SIZE_FIELD + 2],
            self.data[pos + HBIN_SIZE_FIELD + 3],
        ]) as usize;
        if hbin_size < HBIN_HEADER_BYTES || !hbin_size.is_multiple_of(BIN_ALIGNMENT) {
            self.structure_stopped = true;
            return false;
        }
        // The declared size may run past a hive cut short of what its base
        // block claims; every cell up to the cut is still readable, exactly
        // as `Tolerances::short_data` already allows for the allocated walk.
        self.bin_end = pos.saturating_add(hbin_size).min(self.data.len());
        self.bin_pos = pos.saturating_add(hbin_size);
        self.cell_pos = pos + HBIN_HEADER_BYTES;
        true
    }
}

/// Check whether `bytes` opens with an `nk` or `vk` signature and, if so,
/// decode it through the crate's own field parsing.
fn classify<'a>(hive: Hive<'a>, bytes: &'a [u8], offset: u32) -> Option<RecoveredCell<'a>> {
    if bytes.len() < 2 {
        return None;
    }
    match &bytes[..2] {
        b"nk" => Some(match KeyNode::from_cell_bytes(hive, bytes, offset) {
            Ok(node) => RecoveredCell::Key(node),
            Err(error) => RecoveredCell::Undecodable {
                signature: *b"nk",
                error,
            },
        }),
        b"vk" => Some(match KeyValue::from_cell_bytes(hive, bytes, offset) {
            Ok(value) => RecoveredCell::Value(value),
            Err(error) => RecoveredCell::Undecodable {
                signature: *b"vk",
                error,
            },
        }),
        _ => None,
    }
}

impl<'a> Iterator for UnallocatedCells<'a> {
    type Item = UnallocatedCell<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            if self.examined >= MAX_UNALLOCATED_CELLS {
                self.capped = true;
                self.done = true;
                return None;
            }
            while self.cell_pos + 4 > self.bin_end {
                if !self.advance_bin() {
                    self.done = true;
                    return None;
                }
            }
            // Note: this re-reads the same little-endian signed cell-size
            // field `hive.rs::cell_data` decodes, but cannot call it directly —
            // this walk must accept a *positive* sign (unallocated) where
            // `cell_data` requires negative (allocated) and errors otherwise.
            // Flagged by an independent code review on 2026-09-18; left as its
            // own decode since the two callers' validation rules genuinely
            // differ and both are pinned by passing tests.
            let cell_offset = self.cell_pos;
            let raw = i32::from_le_bytes([
                self.data[cell_offset],
                self.data[cell_offset + 1],
                self.data[cell_offset + 2],
                self.data[cell_offset + 3],
            ]);
            let cell_len = raw.unsigned_abs() as usize;
            if raw == 0 {
                // A zero cell size is the tail of a bin that was allocated
                // and never written — the ordinary, benign end of a bin's
                // cells, not damage. Nothing follows it in this bin to be
                // missed, so this simply moves on to the next one.
                if !self.advance_bin() {
                    self.done = true;
                    return None;
                }
                continue;
            }
            if cell_len < CELL_ALIGNMENT
                || !cell_len.is_multiple_of(CELL_ALIGNMENT)
                || cell_offset + cell_len > self.bin_end
            {
                // Damage inside this bin: nothing past this point in it can
                // be located reliably by walking the size chain, so the rest
                // of the bin is unread rather than "empty" (the free-space
                // counterpart of HIVE-002's rule for a broken subkey index).
                // The next bin's position came from this bin's own header,
                // read before this cell, so the chain past this bin is
                // unaffected.
                self.structure_stopped = true;
                if !self.advance_bin() {
                    self.done = true;
                    return None;
                }
                continue;
            }
            self.cell_pos = cell_offset + cell_len;

            if raw < 0 {
                // Allocated: not this walk's business. The live tree already
                // covers it; step over it and keep scanning for free space.
                continue;
            }
            self.examined += 1;
            let bytes = &self.data[cell_offset + 4..cell_offset + cell_len];
            if let Some(recovered) = classify(self.hive, bytes, cell_offset as u32) {
                return Some(UnallocatedCell {
                    bin_offset: cell_offset as u32,
                    cell: recovered,
                });
            }
            // Free bytes that do not open with a recognised signature: not a
            // fabricated key, just space this walk has nothing to say about.
        }
    }
}
