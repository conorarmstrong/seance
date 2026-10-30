//! Security descriptors (`sk` cells): who could change a key.
//!
//! Layout from Maxim Suhanov's *Windows registry file format specification*
//! (CC BY 4.0). Field offsets are written as constants beside their names so a
//! reader can check them against that document without decoding arithmetic.
//!
//! # What this module does and does not do
//!
//! It reads the `sk` **cell** — the ring links, the reference count, and the
//! bytes of the self-relative security descriptor it carries — and hands those
//! bytes to the caller. It does **not** decode the descriptor: owner SIDs,
//! ACLs and ACEs are `seance_core::secdesc`'s subject, because the same NT
//! descriptor appears in NTFS `$Secure:$SDS` and there must be one decoder for
//! both rather than two that can disagree on a court-facing surface.
//!
//! It also computes nothing. A reference count is transcribed, never repaired;
//! an ACL is never evaluated into "who can really write this"; and the question
//! of whether a key's ACL is *unusual* belongs to a caller that can measure its
//! own false-positive rate (`HUNT-122` is what a rushed classifier over this
//! data looks like).
//!
//! # What the real hives say
//!
//! Twelve hives under `reference/plaso/test_data/` were scanned cell by cell
//! while this was planned: 334,111 allocated `nk` cells and 820 allocated `sk`
//! cells. In all twelve, every `nk` names an *allocated* `sk` (not one
//! `0xFFFFFFFF`), every descriptor sets `SE_SELF_RELATIVE`, no declared
//! descriptor size overruns its cell, and each cell's reference count equals
//! the number of `nk` cells pointing at it **exactly**. The ring closes through
//! `flink` and `blink` with identical membership: 2 cells in `SAM`, 11 in
//! `NTUSER.DAT`, 193 in `SYSTEM`, 289 in `SOFTWARE` — the last of those shared
//! by 117,488 keys, with one descriptor named by 42,002 of them.
//!
//! That last figure is why the ring exists here at all: the distinct descriptor
//! population is what an examiner reads, and walking the ring answers it in 289
//! reads instead of 117,488.

use crate::error::{HiveError, Result};
use crate::hive::Hive;

/// Fixed part of a security cell, before the descriptor.
const SK_FIXED_BYTES: usize = 0x14;

const SK_FLINK: usize = 0x04;
const SK_BLINK: usize = 0x08;
const SK_REFERENCE_COUNT: usize = 0x0C;
const SK_DESCRIPTOR_SIZE: usize = 0x10;

/// How many cells the ring walk will visit before it calls the hive hostile.
///
/// The largest ring in the corpus is 289 cells (`SOFTWARE`). A hive whose
/// `flink` chain exceeds this is either damaged or crafted; in an ingest
/// pipeline an unbounded walk is an outage rather than a parse error, which is
/// the same reason `key_node::MAX_INDEX_DEPTH` exists.
const MAX_RING_CELLS: usize = 65_536;

/// One `sk` cell: a security descriptor and the bookkeeping around it.
#[derive(Clone, Copy, Debug)]
pub struct SecurityCell<'a> {
    cell: &'a [u8],
    offset: u32,
}

impl<'a> SecurityCell<'a> {
    pub(crate) fn from_cell_offset(hive: Hive<'a>, offset: u32) -> Result<Self> {
        let cell = hive.cell_data(offset)?;
        if cell.len() < SK_FIXED_BYTES {
            return Err(HiveError::Truncated {
                structure: "key security descriptor",
                offset: SK_FIXED_BYTES,
                available: cell.len(),
            });
        }
        if &cell[..2] != b"sk" {
            // Reading another structure's bytes as an ACL would produce ACEs
            // that are not in the evidence, which is worse than reading none.
            let mut found = [0u8; 4];
            let n = cell.len().min(4);
            found[..n].copy_from_slice(&cell[..n]);
            return Err(HiveError::BadSignature {
                structure: "key security descriptor",
                offset: offset as usize,
                expected: "sk",
                found,
            });
        }
        let this = Self { cell, offset };
        // The declared descriptor size is checked here rather than at the
        // accessor, so that a cell handed out is a cell whose descriptor can be
        // read. A length field trusted past the structure that bounds it is
        // how `HUNT-123` hashed bytes that were never signed.
        let declared = this.descriptor_size() as usize;
        let available = cell.len() - SK_FIXED_BYTES;
        if declared > available {
            return Err(HiveError::Truncated {
                structure: "key security descriptor body",
                offset: SK_FIXED_BYTES + declared,
                available: cell.len(),
            });
        }
        Ok(this)
    }

    fn u32_at(&self, at: usize) -> u32 {
        // Every offset here is inside `SK_FIXED_BYTES`, which the constructor
        // has already proven the cell holds.
        u32::from_le_bytes(self.cell[at..at + 4].try_into().unwrap_or([0; 4]))
    }

    /// Where this cell is, within the hive-bin data.
    ///
    /// Two keys with the same ACL name the same cell, so this is the identity
    /// by which a shared descriptor is recognised as one descriptor.
    pub fn cell_offset(&self) -> u32 {
        self.offset
    }

    /// The next cell on the security ring.
    pub fn flink(&self) -> u32 {
        self.u32_at(SK_FLINK)
    }

    /// The previous cell on the security ring.
    pub fn blink(&self) -> u32 {
        self.u32_at(SK_BLINK)
    }

    /// How many keys the hive says share this descriptor.
    ///
    /// **Transcribed, not repaired.** Every one of the 820 real cells carries a
    /// count equal to the number of keys pointing at it, so a count of zero — or
    /// one that disagrees with a walk — is a fact about the hive, and correcting
    /// it here would hide that fact from the examiner who needs it.
    pub fn reference_count(&self) -> u32 {
        self.u32_at(SK_REFERENCE_COUNT)
    }

    /// The length the cell declares for its descriptor.
    ///
    /// Proven to fit the cell before this cell was handed out.
    pub fn descriptor_size(&self) -> u32 {
        self.u32_at(SK_DESCRIPTOR_SIZE)
    }

    /// The self-relative NT security descriptor, exactly as the hive holds it.
    ///
    /// Bounded by the declared size and by the cell, whichever is smaller — and
    /// the constructor has already refused the case where the former exceeds
    /// the latter, so this cannot silently truncate.
    pub fn descriptor(&self) -> &'a [u8] {
        let end = (SK_FIXED_BYTES + self.descriptor_size() as usize).min(self.cell.len());
        &self.cell[SK_FIXED_BYTES..end]
    }
}

/// Every distinct security descriptor in a hive, walked from the ring.
///
/// # Why this carries an incompleteness flag
///
/// The population is the answer to "what ACLs does this hive hold", and a short
/// answer read as a complete one is the failure this whole codebase is written
/// against. A ring that does not close, or one that exceeds
/// [`MAX_RING_CELLS`], yields the cells that *were* read with
/// [`SecurityRing::is_incomplete`] set — never a silently short list.
#[derive(Clone, Debug)]
pub struct SecurityRing<'a> {
    cells: Vec<SecurityCell<'a>>,
    incomplete: Option<&'static str>,
}

impl<'a> SecurityRing<'a> {
    /// The cells read. On a complete ring this is every descriptor in the hive.
    pub fn iter(&self) -> impl Iterator<Item = &SecurityCell<'a>> {
        self.cells.iter()
    }

    /// How many cells were read — which is not necessarily how many the hive
    /// holds. Ask [`Self::is_incomplete`] before presenting this as a count.
    pub fn listed_len(&self) -> usize {
        self.cells.len()
    }

    /// Whether the walk stopped short of enumerating the ring.
    pub fn is_incomplete(&self) -> bool {
        self.incomplete.is_some()
    }

    /// Why the walk stopped short, for a caller that must state it.
    pub fn incomplete_reason(&self) -> Option<&'static str> {
        self.incomplete
    }
}

/// The empty population, for a hive whose root records no descriptor.
///
/// A distinct function rather than a `Default`, so that "this hive records no
/// security" is written down at its one call site instead of being inferred
/// from an empty vector somewhere downstream.
pub(crate) fn walk_ring_empty<'a>() -> Result<SecurityRing<'a>> {
    Ok(SecurityRing {
        cells: Vec::new(),
        incomplete: None,
    })
}

/// Walk the security ring starting from `start`.
///
/// `start` is any cell on the ring — in practice the root key's descriptor,
/// because every hive that records security records it for the root.
pub(crate) fn walk_ring<'a>(hive: Hive<'a>, start: u32) -> Result<SecurityRing<'a>> {
    let first = SecurityCell::from_cell_offset(hive, start)?;
    let mut cells = vec![first];
    let mut seen = vec![start];
    let mut incomplete = None;
    let mut at = first.flink();

    loop {
        if at == start {
            break; // the ring closed, which is the complete answer
        }
        if cells.len() >= MAX_RING_CELLS {
            incomplete = Some("the security ring exceeded this reader's cell ceiling");
            break;
        }
        // A `flink` that revisits a cell without having reached the start is a
        // ring that does not close. Stopping is not enough: the caller has to
        // be told the population is short.
        if seen.contains(&at) {
            incomplete = Some("the security ring revisited a cell without closing");
            break;
        }
        match SecurityCell::from_cell_offset(hive, at) {
            Ok(cell) => {
                seen.push(at);
                at = cell.flink();
                cells.push(cell);
            }
            Err(_) => {
                incomplete = Some("a cell on the security ring would not read");
                break;
            }
        }
    }

    Ok(SecurityRing { cells, incomplete })
}
