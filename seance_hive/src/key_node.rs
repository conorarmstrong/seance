//! Key nodes (`nk`) and the four index forms that hold their subkeys.
//!
//! Layout from Maxim Suhanov's *Windows registry file format specification*
//! (CC BY 4.0). Field offsets are written as constants beside their names so a
//! reader can check them against that document without decoding arithmetic.

use crate::error::{HiveError, Result};
use crate::hive::Hive;
use crate::key_value::KeyValues;
use crate::name::HiveNameString;
use crate::security::SecurityCell;

/// Fixed part of a key node, before the name.
const NK_FIXED_BYTES: usize = 0x4C;

const NK_FLAGS: usize = 0x02;
const NK_LAST_WRITTEN: usize = 0x04;
/// The layered-key bit fields (minor version 6): the second byte of what
/// older hives call the access bits.
const NK_LAYERED_KEY_BITS: usize = 0x0D;
const NK_PARENT: usize = 0x10;
const NK_SUBKEY_COUNT: usize = 0x14;
const NK_SUBKEYS_OFFSET: usize = 0x1C;
const NK_VALUE_COUNT: usize = 0x24;
const NK_VALUES_OFFSET: usize = 0x28;
const NK_SECURITY_OFFSET: usize = 0x2C;
const NK_CLASS_NAME_OFFSET: usize = 0x30;
const NK_NAME_LENGTH: usize = 0x48;
const NK_CLASS_NAME_LENGTH: usize = 0x4A;

/// The name is one byte per character rather than UTF-16LE.
const KEY_COMP_NAME: u16 = 0x0020;

/// How deep an index-root chain may go before this reader calls it hostile.
///
/// A real hive nests `ri` over leaves and stops. A crafted one can point a
/// list at itself; without this bound the walk never returns, which in an
/// ingest pipeline is a denial of service rather than a parse error.
const MAX_INDEX_DEPTH: usize = 8;

/// An offset field set to all ones means "no such structure".
const NONE: u32 = u32::MAX;

/// A key: its name, its timestamps, its values and its subkeys.
#[derive(Clone, Copy, Debug)]
pub struct KeyNode<'a> {
    hive: Hive<'a>,
    cell: &'a [u8],
    offset: u32,
}

impl<'a> KeyNode<'a> {
    pub(crate) fn from_cell_offset(hive: Hive<'a>, offset: u32) -> Result<Self> {
        let cell = hive.cell_data(offset)?;
        Self::from_cell_bytes(hive, cell, offset)
    }

    /// Parse a key node from cell contents the caller already holds, rather
    /// than looking them up by offset through [`Hive::cell_data`].
    ///
    /// The structural checks are exactly [`Self::from_cell_offset`]'s — this
    /// is the routine that call makes, factored out so a second caller can
    /// reach it without going through the allocation check `cell_data` makes.
    /// The one caller today is [`crate::unallocated::UnallocatedCells`], which
    /// walks a hive's *unallocated* space on purpose and so cannot present an
    /// offset `cell_data` would accept; it must still hold a recovered node to
    /// this same standard, so the recovered node is never one degree less
    /// scrutinised than a live one.
    pub(crate) fn from_cell_bytes(hive: Hive<'a>, cell: &'a [u8], offset: u32) -> Result<Self> {
        if cell.len() < NK_FIXED_BYTES {
            return Err(HiveError::Truncated {
                structure: "key node",
                offset: NK_FIXED_BYTES,
                available: cell.len(),
            });
        }
        if &cell[..2] != b"nk" {
            return Err(HiveError::BadSignature {
                structure: "key node",
                offset: offset as usize,
                expected: "nk",
                found: [cell[0], cell[1], 0, 0],
            });
        }
        Ok(Self { hive, cell, offset })
    }

    fn u16_at(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.cell[at], self.cell[at + 1]])
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes([
            self.cell[at],
            self.cell[at + 1],
            self.cell[at + 2],
            self.cell[at + 3],
        ])
    }

    /// Where this node's cell starts, relative to the hive-bin data.
    pub fn cell_offset(&self) -> u32 {
        self.offset
    }

    /// The layered-key bit fields at `nk+0x0D`, or `None` when this hive is
    /// not a differencing hive (minor version below 6).
    ///
    /// Before minor 6 the byte is spare, and a stray value in it is not a
    /// layer: reading it as one would report a deletion that never happened.
    pub fn layered_key_bits(&self) -> Option<crate::layered::LayeredKeyBits> {
        (self.hive.minor_version() >= crate::layered::LAYERED_MINOR_VERSION)
            .then(|| crate::layered::LayeredKeyBits::from_raw(self.cell[NK_LAYERED_KEY_BITS]))
    }

    pub fn flags(&self) -> u16 {
        self.u16_at(NK_FLAGS)
    }

    /// When the key was last written, as a Windows FILETIME.
    pub fn last_written_filetime(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.cell[NK_LAST_WRITTEN..NK_LAST_WRITTEN + 8]);
        u64::from_le_bytes(bytes)
    }

    /// The parent key's cell offset, or `None` for the root.
    pub fn parent_offset(&self) -> Option<u32> {
        match self.u32_at(NK_PARENT) {
            NONE => None,
            offset => Some(offset),
        }
    }

    /// How many subkeys the node says it has. Advisory: the index is what is
    /// actually walked, and the two can disagree in a damaged hive.
    pub fn subkey_count(&self) -> u32 {
        self.u32_at(NK_SUBKEY_COUNT)
    }

    pub fn value_count(&self) -> u32 {
        self.u32_at(NK_VALUE_COUNT)
    }

    /// The key's name.
    ///
    /// Bounded by the cell: the length field is attacker-controlled and the
    /// name is the last thing in the structure, so a length that runs past the
    /// cell is an error rather than a read of the next key's bytes.
    pub fn name(&self) -> Result<HiveNameString<'a>> {
        let length = self.u16_at(NK_NAME_LENGTH) as usize;
        let end = NK_FIXED_BYTES + length;
        if end > self.cell.len() {
            return Err(HiveError::Truncated {
                structure: "key name",
                offset: end,
                available: self.cell.len(),
            });
        }
        let bytes = &self.cell[NK_FIXED_BYTES..end];
        Ok(if self.flags() & KEY_COMP_NAME != 0 {
            HiveNameString::Latin1(bytes)
        } else {
            HiveNameString::Utf16Le(bytes)
        })
    }

    /// The key's class name, when it has one.
    pub fn class_name(&self) -> Option<Result<HiveNameString<'a>>> {
        let offset = self.u32_at(NK_CLASS_NAME_OFFSET);
        if offset == NONE {
            return None;
        }
        let length = self.u16_at(NK_CLASS_NAME_LENGTH) as usize;
        Some(self.hive.cell_data(offset).and_then(|cell| {
            if length > cell.len() {
                Err(HiveError::Truncated {
                    structure: "class name",
                    offset: length,
                    available: cell.len(),
                })
            } else {
                // A class name is always UTF-16LE; there is no compressed form.
                Ok(HiveNameString::Utf16Le(&cell[..length]))
            }
        }))
    }

    /// This key's subkeys, or `None` when it has none.
    ///
    /// The outer `Option` is "no subkeys", the inner `Result` is "the index
    /// would not read" — two different answers that must not collapse into
    /// one, because the second is a hole in the evidence and the first is not.
    /// Where this key's security descriptor is, or `None` if it records none.
    ///
    /// `0xFFFFFFFF` in the field is the absence of a descriptor, not a cell at
    /// offset 4,294,967,295 — the same convention every other offset field in
    /// a key node uses.
    pub fn security_offset(&self) -> Option<u32> {
        let raw = u32::from_le_bytes(
            self.cell[NK_SECURITY_OFFSET..NK_SECURITY_OFFSET + 4]
                .try_into()
                .unwrap_or([0xFF; 4]),
        );
        (raw != NONE).then_some(raw)
    }

    /// This key's security descriptor cell.
    ///
    /// `None` means the key records no descriptor; `Some(Err(..))` means it
    /// names one that would not read. Those are different sentences and an
    /// examiner is entitled to both — the same contract [`Self::subkeys`] and
    /// [`Self::values`] keep.
    ///
    /// Not one of the 334,111 key nodes in the twelve real hives under
    /// `reference/plaso/test_data/` takes the `None` branch, so on real
    /// evidence a key without a descriptor is itself worth remarking on.
    pub fn security(&self) -> Option<Result<SecurityCell<'a>>> {
        let offset = self.security_offset()?;
        Some(SecurityCell::from_cell_offset(self.hive, offset))
    }

    pub fn subkeys(&self) -> Option<Result<SubKeyNodes<'a>>> {
        let offset = self.u32_at(NK_SUBKEYS_OFFSET);
        if offset == NONE || self.subkey_count() == 0 {
            return None;
        }
        Some(SubKeyNodes::new(self.hive, offset))
    }

    /// This key's values, or `None` when it has none.
    pub fn values(&self) -> Option<Result<KeyValues<'a>>> {
        let offset = self.u32_at(NK_VALUES_OFFSET);
        let count = self.value_count();
        if offset == NONE || count == 0 {
            return None;
        }
        Some(KeyValues::new(self.hive, offset, count))
    }

    // There is deliberately no `subkey(name)` / `subpath(path)` / `value(name)`
    // lookup. Windows compares registry names case-insensitively across the
    // whole Basic Multilingual Plane, and the only honest implementations are a
    // 1,500-line generated fold table or a lookup that is wrong on non-ASCII
    // names. Every caller in this project enumerates and compares names
    // itself, so the crate offers enumeration and nothing that could be
    // mistaken for a Windows-faithful lookup (HIVE-001, withdrawn 2026-09-14).
}

/// One subkeys-list cell, its header checked and its entries bounded.
///
/// The four forms a hive uses:
///
/// * `lf` — fast leaf: 8 bytes per entry, a key-node offset and the first four
///   characters of its name as a hint.
/// * `lh` — hash leaf: the same shape, with a name hash instead of the hint.
/// * `li` — index leaf: 4 bytes per entry, offsets only.
/// * `ri` — index root: 4 bytes per entry, each naming another list of any of
///   these forms.
///
/// The hints and hashes are not read. They exist to make a *lookup* fast, and
/// this reader enumerates; trusting a hash to decide a key's name is how a
/// reader reports a key that is not there.
enum SubkeyList<'a> {
    /// `lf`, `lh` or `li`: `count` key-node offsets, one every `stride` bytes
    /// from the start of `entries`, which is known to hold all of them.
    Leaf {
        entries: &'a [u8],
        stride: usize,
        count: usize,
    },
    /// `ri`: `count` sublist offsets, four bytes apart.
    Root { entries: &'a [u8], count: usize },
}

/// The little-endian `u32` at `entries[base..base + 4]`. Callers have already
/// bounded `entries` against the list's count, so the fallback never fires.
fn entry_u32(entries: &[u8], base: usize) -> u32 {
    entries
        .get(base..base + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(NONE, u32::from_le_bytes)
}

/// Read a subkeys-list cell's header and bound its entries against its count.
fn parse_subkey_list(hive: Hive<'_>, offset: u32) -> Result<SubkeyList<'_>> {
    let cell = hive.cell_data(offset)?;
    if cell.len() < 4 {
        return Err(HiveError::Truncated {
            structure: "subkeys list",
            offset: 4,
            available: cell.len(),
        });
    }
    let signature = &cell[..2];
    let count = u16::from_le_bytes([cell[2], cell[3]]) as usize;
    let entries = &cell[4..];
    let (structure, stride) = match signature {
        b"lf" | b"lh" => ("subkey leaf", 8),
        b"li" => ("index leaf", 4),
        b"ri" => ("index root", 4),
        other => {
            return Err(HiveError::BadSignature {
                structure: "subkeys list",
                offset: offset as usize,
                expected: "lf, lh, li or ri",
                found: [
                    other.first().copied().unwrap_or(0),
                    other.get(1).copied().unwrap_or(0),
                    0,
                    0,
                ],
            })
        }
    };
    if entries.len() < count * stride {
        return Err(HiveError::Truncated {
            structure,
            offset: count * stride,
            available: entries.len(),
        });
    }
    Ok(if signature == b"ri" {
        SubkeyList::Root { entries, count }
    } else {
        SubkeyList::Leaf {
            entries,
            stride,
            count,
        }
    })
}

/// Resolve a subkeys-list cell, at index depth `depth`, to the key-node
/// offsets it names. Used for everything below an index root; a leaf at the
/// top of a key's index is read in place by [`SubKeyNodes`] instead.
fn collect_subkey_offsets(
    hive: Hive<'_>,
    offset: u32,
    depth: usize,
    unresolved: &mut Vec<UnresolvedSublist>,
) -> Result<Vec<u32>> {
    if depth >= MAX_INDEX_DEPTH {
        return Err(HiveError::StructureTooDeep {
            limit: MAX_INDEX_DEPTH,
        });
    }
    let mut offsets = Vec::new();
    match parse_subkey_list(hive, offset)? {
        SubkeyList::Leaf {
            entries,
            stride,
            count,
        } => {
            offsets.extend((0..count).map(|i| entry_u32(entries, i * stride)));
        }
        SubkeyList::Root { entries, count } => {
            collect_root_offsets(hive, entries, count, depth, unresolved, &mut offsets);
        }
    }
    Ok(offsets)
}

/// Append the offsets every sublist of an `ri` names, recording each sublist
/// that would not read.
fn collect_root_offsets(
    hive: Hive<'_>,
    entries: &[u8],
    count: usize,
    depth: usize,
    unresolved: &mut Vec<UnresolvedSublist>,
    offsets: &mut Vec<u32>,
) {
    for i in 0..count {
        let child = entry_u32(entries, i * 4);
        // One bad sublist does not cost the sublists beside it: a damaged
        // hive should yield the keys it still has. But the loss is recorded,
        // not swallowed — a short list that reads like a complete one is a
        // false absence (HIVE-002).
        match collect_subkey_offsets(hive, child, depth + 1, unresolved) {
            Ok(mut nested) => offsets.append(&mut nested),
            Err(error) => unresolved.push(UnresolvedSublist {
                offset: child,
                error,
            }),
        }
    }
}

/// Where the next key-node offset comes from.
enum SubkeyOffsets<'a> {
    /// A leaf index (`lf`, `lh`, `li`), read in place one entry at a time —
    /// no allocation, the common case (ROADMAP §5.9).
    Leaf {
        entries: &'a [u8],
        stride: usize,
        count: usize,
        next: usize,
    },
    /// An index root (`ri`), resolved up front: that walk is what carries the
    /// unresolved-sublist record and the depth bound.
    Resolved(std::vec::IntoIter<u32>),
}

impl SubkeyOffsets<'_> {
    fn remaining(&self) -> usize {
        match self {
            Self::Leaf { count, next, .. } => count - next,
            Self::Resolved(offsets) => offsets.len(),
        }
    }
}

impl Iterator for SubkeyOffsets<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        match self {
            Self::Leaf {
                entries,
                stride,
                count,
                next,
            } => {
                if *next >= *count {
                    return None;
                }
                let offset = entry_u32(entries, *next * *stride);
                *next += 1;
                Some(offset)
            }
            Self::Resolved(offsets) => offsets.next(),
        }
    }
}

/// The subkeys of one key, yielded one at a time.
///
/// The list is bounded against its count up front — that is what bounds the
/// walk — and each node is parsed only when it is asked for. A leaf index is
/// read in place; an index root is resolved to its offsets first, because
/// that is where damage is found and recorded.
pub struct SubKeyNodes<'a> {
    hive: Hive<'a>,
    offsets: SubkeyOffsets<'a>,
    unresolved: Vec<UnresolvedSublist>,
    /// Offsets already handed out, so [`SubKeyNodes::listed_len`] answers the
    /// same number before, during and after the walk.
    consumed: usize,
}

impl<'a> SubKeyNodes<'a> {
    fn new(hive: Hive<'a>, offset: u32) -> Result<Self> {
        let mut unresolved = Vec::new();
        let offsets = match parse_subkey_list(hive, offset)? {
            SubkeyList::Leaf {
                entries,
                stride,
                count,
            } => SubkeyOffsets::Leaf {
                entries,
                stride,
                count,
                next: 0,
            },
            SubkeyList::Root { entries, count } => {
                let mut offsets = Vec::new();
                collect_root_offsets(hive, entries, count, 0, &mut unresolved, &mut offsets);
                SubkeyOffsets::Resolved(offsets.into_iter())
            }
        };
        Ok(Self {
            hive,
            offsets,
            unresolved,
            consumed: 0,
        })
    }
}

/// A subkey list named by an index root (`ri`) that would not read.
///
/// The keys it named are absent from the enumeration and are **not** absent
/// from the hive; a caller that enumerates subkeys has to carry this onto
/// whatever it emits, or a damaged key reads as a short, complete one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedSublist {
    /// Cell offset of the sublist, as the index root recorded it.
    pub offset: u32,
    /// Why it would not read.
    pub error: HiveError,
}

impl SubKeyNodes<'_> {
    /// The `ri` sublists that could not be resolved, with the reason for each.
    /// Empty when every list the index named was read, which is the only case
    /// in which this enumeration is the key's whole subkey set.
    pub fn unresolved_sublists(&self) -> &[UnresolvedSublist] {
        &self.unresolved
    }

    /// Whether the enumeration is short of what the key's index named.
    pub fn is_incomplete(&self) -> bool {
        !self.unresolved.is_empty()
    }

    /// How many key-node offsets the index actually named.
    ///
    /// The number to compare against [`KeyNode::subkey_count`], which is what
    /// the key *says* it has. The two agree in an intact hive and can disagree
    /// in two ways that mean different things: a list holding fewer offsets
    /// than the count declares is a damaged index or a deleted key whose parent
    /// still counts it, and a list holding more is an index the count has not
    /// been updated for. Neither is resolved here — a reader that silently
    /// trusted one over the other would report a key's contents as settled
    /// when the hive itself disagrees about them.
    ///
    /// Counted before iteration and unaffected by it, so it can be read either
    /// side of the walk.
    pub fn listed_len(&self) -> usize {
        self.offsets.remaining() + self.consumed
    }
}

impl<'a> Iterator for SubKeyNodes<'a> {
    type Item = Result<KeyNode<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.offsets.next()?;
        self.consumed += 1;
        Some(KeyNode::from_cell_offset(self.hive, offset))
    }
}
