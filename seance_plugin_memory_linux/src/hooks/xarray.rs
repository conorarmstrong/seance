//! Walking an `xarray` (and so an `idr`, whose `idr_rt` became one in Linux
//! 4.20 — from 4.11 to 4.19 it was a radix tree, which this does not walk) for
//! every pointer entry it holds, with the index each sits at.
//!
//! The layout, from `include/linux/xarray.h`:
//!
//! * `xarray.xa_head` is either null (empty), an internal pointer to an
//!   `xa_node` (low two bits `10`), or a single entry at index 0;
//! * an `xa_node` holds `XA_CHUNK_SIZE` slots (the array length the symbol
//!   table declares, 64 on every configuration this tier has met) and a
//!   `shift`: slot `i` of a node whose base index is `b` covers indices from
//!   `b + (i << shift)`, and a node with `shift == 0` is a leaf whose slots are
//!   the entries themselves;
//! * a slot holding an internal pointer below 4096 (`XA_RETRY_ENTRY`,
//!   `XA_ZERO_ENTRY`, sibling entries) is not a node and is skipped; a slot
//!   with its low bit set is an integer value entry, which an IDR of pointers
//!   never holds and which is skipped and counted.
//!
//! Nothing here reads the entries themselves: the walk yields `(index,
//! pointer)` pairs and the caller decides what the pointer is.

use std::collections::HashSet;

use seance_memory::binding::BuildBinding;
use seance_memory::object::StructReader;

/// Internal entries below this are markers, not nodes.
const XA_INTERNAL_MARKER_LIMIT: u64 = 4096;
/// A node pointer's tag.
const XA_TAG_MASK: u64 = 3;
const XA_TAG_INTERNAL: u64 = 2;
/// The deepest tree a 64-bit index can need at 6 bits a level, plus slack.
const MAX_DEPTH: u32 = 16;
/// Most entries one walk yields.
pub const MAX_ENTRIES: usize = 1 << 20;

/// What a walk found and could not find.
#[derive(Debug, Clone, Default)]
pub struct XarrayWalk {
    /// `(index, pointer)` for every pointer entry, in index order per node.
    pub entries: Vec<(u64, u64)>,
    /// Nodes whose bytes would not read; each costs its whole subtree.
    pub unreadable_nodes: Vec<u64>,
    /// Value (non-pointer) entries skipped.
    pub value_entries_skipped: usize,
    /// Whether the cap or the depth bound stopped the walk.
    pub capped: bool,
}

impl XarrayWalk {
    /// Whether every node the tree reaches was read.
    pub fn is_complete(&self) -> bool {
        self.unreadable_nodes.is_empty() && !self.capped
    }
}

/// Walk the `xarray` at `head_address` (the address of the `xa_head` member,
/// i.e. of the `xarray` plus the member's offset).
///
/// `layout` must declare `xa_slots` and `xa_shift` on the `xa_node` type.
pub fn walk(
    reader: &StructReader,
    layout: &BuildBinding,
    head_address: u64,
) -> Result<XarrayWalk, String> {
    let node_type = layout
        .type_of("xa_node")
        .ok()
        .and_then(|t| t.type_name())
        .ok_or("this build declares no xa_node type")?;
    let slots_member = layout
        .member("xa_slots")
        .ok()
        .and_then(|m| m.member())
        .ok_or("this build declares no xa_node.slots")?;
    let shift_member = layout
        .member("xa_shift")
        .ok()
        .and_then(|m| m.member())
        .ok_or("this build declares no xa_node.shift")?;

    let head = reader
        .read_pointer_at(head_address)
        .map_err(|e| format!("xa_head at {head_address:#x} could not be read: {e}"))?;
    let mut walk = XarrayWalk::default();
    if head == 0 {
        return Ok(walk);
    }
    if head & XA_TAG_MASK != XA_TAG_INTERNAL {
        // A single entry at index 0.
        if head & 1 == 1 {
            walk.value_entries_skipped += 1;
        } else {
            walk.entries.push((0, head));
        }
        return Ok(walk);
    }

    let mut seen: HashSet<u64> = HashSet::new();
    let mut cursor = Cursor {
        reader,
        node_type,
        slots_member,
        shift_member,
        walk: &mut walk,
        seen: &mut seen,
    };
    cursor.node(head & !XA_TAG_MASK, 0, 0);
    Ok(walk)
}

struct Cursor<'a> {
    reader: &'a StructReader,
    node_type: &'static str,
    slots_member: &'static str,
    shift_member: &'static str,
    walk: &'a mut XarrayWalk,
    seen: &'a mut HashSet<u64>,
}

impl Cursor<'_> {
    fn node(&mut self, address: u64, base_index: u64, depth: u32) {
        if depth >= MAX_DEPTH || !self.seen.insert(address) {
            self.walk.capped = true;
            return;
        }
        let node = match self.reader.object(address, self.node_type) {
            Ok(node) => node,
            Err(_) => {
                self.walk.unreadable_nodes.push(address);
                return;
            }
        };
        let shift = match node.unsigned(self.shift_member) {
            Ok(shift) => shift,
            Err(_) => {
                self.walk.unreadable_nodes.push(address);
                return;
            }
        };
        if shift > 63 {
            self.walk.unreadable_nodes.push(address);
            return;
        }
        let slot_count = match node.array_len_capped(self.slots_member, 1024) {
            Ok(count) => count,
            Err(_) => {
                self.walk.unreadable_nodes.push(address);
                return;
            }
        };
        for slot in 0..slot_count {
            let entry = match node.element_int(self.slots_member, slot) {
                Ok(value) => value.as_u64().unwrap_or(0),
                Err(_) => {
                    self.walk.unreadable_nodes.push(address);
                    return;
                }
            };
            if entry == 0 {
                continue;
            }
            let index = base_index.wrapping_add(slot << shift);
            if entry & XA_TAG_MASK == XA_TAG_INTERNAL {
                if entry < XA_INTERNAL_MARKER_LIMIT {
                    continue; // retry / zero / sibling marker
                }
                if shift == 0 {
                    // A leaf must not hold a node; treat as corrupt and stop.
                    self.walk.capped = true;
                    return;
                }
                self.node(entry & !XA_TAG_MASK, index, depth + 1);
                continue;
            }
            if entry & 1 == 1 {
                self.walk.value_entries_skipped += 1;
                continue;
            }
            // A pointer entry in an interior node is a multi-order entry, which
            // an IDR never holds; it is reported at its index all the same.
            if self.walk.entries.len() >= MAX_ENTRIES {
                self.walk.capped = true;
                return;
            }
            self.walk.entries.push((index, entry));
        }
    }
}
