//! Walking the node and block B-trees of a version-36 store.

use super::page::{read_btree_page, PageFault, PTYPE_BBT, PTYPE_NBT};
use super::{le_u16, le_u32, le_u64, Bref};

/// Deeper than this is not a real tree (Outlook's are two or three levels).
pub const MAX_DEPTH: usize = 8;

/// One node B-tree leaf entry (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NbtEntry {
    pub nid: u64,
    pub bid_data: u64,
    pub bid_sub: u64,
    pub nid_parent: u32,
}

/// One block B-tree leaf entry (24 bytes): the block's reference, its stored
/// size, its inflated size and its reference count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BbtEntry {
    pub bref: Bref,
    pub cb: u16,
    pub cb_inflated: u16,
    pub c_ref: u16,
}

/// What one tree walk reached, and every page it could not.
#[derive(Debug, Clone)]
pub struct Walk<E> {
    pub entries: Vec<E>,
    pub pages_walked: usize,
    pub faults: Vec<PageFault>,
}

impl<E> Default for Walk<E> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            pages_walked: 0,
            faults: Vec::new(),
        }
    }
}

/// Intermediate entries are a key and a BREF: 24 bytes at every level.
const INTERMEDIATE_CB: u8 = 24;
const NBT_LEAF_CB: u8 = 32;
const BBT_LEAF_CB: u8 = 24;

/// Walk a tree iteratively from `root`, handing each leaf entry's bytes to
/// `leaf`. A page that cannot be read costs that page and the subtree below
/// it, and is recorded; the walk goes on with its siblings. A page reached
/// twice (a loop, or a child two parents share) is not walked again, and the
/// depth is capped, so no input can make the walk run forever.
fn walk<E>(
    data: &[u8],
    root: Bref,
    ptype: u8,
    leaf_cb: u8,
    leaf: impl Fn(&[u8]) -> Option<E>,
) -> Walk<E> {
    let mut out = Walk::default();
    let mut visited = std::collections::HashSet::new();
    // (page, the level its parent says it must be, depth)
    let mut stack: Vec<(Bref, Option<u8>, usize)> = vec![(root, None, 0)];
    while let Some((bref, want_level, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            out.faults.push(PageFault::TooDeep { ib: bref.ib });
            continue;
        }
        if !visited.insert(bref.ib) {
            out.faults.push(PageFault::ReachedTwice { ib: bref.ib });
            continue;
        }
        let page = match read_btree_page(data, bref, ptype) {
            Ok(p) => p,
            Err(f) => {
                out.faults.push(f);
                continue;
            }
        };
        if want_level.is_some_and(|l| l != page.level) {
            out.faults.push(PageFault::BadMetadata {
                ib: bref.ib,
                detail: format!(
                    "level {} where its parent's level implies {}",
                    page.level,
                    want_level.unwrap_or(0)
                ),
            });
            continue;
        }
        let want_cb = if page.level == 0 {
            leaf_cb
        } else {
            INTERMEDIATE_CB
        };
        if page.cb_ent != want_cb {
            out.faults.push(PageFault::BadMetadata {
                ib: bref.ib,
                detail: format!(
                    "entry size {} where a level-{} page of this tree has {}",
                    page.cb_ent, page.level, want_cb
                ),
            });
            continue;
        }
        out.pages_walked += 1;
        if page.level == 0 {
            out.entries
                .extend((0..usize::from(page.c_ent)).filter_map(|i| page.entry(i).and_then(&leaf)));
        } else {
            // Pushed in reverse so the children are walked in key order.
            for i in (0..usize::from(page.c_ent)).rev() {
                if let Some(e) = page.entry(i) {
                    let child = Bref {
                        bid: le_u64(e, 8).unwrap_or(0),
                        ib: le_u64(e, 16).unwrap_or(0),
                    };
                    stack.push((child, Some(page.level - 1), depth + 1));
                }
            }
        }
    }
    out
}

/// Walk the node B-tree.
pub fn walk_nbt(data: &[u8], root: Bref) -> Walk<NbtEntry> {
    walk(data, root, PTYPE_NBT, NBT_LEAF_CB, |e| {
        Some(NbtEntry {
            nid: le_u64(e, 0)?,
            bid_data: le_u64(e, 8)?,
            bid_sub: le_u64(e, 16)?,
            nid_parent: le_u32(e, 24)?,
        })
    })
}

/// Walk the block B-tree.
pub fn walk_bbt(data: &[u8], root: Bref) -> Walk<BbtEntry> {
    walk(data, root, PTYPE_BBT, BBT_LEAF_CB, |e| {
        Some(BbtEntry {
            bref: Bref {
                bid: le_u64(e, 0)?,
                ib: le_u64(e, 8)?,
            },
            cb: le_u16(e, 16)?,
            cb_inflated: le_u16(e, 18)?,
            c_ref: le_u16(e, 20)?,
        })
    })
}
