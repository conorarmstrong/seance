//! Freelist trunk/leaf page collection.
//!
//! Ported from the reference `collectFreelistReferences`. Walks the freelist
//! trunk chain (head recorded at header offset 32) gathering every trunk and
//! leaf page index. Cycle-guarded and bounds-checked.

use super::reader::PageReader;
use std::collections::HashSet;

/// A page belonging to the freelist, with a note describing how it was reached.
#[derive(Debug, Clone)]
pub struct FreelistPage {
    pub page_index: usize,
    pub is_trunk: bool,
}

/// Collects freelist pages by walking the trunk chain from `first_trunk`
/// (1-based). `total_freelist` caps the number of leaf pages gathered.
pub fn collect_freelist_pages(
    reader: &PageReader,
    first_trunk: u32,
    total_freelist: u32,
) -> Vec<FreelistPage> {
    let mut refs = Vec::new();
    let mut collected = 0usize;
    let mut next_trunk = first_trunk;
    let mut seen: HashSet<usize> = HashSet::new();

    while next_trunk != 0 && collected < total_freelist as usize {
        let trunk_index = next_trunk as usize - 1;
        if next_trunk == 0 || !seen.insert(trunk_index) {
            break;
        }
        let page = reader.read_page(trunk_index);
        if page.len() < 8 {
            break;
        }
        refs.push(FreelistPage {
            page_index: trunk_index,
            is_trunk: true,
        });
        let next = u32::from_be_bytes([page[0], page[1], page[2], page[3]]);
        let leaf_count = u32::from_be_bytes([page[4], page[5], page[6], page[7]]) as usize;
        for i in 0..leaf_count {
            let off = 8 + i * 4;
            if off + 4 > page.len() {
                break;
            }
            let page_num =
                u32::from_be_bytes([page[off], page[off + 1], page[off + 2], page[off + 3]]);
            if page_num == 0 {
                continue;
            }
            refs.push(FreelistPage {
                page_index: page_num as usize - 1,
                is_trunk: false,
            });
            collected += 1;
        }
        next_trunk = next;
    }
    refs
}
