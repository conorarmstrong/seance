//! The CIM repository's index: `INDEX.BTR` (HUNT-195).
//!
//! `OBJECTS.DATA` holds records; `INDEX.BTR` is the B-tree through which the
//! repository finds them. A page's descriptor table lists every record the
//! page holds, but the index decides which of those the repository still
//! resolves: a record deleted or unlinked can stay listed in a current page
//! while the index no longer names it.
//!
//! # Layout (as read off the real files; Vista onward)
//!
//! `INDEX.BTR` is 8192-byte pages addressed in *logical* pages through the
//! `INDEX.BTR` section of the active `MAPPINGn.MAP`. Every field is
//! little-endian.
//!
//! | Offset | Field |
//! |--------|-------|
//! | 0 | signature `0xACCC` |
//! | 4 | the page's own logical number |
//! | 8, 12 | zero on every page held |
//! | 16 | key count `N` |
//! | 20 | `N` u32 whose meaning is not documented (not read) |
//! | then | `N + 1` u32 child pages (logical; `0` and `0xFFFFFFFF` mean none) |
//! | then | `N` u16 key offsets, in u16 units into the definition table |
//! | then | u16 definition-table length in u16 units, then the table |
//! | then | u16 string count `S`, `S + 1` u16 string offsets, then the strings |
//!
//! A definition-table entry is a part count followed by that many string
//! indices; a key is its parts joined with `/`. Strings are NUL-terminated
//! UTF-8, found by their offset from the start of the string area, in no
//! particular order. A key that ends `.<logical page>.<record id>.<size>` is a
//! *data reference*: it names the record `OBJECTS.DATA`'s descriptor table
//! lists as `<record id>` of `<size>` bytes in that logical page.
//!
//! The root is the logical page in the fourth u32 of the first mapping entry
//! of `INDEX.BTR`'s section ([`PageMap::first_entry_aux`]). Walking every
//! *mapped* index page instead of the tree from its root is wrong: pages the
//! tree no longer reaches stay mapped and still hold data references (23 on
//! the Perseverance repository, 4 on each Flare one).
//!
//! The Windows XP form keeps the index's mapping in `INDEX.MAP`, one XP-form section of its own, and names its root the
//! way Windows Server 2003 does (`VALIDATION.md` `WMI-9`). Windows Server 2003 R2 SP2 keeps
//! its index in `INDEX.BTR` mapped by the second section of `MAPPINGn.MAP` (XP-style four-byte entries), with
//! the page layout above except that the root is not in the mapping: it is the fourth u32 of logical page 0's
//! header (`VALIDATION.md` `WMI-8`).
//!
//! References: Joachim Metz, *WMI repository file format* (libyal/dtformats),
//! and the bytes of the repositories graded in `VALIDATION.md` `WMI-4`.
//! `dissect.cim` (AGPL-3.0) is an external grader of the result, never a
//! source of this code.

use crate::wmi_mapping::PageMap;
use std::collections::HashSet;

/// Bytes in one index page.
pub const INDEX_PAGE: usize = 8192;
/// The signature every index page starts with.
pub const INDEX_SIGNATURE: u32 = 0xACCC;
/// Ceiling on one `INDEX.BTR` read. The real ones are 4.5 to 5 MB.
pub const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

/// A data reference: (logical `OBJECTS.DATA` page, record id, record size).
pub type DataRef = (u32, u32, u32);

/// What the index tree, walked from its root, names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexedSet {
    pub refs: HashSet<DataRef>,
    pub pages_visited: usize,
    pub keys_total: usize,
    /// Keys containing a `.` whose tail is not three numbers: not data
    /// references, not counted as such.
    pub dotted_keys_not_references: usize,
}

/// What looking for `INDEX.BTR` beside `OBJECTS.DATA` came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexRead {
    /// The index was not read; the reason says why (no mapping, the XP form,
    /// not found, withheld, could not look, refused).
    Unread(String),
    /// The index was walked from its root.
    Read(IndexedSet),
}

impl Default for IndexRead {
    fn default() -> Self {
        IndexRead::Unread("no page mapping was read, so INDEX.BTR was not looked for".to_string())
    }
}

impl IndexRead {
    pub fn set(&self) -> Option<&IndexedSet> {
        match self {
            IndexRead::Read(s) => Some(s),
            IndexRead::Unread(_) => None,
        }
    }
}

fn u32_at(p: &[u8], at: usize) -> Option<u32> {
    let b = p.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u16_at(p: &[u8], at: usize) -> Option<usize> {
    let b = p.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]) as usize)
}

/// One decoded page: its own logical number, children and key strings.
struct Page {
    own: u32,
    children: Vec<u32>,
    keys: Vec<String>,
}

fn parse_page(p: &[u8]) -> Result<Page, String> {
    let bad = |what: &str| format!("an index page is truncated at its {what}");
    let sig = u32_at(p, 0).ok_or_else(|| bad("signature"))?;
    if sig != INDEX_SIGNATURE {
        return Err(format!(
            "an index page has signature {sig:#x}, not {INDEX_SIGNATURE:#x}"
        ));
    }
    let own = u32_at(p, 4).ok_or_else(|| bad("logical number"))?;
    let n = u32_at(p, 16).ok_or_else(|| bad("key count"))? as usize;
    // Each key costs 4 + 4 + 2 bytes before anything else.
    if n > INDEX_PAGE / 10 {
        return Err(format!(
            "an index page declares {n} keys, more than a page holds"
        ));
    }
    let mut o = 20 + 4 * n;
    let mut children = Vec::with_capacity(n + 1);
    for k in 0..=n {
        children.push(u32_at(p, o + 4 * k).ok_or_else(|| bad("child list"))?);
    }
    o += 4 * (n + 1);
    let mut offsets = Vec::with_capacity(n);
    for k in 0..n {
        offsets.push(u16_at(p, o + 2 * k).ok_or_else(|| bad("key offsets"))?);
    }
    o += 2 * n;
    let dts = u16_at(p, o).ok_or_else(|| bad("definition table size"))?;
    let mut table = Vec::with_capacity(dts);
    for k in 0..dts {
        table.push(u16_at(p, o + 2 + 2 * k).ok_or_else(|| bad("definition table"))?);
    }
    o += 2 + 2 * dts;
    let ns = u16_at(p, o).ok_or_else(|| bad("string count"))?;
    let mut soffs = Vec::with_capacity(ns + 1);
    for k in 0..=ns {
        soffs.push(u16_at(p, o + 2 + 2 * k).ok_or_else(|| bad("string offsets"))?);
    }
    let base = o + 2 + 2 * (ns + 1);
    let string = |i: usize| -> Result<String, String> {
        let off = *soffs
            .get(i)
            .ok_or_else(|| format!("a key names string {i} of {ns}"))?;
        let start = base
            .checked_add(off)
            .filter(|&s| s < p.len())
            .ok_or_else(|| format!("string {i} starts past the page"))?;
        let len = p[start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| format!("string {i} has no terminator inside the page"))?;
        Ok(String::from_utf8_lossy(&p[start..start + len]).into_owned())
    };
    let mut keys = Vec::with_capacity(n);
    for &off in &offsets {
        let count = *table
            .get(off)
            .ok_or_else(|| "a key offset is past the definition table".to_string())?;
        let mut parts = Vec::with_capacity(count);
        for j in 0..count {
            let idx = *table
                .get(off + 1 + j)
                .ok_or_else(|| "a key definition runs past the table".to_string())?;
            parts.push(string(idx)?);
        }
        keys.push(parts.join("/"));
    }
    Ok(Page {
        own,
        children,
        keys,
    })
}

/// The data reference a key ends in, when it ends in one.
fn data_reference(key: &str) -> Option<DataRef> {
    let mut it = key.rsplitn(4, '.');
    let size = it.next()?.parse().ok()?;
    let id = it.next()?.parse().ok()?;
    let page = it.next()?.parse().ok()?;
    it.next()?;
    Some((page, id, size))
}

/// Walk the index tree from its root and collect every data reference it
/// names, or say why it cannot be trusted.
///
/// Every page is reached through the mapping, must carry the signature and its
/// own logical number, and may be reached once: a page reached twice is a
/// cycle or a shared child, and either refuses the index rather than guess.
pub fn indexed_records(index: &[u8], map: &PageMap) -> Result<IndexedSet, String> {
    if !index.len().is_multiple_of(INDEX_PAGE) {
        return Err(format!(
            "INDEX.BTR is {} bytes, not a whole number of {INDEX_PAGE}-byte pages",
            index.len()
        ));
    }
    let physical_pages = index.len() / INDEX_PAGE;
    let accounted = map.physical_pages as usize;
    // A file longer than the mapping accounts for holds pages the mapping knows nothing of. A file
    // shorter is a file that was never extended to the mapping's trailing free pages (a Windows 11
    // index holds 643 of the 645 pages its mapping counts, the last two free); that is fine only if
    // every page past the end of the file is on the free list, so no logical page lives there.
    if accounted < physical_pages {
        return Err(format!(
            "the mapping accounts for {accounted} physical pages of INDEX.BTR but the file holds \
             {physical_pages}"
        ));
    }
    if let Some(missing) = (physical_pages..accounted).find(|&p| !map.free.contains(&(p as u32))) {
        return Err(format!(
            "the mapping accounts for {accounted} physical pages of INDEX.BTR but the file holds \
             {physical_pages}, and physical page {missing}, past its end, is not on the free list"
        ));
    }
    let root = if map.root_in_page_zero {
        // The Windows Server 2003 form: the root is named by the header of logical page 0.
        let phys = map
            .physical(0)
            .filter(|&p| p < physical_pages)
            .ok_or_else(|| "index page 0 is not mapped to a page of INDEX.BTR".to_string())?;
        u32_at(&index[phys * INDEX_PAGE..(phys + 1) * INDEX_PAGE], 12)
            .ok_or_else(|| "index page 0 is truncated at its root field".to_string())?
    } else {
        map.first_entry_aux
    };
    let mut out = IndexedSet::default();
    let mut seen: HashSet<u32> = HashSet::new();
    let mut stack = vec![root];
    while let Some(logical) = stack.pop() {
        if !seen.insert(logical) {
            return Err(format!(
                "index page {logical} is reached twice from the root, so the tree is not a tree"
            ));
        }
        if seen.len() > map.logical.len() {
            return Err("the index tree visits more pages than the mapping holds".to_string());
        }
        let phys = map
            .physical(logical as usize)
            .filter(|&p| p < physical_pages)
            .ok_or_else(|| format!("index page {logical} is not mapped to a page of INDEX.BTR"))?;
        let page = parse_page(&index[phys * INDEX_PAGE..(phys + 1) * INDEX_PAGE])
            .map_err(|e| format!("{e} (logical page {logical})"))?;
        if page.own != logical {
            return Err(format!(
                "the page mapped as logical {logical} names itself logical {}",
                page.own
            ));
        }
        out.keys_total += page.keys.len();
        for key in &page.keys {
            match data_reference(key) {
                Some(r) => {
                    out.refs.insert(r);
                }
                None if key.contains('.') => out.dotted_keys_not_references += 1,
                None => {}
            }
        }
        for &c in &page.children {
            if c != 0 && c != crate::wmi_mapping::UNMAPPED {
                stack.push(c);
            }
        }
    }
    out.pages_visited = seen.len();
    Ok(out)
}
