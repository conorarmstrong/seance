#![forbid(unsafe_code)]
//! HFS+ filesystem parser.
//!
//! Parses an HFS+ (or HFSX) volume presented as a whole-volume `DataSource` and
//! emits one `FileEntry` artifact per file/folder. Regular files carry an attached
//! content `DataSource` reconstructed from their data-fork extents.
//!
//! On-disk layout notes (all multi-byte fields are BIG-ENDIAN):
//! - Volume header lives at byte offset 1024.
//! - The catalog is a B-tree whose bytes are reconstructed from the catalog fork's
//!   extents. Node 0 is the header node; leaf nodes hold the file/folder records.
//!
//! References:
//! - Apple TN1150 "HFS Plus Volume Format".

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::{read_exact_or_fail, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use tracing::{debug, info, warn};

// --- Constants ---

// Volume header sits 1024 bytes into the volume (after boot blocks).
const VOLUME_HEADER_OFFSET: u64 = 1024;
const SIG_HFSPLUS: u16 = 0x482B; // "H+"
const SIG_HFSX: u16 = 0x4858; // "HX"

// Fork data offset within the volume header, and the catalog fork's position.
const VH_BLOCK_SIZE_OFFSET: usize = 40;
const VH_TOTAL_BLOCKS_OFFSET: usize = 44;
// HFSPlusVolumeHeader.allocationFile: the free/allocated block bitmap fork,
// TN1150 "HFS Plus Volume Header". Read to tell an orphaned deleted file's
// still-intact data blocks from ones already reallocated to something else.
const VH_ALLOCATION_FORK_OFFSET: usize = 112;
const VH_CATALOG_FORK_OFFSET: usize = 272;

// HFSPlusForkData is 80 bytes: logicalSize u64, clumpSize u32, totalBlocks u32,
// then 8 extent descriptors (startBlock u32, blockCount u32).
const FORK_DATA_SIZE: usize = 80;
const FORK_EXTENTS_OFFSET: usize = 16;
const FORK_EXTENT_COUNT: usize = 8;

// BTNodeDescriptor is 14 bytes at the start of every B-tree node.
const BTNODE_DESC_SIZE: usize = 14;
const NODE_KIND_LEAF: i8 = -1;
// BTNodeDescriptor.height is always 1 for a leaf node (TN1150 "B-Trees"):
// checked alongside `NODE_KIND_LEAF` when a candidate node's bytes have not
// already been reached by the live tree walk, so unrelated unallocated bytes
// that happen to carry a 0xFF kind byte still need a second, independent
// field to agree before they are read as a leaf node.
const NODE_HEIGHT_LEAF: u8 = 1;

// HFSPlusCatalogFile: fileID @8, dataFork (HFSPlusForkData) @88.
const CATALOG_FILE_DATAFORK_OFFSET: usize = 88;

// Catalog record types (first u16 of the record data).
const REC_FOLDER: u16 = 1;
const REC_FILE: u16 = 2;
const REC_FOLDER_THREAD: u16 = 3;
const REC_FILE_THREAD: u16 = 4;

// Reserved CNID range and the root folder CNID.
const ROOT_CNID: u32 = 2;
const FIRST_USER_CNID: u32 = 16;

// Seconds between the HFS/Mac epoch (1904-01-01) and the Unix epoch (1970-01-01).
// HFS+ catalog dates are u32 seconds since 1904, stored in GMT/UTC (TN1150).
const HFS_EPOCH_TO_UNIX: i64 = 2_082_844_800;

// Catalog date offsets within a folder/file record's data (shared layout):
//   createDate @ +12, contentModDate @ +16, attributeModDate @ +20,
//   accessDate @ +24, backupDate @ +28.
const CATALOG_CREATE_DATE_OFFSET: usize = 12;
const CATALOG_CONTENT_MOD_DATE_OFFSET: usize = 16;
const CATALOG_ACCESS_DATE_OFFSET: usize = 24;

/// `HFSPlusBSDInfo.ownerFlags` within a catalog file record: the `permissions`
/// structure begins at +32 and its `ownerFlags` byte is its tenth
/// (`ownerID` 4, `groupID` 4, `adminFlags` 1, then this). TN1150.
const CATALOG_OWNER_FLAGS_OFFSET: usize = 41;

/// `UF_COMPRESSED`. Set by the operating system when a file's data has been
/// moved into the `com.apple.decmpfs` extended attribute or its resource fork,
/// which leaves the **data fork empty by design**.
///
/// One byte is read for it, and it is worth reading because without it such a
/// file is published as a complete zero-byte file — technically a true
/// statement about the data fork, and read by anybody as "the file is empty".
/// The attributes B-tree this build does not walk is where the bytes are.
const UF_COMPRESSED: u8 = 0x20;

/// What an `UF_COMPRESSED` entry's empty data fork means.
const DECMPFS_NOTE: &str = concat!(
    "This file's `UF_COMPRESSED` flag is set, so the operating system moved its data into ",
    "the `com.apple.decmpfs` extended attribute or its resource fork and left the data fork ",
    "empty. This build walks neither the attributes B-tree nor resource forks, so the ",
    "content is NOT recovered — and the data fork being zero bytes is not the file being ",
    "empty. Its size, as the catalog records it, is the data fork's; the real length is in ",
    "the decmpfs header this build does not read."
);

/// Convert an HFS+ catalog date (u32 seconds since 1904-01-01, GMT) to an RFC
/// 3339 string. Returns `None` for the 0 "unset" sentinel so an unset field is
/// omitted rather than surfaced as a fabricated 1904 timestamp (BUG-102).
fn hfs_date_to_rfc3339(hfs: u32) -> Option<String> {
    if hfs == 0 {
        return None;
    }
    let unix = hfs as i64 - HFS_EPOCH_TO_UNIX;
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix, 0).map(|dt| dt.to_rfc3339())
}

// Safety limits to bound work on corrupt volumes.
const MAX_CATALOG_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CONTENT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RECORDS_PER_NODE: usize = 8192;
const MAX_PATH_DEPTH: usize = 256;
// 64 MiB of bitmap is 512M bits, i.e. up to a 2 TiB volume at a 4 KiB block
// size -- ample for the images this build is run against; a bigger volume's
// bitmap is read only up to this cap; a block the cap fell short of reads as
// "could not check" (see `bit_is_allocated`), never as "free".
const MAX_ALLOCATION_BYTES: u64 = 64 * 1024 * 1024;
// Bounds the orphaned-catalog-leaf sweep of unallocated space to at most this
// many allocation blocks so a corrupt/implausible `totalBlocks` field cannot
// turn the pass into an unbounded scan; a volume larger than this is swept
// only up to the cap, and that shortfall is reported (never presented as "the
// rest of the volume held no deleted files").
const MAX_ORPHAN_SCAN_BLOCKS: usize = 1_000_000;
// A legitimate inline (non-overflow) data-fork extent describes at most a
// `MAX_CONTENT_BYTES`-sized run; anything claiming far more blocks than that
// is corrupt/implausible input, not a file to walk block-by-block when
// checking its allocation status.
const MAX_EXTENT_BLOCKS_TO_CHECK: u32 = 1_000_000;

// --- Big-endian slice helpers (panic-free on short/corrupt input) ---

fn be_u16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn be_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn be_u64(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8)
        .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Decode an HFSUniStr255 at `off`: a u16 code-unit count followed by that many
/// UTF-16BE code units. Returns the decoded string. Empty names (thread keys)
/// yield an empty string.
fn decode_hfs_name(d: &[u8], off: usize) -> Option<String> {
    let len = be_u16(d, off)? as usize;
    // HFSUniStr255 caps at 255 code units; clamp defensively.
    let n = len.min(255);
    let mut units = Vec::with_capacity(n);
    for i in 0..n {
        units.push(be_u16(d, off + 2 + i * 2)?);
    }
    Some(String::from_utf16_lossy(&units))
}

// Structural reads go through `seance_core::io::read_exact_or_fail` (BUG-104): a
// truncated/corrupt extent must surface as an error, never be silently
// zero-filled and served as legitimate catalog/file content.

// --- Data Structures ---

/// A data fork: its logical byte size plus the non-empty extents backing it.
#[derive(Debug, Clone)]
struct ForkData {
    logical_size: u64,
    /// (startBlock, blockCount) pairs with blockCount > 0.
    extents: Vec<(u32, u32)>,
}

/// Parse an 80-byte HFSPlusForkData structure.
fn parse_fork(d: &[u8]) -> Option<ForkData> {
    if d.len() < FORK_DATA_SIZE {
        return None;
    }
    let logical_size = be_u64(d, 0)?;
    let mut extents = Vec::new();
    for i in 0..FORK_EXTENT_COUNT {
        let base = FORK_EXTENTS_OFFSET + i * 8;
        let start = be_u32(d, base)?;
        let count = be_u32(d, base + 4)?;
        if count > 0 {
            extents.push((start, count));
        }
    }
    Some(ForkData {
        logical_size,
        extents,
    })
}

struct VolumeHeader {
    signature: u16,
    block_size: u32,
    total_blocks: u32,
    catalog_fork: ForkData,
    /// The free/allocated block bitmap fork. Zero-sized on a synthetic volume
    /// that never set one; the orphaned-file recovery pass then simply does
    /// not run (see `reconstruct_allocation_bitmap`).
    allocation_fork: ForkData,
}

fn parse_volume_header(ds: &dyn DataSource) -> Result<VolumeHeader, ModuleError> {
    // The volume header is 512 bytes; the catalog fork ends at offset 272+80=352.
    let mut hdr = vec![0u8; 512];
    read_exact_or_fail(ds, VOLUME_HEADER_OFFSET, &mut hdr, "HFS+ volume header")?;

    let signature =
        be_u16(&hdr, 0).ok_or_else(|| ModuleError::ParsingError("short volume header".into()))?;
    if signature != SIG_HFSPLUS && signature != SIG_HFSX {
        return Err(ModuleError::ParsingError(format!(
            "invalid HFS+ signature: 0x{:04X}",
            signature
        )));
    }

    let block_size = be_u32(&hdr, VH_BLOCK_SIZE_OFFSET)
        .ok_or_else(|| ModuleError::ParsingError("missing block size".into()))?;
    let total_blocks = be_u32(&hdr, VH_TOTAL_BLOCKS_OFFSET).unwrap_or(0);

    if block_size == 0 || (block_size as usize) < BTNODE_DESC_SIZE {
        return Err(ModuleError::ParsingError(format!(
            "implausible block size: {}",
            block_size
        )));
    }

    let catalog_fork = parse_fork(&hdr[VH_CATALOG_FORK_OFFSET..])
        .ok_or_else(|| ModuleError::ParsingError("could not parse catalog fork".into()))?;
    // The header buffer is 512 bytes and this fork's 80 bytes sit well inside
    // it (112+80 = 192 < 512), so this cannot fail for the same reason the
    // catalog fork parse above cannot; kept fallible rather than `.unwrap()`
    // on principle, since `hdr`'s length is a compile-time literal, not a
    // proof `parse_fork` will never change.
    let allocation_fork = parse_fork(&hdr[VH_ALLOCATION_FORK_OFFSET..])
        .ok_or_else(|| ModuleError::ParsingError("could not parse allocation fork".into()))?;

    Ok(VolumeHeader {
        signature,
        block_size,
        total_blocks,
        catalog_fork,
        allocation_fork,
    })
}

/// Concatenate a fork's extents into a contiguous byte buffer, truncated to its
/// logical size. Used to reconstruct the catalog B-tree from the volume.
///
/// Returns `(bytes, complete)`. `complete` is false when the reconstruction fell
/// short of `fork.logical_size` — the volume header only carries the first eight
/// extent descriptors, so a fragmented fork continues in the extents-overflow
/// B-tree (not followed here), and a truncated image simply runs out. Callers
/// must not present what they parsed out of a short reconstruction as a whole
/// result (BUG-275).
fn read_fork_bytes(
    ds: &dyn DataSource,
    block_size: u32,
    fork: &ForkData,
    cap: u64,
) -> Result<(Vec<u8>, bool), ModuleError> {
    let logical = fork.logical_size;
    if logical == 0 {
        return Err(ModuleError::ParsingError("fork is empty".into()));
    }
    if logical > cap {
        return Err(ModuleError::ParsingError(format!(
            "fork size {} exceeds cap {}",
            logical, cap
        )));
    }

    let ds_size = ds.size();
    let mut buf = Vec::with_capacity(logical as usize);
    for (start, count) in &fork.extents {
        let have = buf.len() as u64;
        if have >= logical {
            break;
        }
        // blockCount * block_size is attacker-controlled and can be astronomically
        // large (a 512 GB extent from a 1.7 KB volume). Use checked arithmetic and
        // read at most what the fork still needs (remaining logical size) and what
        // the volume physically holds past this extent's start — an extent can
        // never exceed the data source. This bounds the allocation to the smaller
        // of the (already capped) logical size and the real source length.
        let phys = (*start as u64)
            .checked_mul(block_size as u64)
            .ok_or_else(|| ModuleError::ParsingError("extent physical offset overflows".into()))?;
        let ext_len = (*count as u64)
            .checked_mul(block_size as u64)
            .ok_or_else(|| ModuleError::ParsingError("extent byte length overflows".into()))?;
        let to_read = ext_len
            .min(logical - have)
            .min(ds_size.saturating_sub(phys));
        if to_read == 0 {
            continue;
        }
        let mut chunk = vec![0u8; to_read as usize];
        read_exact_or_fail(ds, phys, &mut chunk, "HFS+ fork extent")?;
        buf.extend_from_slice(&chunk);
    }
    buf.truncate(logical as usize);
    let complete = buf.len() as u64 == logical;
    Ok((buf, complete))
}

/// A file or folder discovered in the catalog leaf records.
struct CatalogEntry {
    cnid: u32,
    parent_cnid: u32,
    name: String,
    is_directory: bool,
    size: u64,
    data_fork: Option<ForkData>,
    /// Catalog MAC times (RFC 3339, UTC), omitted when unset (BUG-102).
    created: Option<String>,
    modified: Option<String>,
    accessed: Option<String>,
    /// `UF_COMPRESSED` in the record's own `permissions.ownerFlags`: the
    /// file's data is in an extended attribute or its resource fork, and its
    /// data fork is empty by design.
    compressed: bool,
}

/// Read (create, contentMod, access) dates from a folder/file catalog record's
/// data area and convert each to RFC 3339. Both record types share these offsets.
fn parse_catalog_dates(
    record: &[u8],
    data_off: usize,
) -> (Option<String>, Option<String>, Option<String>) {
    let created =
        be_u32(record, data_off + CATALOG_CREATE_DATE_OFFSET).and_then(hfs_date_to_rfc3339);
    let modified =
        be_u32(record, data_off + CATALOG_CONTENT_MOD_DATE_OFFSET).and_then(hfs_date_to_rfc3339);
    let accessed =
        be_u32(record, data_off + CATALOG_ACCESS_DATE_OFFSET).and_then(hfs_date_to_rfc3339);
    (created, modified, accessed)
}

/// Result of scanning all leaf nodes: the emittable entries plus a
/// CNID -> (parent CNID, name) map built from thread records for path building.
struct CatalogScan {
    entries: Vec<CatalogEntry>,
    thread_map: HashMap<u32, (u32, String)>,
    /// The B-tree's own node size (`BTHeaderRec.nodeSize`), kept so the
    /// orphaned-leaf-node sweep of unallocated space reads candidate nodes at
    /// the SAME size this tree actually uses, rather than guessing one.
    node_size: usize,
}

/// Walk every leaf node of the catalog B-tree, collecting file/folder records and
/// thread records.
fn scan_catalog(catalog: &[u8]) -> Result<CatalogScan, ModuleError> {
    // BTHeaderRec lives at offset 14 within node 0 (the header node).
    let node_size = be_u16(catalog, BTNODE_DESC_SIZE + 18)
        .ok_or_else(|| ModuleError::ParsingError("missing B-tree nodeSize".into()))?
        as usize;
    let first_leaf = be_u32(catalog, BTNODE_DESC_SIZE + 10)
        .ok_or_else(|| ModuleError::ParsingError("missing firstLeafNode".into()))?;

    if node_size < BTNODE_DESC_SIZE + 2 || catalog.len() < node_size {
        return Err(ModuleError::ParsingError(format!(
            "implausible node size: {}",
            node_size
        )));
    }

    let total_nodes = catalog.len() / node_size;
    let mut entries = Vec::new();
    let mut thread_map: HashMap<u32, (u32, String)> = HashMap::new();

    // Follow the leaf chain via each node's fLink; bound iterations by the node
    // count so a corrupt fLink cycle cannot loop forever.
    let mut node_num = first_leaf as usize;
    let mut visited = 0usize;
    while node_num != 0 && visited < total_nodes {
        visited += 1;

        let node_start = node_num * node_size;
        let node_end = node_start + node_size;
        if node_end > catalog.len() {
            break;
        }
        let node = &catalog[node_start..node_end];

        let kind = node[8] as i8;
        let f_link = be_u32(node, 0).unwrap_or(0);
        if kind != NODE_KIND_LEAF {
            node_num = f_link as usize;
            continue;
        }

        parse_leaf_node_records(node, node_size, &mut entries, &mut thread_map);

        node_num = f_link as usize;
    }

    Ok(CatalogScan {
        entries,
        thread_map,
        node_size,
    })
}

/// Decode every record in one already-identified LEAF node's record-offset
/// array, routing each into `entries` or `thread_map` via `parse_catalog_record`
/// -- the SAME decoder the live catalog walk above and the orphaned-leaf-node
/// recovery pass below both use, so the two can never silently diverge on what
/// counts as a valid record. Returns how many new file/folder entries this
/// node yielded, so a caller validating a *candidate* node found sitting in
/// unallocated space (whose kind/height bytes alone only say it is
/// leaf-shaped, not that it is genuine) can require at least one real record
/// before trusting it.
fn parse_leaf_node_records(
    node: &[u8],
    node_size: usize,
    entries: &mut Vec<CatalogEntry>,
    thread_map: &mut HashMap<u32, (u32, String)>,
) -> usize {
    let entries_before = entries.len();
    let num_records = be_u16(node, 10).unwrap_or(0) as usize;
    let num_records = num_records.min(MAX_RECORDS_PER_NODE);

    for i in 0..num_records {
        // Record offset array grows backward from the node end: the offset of
        // record i sits at node_size - 2*(i+1); record i spans [off_i, off_{i+1}).
        // Stop once the offset slot for this record would fall before the start
        // of the node: with an attacker-controlled numRecords and a small
        // node_size, node_size - 2*(i+2) would underflow (debug panic).
        if 2 * (i + 2) > node_size {
            break;
        }
        let off_i = match be_u16(node, node_size - 2 * (i + 1)) {
            Some(v) => v as usize,
            None => break,
        };
        let off_next = match be_u16(node, node_size - 2 * (i + 2)) {
            Some(v) => v as usize,
            None => break,
        };
        if off_next <= off_i || off_next > node.len() {
            continue;
        }
        let record = &node[off_i..off_next];
        parse_catalog_record(record, entries, thread_map);
    }

    entries.len() - entries_before
}

/// Parse one catalog record (key followed by data) and route it to the entry list
/// or the thread map.
fn parse_catalog_record(
    record: &[u8],
    entries: &mut Vec<CatalogEntry>,
    thread_map: &mut HashMap<u32, (u32, String)>,
) {
    // HFSPlusCatalogKey: keyLength u16 @0 (length of the rest of the key), then
    // parentID u32 @2, then nodeName (HFSUniStr255) @6. Data follows the key at
    // offset 2 + keyLength (always even since keyLength = 6 + 2*nameLen).
    let key_length = match be_u16(record, 0) {
        Some(v) => v as usize,
        None => return,
    };
    let key_parent = match be_u32(record, 2) {
        Some(v) => v,
        None => return,
    };
    let key_name = decode_hfs_name(record, 6).unwrap_or_default();

    let data_off = 2 + key_length;
    let record_type = match be_u16(record, data_off) {
        Some(v) => v,
        None => return,
    };

    match record_type {
        REC_FOLDER => {
            // HFSPlusCatalogFolder: folderID u32 @8 within the data.
            if let Some(folder_id) = be_u32(record, data_off + 8) {
                let (created, modified, accessed) = parse_catalog_dates(record, data_off);
                entries.push(CatalogEntry {
                    cnid: folder_id,
                    parent_cnid: key_parent,
                    name: key_name,
                    is_directory: true,
                    size: 0,
                    data_fork: None,
                    created,
                    modified,
                    accessed,
                    // A folder record's `permissions` has no meaning here.
                    compressed: false,
                });
            }
        }
        REC_FILE => {
            // HFSPlusCatalogFile: fileID u32 @8, dataFork (HFSPlusForkData) @88.
            let file_id = match be_u32(record, data_off + 8) {
                Some(v) => v,
                None => return,
            };
            let (created, modified, accessed) = parse_catalog_dates(record, data_off);
            let fork_start = data_off + CATALOG_FILE_DATAFORK_OFFSET;
            let data_fork = record.get(fork_start..).and_then(parse_fork);
            let size = data_fork.as_ref().map(|f| f.logical_size).unwrap_or(0);
            // One byte that decides whether an empty data fork means an empty
            // file. See `UF_COMPRESSED`.
            let compressed = record
                .get(data_off + CATALOG_OWNER_FLAGS_OFFSET)
                .is_some_and(|f| f & UF_COMPRESSED != 0);
            entries.push(CatalogEntry {
                cnid: file_id,
                parent_cnid: key_parent,
                name: key_name,
                is_directory: false,
                size,
                data_fork,
                created,
                modified,
                accessed,
                compressed,
            });
        }
        REC_FOLDER_THREAD | REC_FILE_THREAD => {
            // HFSPlusCatalogThread: parentID u32 @4, nodeName @8 within the data.
            // The record KEY's parentID is the object's OWN CNID; the data holds
            // the real parent CNID and name.
            let own_cnid = key_parent;
            if let (Some(parent), Some(name)) = (
                be_u32(record, data_off + 4),
                decode_hfs_name(record, data_off + 8),
            ) {
                thread_map.insert(own_cnid, (parent, name));
            }
        }
        _ => {}
    }
}

/// Build the absolute path of an object's PARENT directory by walking the thread
/// map from `parent_cnid` up to the root. Returns "/" for objects at the root.
fn build_parent_path(parent_cnid: u32, thread_map: &HashMap<u32, (u32, String)>) -> String {
    let mut comps: Vec<&str> = Vec::new();
    let mut cur = parent_cnid;
    let mut depth = 0;
    while cur != ROOT_CNID && depth < MAX_PATH_DEPTH {
        match thread_map.get(&cur) {
            Some((parent, name)) => {
                comps.push(name.as_str());
                cur = *parent;
                depth += 1;
            }
            None => break, // broken chain: emit what we have
        }
    }
    comps.reverse();
    if comps.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", comps.join("/"))
    }
}

// --- Deleted-file recovery: orphaned catalog leaf nodes in unallocated space ---
//
// HFS+ deletion removes the catalog record itself -- unlike ext, which clears
// an inode's block pointers but leaves the dirent in place. What HFS+ leaves
// behind is the data blocks the removed record pointed to (freed but not
// zeroed) and, if the B-tree was rebalanced afterward rather than that node
// reused where it stood, the leaf node's own bytes: descriptor, key and all,
// sitting untouched in whatever is now unallocated space. ROADMAP §5.6.

/// Reconstruct the volume's allocation-file bitmap (one bit per allocation
/// block, TN1150 "Volume Bitmap") from its fork descriptor in the volume
/// header. `None` when the fork is empty -- a synthetic/test volume that never
/// set one, or a real one this build could not even start to read -- so the
/// orphaned-catalog-leaf sweep that depends on it simply does not run, rather
/// than treat "never checked" as "free".
fn reconstruct_allocation_bitmap(
    ds: &dyn DataSource,
    block_size: u32,
    fork: &ForkData,
) -> Option<Vec<u8>> {
    if fork.logical_size == 0 {
        return None;
    }
    match read_fork_bytes(ds, block_size, fork, MAX_ALLOCATION_BYTES) {
        Ok((bytes, complete)) => {
            if !complete {
                warn!(
                    "HFS+ allocation bitmap reconstruction is short: {} of {} bytes; blocks \
                     beyond that point read as 'could not check', never as free",
                    bytes.len(),
                    fork.logical_size
                );
            }
            Some(bytes)
        }
        Err(e) => {
            warn!(
                "HFS+ allocation bitmap could not be reconstructed, so the orphaned-catalog-leaf \
                 recovery pass will not run: {}",
                e
            );
            None
        }
    }
}

/// Whether allocation block `block` is marked allocated (`true`) or free
/// (`false`) in a reconstructed allocation-file bitmap. TN1150: bit N of the
/// file is bit `(7 - N % 8)` of byte `N / 8`, most-significant bit first, and
/// a set bit means "in use". `None` when the reconstruction never reached
/// this block -- kept distinct from `Some(false)` ("known free") so a short
/// bitmap can never be read as proof of free space.
fn bit_is_allocated(bitmap: &[u8], block: u32) -> Option<bool> {
    let byte = bitmap.get((block / 8) as usize)?;
    let bit = 7 - (block % 8);
    Some((byte >> bit) & 1 == 1)
}

/// How the data behind a recovered deleted file's extents stands, checked
/// against the volume's allocation bitmap. The three outcomes are kept
/// distinct on purpose (forensic-honesty invariant): "not touched since
/// deletion" is never conflated with "reallocated" or with "could not tell".
enum RecoveredContentStatus {
    /// Every block the extents name is still marked free: the bytes have not
    /// been touched since deletion, and reading them back serves this file's
    /// own content.
    Intact,
    /// At least one named block is now marked allocated: it may already hold
    /// another file's bytes, so none of the extents are read and nothing is
    /// presented as this file's content.
    Reallocated,
    /// The extents could not be checked at all -- past the volume's own
    /// `totalBlocks`, an overflowing start+count, an implausibly large single
    /// extent, or simply beyond what the bitmap reconstruction reached.
    /// Carries the reason so it lands on the record, not just in a log.
    Inconsistent(String),
}

/// Check every block an orphaned file's (inline, in-catalog-record) data-fork
/// extents name against the volume's allocation bitmap. See
/// [`RecoveredContentStatus`] for why the three outcomes never collapse into
/// each other.
fn recovered_content_status(
    fork: &ForkData,
    total_blocks: u32,
    bitmap: &[u8],
) -> RecoveredContentStatus {
    for (start, count) in &fork.extents {
        if *count > MAX_EXTENT_BLOCKS_TO_CHECK {
            return RecoveredContentStatus::Inconsistent(format!(
                "extent block count {count} exceeds the {MAX_EXTENT_BLOCKS_TO_CHECK}-block sanity cap"
            ));
        }
        let end = match start.checked_add(*count) {
            Some(e) => e,
            None => {
                return RecoveredContentStatus::Inconsistent(format!(
                    "extent start block {start} + count {count} overflows"
                ))
            }
        };
        if end > total_blocks {
            return RecoveredContentStatus::Inconsistent(format!(
                "extent [{start}, {end}) reaches past the volume's {total_blocks} total blocks"
            ));
        }
        for block in *start..end {
            match bit_is_allocated(bitmap, block) {
                Some(true) => return RecoveredContentStatus::Reallocated,
                Some(false) => {}
                None => {
                    return RecoveredContentStatus::Inconsistent(format!(
                        "allocation bitmap reconstruction does not reach block {block}"
                    ))
                }
            }
        }
    }
    RecoveredContentStatus::Intact
}

/// One file or folder whose catalog record was found orphaned in unallocated
/// space, reachable through no live B-tree walk.
struct OrphanedCatalogEntry {
    entry: CatalogEntry,
    /// Physical byte offset of the leaf node the record was recovered from --
    /// this recovery's own provenance, kept on the record the same way a
    /// carved file keeps its carving offset.
    node_offset: u64,
}

/// Result of sweeping the volume's unallocated blocks for orphaned catalog
/// leaf nodes.
struct OrphanScanResult {
    entries: Vec<OrphanedCatalogEntry>,
    /// True when `totalBlocks` exceeds `MAX_ORPHAN_SCAN_BLOCKS` and the sweep
    /// stopped short of covering the whole volume.
    capped: bool,
    blocks_scanned: u64,
}

/// Sweep the volume's unallocated blocks for a leaf node that looks like an
/// orphaned fragment of the catalog B-tree: a node descriptor whose kind and
/// height match a leaf (TN1150 "B-Trees"), sitting entirely in blocks the
/// allocation bitmap marks free, that decodes at least one real file/folder
/// record through `parse_leaf_node_records` -- the SAME decoder the live tree
/// walk in `scan_catalog` uses, so a byte pattern that decoder would reject
/// cannot pass here either.
///
/// A CNID still present in `live_cnids` is not reported as an orphan: it is
/// reachable from the live tree, so this candidate's bytes -- whatever they
/// are -- are not evidence of a deletion.
fn scan_unallocated_for_orphaned_catalog_leaves(
    ds: &dyn DataSource,
    block_size: u32,
    total_blocks: u32,
    node_size: usize,
    bitmap: &[u8],
    live_cnids: &HashSet<u32>,
) -> OrphanScanResult {
    let mut entries = Vec::new();
    let node_size_u64 = node_size as u64;
    if node_size < BTNODE_DESC_SIZE + 2
        || block_size == 0
        || !node_size_u64.is_multiple_of(block_size as u64)
    {
        // A node smaller than its own descriptor, or one that does not sit on
        // whole allocation blocks, is not a shape this volume could actually
        // have written; nothing to sweep for.
        return OrphanScanResult {
            entries,
            capped: false,
            blocks_scanned: 0,
        };
    }
    let blocks_per_node = node_size_u64 / block_size as u64;
    let ds_size = ds.size();
    let scan_limit = (total_blocks as u64).min(MAX_ORPHAN_SCAN_BLOCKS as u64);
    let capped = scan_limit < total_blocks as u64;

    let mut block = 0u64;
    while block + blocks_per_node <= scan_limit {
        let all_free = (block..block + blocks_per_node)
            .all(|b| bit_is_allocated(bitmap, b as u32) == Some(false));
        if !all_free {
            block += 1;
            continue;
        }

        let phys = block * block_size as u64;
        if phys + node_size_u64 > ds_size {
            block += 1;
            continue;
        }
        let mut node = vec![0u8; node_size];
        let read_ok = matches!(ds.read_at(phys, &mut node), Ok(n) if n == node_size);
        if !read_ok {
            block += 1;
            continue;
        }

        let looks_like_leaf =
            node[8] as i8 == NODE_KIND_LEAF && node.get(9) == Some(&NODE_HEIGHT_LEAF);
        if looks_like_leaf {
            let mut node_entries = Vec::new();
            let mut node_threads = HashMap::new();
            let yielded =
                parse_leaf_node_records(&node, node_size, &mut node_entries, &mut node_threads);
            if yielded > 0 {
                let mut matched = false;
                for e in node_entries {
                    // An empty name is a thread record's key, not a real
                    // file/folder; a CNID the live tree still holds is not an
                    // orphan of anything.
                    if e.name.is_empty() || live_cnids.contains(&e.cnid) {
                        continue;
                    }
                    matched = true;
                    entries.push(OrphanedCatalogEntry {
                        entry: e,
                        node_offset: phys,
                    });
                }
                if matched {
                    block += blocks_per_node;
                    continue;
                }
            }
        }
        block += 1;
    }

    OrphanScanResult {
        entries,
        capped,
        blocks_scanned: scan_limit,
    }
}

// --- Module Implementation ---

pub struct HfsPlusParser;

impl ForensicsModule for HfsPlusParser {
    fn id(&self) -> &str {
        "plugin.filesystem.hfsplus"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileSystem]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Gate: only run on HFS+ filesystem artifacts.
        let subtype = artifact.subtype();
        let fs_type = artifact
            .metadata
            .get("filesystem_type")
            .and_then(|v| v.as_str());
        let applies = subtype == Some("hfsplus")
            || fs_type
                .map(|s| {
                    s.eq_ignore_ascii_case("HFS+")
                        || s.eq_ignore_ascii_case("HFSPLUS")
                        || s.eq_ignore_ascii_case("HFSX")
                })
                .unwrap_or(false);
        if !applies {
            return Ok(Vec::new());
        }

        info!(
            "HFS+ parser processing filesystem artifact ID: {}",
            artifact.id
        );

        let ds = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("HFS+ parser requires a data source".to_string())
        })?;

        let vh = parse_volume_header(ds.as_ref())?;
        info!(
            "HFS+: signature=0x{:04X}, blockSize={}, totalBlocks={}, catalogSize={}",
            vh.signature, vh.block_size, vh.total_blocks, vh.catalog_fork.logical_size
        );

        // Reconstruct the catalog B-tree bytes, then walk its leaf nodes.
        let (catalog, catalog_complete) = read_fork_bytes(
            ds.as_ref(),
            vh.block_size,
            &vh.catalog_fork,
            MAX_CATALOG_BYTES,
        )?;
        if !catalog_complete {
            warn!(
                "HFS+ catalog reconstruction is short: {} of {} bytes (only the volume header's \
                 eight extent descriptors are followed); the file list is not complete",
                catalog.len(),
                vh.catalog_fork.logical_size
            );
        }
        let scan = scan_catalog(&catalog)?;

        let mut produced = Vec::new();
        let mut slack_candidates = Vec::new();
        for entry in &scan.entries {
            // Skip reserved CNIDs (root, special files); their threads are still
            // used for path building above.
            if entry.cnid < FIRST_USER_CNID {
                continue;
            }

            let parent_path = build_parent_path(entry.parent_cnid, &scan.thread_map);
            let path = if parent_path == "/" {
                format!("/{}", entry.name)
            } else {
                format!("{}/{}", parent_path, entry.name)
            };

            let mut metadata = json!({
                "name": entry.name,
                "path": path,
                "parent_path": parent_path,
                "cnid": entry.cnid,
                "parent_cnid": entry.parent_cnid,
                "is_directory": entry.is_directory,
                "size": entry.size,
                "filesystem_type": "HFS+",
            });

            // The catalog B-tree we walked is shorter than its logical size, so
            // this listing is a prefix of the volume's real file list. Say so on
            // every entry it produced — "we stopped early" must never look the
            // same as "that was all there was" (BUG-275). Directories carry the
            // established listing flag too: their children may simply not have
            // been reached.
            if !catalog_complete {
                metadata["catalog_incomplete"] = json!(true);
                metadata["catalog_incomplete_reason"] = json!(IncompleteReason::ShortRead.as_str());
                // `catalog_incomplete` is HFS+-specific and nothing outside this
                // crate reads it. `inventory_incomplete` is the key the API,
                // export and cross-plugin honesty paths key on for a short
                // listing — the same convention `build_file_content` below
                // already follows with `content_incomplete` (B3-018). Both are
                // stamped: the bespoke key stays for any existing consumer.
                metadata["inventory_incomplete"] = json!(true);
                metadata["inventory_incomplete_reason"] =
                    json!(IncompleteReason::ShortRead.as_str());
                if entry.is_directory {
                    metadata["directory_parse_incomplete"] = json!(true);
                }
            }

            // HFS+ catalog MAC times are stored in GMT/UTC (BUG-102). Surface
            // them as RFC 3339 for the timeline / sort-by-date; omit unset ones.
            if let Some(ref t) = entry.created {
                metadata["created"] = json!(t);
            }
            if let Some(ref t) = entry.modified {
                metadata["modified"] = json!(t);
            }
            if let Some(ref t) = entry.accessed {
                metadata["accessed"] = json!(t);
            }

            // Attach content for regular files from their data-fork extents.
            let content: Option<Arc<dyn DataSource>> = if entry.is_directory {
                None
            } else if let Some(fork) = &entry.data_fork {
                build_file_content(ds, vh.block_size, fork, &mut metadata)
            } else {
                None
            };

            // A compressed file's data fork is empty BY DESIGN — the bytes are
            // in the `com.apple.decmpfs` attribute or the resource fork, and
            // this build walks neither. Without this the record was a complete
            // zero-byte file: a true statement about the data fork, and read
            // by anybody as "the file is empty".
            if entry.compressed && !entry.is_directory {
                metadata["compression"] = json!("hfsplus_decmpfs");
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] =
                    json!(IncompleteReason::Compressed.as_str());
                metadata["content_incomplete_detail"] = json!(DECMPFS_NOTE);
                // The data fork's own length, kept so the two are not confused:
                // it is genuinely zero, and it is not the file's size.
                metadata["data_fork_logical_size"] = json!(entry.size);
            }

            let file_entry =
                Artifact::new(artifact.case_id, ArtifactType::FileEntry, content, metadata)
                    .with_parent(artifact.id);
            if !entry.is_directory {
                if let Some(fork) = &entry.data_fork {
                    slack_candidates.push((
                        file_entry.id,
                        entry.name.clone(),
                        path.clone(),
                        fork,
                        entry.compressed,
                    ));
                }
            }
            produced.push(file_entry);
        }

        info!("HFS+ parser produced {} file entries", produced.len());

        // Sweep unallocated space for orphaned catalog leaf nodes: HFS+
        // deletion removes the catalog record but not the data blocks it
        // named or (when the tree was rebalanced rather than the node reused
        // in place) the leaf node's own bytes. ROADMAP §5.6. Requires the
        // allocation bitmap; a volume that never set one (or one this build
        // could not reconstruct at all) simply gets no recovery pass.
        if let Some(bitmap) =
            reconstruct_allocation_bitmap(ds.as_ref(), vh.block_size, &vh.allocation_fork)
        {
            let live_cnids: HashSet<u32> = scan.entries.iter().map(|e| e.cnid).collect();
            let orphan_scan = scan_unallocated_for_orphaned_catalog_leaves(
                ds.as_ref(),
                vh.block_size,
                vh.total_blocks,
                scan.node_size,
                &bitmap,
                &live_cnids,
            );

            if orphan_scan.capped {
                warn!(
                    "HFS+ orphaned-catalog sweep capped at {} of {} blocks; deleted files beyond \
                     that point were not searched for",
                    orphan_scan.blocks_scanned, vh.total_blocks
                );
            }

            let mut recovered = 0usize;
            for orphan in &orphan_scan.entries {
                let entry = &orphan.entry;
                if entry.cnid < FIRST_USER_CNID {
                    continue;
                }

                let parent_path = build_parent_path(entry.parent_cnid, &scan.thread_map);
                let path = if parent_path == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{}/{}", parent_path, entry.name)
                };

                // `deleted` + `deleted_recovery_source` match the convention
                // the FAT and ext4 readers already use for their own
                // undelete recoveries, so a consumer that already knows to
                // keep those out of the normal file listing keeps this one
                // out too, without a fourth bespoke flag to learn.
                let mut metadata = json!({
                    "name": entry.name,
                    "path": path,
                    "parent_path": parent_path,
                    "cnid": entry.cnid,
                    "parent_cnid": entry.parent_cnid,
                    "is_directory": entry.is_directory,
                    "size": entry.size,
                    "filesystem_type": "HFS+",
                    "deleted": true,
                    "deleted_recovery_source": "hfsplus_orphaned_catalog_leaf",
                    "deleted_recovery_leaf_node_offset": orphan.node_offset,
                });
                if let Some(ref t) = entry.created {
                    metadata["created"] = json!(t);
                }
                if let Some(ref t) = entry.modified {
                    metadata["modified"] = json!(t);
                }
                if let Some(ref t) = entry.accessed {
                    metadata["accessed"] = json!(t);
                }

                // Three, and only three, outcomes -- and each says plainly
                // which it is (task requirement, and the forensic-honesty
                // invariant that recovered evidence never reads as more
                // certain than it is):
                //   (a) content_recovered -- blocks unallocated and intact.
                //   (b) content_not_recoverable_reallocated -- a block now
                //       belongs to something else; nothing is read from it.
                //   (c) content_not_recoverable_unreadable -- the extents
                //       themselves could not be checked or trusted.
                let content: Option<Arc<dyn DataSource>> = if entry.is_directory {
                    None
                } else if let Some(fork) = &entry.data_fork {
                    if fork.logical_size == 0 {
                        metadata["deleted_recovery_status"] = json!("content_recovered");
                        Some(Arc::new(seance_core::data_source::ByteSliceDataSource::new(
                            Vec::new(),
                        )) as Arc<dyn DataSource>)
                    } else {
                        match recovered_content_status(fork, vh.total_blocks, &bitmap) {
                            RecoveredContentStatus::Intact => {
                                metadata["deleted_recovery_status"] = json!("content_recovered");
                                build_file_content(ds, vh.block_size, fork, &mut metadata)
                            }
                            RecoveredContentStatus::Reallocated => {
                                metadata["deleted_recovery_status"] =
                                    json!("content_not_recoverable_reallocated");
                                metadata["deleted_content_caveat"] =
                                    json!("blocks_reallocated_to_another_file");
                                metadata["content_incomplete"] = json!(true);
                                metadata["content_incomplete_reason"] =
                                    json!(IncompleteReason::UnresolvedStructure.as_str());
                                None
                            }
                            RecoveredContentStatus::Inconsistent(detail) => {
                                metadata["deleted_recovery_status"] =
                                    json!("content_not_recoverable_unreadable");
                                metadata["deleted_content_caveat"] =
                                    json!("blocks_unreadable_or_inconsistent");
                                metadata["deleted_content_caveat_detail"] = json!(detail);
                                metadata["content_incomplete"] = json!(true);
                                metadata["content_incomplete_reason"] =
                                    json!(IncompleteReason::UnresolvedStructure.as_str());
                                None
                            }
                        }
                    }
                } else {
                    None
                };

                produced.push(
                    Artifact::new(artifact.case_id, ArtifactType::FileEntry, content, metadata)
                        .with_parent(artifact.id),
                );
                recovered += 1;
            }
            if recovered > 0 {
                info!(
                    "HFS+ parser recovered {} deleted entries from orphaned catalog leaf nodes in \
                     unallocated space",
                    recovered
                );
            }
        }

        // A short catalog can cut so deep that NO leaf record is reachable, and
        // then the entry-level flags above have nothing to attach to: the parser
        // returns an empty list, which reads as "this volume held no files"
        // rather than "the catalog could not be reconstructed" (B3-018). Emit
        // one volume-level marker whenever the catalog was short, so the fact
        // survives even a zero-entry walk.
        if !catalog_complete {
            let entries = produced.len();
            let detail = format!(
                "the HFS+ catalog B-tree was reconstructed to {} of {} bytes (only the volume \
                 header's eight extent descriptors are followed; the extents-overflow B-tree is \
                 not walked), so the {} file entries listed are a prefix of the volume",
                catalog.len(),
                vh.catalog_fork.logical_size,
                entries
            );
            produced.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "HfsPlusCatalogIncomplete",
                        "subtype": "parse_incomplete",
                        "status": "CatalogNotReconstructedInFull",
                        "filesystem_type": "HFS+",
                        "inventory_incomplete": true,
                        "inventory_incomplete_reason": IncompleteReason::ShortRead.as_str(),
                        "content_incomplete": true,
                        "content_incomplete_reason": IncompleteReason::ShortRead.as_str(),
                        "catalog_incomplete": true,
                        "catalog_bytes_read": catalog.len(),
                        "catalog_logical_size": vh.catalog_fork.logical_size,
                        "entries_listed": entries,
                        "content_incomplete_detail": detail,
                        "inventory_incomplete_detail": detail,
                        "detail": detail,
                        "name": format!("HFS+ catalog: incomplete — {detail}"),
                    }),
                )
                .with_parent(artifact.id)
                .with_subtype("parse_incomplete"),
            );
        }

        // File slack (HUNT-282): one region per live regular file whose last
        // allocation block holds bytes past the file's logical end. The window
        // is located from the fork's allocation extents in whole blocks, not
        // from the byte runs published on the entry, which are trimmed to the
        // logical size. A compressed file's data fork is empty by design and a
        // file whose extents continue in the overflow tree has an incomplete
        // run list; both are counted as "could not locate", never as "no slack".
        let mut slack = seance_core::slack::SlackCollector::new(
            seance_core::slack::SlackLabels {
                filesystem: "hfsplus",
                offset_basis: "the start of this volume, not the start of the evidence",
            },
            u64::from(vh.block_size),
        );
        for (owner_id, name, path, fork, compressed) in &slack_candidates {
            if *compressed {
                slack.not_located();
                continue;
            }
            let logical = fork.logical_size;
            let runs: Vec<(Option<u64>, u64)> = fork
                .extents
                .iter()
                .map(|(start, count)| {
                    (
                        Some(u64::from(*start) * u64::from(vh.block_size)),
                        u64::from(*count) * u64::from(vh.block_size),
                    )
                })
                .collect();
            match seance_core::slack::locate_slack(&runs, logical, u64::from(vh.block_size)) {
                seance_core::slack::SlackLocation::Window(window) => slack.offer(
                    artifact,
                    ds,
                    seance_core::slack::SlackOwner {
                        artifact_id: *owner_id,
                        name,
                        path: Some(path),
                        logical_size: logical,
                    },
                    window,
                ),
                seance_core::slack::SlackLocation::NoTail => {}
                seance_core::slack::SlackLocation::Undescribed => slack.not_located(),
            }
        }
        let (slack_artifacts, _) = slack.finish(artifact);
        produced.extend(slack_artifacts);

        // Publish in-image sidecars (`-wal`, `.LOG1`/`.LOG2`) and each
        // `.tracev3`'s log tree, so evidence inside this volume is read the way
        // the same files loose on disk are.
        seance_core::data_source::attach_sibling_bundles(&mut produced);

        Ok(produced)
    }
}

/// Content for a file whose reconstruction stopped short of its logical size.
///
/// `size()` reports the file's real logical size while only the recovered prefix
/// is readable; reads past the prefix return 0 (a short read, never zeros).
/// That keeps the shortfall visible to every consumer instead of presenting the
/// prefix as the whole file. In particular the hash module compares bytes read
/// against `size()` and records `hash_skipped: "short_read"` rather than a
/// digest of a truncated prefix stored under a full-size FileEntry (BUG-214).
///
/// Its contract matches `seance_core::test_support::TruncatedSource::new`, but
/// that type is gated behind `cfg(any(test, feature = "test-support"))` and must
/// stay unreachable from a shipped path: this one is production content, not a
/// test double.
#[derive(Debug)]
struct TruncatedContentSource {
    bytes: Vec<u8>,
    logical_size: u64,
}

impl DataSource for TruncatedContentSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let start = match usize::try_from(offset) {
            Ok(s) if s < self.bytes.len() => s,
            _ => return Ok(0),
        };
        let to_read = std::cmp::min(buf.len(), self.bytes.len() - start);
        buf[..to_read].copy_from_slice(&self.bytes[start..start + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.logical_size
    }
}

/// Project a data fork's extents onto byte runs in the volume, clamped so the
/// runs never claim more than the fork's logical size. Returns the runs and the
/// number of logical bytes they cover; a shortfall means the extents-overflow
/// B-tree holds extents this parser did not follow.
fn fork_byte_runs(
    fork: &ForkData,
    block_size: u32,
    logical: u64,
) -> (Vec<(Option<u64>, u64)>, u64) {
    let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
    let mut covered = 0u64;
    for (start, count) in &fork.extents {
        let remaining = logical.saturating_sub(covered);
        if remaining == 0 {
            break;
        }
        // Every factor comes from the volume, so saturate rather than wrap: a
        // wrapped offset would name a low, unrelated part of the image.
        let phys = (*start as u64).saturating_mul(block_size as u64);
        let ext_len = (*count as u64).saturating_mul(block_size as u64);
        let take = ext_len.min(remaining);
        if take == 0 {
            continue;
        }
        runs.push((Some(phys), take));
        covered = covered.saturating_add(take);
    }
    (runs, covered)
}

/// Reconstruct a regular file's bytes from its data-fork extents and wrap them in
/// a data source. Records the byte runs into `metadata`.
///
/// Files up to `MAX_CONTENT_BYTES` are materialized in memory; larger ones are
/// served straight from their extents by a run-list source. Either way the
/// `data_runs` are published, because an entry with a size and no runs cannot be
/// hashed, previewed or re-served later — the file looks present in the
/// inventory and is unobtainable, which reads as "the tool found nothing" rather
/// than "the tool declined to load it".
fn build_file_content(
    source: &Arc<dyn DataSource>,
    block_size: u32,
    fork: &ForkData,
    metadata: &mut serde_json::Value,
) -> Option<Arc<dyn DataSource>> {
    let ds = source.as_ref();
    let logical = fork.logical_size;
    metadata["extent_count"] = json!(fork.extents.len());

    if logical == 0 {
        return Some(Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(Vec::new()),
        ));
    }
    if logical > MAX_CONTENT_BYTES {
        // Too large to hold in memory, but the extents are known: publish them
        // and serve the file lazily from the volume.
        let (runs, covered) = fork_byte_runs(fork, block_size, logical);
        let (runs_json, runs_contiguous) = seance_core::data_source::byte_runs_to_metadata(&runs);
        metadata["data_runs"] = runs_json;
        let fully_covered = covered == logical;
        metadata["data_runs_complete"] = json!(runs_contiguous && fully_covered);
        if !fully_covered {
            // The first eight extent descriptors do not reach the logical size;
            // the rest live in the extents-overflow B-tree, which this parser
            // does not walk. Attaching a source whose size is the short coverage
            // would hash as a complete small file (BUG-214), so attach nothing.
            metadata["content_truncated"] = json!(true);
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] =
                json!(IncompleteReason::UnresolvedStructure.as_str());
            metadata["content_bytes"] = json!(covered);
            metadata["logical_size"] = json!(logical);
            warn!(
                "HFS+ oversized file: extents cover {} of {} bytes; no content attached",
                covered, logical
            );
            return None;
        }
        // `covered == logical` is guaranteed here — the branch above returns
        // None otherwise — so this states that invariant rather than relying on
        // a reader tracing the control flow to it. If `fork_byte_runs` ever
        // returns block-aligned runs, the trim keeps the served length equal to
        // the file's, instead of appending the last block's slack.
        return Some(Arc::new(
            seance_core::data_source::RunListDataSource::with_logical_size(
                Arc::clone(source),
                runs,
                logical,
            ),
        ));
    }

    let mut content = Vec::with_capacity(logical as usize);
    let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
    let mut remaining = logical as usize;

    for (start, count) in &fork.extents {
        if remaining == 0 {
            break;
        }
        let phys = *start as u64 * block_size as u64;
        let ext_len = *count as usize * block_size as usize;
        let to_read = ext_len.min(remaining);
        let mut chunk = vec![0u8; to_read];
        if let Err(e) = read_exact_or_fail(ds, phys, &mut chunk, "HFS+ file extent") {
            // The volume cannot deliver this extent, so no content is attached.
            // Say so: without these flags the entry kept its full logical size
            // and simply had no content, which reads as "this file was empty"
            // rather than "this image could not produce it".
            warn!("HFS+ content read failed at offset {}: {}", phys, e);
            let (runs_json, _) = seance_core::data_source::byte_runs_to_metadata(&runs);
            metadata["data_runs"] = runs_json;
            metadata["data_runs_complete"] = json!(false);
            metadata["content_truncated"] = json!(true);
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] = json!(IncompleteReason::ShortRead.as_str());
            metadata["content_bytes"] = json!(content.len() as u64);
            metadata["logical_size"] = json!(logical);
            return None;
        }
        content.extend_from_slice(&chunk);
        runs.push((Some(phys), to_read as u64));
        remaining -= to_read;
    }

    // Persist the filesystem-window byte runs so the content resolver can re-serve.
    let (runs_json, runs_contiguous) = seance_core::data_source::byte_runs_to_metadata(&runs);
    metadata["data_runs"] = runs_json;

    // BUG-103: only the first 8 extent descriptors are parsed; any beyond that
    // live in the extents-overflow B-tree (not reconstructed here). Never report
    // the content as complete unless the bytes we gathered actually cover the
    // logical size — a short reconstruction must surface as incomplete, not be
    // hashed/served as if it were the whole file.
    let covered = content.len() as u64;
    let fully_covered = covered == logical;
    metadata["data_runs_complete"] = json!(runs_contiguous && fully_covered);
    if !fully_covered {
        metadata["content_truncated"] = json!(true);
        // `content_incomplete` is the flag the API, export and integrity-verify
        // paths read; `content_truncated` is HFS+-specific. The oversized path
        // above already sets both — this path set only the local one, so a
        // consumer checking the standard flag saw a full-size file (B2-138).
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] =
            json!(IncompleteReason::UnresolvedStructure.as_str());
        metadata["content_bytes"] = json!(covered);
        metadata["logical_size"] = json!(logical);
        warn!(
            "HFS+ file content incomplete: {} of {} bytes ({} extents parsed, extents-overflow not followed)",
            covered,
            logical,
            fork.extents.len()
        );
    }

    debug!(
        "HFS+ built {} bytes of content from {} extents",
        content.len(),
        fork.extents.len()
    );
    if !fully_covered {
        // Do NOT hand back a source whose size() is the partial length: it would
        // read as a complete small file and be hashed as the authoritative
        // content of a full-size FileEntry (BUG-214).
        return Some(Arc::new(TruncatedContentSource {
            bytes: content,
            logical_size: logical,
        }));
    }
    Some(Arc::new(
        seance_core::data_source::ByteSliceDataSource::new(content),
    ))
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;

    #[test]
    fn test_module_metadata() {
        let module = HfsPlusParser;
        assert_eq!(module.id(), "plugin.filesystem.hfsplus");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert!(module.subscribes_to().contains(&ArtifactType::FileSystem));
        assert_eq!(module.input_capability(), InputCapability::RandomAccess);
    }

    #[test]
    fn test_decode_hfs_name_utf16be() {
        // HFSUniStr255 for "Hi": length=2, then 0x0048 0x0069 (BE).
        let mut d = Vec::new();
        d.extend_from_slice(&2u16.to_be_bytes());
        d.extend_from_slice(&0x0048u16.to_be_bytes());
        d.extend_from_slice(&0x0069u16.to_be_bytes());
        assert_eq!(decode_hfs_name(&d, 0).unwrap(), "Hi");

        // Empty name (thread key) decodes to "".
        let empty = 0u16.to_be_bytes();
        assert_eq!(decode_hfs_name(&empty, 0).unwrap(), "");

        // Multi-byte code unit: 0x00E9 = 'é'.
        let mut e = Vec::new();
        e.extend_from_slice(&1u16.to_be_bytes());
        e.extend_from_slice(&0x00E9u16.to_be_bytes());
        assert_eq!(decode_hfs_name(&e, 0).unwrap(), "é");
    }

    #[test]
    fn test_parse_volume_header() {
        // Build a synthetic volume: 1024 bytes of boot area, then a 512-byte header.
        let mut vol = vec![0u8; 1024 + 512];
        let h = 1024usize;
        // signature "H+", blockSize 4096, totalBlocks 10240.
        vol[h..h + 2].copy_from_slice(&SIG_HFSPLUS.to_be_bytes());
        vol[h + VH_BLOCK_SIZE_OFFSET..h + VH_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&4096u32.to_be_bytes());
        vol[h + VH_TOTAL_BLOCKS_OFFSET..h + VH_TOTAL_BLOCKS_OFFSET + 4]
            .copy_from_slice(&10240u32.to_be_bytes());
        // Catalog fork: logicalSize=327680, one extent (startBlock=962, count=80).
        let cf = h + VH_CATALOG_FORK_OFFSET;
        vol[cf..cf + 8].copy_from_slice(&327680u64.to_be_bytes());
        vol[cf + 12..cf + 16].copy_from_slice(&80u32.to_be_bytes()); // totalBlocks
        let ext0 = cf + FORK_EXTENTS_OFFSET;
        vol[ext0..ext0 + 4].copy_from_slice(&962u32.to_be_bytes());
        vol[ext0 + 4..ext0 + 8].copy_from_slice(&80u32.to_be_bytes());

        let ds = ByteSliceDataSource::new(vol);
        let vh = parse_volume_header(&ds).unwrap();
        assert_eq!(vh.signature, SIG_HFSPLUS);
        assert_eq!(vh.block_size, 4096);
        assert_eq!(vh.total_blocks, 10240);
        assert_eq!(vh.catalog_fork.logical_size, 327680);
        assert_eq!(vh.catalog_fork.extents, vec![(962, 80)]);
    }

    #[test]
    fn test_parse_volume_header_rejects_bad_signature() {
        let mut vol = vec![0u8; 1024 + 512];
        vol[1024] = 0xDE;
        vol[1025] = 0xAD;
        let ds = ByteSliceDataSource::new(vol);
        assert!(parse_volume_header(&ds).is_err());
    }

    #[test]
    fn test_parse_catalog_file_record() {
        // Build a catalog file record: key (parentID=2, name="a.txt") + file data
        // with fileID=17 and a data fork of logical size 42.
        let name: Vec<u16> = "a.txt".encode_utf16().collect();
        let name_len = name.len();
        let key_length = 6 + 2 * name_len; // parentID(4) + nameLen(2) + chars

        let mut rec = Vec::new();
        rec.extend_from_slice(&(key_length as u16).to_be_bytes()); // keyLength
        rec.extend_from_slice(&2u32.to_be_bytes()); // parentID
        rec.extend_from_slice(&(name_len as u16).to_be_bytes()); // nameLen
        for u in &name {
            rec.extend_from_slice(&u.to_be_bytes());
        }
        // Data begins here at offset 2 + key_length.
        let data_start = rec.len();
        assert_eq!(data_start, 2 + key_length);
        // Grow data to hold up to the data fork (offset 88) + 80 bytes.
        rec.resize(
            data_start + CATALOG_FILE_DATAFORK_OFFSET + FORK_DATA_SIZE,
            0,
        );
        rec[data_start..data_start + 2].copy_from_slice(&REC_FILE.to_be_bytes()); // recordType
        rec[data_start + 8..data_start + 12].copy_from_slice(&17u32.to_be_bytes()); // fileID
        let fork = data_start + CATALOG_FILE_DATAFORK_OFFSET;
        rec[fork..fork + 8].copy_from_slice(&42u64.to_be_bytes()); // dataFork.logicalSize

        let mut entries = Vec::new();
        let mut thread_map = HashMap::new();
        parse_catalog_record(&rec, &mut entries, &mut thread_map);

        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.cnid, 17);
        assert_eq!(e.parent_cnid, 2);
        assert_eq!(e.name, "a.txt");
        assert!(!e.is_directory);
        assert_eq!(e.size, 42);
        // An ordinary file claims no compression.
        assert!(!e.compressed);
    }

    /// One byte that decides whether an empty data fork means an empty file.
    ///
    /// A `UF_COMPRESSED` file's data is in the `com.apple.decmpfs` attribute
    /// or the resource fork, and its data fork is empty **by design**. This
    /// build walks neither, so such a file used to be published as a complete
    /// zero-byte file — true about the data fork, and read by anybody as "the
    /// file is empty".
    #[test]
    fn a_uf_compressed_catalog_record_is_recognised_from_its_owner_flags() {
        let name: Vec<u16> = "photo.heic".encode_utf16().collect();
        let name_len = name.len();
        let key_length = 6 + 2 * name_len;

        let build = |owner_flags: u8, logical: u64| -> Vec<CatalogEntry> {
            let mut rec = Vec::new();
            rec.extend_from_slice(&(key_length as u16).to_be_bytes());
            rec.extend_from_slice(&2u32.to_be_bytes());
            rec.extend_from_slice(&(name_len as u16).to_be_bytes());
            for u in &name {
                rec.extend_from_slice(&u.to_be_bytes());
            }
            let data_start = rec.len();
            rec.resize(
                data_start + CATALOG_FILE_DATAFORK_OFFSET + FORK_DATA_SIZE,
                0,
            );
            rec[data_start..data_start + 2].copy_from_slice(&REC_FILE.to_be_bytes());
            rec[data_start + 8..data_start + 12].copy_from_slice(&99u32.to_be_bytes());
            // `permissions.ownerFlags`, the tenth byte of the BSD info at +32.
            rec[data_start + CATALOG_OWNER_FLAGS_OFFSET] = owner_flags;
            let fork = data_start + CATALOG_FILE_DATAFORK_OFFSET;
            rec[fork..fork + 8].copy_from_slice(&logical.to_be_bytes());
            let mut entries = Vec::new();
            let mut thread_map = HashMap::new();
            parse_catalog_record(&rec, &mut entries, &mut thread_map);
            entries
        };

        // Compressed: the flag is set and the data fork is empty, which is what
        // a real decmpfs file looks like in the catalog.
        let compressed = build(UF_COMPRESSED, 0);
        assert_eq!(compressed.len(), 1);
        assert!(compressed[0].compressed);
        assert_eq!(compressed[0].size, 0);

        // The flag among others still reads: `UF_IMMUTABLE` (0x02) beside it.
        let both = build(UF_COMPRESSED | 0x02, 0);
        assert!(both[0].compressed);

        // And a file with other owner flags and no compression does not.
        let plain = build(0x02, 4096);
        assert!(!plain[0].compressed);
        assert_eq!(plain[0].size, 4096);
    }

    #[test]
    fn test_read_fork_bytes_bounds_oversized_extent() {
        // Regression: a fork with a small logical size but an extent whose
        // blockCount * block_size is enormous (512 GB) must NOT allocate that
        // much. The read is capped by the remaining logical size and by the
        // data source length. Completing without OOM is the assertion.
        let block_size = 4096u32;
        let ds = ByteSliceDataSource::new(vec![0u8; 8192]); // tiny volume
                                                            // count 0x0800_0000 * 4096 == 512 GiB, mirroring the fuzz reproducer.
        let fork = ForkData {
            logical_size: 4096,
            extents: vec![(0, 0x0800_0000)],
        };
        let (out, complete) = read_fork_bytes(&ds, block_size, &fork, MAX_CATALOG_BYTES).unwrap();
        assert!(out.len() as u64 <= fork.logical_size);
        assert!(
            complete,
            "the volume does hold the whole 4 KiB logical size"
        );
    }

    /// BUG-275: when the fork's extents cover less than its logical size (a
    /// truncated volume, or a fragmented fork continuing in the extents-overflow
    /// B-tree that is not followed), the caller must be told.
    #[test]
    fn test_read_fork_bytes_reports_short_reconstruction() {
        let block_size = 4096u32;
        // The volume holds one block, but the fork claims four.
        let ds = ByteSliceDataSource::new(vec![0xAB; 4096]);
        let fork = ForkData {
            logical_size: 4 * 4096,
            extents: vec![(0, 1)],
        };

        let (out, complete) = read_fork_bytes(&ds, block_size, &fork, MAX_CATALOG_BYTES).unwrap();
        assert_eq!(out.len(), 4096);
        assert!(
            !complete,
            "a reconstruction short of the logical size must not report complete"
        );
    }

    #[test]
    fn test_scan_catalog_small_node_large_numrecords_no_panic() {
        // Regression: a leaf node advertising more records than its node_size can
        // hold made the record-offset extraction compute node_size - 2*(i+2),
        // which underflows usize (debug panic) once 2*(i+2) > node_size.
        // Build a catalog with node_size = 16 (the minimum) and a leaf node whose
        // numRecords (200) drives i well past node_size/2. Completing the scan
        // without panicking is the assertion.
        let mut catalog = vec![0u8; 128];
        // Header-node fields are read at absolute offsets: firstLeafNode @ 24,
        // nodeSize @ 32.
        catalog[24..28].copy_from_slice(&3u32.to_be_bytes()); // firstLeafNode = node 3
        catalog[32..34].copy_from_slice(&16u16.to_be_bytes()); // nodeSize = 16
                                                               // Node 3 occupies bytes [48..64].
        catalog[48..52].copy_from_slice(&0u32.to_be_bytes()); // fLink = 0 (chain ends)
        catalog[56] = 0xFF; // kind = NODE_KIND_LEAF (-1)
        catalog[58..60].copy_from_slice(&200u16.to_be_bytes()); // numRecords = 200

        let scan = scan_catalog(&catalog).expect("scan_catalog must not panic");
        // No well-formed records in the fixture; the point is that it returned.
        assert!(scan.entries.is_empty());
    }

    #[test]
    fn test_build_parent_path_from_threads() {
        // thread_map: sub(cnid 16) -> parent root(2), name "sub".
        let mut thread_map = HashMap::new();
        thread_map.insert(16u32, (ROOT_CNID, "sub".to_string()));

        // A file whose parent is the root -> parent path "/".
        assert_eq!(build_parent_path(ROOT_CNID, &thread_map), "/");
        // A file whose parent is "sub" -> parent path "/sub".
        assert_eq!(build_parent_path(16, &thread_map), "/sub");
    }

    #[test]
    fn test_hfs_date_to_rfc3339() {
        // BUG-102: HFS date = u32 seconds since 1904 (GMT). 2021-01-01T00:00:00Z
        // is unix 1_609_459_200, i.e. HFS 3_692_304_000.
        let ts = hfs_date_to_rfc3339(3_692_304_000).unwrap();
        assert!(ts.starts_with("2021-01-01T00:00:00"), "got {}", ts);
        // Zero is the unset sentinel -> omitted, never surfaced as 1904.
        assert!(hfs_date_to_rfc3339(0).is_none());
    }

    #[test]
    fn test_catalog_file_record_parses_dates() {
        // BUG-102: a file record's create/contentMod/access dates must decode.
        let name: Vec<u16> = "b.txt".encode_utf16().collect();
        let name_len = name.len();
        let key_length = 6 + 2 * name_len;

        let mut rec = Vec::new();
        rec.extend_from_slice(&(key_length as u16).to_be_bytes());
        rec.extend_from_slice(&2u32.to_be_bytes());
        rec.extend_from_slice(&(name_len as u16).to_be_bytes());
        for u in &name {
            rec.extend_from_slice(&u.to_be_bytes());
        }
        let data_start = rec.len();
        rec.resize(
            data_start + CATALOG_FILE_DATAFORK_OFFSET + FORK_DATA_SIZE,
            0,
        );
        rec[data_start..data_start + 2].copy_from_slice(&REC_FILE.to_be_bytes());
        rec[data_start + 8..data_start + 12].copy_from_slice(&18u32.to_be_bytes()); // fileID
        let hfs_2021: u32 = 3_692_304_000;
        // createDate @ +12, contentModDate @ +16. accessDate @ +24 left zero.
        rec[data_start + CATALOG_CREATE_DATE_OFFSET..data_start + CATALOG_CREATE_DATE_OFFSET + 4]
            .copy_from_slice(&hfs_2021.to_be_bytes());
        rec[data_start + CATALOG_CONTENT_MOD_DATE_OFFSET
            ..data_start + CATALOG_CONTENT_MOD_DATE_OFFSET + 4]
            .copy_from_slice(&hfs_2021.to_be_bytes());

        let mut entries = Vec::new();
        let mut thread_map = HashMap::new();
        parse_catalog_record(&rec, &mut entries, &mut thread_map);

        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert!(e
            .created
            .as_deref()
            .unwrap()
            .starts_with("2021-01-01T00:00:00"));
        assert!(e
            .modified
            .as_deref()
            .unwrap()
            .starts_with("2021-01-01T00:00:00"));
        assert!(e.accessed.is_none(), "unset access date must be omitted");
    }

    #[test]
    fn test_truncated_volume_header_fails_closed() {
        // BUG-104: a volume that ends inside the 512-byte header must error rather
        // than parse a zero-padded buffer. The fail-closed read itself lives in
        // seance_core::io; this pins the behaviour at the HFS+ call site.
        let mut vol = vec![0u8; 1024 + 200]; // header truncated at 200 of 512 bytes
        vol[1024..1026].copy_from_slice(&SIG_HFSPLUS.to_be_bytes());
        let ds = ByteSliceDataSource::new(vol);
        assert!(parse_volume_header(&ds).is_err());
    }

    #[test]
    fn test_truncated_file_extent_yields_no_content() {
        // An extent that runs past the end of the volume must not be zero-padded
        // into content; build_file_content gives up rather than fabricate bytes.
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEEu8; 512]));
        let fork = ForkData {
            logical_size: 2048,
            extents: vec![(4, 1)], // starts at byte 2048, past EOF
        };
        let mut metadata = json!({});
        assert!(build_file_content(&ds, 512, &fork, &mut metadata).is_none());
        // B2-069: "no content" and "an empty file" must not look the same. The
        // entry keeps its 2048-byte size, so it has to say why nothing came
        // back.
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(
            metadata["content_incomplete_reason"],
            json!(IncompleteReason::ShortRead.as_str())
        );
        assert_eq!(metadata["content_truncated"], json!(true));
        assert_eq!(metadata["content_bytes"], json!(0u64));
        assert_eq!(metadata["logical_size"], json!(2048u64));
    }

    /// B2-069: a file over `MAX_CONTENT_BYTES` used to get `content_truncated`
    /// and nothing else — no runs, no source — so it could never be hashed,
    /// previewed or re-served even though its extents were known. It is served
    /// from its extents instead of being materialized in RAM.
    #[test]
    fn an_oversized_file_is_served_from_its_extents_rather_than_dropped() {
        let block_size = 512u32;
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEEu8; 4096]));
        let logical = MAX_CONTENT_BYTES + block_size as u64;
        let blocks = (logical / block_size as u64) as u32;
        let fork = ForkData {
            logical_size: logical,
            extents: vec![(0, blocks)],
        };
        let mut metadata = json!({});
        let content = build_file_content(&ds, block_size, &fork, &mut metadata)
            .expect("known extents must yield a servable source");

        assert_eq!(content.size(), logical);
        assert_eq!(metadata["data_runs_complete"], json!(true));
        assert!(
            !metadata["data_runs"].as_array().unwrap().is_empty(),
            "the byte runs must be published so the content resolver can re-serve"
        );
        assert!(metadata.get("content_truncated").is_none());
    }

    /// The failure path of the above: when the eight in-catalog extents do not
    /// reach the logical size, no source is attached (a short source would hash
    /// as a complete small file, BUG-214) and the shortfall is stated.
    #[test]
    fn an_oversized_file_with_short_extent_coverage_attaches_no_content_and_says_why() {
        let block_size = 512u32;
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEEu8; 4096]));
        let logical = MAX_CONTENT_BYTES + block_size as u64;
        let fork = ForkData {
            logical_size: logical,
            extents: vec![(0, 1)], // 512 bytes of a >256 MiB file
        };
        let mut metadata = json!({});
        let content = build_file_content(&ds, block_size, &fork, &mut metadata);

        assert!(content.is_none());
        assert_eq!(metadata["data_runs_complete"], json!(false));
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(
            metadata["content_incomplete_reason"],
            json!(IncompleteReason::UnresolvedStructure.as_str())
        );
        assert_eq!(metadata["content_bytes"], json!(512u64));
        assert_eq!(metadata["logical_size"], json!(logical));
    }

    #[test]
    fn test_build_file_content_flags_incomplete_coverage() {
        // BUG-103: a fork whose (first-8) extents cover fewer bytes than the
        // logical size must be flagged incomplete, never reported as complete.
        let block_size = 512u32;
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEEu8; 4096]));
        // logical 2048, but a single 1-block extent only covers 512 bytes.
        let fork = ForkData {
            logical_size: 2048,
            extents: vec![(0, 1)],
        };
        let mut metadata = json!({});
        let content = build_file_content(&ds, block_size, &fork, &mut metadata);
        assert!(content.is_some());
        assert_eq!(metadata["data_runs_complete"], json!(false));
        assert_eq!(metadata["content_truncated"], json!(true));
        // B2-138: `content_truncated` is HFS+-specific. Consumers that check
        // only the standard `content_incomplete` flag — the API, export and
        // integrity-verify paths — saw a full-size file with complete content.
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(
            metadata["content_incomplete_reason"],
            json!(IncompleteReason::UnresolvedStructure.as_str())
        );
        assert_eq!(metadata["content_bytes"], json!(512));
        assert_eq!(metadata["logical_size"], json!(2048));
    }

    #[test]
    fn test_truncated_content_reports_logical_size_and_short_reads() {
        // BUG-214: a partial reconstruction must not be handed back as a
        // complete small source. Its size() is the file's logical size, so the
        // hash module sees bytes_hashed < size and records a short read instead
        // of a digest of a truncated prefix.
        let block_size = 512u32;
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEEu8; 4096]));
        let fork = ForkData {
            logical_size: 2048,
            extents: vec![(0, 1)], // covers only 512 of 2048 bytes
        };
        let mut metadata = json!({});
        let content = build_file_content(&ds, block_size, &fork, &mut metadata).unwrap();

        assert_eq!(
            content.size(),
            2048,
            "the source must declare the file's logical size, not the recovered prefix"
        );

        // The recovered prefix is readable...
        let mut buf = vec![0u8; 2048];
        let n = content.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 512);
        assert!(buf[..512].iter().all(|&b| b == 0xEE));

        // ...and the missing tail short-reads rather than yielding fabricated zeros.
        let mut tail = vec![0u8; 16];
        assert_eq!(content.read_at(512, &mut tail).unwrap(), 0);
        assert_eq!(content.read_at(4096, &mut tail).unwrap(), 0);
    }

    #[test]
    fn test_fully_covered_content_is_a_plain_byte_slice() {
        // A complete reconstruction is unchanged: size() == logical size and the
        // whole file reads back.
        let block_size = 512u32;
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEEu8; 4096]));
        let fork = ForkData {
            logical_size: 1024,
            extents: vec![(0, 2)],
        };
        let mut metadata = json!({});
        let content = build_file_content(&ds, block_size, &fork, &mut metadata).unwrap();

        assert_eq!(content.size(), 1024);
        let mut buf = vec![0u8; 1024];
        assert_eq!(content.read_at(0, &mut buf).unwrap(), 1024);
        assert_eq!(metadata["data_runs_complete"], json!(true));
        assert!(metadata.get("content_truncated").is_none());
        assert!(metadata.get("content_incomplete").is_none());
    }

    /// Build a minimal HFS+ volume whose catalog B-tree is a 512-byte header
    /// node followed by one leaf node holding a single file record ("a.txt",
    /// CNID 17). `catalog_logical_size` is what the volume header CLAIMS the
    /// catalog fork is; the volume only physically holds two nodes, so a claim
    /// larger than 1024 makes the reconstruction short.
    fn build_hfsplus_volume(catalog_logical_size: u64) -> Vec<u8> {
        const BS: usize = 512;
        const NODE: usize = 512;
        const CATALOG_BLOCK: usize = 4;

        let mut vol = vec![0u8; (CATALOG_BLOCK + 2) * BS];

        // --- Volume header at byte 1024 ---
        let h = 1024usize;
        vol[h..h + 2].copy_from_slice(&SIG_HFSPLUS.to_be_bytes());
        vol[h + VH_BLOCK_SIZE_OFFSET..h + VH_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&(BS as u32).to_be_bytes());
        vol[h + VH_TOTAL_BLOCKS_OFFSET..h + VH_TOTAL_BLOCKS_OFFSET + 4]
            .copy_from_slice(&((CATALOG_BLOCK + 2) as u32).to_be_bytes());
        let cf = h + VH_CATALOG_FORK_OFFSET;
        vol[cf..cf + 8].copy_from_slice(&catalog_logical_size.to_be_bytes());
        vol[cf + 12..cf + 16].copy_from_slice(&2u32.to_be_bytes()); // totalBlocks
        let ext0 = cf + FORK_EXTENTS_OFFSET;
        vol[ext0..ext0 + 4].copy_from_slice(&(CATALOG_BLOCK as u32).to_be_bytes());
        vol[ext0 + 4..ext0 + 8].copy_from_slice(&2u32.to_be_bytes()); // 2 blocks = 2 nodes

        // --- Catalog node 0: B-tree header node ---
        let n0 = CATALOG_BLOCK * BS;
        vol[n0 + BTNODE_DESC_SIZE + 10..n0 + BTNODE_DESC_SIZE + 14]
            .copy_from_slice(&1u32.to_be_bytes()); // firstLeafNode = 1
        vol[n0 + BTNODE_DESC_SIZE + 18..n0 + BTNODE_DESC_SIZE + 20]
            .copy_from_slice(&(NODE as u16).to_be_bytes()); // nodeSize

        // --- Catalog node 1: leaf node with one file record ---
        let n1 = n0 + NODE;
        vol[n1..n1 + 4].copy_from_slice(&0u32.to_be_bytes()); // fLink = 0
        vol[n1 + 8] = NODE_KIND_LEAF as u8;
        vol[n1 + 10..n1 + 12].copy_from_slice(&1u16.to_be_bytes()); // numRecords

        // Record: key(parentID=2, "a.txt") + HFSPlusCatalogFile(fileID=17).
        let name: Vec<u16> = "a.txt".encode_utf16().collect();
        let key_length = 6 + 2 * name.len();
        let mut rec = Vec::new();
        rec.extend_from_slice(&(key_length as u16).to_be_bytes());
        rec.extend_from_slice(&ROOT_CNID.to_be_bytes());
        rec.extend_from_slice(&(name.len() as u16).to_be_bytes());
        for u in &name {
            rec.extend_from_slice(&u.to_be_bytes());
        }
        let data_start = rec.len();
        rec.resize(
            data_start + CATALOG_FILE_DATAFORK_OFFSET + FORK_DATA_SIZE,
            0,
        );
        rec[data_start..data_start + 2].copy_from_slice(&REC_FILE.to_be_bytes());
        rec[data_start + 8..data_start + 12].copy_from_slice(&17u32.to_be_bytes());

        let rec_start = BTNODE_DESC_SIZE;
        let rec_end = rec_start + rec.len();
        vol[n1 + rec_start..n1 + rec_end].copy_from_slice(&rec);
        // Record offset array grows backward from the node end.
        vol[n1 + NODE - 2..n1 + NODE].copy_from_slice(&(rec_start as u16).to_be_bytes());
        vol[n1 + NODE - 4..n1 + NODE - 2].copy_from_slice(&(rec_end as u16).to_be_bytes());

        vol
    }

    fn hfsplus_artifact(vol: Vec<u8>) -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::new(ByteSliceDataSource::new(vol)) as Arc<dyn DataSource>),
            json!({ "subtype": "hfsplus", "filesystem_type": "HFS+" }),
        )
    }

    /// BUG-275: the catalog fork claims 3 nodes but the volume only holds 2, so
    /// the file list is a prefix. The entries it did produce must say so.
    #[test]
    fn test_short_catalog_flags_entries_incomplete() {
        let artifact = hfsplus_artifact(build_hfsplus_volume(3 * 512));
        let produced = HfsPlusParser.process(&artifact).expect("process ok");

        let entries: Vec<_> = produced
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "the reachable record is still inventoried"
        );
        let md = &entries[0].metadata;
        assert_eq!(md["name"], json!("a.txt"));
        assert_eq!(
            md["catalog_incomplete"],
            json!(true),
            "a short catalog reconstruction must not look like a full file list"
        );
        assert_eq!(md["catalog_incomplete_reason"], json!("short_read"));
    }

    /// B3-018: the entry-level honesty flag was HFS+-private (`catalog_incomplete`).
    /// Consumers key on `inventory_incomplete`, so a prefix listing presented as
    /// the whole volume. Both keys must now be present.
    #[test]
    fn short_catalog_stamps_the_standard_inventory_flag_on_entries() {
        let artifact = hfsplus_artifact(build_hfsplus_volume(3 * 512));
        let produced = HfsPlusParser.process(&artifact).expect("process ok");

        let entry = produced
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("the reachable record is still inventoried");
        assert_eq!(
            entry.metadata["inventory_incomplete"],
            json!(true),
            "a short catalog must set the flag standard consumers read"
        );
        assert_eq!(
            entry.metadata["inventory_incomplete_reason"],
            json!("short_read")
        );
    }

    /// B3-018: when the catalog is cut so short that no leaf record survives, a
    /// bare empty artifact list is indistinguishable from an empty volume. One
    /// volume-level marker must carry the fact instead.
    #[test]
    fn short_catalog_emits_a_volume_level_incompleteness_marker() {
        let artifact = hfsplus_artifact(build_hfsplus_volume(3 * 512));
        let produced = HfsPlusParser.process(&artifact).expect("process ok");

        let marker = produced
            .iter()
            .find(|a| a.metadata["type"] == json!("HfsPlusCatalogIncomplete"))
            .expect("a short catalog must emit a volume-level marker");
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(
            marker.metadata["content_incomplete_reason"],
            json!("short_read")
        );
        assert_eq!(marker.metadata["entries_listed"], json!(1));
    }

    /// Control: when the catalog fork is fully reconstructed the entries carry
    /// no incompleteness flag.
    #[test]
    fn test_complete_catalog_carries_no_incomplete_flag() {
        let artifact = hfsplus_artifact(build_hfsplus_volume(2 * 512));
        let produced = HfsPlusParser.process(&artifact).expect("process ok");

        let produced: Vec<&Artifact> = produced
            .iter()
            .filter(|a| a.metadata.get("type") != Some(&json!("SlackSpaceSummary")))
            .collect();
        assert_eq!(produced.len(), 1, "no marker when the catalog is whole");
        let md = &produced[0].metadata;
        assert_eq!(md["name"], json!("a.txt"));
        assert!(md.get("catalog_incomplete").is_none());
        assert!(md.get("inventory_incomplete").is_none());
    }

    // --- ROADMAP §5.6: deleted-file recovery from orphaned catalog leaves ---

    /// Encode a name as an HFSUniStr255: a u16 code-unit count followed by
    /// that many UTF-16BE code units.
    fn encode_hfs_name(name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut out = Vec::with_capacity(2 + units.len() * 2);
        out.extend_from_slice(&(units.len() as u16).to_be_bytes());
        for u in &units {
            out.extend_from_slice(&u.to_be_bytes());
        }
        out
    }

    /// Build an HFSPlusCatalogKey: keyLength, parentID, then the name.
    fn build_catalog_key(parent: u32, name: &str) -> Vec<u8> {
        let name_bytes = encode_hfs_name(name);
        let key_length = 4 + name_bytes.len(); // parentID(4) + nameLen(2) + chars
        let mut key = Vec::with_capacity(2 + key_length);
        key.extend_from_slice(&(key_length as u16).to_be_bytes());
        key.extend_from_slice(&parent.to_be_bytes());
        key.extend_from_slice(&name_bytes);
        key
    }

    /// Build a whole catalog FILE record (key + HFSPlusCatalogFile data) with
    /// the given CNID and data-fork extents, matching the layout
    /// `parse_catalog_record`'s `REC_FILE` arm expects.
    fn build_file_record(
        parent: u32,
        name: &str,
        cnid: u32,
        fork_logical: u64,
        fork_extents: &[(u32, u32)],
    ) -> Vec<u8> {
        let mut rec = build_catalog_key(parent, name);
        let data_start = rec.len();
        rec.resize(
            data_start + CATALOG_FILE_DATAFORK_OFFSET + FORK_DATA_SIZE,
            0,
        );
        rec[data_start..data_start + 2].copy_from_slice(&REC_FILE.to_be_bytes());
        rec[data_start + 8..data_start + 12].copy_from_slice(&cnid.to_be_bytes());
        let fork = data_start + CATALOG_FILE_DATAFORK_OFFSET;
        rec[fork..fork + 8].copy_from_slice(&fork_logical.to_be_bytes());
        for (i, (start, count)) in fork_extents.iter().enumerate().take(FORK_EXTENT_COUNT) {
            let base = fork + FORK_EXTENTS_OFFSET + i * 8;
            rec[base..base + 4].copy_from_slice(&start.to_be_bytes());
            rec[base + 4..base + 8].copy_from_slice(&count.to_be_bytes());
        }
        rec
    }

    /// Lay `records` into a `node_size`-byte leaf node: descriptor (kind=leaf,
    /// height=1, numRecords), the records themselves back to back from
    /// `BTNODE_DESC_SIZE`, and the record-offset array growing backward from
    /// the node's end, exactly as `parse_leaf_node_records` expects to read.
    fn build_leaf_node(node_size: usize, records: &[Vec<u8>]) -> Vec<u8> {
        let mut node = vec![0u8; node_size];
        node[8] = NODE_KIND_LEAF as u8;
        node[9] = NODE_HEIGHT_LEAF;
        node[10..12].copy_from_slice(&(records.len() as u16).to_be_bytes());

        let mut offset = BTNODE_DESC_SIZE;
        let mut rec_offsets = Vec::with_capacity(records.len() + 1);
        for r in records {
            rec_offsets.push(offset);
            node[offset..offset + r.len()].copy_from_slice(r);
            offset += r.len();
        }
        rec_offsets.push(offset); // sentinel: free-space start

        for (i, off) in rec_offsets.iter().enumerate() {
            let slot = node_size - 2 * (i + 1);
            node[slot..slot + 2].copy_from_slice(&(*off as u16).to_be_bytes());
        }
        node
    }

    /// Build a catalog B-tree header node: just enough of `BTHeaderRec` for
    /// `scan_catalog` to find the first leaf and the tree's node size.
    fn build_header_node(node_size: usize, first_leaf: u32) -> Vec<u8> {
        let mut node = vec![0u8; node_size];
        node[BTNODE_DESC_SIZE + 10..BTNODE_DESC_SIZE + 14]
            .copy_from_slice(&first_leaf.to_be_bytes());
        node[BTNODE_DESC_SIZE + 18..BTNODE_DESC_SIZE + 20]
            .copy_from_slice(&(node_size as u16).to_be_bytes());
        node
    }

    /// Build a small HFS+ volume (8 blocks of 512 bytes) that models an
    /// on-disk deletion: "ghost.txt" (CNID 20) was written, then deleted --
    /// its catalog record no longer exists in the LIVE tree (block 5's leaf
    /// node is empty, as if the tree was rebalanced after the record was
    /// removed) -- but its former leaf-node bytes (block 7) and its former
    /// data block (block 6) were never zeroed, exactly as real HFS+ deletion
    /// leaves them.
    ///
    /// Layout: block 2 = volume header, block 3 = allocation bitmap, blocks
    /// 4-5 = live catalog (header node, empty leaf node), block 6 = the
    /// deleted file's former data, block 7 = its orphaned leaf node.
    /// `data_block_reallocated` marks block 6 allocated in the bitmap instead
    /// of free, modelling a block since reused by a different live file.
    fn build_hfsplus_orphan_volume(content: &[u8], data_block_reallocated: bool) -> Vec<u8> {
        const BS: usize = 512;
        const TOTAL_BLOCKS: u32 = 8;
        let mut vol = vec![0u8; BS * TOTAL_BLOCKS as usize];

        // Block 6: the deleted file's former data-fork content.
        assert!(content.len() <= BS, "test content must fit one block");
        vol[6 * BS..6 * BS + content.len()].copy_from_slice(content);

        // Block 7: the orphaned leaf node, holding the one FILE record that
        // no longer exists in the live tree.
        let rec = build_file_record(ROOT_CNID, "ghost.txt", 20, content.len() as u64, &[(6, 1)]);
        let orphan_node = build_leaf_node(BS, &[rec]);
        vol[7 * BS..7 * BS + BS].copy_from_slice(&orphan_node);

        // Blocks 4-5: the live catalog -- header node, then an EMPTY leaf
        // (the deletion already happened; nothing reaches "ghost.txt" here).
        let header = build_header_node(BS, 1);
        vol[4 * BS..4 * BS + BS].copy_from_slice(&header);
        let live_leaf = build_leaf_node(BS, &[]);
        vol[5 * BS..5 * BS + BS].copy_from_slice(&live_leaf);

        // Block 3: the allocation bitmap. Blocks 0-5 (boot/header/bitmap/
        // catalog) allocated; block 6 (data) per the flag; block 7 (the
        // orphan node itself) always free -- that is the scenario.
        let mut bitmap_byte: u8 = 0b1111_1100;
        if data_block_reallocated {
            bitmap_byte |= 0b0000_0010;
        }
        vol[3 * BS] = bitmap_byte;

        // The volume header at byte 1024 (exactly block 2 at a 512-byte block
        // size).
        let h = 1024usize;
        vol[h..h + 2].copy_from_slice(&SIG_HFSPLUS.to_be_bytes());
        vol[h + VH_BLOCK_SIZE_OFFSET..h + VH_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&(BS as u32).to_be_bytes());
        vol[h + VH_TOTAL_BLOCKS_OFFSET..h + VH_TOTAL_BLOCKS_OFFSET + 4]
            .copy_from_slice(&TOTAL_BLOCKS.to_be_bytes());

        // Allocation fork: logicalSize=1 byte, one extent at block 3.
        let af = h + VH_ALLOCATION_FORK_OFFSET;
        vol[af..af + 8].copy_from_slice(&1u64.to_be_bytes());
        vol[af + FORK_EXTENTS_OFFSET..af + FORK_EXTENTS_OFFSET + 4]
            .copy_from_slice(&3u32.to_be_bytes());
        vol[af + FORK_EXTENTS_OFFSET + 4..af + FORK_EXTENTS_OFFSET + 8]
            .copy_from_slice(&1u32.to_be_bytes());

        // Catalog fork: logicalSize=2 nodes, extent at blocks 4-5.
        let cf = h + VH_CATALOG_FORK_OFFSET;
        vol[cf..cf + 8].copy_from_slice(&(2 * BS as u64).to_be_bytes());
        vol[cf + FORK_EXTENTS_OFFSET..cf + FORK_EXTENTS_OFFSET + 4]
            .copy_from_slice(&4u32.to_be_bytes());
        vol[cf + FORK_EXTENTS_OFFSET + 4..cf + FORK_EXTENTS_OFFSET + 8]
            .copy_from_slice(&2u32.to_be_bytes());

        vol
    }

    /// The core case: a deleted file's catalog record is gone from the live
    /// tree, but its leaf node and its data block were never touched. The
    /// recovery pass must find it, reconstruct its name and CNID from the
    /// SAME decoder the live walk uses, and -- because the block the extent
    /// names is still free -- read back its actual content.
    #[test]
    fn recovers_name_and_content_of_a_deleted_file_whose_blocks_are_still_free() {
        let content = b"the ghost's secret payload, still on disk".to_vec();
        let vol = build_hfsplus_orphan_volume(&content, false);
        let artifact = hfsplus_artifact(vol);
        let produced = HfsPlusParser.process(&artifact).expect("process ok");

        let ghost = produced
            .iter()
            .find(|a| a.metadata.get("name") == Some(&json!("ghost.txt")))
            .expect("the orphaned catalog record must be recovered");

        assert_eq!(ghost.metadata["deleted"], json!(true));
        assert_eq!(
            ghost.metadata["deleted_recovery_source"],
            json!("hfsplus_orphaned_catalog_leaf")
        );
        assert_eq!(ghost.metadata["cnid"], json!(20));
        assert_eq!(
            ghost.metadata["deleted_recovery_status"],
            json!("content_recovered"),
            "the extent's block is still free, so this must read as fully recovered"
        );
        assert!(ghost.metadata.get("content_incomplete").is_none());

        let content_source = ghost
            .data
            .as_ref()
            .expect("intact-and-unallocated content must be attached");
        assert_eq!(content_source.size(), content.len() as u64);
        let mut buf = vec![0u8; content.len()];
        content_source.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, content, "recovered bytes must match what was written");

        // It must never be mistaken for a live entry: the live tree's own
        // walk found nothing (the leaf node it reconstructs from is empty).
        assert!(
            !produced
                .iter()
                .any(|a| a.metadata.get("name") == Some(&json!("ghost.txt"))
                    && a.metadata.get("deleted").is_none()),
            "a recovered entry must never be merged into the live listing"
        );
    }

    /// The other side of the same scenario: the leaf node survived, but the
    /// block its extent names has since been given to a different live file.
    /// The name and CNID are still recovered, but the content must be refused
    /// outright -- not served, not guessed, not silently substituted with
    /// whatever now occupies that block.
    #[test]
    fn refuses_content_of_a_deleted_file_whose_block_was_reallocated() {
        // What now actually lives in block 6 -- a different file's bytes.
        let new_owners_bytes = b"this block now belongs to somebody else!!".to_vec();
        let vol = build_hfsplus_orphan_volume(&new_owners_bytes, true);
        let artifact = hfsplus_artifact(vol);
        let produced = HfsPlusParser.process(&artifact).expect("process ok");

        let ghost = produced
            .iter()
            .find(|a| a.metadata.get("name") == Some(&json!("ghost.txt")))
            .expect("the orphaned catalog record's NAME must still be recovered");

        assert_eq!(ghost.metadata["deleted"], json!(true));
        assert_eq!(
            ghost.metadata["deleted_recovery_status"],
            json!("content_not_recoverable_reallocated")
        );
        assert_eq!(
            ghost.metadata["deleted_content_caveat"],
            json!("blocks_reallocated_to_another_file")
        );
        assert_eq!(ghost.metadata["content_incomplete"], json!(true));
        assert_eq!(
            ghost.metadata["content_incomplete_reason"],
            json!(IncompleteReason::UnresolvedStructure.as_str())
        );
        assert!(
            ghost.data.is_none(),
            "the reallocated block's bytes must never be presented as this file's content"
        );
    }

    /// A third case alongside the two above: the extent itself cannot be
    /// trusted (it points past the volume), so the outcome is neither
    /// "recovered" nor "reallocated" but "could not tell" -- and that must
    /// say so on the record rather than default to either of the other two.
    #[test]
    fn reports_inconsistent_extents_as_unreadable_rather_than_guessing() {
        const BS: usize = 512;
        const TOTAL_BLOCKS: u32 = 8;
        let mut vol = vec![0u8; BS * TOTAL_BLOCKS as usize];

        // Orphaned leaf node at block 7, but its extent (block 50, count 1)
        // points past the volume's 8 total blocks.
        let rec = build_file_record(ROOT_CNID, "ghost.txt", 20, 512, &[(50, 1)]);
        let orphan_node = build_leaf_node(BS, &[rec]);
        vol[7 * BS..7 * BS + BS].copy_from_slice(&orphan_node);

        let header = build_header_node(BS, 1);
        vol[4 * BS..4 * BS + BS].copy_from_slice(&header);
        let live_leaf = build_leaf_node(BS, &[]);
        vol[5 * BS..5 * BS + BS].copy_from_slice(&live_leaf);

        vol[3 * BS] = 0b1111_1100; // blocks 0-5 allocated, 6 & 7 free

        let h = 1024usize;
        vol[h..h + 2].copy_from_slice(&SIG_HFSPLUS.to_be_bytes());
        vol[h + VH_BLOCK_SIZE_OFFSET..h + VH_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&(BS as u32).to_be_bytes());
        vol[h + VH_TOTAL_BLOCKS_OFFSET..h + VH_TOTAL_BLOCKS_OFFSET + 4]
            .copy_from_slice(&TOTAL_BLOCKS.to_be_bytes());
        let af = h + VH_ALLOCATION_FORK_OFFSET;
        vol[af..af + 8].copy_from_slice(&1u64.to_be_bytes());
        vol[af + FORK_EXTENTS_OFFSET..af + FORK_EXTENTS_OFFSET + 4]
            .copy_from_slice(&3u32.to_be_bytes());
        vol[af + FORK_EXTENTS_OFFSET + 4..af + FORK_EXTENTS_OFFSET + 8]
            .copy_from_slice(&1u32.to_be_bytes());
        let cf = h + VH_CATALOG_FORK_OFFSET;
        vol[cf..cf + 8].copy_from_slice(&(2 * BS as u64).to_be_bytes());
        vol[cf + FORK_EXTENTS_OFFSET..cf + FORK_EXTENTS_OFFSET + 4]
            .copy_from_slice(&4u32.to_be_bytes());
        vol[cf + FORK_EXTENTS_OFFSET + 4..cf + FORK_EXTENTS_OFFSET + 8]
            .copy_from_slice(&2u32.to_be_bytes());

        let artifact = hfsplus_artifact(vol);
        let produced = HfsPlusParser.process(&artifact).expect("process ok");

        let ghost = produced
            .iter()
            .find(|a| a.metadata.get("name") == Some(&json!("ghost.txt")))
            .expect("the orphaned catalog record's NAME must still be recovered");

        assert_eq!(
            ghost.metadata["deleted_recovery_status"],
            json!("content_not_recoverable_unreadable")
        );
        assert_eq!(
            ghost.metadata["deleted_content_caveat"],
            json!("blocks_unreadable_or_inconsistent")
        );
        assert!(ghost.metadata["deleted_content_caveat_detail"]
            .as_str()
            .unwrap()
            .contains("total blocks"));
        assert!(ghost.data.is_none());
    }

    /// Without an allocation bitmap at all (the fixtures used throughout the
    /// rest of this file never set one), the recovery pass must not run --
    /// guessing "free" for blocks it never checked would be worse than not
    /// running.
    #[test]
    fn no_allocation_bitmap_means_no_recovery_pass_and_no_false_positives() {
        // build_hfsplus_volume (used by the pre-existing tests above) never
        // sets an allocation fork, so its `logical_size` is 0.
        let artifact = hfsplus_artifact(build_hfsplus_volume(2 * 512));
        let produced = HfsPlusParser.process(&artifact).expect("process ok");
        assert!(
            !produced
                .iter()
                .any(|a| a.metadata.get("deleted") == Some(&json!(true))),
            "no allocation bitmap means no orphan sweep, and so no recovered entries"
        );
    }

    /// Build an 8-block, 512-byte-block HFS+ volume whose live catalog holds
    /// one file ("kept.txt", CNID 16) with the given logical size and the one
    /// data block 6. `block6` is the whole data block, so a test can plant bytes
    /// after the logical end. SYNTHETIC: written by this module's own helpers.
    fn build_hfsplus_live_file_volume(logical: u64, block6: &[u8]) -> Vec<u8> {
        const BS: usize = 512;
        assert_eq!(block6.len(), BS);
        let mut vol = build_hfsplus_orphan_volume(b"", false);
        vol[6 * BS..7 * BS].copy_from_slice(block6);
        // Block 7 held the orphaned leaf of the deleted-file scenario; clear it
        // so nothing is recovered, and put the live record in block 5.
        vol[7 * BS..8 * BS].fill(0);
        let rec = build_file_record(ROOT_CNID, "kept.txt", 16, logical, &[(6, 1)]);
        let leaf = build_leaf_node(BS, &[rec]);
        vol[5 * BS..6 * BS].copy_from_slice(&leaf);
        // Blocks 0-6 allocated.
        vol[3 * BS] = 0b1111_1110;
        vol
    }

    /// HUNT-282. The tail of a live file's last allocation block, past its
    /// logical end, is published as a `SlackSpace` region holding exactly the
    /// bytes there, in the volume's coordinate space; a file with nothing in
    /// its tail raises nothing. SYNTHETIC volume with a planted tail.
    #[test]
    fn a_live_files_planted_tail_is_published_as_a_slack_region() {
        const BS: usize = 512;
        let mut block = vec![0u8; BS];
        block[..11].copy_from_slice(b"hello slack");
        let planted = b"PLANTED-TAIL-0123456789";
        block[100..100 + planted.len()].copy_from_slice(planted);
        let artifact = hfsplus_artifact(build_hfsplus_live_file_volume(11, &block));
        let out = HfsPlusParser.process(&artifact).expect("process ok");

        let regions: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
            .collect();
        assert_eq!(regions.len(), 1, "{out:#?}");
        let r = regions[0];
        assert_eq!(r.metadata["filesystem"], json!("hfsplus"));
        assert_eq!(r.metadata["source"], json!("file_slack"));
        assert_eq!(r.metadata["parent_file"], json!("kept.txt"));
        assert_eq!(r.metadata["offset_bytes"], json!(6 * BS as u64 + 11));
        assert_eq!(r.metadata["size_bytes"], json!(BS as u64 - 11));
        assert_eq!(r.metadata["cluster_size"], json!(BS as u64));
        assert_eq!(r.metadata["logical_size"], json!(11));
        let src = r.data.as_ref().expect("a region carries its bytes");
        let mut got = vec![0u8; src.size() as usize];
        src.read_at(0, &mut got).unwrap();
        assert_eq!(got, block[11..].to_vec(), "the region is the block's tail");
        assert!(
            got.windows(planted.len()).any(|w| w == planted),
            "the planted bytes are in the region"
        );

        let summary = out
            .iter()
            .find(|a| a.metadata.get("type") == Some(&json!("SlackSpaceSummary")))
            .expect("the summary is always published");
        assert_eq!(summary.metadata["regions_emitted"], json!(1));
        assert_eq!(summary.metadata["filesystem"], json!("hfsplus"));

        // The same file with an all-zero tail publishes no region, and says it
        // looked.
        let mut clean = vec![0u8; BS];
        clean[..11].copy_from_slice(b"hello slack");
        let artifact = hfsplus_artifact(build_hfsplus_live_file_volume(11, &clean));
        let out = HfsPlusParser.process(&artifact).expect("process ok");
        assert!(!out
            .iter()
            .any(|a| a.artifact_type == ArtifactType::SlackSpace));
        let summary = out
            .iter()
            .find(|a| a.metadata.get("type") == Some(&json!("SlackSpaceSummary")))
            .expect("the summary is always published");
        assert_eq!(summary.metadata["zero_tails"], json!(1));
    }
}
