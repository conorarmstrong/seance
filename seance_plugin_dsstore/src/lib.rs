#![forbid(unsafe_code)]
//! Record-level parser for macOS `.DS_Store` files (Finder metadata stored in an
//! Apple "Buddy" allocator).
//!
//! Unlike the carver (`seance_carving/src/formats/ds_store.rs`), which only
//! recognises the `Bud1` magic, this module walks the buddy allocator and the
//! embedded B-tree to actually decode the records. For every distinct filename
//! it emits ONE [`ArtifactType::ParsedRecord`] summarising which Finder metadata
//! structures existed for it (evidence the file/folder was viewed in Finder).
//!
//! # Format (all buddy structures are big-endian)
//!
//! - `bytes[0..4]  = 0x00000001` (alignment)
//! - `bytes[4..8]  = "Bud1"` magic
//! - Buddy header @ 8: `u32 offset`, `u32 size`, `u32 offset_copy` (== offset).
//!   Buddy addresses are relative to file offset 4 (add 4 to the stored offset).
//! - Bookkeeping block @ `offset+4`: `u32 block_count`, `u32` unused, the block
//!   address table padded up to a multiple of 256 slots, then `u32 dir_count`
//!   and `dir_count` directory entries (`u8 name_len`, name, `u32 block_no`),
//!   then a free list (ignored). Each address packs a 5-bit size exponent in its
//!   low bits and the (32-aligned) offset in the rest.
//! - The `DSDB` directory entry resolves to the master block:
//!   `u32 root_block_id`, `u32 levels`, `u32 record_count`, `u32 block_count`.
//! - A B-tree node starts with `u32 mode` and `u32 count`. `mode == 0` is a leaf
//!   with `count` records; otherwise it is an internal node interleaving
//!   `count` (child-block-id, record) pairs followed by a trailing child (`mode`).
//! - A record: `u32 name_len` (UTF-16 code units), UTF-16BE name, 4-byte
//!   structureId (ASCII), 4-byte dataType (ASCII), then the typed value.
//!
//! Everything is bounds-checked; malformed input yields an empty `Vec`, never a
//! panic. If the B-tree walk finds nothing, a defensive linear scan for record
//! patterns runs as a fallback.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_capped, read_full, IncompleteReason},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::collections::{HashMap, HashSet};

/// Cap on how many bytes we ever read from a candidate `.DS_Store`.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Total record budget across the whole file (cycle / corruption guard).
const MAX_RECORDS: usize = 2_000_000;
/// Sanity cap on the buddy block-address table length.
const MAX_BLOCKS: usize = 1 << 22;
/// Sanity cap on the number of directory entries in the bookkeeping block.
const MAX_DIRS: usize = 65_536;
/// Recursion-depth cap for the B-tree walk.
const MAX_DEPTH: usize = 64;
/// Filename length cap (UTF-16 units) while walking the trusted B-tree.
const MAX_NAME_UNITS_BTREE: usize = 8192;
/// Filename length cap (UTF-16 units) for the (untrusted) linear scan.
const MAX_NAME_UNITS_SCAN: usize = 1024;

/// The `.DS_Store` record parser module.
pub struct DSStoreParser;

impl ForensicsModule for DSStoreParser {
    fn id(&self) -> &str {
        "plugin.macos.ds_store"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(parse_artifact(artifact))
    }
}

// --- selection + IO ----------------------------------------------------------

fn basename(name: &str) -> String {
    name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase()
}

fn parse_artifact(artifact: &Artifact) -> Vec<Artifact> {
    if artifact
        .metadata
        .get("is_directory")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return Vec::new();
    }
    let name = artifact
        .metadata
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let name_match = basename(name) == ".ds_store";

    let Some(data) = artifact.data.as_ref() else {
        return Vec::new();
    };

    // If the name does not self-select, cheaply probe the magic before reading
    // the whole file (this module subscribes to every FileEntry/FileContent).
    if !name_match {
        let mut head = [0u8; 8];
        let n = read_full(data.as_ref(), 0, &mut head);
        if n < 8 || &head[4..8] != b"Bud1" {
            return Vec::new();
        }
    }

    let declared = data.size();
    let buf = read_capped(data.as_ref(), MAX_FILE_BYTES);
    if buf.len() < 8 || &buf[4..8] != b"Bud1" {
        return Vec::new();
    }
    let bytes_short = (buf.len() as u64) < declared;

    let (entries, records_capped) = parse_ds_store(&buf);
    let mut out = Vec::with_capacity(entries.len() + 1);
    for (filename, structures) in entries {
        let meta = json!({
            "type": "DSStoreEntry",
            "subtype": "ds_store",
            "filename": filename,
            "structures": structures,
            "name": filename,
        });
        out.push(
            Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
                .with_parent(artifact.id),
        );
    }
    if bytes_short || records_capped {
        out.push(incomplete_marker(
            artifact,
            out.len(),
            bytes_short,
            records_capped,
            buf.len() as u64,
            declared,
        ));
    }
    out
}

/// A record stating that this `.DS_Store` was only partly parsed, and why.
///
/// Forensic meaning: `.DS_Store` entries are proof that a folder once held a
/// named file — often the only surviving trace after the file itself is gone.
/// A prefix of that inventory presented as the whole thing lets an examiner
/// conclude a filename was never in the folder when the walk simply stopped.
fn incomplete_marker(
    artifact: &Artifact,
    entries_emitted: usize,
    bytes_short: bool,
    records_capped: bool,
    bytes_read: u64,
    declared_size: u64,
) -> Artifact {
    let reason = if records_capped {
        IncompleteReason::CapReached
    } else {
        IncompleteReason::ShortRead
    };
    let meta = json!({
        "type": "DSStoreParseStatus",
        "subtype": "ds_store_incomplete",
        "name": ".DS_Store (partially parsed)",
        "content_incomplete": true,
        "content_incomplete_reason": reason.as_str(),
        "entries_emitted": entries_emitted,
        "record_cap_reached": records_capped,
        "input_truncated": bytes_short,
        "bytes_read": bytes_read,
        "declared_size": declared_size,
        "max_records": MAX_RECORDS,
        "max_file_bytes": MAX_FILE_BYTES,
    });
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta).with_parent(artifact.id)
}

// --- collector ---------------------------------------------------------------

/// Accumulates `(filename -> ordered, de-duplicated structure ids)` preserving
/// first-seen filename order for stable output.
#[derive(Default)]
struct Collected {
    order: Vec<String>,
    map: HashMap<String, Vec<String>>,
    total: usize,
}

impl Collected {
    fn push(&mut self, name: String, sid: String) {
        match self.map.get_mut(&name) {
            Some(v) => {
                if !v.contains(&sid) {
                    v.push(sid);
                }
            }
            None => {
                self.order.push(name.clone());
                self.map.insert(name, vec![sid]);
            }
        }
        self.total += 1;
    }

    fn into_entries(mut self) -> Vec<(String, Vec<String>)> {
        self.order
            .into_iter()
            .filter_map(|k| self.map.remove(&k).map(|v| (k, v)))
            .collect()
    }
}

// --- byte helpers ------------------------------------------------------------

fn be_u32(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let b: [u8; 4] = buf.get(off..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}

/// Decode a buddy address into `(file_offset, block_size)`.
/// Low 5 bits are a size exponent; the rest is the 32-aligned offset. Buddy
/// offsets are relative to file offset 4.
fn addr_to_offset_size(addr: u32) -> (usize, usize) {
    let offset = (addr & !0x1f) as usize;
    let exp = addr & 0x1f;
    let size = 1usize << exp; // exp <= 31
    (offset.saturating_add(4), size)
}

fn utf16be_lossy(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Strict UTF-16BE decode used by the linear scan: rejects odd length, lone
/// surrogates, empty results and control characters (real filenames are
/// printable), which keeps the pattern scan's false-positive rate low.
fn utf16be_strict_printable(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16(&units).ok()?;
    if s.is_empty() || s.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(s)
}

fn is_known_dtype(d: &[u8; 4]) -> bool {
    matches!(
        d,
        b"bool" | b"shor" | b"long" | b"type" | b"comp" | b"dutc" | b"blob" | b"ustr"
    )
}

/// Advance past a record's typed value, returning the offset just after it.
fn advance_value(buf: &[u8], p: usize, dtype: &[u8; 4]) -> Option<usize> {
    let np = match dtype {
        b"bool" => p.checked_add(1)?,
        b"shor" | b"long" | b"type" => p.checked_add(4)?,
        b"comp" | b"dutc" => p.checked_add(8)?,
        b"blob" => {
            let l = be_u32(buf, p)? as usize;
            p.checked_add(4)?.checked_add(l)?
        }
        b"ustr" => {
            let l = be_u32(buf, p)? as usize;
            p.checked_add(4)?.checked_add(l.checked_mul(2)?)?
        }
        _ => return None,
    };
    if np > buf.len() {
        return None;
    }
    Some(np)
}

// --- parse entry point -------------------------------------------------------

/// Returns the collected entries and whether the record budget stopped the walk.
fn parse_ds_store(buf: &[u8]) -> (Vec<(String, Vec<String>)>, bool) {
    let mut coll = Collected::default();
    let _ = parse_via_btree(buf, &mut coll);
    if coll.total == 0 {
        // B-tree walk found nothing; fall back to a defensive linear scan.
        let mut scan = Collected::default();
        linear_scan(buf, &mut scan);
        if scan.total > 0 {
            tracing::debug!(
                records = scan.total,
                "ds_store: B-tree walk empty, recovered records via linear scan"
            );
        }
        let capped = scan.total >= MAX_RECORDS;
        return (scan.into_entries(), capped);
    }
    let capped = coll.total >= MAX_RECORDS;
    (coll.into_entries(), capped)
}

// --- buddy allocator + B-tree ------------------------------------------------

fn parse_via_btree(buf: &[u8], coll: &mut Collected) -> Option<()> {
    if buf.len() < 32 || &buf[4..8] != b"Bud1" {
        return None;
    }
    let off_bk = be_u32(buf, 8)? as usize;
    let off_copy = be_u32(buf, 16)? as usize;
    if off_bk != off_copy {
        return None;
    }
    let root = off_bk.checked_add(4)?;

    let block_count = be_u32(buf, root)? as usize;
    if block_count == 0 || block_count > MAX_BLOCKS {
        return None;
    }
    // Skip block_count + the unused u32 that follows it.
    let mut p = root.checked_add(8)?;
    let slots = (block_count + 255) & !255;
    let mut addresses = Vec::with_capacity(block_count);
    for i in 0..slots {
        let a = be_u32(buf, p)?;
        p = p.checked_add(4)?;
        if i < block_count {
            addresses.push(a);
        }
    }

    let dir_count = be_u32(buf, p)? as usize;
    p = p.checked_add(4)?;
    if dir_count > MAX_DIRS {
        return None;
    }
    let mut dsdb_block = None;
    for _ in 0..dir_count {
        let nlen = *buf.get(p)? as usize;
        p = p.checked_add(1)?;
        let name = buf.get(p..p.checked_add(nlen)?)?;
        p = p.checked_add(nlen)?;
        let blk = be_u32(buf, p)?;
        p = p.checked_add(4)?;
        if name.eq_ignore_ascii_case(b"DSDB") {
            dsdb_block = Some(blk);
        }
    }

    let dsdb_block = dsdb_block?;
    let &master_addr = addresses.get(dsdb_block as usize)?;
    let (mo, _) = addr_to_offset_size(master_addr);
    let root_id = be_u32(buf, mo)?; // levels/rec_count/block_count follow, unused

    let mut visited = HashSet::new();
    walk_node(buf, &addresses, root_id, 0, &mut visited, coll);
    Some(())
}

fn walk_node(
    buf: &[u8],
    addresses: &[u32],
    node_id: u32,
    depth: usize,
    visited: &mut HashSet<u32>,
    coll: &mut Collected,
) {
    if depth > MAX_DEPTH || coll.total >= MAX_RECORDS {
        return;
    }
    if !visited.insert(node_id) {
        return; // cycle guard
    }
    let Some(&addr) = addresses.get(node_id as usize) else {
        return;
    };
    let (o, _size) = addr_to_offset_size(addr);
    let Some(mode) = be_u32(buf, o) else {
        return;
    };
    let Some(count) = be_u32(buf, o.saturating_add(4)) else {
        return;
    };
    let mut p = match o.checked_add(8) {
        Some(v) => v,
        None => return,
    };

    if mode == 0 {
        // Leaf: `count` records back to back.
        for _ in 0..count {
            if coll.total >= MAX_RECORDS {
                break;
            }
            match read_record(buf, p, coll) {
                Some(np) => p = np,
                None => break,
            }
        }
    } else {
        // Internal: (child, record) pairs, then a trailing rightmost child.
        for _ in 0..count {
            if coll.total >= MAX_RECORDS {
                break;
            }
            let Some(child) = be_u32(buf, p) else {
                break;
            };
            p = match p.checked_add(4) {
                Some(v) => v,
                None => break,
            };
            walk_node(buf, addresses, child, depth + 1, visited, coll);
            match read_record(buf, p, coll) {
                Some(np) => p = np,
                None => break,
            }
        }
        walk_node(buf, addresses, mode, depth + 1, visited, coll);
    }
}

/// Read one record from a trusted B-tree node, push it, and return the offset
/// just past it. Returns `None` on any bounds/format problem (caller stops the
/// current node so a desynced offset never produces garbage).
fn read_record(buf: &[u8], mut p: usize, coll: &mut Collected) -> Option<usize> {
    let nlen = be_u32(buf, p)? as usize;
    p = p.checked_add(4)?;
    if nlen == 0 || nlen > MAX_NAME_UNITS_BTREE {
        return None;
    }
    let name_end = p.checked_add(nlen.checked_mul(2)?)?;
    let name_bytes = buf.get(p..name_end)?;
    let name = utf16be_lossy(name_bytes);
    p = name_end;

    let sid: [u8; 4] = buf.get(p..p.checked_add(4)?)?.try_into().ok()?;
    p = p.checked_add(4)?;
    let dtype: [u8; 4] = buf.get(p..p.checked_add(4)?)?.try_into().ok()?;
    p = p.checked_add(4)?;
    if !is_known_dtype(&dtype) {
        return None;
    }
    let np = advance_value(buf, p, &dtype)?;

    coll.push(name, String::from_utf8_lossy(&sid).into_owned());
    Some(np)
}

// --- linear-scan fallback ----------------------------------------------------

/// Byte-by-byte scan for record patterns when the B-tree walk yields nothing.
/// Strong validation (bounded UTF-16 name, printable structureId, known
/// dataType, in-bounds value) keeps false positives low.
fn linear_scan(buf: &[u8], coll: &mut Collected) {
    let mut i = 0usize;
    while i + 8 <= buf.len() && coll.total < MAX_RECORDS {
        match try_scan_record(buf, i) {
            Some((name, sid, np)) => {
                coll.push(name, sid);
                i = np.max(i + 1);
            }
            None => i += 1,
        }
    }
}

fn try_scan_record(buf: &[u8], p: usize) -> Option<(String, String, usize)> {
    let nlen = be_u32(buf, p)? as usize;
    if !(1..=MAX_NAME_UNITS_SCAN).contains(&nlen) {
        return None;
    }
    let name_start = p.checked_add(4)?;
    let name_end = name_start.checked_add(nlen.checked_mul(2)?)?;
    let name_bytes = buf.get(name_start..name_end)?;

    let sid: [u8; 4] = buf
        .get(name_end..name_end.checked_add(4)?)?
        .try_into()
        .ok()?;
    let dtype_start = name_end.checked_add(4)?;
    let dtype: [u8; 4] = buf
        .get(dtype_start..dtype_start.checked_add(4)?)?
        .try_into()
        .ok()?;

    if !sid.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    if !is_known_dtype(&dtype) {
        return None;
    }
    let name = utf16be_strict_printable(name_bytes)?;

    let vstart = dtype_start.checked_add(4)?;
    let np = advance_value(buf, vstart, &dtype)?;
    Some((name, String::from_utf8_lossy(&sid).into_owned(), np))
}

#[cfg(test)]
mod tests;
