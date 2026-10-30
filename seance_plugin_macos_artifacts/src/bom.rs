//! Bill of Materials — `/var/db/receipts/*.bom` (and `.pkg` `Bom` files).
//!
//! A BOM is the manifest of every file an installer package laid down: full
//! path, type, size, mode, owner and mtime. It is `lsbom`'s input, and the
//! record of what a given package actually installed — software provenance at
//! file granularity.
//!
//! Format (big-endian throughout), verified against hogliux/bomutils:
//!
//! - `BOMHeader` @0: magic `"BOMStore"`, version, numberOfBlocks, indexOffset/
//!   indexLength (the block table), varsOffset/varsLength (the named variables).
//! - The block table maps a *block id* to a `(address, length)` in the file;
//!   block 0 is the null block.
//! - The `Paths` variable names the block holding a `BOMTree`, whose `child` is
//!   the root `BOMPaths` node. `BOMPaths` is a b-tree: branch nodes point to
//!   child `BOMPaths`, leaf entries pair a `BOMPathInfo1` (→ `BOMPathInfo2`
//!   metadata) with a `BOMFile` (parent id + name component). Full paths are
//!   reconstructed by walking each file's parent chain.

use anyhow::{bail, Context, Result};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::collections::HashMap;
use tracing::{info, warn};

use crate::{basename_lower, stamp_incomplete, to_rfc3339, Staged};

/// Cap on emitted file entries — a guard against a corrupt/hostile tree, not a
/// real package (the largest OS packages are ~100k files).
const MAX_ENTRIES: usize = 5_000_000;
/// Cap on tree nodes visited, likewise.
const MAX_NODES: usize = 2_000_000;
/// Largest BOM we read into memory. Receipts are small (KBs–MBs).
const MAX_BOM_BYTES: u64 = 256 * 1024 * 1024;

pub struct BomParser;

fn is_bom(name: &str) -> bool {
    let b = basename_lower(name);
    b.ends_with(".bom") || b == "bom"
}

fn be_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}
fn be_u16(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

/// The `BOMPathInfo2` metadata for an entry: type, permissions, owner, mtime
/// and size.
struct PathInfo {
    is_dir: bool,
    is_link: bool,
    mode: u16,
    uid: u32,
    gid: u32,
    modtime: u32,
    size: u32,
}

/// One resolved BOM path entry.
struct BomEntry {
    id: u32,
    parent: u32,
    name: String,
    /// `None` when the entry's `BOMPathInfo2` block was missing or too short.
    /// The zeroes that stood here read as a real 0-byte file owned by root with
    /// mode 0 — a fabricated fact about what an installer laid down — so the
    /// metadata stays absent and the record says why.
    info: Option<PathInfo>,
}

/// What a BOM walk could not account for.
///
/// A partial inventory that does not say so reads as "this is everything the
/// package installed", which is the one claim a receipt must never make
/// falsely.
#[derive(Default)]
struct WalkGaps {
    /// `MAX_NODES` / `MAX_ENTRIES` stopped the walk.
    capped: bool,
    /// Tree nodes or leaf blocks that could not be resolved (out of range, or
    /// shorter than the structure they claim), so the entries they hold are
    /// missing from the inventory entirely.
    unresolved_blocks: usize,
    /// Path ids that appeared more than once. Only the last is resolvable, so
    /// any path reconstructed through an earlier one names the wrong parent.
    duplicate_ids: usize,
}

impl WalkGaps {
    fn is_empty(&self) -> bool {
        !self.capped && self.unresolved_blocks == 0 && self.duplicate_ids == 0
    }
}

fn parse_bom(data: &[u8]) -> Result<(Vec<BomEntry>, WalkGaps)> {
    if data.len() < 32 || &data[0..8] != b"BOMStore" {
        bail!("not a BOMStore file");
    }
    let index_off = be_u32(data, 16).context("indexOffset")? as usize;
    let vars_off = be_u32(data, 24).context("varsOffset")? as usize;

    // Block table: id -> (address, length).
    let n_ptrs = be_u32(data, index_off).context("block count")? as usize;
    let mut blocks: Vec<(u32, u32)> = Vec::with_capacity(n_ptrs.min(1 << 20));
    for i in 0..n_ptrs {
        let p = index_off + 4 + i * 8;
        let addr = be_u32(data, p).context("block addr")?;
        let len = be_u32(data, p + 4).context("block len")?;
        blocks.push((addr, len));
    }
    let block = |id: u32| -> Option<(usize, usize)> {
        let (a, l) = *blocks.get(id as usize)?;
        let (a, l) = (a as usize, l as usize);
        if a.checked_add(l)? <= data.len() {
            Some((a, l))
        } else {
            None
        }
    };

    // Named variables: find "Paths".
    let var_count = be_u32(data, vars_off).context("var count")? as usize;
    let mut p = vars_off + 4;
    let mut paths_block = None;
    for _ in 0..var_count {
        let index = be_u32(data, p).context("var index")?;
        let len = *data.get(p + 4).context("var name length")? as usize;
        let name = data
            .get(p + 5..p + 5 + len)
            .context("var name")
            .map(|s| String::from_utf8_lossy(s).into_owned())?;
        if name == "Paths" {
            paths_block = Some(index);
        }
        p += 5 + len;
    }
    let paths_block = paths_block.context("no Paths variable")?;

    // BOMTree -> root BOMPaths node.
    let (taddr, tlen) = block(paths_block).context("Paths block out of range")?;
    if tlen < 13 || &data[taddr..taddr + 4] != b"tree" {
        bail!("Paths block is not a BOMTree");
    }
    let root = be_u32(data, taddr + 8).context("tree child")?;

    // Walk the tree, collecting leaf entries. Every soft failure below drops
    // entries from the inventory, so each one is counted rather than skipped
    // silently: an examiner reading a receipt has no other way to tell a short
    // list from a complete one.
    let mut entries = Vec::new();
    let mut gaps = WalkGaps::default();
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![root];
    let mut nodes = 0usize;
    while let Some(node_id) = stack.pop() {
        if node_id == 0 || !visited.insert(node_id) {
            continue;
        }
        nodes += 1;
        if nodes > MAX_NODES || entries.len() > MAX_ENTRIES {
            gaps.capped = true;
            break;
        }
        let Some((addr, len)) = block(node_id) else {
            gaps.unresolved_blocks += 1;
            continue;
        };
        if len < 12 {
            gaps.unresolved_blocks += 1;
            continue;
        }
        let is_leaf = be_u16(data, addr).unwrap_or(0) != 0;
        let count = be_u16(data, addr + 2).unwrap_or(0) as usize;
        for i in 0..count {
            let e = addr + 12 + i * 8;
            let (Some(index0), Some(index1)) = (be_u32(data, e), be_u32(data, e + 4)) else {
                gaps.unresolved_blocks += 1;
                break;
            };
            if !is_leaf {
                stack.push(index0); // branch -> child BOMPaths
                continue;
            }
            // Leaf: index0 -> BOMPathInfo1, index1 -> BOMFile.
            let Some((pi1, pi1_len)) = block(index0) else {
                gaps.unresolved_blocks += 1;
                continue;
            };
            if pi1_len < 8 {
                gaps.unresolved_blocks += 1;
                continue;
            }
            let id = be_u32(data, pi1).unwrap_or(0);
            let pi2_idx = be_u32(data, pi1 + 4).unwrap_or(0);

            let Some((faddr, flen)) = block(index1) else {
                gaps.unresolved_blocks += 1;
                continue;
            };
            if flen < 5 {
                gaps.unresolved_blocks += 1;
                continue;
            }
            let parent = be_u32(data, faddr).unwrap_or(0);
            let name_bytes = &data[faddr + 4..faddr + flen];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();

            let info = block(pi2_idx)
                .filter(|(_, pi2_len)| *pi2_len >= 22)
                .map(|(pi2, _)| {
                    let t = data[pi2];
                    PathInfo {
                        is_dir: t == 2,
                        is_link: t == 3,
                        mode: be_u16(data, pi2 + 4).unwrap_or(0),
                        uid: be_u32(data, pi2 + 6).unwrap_or(0),
                        gid: be_u32(data, pi2 + 10).unwrap_or(0),
                        modtime: be_u32(data, pi2 + 14).unwrap_or(0),
                        size: be_u32(data, pi2 + 18).unwrap_or(0),
                    }
                });
            entries.push(BomEntry {
                id,
                parent,
                name,
                info,
            });
        }
    }
    Ok((entries, gaps))
}

/// Reconstruct a full path for `id` by walking its parent chain, and say
/// whether the chain reached the root.
///
/// A chain that stops early yields a RELATIVE path: formatting the resolved
/// suffix with a leading `/` would claim an absolute location on disk that the
/// BOM never proved, which is the form an examiner would cite.
fn full_path(id: u32, by_id: &HashMap<u32, (&str, u32)>) -> (String, bool) {
    let mut parts = Vec::new();
    let mut cur = id;
    let mut guard = 0;
    let mut rooted = false;
    while guard < 4096 {
        if cur == 0 {
            rooted = true;
            break;
        }
        let Some((name, parent)) = by_id.get(&cur) else {
            break;
        };
        if !name.is_empty() && *name != "." {
            parts.push(*name);
        }
        cur = *parent;
        guard += 1;
    }
    parts.reverse();
    let joined = parts.join("/");
    if rooted {
        (format!("/{joined}"), true)
    } else {
        (joined, false)
    }
}

/// The record that says this package inventory is short, or `None` when it is
/// whole.
///
/// It is a separate artifact rather than a flag on every entry because the
/// shortfall is a fact about the LISTING, not about any one file the installer
/// laid down — and because a receipt can hold a hundred thousand of them.
fn inventory_marker(
    artifact: &Artifact,
    name: &str,
    staged: &Staged,
    gaps: &WalkGaps,
    emitted: usize,
) -> Option<Artifact> {
    if gaps.is_empty() && staged.incomplete_reason().is_none() {
        return None;
    }
    let mut reasons = Vec::new();
    if let Some(reason) = staged.incomplete_reason() {
        reasons.push((reason, staged.detail(name)));
    }
    if gaps.capped {
        reasons.push((
            IncompleteReason::CapReached,
            format!(
                "the path-tree walk stopped at the parser cap ({MAX_NODES} nodes / \
                 {MAX_ENTRIES} entries); the rest of the package inventory was not read"
            ),
        ));
    }
    if gaps.unresolved_blocks > 0 {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} block(s) the path tree points at could not be resolved, so the entries they \
                 hold are missing from this inventory",
                gaps.unresolved_blocks
            ),
        ));
    }
    if gaps.duplicate_ids > 0 {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} path id(s) appear more than once; only the last of each resolves, so paths \
                 reconstructed through the earlier ones may name the wrong parent",
                gaps.duplicate_ids
            ),
        ));
    }

    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("BomEntryIncomplete"));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("file_name".into(), json!(name));
    meta.insert("status".into(), json!("InventoryIncomplete"));
    meta.insert("entries_emitted".into(), json!(emitted));
    let detail = stamp_incomplete(&mut meta, "inventory", &reasons)?;
    meta.insert(
        "name".into(),
        json!(format!("BOM {name}: inventory incomplete — {detail}")),
    );
    Some(
        Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            meta.into(),
        )
        .with_parent(artifact.id)
        .with_subtype("parse_incomplete"),
    )
}

impl ForensicsModule for BomParser {
    fn id(&self) -> &str {
        "macos.bom"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !is_bom(name) {
            return Ok(Vec::new());
        }
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let staged = Staged::read(ds.as_ref(), MAX_BOM_BYTES);
        if staged.bytes.len() < 8 || &staged.bytes[0..8] != b"BOMStore" {
            // Not a BOM; stay silent — unless we never saw enough of the file
            // to tell, in which case a receipt named `.bom` would vanish.
            return Ok(staged
                .incomplete_marker(
                    artifact.case_id,
                    artifact.id,
                    "BomEntryIncomplete",
                    name,
                    "so the package inventory it holds could not be read",
                )
                .into_iter()
                .collect());
        }

        let (entries, mut gaps) = match parse_bom(&staged.bytes) {
            Ok(e) => e,
            Err(e) => {
                warn!("BomParser failed on {name}: {e}");
                return Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "BomEntry",
                        "subtype": "bom",
                        "file_name": name,
                        "status": "ParseFailed",
                        "error": e.to_string(),
                        "content_incomplete": true,
                        "content_incomplete_reason":
                            seance_core::io::IncompleteReason::UnresolvedStructure.as_str(),
                    }),
                )
                .with_parent(artifact.id)]);
            }
        };

        // A path id claimed twice leaves only the last resolvable, so paths
        // reconstructed through the earlier one name the wrong parent.
        let mut by_id: HashMap<u32, (&str, u32)> = HashMap::with_capacity(entries.len());
        for e in &entries {
            if by_id.insert(e.id, (e.name.as_str(), e.parent)).is_some() {
                gaps.duplicate_ids += 1;
            }
        }

        let mut out = Vec::with_capacity(entries.len());
        for e in &entries {
            let (path, rooted) = full_path(e.id, &by_id);
            let kind = match &e.info {
                Some(i) if i.is_dir => "directory",
                Some(i) if i.is_link => "symlink",
                Some(_) => "file",
                None => "unknown",
            };
            let mut meta = serde_json::Map::new();
            meta.insert("type".into(), json!("BomEntry"));
            meta.insert("subtype".into(), json!("bom"));
            meta.insert("path".into(), json!(path));
            meta.insert("path_rooted".into(), json!(rooted));

            let mut reasons = Vec::new();
            if !rooted {
                reasons.push((
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the parent chain for path id {} broke before the root, so `path` is the \
                         suffix that could be resolved and not an absolute location on disk",
                        e.id
                    ),
                ));
            }
            match &e.info {
                Some(i) => {
                    meta.insert("entry_type".into(), json!(kind));
                    meta.insert("size".into(), json!(i.size));
                    meta.insert("mode".into(), json!(format!("{:o}", i.mode)));
                    meta.insert("uid".into(), json!(i.uid));
                    meta.insert("gid".into(), json!(i.gid));
                    meta.insert("modtime".into(), json!(i.modtime));
                    if i.modtime != 0 {
                        if let Some(r) = to_rfc3339(i.modtime as i64) {
                            meta.insert("modtime_rfc3339".into(), json!(r));
                        }
                    }
                }
                // No zero-filled stand-ins: a 0-byte root-owned file with mode
                // 0 is a claim about what the installer laid down, and this BOM
                // makes no such claim.
                None => reasons.push((
                    IncompleteReason::UnresolvedStructure,
                    "the BOMPathInfo2 metadata block for this entry is missing or too short, so \
                     its type, mode, owner, mtime and size are unknown"
                        .to_string(),
                )),
            }
            let _ = stamp_incomplete(&mut meta, "content", &reasons);

            meta.insert("source_bom".into(), json!(name));
            meta.insert("name".into(), json!(format!("{kind}: {path}")));
            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    meta.into(),
                )
                .with_parent(artifact.id)
                .with_subtype("bom"),
            );
        }

        // One marker for everything that makes the LISTING short, so a
        // truncated package inventory cannot be read as the full manifest of
        // what the installer put on the disk.
        if let Some(marker) = inventory_marker(artifact, name, &staged, &gaps, out.len()) {
            out.push(marker);
        }

        info!("BomParser: {} entries from {name}", out.len());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::test_support::TruncatedSource;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Ways a real receipt goes wrong, applied to the tiny BOM below so each
    /// soft failure is exercised through the real parser.
    #[derive(Default, Clone, Copy)]
    struct Tweaks {
        /// Point the file's `BOMPathInfo1` at a block id the table does not
        /// define, so its metadata cannot be read.
        orphan_pi2: bool,
        /// Give the file a parent id no entry defines, breaking the path chain.
        orphan_parent: bool,
        /// Emit a second leaf entry reusing the file's path id.
        duplicate_id: bool,
    }

    /// A tiny BOM writer producing a valid file for the parser to read back, so
    /// the test asserts the parser against the documented bomutils structure.
    /// Contains one directory "." (id 1) and one file (id 2) under it.
    fn build_bom(
        file_name: &str,
        size: u32,
        mode: u16,
        uid: u32,
        gid: u32,
        modtime: u32,
    ) -> Vec<u8> {
        build_bom_tweaked(file_name, size, mode, uid, gid, modtime, Tweaks::default())
    }

    fn build_bom_tweaked(
        file_name: &str,
        size: u32,
        mode: u16,
        uid: u32,
        gid: u32,
        modtime: u32,
        tweaks: Tweaks,
    ) -> Vec<u8> {
        // Blocks are appended after a 512-byte header area; we record (addr,len).
        let mut body: Vec<u8> = Vec::new();
        let base = 512usize;
        let mut ptrs: Vec<(u32, u32)> = vec![(0, 0)]; // block 0 = null
        let add = |bytes: &[u8], body: &mut Vec<u8>, ptrs: &mut Vec<(u32, u32)>| -> u32 {
            let addr = base + body.len();
            body.extend_from_slice(bytes);
            ptrs.push((addr as u32, bytes.len() as u32));
            (ptrs.len() - 1) as u32
        };
        let pi2 = |t: u8, mode: u16, uid: u32, gid: u32, mt: u32, size: u32| -> Vec<u8> {
            let mut b = vec![t, 1];
            b.extend_from_slice(&0u16.to_be_bytes()); // architecture
            b.extend_from_slice(&mode.to_be_bytes());
            b.extend_from_slice(&uid.to_be_bytes());
            b.extend_from_slice(&gid.to_be_bytes());
            b.extend_from_slice(&mt.to_be_bytes());
            b.extend_from_slice(&size.to_be_bytes());
            b.push(1); // unknown1
            b.extend_from_slice(&0u32.to_be_bytes()); // checksum
            b.extend_from_slice(&0u32.to_be_bytes()); // linkNameLength
            b
        };
        let pi1 = |id: u32, pi2_idx: u32| -> Vec<u8> {
            let mut b = id.to_be_bytes().to_vec();
            b.extend_from_slice(&pi2_idx.to_be_bytes());
            b
        };
        let file = |parent: u32, name: &str| -> Vec<u8> {
            let mut b = parent.to_be_bytes().to_vec();
            b.extend_from_slice(name.as_bytes());
            b.push(0);
            b
        };

        // Directory "." (id 1)
        let dir_pi2 = add(&pi2(2, 0o40755, 0, 0, 0, 0), &mut body, &mut ptrs);
        let dir_pi1 = add(&pi1(1, dir_pi2), &mut body, &mut ptrs);
        let dir_file = add(&file(0, "."), &mut body, &mut ptrs);
        // File (id 2, parent 1)
        let f_pi2 = add(&pi2(1, mode, uid, gid, modtime, size), &mut body, &mut ptrs);
        // 9999 is past the end of the block table, so the metadata block cannot
        // be resolved — the shape a corrupt receipt presents.
        let f_pi1 = add(
            &pi1(2, if tweaks.orphan_pi2 { 9999 } else { f_pi2 }),
            &mut body,
            &mut ptrs,
        );
        let f_file = add(
            &file(if tweaks.orphan_parent { 7777 } else { 1 }, file_name),
            &mut body,
            &mut ptrs,
        );
        // A second leaf reusing path id 2.
        let dup = tweaks.duplicate_id.then(|| {
            let d_pi2 = add(&pi2(1, mode, uid, gid, modtime, size), &mut body, &mut ptrs);
            let d_pi1 = add(&pi1(2, d_pi2), &mut body, &mut ptrs);
            let d_file = add(&file(1, "duplicate.txt"), &mut body, &mut ptrs);
            (d_pi1, d_file)
        });
        let entry_count = 2 + u16::from(dup.is_some());

        // Leaf BOMPaths: isLeaf=1, count, forward=0, backward=0, entries.
        let mut paths = Vec::new();
        paths.extend_from_slice(&1u16.to_be_bytes()); // isLeaf
        paths.extend_from_slice(&entry_count.to_be_bytes()); // count
        paths.extend_from_slice(&0u32.to_be_bytes()); // forward
        paths.extend_from_slice(&0u32.to_be_bytes()); // backward
        paths.extend_from_slice(&dir_pi1.to_be_bytes());
        paths.extend_from_slice(&dir_file.to_be_bytes());
        paths.extend_from_slice(&f_pi1.to_be_bytes());
        paths.extend_from_slice(&f_file.to_be_bytes());
        if let Some((d_pi1, d_file)) = dup {
            paths.extend_from_slice(&d_pi1.to_be_bytes());
            paths.extend_from_slice(&d_file.to_be_bytes());
        }
        let paths_block = add(&paths, &mut body, &mut ptrs);

        // BOMTree
        let mut tree = b"tree".to_vec();
        tree.extend_from_slice(&1u32.to_be_bytes()); // version
        tree.extend_from_slice(&paths_block.to_be_bytes()); // child
        tree.extend_from_slice(&4096u32.to_be_bytes()); // blockSize
        tree.extend_from_slice(&u32::from(entry_count).to_be_bytes()); // pathCount
        tree.push(0);
        let tree_block = add(&tree, &mut body, &mut ptrs);

        // Block table and vars go after the body.
        let index_off = base + body.len();
        let mut index = (ptrs.len() as u32).to_be_bytes().to_vec();
        for (a, l) in &ptrs {
            index.extend_from_slice(&a.to_be_bytes());
            index.extend_from_slice(&l.to_be_bytes());
        }
        let vars_off = index_off + index.len();
        let mut vars = 1u32.to_be_bytes().to_vec(); // one var
        vars.extend_from_slice(&tree_block.to_be_bytes()); // "Paths" -> tree block
        vars.push(5);
        vars.extend_from_slice(b"Paths");

        // Assemble: header (32 bytes) + padding to `base` + body + index + vars.
        let mut out = Vec::new();
        out.extend_from_slice(b"BOMStore");
        out.extend_from_slice(&1u32.to_be_bytes()); // version
        out.extend_from_slice(&((ptrs.len() - 1) as u32).to_be_bytes()); // numberOfBlocks
        out.extend_from_slice(&(index_off as u32).to_be_bytes());
        out.extend_from_slice(&(index.len() as u32).to_be_bytes());
        out.extend_from_slice(&(vars_off as u32).to_be_bytes());
        out.extend_from_slice(&(vars.len() as u32).to_be_bytes());
        out.resize(base, 0); // pad to base where body starts
        out.extend_from_slice(&body);
        out.extend_from_slice(&index);
        out.extend_from_slice(&vars);
        out
    }

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        run_source(Arc::new(ByteSliceDataSource::new(bytes)), name)
    }

    fn run_source(src: Arc<dyn DataSource>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": name }),
        );
        BomParser.process(&art).unwrap()
    }

    /// The single inventory-shortfall marker, if the parser emitted one.
    fn marker(out: &[Artifact]) -> Option<&Artifact> {
        out.iter()
            .find(|a| a.metadata["type"] == json!("BomEntryIncomplete"))
    }

    #[test]
    fn parses_a_bom_file_inventory() {
        let bom = build_bom("hello.txt", 1234, 0o100644, 501, 20, 1_600_000_000);
        let out = run(bom, "com.example.pkg.bom");
        // Two entries: the "." directory and the file.
        let file = out
            .iter()
            .find(|a| a.metadata["entry_type"] == json!("file"))
            .expect("a file entry");
        assert_eq!(file.metadata["path"], json!("/hello.txt"));
        assert_eq!(file.metadata["size"], json!(1234));
        assert_eq!(file.metadata["uid"], json!(501));
        assert_eq!(file.metadata["gid"], json!(20));
        assert_eq!(
            file.metadata["modtime_rfc3339"].as_str().unwrap(),
            "2020-09-13T12:26:40+00:00"
        );
        assert!(out
            .iter()
            .any(|a| a.metadata["entry_type"] == json!("directory")));
        // A whole receipt says nothing about incompleteness, so the flag means
        // something when it is there.
        assert!(marker(&out).is_none());
        assert!(file.metadata.get("content_incomplete").is_none());
    }

    /// A missing `BOMPathInfo2` used to be filled with zeroes, which read as a
    /// real 0-byte file owned by root with mode 0 — a fabricated statement
    /// about what the installer laid down.
    #[test]
    fn an_entry_without_pathinfo2_reports_unknown_metadata_instead_of_zeroes() {
        let bom = build_bom_tweaked(
            "hello.txt",
            1234,
            0o100644,
            501,
            20,
            1_600_000_000,
            Tweaks {
                orphan_pi2: true,
                ..Tweaks::default()
            },
        );
        let out = run(bom, "com.example.pkg.bom");
        let entry = out
            .iter()
            .find(|a| a.metadata["path"] == json!("/hello.txt"))
            .expect("the entry is still inventoried");
        for absent in ["size", "mode", "uid", "gid", "modtime", "entry_type"] {
            assert!(
                entry.metadata.get(absent).is_none(),
                "{absent} must stay absent, not be invented"
            );
        }
        assert_eq!(entry.metadata["content_incomplete"], json!(true));
        assert_eq!(
            entry.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert!(entry.metadata["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("BOMPathInfo2"));
    }

    /// A parent chain that breaks before the root leaves a suffix, not an
    /// absolute path. Formatting it with a leading `/` asserted a location on
    /// disk the receipt never proved.
    #[test]
    fn a_broken_parent_chain_is_not_formatted_as_an_absolute_path() {
        let bom = build_bom_tweaked(
            "hello.txt",
            1234,
            0o100644,
            501,
            20,
            1_600_000_000,
            Tweaks {
                orphan_parent: true,
                ..Tweaks::default()
            },
        );
        let out = run(bom, "com.example.pkg.bom");
        let entry = out
            .iter()
            .find(|a| a.metadata["path"] == json!("hello.txt"))
            .expect("the resolved suffix is kept");
        assert_eq!(entry.metadata["path_rooted"], json!(false));
        assert_eq!(entry.metadata["content_incomplete"], json!(true));
        assert!(entry.metadata["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("parent chain"));
    }

    /// Duplicate path ids silently last-win in the lookup, so paths built
    /// through the earlier one name the wrong parent. The inventory has to say
    /// it happened.
    #[test]
    fn duplicate_path_ids_are_reported_on_the_inventory() {
        let bom = build_bom_tweaked(
            "hello.txt",
            1234,
            0o100644,
            501,
            20,
            1_600_000_000,
            Tweaks {
                duplicate_id: true,
                ..Tweaks::default()
            },
        );
        let out = run(bom, "com.example.pkg.bom");
        let m = marker(&out).expect("the duplicate must be reported");
        assert_eq!(m.metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            m.metadata["inventory_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert!(m.metadata["inventory_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("more than once"));
    }

    /// A receipt read short of its declared size holds fewer entries than the
    /// package installed, and a file list that does not say so reads as the
    /// full manifest.
    #[test]
    fn a_bom_read_short_of_its_declared_size_says_the_inventory_is_partial() {
        let bom = build_bom("hello.txt", 1234, 0o100644, 501, 20, 1_600_000_000);
        let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(bom));
        let out = run_source(src, "com.example.pkg.bom");
        let m = marker(&out).expect("the short read must be reported");
        assert_eq!(m.metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            m.metadata["inventory_incomplete_reason"],
            json!("short_read")
        );
        assert_eq!(m.metadata["entries_emitted"], json!(2));
    }

    /// A `.bom` whose header could not even be staged must not be mistaken for
    /// "not a BOM": the receipt would vanish from the case with no trace.
    #[test]
    fn a_bom_whose_header_was_never_staged_is_still_reported() {
        let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(Vec::new(), 4096));
        let out = run_source(src, "com.example.pkg.bom");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["type"], json!("BomEntryIncomplete"));
        assert_eq!(out[0].metadata["content_incomplete"], json!(true));
        assert_eq!(
            out[0].metadata["content_incomplete_reason"],
            json!("short_read")
        );
    }

    #[test]
    fn ignores_non_bom() {
        assert!(run(b"not a bom".to_vec(), "x.bom").is_empty());
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(vec![0u8; 8]))),
            json!({ "name": "photo.jpg" }),
        );
        assert!(BomParser.process(&art).unwrap().is_empty());
    }
}
