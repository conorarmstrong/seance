#![forbid(unsafe_code)]
//! F2FS (Flash-Friendly File System) parser plugin.
//!
//! F2FS is the default filesystem for the `/data` partition on modern Android
//! devices, so this parser is the entry point for recovering application data,
//! media, and databases from a phone image. It subscribes to `FileSystem`
//! artifacts that a detector has tagged as F2FS, parses the on-disk structures,
//! walks the directory tree from the root inode, and emits a `FileEntry` for
//! each file and directory with the byte-run (or inline) provenance needed to
//! re-serve content straight from the image.
//!
//! # Scope of this version
//!
//! * Reads the **NAT directly** (node id -> node block address). The current
//!   copy of a NAT block is selected by the `nat_bitmap` carried in the newer
//!   checkpoint pack; that bitmap is **not** consulted here, so on a heavily
//!   updated volume a node whose NAT block has been flipped to its mirror copy
//!   may resolve to a stale address. Freshly written / lightly used volumes
//!   (bitmap bit clear) resolve correctly.
//! * Data blocks are resolved from the inode's direct pointers plus the direct,
//!   single-indirect and double-indirect node chain. Every walk is bounded.
//! * Inline data and inline dentries are handled.
//! * **Not** handled: fsverity/encryption (fscrypt) is surfaced as opaque
//!   ciphertext (we do not decrypt), and compressed clusters are emitted by
//!   their raw on-disk runs (not decompressed).
//!
//! All parsing is defensive: every offset derives from attacker-controlled
//! header fields, so reads are bounds-checked, arithmetic saturates, recursion
//! and totals are capped, and malformed input yields fewer entries (or an empty
//! result) rather than a panic or unbounded memory use.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{TimeZone, Utc};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{byte_runs_to_metadata, ByteSliceDataSource, DataSource, RunListDataSource},
    io::{read_exact_or_fail, read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

// --- On-disk constants (from Linux include/linux/f2fs_fs.h) ---

/// The primary superblock lives at this fixed byte offset within the volume.
const F2FS_SUPER_OFFSET: u64 = 1024;
/// `f2fs_super_block.magic` (little-endian u32 at superblock offset 0).
const F2FS_MAGIC: u32 = 0xF2F5_2010;
/// F2FS only supports a 4 KiB block; `log_blocksize` must be 12.
const F2FS_LOG_BLOCKSIZE: u32 = 12;
/// `f2fs_super_block.feature` bit: inodes carry the extra-attribute area.
const F2FS_FEATURE_EXTRA_ATTR: u32 = 0x0008;

/// `sizeof(struct f2fs_nat_entry)` = version(1) + ino(4) + block_addr(4).
const NAT_ENTRY_SIZE: u64 = 9;
/// Entries per 4 KiB NAT block: floor(4096 / 9).
const NAT_ENTRY_PER_BLOCK: u32 = 455;
/// Byte offset of `block_addr` within an `f2fs_nat_entry`.
const NAT_ENTRY_BLOCK_ADDR_OFF: usize = 5;

/// Data-block pointers stored directly in an inode (`i_addr`), no extra attrs.
const DEF_ADDRS_PER_INODE: usize = 923;
/// Byte offset of `i_addr[0]` in a bare inode (before any extra-attr area).
const INODE_I_ADDR_OFF: usize = 360;
/// `i_nid[5]` sits after the full 923-entry `i_addr` union, at a fixed offset.
const INODE_I_NID_OFF: usize = INODE_I_ADDR_OFF + DEF_ADDRS_PER_INODE * 4; // 4052
/// Data-block pointers per direct node (`addr[]`), and node ids per indirect
/// node (`nid[]`): floor((4096 - sizeof(node_footer=24)) / 4).
const ADDRS_PER_BLOCK: usize = 1018;
const NIDS_PER_BLOCK: usize = 1018;
/// One reserved `__le32` slot precedes inline data in the `i_addr` region.
const DEF_INLINE_RESERVED_SIZE: usize = 1;

/// `i_inline` flag bits.
const F2FS_INLINE_XATTR: u8 = 0x01;
const F2FS_INLINE_DATA: u8 = 0x02;
const F2FS_INLINE_DENTRY: u8 = 0x04;

/// `i_advise` (inode offset 2) bit set by f2fs on an fscrypt-encrypted inode.
/// The kernel's `file_is_encrypt()` tests exactly this bit.
const FADVISE_ENCRYPT_BIT: u8 = 0x04;

/// `i_flags` (inode offset 80) bit marking a transparently-compressed file.
const F2FS_COMPR_FL: u32 = 0x0000_0004;

/// A block address of 0 is an unallocated hole; 0xffffffff (NEW_ADDR) is
/// reserved-but-unwritten. Both read back as zeros.
const NULL_ADDR: u32 = 0;
const NEW_ADDR: u32 = 0xffff_ffff;

// --- Directory (dentry-block) geometry ---

const F2FS_SLOT_LEN: usize = 8;
/// `sizeof(struct f2fs_dir_entry)` = hash(4) + ino(4) + name_len(2) + type(1).
const SIZE_OF_DIR_ENTRY: usize = 11;
/// Regular dentry block: NR_DENTRY_IN_BLOCK dir entries + name slots.
const NR_DENTRY_IN_BLOCK: usize = 214;
/// dentry_bitmap bytes: ceil(214 / 8).
const SIZE_OF_DENTRY_BITMAP: usize = 27;
/// dentry array offset in a dentry block: bitmap(27) + reserved(3).
const DENTRY_BLOCK_DENTRY_OFF: usize = 30;
/// filename array offset in a dentry block: 30 + 214*11.
const DENTRY_BLOCK_FILENAME_OFF: usize =
    DENTRY_BLOCK_DENTRY_OFF + NR_DENTRY_IN_BLOCK * SIZE_OF_DIR_ENTRY; // 2384

// --- Safety caps against malformed / adversarial images ---

/// Hard ceiling on emitted file entries so a crafted (or cyclic) tree cannot
/// exhaust memory.
const MAX_FILES: usize = 5_000_000;
/// Maximum directory-recursion depth.
const MAX_RECURSION_DEPTH: usize = 100;
/// Cap on logical blocks resolved for a single file (~8 GiB at 4 KiB blocks).
const MAX_FILE_BLOCKS: u64 = 1 << 21;

/// The record type of the volume's walk status: the refusal when the
/// superblock will not parse, and the summary when the walk fell short. Named
/// so the frontend's `walk_status` rule files it under *What could not be
/// read* (it was `f2fs_walk_summary`, which `summary` filed under *Derived
/// analysis* -- HUNT-173).
const WALK_STATUS_TYPE: &str = "f2fs_walk_status";
/// Cap on directory data blocks scanned (~256 MiB directory).
const MAX_DIR_BLOCKS: u64 = 1 << 16;
/// Cap on node-block reads while resolving one file's runs.
const MAX_NODE_READS: u64 = 200_000;

// --- Little-endian readers (defensive: never panic, zero-fill past the end) ---

fn rd_u16(b: &[u8], o: usize) -> u16 {
    let mut a = [0u8; 2];
    fill(&mut a, b, o);
    u16::from_le_bytes(a)
}
fn rd_u32(b: &[u8], o: usize) -> u32 {
    let mut a = [0u8; 4];
    fill(&mut a, b, o);
    u32::from_le_bytes(a)
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    fill(&mut a, b, o);
    u64::from_le_bytes(a)
}
/// Copy up to `dst.len()` bytes from `src[o..]`, leaving the rest zero. Any
/// out-of-range offset simply yields zeros rather than panicking.
fn fill(dst: &mut [u8], src: &[u8], o: usize) {
    if o >= src.len() {
        return;
    }
    let n = dst.len().min(src.len() - o);
    dst[..n].copy_from_slice(&src[o..o + n]);
}

// --- Plugin entry point ---

/// Parser for the F2FS filesystem.
#[derive(Debug, Default)]
pub struct F2fsParser;

impl F2fsParser {
    pub fn new() -> Self {
        Self
    }
}

impl ForensicsModule for F2fsParser {
    fn id(&self) -> &str {
        "plugin.fs.f2fs"
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
        // Gate on the detector's classification. It emits `subtype: "f2fs"` and
        // `filesystem_type: "F2FS"`; match either, case-insensitively, so a
        // caller passing "F2FS" does not silently skip the volume.
        let is_f2fs = |s: &str| s.eq_ignore_ascii_case("f2fs");
        if let Some(subtype) = artifact.subtype() {
            if !is_f2fs(subtype) {
                return Ok(Vec::new());
            }
        }
        let fs_type = artifact
            .metadata
            .get("filesystem_type")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !fs_type.is_empty() && !is_f2fs(fs_type) {
            return Ok(Vec::new());
        }

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("F2FS parser requires a data source".to_string())
        })?;

        // A superblock that will not parse is not a hard error -- the
        // detector may have matched a truncated or corrupt volume, and we must
        // never panic on untrusted input -- but neither is it "nothing here".
        // An empty list is folded into "ran with no output", which reads as a
        // volume with no files; the volume is refused on the record, with the
        // reason (HUNT-173).
        let sb = match Superblock::parse(data_source.as_ref()) {
            Ok(sb) => sb,
            Err(e) => {
                warn!("F2FS superblock parse failed for {}: {}", artifact.id, e);
                let reason = if e.to_string().starts_with("short read") {
                    IncompleteReason::ShortRead
                } else {
                    IncompleteReason::UnresolvedStructure
                };
                return Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": WALK_STATUS_TYPE,
                        "walked": false,
                        "superblock_error": e.to_string(),
                        "files_emitted": 0,
                        "inventory_incomplete": true,
                        "inventory_incomplete_reason": reason.as_str(),
                    }),
                )
                .with_parent(artifact.id)]);
            }
        };

        info!(
            "F2FS superblock: block_size={}, blocks_per_seg={}, nat_blkaddr={}, root_ino={}, feature=0x{:x}",
            sb.block_size, sb.blocks_per_seg, sb.nat_blkaddr, sb.root_ino, sb.feature
        );

        let mut produced = Vec::new();
        let mut ctx = Context {
            case_id: artifact.case_id,
            parent_id: artifact.id,
            source: data_source.clone(),
            sb: &sb,
            produced: &mut produced,
            visited_dirs: HashMap::new(),
            depth: 0,
            depth_capped: 0,
            files_capped: false,
            unresolved_inodes: 0,
        };

        parse_inode(&mut ctx, sb.root_ino, "/");
        let depth_capped = ctx.depth_capped;
        let files_capped = ctx.files_capped;
        let unresolved_inodes = ctx.unresolved_inodes;

        info!("F2FS parser emitted {} file entries", produced.len());

        // A `/data` tree that is a subset of the volume must say so. Without
        // this record a capped or partially-resolved walk was published as a
        // complete inventory, and "no such file" read as fact (B7-010).
        if depth_capped > 0 || files_capped || unresolved_inodes > 0 {
            warn!(
                "F2FS inventory is INCOMPLETE for {}: {} subtree(s) past the depth cap, \
                 file cap {}, {} inode(s) named but unresolvable",
                artifact.id, depth_capped, files_capped, unresolved_inodes
            );
            let reason = if files_capped || depth_capped > 0 {
                IncompleteReason::CapReached
            } else {
                IncompleteReason::UnresolvedStructure
            };
            let files_emitted = produced.len();
            produced.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": WALK_STATUS_TYPE,
                        "walked": true,
                        "files_emitted": files_emitted,
                        "subtrees_past_depth_cap": depth_capped,
                        "file_cap_reached": files_capped,
                        "unresolved_inodes": unresolved_inodes,
                        "inventory_incomplete": true,
                        "inventory_incomplete_reason": reason.as_str(),
                        "content_incomplete": true,
                        "content_incomplete_reason": reason.as_str(),
                    }),
                )
                .with_parent(artifact.id),
            );
        }
        Ok(produced)
    }
}

// --- Superblock ---

#[derive(Debug)]
struct Superblock {
    block_size: u64,
    blocks_per_seg: u64,
    nat_blkaddr: u32,
    root_ino: u32,
    feature: u32,
}

impl Superblock {
    fn parse(source: &dyn DataSource) -> Result<Self> {
        // The whole block-0 tail comfortably covers every field we read
        // (feature lives at superblock offset 2180). Fill the buffer with a
        // short-read loop and require every field we parse to have actually been
        // read: the buffer is pre-zeroed, so a partial read could otherwise pass
        // the magic check while later fields (nat_blkaddr, root_ino, feature) are
        // fabricated zeros. Fail closed instead.
        let mut buf = vec![0u8; 4096];
        let mut filled = 0usize;
        while filled < buf.len() {
            match source.read_at(F2FS_SUPER_OFFSET + filled as u64, &mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) => return Err(e.into()),
            }
        }
        // The highest field read is `feature` at superblock offset 2180 (u32),
        // i.e. we need at least 2184 bytes of the superblock present.
        const MIN_SUPERBLOCK_BYTES: usize = 2184;
        if filled < MIN_SUPERBLOCK_BYTES {
            return Err(anyhow!(
                "short read of F2FS superblock: {} of {} required bytes",
                filled,
                MIN_SUPERBLOCK_BYTES
            ));
        }

        let magic = rd_u32(&buf, 0);
        if magic != F2FS_MAGIC {
            return Err(anyhow!("invalid F2FS magic 0x{:08X}", magic));
        }

        // log_blocksize (offset 16). F2FS only supports 4 KiB blocks and every
        // per-block constant here (NAT entries, addr/nid counts, dentry
        // geometry) assumes it; reject anything else rather than mis-parse.
        let log_blocksize = rd_u32(&buf, 16);
        if log_blocksize != F2FS_LOG_BLOCKSIZE {
            return Err(anyhow!(
                "unsupported F2FS log_blocksize {} (only 4 KiB / 12 supported)",
                log_blocksize
            ));
        }
        let block_size = 1u64 << log_blocksize;

        // log_blocks_per_seg (offset 20) drives the NAT mirror stride below.
        let log_blocks_per_seg = rd_u32(&buf, 20);
        if log_blocks_per_seg > 30 {
            return Err(anyhow!(
                "implausible F2FS log_blocks_per_seg {}",
                log_blocks_per_seg
            ));
        }
        let blocks_per_seg = 1u64 << log_blocks_per_seg;

        let nat_blkaddr = rd_u32(&buf, 84);
        let root_ino = rd_u32(&buf, 96);
        // feature flags at offset 2180 (post volume_name/extension_list/version).
        let feature = rd_u32(&buf, 2180);

        Ok(Superblock {
            block_size,
            blocks_per_seg,
            nat_blkaddr,
            root_ino,
            feature,
        })
    }
}

/// Byte offset of the physical block that holds NAT entry `nid`.
///
/// Mirrors the kernel's `current_nat_addr()` with the checkpoint `nat_bitmap`
/// assumed all-zero (the primary copy). For a NAT block offset within the first
/// segment this reduces to `nat_blkaddr + block_off`; the general form keeps
/// larger volumes correct for un-flipped blocks.
fn nat_entry_offset(sb: &Superblock, nid: u32) -> u64 {
    let block_off = (nid / NAT_ENTRY_PER_BLOCK) as u64;
    let seg_mask = sb.blocks_per_seg.saturating_sub(1);
    let block_addr = (sb.nat_blkaddr as u64)
        .saturating_add(block_off << 1)
        .saturating_sub(block_off & seg_mask);
    let entry_in_block = (nid % NAT_ENTRY_PER_BLOCK) as u64;
    block_addr
        .saturating_mul(sb.block_size)
        .saturating_add(entry_in_block.saturating_mul(NAT_ENTRY_SIZE))
}

/// Resolve `nid` to the physical block address of its node, via the NAT.
/// Returns `None` when the entry could not be read in full; the caller treats
/// NULL/NEW addresses as "no node".
///
/// The read is gathered with `read_full` rather than a single `read_at`. A
/// windowed or container-backed image routinely hands back fewer bytes than
/// asked for, and a `None` here is expensive: `collect_node` reserves the whole
/// subtree as holes and marks the file's reconstruction incomplete, so treating
/// an ordinary partial read as a NAT miss would punch fabricated holes into a
/// file that is entirely readable.
fn lookup_nat(source: &dyn DataSource, sb: &Superblock, nid: u32) -> Option<u32> {
    let offset = nat_entry_offset(sb, nid);
    let mut entry = [0u8; NAT_ENTRY_SIZE as usize];
    if read_full(source, offset, &mut entry) < NAT_ENTRY_SIZE as usize {
        return None;
    }
    Some(rd_u32(&entry, NAT_ENTRY_BLOCK_ADDR_OFF))
}

// --- Inode ---

#[derive(Debug)]
struct Inode {
    mode: u16,
    inline: u8,
    /// `i_advise` byte (offset 2): carries the persistent fscrypt marker.
    advise: u8,
    /// `i_flags` (offset 80): carries the compression marker.
    flags: u32,
    size: u64,
    atime: (i64, u32),
    ctime: (i64, u32),
    mtime: (i64, u32),
    /// Bytes of extra-attribute area (0 when the feature is off). The data
    /// pointer array `i_addr` begins this many bytes past its bare offset.
    extra_isize: usize,
    /// Usable data-block pointers held directly in the inode.
    addrs_per_inode: usize,
    /// The full 4 KiB node block, retained for direct/inline pointer reads.
    raw: Vec<u8>,
}

impl Inode {
    fn parse(raw: Vec<u8>, feature: u32) -> Self {
        let mode = rd_u16(&raw, 0);
        let advise = raw.get(2).copied().unwrap_or(0);
        let inline = raw.get(3).copied().unwrap_or(0);
        let flags = rd_u32(&raw, 80);
        let size = rd_u64(&raw, 16);
        let atime = (rd_u64(&raw, 32) as i64, rd_u32(&raw, 56));
        let ctime = (rd_u64(&raw, 40) as i64, rd_u32(&raw, 60));
        let mtime = (rd_u64(&raw, 48) as i64, rd_u32(&raw, 64));

        // extra-attr geometry. i_extra_isize / i_inline_xattr_size are only
        // meaningful when the EXTRA_ATTR feature is set; otherwise i_addr starts
        // at its bare offset and all 923 pointers are data addresses.
        let (extra_isize, inline_xattr_size) = if feature & F2FS_FEATURE_EXTRA_ATTR != 0 {
            (rd_u16(&raw, 360) as usize, rd_u16(&raw, 362) as usize)
        } else {
            (0, 0)
        };
        // Clamp a garbage extra_isize so the addr base stays inside the block.
        let extra_isize = extra_isize.min(DEF_ADDRS_PER_INODE * 4);
        let extra_words = extra_isize / 4;
        let inline_xattr_words = if inline & F2FS_INLINE_XATTR != 0 {
            inline_xattr_size
        } else {
            0
        };
        let addrs_per_inode = DEF_ADDRS_PER_INODE
            .saturating_sub(extra_words)
            .saturating_sub(inline_xattr_words);

        Inode {
            mode,
            inline,
            advise,
            flags,
            size,
            atime,
            ctime,
            mtime,
            extra_isize,
            addrs_per_inode,
            raw,
        }
    }

    fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000 // S_IFDIR
    }

    /// fscrypt-encrypted: the block pointers reference ciphertext we do not
    /// decrypt, so the served content is opaque ciphertext.
    fn is_encrypted(&self) -> bool {
        self.advise & FADVISE_ENCRYPT_BIT != 0
    }

    /// Transparently-compressed: the raw block runs are compressed clusters this
    /// parser does not decompress.
    fn is_compressed(&self) -> bool {
        self.flags & F2FS_COMPR_FL != 0
    }
    fn is_file(&self) -> bool {
        self.mode & 0xF000 == 0x8000 // S_IFREG
    }
    fn has_inline_data(&self) -> bool {
        self.inline & F2FS_INLINE_DATA != 0
    }
    fn has_inline_dentry(&self) -> bool {
        self.inline & F2FS_INLINE_DENTRY != 0
    }

    /// Byte offset of the (extra-attr-adjusted) `i_addr[0]`.
    fn addr_base(&self) -> usize {
        INODE_I_ADDR_OFF + self.extra_isize
    }
    /// Byte offset where inline data / inline dentries begin (one reserved slot
    /// past `i_addr[0]`).
    fn inline_area(&self) -> usize {
        self.addr_base() + DEF_INLINE_RESERVED_SIZE * 4
    }
    /// Maximum inline payload: `sizeof(__le32) * (addrs_per_inode - reserved)`.
    fn inline_max(&self) -> usize {
        4 * self
            .addrs_per_inode
            .saturating_sub(DEF_INLINE_RESERVED_SIZE)
    }
}

// --- Data-block (run) resolution ---

/// Capacity, in data blocks, of the subtree reached through one `i_nid` slot at
/// the given indirection `level` (0 = direct node, 1 = indirect, 2 = double).
fn subtree_blocks(level: u8) -> u64 {
    let addrs = ADDRS_PER_BLOCK as u64;
    let nids = NIDS_PER_BLOCK as u64;
    match level {
        0 => addrs,
        1 => nids.saturating_mul(addrs),
        _ => nids.saturating_mul(nids).saturating_mul(addrs),
    }
}

/// Collect a file/directory's data-block addresses in logical order, up to
/// `capped` blocks. Holes (unallocated subtrees or NULL/NEW pointers) are
/// recorded as 0. `complete` is set false if any bound truncated the walk.
fn collect_addrs(
    source: &dyn DataSource,
    sb: &Superblock,
    inode: &Inode,
    capped: u64,
    complete: &mut bool,
) -> Vec<u32> {
    let mut addrs: Vec<u32> = Vec::new();

    // 1. Direct data pointers held in the inode itself.
    let base = inode.addr_base();
    for i in 0..inode.addrs_per_inode {
        if addrs.len() as u64 >= capped {
            return addrs;
        }
        addrs.push(rd_u32(&inode.raw, base + i * 4));
    }

    // 2. The i_nid chain: two direct nodes, two indirect, one double-indirect.
    let mut node_budget = MAX_NODE_READS;
    let levels: [u8; 5] = [0, 0, 1, 1, 2];
    for (k, &level) in levels.iter().enumerate() {
        if addrs.len() as u64 >= capped {
            break;
        }
        let nid = rd_u32(&inode.raw, INODE_I_NID_OFF + k * 4);
        collect_node(
            source,
            sb,
            nid,
            level,
            capped,
            &mut addrs,
            &mut node_budget,
            complete,
        );
    }
    addrs
}

/// Recursively gather data-block addresses from a node subtree. `level` 0 reads
/// a direct node's `addr[]`; higher levels read a node's `nid[]` and recurse.
///
/// A subtree this walk cannot resolve — budget exhausted, NAT miss, node block
/// off the end of the image, short read — still occupies its full span of the
/// file's logical block space. Its slots are therefore reserved as holes and
/// `complete` is cleared, never simply skipped: skipping would pull every later
/// `i_nid` subtree leftward, so an examiner would get a file whose surviving
/// bytes sit at the wrong offsets rather than one that is honestly short. A
/// shifted file still hashes, so nothing downstream could catch the error.
#[allow(clippy::too_many_arguments)]
fn collect_node(
    source: &dyn DataSource,
    sb: &Superblock,
    nid: u32,
    level: u8,
    capped: u64,
    addrs: &mut Vec<u32>,
    node_budget: &mut u64,
    complete: &mut bool,
) {
    if addrs.len() as u64 >= capped {
        return;
    }
    let remaining = capped - addrs.len() as u64;

    // A zero node id (or an unallocated node address) means the whole subtree is
    // sparse: emit holes so later, allocated subtrees keep their logical offset.
    let fill_holes = |addrs: &mut Vec<u32>| {
        let n = subtree_blocks(level).min(remaining);
        addrs.resize(addrs.len() + n as usize, NULL_ADDR);
    };
    // An unresolvable subtree: reserve its logical span so what follows stays in
    // place, and record that this file's run list is not the whole story.
    let unresolved = |addrs: &mut Vec<u32>, complete: &mut bool| {
        fill_holes(addrs);
        *complete = false;
    };
    if nid == 0 {
        fill_holes(addrs);
        return;
    }
    if *node_budget == 0 {
        unresolved(addrs, complete);
        return;
    }
    *node_budget -= 1;

    let block_addr = match lookup_nat(source, sb, nid) {
        Some(b) => b,
        None => {
            unresolved(addrs, complete);
            return;
        }
    };
    if block_addr == NULL_ADDR || block_addr == NEW_ADDR {
        fill_holes(addrs);
        return;
    }
    let offset = (block_addr as u64).saturating_mul(sb.block_size);
    if offset >= source.size() {
        unresolved(addrs, complete);
        return;
    }
    let mut block = vec![0u8; sb.block_size as usize];
    // Fail closed on a short read. The buffer is pre-zeroed, so a partial node
    // block would have its tail parsed as real NULL_ADDR block pointers —
    // fabricated holes in the middle of a file (BUG-244).
    if read_exact_or_fail(source, offset, &mut block, "F2FS node block").is_err() {
        unresolved(addrs, complete);
        return;
    }

    if level == 0 {
        for i in 0..ADDRS_PER_BLOCK {
            if addrs.len() as u64 >= capped {
                return;
            }
            addrs.push(rd_u32(&block, i * 4));
        }
    } else {
        for i in 0..NIDS_PER_BLOCK {
            if addrs.len() as u64 >= capped {
                return;
            }
            let child = rd_u32(&block, i * 4);
            collect_node(
                source,
                sb,
                child,
                level - 1,
                capped,
                addrs,
                node_budget,
                complete,
            );
        }
    }
}

/// Build the `data_runs` metadata and a backing data source for a regular file.
/// Returns `None` for empty or inline files (the caller handles inline).
fn build_file_runs(
    ctx: &Context,
    inode: &Inode,
    metadata: &mut serde_json::Value,
) -> Option<Arc<dyn DataSource>> {
    if inode.size == 0 {
        return None;
    }
    let block_size = ctx.sb.block_size;
    let total_blocks = inode.size.div_ceil(block_size);
    let capped = total_blocks.min(MAX_FILE_BLOCKS);
    let cap_reached = total_blocks > MAX_FILE_BLOCKS;
    let mut complete = !cap_reached;

    let addrs = collect_addrs(ctx.source.as_ref(), ctx.sb, inode, capped, &mut complete);

    // Turn block addresses into byte runs, clamping the final run so the runs
    // sum to exactly i_size (the last block is usually partial).
    let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
    let mut acc = 0u64;
    for &a in &addrs {
        if acc >= inode.size {
            break;
        }
        let len = block_size.min(inode.size - acc);
        let off = if a == NULL_ADDR || a == NEW_ADDR {
            None // hole -> zero-filled
        } else {
            Some((a as u64).saturating_mul(block_size))
        };
        runs.push((off, len));
        acc += len;
    }
    if runs.is_empty() {
        return None;
    }

    let (runs_json, meta_complete) = byte_runs_to_metadata(&runs);
    metadata["data_runs"] = runs_json;
    metadata["data_runs_complete"] = json!(complete && meta_complete);
    if cap_reached {
        // Only the first MAX_FILE_BLOCKS (8 GiB) blocks were mapped; the rest
        // of the file was never looked at. Said as the cap it is, not as an
        // unresolved structure, which would send an examiner looking for
        // corruption that is not there (HUNT-173).
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!(IncompleteReason::CapReached.as_str());
        metadata["file_blocks_mapped"] = json!(capped);
        metadata["file_blocks_total"] = json!(total_blocks);
    } else if !complete {
        // Some subtree of the node tree could not be resolved. Its logical span
        // is held open as holes so the rest of the file stays at the right
        // offsets, but those bytes are unknown, not known-to-be-zero: the served
        // content and its hash are of a partially reconstructed file.
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] =
            json!(IncompleteReason::UnresolvedStructure.as_str());
    }

    // The loop above already caps each run at the remaining `inode.size`, so
    // this is a no-op today; stating the logical size keeps it one if that
    // capping is ever refactored, rather than silently serving the last
    // block's slack as file content.
    Some(Arc::new(RunListDataSource::with_logical_size(
        ctx.source.clone(),
        runs,
        inode.size,
    )))
}

// --- Directory entries ---

/// A resolved directory entry: (node id, name, F2FS file type).
type Dentry = (u32, String, u8);

/// Read every child entry of a directory inode (inline or block-based).
///
/// Returns the entries plus `None` when the whole directory was enumerated, or
/// `Some(reason)` when it was not: the node tree would not resolve, a dentry
/// block could not be read, or a safety cap (`MAX_DIR_BLOCKS`, `MAX_FILES`)
/// stopped the walk. A short listing that reports itself complete tells an
/// examiner a file was not in that directory when the tool simply never read
/// the block naming it (B2-155).
fn read_dir_entries(ctx: &Context, inode: &Inode) -> (Vec<Dentry>, Option<IncompleteReason>) {
    let mut out = Vec::new();

    if inode.has_inline_dentry() {
        parse_inline_dentry(inode, &mut out);
        return (out, None);
    }

    // Block-based directory: resolve its data blocks and parse each as a
    // dentry block.
    let block_size = ctx.sb.block_size;
    let declared_blocks = inode.size.div_ceil(block_size);
    let total_blocks = declared_blocks.min(MAX_DIR_BLOCKS);
    if total_blocks == 0 {
        return (out, None);
    }
    // The block cap drops the tail of a large directory outright.
    let mut incomplete = (declared_blocks > MAX_DIR_BLOCKS).then_some(IncompleteReason::CapReached);
    let mut complete = true;
    let addrs = collect_addrs(
        ctx.source.as_ref(),
        ctx.sb,
        inode,
        total_blocks,
        &mut complete,
    );
    if !complete && incomplete.is_none() {
        // Part of the node tree naming this directory's blocks was unreadable.
        incomplete = Some(IncompleteReason::UnresolvedStructure);
    }

    for &a in &addrs {
        if a == NULL_ADDR || a == NEW_ADDR {
            continue;
        }
        let offset = (a as u64).saturating_mul(block_size);
        if offset >= ctx.source.size() {
            // The block address points past the end of the image: the entries
            // it holds are unreadable, not absent.
            incomplete.get_or_insert(IncompleteReason::ShortRead);
            continue;
        }
        let mut block = vec![0u8; block_size as usize];
        // A partially read dentry block would have its zero tail parsed as
        // real (empty) dentry slots; skip it rather than invent entries.
        if read_exact_or_fail(ctx.source.as_ref(), offset, &mut block, "F2FS dentry block").is_err()
        {
            incomplete.get_or_insert(IncompleteReason::ShortRead);
            continue;
        }
        parse_dentries(
            &block,
            0,
            SIZE_OF_DENTRY_BITMAP,
            DENTRY_BLOCK_DENTRY_OFF,
            DENTRY_BLOCK_FILENAME_OFF,
            NR_DENTRY_IN_BLOCK,
            &mut out,
        );
        if out.len() >= MAX_FILES {
            incomplete.get_or_insert(IncompleteReason::CapReached);
            break;
        }
    }
    (out, incomplete)
}

/// Parse an inline directory stored in the inode's `i_addr` region. The
/// geometry (entry count, bitmap size, reserved padding) is derived from the
/// inline payload size exactly as the kernel computes it.
fn parse_inline_dentry(inode: &Inode, out: &mut Vec<Dentry>) {
    let base = inode.inline_area();
    let max_inline = inode.inline_max();
    if max_inline == 0 {
        return;
    }
    // NR_INLINE_DENTRY = max_inline * 8 / ((SIZE_OF_DIR_ENTRY + SLOT) * 8 + 1).
    let nr = (max_inline * 8) / ((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * 8 + 1);
    if nr == 0 {
        return;
    }
    let bitmap_size = nr.div_ceil(8);
    let used = (SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * nr + bitmap_size;
    let reserved = max_inline.saturating_sub(used);
    let dentry_off = base + bitmap_size + reserved;
    let filename_off = dentry_off + nr * SIZE_OF_DIR_ENTRY;
    parse_dentries(
        &inode.raw,
        base,
        bitmap_size,
        dentry_off,
        filename_off,
        nr,
        out,
    );
}

/// Walk the set bits of a dentry bitmap, decoding one `f2fs_dir_entry` per run
/// of slots. Shared by block and inline directories. Every index is
/// bounds-checked against `buf`; a zero-length name advances by one slot so a
/// crafted entry cannot spin the loop.
#[allow(clippy::too_many_arguments)]
fn parse_dentries(
    buf: &[u8],
    bitmap_off: usize,
    bitmap_size: usize,
    dentry_off: usize,
    filename_off: usize,
    max_entries: usize,
    out: &mut Vec<Dentry>,
) {
    if bitmap_off + bitmap_size > buf.len() {
        return;
    }
    let mut bit = 0usize;
    while bit < max_entries {
        // F2FS uses little-endian bit order (f2fs_test_bit / test_bit_le).
        let set = (buf[bitmap_off + bit / 8] >> (bit % 8)) & 1 == 1;
        if !set {
            bit += 1;
            continue;
        }
        let de = dentry_off + bit * SIZE_OF_DIR_ENTRY;
        if de + SIZE_OF_DIR_ENTRY > buf.len() {
            break;
        }
        let ino = rd_u32(buf, de + 4);
        let name_len = rd_u16(buf, de + 8) as usize;
        let file_type = buf[de + 10];
        let slots = name_len.div_ceil(F2FS_SLOT_LEN).max(1);

        if ino != 0 && name_len > 0 {
            let name_start = filename_off + bit * F2FS_SLOT_LEN;
            let name_end = (name_start + name_len).min(buf.len());
            if name_start < name_end {
                let name = String::from_utf8_lossy(&buf[name_start..name_end]).to_string();
                out.push((ino, name, file_type));
            }
        }

        bit += slots;
        if out.len() >= MAX_FILES {
            break;
        }
    }
}

// --- Tree walk ---

struct Context<'a> {
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    source: Arc<dyn DataSource>,
    sb: &'a Superblock,
    produced: &'a mut Vec<Artifact>,
    /// Directory node ids already descended into. A corrupt/cyclic directory
    /// graph would otherwise re-descend the same directory; visiting each dir at
    /// most once keeps the walk linear.
    /// Directories already emitted, by node id, with the index of their
    /// `FileEntry` in `produced` -- so a directory reached a second time
    /// through a cyclic graph is recorded on the first entry, not emitted
    /// again under a second path (HUNT-173).
    visited_dirs: HashMap<u32, usize>,
    depth: usize,
    /// Subtrees abandoned at `MAX_RECURSION_DEPTH`. Everything below them is
    /// absent from the inventory (B7-010).
    depth_capped: u64,
    /// True once `MAX_FILES` stopped the walk: files exist that were never
    /// enumerated (B7-010).
    files_capped: bool,
    /// Children named by a directory whose inode could not be resolved (NAT
    /// miss, unallocated/short block). Their absence is a failure to read, not
    /// evidence that the file was not there (B7-010).
    unresolved_inodes: u64,
}

/// Parse the inode at `nid`, emit its `FileEntry`, and recurse into it if it is
/// a directory. Best-effort: any failure to read/parse this inode simply omits
/// it (and its subtree) rather than aborting the whole volume.
fn parse_inode(ctx: &mut Context, nid: u32, path: &str) {
    // Every bare return below drops this inode AND its whole subtree. Counted
    // here so the volume can say its inventory is short instead of presenting a
    // partial `/data` tree as the complete one (B7-010).
    if ctx.depth > MAX_RECURSION_DEPTH {
        ctx.depth_capped += 1;
        return;
    }
    if ctx.produced.len() >= MAX_FILES {
        ctx.files_capped = true;
        return;
    }

    let block_addr = match lookup_nat(ctx.source.as_ref(), ctx.sb, nid) {
        Some(b) => b,
        None => {
            ctx.unresolved_inodes += 1;
            return;
        }
    };
    if block_addr == NULL_ADDR || block_addr == NEW_ADDR {
        ctx.unresolved_inodes += 1;
        return;
    }
    let offset = (block_addr as u64).saturating_mul(ctx.sb.block_size);
    if offset >= ctx.source.size() {
        ctx.unresolved_inodes += 1;
        return;
    }
    let mut raw = vec![0u8; ctx.sb.block_size as usize];
    // Fail closed on a short read: the pre-zeroed tail would be parsed as real
    // mode bits, sizes and block addresses. A partial inode block is not an
    // inode (BUG-244).
    if read_exact_or_fail(ctx.source.as_ref(), offset, &mut raw, "F2FS inode block").is_err() {
        ctx.unresolved_inodes += 1;
        return;
    }

    let inode = Inode::parse(raw, ctx.sb.feature);
    // An all-zero (unallocated) inode has mode 0; skip it. A directory entry
    // named it, so this is a name whose inode we could not recover.
    if inode.mode == 0 {
        ctx.unresolved_inodes += 1;
        return;
    }

    let name = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent_path = Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut metadata = json!({
        "name": name,
        "path": path,
        "parent_path": parent_path,
        "inode": nid,
        "size": inode.size,
        "is_directory": inode.is_dir(),
        "mode": inode.mode,
        "modified": fmt_ts(inode.mtime.0, inode.mtime.1),
        "changed": fmt_ts(inode.ctime.0, inode.ctime.1),
        "accessed": fmt_ts(inode.atime.0, inode.atime.1),
    });

    // Attach content provenance for regular files: inline bytes for small files,
    // otherwise byte runs resolved from the block pointers.
    let file_source: Option<Arc<dyn DataSource>> = if inode.is_file() {
        if inode.has_inline_data() {
            let start = inode.inline_area();
            let len = (inode.size as usize).min(inode.inline_max());
            if len > 0 && start + len <= inode.raw.len() {
                let data = inode.raw[start..start + len].to_vec();
                metadata["resident_data_b64"] = json!(BASE64.encode(&data));
                Some(Arc::new(ByteSliceDataSource::new(data)))
            } else {
                None
            }
        } else {
            build_file_runs(ctx, &inode, &mut metadata)
        }
    } else {
        None
    };

    // Honesty flags: the block pointers we serve/hash reference ciphertext
    // (fscrypt) or undecompressed clusters. Emit machine-readable markers so an
    // examiner is not handed high-entropy "file content" with no signal that it
    // is not plaintext (BUG-165). Mirrors the flags the btrfs parser sets.
    if inode.is_encrypted() {
        metadata["encrypted"] = json!(true);
        metadata["content_ciphertext"] = json!("f2fs_fscrypt");
    }
    if inode.is_compressed() {
        metadata["compression_unsupported"] = json!("f2fs");
    }
    // `content_incomplete` is the flag the API, export and integrity-verify
    // paths read; the two keys above are for display only. Without it,
    // ciphertext and compressed clusters travel the same code path as plaintext
    // and their digests are recorded as digests of the file's actual bytes
    // (B2-007). An already-set reason (an unresolved node subtree) is left
    // alone: it describes a defect in the reconstruction itself.
    if metadata.get("content_incomplete").is_none() {
        let opaque = if inode.is_encrypted() {
            Some(IncompleteReason::Encrypted)
        } else if inode.is_compressed() {
            Some(IncompleteReason::Compressed)
        } else {
            None
        };
        if let Some(reason) = opaque {
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] = json!(reason.as_str());
        }
    }

    let dir_artifact_idx = ctx.produced.len();
    if inode.is_dir() {
        // Cycle guard: a directory reached twice is corrupt/cyclic. Checked
        // before the push, so it is emitted once, under the path it was first
        // reached by; the other path is recorded on that entry rather than
        // minting a second one, and it is not re-descended.
        if let Some(&first) = ctx.visited_dirs.get(&nid) {
            if let Some(md) = ctx
                .produced
                .get_mut(first)
                .and_then(|a| a.metadata.as_object_mut())
            {
                let also = md.entry("also_reached_at").or_insert_with(|| json!([]));
                if let Some(list) = also.as_array_mut() {
                    list.push(json!(path));
                }
            }
            return;
        }
        ctx.visited_dirs.insert(nid, dir_artifact_idx);
    }
    let artifact = Artifact::new(ctx.case_id, ArtifactType::FileEntry, file_source, metadata)
        .with_parent(ctx.parent_id);
    ctx.produced.push(artifact);

    if inode.is_dir() {
        let (entries, dir_incomplete) = read_dir_entries(ctx, &inode);
        if let Some(reason) = dir_incomplete {
            // The listing below is a subset of the directory. Stamp it on the
            // directory's own artifact so "no such file here" can never be
            // read as fact when the tool never got to the block naming it.
            if let Some(md) = ctx
                .produced
                .get_mut(dir_artifact_idx)
                .and_then(|a| a.metadata.as_object_mut())
            {
                md.insert("directory_parse_incomplete".to_string(), json!(true));
                md.insert(
                    "directory_parse_incomplete_reason".to_string(),
                    json!(reason.as_str()),
                );
            }
        }
        for (child_nid, child_name, _ft) in entries {
            if child_name == "." || child_name == ".." || child_name.is_empty() {
                continue;
            }
            let child_path = if path == "/" {
                format!("/{}", child_name)
            } else {
                format!("{}/{}", path, child_name)
            };
            ctx.depth += 1;
            parse_inode(ctx, child_nid, &child_path);
            ctx.depth -= 1;
        }
    }
}

/// Format an F2FS timestamp (epoch seconds + nanoseconds) as RFC 3339. An unset
/// (all-zero) or out-of-range value yields an empty string.
fn fmt_ts(secs: i64, nanos: u32) -> String {
    if secs == 0 && nanos == 0 {
        return String::new();
    }
    match Utc.timestamp_opt(secs, nanos).single() {
        Some(dt) => dt.to_rfc3339(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests;
