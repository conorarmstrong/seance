#![forbid(unsafe_code)]
// XFS Filesystem Parser
//
// Implements full directory traversal including:
// - Shortform directories (inline in inode data fork)
// - Block directories (single block with XDB3 magic)
// - Leaf/node directories (multi-block with B-tree index)
// - B-tree extent resolution for large files/directories
// - Recursive inode walking to produce FileEntry artifacts
//
// References:
// - XFS Filesystem Structure: https://xfs.org/docs/xfsdocs-xml-dev/XFS_Filesystem_Structure/tmp/en-US/html/index.html
// - XFS Algorithms & Data Structures: http://ftp.ntu.edu.tw/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf
// - Linux Kernel XFS Documentation: https://www.kernel.org/doc/html/v6.12/admin-guide/xfs.html

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use chrono::{TimeZone, Utc};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::{read_exact_or_fail, read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::fmt;
use std::io;
use std::sync::Arc;
use tracing::{debug, info, warn};

// --- Constants ---

const XFS_SB_MAGIC: u32 = 0x58465342; // "XFSB"

// Inode data fork format
const XFS_DINODE_FMT_LOCAL: u8 = 1; // Inline data (shortform dirs, small files)
const XFS_DINODE_FMT_EXTENTS: u8 = 2; // Extent list
const XFS_DINODE_FMT_BTREE: u8 = 3; // B-tree of extents

// Directory block magic numbers (v3/v5 format)
const XFS_DIR3_BLOCK_MAGIC: u32 = 0x58444233; // "XDB3" — single-block directory
const XFS_DIR3_DATA_MAGIC: u32 = 0x58444433; // "XDD3" — multi-block directory data
                                             // v2/v4 format equivalents
const XFS_DIR2_BLOCK_MAGIC: u32 = 0x58443242; // "XD2B"
const XFS_DIR2_DATA_MAGIC: u32 = 0x58443244; // "XD2D"

// B-tree magic numbers
const XFS_BMAP_MAGIC: u32 = 0x424d4150; // "BMAP" — v2 B-tree extent block
const XFS_BMAP3_MAGIC: u32 = 0x424d4133; // "BMA3" — v3 B-tree extent block

// Inode core size (v3 inode format for XFS v5)
const XFS_V3_DINODE_CORE_SIZE: usize = 176;
// v2 inode core size (for XFS v4)
const XFS_V2_DINODE_CORE_SIZE: usize = 100;

// Mode bits
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;

// Limits
const MAX_RECURSION_DEPTH: usize = 64;
const MAX_DIR_ENTRIES: usize = 500_000;
/// Cap on directory data blocks walked for one directory. `di_size` is
/// attacker-controlled, and the XFS directory logical space runs to 32 GiB.
/// Hitting this cap makes the listing incomplete (BUG-213).
const MAX_DIR_DATA_BLOCKS: u64 = 262_144;
const MAX_EXTENTS: usize = 100_000;
const MAX_BTREE_DEPTH: usize = 8;

// --- Data Structures ---

#[derive(Debug)]
struct XfsSuperblock {
    _magic: u32,
    blocksize: u32,
    dblocks: u64,
    _rblocks: u64,
    agcount: u32,
    agblocks: u32,
    /// log2 of blocks-per-AG (sb_agblklog); splits an fsbno into (agno, agbno).
    agblklog: u8,
    sectsize: u16,
    inodesize: u16,
    inopblock: u16,
    version: u16,
    uuid: [u8; 16],
    fname: String,
    rootino: u64,
    /// v5 feature flags (sb_features_incompat at offset 460)
    v5: bool,
    /// XFS_SB_FEAT_INCOMPAT_BIGTIME: inode timestamps are a single 64-bit
    /// big-endian nanosecond count (since 1901-12-13 20:45:52 UTC) rather
    /// than the legacy 32-bit sec/nsec pair. See `decode_bigtime` for the
    /// conversion.
    bigtime: bool,
    /// XFS_SB_FEAT_INCOMPAT_NREXT64: 64-bit di_big_nextents at inode offset 0x18
    /// (legacy di_nextents at 0x4c is padding).
    nrext64: bool,
    /// Directory entries carry a 1-byte file type between the name and the
    /// inode number. Mandatory on v5; on v4 it is opt-in via
    /// `XFS_SB_VERSION2_FTYPE` in `sb_features2`. Getting this wrong shifts
    /// every directory entry by one byte, so children resolve to garbage inode
    /// numbers and whole subtrees vanish from the inventory.
    ftype: bool,
}

impl XfsSuperblock {
    fn dinode_core_size(&self) -> usize {
        if self.v5 {
            XFS_V3_DINODE_CORE_SIZE
        } else {
            XFS_V2_DINODE_CORE_SIZE
        }
    }
}

#[derive(Debug, Clone)]
struct XfsInode {
    _ino: u64,
    mode: u16,
    format: u8,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    /// Raw 8-byte big-endian `xfs_timestamp_t` for di_atime/di_mtime/di_ctime.
    /// Under the legacy layout this is {sec: u32, nsec: u32}; under bigtime
    /// it is one 64-bit nanosecond count. Kept raw here so the caller can
    /// pick the right decode once it knows which layout applies
    /// (`superblock.bigtime`).
    atime_raw: u64,
    mtime_raw: u64,
    ctime_raw: u64,
    /// di_crtime (creation time), only present in the v3 inode core (v5
    /// filesystems). `None` on v4, where this byte range belongs to the
    /// data fork instead.
    crtime_raw: Option<u64>,
    _nextents: u32,
    extents: Vec<XfsExtent>,
    /// Set when `extents` is NOT the complete on-disk extent list: the btree
    /// walk failed outright (BUG-162), or a safety cap truncated a non-empty
    /// list (BUG-238). Either way the FileEntry must declare its content
    /// incomplete rather than look like a valid full-size file whose missing
    /// tail is a sparse hole.
    extents_incomplete: Option<IncompleteReason>,
    /// Raw data fork bytes (for LOCAL format inodes)
    dfork_data: Vec<u8>,
}

impl XfsInode {
    fn is_dir(&self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }

    fn is_file(&self) -> bool {
        (self.mode & S_IFMT) == S_IFREG
    }

    fn is_symlink(&self) -> bool {
        (self.mode & S_IFMT) == S_IFLNK
    }
}

#[derive(Debug, Clone, Copy)]
struct XfsExtent {
    logical: u64,
    physical: u64,
    count: u64,
    /// Preallocated but never written (extent state flag, bit 127). The kernel
    /// serves zeros for these blocks; the residual bytes still on disk are not
    /// file content (BUG-208).
    unwritten: bool,
}

/// Convert an XFS filesystem block number (fsbno) into an absolute device block.
///
/// An fsbno is NOT a linear block index: it packs (agno, agbno) as
/// `agno << sb_agblklog | agbno`, and the AG's first block sits at
/// `agno * sb_agblocks`. Multiplying a raw fsbno by the block size only happens
/// to work when `agblocks == 1 << agblklog`; every other geometry reads the
/// wrong physical blocks (BUG-239). Every fsbno consumer — extents, data runs
/// and bmap btree pointers alike — must go through here.
fn fsbno_to_abs_block(fsbno: u64, agblocks: u64, agblklog: u8) -> u64 {
    // agblklog is a raw superblock byte used as a shift width. parse_xfs_superblock
    // already rejects >= 64, but keep the guard local so no caller can panic.
    if agblklog >= 64 {
        return fsbno;
    }
    let agno = fsbno >> agblklog;
    let agbno = fsbno & ((1u64 << agblklog) - 1);
    agno.saturating_mul(agblocks).saturating_add(agbno)
}

// --- XFS File Data Source ---
// Maps extent-based file data through the filesystem data source.

struct XfsFileSource {
    inner: Arc<dyn DataSource>,
    blocksize: u32,
    /// blocks per allocation group and its log2, to decode an extent's fsbno
    /// (startblock) into an absolute device block: agno*agblocks + agbno.
    agblocks: u32,
    agblklog: u8,
    size: u64,
    extents: Vec<XfsExtent>,
    /// True when `extents` is the complete on-disk extent list. When false the
    /// walk stopped early (cap/parse failure) and everything past the last
    /// known extent is UNKNOWN, not a sparse hole (BUG-238).
    extents_complete: bool,
    /// One past the highest logical block any known extent covers.
    mapped_block_end: u64,
}

impl fmt::Debug for XfsFileSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfsFileSource")
            .field("blocksize", &self.blocksize)
            .field("size", &self.size)
            .field("extents", &self.extents.len())
            .finish()
    }
}

impl XfsFileSource {
    fn new(
        inner: Arc<dyn DataSource>,
        blocksize: u32,
        agblocks: u32,
        agblklog: u8,
        size: u64,
        extents: Vec<XfsExtent>,
        extents_complete: bool,
    ) -> Self {
        let mapped_block_end = extents
            .iter()
            .map(|e| e.logical.saturating_add(e.count))
            .max()
            .unwrap_or(0);
        Self {
            inner,
            blocksize,
            agblocks,
            agblklog,
            size,
            extents,
            extents_complete,
            mapped_block_end,
        }
    }

    /// Convert an XFS filesystem block number (fsbno) into an absolute device
    /// block. fsbno encodes (agno, agbno): agno = fsbno >> agblklog. A single
    /// extent never crosses an AG boundary, so this is valid for any block
    /// within an extent.
    fn fsbno_to_abs_block(&self, fsbno: u64) -> u64 {
        fsbno_to_abs_block(fsbno, self.agblocks as u64, self.agblklog)
    }

    /// Find the extent containing the given logical block and return the physical
    /// offset. `None` means the range reads as zeros: either a sparse hole, or an
    /// unwritten (preallocated) extent whose on-disk bytes are not file content
    /// (BUG-208).
    fn resolve_logical_offset(&self, offset: u64) -> Option<u64> {
        let logical_block = offset / self.blocksize as u64;
        let offset_in_block = offset % self.blocksize as u64;

        for ext in &self.extents {
            if logical_block >= ext.logical && logical_block < ext.logical + ext.count {
                if ext.unwritten {
                    return None;
                }
                let block_delta = logical_block - ext.logical;
                let abs_block = self.fsbno_to_abs_block(ext.physical.saturating_add(block_delta));
                // Extent start blocks come from the image and may be hostile or
                // corrupt. A wrapping multiply lands on a low device offset, so
                // WRONG image bytes get hashed, exported and previewed as this
                // file's content (B7-002). Saturating matches the B-map walk,
                // and a saturated offset simply reads past the device end.
                return Some(
                    abs_block
                        .saturating_mul(self.blocksize as u64)
                        .saturating_add(offset_in_block),
                );
            }
        }
        None // Sparse hole
    }
}

impl DataSource for XfsFileSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }

        let to_read = std::cmp::min(buf.len() as u64, self.size - offset) as usize;
        let mut bytes_read = 0;

        while bytes_read < to_read {
            let current_offset = offset + bytes_read as u64;
            let logical_block = current_offset / self.blocksize as u64;
            let offset_in_block = current_offset % self.blocksize as u64;
            let remaining_in_block = self.blocksize as u64 - offset_in_block;
            let chunk = std::cmp::min((to_read - bytes_read) as u64, remaining_in_block) as usize;

            if let Some(phys_offset) = self.resolve_logical_offset(current_offset) {
                let n = self
                    .inner
                    .read_at(phys_offset, &mut buf[bytes_read..bytes_read + chunk])?;
                if n == 0 {
                    break;
                }
                bytes_read += n;
            } else {
                // No extent covers this block. That is a genuine sparse range —
                // a hole between extents, an unwritten extent, or the sparse
                // tail an ftruncate/fallocate leaves past the last extent — and
                // the kernel serves zeros for all of them, up to i_size. The
                // old "past every extent -> stop" break made a sparse tail
                // short-read after a single zero block (BUG-237).
                //
                // The one range we must NOT zero-fill is the tail past the last
                // known extent of an INCOMPLETE extent list: there we simply do
                // not know what is on disk, so report an honest short read
                // instead of fabricating a hole (BUG-238).
                if !self.extents_complete && logical_block >= self.mapped_block_end {
                    break;
                }
                buf[bytes_read..bytes_read + chunk].fill(0);
                bytes_read += chunk;
            }
        }

        Ok(bytes_read)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

// --- Parsing Context ---

struct ParsingContext<'a> {
    artifact_id: uuid::Uuid,
    case_id: uuid::Uuid,
    data_source: Arc<dyn DataSource>,
    superblock: &'a XfsSuperblock,
    produced_artifacts: &'a mut Vec<Artifact>,
    dir_entry_count: usize,
    /// Set when the global `MAX_DIR_ENTRIES` budget cut the tree walk short.
    /// Beyond that point whole subtrees are simply never visited, and without a
    /// filesystem-level marker the inventory reads as a complete enumeration of
    /// the volume — an examiner would take a missing file as a file that was
    /// never there.
    walk_truncated: bool,
    /// Inode numbers a recovered deleted directory entry already names, so
    /// the freed-inode scan reports each freed inode once (HUNT-175).
    named_deleted_inodes: std::collections::HashSet<u64>,
    /// Set when `MAX_RECURSION_DEPTH` stopped the walk descending: the
    /// subtrees below that depth are never visited.
    depth_capped: bool,
}

// --- Module Implementation ---

pub struct XfsParser;

impl ForensicsModule for XfsParser {
    fn id(&self) -> &str {
        "plugin.filesystem.xfs"
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
        let subtype = artifact.metadata.get("subtype").and_then(|v| v.as_str());

        if subtype != Some("xfs") {
            return Ok(Vec::new());
        }

        info!(
            "XFS parser processing filesystem artifact ID: {}",
            artifact.id
        );

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("XFS parser requires a data source".to_string())
        })?;

        let superblock = parse_xfs_superblock(data_source.as_ref())?;

        info!(
            "XFS: version={}, blocksize={}, blocks={}, AGs={}, inodesize={}, root={}",
            superblock.version,
            superblock.blocksize,
            superblock.dblocks,
            superblock.agcount,
            superblock.inodesize,
            superblock.rootino
        );

        let mut produced_artifacts = vec![];

        // Emit filesystem metadata artifact
        produced_artifacts.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::FileSystem,
                Some(Arc::clone(data_source)),
                json!({
                    "filesystem_type": "XFS",
                    "version": superblock.version,
                    "blocksize": superblock.blocksize,
                    "total_blocks": superblock.dblocks,
                    "allocation_groups": superblock.agcount,
                    "sector_size": superblock.sectsize,
                    "inode_size": superblock.inodesize,
                    "filesystem_name": superblock.fname,
                    "uuid": format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                                   superblock.uuid[0], superblock.uuid[1], superblock.uuid[2], superblock.uuid[3],
                                   superblock.uuid[4], superblock.uuid[5], superblock.uuid[6], superblock.uuid[7],
                                   superblock.uuid[8], superblock.uuid[9], superblock.uuid[10], superblock.uuid[11],
                                   superblock.uuid[12], superblock.uuid[13], superblock.uuid[14], superblock.uuid[15]),
                    "root_inode": superblock.rootino,
                }),
            ).with_parent(artifact.id)
        );

        // Recursive traversal from root inode
        let mut ctx = ParsingContext {
            artifact_id: artifact.id,
            case_id: artifact.case_id,
            data_source: Arc::clone(data_source),
            superblock: &superblock,
            produced_artifacts: &mut produced_artifacts,
            dir_entry_count: 0,
            walk_truncated: false,
            named_deleted_inodes: Default::default(),
            depth_capped: false,
        };

        let root_error = parse_inode(&mut ctx, superblock.rootino, "/", 0)
            .err()
            .map(|e| e.to_string());
        // Every inode the kernel freed and nothing names any more: the
        // deleted files whose directory entries did not survive (HUNT-175).
        let freed_scan = scan_freed_inodes(&mut ctx);
        let walk_truncated = ctx.walk_truncated;
        let depth_capped = ctx.depth_capped;

        if let Some(e) = root_error {
            // Without the root there is no walk, and a FileSystem record with
            // no files under it reads as an empty volume. Say it could not be
            // read (HUNT-175).
            warn!("Failed to parse XFS root inode: {}", e);
            let detail = format!(
                "The root inode ({}) of this XFS volume could not be read ({e}), so no file or \
                 directory under it is listed. The absence of files is a failure to start the \
                 walk, not evidence that the volume is empty. Deleted inodes found by the \
                 inode B+tree scan are still reported.",
                superblock.rootino
            );
            let md = &mut produced_artifacts[0].metadata;
            md["root_inode_readable"] = json!(false);
            md["root_inode_error"] = json!(e);
            md["inventory_incomplete"] = json!(true);
            md["inventory_incomplete_reason"] =
                json!(IncompleteReason::UnresolvedStructure.as_str());
            md["inventory_incomplete_detail"] = json!(detail);
        }
        if depth_capped {
            warn!(
                "XFS directory depth cap ({}) reached; deeper subtrees were not walked",
                MAX_RECURSION_DEPTH
            );
            produced_artifacts[0].metadata["directory_parse_incomplete"] = json!(true);
            produced_artifacts[0].metadata["directory_depth_capped"] = json!(MAX_RECURSION_DEPTH);
        }
        produced_artifacts[0].metadata["freed_inode_scan"] = freed_scan.to_json();

        if walk_truncated {
            // The FileSystem artifact this module mints is the volume-level
            // record, so it carries the honesty flag for the whole walk.
            warn!(
                "XFS directory-entry budget ({}) exhausted; the file inventory is incomplete",
                MAX_DIR_ENTRIES
            );
            produced_artifacts[0].metadata["directory_parse_incomplete"] = json!(true);
            produced_artifacts[0].metadata["directory_parse_incomplete_reason"] =
                json!("xfs_max_dir_entries");
        }

        info!("XFS parser produced {} artifacts", produced_artifacts.len());
        Ok(produced_artifacts)
    }
}

// --- Superblock Parsing ---

fn parse_xfs_superblock(data_source: &dyn DataSource) -> Result<XfsSuperblock, ModuleError> {
    let mut sb_data = vec![0u8; 512];
    // Fail closed: a short read leaves the tail zero and every field past it
    // (agblocks, agblklog, versionnum, sectsize, feature bits) would be
    // fabricated zeros that mis-size the whole filesystem (BUG-243).
    read_exact_or_fail(data_source, 0, &mut sb_data, "XFS superblock")?;

    let magic = BigEndian::read_u32(&sb_data[0..4]);
    if magic != XFS_SB_MAGIC {
        return Err(ModuleError::ParsingError(format!(
            "Invalid XFS magic: expected 0x{:08X}, got 0x{:08X}",
            XFS_SB_MAGIC, magic
        )));
    }

    let blocksize = BigEndian::read_u32(&sb_data[4..8]);
    let dblocks = BigEndian::read_u64(&sb_data[8..16]);
    let rblocks = BigEndian::read_u64(&sb_data[16..24]);

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&sb_data[32..48]);

    let rootino = BigEndian::read_u64(&sb_data[56..64]);
    let agblocks = BigEndian::read_u32(&sb_data[84..88]);
    let agcount = BigEndian::read_u32(&sb_data[88..92]);
    let agblklog = sb_data[124]; // sb_agblklog @ 0x7c

    // sb_versionnum is at 0x64 (100), not 0x60: sb_agcount (0x58) is followed by
    // sb_rbmblocks (0x5c) AND sb_logblocks (0x60) before sb_versionnum. Reading
    // 4 bytes early made version=0 (v5 misdetected as v2 -> wrong inode core
    // size -> the whole walk misaligned) and garbage sect/inode sizes.
    let version = BigEndian::read_u16(&sb_data[100..102]); // sb_versionnum @ 0x64
    let sectsize = BigEndian::read_u16(&sb_data[102..104]); // sb_sectsize    @ 0x66
    let inodesize = BigEndian::read_u16(&sb_data[104..106]); // sb_inodesize  @ 0x68
    let inopblock = BigEndian::read_u16(&sb_data[106..108]); // sb_inopblock  @ 0x6a

    // These geometry fields are used as divisors and multipliers when locating
    // inodes: inode_offset divides agino by inopblock and derives block offsets
    // from agblocks/blocksize. A zero from a malformed superblock would
    // divide-by-zero (panic in debug) or misplace every read, so reject the
    // volume up front.
    if blocksize == 0 || sectsize == 0 || inodesize == 0 || inopblock == 0 || agblocks == 0 {
        return Err(ModuleError::ParsingError(format!(
            "Invalid XFS superblock geometry: blocksize={}, sectsize={}, inodesize={}, inopblock={}, agblocks={}",
            blocksize, sectsize, inodesize, inopblock, agblocks
        )));
    }

    // blocksize sizes per-block buffer allocations (vec![0u8; blocksize]); a bogus
    // u32 (up to 4 GiB) would OOM-abort (not caught by catch_unwind). XFS blocksize
    // is a power of two in 512..=65536. agblklog is used as a shift width
    // (1u64 << agblklog) when decoding fsbno -> (agno, agbno); a value >= 64 would
    // panic, and no valid volume needs more than 32.
    if !blocksize.is_power_of_two() || !(512..=65536).contains(&blocksize) || agblklog >= 64 {
        return Err(ModuleError::ParsingError(format!(
            "Invalid XFS superblock: blocksize={blocksize}, agblklog={agblklog}"
        )));
    }

    // sb_inodesize is a power of two in 256..=2048 on every real volume. The
    // inode parser indexes fixed core offsets (di_nextents @0x4c, di_forkoff
    // @0x52), so a crafted smaller value would index past the buffer and panic
    // on evidence-derived input.
    if !inodesize.is_power_of_two() || !(256..=2048).contains(&inodesize) {
        return Err(ModuleError::ParsingError(format!(
            "Invalid XFS superblock: inodesize={inodesize} (expected a power of two in 256..=2048)"
        )));
    }

    let fname_bytes = &sb_data[108..120];
    let fname_end = fname_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    let fname = String::from_utf8_lossy(&fname_bytes[..fname_end]).to_string();

    // Detect v5 format: version number has V5 bit (0x4000) set in sb_features2
    // or more reliably, version & 0xf >= 5
    let v5 = (version & 0x000f) >= 5;

    // v5 only: sb_features_incompat at offset 216.
    // XFS_SB_FEAT_INCOMPAT_BIGTIME (0x8) switches inode timestamps to a
    // 64-bit nanosecond format this parser does not decode.
    // sb_features2 @ 0xC8 (200), only meaningful when MOREBITS is set in the
    // version number. An old alignment bug wrote the flags to sb_bad_features2
    // (@0xCC) instead, and the kernel repairs that by OR-ing the two, so read
    // both: missing the ftype bit misaligns every v4 directory entry.
    const XFS_SB_VERSION_MOREBITSBIT: u16 = 0x8000;
    const XFS_SB_VERSION2_FTYPE: u32 = 0x0000_0200;
    let features2 =
        BigEndian::read_u32(&sb_data[200..204]) | BigEndian::read_u32(&sb_data[204..208]);
    let v4_ftype =
        (version & XFS_SB_VERSION_MOREBITSBIT) != 0 && (features2 & XFS_SB_VERSION2_FTYPE) != 0;

    let mut bigtime = false;
    let mut nrext64 = false;
    let mut v5_ftype = false;
    if v5 {
        let features_incompat = BigEndian::read_u32(&sb_data[216..220]);
        // XFS_SB_FEAT_INCOMPAT_FTYPE (0x1). mkfs.xfs sets this for every v5
        // volume it creates, which is why assuming v5 implies ftype usually
        // works, but the bit is what the kernel reads. A v5 image written
        // without it — by another tool, or hand-built — misaligns every
        // directory entry on the volume, so trust the bit, not the version.
        v5_ftype = (features_incompat & 0x1) != 0;
        bigtime = (features_incompat & 0x8) != 0;
        // XFS_SB_FEAT_INCOMPAT_NREXT64 (0x20): the data-fork extent count becomes
        // a 64-bit di_big_nextents at inode offset 0x18, and the legacy
        // di_nextents slot at 0x4c is repurposed as padding. Default in recent
        // mkfs.xfs; without handling it every file reports zero extents.
        nrext64 = (features_incompat & 0x20) != 0;
        if bigtime {
            debug!(
                "XFS bigtime feature detected: inode timestamps are 64-bit nanosecond counts since 1901-12-13 20:45:52 UTC"
            );
        }
    }

    Ok(XfsSuperblock {
        _magic: magic,
        blocksize,
        dblocks,
        _rblocks: rblocks,
        agcount,
        agblocks,
        agblklog,
        sectsize,
        inodesize,
        inopblock,
        version,
        uuid,
        fname,
        rootino,
        v5,
        bigtime,
        nrext64,
        // Each format carries the flag in its own place: v5 in
        // sb_features_incompat, v4 in sb_features2.
        ftype: if v5 { v5_ftype } else { v4_ftype },
    })
}

// --- Inode Location ---

/// Calculate the byte offset of an inode given its inode number.
///
/// XFS inode numbers encode: AG number in the high bits, relative inode within
/// the AG in the low bits. The split point depends on agblocks and inodes-per-block.
/// ceil(log2(n)): the number of bits needed to index 0..n-1. Matches the
/// on-disk sb_agblklog / sb_inopblog definitions.
fn ceil_log2(n: u64) -> u32 {
    if n <= 1 {
        0
    } else {
        64 - (n - 1).leading_zeros()
    }
}

fn inode_offset(sb: &XfsSuperblock, ino: u64) -> u64 {
    // XFS splits an inode number into (agno, agino) at bit
    // (sb_agblklog + sb_inopblog), i.e. ceil_log2(agblocks) + ceil_log2(inopblock).
    // The previous `bit_length(agblocks * inopblock)` heuristic was off by one
    // whenever agblocks was an exact power of two (e.g. 1024), which shifted agno
    // one bit too far and misplaced every inode in AG >= 2. All operands derive
    // from attacker-controlled fields, so saturate products/sums; the shift is
    // capped at 63. Divisors (inopblock) are validated non-zero at parse time.
    let agino_shift = (ceil_log2(sb.agblocks as u64) + ceil_log2(sb.inopblock as u64)).min(63);

    let agno = ino >> agino_shift;
    let agino = ino & ((1u64 << agino_shift) - 1);

    let inopblock = (sb.inopblock as u64).max(1);
    let block_in_ag = agino / inopblock;
    let inode_in_block = agino % inopblock;

    let ag_offset = agno
        .saturating_mul(sb.agblocks as u64)
        .saturating_mul(sb.blocksize as u64);
    let block_offset = block_in_ag.saturating_mul(sb.blocksize as u64);
    let inode_offset_in_block = inode_in_block.saturating_mul(sb.inodesize as u64);

    ag_offset
        .saturating_add(block_offset)
        .saturating_add(inode_offset_in_block)
}

// --- Inode Parsing ---

fn parse_xfs_inode(
    data_source: &dyn DataSource,
    sb: &XfsSuperblock,
    ino: u64,
) -> Result<XfsInode, ModuleError> {
    let offset = inode_offset(sb, ino);
    let mut inode_data = vec![0u8; sb.inodesize as usize];

    // Fail closed on a short read: the tail would stay zero and the parser below
    // would decode fabricated zero fields as a real (empty) inode (BUG-155).
    // A single `read_at` returning less than the inode is ordinary on a windowed
    // or container-backed image, so gather the whole inode before deciding it is
    // missing; rejecting on the first partial read would lose real evidence.
    let n = read_full(data_source, offset, &mut inode_data);
    if n < sb.inodesize as usize {
        return Err(ModuleError::ParsingError(format!(
            "XFS inode {}: short read ({} of {} bytes) at offset {}; refusing to parse zero-padded inode",
            ino, n, sb.inodesize, offset
        )));
    }

    // Validate inode magic "IN" (0x494e)
    let magic = BigEndian::read_u16(&inode_data[0..2]);
    if magic != 0x494e {
        return Err(ModuleError::ParsingError(format!(
            "Invalid inode magic at offset {}: expected 0x494E, got 0x{:04X}",
            offset, magic
        )));
    }

    let mode = BigEndian::read_u16(&inode_data[2..4]);
    // Offset 4: version (1 byte)
    // Offset 5: format (1 byte) — data fork format
    let format = inode_data[5];
    // Offset 6: onlink (2 bytes, v1 nlink)
    let nlink_v1 = BigEndian::read_u16(&inode_data[6..8]) as u32;
    let uid = BigEndian::read_u32(&inode_data[8..12]);
    let gid = BigEndian::read_u32(&inode_data[12..16]);
    // Offset 16: nlink (4 bytes, v2+ nlink)
    let nlink_v2 = BigEndian::read_u32(&inode_data[16..20]);
    let nlink = if nlink_v2 > 0 { nlink_v2 } else { nlink_v1 };

    // di_atime at 0x20 (32): 8 bytes. Legacy layout is sec u32 + nsec u32;
    // under XFS_SB_FEAT_INCOMPAT_BIGTIME the kernel reinterprets the same 8
    // bytes as one 64-bit BE nanosecond count (union xfs_timestamp_t in
    // fs/xfs/libxfs/xfs_format.h). Read the full 8 bytes as one value here —
    // the legacy sec is just its high 32 bits — and let the caller decode
    // per `superblock.bigtime`. Preceded by di_pad[6] (0x18) and
    // di_flushiter (0x1e), or di_big_nextents under NREXT64.
    let atime_raw = BigEndian::read_u64(&inode_data[32..40]);
    // di_mtime at 0x28 (40)
    let mtime_raw = BigEndian::read_u64(&inode_data[40..48]);
    // di_ctime at 0x30 (48)
    let ctime_raw = BigEndian::read_u64(&inode_data[48..56]);
    // di_crtime at 0x90 (144), v3 inode core only (v5 filesystems). The v2
    // (100-byte) core has no creation time; that byte range is already the
    // data fork. `inode_data` is always >= 256 bytes (validated at
    // superblock parse), so this read is in-bounds regardless of format —
    // it is only *meaningful* when `sb.v5`.
    let crtime_raw = if sb.v5 {
        Some(BigEndian::read_u64(&inode_data[144..152]))
    } else {
        None
    };

    // Offset 56: size (8 bytes)
    let size = BigEndian::read_u64(&inode_data[56..64]);

    // Data-fork extent count. With NREXT64 it is a 64-bit di_big_nextents at
    // offset 0x18 (24); otherwise the legacy di_nextents (be32) at 0x4c (76).
    let nextents_raw = if sb.nrext64 {
        BigEndian::read_u64(&inode_data[24..32])
    } else {
        BigEndian::read_u32(&inode_data[76..80]) as u64
    };
    let nextents = nextents_raw.min(MAX_EXTENTS as u64) as u32;

    let dfork_offset = sb.dinode_core_size();
    // di_forkoff (dinode +0x52) is the size of the data fork in 8-byte units.
    // Zero means "no attribute fork", so the data fork runs to the end of the
    // inode. Ignoring it lets extent lists, btree roots and LOCAL data (a
    // shortform directory!) read straight on into the attribute fork: extended
    // attribute bytes get decoded as extra extents or as directory entries, so a
    // file with xattrs gains content it never had and a directory gains children
    // that never existed.
    let forkoff_bytes = (inode_data[82] as usize).saturating_mul(8);
    let dfork_end = if forkoff_bytes == 0 {
        sb.inodesize as usize
    } else {
        dfork_offset
            .saturating_add(forkoff_bytes)
            .min(sb.inodesize as usize)
    };
    if dfork_end < dfork_offset {
        return Err(ModuleError::ParsingError(format!(
            "XFS inode {}: di_forkoff {} puts the attribute fork inside the inode core",
            ino, inode_data[82]
        )));
    }

    // Parse extents or keep raw data fork
    let mut extents = Vec::new();
    let mut dfork_data = Vec::new();
    // True when a safety cap (or a fork that ran out of room) stopped the
    // extent walk before the on-disk list ended.
    let mut extents_truncated = false;
    // Set when a record that should have been an extent could not be decoded,
    // or when the inode format itself carries no stream this parser can read.
    let mut extents_unresolved = false;

    match format {
        XFS_DINODE_FMT_LOCAL => {
            // Inline data — store raw bytes
            if dfork_offset < dfork_end {
                dfork_data = inode_data[dfork_offset..dfork_end].to_vec();
            }
        }
        XFS_DINODE_FMT_EXTENTS => {
            let count = std::cmp::min(nextents as usize, MAX_EXTENTS);
            if nextents_raw > count as u64 {
                extents_truncated = true;
            }
            for i in 0..count {
                let ext_offset = dfork_offset + i * 16;
                // Bounded by the DATA fork's end, not the inode's: a record that
                // would start inside the attribute fork is not an extent.
                if ext_offset + 16 > dfork_end {
                    // The fork claims more records than it holds; the rest of the
                    // list was never seen.
                    extents_truncated = true;
                    break;
                }
                match unpack_extent(&inode_data[ext_offset..ext_offset + 16]) {
                    Some(ext) => extents.push(ext),
                    // A record the unpacker rejects is one extent of this file
                    // that we cannot place. Dropping it without a tally left
                    // its byte range looking like a genuine hole (B7-003).
                    None => extents_unresolved = true,
                }
            }
        }
        XFS_DINODE_FMT_BTREE
            // B-tree root is in the data fork
            if dfork_offset + 4 <= dfork_end => {
                match parse_btree_extents(data_source, sb, &inode_data[dfork_offset..dfork_end]) {
                    Ok((bext, truncated)) => {
                        extents = bext;
                        extents_truncated |= truncated;
                    }
                    Err(e) => {
                        warn!("Failed to parse B-tree extents for inode {}: {}", ino, e);
                        extents_truncated = true;
                    }
                }
            }
        _ => {}
    }

    // Why this file's extent list is not the whole on-disk list, if it isn't.
    //
    // An empty btree result means the walk failed outright or its root did not
    // fit the fork: recording full `size` with no extents would present a
    // valid-looking full-size file with no recoverable content (BUG-162).
    // A NON-empty but capped list is just as dangerous: the missing tail would
    // otherwise be emitted as a sparse run and hashed/exported as zeros that
    // are indistinguishable from a genuine hole (BUG-238).
    // A sized regular file whose stream we could not locate must say so. Only a
    // genuinely sparse extent-format file (nextents == 0, nothing rejected) is
    // legitimately extent-less: for it the kernel serves zeros, and so do we.
    // Every other empty case — an unreadable btree root, an inline file whose
    // data fork is empty, an inode format this parser does not decode — was
    // previously published as a full-size file with no content and no flag,
    // which reads as "this file was empty" (B7-003).
    let extents_incomplete = if (mode & S_IFMT) == S_IFREG && size > 0 {
        match format {
            // Inline content lives in the data fork. A declared size larger
            // than the fork holds means the tail is simply not there; serving
            // the short prefix under the full size reads as a complete file.
            XFS_DINODE_FMT_LOCAL if size > dfork_data.len() as u64 => {
                Some(IncompleteReason::ShortRead)
            }
            XFS_DINODE_FMT_LOCAL => None,
            XFS_DINODE_FMT_BTREE if extents.is_empty() => {
                Some(IncompleteReason::UnresolvedStructure)
            }
            XFS_DINODE_FMT_EXTENTS | XFS_DINODE_FMT_BTREE => {
                if extents_unresolved {
                    Some(IncompleteReason::UnresolvedStructure)
                } else if extents_truncated {
                    Some(IncompleteReason::CapReached)
                } else {
                    None
                }
            }
            _ => Some(IncompleteReason::UnresolvedStructure),
        }
    } else {
        None
    };

    Ok(XfsInode {
        _ino: ino,
        mode,
        format,
        nlink,
        uid,
        gid,
        size,
        atime_raw,
        mtime_raw,
        ctime_raw,
        crtime_raw,
        _nextents: nextents,
        extents_incomplete,
        extents,
        dfork_data,
    })
}

// --- Extent Unpacking ---

/// Unpack a 128-bit XFS extent record (big-endian).
///
/// Layout (128 bits total):
///   Bit 127:       state flag (0=normal, 1=unwritten)
///   Bits 73-126:   logical file block offset (54 bits)
///   Bits 21-72:    physical start block (52 bits)
///   Bits 0-20:     block count (21 bits)
fn unpack_extent(data: &[u8]) -> Option<XfsExtent> {
    if data.len() < 16 {
        return None;
    }

    let hi = BigEndian::read_u64(&data[0..8]);
    let lo = BigEndian::read_u64(&data[8..16]);

    // Skip null extents
    if hi == 0 && lo == 0 {
        return None;
    }

    // Bit 127 is the extent state flag: 1 = unwritten (preallocated).
    let unwritten = (hi >> 63) & 1 == 1;
    let logical = (hi >> 9) & 0x003F_FFFF_FFFF_FFFF; // 54 bits
    let physical = ((hi & 0x1FF) << 43) | (lo >> 21); // 52 bits
    let count = lo & 0x001F_FFFF; // 21 bits

    if count == 0 {
        return None;
    }

    Some(XfsExtent {
        logical,
        physical,
        count,
        unwritten,
    })
}

// --- B-tree Extent Resolution ---

/// Parse a B-tree root block (from the inode data fork) and resolve all leaf
/// extents. Returns `(extents, truncated)`; `truncated` is true when the walk
/// stopped before the on-disk list ended (record cap, pointer array that ran
/// past the block, or `MAX_EXTENTS`), so the caller can flag the file's content
/// as incomplete rather than sparse-fill the missing tail (BUG-238).
fn parse_btree_extents(
    data_source: &dyn DataSource,
    sb: &XfsSuperblock,
    btree_root: &[u8],
) -> Result<(Vec<XfsExtent>, bool)> {
    // B-tree root header in the data fork:
    //   Offset 0: level (2 bytes BE) — 0 = leaf, >0 = internal
    //   Offset 2: numrecs (2 bytes BE)
    //   Offset 4: keys and/or pointers
    if btree_root.len() < 4 {
        return Err(anyhow!("B-tree root too small"));
    }

    let level = BigEndian::read_u16(&btree_root[0..2]);
    let numrecs = BigEndian::read_u16(&btree_root[2..4]) as usize;

    if level == 0 {
        // Leaf node in the inode itself — records are inline extents
        let mut extents = Vec::new();
        let mut truncated = false;
        for i in 0..numrecs {
            let off = 4 + i * 16;
            if off + 16 > btree_root.len() {
                truncated = true;
                break;
            }
            if let Some(ext) = unpack_extent(&btree_root[off..off + 16]) {
                extents.push(ext);
            }
        }
        return Ok((extents, truncated));
    }

    // Internal node: keys are at offset 4, pointers follow after all keys.
    // Key size = 16 bytes (startoff u64 + startblock u64), pointer = 8 bytes (block number u64)
    // But in the data fork root, the layout is different from on-disk blocks:
    //   Keys start at offset 4, each 16 bytes
    //   Pointers start at offset 4 + numrecs*16, each 8 bytes
    let keys_start = 4;
    let ptrs_start = keys_start + numrecs * 16;

    let mut child_blocks = Vec::new();
    let mut truncated = false;
    for i in 0..numrecs {
        let ptr_off = ptrs_start + i * 8;
        if ptr_off + 8 > btree_root.len() {
            truncated = true;
            break;
        }
        let block_num = BigEndian::read_u64(&btree_root[ptr_off..ptr_off + 8]);
        child_blocks.push(block_num);
    }

    // Recursively read child blocks
    let mut all_extents = Vec::new();
    for block_num in child_blocks {
        {
            let mut visited = std::collections::HashSet::new();
            read_btree_block(
                data_source,
                sb,
                block_num,
                level - 1,
                &mut all_extents,
                0,
                &mut visited,
                &mut truncated,
            )?;
        }
        if all_extents.len() > MAX_EXTENTS {
            truncated = true;
            break;
        }
    }

    Ok((all_extents, truncated))
}

/// Recursively read a B-tree block (on-disk format) and collect extents.
/// `truncated` is set whenever a safety cap stops the walk early, so the file's
/// missing extents are never presented as a sparse hole (BUG-238).
#[allow(clippy::too_many_arguments)]
fn read_btree_block(
    data_source: &dyn DataSource,
    sb: &XfsSuperblock,
    block_num: u64,
    level: u16,
    extents: &mut Vec<XfsExtent>,
    depth: usize,
    visited: &mut std::collections::HashSet<u64>,
    truncated: &mut bool,
) -> Result<()> {
    if depth > MAX_BTREE_DEPTH {
        return Err(anyhow!("B-tree depth exceeded maximum"));
    }
    if extents.len() > MAX_EXTENTS {
        *truncated = true;
        return Ok(());
    }
    // A shared/cyclic node graph (a block reachable via multiple pointers) would
    // otherwise be re-read up to branching^depth times even though depth is
    // small; visiting each block once makes the walk linear.
    if !visited.insert(block_num) {
        return Ok(());
    }

    // A bmap btree pointer is an fsbno, exactly like an extent's startblock: it
    // packs (agno, agbno) and must be AG-decoded before it becomes a device
    // offset. Multiplying the raw fsbno by the block size read the wrong blocks
    // on every geometry where agblocks != 1 << agblklog (BUG-239).
    let abs_block = fsbno_to_abs_block(block_num, sb.agblocks as u64, sb.agblklog);
    let offset = abs_block.saturating_mul(sb.blocksize as u64);
    let mut block = vec![0u8; sb.blocksize as usize];
    // Fail closed on a short read: a zero-padded B-map block would parse a
    // fabricated header/records and yield wrong extents (BUG-155).
    read_exact_or_fail(data_source, offset, &mut block, "XFS B-map block")?;

    // On-disk B-tree block header:
    //   v2: magic(4) + level(2) + numrecs(2) + leftsib(8) + rightsib(8) = 24 bytes
    //   v3: magic(4) + level(2) + numrecs(2) + leftsib(8) + rightsib(8) + blkno(8) + lsn(8) + uuid(16) + owner(8) + crc(4) = 72 bytes
    let magic = BigEndian::read_u32(&block[0..4]);
    let hdr_size = match magic {
        XFS_BMAP_MAGIC => 24,
        XFS_BMAP3_MAGIC => 72,
        _ => return Err(anyhow!("Invalid B-tree block magic: 0x{:08X}", magic)),
    };

    let blk_level = BigEndian::read_u16(&block[4..6]);
    let numrecs = BigEndian::read_u16(&block[6..8]) as usize;

    if blk_level != level {
        return Err(anyhow!(
            "B-tree level mismatch: expected {}, got {}",
            level,
            blk_level
        ));
    }

    if level == 0 {
        // Leaf block: records are packed extents starting after header
        for i in 0..numrecs {
            let off = hdr_size + i * 16;
            if off + 16 > block.len() {
                *truncated = true;
                break;
            }
            if extents.len() >= MAX_EXTENTS {
                *truncated = true;
                break;
            }
            if let Some(ext) = unpack_extent(&block[off..off + 16]) {
                extents.push(ext);
            }
        }
    } else {
        // Internal block: keys followed by pointers
        // Keys at hdr_size, each 16 bytes; pointers at hdr_size + numrecs*16, each 8 bytes
        let ptrs_start = hdr_size + numrecs * 16;
        for i in 0..numrecs {
            let ptr_off = ptrs_start + i * 8;
            if ptr_off + 8 > block.len() {
                *truncated = true;
                break;
            }
            let child = BigEndian::read_u64(&block[ptr_off..ptr_off + 8]);
            read_btree_block(
                data_source,
                sb,
                child,
                level - 1,
                extents,
                depth + 1,
                visited,
                truncated,
            )?;
        }
    }

    Ok(())
}

// --- Recursive Inode Walking ---

fn parse_inode(ctx: &mut ParsingContext, ino: u64, path: &str, depth: usize) -> Result<()> {
    if depth > MAX_RECURSION_DEPTH {
        ctx.depth_capped = true;
        return Ok(());
    }
    if ctx.dir_entry_count > MAX_DIR_ENTRIES {
        ctx.walk_truncated = true;
        return Ok(());
    }

    // An inode that will not read, or that a live entry names but that is
    // unallocated, is an entry missing from the listing: the caller must be
    // told, so it can mark its directory incomplete. Both used to return
    // `Ok(())` after a `debug!`, and an unreadable ROOT then left a volume
    // that listed nothing with nothing saying so (HUNT-175).
    let inode = parse_xfs_inode(ctx.data_source.as_ref(), ctx.superblock, ino)
        .map_err(|e| anyhow!("inode {ino} at {path} could not be read: {e}"))?;
    if inode.mode == 0 {
        return Err(anyhow!(
            "inode {ino} at {path} is named by a live directory entry but is unallocated"
        ));
    }

    let name = std::path::Path::new(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let parent_path = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut metadata = json!({
        "name": if path == "/" { "/" } else { &name },
        "path": path,
        "parent_path": parent_path,
        "inode": ino,
        "mode": inode.mode,
        "uid": inode.uid,
        "gid": inode.gid,
        "size": inode.size,
        "nlink": inode.nlink,
        "is_directory": inode.is_dir(),
        "is_symlink": inode.is_symlink(),
        "data_format": match inode.format {
            XFS_DINODE_FMT_LOCAL => "local",
            XFS_DINODE_FMT_EXTENTS => "extents",
            XFS_DINODE_FMT_BTREE => "btree",
            _ => "unknown",
        },
        "extent_count": inode.extents.len(),
    });

    write_inode_times(ctx.superblock, &inode, &mut metadata);

    // Build data source for regular files, persisting filesystem-window byte
    // runs (or inline bytes) so the content resolver can re-serve from the DB.
    // A fully sparse regular file (size > 0, no extents, nothing unresolved) is
    // real content: the kernel serves zeros for it. It used to fall through to
    // `None` here, so a 1 GiB sparse file was published with no source and no
    // runs at all — indistinguishable from a file whose content we lost
    // (B7-003).
    let fully_sparse_file = inode.is_file()
        && inode.extents.is_empty()
        && inode.size > 0
        && inode.extents_incomplete.is_none()
        && inode.format != XFS_DINODE_FMT_LOCAL;
    let has_stream = inode.is_file() && (!inode.extents.is_empty() || fully_sparse_file);
    let file_source: Option<Arc<dyn DataSource>> = if has_stream {
        let bs = ctx.superblock.blocksize as u64;
        let agblocks = ctx.superblock.agblocks as u64;
        let agblklog = ctx.superblock.agblklog;
        let mut exts = inode.extents.clone();
        exts.sort_by_key(|e| e.logical);
        let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
        let mut pos = 0u64;
        let mut has_unwritten = false;
        for e in &exts {
            // Extent logical/physical block numbers and counts come straight
            // from the image. A wrapping multiply here turns a hostile or
            // corrupt extent into a low device offset, and the WRONG image
            // bytes are then hashed, exported and previewed as this file's
            // content (B7-002). Saturating matches fsbno_to_abs_block and the
            // B-map walk; a saturated run simply reads past the device end.
            let logical_byte = e.logical.saturating_mul(bs);
            let extent_bytes = e.count.saturating_mul(bs);
            if logical_byte > pos {
                runs.push((None, logical_byte - pos));
            }
            if e.unwritten {
                // Preallocated, never written: the range reads as zeros, so it
                // must persist as a sparse run and never as its physical blocks
                // (BUG-208).
                has_unwritten = true;
                runs.push((None, extent_bytes));
            } else {
                // Decode the fsbno (agno + agbno) to an absolute device block.
                let abs_block = fsbno_to_abs_block(e.physical, agblocks, agblklog);
                runs.push((Some(abs_block.saturating_mul(bs)), extent_bytes));
            }
            pos = logical_byte.saturating_add(extent_bytes);
        }
        // A genuine sparse tail is a real hole and must persist as one (BUG-237).
        // A tail past a TRUNCATED extent list is unknown territory: emitting a
        // sparse run there would re-serve fabricated zeros from the DB as if
        // they were file content (BUG-238).
        if pos < inode.size && inode.extents_incomplete.is_none() {
            runs.push((None, inode.size - pos));
        }
        let (runs_json, complete) = seance_core::data_source::byte_runs_to_metadata(&runs);
        metadata["data_runs"] = runs_json;
        metadata["data_runs_complete"] = json!(complete && inode.extents_incomplete.is_none());
        if has_unwritten {
            // Honesty flag: preallocated ranges hash as zeros, not as whatever
            // still sits in those blocks.
            metadata["has_unwritten_extents"] = json!(true);
        }

        Some(Arc::new(XfsFileSource::new(
            ctx.data_source.clone(),
            ctx.superblock.blocksize,
            ctx.superblock.agblocks,
            ctx.superblock.agblklog,
            inode.size,
            inode.extents.clone(),
            inode.extents_incomplete.is_none(),
        )))
    } else if inode.is_file()
        && inode.format == XFS_DINODE_FMT_LOCAL
        && !inode.dfork_data.is_empty()
    {
        // Small inline file: store the bytes inline so they re-serve from the DB.
        let data =
            inode.dfork_data[..std::cmp::min(inode.dfork_data.len(), inode.size as usize)].to_vec();
        use base64::Engine as _;
        metadata["resident_data_b64"] =
            json!(base64::engine::general_purpose::STANDARD.encode(&data));
        Some(Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(data),
        ))
    } else {
        None
    };

    if let Some(reason) = inode.extents_incomplete {
        // The extent list is not the whole on-disk list: the btree walk failed
        // (BUG-162) or a cap truncated it (BUG-238). Either way a full `size`
        // with a short/absent extent list must not read as a valid full-size
        // file. `data_runs_complete: false` is the same honesty flag the
        // NTFS/run-list path uses for truncated run lists.
        metadata["data_runs_complete"] = json!(false);
        metadata["extents_incomplete"] = json!(reason.as_str());
        // `content_incomplete` is the flag the API, export and integrity-verify
        // paths read; `extents_incomplete` is XFS-specific. Without it a tool
        // checking only the standard flag sees a full-size file whose attached
        // source zero-fills everything past the extents we found (B2-140).
        metadata["content_incomplete"] = json!(true);
        if metadata.get("content_incomplete_reason").is_none() {
            metadata["content_incomplete_reason"] = json!(reason.as_str());
        }
    }

    let artifact = Artifact::new(ctx.case_id, ArtifactType::FileEntry, file_source, metadata)
        .with_parent(ctx.artifact_id);

    ctx.produced_artifacts.push(artifact);
    let dir_artifact_index = ctx.produced_artifacts.len() - 1;
    ctx.dir_entry_count += 1;

    // Recurse into directories
    if inode.is_dir() {
        match inode.format {
            XFS_DINODE_FMT_LOCAL => {
                // A shortform directory that would not parse, or that ran out
                // of fork mid-list, yields an empty or short listing. Left
                // unflagged it is indistinguishable from a directory that
                // genuinely holds nothing, and an examiner reads "no files
                // here" as fact (B2-139).
                let mut parse_error = None;
                let complete = match parse_shortform_dir(ctx, &inode, path, depth) {
                    Ok(complete) => complete,
                    Err(e) => {
                        debug!("Failed to parse shortform dir {}: {}", path, e);
                        parse_error = Some(e.to_string());
                        false
                    }
                };
                if !complete {
                    if let Some(obj) = ctx
                        .produced_artifacts
                        .get_mut(dir_artifact_index)
                        .and_then(|a| a.metadata.as_object_mut())
                    {
                        obj.insert("directory_parse_incomplete".to_string(), json!(true));
                        if let Some(err) = parse_error {
                            obj.insert("directory_parse_error".to_string(), json!(err));
                        }
                    }
                }
            }
            XFS_DINODE_FMT_EXTENTS | XFS_DINODE_FMT_BTREE if !inode.extents.is_empty() => {
                // A directory whose block walk stopped early must not look like
                // a fully enumerated one (BUG-213); stamp the same honesty flag
                // ext4 uses for a truncated listing.
                let complete = match parse_block_dir(ctx, &inode, path, depth) {
                    Ok(complete) => complete,
                    Err(e) => {
                        debug!("Failed to parse block dir {}: {}", path, e);
                        false
                    }
                };
                if !complete {
                    if let Some(obj) = ctx
                        .produced_artifacts
                        .get_mut(dir_artifact_index)
                        .and_then(|a| a.metadata.as_object_mut())
                    {
                        obj.insert("directory_parse_incomplete".to_string(), json!(true));
                    }
                }
            }
            other => {
                // An extent or B-tree directory whose extent list came out
                // empty (a B-map root that would not parse), or a fork format
                // this parser does not decode: its children were never
                // looked for, and an empty listing must not say otherwise.
                let why = if other == XFS_DINODE_FMT_EXTENTS || other == XFS_DINODE_FMT_BTREE {
                    "the directory's extent list is empty, so none of its blocks was read"
                        .to_string()
                } else {
                    format!("the directory's data fork format {other} is not decoded")
                };
                if let Some(obj) = ctx
                    .produced_artifacts
                    .get_mut(dir_artifact_index)
                    .and_then(|a| a.metadata.as_object_mut())
                {
                    obj.insert("directory_parse_incomplete".to_string(), json!(true));
                    obj.insert("directory_parse_error".to_string(), json!(why));
                }
            }
        }
    }

    Ok(())
}

/// Write an inode's timestamps onto `metadata` in the layout the volume uses.
///
/// Shared by the live walk and the deleted-inode records: a freed XFS inode
/// keeps its core, so its times are read the same way.
fn write_inode_times(sb: &XfsSuperblock, inode: &XfsInode, metadata: &mut serde_json::Value) {
    if sb.bigtime {
        // Bigtime inode: each xfs_timestamp_t is one 64-bit BE nanosecond
        // count rather than a sec/nsec pair. di_crtime becomes readable too
        // (v3 core), unlike the legacy branch below which has nowhere to get
        // a creation time from. A field is only marked unsupported when it
        // individually fails to decode — never a blanket flag for all four
        // once the format itself is understood (ROADMAP §5.7).
        let mut unsupported_fields: Vec<&str> = Vec::new();
        match decode_bigtime(inode.ctime_raw) {
            BigtimeField::Value(s) => metadata["changed"] = json!(s),
            BigtimeField::Unset => {}
            BigtimeField::Undecodable => unsupported_fields.push("changed"),
        }
        match decode_bigtime(inode.mtime_raw) {
            BigtimeField::Value(s) => metadata["modified"] = json!(s),
            BigtimeField::Unset => {}
            BigtimeField::Undecodable => unsupported_fields.push("modified"),
        }
        match decode_bigtime(inode.atime_raw) {
            BigtimeField::Value(s) => metadata["accessed"] = json!(s),
            BigtimeField::Unset => {}
            BigtimeField::Undecodable => unsupported_fields.push("accessed"),
        }
        if let Some(crtime_raw) = inode.crtime_raw {
            match decode_bigtime(crtime_raw) {
                BigtimeField::Value(s) => metadata["created"] = json!(s),
                BigtimeField::Unset => {}
                BigtimeField::Undecodable => unsupported_fields.push("created"),
            }
        }
        if !unsupported_fields.is_empty() {
            metadata["timestamps_unsupported"] = json!(unsupported_fields);
        }
    } else {
        // XFS ctime is the inode *change* time. The legacy (non-bigtime)
        // inode core parsed here carries no creation time, so no "created"
        // field is emitted.
        metadata["changed"] = json!(format_timestamp((inode.ctime_raw >> 32) as u32));
        metadata["modified"] = json!(format_timestamp((inode.mtime_raw >> 32) as u32));
        metadata["accessed"] = json!(format_timestamp((inode.atime_raw >> 32) as u32));
    }
}

// --- Shortform Directory Parsing ---

/// Parse a shortform (inline) directory stored in the inode data fork.
///
/// Layout:
///   Offset 0: count (1 byte) — number of entries (excluding . and ..)
///   Offset 1: i8count (1 byte) — number of entries with 8-byte inodes
///   Offset 2: parent inode (4 bytes BE, or 8 bytes if i8count > 0)
///   Then entries: namelen(1) + offset(2) + name(N) + inode(4 or 8)
///
/// Returns whether every entry the header declared was enumerated. `false`
/// means names are missing — a header too short to read, an entry running past
/// the end of the fork, or a child inode that would not parse — and the caller
/// stamps `directory_parse_incomplete`. An empty listing and a listing we could
/// not finish must never look the same to an examiner (B2-139).
fn parse_shortform_dir(
    ctx: &mut ParsingContext,
    inode: &XfsInode,
    path: &str,
    depth: usize,
) -> Result<bool> {
    let data = &inode.dfork_data;
    if data.len() < 6 {
        return Ok(false);
    }

    let count = data[0] as usize;
    let i8count = data[1] as usize;
    let use_64bit_ino = i8count > 0;

    // Parent inode
    let (_, mut pos) = if use_64bit_ino {
        if data.len() < 10 {
            return Ok(false);
        }
        (BigEndian::read_u64(&data[2..10]), 10usize)
    } else {
        (BigEndian::read_u32(&data[2..6]) as u64, 6usize)
    };
    let mut complete = true;

    let ino_size = if use_64bit_ino { 8 } else { 4 };
    // v5 filesystems (and v4 with the ftype feature) store a 1-byte file-type
    // field after the name and before the inode number in each shortform entry.
    // Without skipping it the inode number is read one byte early -> a garbage
    // child inode -> the directory never descends.
    let ftype_size = usize::from(ctx.superblock.ftype);

    for _ in 0..count {
        if pos + 3 > data.len() {
            // The fork ended mid-list: the remaining declared entries were
            // never read, so this listing is a prefix of the directory.
            complete = false;
            break;
        }

        let namelen = data[pos] as usize;
        // offset field is 2 bytes (directory offset tag, not file offset)
        let _offset_tag = BigEndian::read_u16(&data[pos + 1..pos + 3]);
        pos += 3;

        if pos + namelen + ftype_size + ino_size > data.len() {
            complete = false;
            break;
        }

        let name = String::from_utf8_lossy(&data[pos..pos + namelen]).to_string();
        pos += namelen + ftype_size; // skip the name and the ftype byte

        let child_ino = if use_64bit_ino {
            BigEndian::read_u64(&data[pos..pos + 8])
        } else {
            BigEndian::read_u32(&data[pos..pos + 4]) as u64
        };
        pos += ino_size;

        if name == "." || name == ".." {
            continue;
        }

        let child_path = if path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", path, name)
        };

        if let Err(e) = parse_inode(ctx, child_ino, &child_path, depth + 1) {
            // The name is in the directory but its inode would not parse, so
            // no artifact is emitted for it: the listing is short.
            complete = false;
            debug!(
                "Failed to parse inode {} at {}: {}",
                child_ino, child_path, e
            );
        }
    }

    Ok(complete)
}

// --- Block / Leaf / Node Directory Parsing ---

/// Parse an extent-based or B-tree directory by reading its data blocks.
///
/// Handles three cases based on the magic of the first block:
/// - XDB3/XD2B: Single-block directory (all entries in one block)
/// - XDD3/XD2D: Multi-block directory (entries span multiple data blocks)
///
/// Returns whether the whole directory was enumerated. `false` means entries
/// may be missing (unreadable block, unrecognised block magic, or the block cap
/// hit), and the caller stamps `directory_parse_incomplete` (BUG-213).
fn parse_block_dir(
    ctx: &mut ParsingContext,
    inode: &XfsInode,
    path: &str,
    depth: usize,
) -> Result<bool> {
    if inode.extents.is_empty() {
        return Ok(true);
    }

    let blocksize = ctx.superblock.blocksize as usize;

    // Build a file source to read directory data through the extent map
    let dir_source = XfsFileSource::new(
        ctx.data_source.clone(),
        ctx.superblock.blocksize,
        ctx.superblock.agblocks,
        ctx.superblock.agblklog,
        inode.size,
        inode.extents.clone(),
        inode.extents_incomplete.is_none(),
    );

    // Read the first block to determine directory type. `read_full` keeps asking
    // until the block is in hand: one short `read_at` is not evidence that the
    // directory block is short, and treating it as such would drop a readable
    // directory from the inventory.
    let mut first_block = vec![0u8; blocksize];
    let n = read_full(&dir_source, 0, &mut first_block);
    if n < 16 {
        return Err(anyhow!("Directory block too small: {} bytes", n));
    }

    let magic = BigEndian::read_u32(&first_block[0..4]);
    let mut complete = true;

    match magic {
        XFS_DIR3_BLOCK_MAGIC | XFS_DIR2_BLOCK_MAGIC => {
            // Single-block directory — all entries in this one block,
            // ending where the leaf array its tail bounds begins (HUNT-234).
            let hdr_size = if magic == XFS_DIR3_BLOCK_MAGIC {
                64
            } else {
                16
            };
            match block_dir_entries_end(&first_block[..n], blocksize, hdr_size) {
                Some(end) => {
                    complete &=
                        parse_dir_data_entries(ctx, &first_block[..end], hdr_size, path, depth)?;
                }
                None => {
                    // No usable tail: where the entries end is not known, so
                    // whatever the scan finds is a salvage, not the listing.
                    debug!(
                        "Block directory {} has no usable tail; scanning without a bound",
                        path
                    );
                    let _ = parse_dir_data_entries(ctx, &first_block[..n], hdr_size, path, depth)?;
                    complete = false;
                }
            }
        }
        XFS_DIR3_DATA_MAGIC | XFS_DIR2_DATA_MAGIC => {
            // Multi-block directory — read all data blocks
            let hdr_size = if magic == XFS_DIR3_DATA_MAGIC { 64 } else { 16 };
            complete &= parse_dir_data_entries(ctx, &first_block[..n], hdr_size, path, depth)?;

            // Read subsequent data blocks (logical blocks 0, 1, 2, ...)
            // Directory data blocks are in the low logical block range.
            // Leaf/freespace blocks are at high logical offsets (we skip those).
            let all_data_blocks = inode.size / blocksize as u64;
            let dir_data_blocks = all_data_blocks.min(MAX_DIR_DATA_BLOCKS);
            if dir_data_blocks < all_data_blocks {
                warn!(
                    "Directory {} spans {} data blocks; only the first {} are scanned",
                    path, all_data_blocks, dir_data_blocks
                );
                complete = false;
            }
            for blk_idx in 1..dir_data_blocks {
                if ctx.dir_entry_count > MAX_DIR_ENTRIES {
                    complete = false;
                    ctx.walk_truncated = true;
                    break;
                }
                let offset = blk_idx * blocksize as u64;

                // An unmapped logical block is a hole XFS punched when the data
                // block was freed: it holds no entries, and the directory
                // legitimately continues after it. Skip without reading.
                if dir_source.resolve_logical_offset(offset).is_none() {
                    // ...unless the extent list itself is short (a cap or a
                    // failed B-map walk): then an unmapped block may be one
                    // whose mapping was never read, and the entries in it are
                    // missing, not absent (HUNT-175).
                    if inode.extents_incomplete.is_some() {
                        complete = false;
                    }
                    continue;
                }

                let mut block_data = vec![0u8; blocksize];
                // Gather the whole block before judging it short: a partial
                // `read_at` on a windowed image is not a damaged directory, and
                // calling it one would mark a sound listing incomplete.
                let bn = read_full(&dir_source, offset, &mut block_data);
                if bn < 16 {
                    // Short read of a mapped block: whatever entries it held are
                    // lost. Keep walking the rest of the directory, but say the
                    // listing is not whole.
                    warn!(
                        "Short read of dir block {} in {} ({} bytes); entries may be missing",
                        blk_idx, path, bn
                    );
                    complete = false;
                    continue;
                }

                let blk_magic = BigEndian::read_u32(&block_data[0..4]);
                match blk_magic {
                    XFS_DIR3_DATA_MAGIC | XFS_DIR2_DATA_MAGIC => {
                        let bhdr = if blk_magic == XFS_DIR3_DATA_MAGIC {
                            64
                        } else {
                            16
                        };
                        match parse_dir_data_entries(ctx, &block_data[..bn], bhdr, path, depth) {
                            Ok(block_complete) => complete &= block_complete,
                            Err(e) => {
                                debug!(
                                    "Error parsing dir data block {} in {}: {}",
                                    blk_idx, path, e
                                );
                                complete = false;
                            }
                        }
                    }
                    _ => {
                        // A mapped block inside the data range that is not a
                        // data block: corrupt or an unexpected layout. Stopping
                        // here would silently drop every later block, so keep
                        // walking and record that entries may be missing.
                        debug!(
                            "Unexpected magic 0x{:08X} in dir block {} of {}; skipping block",
                            blk_magic, blk_idx, path
                        );
                        complete = false;
                    }
                }
            }
        }
        _ => {
            // Unrecognized magic — try parsing as raw directory data anyway.
            // Whatever comes out is a best-effort salvage, never a full listing.
            debug!(
                "Unknown directory block magic 0x{:08X} for {}, attempting raw parse",
                magic, path
            );
            let _ = parse_dir_data_entries(ctx, &first_block[..n], 0, path, depth);
            complete = false;
        }
    }

    Ok(complete)
}

/// Where the entries of a single-block (`XDB3`/`XD2B`) directory end: the
/// start of the leaf array that the block tail's last eight bytes bound
/// (`be32 count`, `be32 stale`; `count` 8-byte leaf entries lie just before
/// the tail). `None` when the block was not read whole or the tail's count
/// would put the leaf array inside the header — no bound can be trusted.
///
/// The entry scan used to stop only on a zero inode or name length. On a
/// sound block it halts at the leaf array by luck (the first leaf's ninth
/// byte is the high byte of the second-smallest hash, which is at most that
/// of `..`, 0x172E), but a free region whose length runs past the array
/// walked into it and read hash/address pairs as an entry (HUNT-234).
fn block_dir_entries_end(block: &[u8], blocksize: usize, hdr_size: usize) -> Option<usize> {
    let len = block.len();
    if len != blocksize || len < hdr_size + 8 {
        return None;
    }
    let count = BigEndian::read_u32(&block[len - 8..len - 4]) as usize;
    let end = len.checked_sub(count.checked_mul(8)?.checked_add(8)?)?;
    (end >= hdr_size).then_some(end)
}

/// Parse directory entries from a directory data block.
///
/// XFS directory entries (v3 format):
///   Offset 0: inode number (8 bytes BE)
///   Offset 8: name length (1 byte)
///   Offset 9: name (N bytes)
///   Offset 9+N: file type tag (1 byte, v3 only)
///   Then padded to 8-byte alignment
///
/// Free entries have inode = 0xFFFF (freetag = 0xFFFF at offset 0). A free
/// region is not stepped over blind: the names the kernel freed into it are
/// looked for and reported as deleted entries (`recover_free_span_entries`).
///
/// `block` must start at the directory block's first byte: entry tags are
/// block-relative offsets and the recovery validates against them.
///
/// Returns whether every live entry's inode was published; `false` means a
/// name is in the directory but its inode would not read.
fn parse_dir_data_entries(
    ctx: &mut ParsingContext,
    block: &[u8],
    hdr_size: usize,
    path: &str,
    depth: usize,
) -> Result<bool> {
    let mut pos = hdr_size;
    let len = block.len();
    let has_ftype = ctx.superblock.ftype;
    let mut complete = true;

    while pos + 10 <= len {
        if ctx.dir_entry_count > MAX_DIR_ENTRIES {
            ctx.walk_truncated = true;
            break;
        }

        // Check for free space entry (freetag = 0xFFFF)
        let tag = BigEndian::read_u16(&block[pos..pos + 2]);
        if tag == 0xFFFF {
            // Free entry: 2-byte tag + 2-byte length
            if pos + 4 > len {
                break;
            }
            let free_len = BigEndian::read_u16(&block[pos + 2..pos + 4]) as usize;
            if free_len == 0 {
                break;
            }
            let span_end = pos.saturating_add(free_len).min(len);
            recover_free_span_entries(ctx, block, pos, span_end, path);
            pos += free_len;
            // Align to 8 bytes
            pos = (pos + 7) & !7;
            continue;
        }

        // Active entry
        if pos + 11 > len {
            break;
        }

        let entry_ino = BigEndian::read_u64(&block[pos..pos + 8]);
        let namelen = block[pos + 8] as usize;

        if namelen == 0 || entry_ino == 0 {
            // Corrupted or end of entries
            break;
        }

        if pos + 9 + namelen > len {
            break;
        }

        let name = String::from_utf8_lossy(&block[pos + 9..pos + 9 + namelen]).to_string();

        // Calculate entry size: 8 (inode) + 1 (namelen) + name + 1 (filetype if
        // the volume has the ftype feature) + 2 (tag)
        // Rounded up to 8-byte alignment
        let ftype_size = usize::from(has_ftype);
        let entry_size = 8 + 1 + namelen + ftype_size + 2; // +2 for the trailing offset tag
        let padded_size = (entry_size + 7) & !7;
        pos += padded_size;

        if name == "." || name == ".." {
            continue;
        }

        let child_path = if path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", path, name)
        };

        if let Err(e) = parse_inode(ctx, entry_ino, &child_path, depth + 1) {
            // The name is in the directory but its inode would not read: the
            // listing is short, and the caller marks the directory so.
            complete = false;
            debug!(
                "Failed to parse inode {} at {}: {}",
                entry_ino, child_path, e
            );
        }
    }

    Ok(complete)
}

/// Directory entries the kernel freed, found inside one free region of a
/// directory data block (HUNT-175).
///
/// When XFS frees an entry that has no free neighbour before it, it
/// overwrites the entry's first four bytes with the free tag (`0xFFFF`) and the
/// region length; when the entry joins a free region already before it, only
/// that region's length changes. Either way the region's start offset is
/// written into the freed entry's last two bytes. Everything else stays: the
/// inode number (its low 32 bits where the free tag landed), the name length,
/// the name and the file type. Observed on a Linux 6.8 v5 volume
/// (`tests/real_deleted_volume_test.rs`), where three names removed in
/// sequence left the first with the free tag and all three with the first's
/// offset as their tag.
///
/// A candidate at an 8-byte boundary is accepted only when its trailing tag
/// is its own offset or an 8-aligned offset earlier in the same free region
/// (the start the region had when the entry was merged into it); its name
/// holds no NUL or `/`; and its file type, where the volume stores one, is a
/// defined one. A live entry's tag is its own offset; the relaxation admits
/// exactly the merged case and nothing that points outside the region.
fn recover_free_span_entries(
    ctx: &mut ParsingContext,
    block: &[u8],
    span_start: usize,
    span_end: usize,
    path: &str,
) {
    let ftype_size = usize::from(ctx.superblock.ftype);
    let mut q = span_start;
    while q + 12 <= span_end {
        let Some(entry) = read_freed_dirent(block, q, span_start, span_end, ftype_size) else {
            q += 8;
            continue;
        };
        q += entry.size;
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        emit_deleted_dirent(ctx, &entry, path);
    }
}

/// One entry recovered from a directory free region.
struct FreedDirent {
    name: String,
    /// The entry's full inode number, when its first four bytes were not
    /// overwritten by the free tag.
    inode_intact: Option<u64>,
    inode_low32: u32,
    file_type: Option<u8>,
    offset_in_block: usize,
    size: usize,
}

fn read_freed_dirent(
    block: &[u8],
    q: usize,
    span_start: usize,
    span_end: usize,
    ftype_size: usize,
) -> Option<FreedDirent> {
    let namelen = *block.get(q + 8)? as usize;
    if namelen == 0 {
        return None;
    }
    let size = (8 + 1 + namelen + ftype_size + 2 + 7) & !7;
    let end = q.checked_add(size)?;
    if end > span_end || end > block.len() {
        return None;
    }
    let tag = BigEndian::read_u16(&block[end - 2..end]) as usize;
    if tag != q && !((span_start..q).contains(&tag) && tag.is_multiple_of(8)) {
        return None;
    }
    let name_bytes = &block[q + 9..q + 9 + namelen];
    if name_bytes.iter().any(|&b| b == 0 || b == b'/') {
        return None;
    }
    let file_type = if ftype_size == 1 {
        let t = block[q + 9 + namelen];
        // XFS_DIR3_FT_REG_FILE (1) .. XFS_DIR3_FT_WHT (8).
        if !(1..=8).contains(&t) {
            return None;
        }
        Some(t)
    } else {
        None
    };
    let clobbered = BigEndian::read_u16(&block[q..q + 2]) == 0xFFFF;
    Some(FreedDirent {
        name: String::from_utf8_lossy(name_bytes).into_owned(),
        inode_intact: (!clobbered).then(|| BigEndian::read_u64(&block[q..q + 8])),
        inode_low32: BigEndian::read_u32(&block[q + 4..q + 8]),
        file_type,
        offset_in_block: q,
        size,
    })
}

/// The number of bits an inode number on this volume can occupy: the AG
/// number above `agblklog + inopblog` bits of AG-relative inode.
fn inode_number_bits(sb: &XfsSuperblock) -> u32 {
    ceil_log2(sb.agcount as u64) + ceil_log2(sb.agblocks as u64) + ceil_log2(sb.inopblock as u64)
}

const DELETED_CONTENT_DETAIL: &str = "This file was deleted. XFS clears a freed inode's size, \
     extent count and data fork (observed on Linux 6.8), so where its data blocks lay is not \
     recorded anywhere this parser reads, and no content is attached. Its blocks may still hold \
     the data until reused; only carving can reach them, unattributed.";

/// Publish a deleted directory entry, joined to what its freed inode still
/// holds.
fn emit_deleted_dirent(ctx: &mut ParsingContext, entry: &FreedDirent, parent: &str) {
    let child_path = if parent == "/" {
        format!("/{}", entry.name)
    } else {
        format!("{}/{}", parent, entry.name)
    };
    // The inode number: whole when the entry's first bytes survived, or from
    // its low 32 bits when every inode number on the volume fits in 32 bits —
    // then the overwritten high half is provably zero. Otherwise unknown.
    let (inode, basis) = match entry.inode_intact {
        Some(ino) => (Some(ino), "intact_in_entry"),
        None if inode_number_bits(ctx.superblock) <= 32 => (
            Some(entry.inode_low32 as u64),
            "low_32_bits_volume_inode_numbers_fit_32_bits",
        ),
        None => (None, "high_32_bits_overwritten_by_free_tag"),
    };
    let mut metadata = json!({
        "name": entry.name,
        "path": child_path,
        "parent_path": parent,
        "inode": inode,
        "inode_number_basis": basis,
        "deleted": true,
        "deleted_recovery_source": "xfs_directory_free_space",
        "directory_entry_offset_in_block": entry.offset_in_block,
        "is_directory": entry.file_type == Some(2),
        "size": serde_json::Value::Null,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "content_incomplete_detail": DELETED_CONTENT_DETAIL,
    });
    if let Some(t) = entry.file_type {
        metadata["directory_entry_file_type"] = json!(t);
    }
    if inode.is_none() {
        metadata["inode_low_32_bits"] = json!(entry.inode_low32);
    }
    match inode.map(|ino| {
        (
            ino,
            parse_xfs_inode(ctx.data_source.as_ref(), ctx.superblock, ino),
        )
    }) {
        Some((ino, Ok(i))) if i.mode == 0 => {
            // Still free: its surviving core is this file's.
            metadata["inode_state"] = json!("free");
            metadata["uid"] = json!(i.uid);
            metadata["gid"] = json!(i.gid);
            write_inode_times(ctx.superblock, &i, &mut metadata);
            metadata["timestamps_basis"] = json!(
                "read as stored from the freed inode's core; the kernel does not clear them on \
                 free, and the change time is normally that of the unlink"
            );
            ctx.named_deleted_inodes.insert(ino);
        }
        Some((_, Ok(_))) => {
            // Allocated again: either reused by a later file, or this was the
            // old entry of a rename. Its times belong to whatever holds it now.
            metadata["inode_state"] = json!("allocated");
            metadata["inode_state_note"] = json!(
                "the inode this name recorded is allocated now — reused by a later file, or \
                 the name was the old entry of a rename — so nothing read from it is attributed \
                 to this name"
            );
        }
        Some((_, Err(e))) => {
            metadata["inode_state"] = json!("unreadable");
            metadata["inode_state_note"] = json!(e.to_string());
        }
        None => {
            metadata["inode_state"] = json!("unknown");
        }
    }
    ctx.produced_artifacts.push(
        Artifact::new(ctx.case_id, ArtifactType::FileEntry, None, metadata)
            .with_parent(ctx.artifact_id),
    );
}

/// Ceiling on freed-inode records from one volume.
const MAX_FREED_INODE_RECORDS: usize = 100_000;
/// Ceiling on inode B+tree blocks visited per allocation group.
const MAX_INOBT_BLOCKS_PER_AG: usize = 1_000_000;

const XFS_AGI_MAGIC: u32 = 0x5841_4749; // "XAGI"
const XFS_IBT_MAGIC: u32 = 0x4941_4254; // "IABT"
const XFS_IBT_CRC_MAGIC: u32 = 0x4941_4233; // "IAB3"

/// What the freed-inode scan covered, for the file system record.
#[derive(Default)]
struct FreedInodeScan {
    ags_scanned: u32,
    ags_unreadable: Vec<String>,
    free_inodes_examined: u64,
    freed_inodes_reported: usize,
    capped: bool,
}

impl FreedInodeScan {
    fn to_json(&self) -> serde_json::Value {
        let complete = self.ags_unreadable.is_empty() && !self.capped;
        let mut v = json!({
            "method": "inode_btree_free_mask",
            "ags_scanned": self.ags_scanned,
            "free_inodes_examined": self.free_inodes_examined,
            "freed_inodes_reported": self.freed_inodes_reported,
            "max_freed_inode_records": MAX_FREED_INODE_RECORDS,
            "complete": complete,
            "basis": "every inode the inode B+tree marks free is read; one whose core still \
                      carries a non-zero timestamp was in use before it was freed and is \
                      reported, unless a recovered deleted name already reports it",
        });
        if !self.ags_unreadable.is_empty() {
            v["ags_unreadable"] = json!(self.ags_unreadable);
        }
        if self.capped {
            v["capped"] = json!(true);
        }
        v
    }
}

/// Report every inode the inode B+trees mark free whose core shows it was once
/// in use (HUNT-175).
///
/// A freed XFS inode keeps its magic, owner and timestamps; an inode never
/// used since its chunk was allocated has zero timestamps. The walk reads each
/// AG's AGI, follows `agi_root` down the inode B+tree, and for every free bit
/// of every record (skipping sparse-chunk holes) reads the inode.
fn scan_freed_inodes(ctx: &mut ParsingContext) -> FreedInodeScan {
    let sb = ctx.superblock;
    let mut scan = FreedInodeScan::default();
    let agino_bits = (ceil_log2(sb.agblocks as u64) + ceil_log2(sb.inopblock as u64)).min(63);
    let bs = sb.blocksize as u64;
    for agno in 0..sb.agcount {
        let ag_start = (agno as u64)
            .saturating_mul(sb.agblocks as u64)
            .saturating_mul(bs);
        let records = match read_inobt_records(ctx.data_source.as_ref(), sb, ag_start) {
            Ok(r) => r,
            Err(e) => {
                warn!("XFS AG {agno}: inode B+tree not walked: {e}");
                scan.ags_unreadable.push(format!("AG {agno}: {e}"));
                continue;
            }
        };
        scan.ags_scanned += 1;
        for (startino, holemask, free) in records {
            for i in 0..64u32 {
                if free & (1u64 << i) == 0 || holemask & (1u16 << (i / 4)) != 0 {
                    continue;
                }
                scan.free_inodes_examined += 1;
                let agino = startino as u64 + i as u64;
                let ino = ((agno as u64) << agino_bits) | agino;
                if ctx.named_deleted_inodes.contains(&ino) {
                    continue;
                }
                let Ok(inode) = parse_xfs_inode(ctx.data_source.as_ref(), sb, ino) else {
                    continue;
                };
                if inode.mode != 0
                    || (inode.ctime_raw == 0 && inode.mtime_raw == 0 && inode.atime_raw == 0)
                {
                    continue;
                }
                if scan.freed_inodes_reported >= MAX_FREED_INODE_RECORDS {
                    scan.capped = true;
                    return scan;
                }
                let mut metadata = json!({
                    "name": serde_json::Value::Null,
                    "path": serde_json::Value::Null,
                    "name_recovered": false,
                    "inode": ino,
                    "inode_state": "free",
                    "deleted": true,
                    "deleted_recovery_source": "xfs_freed_inode",
                    "uid": inode.uid,
                    "gid": inode.gid,
                    "size": serde_json::Value::Null,
                    "timestamps_basis": "read as stored from the freed inode's core; the kernel \
                        does not clear them on free, and the change time is normally that of \
                        the unlink",
                    "name_note": "no directory entry naming this inode survives in any \
                        directory block this parser reads — a name removed from an inline \
                        (shortform) directory is compacted away — so no name or path is given",
                    "content_incomplete": true,
                    "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    "content_incomplete_detail": DELETED_CONTENT_DETAIL,
                });
                write_inode_times(sb, &inode, &mut metadata);
                ctx.produced_artifacts.push(
                    Artifact::new(ctx.case_id, ArtifactType::FileEntry, None, metadata)
                        .with_parent(ctx.artifact_id),
                );
                scan.freed_inodes_reported += 1;
            }
        }
    }
    scan
}

/// Every `(startino, holemask, free)` record of one AG's inode B+tree.
fn read_inobt_records(
    ds: &dyn DataSource,
    sb: &XfsSuperblock,
    ag_start: u64,
) -> Result<Vec<(u32, u16, u64)>> {
    let mut agi = vec![0u8; 512.min(sb.sectsize as usize).max(64)];
    read_exact_or_fail(ds, ag_start + 2 * sb.sectsize as u64, &mut agi, "XFS AGI")?;
    if BigEndian::read_u32(&agi[0..4]) != XFS_AGI_MAGIC {
        return Err(anyhow!("AGI magic not found"));
    }
    let root = BigEndian::read_u32(&agi[20..24]);
    let bs = sb.blocksize as usize;
    let mut records = Vec::new();
    let mut stack = vec![(root, 0usize)];
    let mut seen = std::collections::HashSet::new();
    while let Some((agbno, depth)) = stack.pop() {
        if depth > MAX_BTREE_DEPTH || agbno as u64 >= sb.agblocks as u64 {
            return Err(anyhow!("inode B+tree pointer {agbno} out of range"));
        }
        if !seen.insert(agbno) || seen.len() > MAX_INOBT_BLOCKS_PER_AG {
            return Err(anyhow!("inode B+tree loops or exceeds its block cap"));
        }
        let mut blk = vec![0u8; bs];
        read_exact_or_fail(
            ds,
            ag_start + agbno as u64 * bs as u64,
            &mut blk,
            "XFS inode B+tree block",
        )?;
        let hdr = match BigEndian::read_u32(&blk[0..4]) {
            XFS_IBT_CRC_MAGIC => 56,
            XFS_IBT_MAGIC => 16,
            m => return Err(anyhow!("inode B+tree block {agbno}: bad magic {m:#010x}")),
        };
        let level = BigEndian::read_u16(&blk[4..6]);
        let numrecs = BigEndian::read_u16(&blk[6..8]) as usize;
        if level == 0 {
            if hdr + numrecs * 16 > bs {
                return Err(anyhow!(
                    "inode B+tree leaf {agbno}: {numrecs} records overflow"
                ));
            }
            for r in 0..numrecs {
                let o = hdr + r * 16;
                // Without the sparse-inode feature bytes 4..8 are one u32
                // freecount, whose high half reads as a zero holemask.
                records.push((
                    BigEndian::read_u32(&blk[o..o + 4]),
                    BigEndian::read_u16(&blk[o + 4..o + 6]),
                    BigEndian::read_u64(&blk[o + 8..o + 16]),
                ));
            }
        } else {
            let maxrecs = (bs - hdr) / 8;
            if numrecs > maxrecs {
                return Err(anyhow!(
                    "inode B+tree node {agbno}: {numrecs} pointers overflow"
                ));
            }
            let ptrs = hdr + maxrecs * 4;
            for r in 0..numrecs {
                let o = ptrs + r * 4;
                stack.push((BigEndian::read_u32(&blk[o..o + 4]), depth + 1));
            }
        }
    }
    Ok(records)
}

// --- Utilities ---

fn format_timestamp(ts: u32) -> String {
    if ts == 0 {
        return String::new();
    }
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

/// Nanoseconds in one second, named at the point it converts a bigtime raw
/// count between whole seconds and a sub-second remainder.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Seconds by which the bigtime epoch (1901-12-13 20:45:52 UTC) precedes the
/// Unix epoch (1970-01-01 00:00:00 UTC).
///
/// The kernel defines the bigtime encoding as
/// `xfs_bigtime_to_unix_nsec(ts) = be64_to_cpu(ts) - XFS_BIGTIME_EPOCH_OFFSET * NSEC_PER_SEC`,
/// with `XFS_BIGTIME_EPOCH_OFFSET = -(int64_t)S32_MIN` (fs/xfs/libxfs/xfs_format.h)
/// — i.e. exactly 2^31 seconds, not a value derived from i64/1e9. 2^31 is not
/// an arbitrary choice: it places bigtime's raw value 0 at the same instant as
/// the legacy 32-bit `xfs_timestamp_t`'s most negative representable second
/// (`time_t == i32::MIN`), which is the well-known 1901-12-13 20:45:52 UTC
/// "far side of the Y2038 problem" date — the crate's tests re-derive this
/// same instant independently (by calendar subtraction, not this constant) as
/// a check on the value below rather than trusting it from memory.
const XFS_BIGTIME_EPOCH_OFFSET_SECS: i64 = 1i64 << 31;

/// One decoded bigtime timestamp field.
#[derive(Debug)]
enum BigtimeField {
    /// Raw was the on-disk zero value. The kernel comment on
    /// `xfs_timestamp_t` calls this "the invalid timestamp, in traditional
    /// xfs terms" — deliberately aligned with the legacy format's own
    /// sec==0 "unset" convention, so both formats treat it the same way.
    Unset,
    /// Decoded to this RFC 3339 string.
    Value(String),
    /// `raw` was set but did not resolve to a representable calendar
    /// instant. Every nonzero u64 maps into 1901..=2486 under this format,
    /// so this arm is not expected to be reachable from real evidence; it
    /// exists so a `chrono` construction failure is reported on the record
    /// for the one field it hit, rather than unwrapped or silently dropped.
    Undecodable,
}

/// Decode one bigtime `xfs_timestamp_t`: a raw 64-bit big-endian nanosecond
/// count since 1901-12-13 20:45:52 UTC.
fn decode_bigtime(raw: u64) -> BigtimeField {
    if raw == 0 {
        return BigtimeField::Unset;
    }
    // raw / NANOS_PER_SEC is at most u64::MAX / 1e9 (~1.8e10), far inside
    // i64's range, so this cast and the epoch-offset subtraction below
    // cannot overflow.
    let secs_since_bigtime_epoch = (raw / NANOS_PER_SEC) as i64;
    let nanos = (raw % NANOS_PER_SEC) as u32;
    let unix_secs = secs_since_bigtime_epoch - XFS_BIGTIME_EPOCH_OFFSET_SECS;
    match Utc.timestamp_opt(unix_secs, nanos).single() {
        Some(dt) => BigtimeField::Value(dt.to_rfc3339()),
        None => BigtimeField::Undecodable,
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_metadata() {
        let module = XfsParser;
        assert_eq!(module.id(), "plugin.filesystem.xfs");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));

        let subscriptions = module.subscribes_to();
        assert!(subscriptions.contains(&ArtifactType::FileSystem));
    }

    #[test]
    fn test_xfs_magic_detection() {
        let mut sb_data = vec![0u8; 512];
        sb_data[0] = 0x58; // 'X'
        sb_data[1] = 0x46; // 'F'
        sb_data[2] = 0x53; // 'S'
        sb_data[3] = 0x42; // 'B'
        let magic = BigEndian::read_u32(&sb_data[0..4]);
        assert_eq!(magic, XFS_SB_MAGIC);
    }

    #[test]
    fn test_unpack_extent_normal() {
        // Build a known extent: logical=10, physical=1000, count=50
        // Bit layout (128 bits total, big-endian):
        //   Bit 127: flag (0)
        //   Bits 73-126: logical (54 bits) = 10
        //   Bits 21-72: physical (52 bits) = 1000
        //   Bits 0-20: count (21 bits) = 50
        let logical: u64 = 10;
        let physical: u64 = 1000;
        let count: u64 = 50;

        // hi = (flag << 63) | (logical << 9) | (physical >> 43)
        let hi: u64 = (logical << 9) | (physical >> 43);
        // lo = (physical << 21) | count
        let lo: u64 = ((physical & 0x7FF_FFFF_FFFF) << 21) | count;

        let mut data = [0u8; 16];
        BigEndian::write_u64(&mut data[0..8], hi);
        BigEndian::write_u64(&mut data[8..16], lo);

        let ext = unpack_extent(&data).unwrap();
        assert_eq!(ext.logical, 10);
        assert_eq!(ext.physical, 1000);
        assert_eq!(ext.count, 50);
    }

    #[test]
    fn test_unpack_extent_zero() {
        let data = [0u8; 16];
        assert!(unpack_extent(&data).is_none());
    }

    #[test]
    fn test_unpack_extent_large_values() {
        // Test with larger values
        let logical: u64 = 0x3F_FFFF_FFFF; // max 54-bit is much larger, use 38-bit
        let physical: u64 = 0xF_FFFF_FFFF; // 40 bits
        let count: u64 = 0x1F_FFFF; // max 21 bits

        let hi: u64 = (logical << 9) | (physical >> 43);
        let lo: u64 = ((physical & 0x7FF_FFFF_FFFF) << 21) | count;

        let mut data = [0u8; 16];
        BigEndian::write_u64(&mut data[0..8], hi);
        BigEndian::write_u64(&mut data[8..16], lo);

        let ext = unpack_extent(&data).unwrap();
        assert_eq!(ext.logical, logical);
        assert_eq!(ext.physical, physical);
        assert_eq!(ext.count, count);
    }

    #[test]
    fn test_inode_offset_simple() {
        let sb = XfsSuperblock {
            _magic: XFS_SB_MAGIC,
            blocksize: 4096,
            dblocks: 1024,
            _rblocks: 0,
            agcount: 1,
            agblocks: 1024,
            agblklog: 10, // log2(1024)
            sectsize: 512,
            inodesize: 512,
            inopblock: 8, // 4096 / 512
            version: 5,
            uuid: [0; 16],
            fname: String::new(),
            rootino: 64,
            v5: true,
            bigtime: false,
            nrext64: false,
            ftype: true,
        };

        // Inode 64: AG 0, agino 64
        // block_in_ag = 64 / 8 = 8
        // inode_in_block = 64 % 8 = 0
        // offset = 0 + 8*4096 + 0 = 32768
        let offset = inode_offset(&sb, 64);
        assert_eq!(offset, 8 * 4096);
    }

    /// Regression (X1): with a power-of-two agblocks (1024), the old
    /// bit_length(agblocks*inopblock) heuristic produced an AG shift of 14 instead
    /// of the correct 13, misplacing every inode in AG >= 2.
    #[test]
    fn test_inode_offset_multi_ag_power_of_two_agblocks() {
        let sb = XfsSuperblock {
            _magic: XFS_SB_MAGIC,
            blocksize: 4096,
            dblocks: 0,
            _rblocks: 0,
            agcount: 4,
            agblocks: 1024, // 2^10, exact power of two
            agblklog: 10,
            sectsize: 512,
            inodesize: 512,
            inopblock: 8, // 2^3
            version: 5,
            uuid: [0; 16],
            fname: String::new(),
            rootino: 64,
            v5: true,
            bigtime: false,
            nrext64: false,
            ftype: true,
        };
        // Correct AG shift = 10 + 3 = 13. ino in AG 3, agino 128:
        // ino = (3 << 13) | 128 = 24704.
        // offset = 3*1024*4096 (AG) + (128/8)*4096 (block) = 12_582_912 + 65_536.
        assert_eq!(inode_offset(&sb, 24704), 12_648_448);
    }

    #[test]
    fn test_shortform_dir_parsing() {
        // Build a minimal shortform directory:
        // count=2, i8count=0, parent_ino=64 (4 bytes BE)
        // Entry 1: namelen=3, offset=1, name="foo", ino=128
        // Entry 2: namelen=3, offset=2, name="bar", ino=192
        let mut data = Vec::new();
        data.push(2); // count
        data.push(0); // i8count (4-byte inodes)

        // Parent inode (4 bytes BE)
        data.extend_from_slice(&64u32.to_be_bytes());

        // Entry 1: namelen=3, offset=1 (2 bytes), name="foo", ino=128 (4 bytes)
        data.push(3); // namelen
        data.extend_from_slice(&1u16.to_be_bytes()); // offset tag
        data.extend_from_slice(b"foo");
        data.extend_from_slice(&128u32.to_be_bytes());

        // Entry 2: namelen=3, offset=2, name="bar", ino=192
        data.push(3);
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(b"bar");
        data.extend_from_slice(&192u32.to_be_bytes());

        // Verify we can parse the header
        assert_eq!(data[0], 2); // count
        assert_eq!(data[1], 0); // i8count

        let parent_ino = BigEndian::read_u32(&data[2..6]);
        assert_eq!(parent_ino, 64);

        // Verify first entry
        let namelen = data[6] as usize;
        assert_eq!(namelen, 3);
        let name = String::from_utf8_lossy(&data[9..12]).to_string();
        assert_eq!(name, "foo");
        let ino = BigEndian::read_u32(&data[12..16]);
        assert_eq!(ino, 128);
    }

    #[test]
    fn test_shortform_dir_64bit_inodes() {
        // Build a shortform directory with 8-byte inodes
        let mut data = Vec::new();
        data.push(1); // count
        data.push(1); // i8count > 0 means 8-byte inodes

        // Parent inode (8 bytes BE)
        data.extend_from_slice(&64u64.to_be_bytes());

        // Entry: namelen=4, offset=1 (2 bytes), name="test", ino=0x100000000 (8 bytes)
        data.push(4);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(b"test");
        data.extend_from_slice(&0x100000000u64.to_be_bytes());

        assert_eq!(data[0], 1);
        assert_eq!(data[1], 1);
        let parent = BigEndian::read_u64(&data[2..10]);
        assert_eq!(parent, 64);
        let entry_ino = BigEndian::read_u64(&data[17..25]);
        assert_eq!(entry_ino, 0x100000000);
    }

    #[test]
    fn test_dir_data_entry_free_skip() {
        // Build a block with a free entry followed by an active entry
        let blocksize = 128;
        let mut block = vec![0u8; blocksize];

        // Free entry at offset 0: freetag=0xFFFF, length=16
        BigEndian::write_u16(&mut block[0..2], 0xFFFF);
        BigEndian::write_u16(&mut block[2..4], 16);

        // Active entry at offset 16: inode=100, namelen=3, name="abc"
        BigEndian::write_u64(&mut block[16..24], 100); // inode
        block[24] = 3; // namelen
        block[25..28].copy_from_slice(b"abc");

        // Verify free entry is detected
        let tag = BigEndian::read_u16(&block[0..2]);
        assert_eq!(tag, 0xFFFF);
        let free_len = BigEndian::read_u16(&block[2..4]);
        assert_eq!(free_len, 16);

        // Verify active entry
        let entry_ino = BigEndian::read_u64(&block[16..24]);
        assert_eq!(entry_ino, 100);
        let namelen = block[24] as usize;
        assert_eq!(namelen, 3);
        let name = String::from_utf8_lossy(&block[25..28]).to_string();
        assert_eq!(name, "abc");
    }

    #[test]
    fn test_btree_header_parsing() {
        // Build a minimal B-tree leaf root (level=0, numrecs=1)
        let mut root = [0u8; 20];
        BigEndian::write_u16(&mut root[0..2], 0); // level=0 (leaf)
        BigEndian::write_u16(&mut root[2..4], 1); // numrecs=1

        // One extent record at offset 4
        let logical: u64 = 5;
        let physical: u64 = 500;
        let count: u64 = 10;
        let hi: u64 = (logical << 9) | (physical >> 43);
        let lo: u64 = ((physical & 0x7FF_FFFF_FFFF) << 21) | count;
        BigEndian::write_u64(&mut root[4..12], hi);
        BigEndian::write_u64(&mut root[12..20], lo);

        // Verify header
        let level = BigEndian::read_u16(&root[0..2]);
        let numrecs = BigEndian::read_u16(&root[2..4]);
        assert_eq!(level, 0);
        assert_eq!(numrecs, 1);

        // Verify extent
        let ext = unpack_extent(&root[4..20]).unwrap();
        assert_eq!(ext.logical, 5);
        assert_eq!(ext.physical, 500);
        assert_eq!(ext.count, 10);
    }

    #[test]
    fn test_format_timestamp() {
        let ts = format_timestamp(1700000000);
        assert!(ts.contains("2023"));

        let empty = format_timestamp(0);
        assert_eq!(empty, "");
    }

    #[test]
    fn test_xfs_file_source_resolve() {
        let extents = vec![
            XfsExtent {
                logical: 0,
                physical: 100,
                count: 5,
                unwritten: false,
            },
            XfsExtent {
                logical: 10,
                physical: 200,
                count: 3,
                unwritten: false,
            },
        ];

        // Create a minimal inner data source. Single-AG geometry (agblklog large
        // enough that agno=0 for these small fsbno) so fsbno maps 1:1 to abs block.
        let inner = Arc::new(seance_core::data_source::ByteSliceDataSource::new(
            vec![0u8; 1024 * 1024],
        ));
        let source = XfsFileSource::new(inner, 4096, 1 << 20, 20, 53248, extents, true);

        // Block 0 → physical 100
        let phys = source.resolve_logical_offset(0).unwrap();
        assert_eq!(phys, 100 * 4096);

        // Block 2 → physical 102
        let phys2 = source.resolve_logical_offset(2 * 4096).unwrap();
        assert_eq!(phys2, 102 * 4096);

        // Block 10 → physical 200
        let phys3 = source.resolve_logical_offset(10 * 4096).unwrap();
        assert_eq!(phys3, 200 * 4096);

        // Block 5 (hole between extents)
        let hole = source.resolve_logical_offset(5 * 4096);
        assert!(hole.is_none());
    }

    /// BUG-208: bit 127 of an XFS extent record marks it unwritten
    /// (preallocated). Those blocks read as zeros; mapping them to their
    /// physical location would serve whatever residual data is still there.
    #[test]
    fn test_unpack_extent_unwritten_flag() {
        let logical: u64 = 7;
        let physical: u64 = 300;
        let count: u64 = 4;

        let mut data = [0u8; 16];
        let hi: u64 = (logical << 9) | (physical >> 43);
        let lo: u64 = ((physical & 0x7FF_FFFF_FFFF) << 21) | count;
        BigEndian::write_u64(&mut data[0..8], hi);
        BigEndian::write_u64(&mut data[8..16], lo);
        let written = unpack_extent(&data).unwrap();
        assert!(!written.unwritten);
        assert_eq!(written.logical, logical);
        assert_eq!(written.physical, physical);

        // Same record with the state flag set.
        BigEndian::write_u64(&mut data[0..8], hi | (1u64 << 63));
        let unwritten = unpack_extent(&data).unwrap();
        assert!(unwritten.unwritten, "bit 127 marks an unwritten extent");
        // The flag must not bleed into the logical offset.
        assert_eq!(unwritten.logical, logical);
        assert_eq!(unwritten.physical, physical);
        assert_eq!(unwritten.count, count);
    }

    /// An unwritten extent must resolve to "zeros", not to its physical blocks.
    #[test]
    fn test_unwritten_extent_reads_as_zeros() {
        let extents = vec![
            XfsExtent {
                logical: 0,
                physical: 100,
                count: 1,
                unwritten: false,
            },
            XfsExtent {
                logical: 1,
                physical: 200,
                count: 1,
                unwritten: true,
            },
        ];

        let mut backing = vec![0u8; 1024 * 1024];
        backing[100 * 4096..100 * 4096 + 4].copy_from_slice(b"real");
        // Residual bytes left in the preallocated (never written) block.
        backing[200 * 4096..200 * 4096 + 8].copy_from_slice(b"RESIDUAL");
        let inner = Arc::new(seance_core::data_source::ByteSliceDataSource::new(backing));
        let source = XfsFileSource::new(inner, 4096, 1 << 20, 20, 2 * 4096, extents, true);

        assert_eq!(source.resolve_logical_offset(0), Some(100 * 4096));
        assert_eq!(
            source.resolve_logical_offset(4096),
            None,
            "an unwritten extent must not map to its physical blocks"
        );

        let mut buf = vec![0xAAu8; 2 * 4096];
        assert_eq!(source.read_at(0, &mut buf).unwrap(), 2 * 4096);
        assert_eq!(&buf[0..4], b"real");
        assert!(
            buf[4096..].iter().all(|&b| b == 0),
            "unwritten extent must read as zeros, got residual disk bytes"
        );
    }

    /// BUG-237: a sparse tail past the last extent (what fallocate/truncate
    /// leaves behind) is a genuine hole up to i_size. The old "past every
    /// extent -> break" made the source short-read after one zero block, so the
    /// file hashed/exported as a prefix.
    #[test]
    fn test_sparse_tail_past_last_extent_reads_zeros_to_size() {
        let extents = vec![XfsExtent {
            logical: 0,
            physical: 100,
            count: 1,
            unwritten: false,
        }];
        let mut backing = vec![0u8; 1024 * 1024];
        backing[100 * 4096..100 * 4096 + 4].copy_from_slice(b"head");
        let inner = Arc::new(seance_core::data_source::ByteSliceDataSource::new(backing));

        let size = 3 * 4096u64; // one mapped block + two blocks of sparse tail
        let source = XfsFileSource::new(inner, 4096, 1 << 20, 20, size, extents, true);

        let mut buf = vec![0xAAu8; size as usize];
        assert_eq!(
            source.read_at(0, &mut buf).unwrap(),
            size as usize,
            "a sparse tail must read out to i_size, not stop after one block"
        );
        assert_eq!(&buf[0..4], b"head");
        assert!(
            buf[4096..].iter().all(|&b| b == 0),
            "the sparse tail must read as zeros"
        );
    }

    /// BUG-238: when the extent list was truncated by a safety cap, the range
    /// past the last known extent is UNKNOWN, not a hole. It must surface as an
    /// honest short read rather than fabricated zeros that hash as content.
    #[test]
    fn test_truncated_extent_list_short_reads_instead_of_faking_a_hole() {
        let extents = vec![XfsExtent {
            logical: 0,
            physical: 100,
            count: 1,
            unwritten: false,
        }];
        let mut backing = vec![0u8; 1024 * 1024];
        backing[100 * 4096..100 * 4096 + 4].copy_from_slice(b"head");
        let inner = Arc::new(seance_core::data_source::ByteSliceDataSource::new(backing));

        let size = 3 * 4096u64;
        let source = XfsFileSource::new(inner, 4096, 1 << 20, 20, size, extents, false);

        let mut buf = vec![0xAAu8; size as usize];
        assert_eq!(
            source.read_at(0, &mut buf).unwrap(),
            4096,
            "only the known extent may be served from a truncated extent list"
        );
        assert_eq!(&buf[0..4], b"head");
        assert!(
            buf[4096..].iter().all(|&b| b == 0xAA),
            "the unknown tail must be left untouched, never zero-filled"
        );
    }

    /// BUG-238: an inode whose extent count exceeds MAX_EXTENTS yields a
    /// partial list. It must be stamped incomplete, not reported as a
    /// full-size file whose missing extents are sparse.
    #[test]
    fn test_extent_count_over_cap_flags_incomplete() {
        let mut image = build_synthetic_xfs_image();
        let ds_probe = seance_core::data_source::ByteSliceDataSource::new(image.clone());
        let sb = parse_xfs_superblock(&ds_probe).unwrap();

        // Rewrite inode 65 (hello.txt) as an extent-format file claiming far
        // more extents than the cap allows.
        let hello_offset = 8 * sb.blocksize as usize + sb.inodesize as usize;
        image[hello_offset + 5] = XFS_DINODE_FMT_EXTENTS;
        BigEndian::write_u64(&mut image[hello_offset + 56..hello_offset + 64], 1 << 30);
        BigEndian::write_u32(
            &mut image[hello_offset + 76..hello_offset + 80],
            (MAX_EXTENTS as u32) + 1,
        );
        // Every record the fork actually holds must decode, or the reason
        // becomes "unresolved_structure" (a record we could not place) instead
        // of "cap_reached" (records we chose not to read).
        fill_fork_with_valid_extents(&mut image, hello_offset, sb.inodesize as usize);

        let ds = seance_core::data_source::ByteSliceDataSource::new(image);
        let inode = parse_xfs_inode(&ds, &sb, 65).unwrap();
        assert_eq!(
            inode.extents_incomplete,
            Some(IncompleteReason::CapReached),
            "a capped extent list must be flagged incomplete"
        );
    }

    /// Fill an inode's data fork with as many valid 16-byte extent records as
    /// it holds (logical 0.., one block each). Used by the cap tests: a fork of
    /// null padding would be read as records that failed to decode, which is a
    /// different kind of incompleteness from hitting a cap.
    fn fill_fork_with_valid_extents(image: &mut [u8], inode_offset: usize, inodesize: usize) {
        let dfork = XFS_V3_DINODE_CORE_SIZE;
        let slots = (inodesize - dfork) / 16;
        for i in 0..slots {
            let logical = i as u64;
            let physical = 20u64 + i as u64;
            let at = inode_offset + dfork + i * 16;
            // hi: logical (54 bits) << 9 | high 9 bits of physical.
            // lo: low 43 bits of physical << 21 | blockcount (21 bits).
            BigEndian::write_u64(&mut image[at..at + 8], (logical << 9) | (physical >> 43));
            BigEndian::write_u64(
                &mut image[at + 8..at + 16],
                ((physical & 0x7FF_FFFF_FFFF) << 21) | 1,
            );
        }
    }

    /// BUG-239: bmap btree pointers are fsbno values (agno/agbno), not linear
    /// block indices. With a non-power-of-two agblocks the two differ, and the
    /// old `block_num * blocksize` read a completely different block.
    #[test]
    fn test_fsbno_decoding_is_not_linear() {
        // agblocks = 1000 but agblklog = 10 (1 << 10 = 1024): AG 1 starts at
        // absolute block 1000 while the fsbno's high bits say 1024.
        assert_eq!(fsbno_to_abs_block((1 << 10) | 5, 1000, 10), 1005);
        // A power-of-two geometry is the case that masked the bug.
        assert_eq!(fsbno_to_abs_block((1 << 10) | 5, 1024, 10), 1029);
    }

    /// BUG-239: end-to-end — a bmap btree block addressed by fsbno must be read
    /// from its AG-decoded device offset.
    #[test]
    fn test_btree_block_read_from_ag_decoded_offset() {
        let blocksize: u32 = 4096;
        let agblocks: u32 = 1000;
        let agblklog: u8 = 10;
        let fsbno: u64 = (1u64 << agblklog) | 5; // AG 1, agbno 5
        let abs_block = agblocks as u64 + 5; // = 1005
        let linear_block = fsbno; // what the buggy code used

        let mut image = vec![0u8; (linear_block as usize + 2) * blocksize as usize];

        // Leaf bmap block (v2 header, 24 bytes) with a single extent record,
        // written at the CORRECT AG-decoded offset.
        let at = abs_block as usize * blocksize as usize;
        BigEndian::write_u32(&mut image[at..at + 4], XFS_BMAP_MAGIC);
        BigEndian::write_u16(&mut image[at + 4..at + 6], 0); // level = leaf
        BigEndian::write_u16(&mut image[at + 6..at + 8], 1); // numrecs
        let logical: u64 = 3;
        let physical: u64 = 4242;
        let count: u64 = 7;
        let hi: u64 = (logical << 9) | (physical >> 43);
        let lo: u64 = ((physical & 0x7FF_FFFF_FFFF) << 21) | count;
        BigEndian::write_u64(&mut image[at + 24..at + 32], hi);
        BigEndian::write_u64(&mut image[at + 32..at + 40], lo);

        // The block the buggy linear addressing would have read holds a valid
        // header too, so a wrong read fails loudly on the record values rather
        // than on a magic mismatch.
        let wrong = linear_block as usize * blocksize as usize;
        BigEndian::write_u32(&mut image[wrong..wrong + 4], XFS_BMAP_MAGIC);
        BigEndian::write_u16(&mut image[wrong + 4..wrong + 6], 0);
        BigEndian::write_u16(&mut image[wrong + 6..wrong + 8], 0); // no records

        let sb = XfsSuperblock {
            _magic: XFS_SB_MAGIC,
            blocksize,
            dblocks: 0,
            _rblocks: 0,
            agcount: 4,
            agblocks,
            agblklog,
            sectsize: 512,
            inodesize: 512,
            inopblock: 8,
            version: 5,
            uuid: [0; 16],
            fname: String::new(),
            rootino: 64,
            v5: true,
            bigtime: false,
            nrext64: false,
            ftype: true,
        };

        let ds = seance_core::data_source::ByteSliceDataSource::new(image);
        let mut extents = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut truncated = false;
        read_btree_block(
            &ds,
            &sb,
            fsbno,
            0,
            &mut extents,
            0,
            &mut visited,
            &mut truncated,
        )
        .expect("the AG-decoded block must parse");

        assert!(!truncated);
        assert_eq!(
            extents.len(),
            1,
            "the record at the AG-decoded block is lost"
        );
        assert_eq!(extents[0].logical, logical);
        assert_eq!(extents[0].physical, physical);
        assert_eq!(extents[0].count, count);
    }

    /// Build a minimal synthetic XFS v5 image with:
    /// - Valid superblock
    /// - Root inode (dir, shortform format) containing two entries: "hello.txt" and "subdir"
    /// - "hello.txt" inode (regular file, LOCAL format) with inline data
    /// - "subdir" inode (dir, shortform format, empty)
    ///
    /// Layout (blocksize=4096, inodesize=512, inopblock=8):
    ///   Block 0: Superblock
    ///   Block 8: Inodes (root=64 at block 8 offset 0, hello=65 at +512, subdir=66 at +1024)
    pub(crate) fn build_synthetic_xfs_image() -> Vec<u8> {
        let blocksize: u32 = 4096;
        let inodesize: u16 = 512;
        let inopblock: u16 = 8;
        let agblocks: u32 = 64;
        let agcount: u32 = 1;

        // Total image: agblocks * blocksize
        let total_size = agblocks as usize * blocksize as usize;
        let mut image = vec![0u8; total_size];

        // --- Superblock (block 0) ---
        let sb = &mut image[0..512];
        // magic "XFSB"
        BigEndian::write_u32(&mut sb[0..4], XFS_SB_MAGIC);
        // blocksize
        BigEndian::write_u32(&mut sb[4..8], blocksize);
        // dblocks
        BigEndian::write_u64(&mut sb[8..16], agblocks as u64);
        // rblocks
        BigEndian::write_u64(&mut sb[16..24], 0);
        // uuid
        sb[32..48].copy_from_slice(&[0xAA; 16]);
        // rootino = 64
        BigEndian::write_u64(&mut sb[56..64], 64);
        // agblocks
        BigEndian::write_u32(&mut sb[84..88], agblocks);
        // agcount
        BigEndian::write_u32(&mut sb[88..92], agcount);
        // version (v5 = 0x0005 with features bits) @ 0x64
        BigEndian::write_u16(&mut sb[100..102], 5);
        // sb_features_incompat @ 0xd8: XFS_SB_FEAT_INCOMPAT_FTYPE (0x1). The
        // directory entries below carry a file-type byte, so the flag has to
        // say so — the parser reads the bit rather than inferring it from v5.
        BigEndian::write_u32(&mut sb[216..220], 0x1);
        // sectsize @ 0x66
        BigEndian::write_u16(&mut sb[102..104], 512);
        // inodesize @ 0x68
        BigEndian::write_u16(&mut sb[104..106], inodesize);
        // inopblock @ 0x6a
        BigEndian::write_u16(&mut sb[106..108], inopblock);
        // fname
        sb[108..115].copy_from_slice(b"TESTXFS");

        // --- Root inode (inode 64, at block 8, offset 0) ---
        // inode 64: agino=64, block_in_ag = 64/8 = 8, inode_in_block = 0
        let root_offset = 8 * blocksize as usize;
        let root = &mut image[root_offset..root_offset + inodesize as usize];

        // magic "IN"
        BigEndian::write_u16(&mut root[0..2], 0x494E);
        // mode: directory (0o40755)
        BigEndian::write_u16(&mut root[2..4], 0o40755);
        // version
        root[4] = 3;
        // format: LOCAL (inline data)
        root[5] = XFS_DINODE_FMT_LOCAL;
        // onlink (v1 nlink)
        BigEndian::write_u16(&mut root[6..8], 3);
        // uid, gid
        BigEndian::write_u32(&mut root[8..12], 0);
        BigEndian::write_u32(&mut root[12..16], 0);
        // nlink (v2)
        BigEndian::write_u32(&mut root[16..20], 3);
        // atime (0x20), mtime (0x28), ctime (0x30)
        BigEndian::write_u32(&mut root[32..36], 1700000000);
        BigEndian::write_u32(&mut root[40..44], 1700000000);
        BigEndian::write_u32(&mut root[48..52], 1700000000);
        // size (shortform dir size)
        let sf_dir_size: u64 = 30; // header(6) + entry1(3+9+4) + entry2(3+6+4) - approximate
        BigEndian::write_u64(&mut root[56..64], sf_dir_size);
        // nextents = 0 (inline)
        BigEndian::write_u32(&mut root[76..80], 0);

        // Data fork starts at offset 176 (v3 core size)
        let dfork = &mut root[176..];

        // Shortform directory:
        //   count=2, i8count=0, parent_ino=64 (self, root)
        //   Entry 1: "hello.txt" -> inode 65
        //   Entry 2: "subdir" -> inode 66
        dfork[0] = 2; // count
        dfork[1] = 0; // i8count (4-byte inodes)
        BigEndian::write_u32(&mut dfork[2..6], 64); // parent = root

        // v5 shortform entries carry a 1-byte ftype after the name.
        let mut pos = 6;
        // Entry 1: namelen=9, offset_tag=1, name="hello.txt", ftype=1(file), ino=65
        dfork[pos] = 9; // namelen
        BigEndian::write_u16(&mut dfork[pos + 1..pos + 3], 1); // offset tag
        dfork[pos + 3..pos + 12].copy_from_slice(b"hello.txt");
        dfork[pos + 12] = 1; // ftype = regular file
        BigEndian::write_u32(&mut dfork[pos + 13..pos + 17], 65); // inode
        pos += 17;

        // Entry 2: namelen=6, offset_tag=2, name="subdir", ftype=2(dir), ino=66
        dfork[pos] = 6;
        BigEndian::write_u16(&mut dfork[pos + 1..pos + 3], 2);
        dfork[pos + 3..pos + 9].copy_from_slice(b"subdir");
        dfork[pos + 9] = 2; // ftype = directory
        BigEndian::write_u32(&mut dfork[pos + 10..pos + 14], 66);

        // --- Inode 65 (hello.txt, regular file, LOCAL) at block 8 + 512 ---
        let hello_offset = root_offset + inodesize as usize;
        let hello = &mut image[hello_offset..hello_offset + inodesize as usize];

        BigEndian::write_u16(&mut hello[0..2], 0x494E); // magic
        BigEndian::write_u16(&mut hello[2..4], 0o100644); // mode: regular file
        hello[4] = 3; // version
        hello[5] = XFS_DINODE_FMT_LOCAL; // format: inline
        BigEndian::write_u16(&mut hello[6..8], 1); // nlink v1
        BigEndian::write_u32(&mut hello[16..20], 1); // nlink v2
        BigEndian::write_u32(&mut hello[32..36], 1700000000); // atime (0x20)
        BigEndian::write_u32(&mut hello[40..44], 1700000000); // mtime (0x28)
        BigEndian::write_u32(&mut hello[48..52], 1700000000); // ctime (0x30)
        let hello_content = b"Hello from XFS!";
        BigEndian::write_u64(&mut hello[56..64], hello_content.len() as u64); // size
        BigEndian::write_u32(&mut hello[76..80], 0); // nextents
                                                     // Inline data at data fork offset
        hello[176..176 + hello_content.len()].copy_from_slice(hello_content);

        // --- Inode 66 (subdir, directory, LOCAL, empty) at block 8 + 1024 ---
        let sub_offset = root_offset + 2 * inodesize as usize;
        let subdir = &mut image[sub_offset..sub_offset + inodesize as usize];

        BigEndian::write_u16(&mut subdir[0..2], 0x494E); // magic
        BigEndian::write_u16(&mut subdir[2..4], 0o40755); // mode: directory
        subdir[4] = 3;
        subdir[5] = XFS_DINODE_FMT_LOCAL;
        BigEndian::write_u16(&mut subdir[6..8], 2);
        BigEndian::write_u32(&mut subdir[16..20], 2);
        BigEndian::write_u32(&mut subdir[32..36], 1700000000); // atime (0x20)
        BigEndian::write_u32(&mut subdir[40..44], 1700000000); // mtime (0x28)
        BigEndian::write_u32(&mut subdir[48..52], 1700000000); // ctime (0x30)
        BigEndian::write_u64(&mut subdir[56..64], 6); // size
        BigEndian::write_u32(&mut subdir[76..80], 0);
        // Empty shortform dir: count=0, i8count=0, parent=64
        subdir[176] = 0; // count
        subdir[177] = 0; // i8count
        BigEndian::write_u32(&mut subdir[178..182], 64); // parent

        image
    }

    #[test]
    fn test_synthetic_xfs_superblock_parsing() {
        let image = build_synthetic_xfs_image();
        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();

        assert_eq!(sb._magic, XFS_SB_MAGIC);
        assert_eq!(sb.blocksize, 4096);
        assert_eq!(sb.inodesize, 512);
        assert_eq!(sb.inopblock, 8);
        assert_eq!(sb.rootino, 64);
        assert_eq!(sb.agcount, 1);
        assert_eq!(sb.agblocks, 64);
        assert!(sb.v5);
        assert_eq!(sb.fname, "TESTXFS");
    }

    #[test]
    fn test_xfs_superblock_zero_inopblock_rejected() {
        // Reproduces the fuzz crash: inopblock = 0 makes inode_offset divide
        // agino by zero (panic). parse_xfs_superblock must reject a zero divisor
        // up front rather than let the walk reach the division.
        let mut sb = vec![0u8; 512];
        BigEndian::write_u32(&mut sb[0..4], XFS_SB_MAGIC); // magic
        BigEndian::write_u32(&mut sb[4..8], 4096); // blocksize
        BigEndian::write_u32(&mut sb[84..88], 1024); // agblocks  @ 0x54
        BigEndian::write_u16(&mut sb[102..104], 512); // sectsize  @ 0x66
        BigEndian::write_u16(&mut sb[104..106], 512); // inodesize @ 0x68
        BigEndian::write_u16(&mut sb[106..108], 0); // inopblock @ 0x6a = 0

        let ds = seance_core::data_source::ByteSliceDataSource::new(sb);
        let err = parse_xfs_superblock(&ds).expect_err("zero inopblock must error");
        assert!(
            err.to_string().contains("inopblock"),
            "unexpected error: {err}"
        );
    }

    /// Regression (X3): a huge blocksize would size a multi-GiB per-block
    /// allocation (OOM). parse_xfs_superblock must reject out-of-range blocksize.
    #[test]
    fn test_xfs_superblock_huge_blocksize_rejected() {
        let mut sb = vec![0u8; 512];
        BigEndian::write_u32(&mut sb[0..4], XFS_SB_MAGIC);
        BigEndian::write_u32(&mut sb[4..8], 0x0002_0000); // blocksize 131072 (> 65536)
        BigEndian::write_u32(&mut sb[84..88], 1024); // agblocks
        BigEndian::write_u16(&mut sb[102..104], 512); // sectsize
        BigEndian::write_u16(&mut sb[104..106], 512); // inodesize
        BigEndian::write_u16(&mut sb[106..108], 8); // inopblock
        let ds = seance_core::data_source::ByteSliceDataSource::new(sb);
        let err = parse_xfs_superblock(&ds).expect_err("huge blocksize must error");
        assert!(err.to_string().contains("blocksize"), "unexpected: {err}");
    }

    /// Regression (X4): agblklog is used as a shift width (1u64 << agblklog) in the
    /// fsbno decoder; a value >= 64 would panic. It must be rejected at parse.
    #[test]
    fn test_xfs_superblock_bad_agblklog_rejected() {
        let mut sb = vec![0u8; 512];
        BigEndian::write_u32(&mut sb[0..4], XFS_SB_MAGIC);
        BigEndian::write_u32(&mut sb[4..8], 4096); // blocksize
        BigEndian::write_u32(&mut sb[84..88], 1024); // agblocks
        BigEndian::write_u16(&mut sb[102..104], 512); // sectsize
        BigEndian::write_u16(&mut sb[104..106], 512); // inodesize
        BigEndian::write_u16(&mut sb[106..108], 8); // inopblock
        sb[124] = 200; // agblklog @ 0x7c, absurd
        let ds = seance_core::data_source::ByteSliceDataSource::new(sb);
        let err = parse_xfs_superblock(&ds).expect_err("bad agblklog must error");
        assert!(err.to_string().contains("agblklog"), "unexpected: {err}");
    }

    #[test]
    fn test_synthetic_xfs_root_inode_parsing() {
        let image = build_synthetic_xfs_image();
        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();
        let root = parse_xfs_inode(ds.as_ref(), &sb, 64).unwrap();

        assert!(root.is_dir());
        assert_eq!(root.format, XFS_DINODE_FMT_LOCAL);
        assert_eq!(root.mode, 0o40755);
        assert!(!root.dfork_data.is_empty());
        // Shortform header: count=2
        assert_eq!(root.dfork_data[0], 2);
    }

    #[test]
    fn test_synthetic_xfs_file_inode_parsing() {
        let image = build_synthetic_xfs_image();
        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();
        let hello = parse_xfs_inode(ds.as_ref(), &sb, 65).unwrap();

        assert!(hello.is_file());
        assert_eq!(hello.format, XFS_DINODE_FMT_LOCAL);
        assert_eq!(hello.size, 15); // "Hello from XFS!" = 15 bytes
        assert_eq!(&hello.dfork_data[..15], b"Hello from XFS!");
    }

    #[test]
    fn test_synthetic_xfs_full_traversal() {
        let image = build_synthetic_xfs_image();
        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();

        let mut produced = Vec::new();
        let mut ctx = ParsingContext {
            artifact_id: uuid::Uuid::new_v4(),
            case_id: uuid::Uuid::new_v4(),
            data_source: ds,
            superblock: &sb,
            produced_artifacts: &mut produced,
            dir_entry_count: 0,
            walk_truncated: false,
            named_deleted_inodes: Default::default(),
            depth_capped: false,
        };

        parse_inode(&mut ctx, 64, "/", 0).unwrap();

        // Should have 3 artifacts: / (root dir), /hello.txt, /subdir
        assert_eq!(
            produced.len(),
            3,
            "Expected 3 artifacts, got {}",
            produced.len()
        );

        // Check root
        let root_meta = &produced[0].metadata;
        assert_eq!(root_meta["name"], "/");
        assert_eq!(root_meta["is_directory"], true);

        // Check hello.txt
        let hello_meta = &produced[1].metadata;
        assert_eq!(hello_meta["name"], "hello.txt");
        assert_eq!(hello_meta["path"], "/hello.txt");
        assert_eq!(hello_meta["is_directory"], false);
        assert_eq!(hello_meta["size"], 15);

        // Verify the file's DataSource contains the right content
        let hello_ds = produced[1].data.as_ref().unwrap();
        let mut buf = vec![0u8; 15];
        let n = hello_ds.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 15);
        assert_eq!(&buf, b"Hello from XFS!");

        // Check subdir
        let sub_meta = &produced[2].metadata;
        assert_eq!(sub_meta["name"], "subdir");
        assert_eq!(sub_meta["path"], "/subdir");
        assert_eq!(sub_meta["is_directory"], true);
    }

    #[test]
    fn test_ctime_labeled_changed_not_created() {
        // The inode core parsed here has no creation time; ctime is the inode
        // *change* time and must not be mislabeled "created".
        let image = build_synthetic_xfs_image();
        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();

        let mut produced = Vec::new();
        let mut ctx = ParsingContext {
            artifact_id: uuid::Uuid::new_v4(),
            case_id: uuid::Uuid::new_v4(),
            data_source: ds,
            superblock: &sb,
            produced_artifacts: &mut produced,
            dir_entry_count: 0,
            walk_truncated: false,
            named_deleted_inodes: Default::default(),
            depth_capped: false,
        };
        parse_inode(&mut ctx, 64, "/", 0).unwrap();

        let hello_meta = &produced[1].metadata;
        assert!(
            hello_meta.get("created").is_none(),
            "ctime must not be mislabeled as created"
        );
        assert!(
            hello_meta["changed"].as_str().unwrap().contains("2023"),
            "changed should carry ctime, got {:?}",
            hello_meta.get("changed")
        );
        assert!(hello_meta["modified"].as_str().unwrap().contains("2023"));
    }

    #[test]
    fn test_bigtime_flag_decodes_timestamps_via_pipeline() {
        let mut image = build_synthetic_xfs_image();
        // sb_features_incompat at offset 216; BIGTIME (0x8) alongside the
        // FTYPE (0x1) the base fixture sets — this overwrites the field, so
        // dropping FTYPE here would misalign the fixture's directory entries
        // and test something other than bigtime.
        BigEndian::write_u32(&mut image[216..220], 0x1 | 0x8);

        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();
        assert!(sb.bigtime, "bigtime feature flag must be detected");

        let mut produced = Vec::new();
        let mut ctx = ParsingContext {
            artifact_id: uuid::Uuid::new_v4(),
            case_id: uuid::Uuid::new_v4(),
            data_source: ds,
            superblock: &sb,
            produced_artifacts: &mut produced,
            dir_entry_count: 0,
            walk_truncated: false,
            named_deleted_inodes: Default::default(),
            depth_capped: false,
        };
        parse_inode(&mut ctx, 64, "/", 0).unwrap();

        // build_synthetic_xfs_image() writes 1700000000 into only the high 4
        // bytes of each 8-byte xfs_timestamp_t, leaving the low 4 bytes
        // zero (it was written as a legacy be32 second count). Read as one
        // bigtime u64 that is 1700000000 * 2^32 nanoseconds since the
        // bigtime epoch — nonzero, so a real (if odd-looking) instant, not
        // the unset sentinel.
        let raw: u64 = 1_700_000_000u64 << 32;

        // Compute the expected instant independently: by calendar
        // subtraction from the documented bigtime epoch instant, not via
        // decode_bigtime's own epoch-offset-constant arithmetic.
        let bigtime_epoch = chrono::NaiveDate::from_ymd_opt(1901, 12, 13)
            .unwrap()
            .and_hms_opt(20, 45, 52)
            .unwrap();
        let expected =
            Utc.from_utc_datetime(&(bigtime_epoch + chrono::Duration::nanoseconds(raw as i64)));
        let expected_rfc3339 = expected.to_rfc3339();

        // This same raw value is far beyond what the legacy 32-bit format
        // could ever hold (max ~2106), proving the bigtime path — not the
        // legacy path re-reading the same bytes — produced this date.
        assert!(expected.timestamp() > u32::MAX as i64);

        let hello_meta = &produced[1].metadata;
        assert_eq!(
            hello_meta["changed"], expected_rfc3339,
            "ctime must decode via bigtime, not be omitted"
        );
        assert_eq!(hello_meta["modified"], expected_rfc3339);
        assert_eq!(hello_meta["accessed"], expected_rfc3339);
        // hello.txt's di_crtime bytes are left zero by the fixture: unset,
        // per the bigtime-zero == legacy-zero sentinel convention, so no
        // "created" field — and nothing here should be flagged undecodable.
        assert!(hello_meta.get("created").is_none());
        assert!(hello_meta.get("timestamps_unsupported").is_none());
    }

    #[test]
    fn test_bigtime_zero_is_the_unset_sentinel_not_a_1901_date() {
        // decode_bigtime(0) must not be conflated with a real 1901-12-13
        // timestamp: the kernel comment on xfs_timestamp_t calls raw 0 "the
        // invalid timestamp, in traditional xfs terms", matching the legacy
        // format's own sec==0 "unset" convention.
        match decode_bigtime(0) {
            BigtimeField::Unset => {}
            other => panic!("expected Unset for raw=0, got {other:?} instead"),
        }
    }

    #[test]
    fn test_decode_bigtime_matches_independently_computed_calendar_date() {
        // A date past the legacy 32-bit ceiling (2038, in fact past even
        // 2106) that only the bigtime format can represent at all — this is
        // the pin for the actual decode arithmetic, computed here via
        // chrono calendar subtraction from the documented bigtime epoch
        // instant, never by calling decode_bigtime's own formula.
        let bigtime_epoch = chrono::NaiveDate::from_ymd_opt(1901, 12, 13)
            .unwrap()
            .and_hms_opt(20, 45, 52)
            .unwrap();
        let target = chrono::NaiveDate::from_ymd_opt(2090, 7, 4)
            .unwrap()
            .and_hms_nano_opt(12, 0, 0, 123_456_789)
            .unwrap();
        let raw = target
            .signed_duration_since(bigtime_epoch)
            .num_nanoseconds()
            .expect("189 years of nanoseconds fits in i64") as u64;

        let expected_rfc3339 = Utc.from_utc_datetime(&target).to_rfc3339();

        match decode_bigtime(raw) {
            BigtimeField::Value(s) => assert_eq!(s, expected_rfc3339),
            other => panic!("expected a decoded value, got {other:?}"),
        }
    }

    #[test]
    fn test_bigtime_crtime_decodes_as_created_via_pipeline() {
        let mut image = build_synthetic_xfs_image();
        BigEndian::write_u32(&mut image[216..220], 0x1 | 0x8);

        // hello.txt is inode 65, at root_offset(=8*4096) + 512.
        let hello_offset = 8 * 4096 + 512;
        // di_crtime at inode core offset 0x90 (144). Reuse the same raw
        // value shape as the other timestamps (seconds in the high 32
        // bits) so it is guaranteed nonzero and independent of ctime/mtime.
        BigEndian::write_u32(
            &mut image[hello_offset + 144..hello_offset + 148],
            1_800_000_000,
        );

        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();
        assert!(sb.bigtime);

        let mut produced = Vec::new();
        let mut ctx = ParsingContext {
            artifact_id: uuid::Uuid::new_v4(),
            case_id: uuid::Uuid::new_v4(),
            data_source: ds,
            superblock: &sb,
            produced_artifacts: &mut produced,
            dir_entry_count: 0,
            walk_truncated: false,
            named_deleted_inodes: Default::default(),
            depth_capped: false,
        };
        parse_inode(&mut ctx, 64, "/", 0).unwrap();

        let raw: u64 = 1_800_000_000u64 << 32;
        let bigtime_epoch = chrono::NaiveDate::from_ymd_opt(1901, 12, 13)
            .unwrap()
            .and_hms_opt(20, 45, 52)
            .unwrap();
        let expected =
            Utc.from_utc_datetime(&(bigtime_epoch + chrono::Duration::nanoseconds(raw as i64)));

        let hello_meta = &produced[1].metadata;
        assert_eq!(hello_meta["created"], expected.to_rfc3339());
    }

    /// Pack a (logical, physical, count) triple into the 128-bit on-disk extent.
    fn pack_extent(logical: u64, physical: u64, count: u64) -> [u8; 16] {
        let hi: u64 = (logical << 9) | (physical >> 43);
        let lo: u64 = ((physical & 0x7FF_FFFF_FFFF) << 21) | count;
        let mut data = [0u8; 16];
        BigEndian::write_u64(&mut data[0..8], hi);
        BigEndian::write_u64(&mut data[8..16], lo);
        data
    }

    /// Write a v3 directory data block holding one entry `name -> ino`.
    fn write_dir_data_block(image: &mut [u8], block: usize, name: &[u8], ino: u64) {
        let base = block * 4096;
        BigEndian::write_u32(&mut image[base..base + 4], XFS_DIR3_DATA_MAGIC);
        let pos = base + 64; // v3 data header
        BigEndian::write_u64(&mut image[pos..pos + 8], ino);
        image[pos + 8] = name.len() as u8;
        image[pos + 9..pos + 9 + name.len()].copy_from_slice(name);
        image[pos + 9 + name.len()] = 1; // ftype = regular file
    }

    /// Write a minimal LOCAL-format regular-file inode.
    fn write_file_inode(image: &mut [u8], offset: usize, content: &[u8]) {
        let inode = &mut image[offset..offset + 512];
        BigEndian::write_u16(&mut inode[0..2], 0x494E);
        BigEndian::write_u16(&mut inode[2..4], 0o100644);
        inode[4] = 3;
        inode[5] = XFS_DINODE_FMT_LOCAL;
        BigEndian::write_u32(&mut inode[16..20], 1);
        BigEndian::write_u32(&mut inode[32..36], 1700000000);
        BigEndian::write_u32(&mut inode[40..44], 1700000000);
        BigEndian::write_u32(&mut inode[48..52], 1700000000);
        BigEndian::write_u64(&mut inode[56..64], content.len() as u64);
        inode[176..176 + content.len()].copy_from_slice(content);
    }

    /// Build an image whose root is an extent-format (multi-block) directory
    /// spanning three logical data blocks: block 0 holds "a.txt", block 2 holds
    /// "b.txt", and block 1 is either an unmapped hole or a mapped non-data
    /// block, depending on `hole`.
    fn build_xfs_block_dir_image(hole: bool) -> Vec<u8> {
        let blocksize: u32 = 4096;
        let agblocks: u32 = 64;
        let mut image = vec![0u8; agblocks as usize * blocksize as usize];

        // --- Superblock ---
        BigEndian::write_u32(&mut image[0..4], XFS_SB_MAGIC);
        BigEndian::write_u32(&mut image[4..8], blocksize);
        BigEndian::write_u64(&mut image[8..16], agblocks as u64);
        BigEndian::write_u64(&mut image[56..64], 64); // rootino
        BigEndian::write_u32(&mut image[84..88], agblocks);
        BigEndian::write_u32(&mut image[88..92], 1); // agcount
        BigEndian::write_u16(&mut image[100..102], 5); // version (v5)
        BigEndian::write_u32(&mut image[216..220], 0x1); // INCOMPAT_FTYPE
        BigEndian::write_u16(&mut image[102..104], 512); // sectsize
        BigEndian::write_u16(&mut image[104..106], 512); // inodesize
        BigEndian::write_u16(&mut image[106..108], 8); // inopblock
        image[124] = 6; // agblklog = log2(agblocks)

        // --- Root inode 64 (block 8, offset 0): extent-format directory ---
        let root_offset = 8 * blocksize as usize;
        {
            let root = &mut image[root_offset..root_offset + 512];
            BigEndian::write_u16(&mut root[0..2], 0x494E);
            BigEndian::write_u16(&mut root[2..4], 0o40755);
            root[4] = 3;
            root[5] = XFS_DINODE_FMT_EXTENTS;
            BigEndian::write_u32(&mut root[16..20], 3); // nlink
            BigEndian::write_u32(&mut root[32..36], 1700000000);
            BigEndian::write_u32(&mut root[40..44], 1700000000);
            BigEndian::write_u32(&mut root[48..52], 1700000000);
            BigEndian::write_u64(&mut root[56..64], 3 * blocksize as u64); // di_size
            let exts: Vec<[u8; 16]> = if hole {
                // Logical block 1 is unmapped: a punched-out (freed) data block.
                vec![pack_extent(0, 16, 1), pack_extent(2, 18, 1)]
            } else {
                vec![
                    pack_extent(0, 16, 1),
                    pack_extent(1, 17, 1),
                    pack_extent(2, 18, 1),
                ]
            };
            BigEndian::write_u32(&mut root[76..80], exts.len() as u32); // nextents
            for (i, e) in exts.iter().enumerate() {
                root[176 + i * 16..176 + i * 16 + 16].copy_from_slice(e);
            }
        }

        // --- Child inodes 65 / 66 ---
        write_file_inode(&mut image, root_offset + 512, b"A");
        write_file_inode(&mut image, root_offset + 1024, b"B");

        // --- Directory data blocks ---
        write_dir_data_block(&mut image, 16, b"a.txt", 65);
        write_dir_data_block(&mut image, 18, b"b.txt", 66);
        if !hole {
            // Mapped, but a free-space block rather than directory data.
            BigEndian::write_u32(&mut image[17 * 4096..17 * 4096 + 4], 0x5844_4633);
        }

        image
    }

    fn walk_block_dir_image(image: Vec<u8>) -> Vec<Artifact> {
        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();
        let mut produced = Vec::new();
        let mut ctx = ParsingContext {
            artifact_id: uuid::Uuid::new_v4(),
            case_id: uuid::Uuid::new_v4(),
            data_source: ds,
            superblock: &sb,
            produced_artifacts: &mut produced,
            dir_entry_count: 0,
            walk_truncated: false,
            named_deleted_inodes: Default::default(),
            depth_capped: false,
        };
        parse_inode(&mut ctx, 64, "/", 0).unwrap();
        produced
    }

    /// BUG-213: a non-data block in the middle of a multi-block directory must
    /// not silently end the walk, and the directory must be flagged incomplete.
    #[test]
    fn test_block_dir_mid_stream_bad_block_flags_incomplete_and_continues() {
        let produced = walk_block_dir_image(build_xfs_block_dir_image(false));

        let names: Vec<&str> = produced
            .iter()
            .map(|a| a.metadata["path"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"/a.txt"), "got {:?}", names);
        assert!(
            names.contains(&"/b.txt"),
            "walk must continue past the bad block, got {:?}",
            names
        );
        assert_eq!(
            produced[0].metadata["directory_parse_incomplete"], true,
            "a directory with an unparsable data block must not look complete"
        );
    }

    /// A punched-out (unmapped) directory data block is a real hole: it holds no
    /// entries, the walk continues, and the listing is still complete.
    #[test]
    fn test_block_dir_unmapped_hole_is_not_flagged_incomplete() {
        let produced = walk_block_dir_image(build_xfs_block_dir_image(true));

        let names: Vec<&str> = produced
            .iter()
            .map(|a| a.metadata["path"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"/a.txt"), "got {:?}", names);
        assert!(names.contains(&"/b.txt"), "got {:?}", names);
        assert!(
            produced[0]
                .metadata
                .get("directory_parse_incomplete")
                .is_none(),
            "an unmapped hole is not a parse failure"
        );
    }

    /// HUNT-175: when the directory's extent list is itself short (a cap, or a
    /// B-map walk that failed), an unmapped block cannot be told from a
    /// punched hole — its mapping may simply not have been read — so the
    /// listing must not claim to be whole.
    #[test]
    fn an_unmapped_block_under_a_truncated_extent_list_flags_the_directory() {
        let ds: Arc<dyn DataSource> = Arc::new(seance_core::data_source::ByteSliceDataSource::new(
            build_xfs_block_dir_image(true),
        ));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();
        let mut produced = Vec::new();
        let mut ctx = ParsingContext {
            artifact_id: uuid::Uuid::new_v4(),
            case_id: uuid::Uuid::new_v4(),
            data_source: ds.clone(),
            superblock: &sb,
            produced_artifacts: &mut produced,
            dir_entry_count: 0,
            walk_truncated: false,
            named_deleted_inodes: Default::default(),
            depth_capped: false,
        };
        let mut dir = parse_xfs_inode(ds.as_ref(), &sb, 64).unwrap();
        assert!(
            parse_block_dir(&mut ctx, &dir, "/", 0).unwrap(),
            "a real hole"
        );
        dir.extents_incomplete = Some(IncompleteReason::CapReached);
        assert!(
            !parse_block_dir(&mut ctx, &dir, "/", 0).unwrap(),
            "an unmapped block under a truncated extent list is not known to be a hole"
        );
    }

    /// HUNT-175: an extent-format directory whose extent list came out empty
    /// was never read, and must not publish as an empty directory.
    #[test]
    fn a_directory_with_no_readable_extents_is_flagged() {
        let mut image = build_xfs_block_dir_image(true);
        // Root inode 64 at block 8: zero its extent count.
        let root = 8 * 4096;
        BigEndian::write_u32(&mut image[root + 76..root + 80], 0);
        let produced = walk_block_dir_image(image);
        assert_eq!(produced.len(), 1, "no children were read");
        assert_eq!(produced[0].metadata["directory_parse_incomplete"], true);
        assert!(produced[0].metadata["directory_parse_error"]
            .as_str()
            .unwrap()
            .contains("extent list is empty"));
    }

    /// HUNT-175: a live name whose inode will not read is a listing that is
    /// short by one, and the directory says so instead of dropping the name.
    #[test]
    fn a_block_directory_entry_whose_inode_will_not_read_flags_the_directory() {
        let mut image = build_xfs_block_dir_image(true);
        // Child inode 66 sits in the root's block, third slot.
        let off = 8 * 4096 + 1024;
        assert_eq!(&image[off..off + 2], b"IN");
        image[off..off + 2].copy_from_slice(b"\0\0");
        let produced = walk_block_dir_image(image);
        assert_eq!(
            produced[0].metadata["directory_parse_incomplete"], true,
            "{}",
            produced[0].metadata
        );
    }

    // ------------------------------------------------------------------
    // B2-034 / B2-005 / B2-099
    // ------------------------------------------------------------------

    /// B2-034: `di_forkoff` bounds the data fork. When an inode carries extended
    /// attributes the attribute fork sits immediately after the data fork inside
    /// the same inode, and reading to the end of the inode hands those attribute
    /// bytes to the shortform-directory parser as if they were entries — a
    /// directory gains children that never existed.
    #[test]
    fn a_shortform_directory_stops_at_the_attribute_fork() {
        let mut image = build_synthetic_xfs_image();
        let root_offset = 8 * 4096;

        // The root's shortform directory occupies 6 + 17 + 14 = 37 bytes from
        // the data fork start. di_forkoff is in 8-byte units: 5 * 8 = 40 bytes
        // covers it, so the attribute fork begins at data-fork byte 40.
        image[root_offset + 82] = 5;

        // Plant a third, forged entry straddling the fork boundary: its name and
        // inode number live in attribute-fork bytes. Without the di_forkoff
        // bound the parser walks straight into it.
        let dfork = root_offset + 176;
        let forged = dfork + 37; // immediately after the two real entries
        image[forged] = 5; // namelen
        BigEndian::write_u16(&mut image[forged + 1..forged + 3], 3); // offset tag
        image[forged + 3..forged + 8].copy_from_slice(b"ghost");
        image[forged + 8] = 1; // ftype
        BigEndian::write_u32(&mut image[forged + 9..forged + 13], 65); // inode

        // The forged entry needs the on-disk entry count to reach it.
        image[dfork] = 3;

        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();

        let mut produced = Vec::new();
        let mut ctx = ParsingContext {
            artifact_id: uuid::Uuid::new_v4(),
            case_id: uuid::Uuid::new_v4(),
            data_source: ds,
            superblock: &sb,
            produced_artifacts: &mut produced,
            dir_entry_count: 0,
            walk_truncated: false,
            named_deleted_inodes: Default::default(),
            depth_capped: false,
        };
        parse_inode(&mut ctx, 64, "/", 0).unwrap();

        let paths: Vec<&str> = produced
            .iter()
            .map(|a| a.metadata["path"].as_str().unwrap())
            .collect();
        assert!(
            !paths.contains(&"/ghost"),
            "attribute-fork bytes must not become directory entries, got {paths:?}"
        );
        assert!(paths.contains(&"/hello.txt"), "got {paths:?}");
        assert!(paths.contains(&"/subdir"), "got {paths:?}");
    }

    /// The success path of the bound above: an inode with no attribute fork
    /// (`di_forkoff == 0`) still uses the whole inode for its data fork.
    #[test]
    fn an_inode_without_an_attribute_fork_uses_the_whole_inode() {
        let image = build_synthetic_xfs_image();
        assert_eq!(image[8 * 4096 + 82], 0, "the fixture has no attribute fork");

        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();
        let root = parse_xfs_inode(ds.as_ref(), &sb, 64).unwrap();
        assert_eq!(
            root.dfork_data.len(),
            sb.inodesize as usize - sb.dinode_core_size(),
            "with di_forkoff == 0 the data fork runs to the end of the inode"
        );
    }

    /// B2-005: on a v4 volume the 1-byte directory file type is opt-in via
    /// `XFS_SB_VERSION2_FTYPE`. Assuming it is absent shifts the inode number one
    /// byte early in every shortform entry, so children resolve to garbage.
    #[test]
    fn a_v4_volume_with_the_ftype_feature_is_detected() {
        let mut image = build_synthetic_xfs_image();
        // v4 version number with MOREBITS set, and FTYPE in sb_features2.
        BigEndian::write_u16(&mut image[100..102], 0x8004);
        BigEndian::write_u32(&mut image[200..204], 0x0000_0200);

        let sb = parse_xfs_superblock(&seance_core::data_source::ByteSliceDataSource::new(
            image.clone(),
        ))
        .unwrap();
        assert!(!sb.v5, "this is a v4 volume");
        assert!(sb.ftype, "sb_features2 FTYPE must be honoured on v4");

        // The same volume without the feature bit must NOT assume a type byte.
        BigEndian::write_u32(&mut image[200..204], 0);
        let plain =
            parse_xfs_superblock(&seance_core::data_source::ByteSliceDataSource::new(image))
                .unwrap();
        assert!(!plain.ftype);
    }

    /// The alignment-bug copy of the feature word counts too: some volumes carry
    /// the flags only in `sb_bad_features2`, and the kernel ORs the two.
    #[test]
    fn a_v4_volume_with_ftype_only_in_bad_features2_is_detected() {
        let mut image = build_synthetic_xfs_image();
        BigEndian::write_u16(&mut image[100..102], 0x8004);
        BigEndian::write_u32(&mut image[204..208], 0x0000_0200); // sb_bad_features2

        let sb = parse_xfs_superblock(&seance_core::data_source::ByteSliceDataSource::new(image))
            .unwrap();
        assert!(sb.ftype);
    }

    /// A v5 volume is not automatically an ftype volume. mkfs.xfs sets the bit
    /// for everything it writes, so `v5 => ftype` holds for most images in the
    /// wild and hid this — but the kernel reads the bit, and a v5 volume
    /// without it has directory entries one byte shorter per name. Inferring
    /// ftype from the version misaligns every entry on such a volume.
    #[test]
    fn a_v5_volume_without_the_incompat_ftype_bit_has_no_ftype() {
        let mut image = build_synthetic_xfs_image();
        // Clear XFS_SB_FEAT_INCOMPAT_FTYPE, leaving the volume v5.
        BigEndian::write_u32(&mut image[216..220], 0x0);

        let sb = parse_xfs_superblock(&seance_core::data_source::ByteSliceDataSource::new(image))
            .unwrap();
        assert!(sb.v5, "fixture should still be a v5 volume");
        assert!(
            !sb.ftype,
            "ftype must come from sb_features_incompat, not from the version"
        );
    }

    /// B2-099: once the global directory-entry budget is spent, `parse_inode`
    /// returns immediately and whole subtrees are never visited. That has to be
    /// recorded, or the missing files read as files that were never on the
    /// volume.
    #[test]
    fn exhausting_the_directory_entry_budget_is_recorded_on_the_walk() {
        let image = build_synthetic_xfs_image();
        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let sb = parse_xfs_superblock(ds.as_ref()).unwrap();

        let mut produced = Vec::new();
        let mut ctx = ParsingContext {
            artifact_id: uuid::Uuid::new_v4(),
            case_id: uuid::Uuid::new_v4(),
            data_source: ds,
            superblock: &sb,
            produced_artifacts: &mut produced,
            // The budget is already spent before the walk begins.
            dir_entry_count: MAX_DIR_ENTRIES + 1,
            walk_truncated: false,
            named_deleted_inodes: Default::default(),
            depth_capped: false,
        };
        parse_inode(&mut ctx, 64, "/", 0).unwrap();

        assert!(
            ctx.walk_truncated,
            "a walk stopped by the entry budget must not look like a finished one"
        );
        assert!(produced.is_empty());
    }

    /// B2-139: a shortform directory whose entries run past the end of the
    /// data fork drops the rest of the list. Before this the drop was a
    /// `debug!` line, so the short listing was published as the directory's
    /// full contents and "not listed" read as "not present on the volume".
    #[test]
    fn a_truncated_shortform_directory_is_flagged_incomplete() {
        let mut image = build_synthetic_xfs_image();
        let ds_probe = seance_core::data_source::ByteSliceDataSource::new(image.clone());
        let sb = parse_xfs_superblock(&ds_probe).unwrap();

        // di_forkoff (+0x52) is the data fork's size in 8-byte units. Set it so
        // the fork ends part-way through the second declared entry: the header
        // still says two, but only one can be read.
        let root_offset = 8 * sb.blocksize as usize;
        image[root_offset + 82] = 4; // data fork = 32 bytes, entry 2 needs 37
        let ds: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(ds),
            json!({ "subtype": "xfs" }),
        );

        let produced = XfsParser.process(&artifact).unwrap();
        let root = produced
            .iter()
            .find(|a| a.metadata["path"] == "/")
            .expect("root directory artifact");
        assert_eq!(
            root.metadata["directory_parse_incomplete"],
            json!(true),
            "a shortform listing that ran out of fork must say so"
        );
    }

    /// B2-140: an inode whose extent list is short still gets an
    /// `XfsFileSource` sized to the full logical size. Consumers that read only
    /// the standard `content_incomplete` flag saw a whole file.
    #[test]
    fn an_incomplete_extent_list_sets_the_standard_incomplete_flag() {
        let mut image = build_synthetic_xfs_image();
        let ds_probe = seance_core::data_source::ByteSliceDataSource::new(image.clone());
        let sb = parse_xfs_superblock(&ds_probe).unwrap();

        // Rewrite hello.txt as an extent-format file claiming more extents than
        // the cap allows, so its extent list is knowingly a prefix.
        let hello_offset = 8 * sb.blocksize as usize + sb.inodesize as usize;
        image[hello_offset + 5] = XFS_DINODE_FMT_EXTENTS;
        BigEndian::write_u64(&mut image[hello_offset + 56..hello_offset + 64], 1 << 30);
        BigEndian::write_u32(
            &mut image[hello_offset + 76..hello_offset + 80],
            (MAX_EXTENTS as u32) + 1,
        );
        fill_fork_with_valid_extents(&mut image, hello_offset, sb.inodesize as usize);

        let ds: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(ds),
            json!({ "subtype": "xfs" }),
        );

        let produced = XfsParser.process(&artifact).unwrap();
        let hello = produced
            .iter()
            .find(|a| a.metadata["name"] == "hello.txt")
            .expect("hello.txt artifact");
        assert_eq!(hello.metadata["data_runs_complete"], json!(false));
        assert_eq!(hello.metadata["extents_incomplete"], json!("cap_reached"));
        assert_eq!(hello.metadata["content_incomplete"], json!(true));
        assert_eq!(
            hello.metadata["content_incomplete_reason"],
            json!("cap_reached")
        );
    }

    /// The success path: a volume walked to its end leaves the filesystem
    /// artifact unflagged, so the flag keeps its meaning.
    #[test]
    fn a_fully_walked_volume_leaves_the_filesystem_artifact_unflagged() {
        let image = build_synthetic_xfs_image();
        let ds: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(ds),
            json!({ "subtype": "xfs" }),
        );

        let produced = XfsParser.process(&artifact).unwrap();
        assert_eq!(produced[0].metadata["filesystem_type"], "XFS");
        assert!(
            produced[0]
                .metadata
                .get("directory_parse_incomplete")
                .is_none(),
            "a three-entry volume is nowhere near the budget"
        );
    }
}

#[cfg(test)]
mod arithmetic_and_empty_stream_tests {
    use super::*;

    /// An extent whose start block is near u64::MAX must not wrap into a low
    /// device offset. A wrapped offset points at unrelated image bytes, which
    /// are then hashed, exported and previewed as this file's content
    /// (B7-002).
    #[test]
    fn a_hostile_extent_offset_saturates_instead_of_wrapping() {
        let extents = vec![XfsExtent {
            logical: 0,
            // agblklog 20 with a huge agno: agno*agblocks alone saturates, and
            // the *blocksize multiply then has to saturate too.
            physical: u64::MAX / 2,
            count: 1,
            unwritten: false,
        }];
        let inner = Arc::new(seance_core::data_source::ByteSliceDataSource::new(vec![
            0xAAu8;
            8192
        ]));
        let source = XfsFileSource::new(inner, 4096, 1 << 20, 20, 4096, extents, true);

        let resolved = source
            .resolve_logical_offset(0)
            .expect("a written extent resolves");
        assert_eq!(
            resolved,
            u64::MAX,
            "a device offset that cannot be represented must saturate past the \
             end of the image, never wrap back into valid bytes"
        );

        // And the read that follows returns nothing rather than the wrong bytes.
        let mut buf = vec![0u8; 16];
        let n = source.read_at(0, &mut buf).unwrap();
        assert_eq!(
            n, 0,
            "a saturated offset reads past the device, not into it"
        );
    }

    /// Rewrite hello.txt in the synthetic image with a given inode format,
    /// logical size and extent count, then run the parser over it.
    fn parse_with_rewritten_hello(format: u8, size: u64, nextents: u32) -> Vec<Artifact> {
        let mut image = tests::build_synthetic_xfs_image();
        let ds_probe = seance_core::data_source::ByteSliceDataSource::new(image.clone());
        let sb = parse_xfs_superblock(&ds_probe).unwrap();
        let hello_offset = 8 * sb.blocksize as usize + sb.inodesize as usize;

        image[hello_offset + 5] = format;
        BigEndian::write_u64(&mut image[hello_offset + 56..hello_offset + 64], size);
        BigEndian::write_u32(&mut image[hello_offset + 76..hello_offset + 80], nextents);

        let ds: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(ds),
            json!({ "subtype": "xfs" }),
        );
        XfsParser.process(&artifact).unwrap()
    }

    /// A fully sparse regular file — non-zero size, no extents — is real
    /// content the kernel serves as zeros. It used to get no data source and no
    /// runs at all, so it was indistinguishable from a file whose stream we
    /// could not recover (B7-003).
    #[test]
    fn a_fully_sparse_file_serves_zeros_to_its_logical_size() {
        let produced = parse_with_rewritten_hello(XFS_DINODE_FMT_EXTENTS, 3 * 4096, 0);
        let file = produced
            .iter()
            .find(|a| a.metadata["path"] == "/hello.txt")
            .expect("hello.txt artifact");

        assert_eq!(
            file.metadata["data_runs"],
            json!([[serde_json::Value::Null, 3 * 4096u64]]),
            "a sparse file must persist its hole, not an empty run list"
        );
        assert_eq!(file.metadata["data_runs_complete"], json!(true));
        assert!(
            file.metadata.get("content_incomplete").is_none(),
            "a genuinely sparse file is complete, not incomplete"
        );

        let source = file.data.as_ref().expect("a sparse file still has content");
        let mut buf = vec![0xAAu8; 3 * 4096];
        assert_eq!(source.read_at(0, &mut buf).unwrap(), 3 * 4096);
        assert!(buf.iter().all(|&b| b == 0));
    }

    /// A sized regular file in an inode format this parser cannot decode has no
    /// recoverable stream. Publishing it with no content and no flag reads to
    /// an examiner as "this file was empty" (B7-003).
    #[test]
    fn a_sized_file_in_an_undecodable_format_is_flagged_incomplete() {
        // 7 is not LOCAL/EXTENTS/BTREE.
        let produced = parse_with_rewritten_hello(7, 4096, 0);
        let file = produced
            .iter()
            .find(|a| a.metadata["path"] == "/hello.txt")
            .expect("hello.txt artifact");

        assert_eq!(file.metadata["content_incomplete"], json!(true));
        assert_eq!(
            file.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert!(
            file.data.is_none(),
            "content we could not locate must not be served as zeros"
        );
    }

    /// An inline (LOCAL) file whose declared size exceeds what its data fork
    /// actually holds is short, not complete: the served prefix used to carry
    /// the full size with no flag at all (B7-003).
    #[test]
    fn an_inline_file_larger_than_its_fork_is_flagged_short() {
        // The synthetic hello.txt fork holds a few hundred bytes at most.
        let produced = parse_with_rewritten_hello(XFS_DINODE_FMT_LOCAL, 64 * 1024, 0);
        let file = produced
            .iter()
            .find(|a| a.metadata["path"] == "/hello.txt")
            .expect("hello.txt artifact");

        assert_eq!(file.metadata["content_incomplete"], json!(true));
        assert_eq!(
            file.metadata["content_incomplete_reason"],
            json!("short_read")
        );
    }
}
