#![forbid(unsafe_code)]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
// APFS Filesystem Parser
//
// Implements APFS container/volume parsing, object map resolution, B-tree traversal,
// and filesystem walking to produce FileEntry artifacts from APFS volumes.
//
// APFS (Apple File System) is the default filesystem on all modern Apple devices
// since 2017. This parser handles the two-level hierarchy:
//   Container (NXSB) -> Object Map -> Volume(s) (APSB) -> Volume OMap -> FS B-tree
//
// References:
// - Apple APFS Reference: https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
// - libapfs: https://github.com/libyal/libfsapfs

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use byteorder::{ByteOrder, LittleEndian};
use chrono::DateTime;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::{read_exact_or_fail, read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::Arc;
use tracing::{debug, info, warn};

mod decmpfs;
mod lzvn;

// --- Constants ---

const NXSB_MAGIC: u32 = 0x4253584E; // "NXSB" little-endian
const APSB_MAGIC: u32 = 0x42535041; // "APSB" little-endian

// Object types (lower 16 bits of o_type). The container superblock is the only
// object whose type the reader checks; the rest of the table is kept so it
// reads as the Apple File System Reference does.
const OBJ_TYPE_NX_SUPERBLOCK: u16 = 0x0001;
#[allow(dead_code)]
const OBJ_TYPE_BTREE: u16 = 0x0002;
#[allow(dead_code)]
const OBJ_TYPE_BTREE_NODE: u16 = 0x0003;
#[allow(dead_code)]
const OBJ_TYPE_OMAP: u16 = 0x0005;
#[allow(dead_code)]
const OBJ_TYPE_FS: u16 = 0x000D;

// Object type flags (upper 16 bits of o_type). Same rule as the table above.
#[allow(dead_code)]
const OBJ_VIRTUAL: u32 = 0x0000_0000;
#[allow(dead_code)]
const OBJ_EPHEMERAL: u32 = 0x8000_0000;
#[allow(dead_code)]
const OBJ_PHYSICAL: u32 = 0x4000_0000;

// B-tree node flags
const BTNODE_ROOT: u16 = 0x0001;
const BTNODE_LEAF: u16 = 0x0002;
const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;
/// The node's index values carry a child hash after the child reference, and the
/// reference is relative to the tree's root oid rather than absolute. Set on the
/// file-system tree of a **sealed** volume, which is every macOS 11+ system
/// volume (LIVE-011).
const BTNODE_HASHED: u16 = 0x0008;
/// The node carries no `obj_phys_t`; the 32 bytes where it would sit are zeroed.
/// Recorded for completeness — the existing reader already takes its fields from
/// offset 32 onwards, so a zeroed header parses without special handling.
#[allow(dead_code)]
const BTNODE_NOHEADER: u16 = 0x0010;

// Object-map value flags (omap_val_t.ov_flags)
const OMAP_VAL_DELETED: u32 = 0x0000_0001;

// FS tree record types (upper 4 bits of j_key_t.obj_id_and_type)
const APFS_TYPE_INODE: u8 = 3;
const APFS_TYPE_XATTR: u8 = 4;
const APFS_TYPE_FILE_EXTENT: u8 = 8;
const APFS_TYPE_DIR_REC: u8 = 9;

// Directory entry types (lower 16 bits of j_drec_val_t.flags). Only DT_DIR
// is branched on; the rest of the table is kept whole for the reader.
#[allow(dead_code)]
const DT_UNKNOWN: u16 = 0;
#[allow(dead_code)]
const DT_FIFO: u16 = 1;
#[allow(dead_code)]
const DT_CHR: u16 = 2;
const DT_DIR: u16 = 4;
#[allow(dead_code)]
const DT_BLK: u16 = 6;
#[allow(dead_code)]
const DT_REG: u16 = 8;
#[allow(dead_code)]
const DT_LNK: u16 = 10;
#[allow(dead_code)]
const DT_SOCK: u16 = 12;
#[allow(dead_code)]
const DT_WHT: u16 = 14;

// Extended-attribute record flags (j_xattr_val_t.flags)
const XATTR_DATA_STREAM: u16 = 0x0001;
const XATTR_DATA_EMBEDDED: u16 = 0x0002;

// The two extended attributes that decide whether a sized file with no
// data-stream extents is decmpfs-compressed rather than unreadable (BUG-156).
const XATTR_NAME_DECMPFS: &str = "com.apple.decmpfs";
const XATTR_NAME_RESOURCE_FORK: &str = "com.apple.ResourceFork";

/// `crypto_id` values that mean "these bytes are not encrypted under a
/// per-extent key".
///
/// Zero is what every extent carries on an unencrypted volume — verified
/// against three real APFS volumes (a `ditto --hfsCompression` volume, the
/// inner volume of an AES-256 disk image, and `test_data/apfs.dmg`), every
/// extent of which reads `crypto_id == 0`. `APFS_UNASSIGNED_CRYPTO_ID` is
/// Apple's reserved "no key assigned" sentinel. Treating either as ciphertext
/// would flag every file on every normal volume, which is why BUG-157 was held
/// until a negative control existed.
const CRYPTO_ID_NONE: u64 = 0;
const APFS_UNASSIGNED_CRYPTO_ID: u64 = u64::MAX;

// Well-known inode numbers
const APFS_ROOT_DIR_INO: u64 = 2;

// Safety limits
const MAX_BTREE_DEPTH: usize = 16;
const MAX_DIR_ENTRIES: usize = 500_000;
const MAX_EXTENTS: usize = 100_000;
const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4 GB for DataSource
const MAX_VOLUMES: usize = 100;
const MAX_INODES: usize = 1_000_000;
/// Ceiling on the compressed bytes this parser will pull into memory to decode
/// a decmpfs file's resource fork.
const MAX_DECMPFS_COMPRESSED: u64 = 64 * 1024 * 1024;
/// Ceiling on a decmpfs file's decoded size. Decoding produces the whole file
/// in memory, so a file above this is reported as undecoded rather than
/// allowed to exhaust the host.
const MAX_DECMPFS_DECODED: u64 = 64 * 1024 * 1024;

// Object header size
const OBJ_PHYS_SIZE: usize = 32;

// --- Data Structures ---

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ObjPhys {
    cksum: u64,
    oid: u64,
    xid: u64,
    o_type: u32,
    o_subtype: u32,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug)]
struct NxSuperblock {
    obj: ObjPhys,
    magic: u32,
    block_size: u32,
    block_count: u64,
    omap_oid: u64,
    fs_oid: Vec<u64>,
    max_file_systems: u32,
    /// Volume OID slots the container declares that this parser refused to read:
    /// `nx_max_file_systems` beyond [`MAX_VOLUMES`], or slots the superblock
    /// block is too small to hold. Those volumes are never walked, so without
    /// this the container's volume list is a prefix presented as the whole
    /// container (B3-019).
    fs_oid_slots_skipped: u32,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug)]
struct ApfsSuperblock {
    obj: ObjPhys,
    magic: u32,
    omap_oid: u64,
    root_tree_oid: u64,
    num_files: u64,
    num_directories: u64,
    vol_uuid: [u8; 16],
    vol_name: String,
    incompatible_features: u64,
    fs_flags: u64,
}

/// Read a little-endian u64 at `off`, returning 0 if the buffer is too short.
fn read_u64_at(buf: &[u8], off: usize) -> u64 {
    if buf.len() >= off + 8 {
        LittleEndian::read_u64(&buf[off..off + 8])
    } else {
        0
    }
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug)]
struct OmapPhys {
    obj: ObjPhys,
    flags: u32,
    tree_oid: u64,
    /// `om_snap_count`: how many snapshots this object map carries. This parser
    /// resolves only the live tree, so a non-zero count means content that
    /// exists ONLY in a snapshot is absent from the case (B7-006).
    snap_count: u32,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug)]
struct BTreeNodePhys {
    obj: ObjPhys,
    flags: u16,
    level: u16,
    nkeys: u32,
    table_space_off: u16,
    table_space_len: u16,
    free_space_off: u16,
    free_space_len: u16,
    key_free_list_off: u16,
    key_free_list_len: u16,
    val_free_list_off: u16,
    val_free_list_len: u16,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct JInodeVal {
    parent_id: u64,
    private_id: u64,
    create_time: i64,
    mod_time: i64,
    change_time: i64,
    access_time: i64,
    internal_flags: u64,
    nchildren_or_nlink: i32,
    owner: u32,
    group: u32,
    mode: u16,
    uncompressed_size: u64,
    /// Logical size from the DSTREAM extended field (the real file size for
    /// regular files); None when the inode has no data stream.
    dstream_size: Option<u64>,
}

// `date_added` is the instant the entry was added to its directory, a fifth
// timestamp the inode itself does not carry. It is published on the FileEntry
// as `date_added` alongside `created`/`modified`/`changed`/`accessed`.
#[derive(Debug, Clone)]
struct JDrecVal {
    file_id: u64,
    date_added: u64,
    flags: u16,
}

#[derive(Debug, Clone)]
struct JFileExtentVal {
    logical_offset: u64,
    len_and_flags: u64,
    phys_block_num: u64,
    crypto_id: u64,
}

#[derive(Debug, Clone)]
struct ApfsExtent {
    logical_offset: u64,
    length: u64,
    phys_block_num: u64,
    /// `j_file_extent_val_t.crypto_id`: the per-extent encryption key or tweak.
    /// Kept rather than discarded because it is the only record that the blocks
    /// this extent points at are ciphertext (BUG-157).
    crypto_id: u64,
}

impl ApfsExtent {
    /// True when this extent's blocks are encrypted under a per-extent key.
    ///
    /// See [`CRYPTO_ID_NONE`] for why exactly two values mean "clear". Anything
    /// else names a crypto-state object, so the bytes at `phys_block_num` are
    /// ciphertext and must never be exported or hashed as though they were the
    /// file's plaintext.
    fn is_encrypted(&self) -> bool {
        !matches!(self.crypto_id, CRYPTO_ID_NONE | APFS_UNASSIGNED_CRYPTO_ID)
    }

    /// True when the extent records a SPARSE range rather than storage.
    ///
    /// APFS writes `phys_block_num == 0` for a hole inside a file: block 0 of the
    /// container holds the container superblock, so it can never legitimately
    /// back file data. Reading it would serve container structures as the file's
    /// bytes — an examiner would see plausible-looking binary data (and hash it)
    /// where the file actually reads as zeros (B2-001).
    fn is_sparse(&self) -> bool {
        self.phys_block_num == 0
    }

    /// Byte offset in the container of `offset_in_extent` bytes into this extent.
    ///
    /// Returns `None` when the arithmetic overflows: extent fields come straight
    /// off the image, and a wrapped offset would silently read unrelated bytes
    /// near the start of the container and serve them as file content.
    fn phys_offset(&self, block_size: u32, offset_in_extent: u64) -> Option<u64> {
        self.phys_block_num
            .checked_mul(block_size as u64)?
            .checked_add(offset_in_extent)
    }
}

// --- ApfsFileSource (DataSource for file content) ---

struct ApfsFileSource {
    inner: Arc<dyn DataSource>,
    block_size: u32,
    size: u64,
    extents: Vec<ApfsExtent>,
    /// True when `extents` is the file's COMPLETE extent list. When false the
    /// MAX_EXTENTS cap dropped records, so everything past the last known extent
    /// is unknown rather than a sparse hole (BUG-212 / B2-031).
    extents_complete: bool,
    /// One past the highest logical byte any known extent covers.
    mapped_end: u64,
}

impl ApfsFileSource {
    fn new(
        inner: Arc<dyn DataSource>,
        block_size: u32,
        size: u64,
        extents: Vec<ApfsExtent>,
        extents_complete: bool,
    ) -> Self {
        let mapped_end = extents
            .iter()
            .map(|e| e.logical_offset.saturating_add(e.length))
            .max()
            .unwrap_or(0);
        Self {
            inner,
            block_size,
            size,
            extents,
            extents_complete,
            mapped_end,
        }
    }

    /// Locate `file_offset` in the extent list: `Ok(index)` of the extent that
    /// covers it, or `Err(next_start)` — the logical offset where the next known
    /// extent begins (`u64::MAX` when none does).
    fn locate(&self, file_offset: u64) -> Result<usize, u64> {
        match self
            .extents
            .binary_search_by_key(&file_offset, |e| e.logical_offset)
        {
            Ok(idx) => Ok(idx),
            Err(idx) => {
                if idx > 0 {
                    let prev = &self.extents[idx - 1];
                    if file_offset < prev.logical_offset.saturating_add(prev.length) {
                        return Ok(idx - 1);
                    }
                }
                Err(self
                    .extents
                    .get(idx)
                    .map(|e| e.logical_offset)
                    .unwrap_or(u64::MAX))
            }
        }
    }
}

impl std::fmt::Debug for ApfsFileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApfsFileSource")
            .field("size", &self.size)
            .field("extents", &self.extents.len())
            .finish()
    }
}

impl DataSource for ApfsFileSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }

        let to_read = std::cmp::min(buf.len() as u64, self.size - offset) as usize;
        let mut bytes_read = 0;

        while bytes_read < to_read {
            let file_offset = offset + bytes_read as u64;

            match self.locate(file_offset) {
                Ok(idx) => {
                    let ext = &self.extents[idx];
                    let ext_end = ext.logical_offset.saturating_add(ext.length);
                    let offset_in_extent = file_offset - ext.logical_offset;
                    let available = (ext_end - file_offset) as usize;
                    let chunk = std::cmp::min(to_read - bytes_read, available);
                    if chunk == 0 {
                        // A zero-length extent covers nothing; stop rather than
                        // spin on it (the length comes off the image).
                        break;
                    }

                    // The last line of defence for BUG-157: whatever built this
                    // source, an encrypted extent's blocks are ciphertext and
                    // are never served as the file's bytes. Returning them
                    // would have them hashed, indexed and exported as
                    // plaintext, and nothing downstream could tell.
                    if ext.is_encrypted() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "APFS extent at logical offset {} is encrypted (crypto_id {}); \
                                 refusing to serve ciphertext as file content",
                                ext.logical_offset, ext.crypto_id
                            ),
                        ));
                    }

                    // An extent at physical block 0 is a hole APFS recorded
                    // explicitly: it reads as zeros, NOT as the container's first
                    // block (B2-001).
                    if ext.is_sparse() {
                        buf[bytes_read..bytes_read + chunk].fill(0);
                        bytes_read += chunk;
                        continue;
                    }

                    let phys_offset = ext
                        .phys_offset(self.block_size, offset_in_extent)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "APFS extent physical offset overflow: block {} * block_size {}",
                                    ext.phys_block_num, self.block_size
                                ),
                            )
                        })?;

                    let n = self
                        .inner
                        .read_at(phys_offset, &mut buf[bytes_read..bytes_read + chunk])?;
                    if n == 0 {
                        return Ok(bytes_read);
                    }
                    bytes_read += n;
                }
                Err(next_start) => {
                    // No extent covers this offset. Inside a complete extent list
                    // that is a genuine hole and reads as zeros. Past the last
                    // known extent of a TRUNCATED list it is unknown data, so
                    // short-read rather than fabricate zeros the caller would
                    // hash and export as content (B2-031).
                    if !self.extents_complete && file_offset >= self.mapped_end {
                        break;
                    }
                    let gap = next_start.saturating_sub(file_offset);
                    let chunk = std::cmp::min((to_read - bytes_read) as u64, gap) as usize;
                    if chunk == 0 {
                        break;
                    }
                    buf[bytes_read..bytes_read + chunk].fill(0);
                    bytes_read += chunk;
                }
            }
        }

        Ok(bytes_read)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

// --- Module Implementation ---

pub struct ApfsParser;

impl ForensicsModule for ApfsParser {
    fn id(&self) -> &str {
        "plugin.filesystem.apfs"
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

        if subtype != Some("apfs") {
            return Ok(Vec::new());
        }

        info!(
            "APFS parser processing filesystem artifact ID: {}",
            artifact.id
        );

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("APFS parser requires a data source".to_string())
        })?;

        // Parse container superblock at block 0
        let nx_sb = parse_nx_superblock(data_source.as_ref())?;
        debug!(
            "APFS Container: block_size={}, block_count={}, volumes={}",
            nx_sb.block_size,
            nx_sb.block_count,
            nx_sb.fs_oid.len()
        );

        let mut produced_artifacts = Vec::new();

        // Read container object map
        let container_omap = parse_omap(data_source.as_ref(), nx_sb.omap_oid, nx_sb.block_size)?;
        debug!(
            "Container OMap tree at physical block {}",
            container_omap.tree_oid
        );

        // Volumes the container names but this parse never reached: the OID did
        // not resolve through the container omap, or its superblock would not
        // parse. Each is a whole filesystem missing from the output, so the
        // count has to reach the examiner, not just a `debug!` line (B3-019).
        let mut volumes_unreadable: usize = 0;
        let mut first_unreadable_error: Option<String> = None;

        // Process each volume
        for (vol_idx, &vol_oid) in nx_sb.fs_oid.iter().enumerate() {
            if vol_oid == 0 {
                continue;
            }
            if vol_idx >= MAX_VOLUMES {
                warn!("Exceeded maximum volume count ({}), stopping", MAX_VOLUMES);
                break;
            }

            // Resolve volume OID via container omap
            let vol_paddr = match omap_lookup(
                data_source.as_ref(),
                container_omap.tree_oid,
                vol_oid,
                nx_sb.block_size,
                true, // container omap is physical
            ) {
                Ok(Some(paddr)) => paddr,
                Ok(None) => {
                    debug!("Volume OID {} not found in container omap", vol_oid);
                    volumes_unreadable += 1;
                    first_unreadable_error.get_or_insert(format!(
                        "volume OID {vol_oid} is not present in the container object map"
                    ));
                    continue;
                }
                Err(e) => {
                    debug!("Failed to resolve volume OID {}: {}", vol_oid, e);
                    volumes_unreadable += 1;
                    first_unreadable_error
                        .get_or_insert(format!("volume OID {vol_oid} did not resolve: {e}"));
                    continue;
                }
            };

            // Parse volume superblock
            let vol_sb = match parse_volume(data_source.as_ref(), vol_paddr, nx_sb.block_size) {
                Ok(sb) => sb,
                Err(e) => {
                    debug!(
                        "Failed to parse volume {} at block {}: {}",
                        vol_idx, vol_paddr, e
                    );
                    volumes_unreadable += 1;
                    first_unreadable_error.get_or_insert(format!(
                        "volume {vol_idx} superblock at block {vol_paddr} did not parse: {e}"
                    ));
                    continue;
                }
            };

            // Encrypted when APFS_FS_UNENCRYPTED (bit 0 of apfs_fs_flags) is
            // CLEAR. Do NOT use incompatible_features bit 0 (that is
            // APFS_INCOMPAT_CASE_INSENSITIVE, the macOS default).
            let encrypted = (vol_sb.fs_flags & 0x1) == 0;
            if encrypted {
                warn!(
                    "APFS volume '{}' is encrypted (FileVault), skipping filesystem walk",
                    vol_sb.vol_name
                );
                // Still emit volume metadata
                produced_artifacts.push(
                    Artifact::new(
                        artifact.case_id,
                        ArtifactType::FileSystem,
                        Some(Arc::clone(data_source)),
                        json!({
                            "filesystem_type": "APFS",
                            "volume_name": vol_sb.vol_name,
                            "volume_uuid": format_uuid(&vol_sb.vol_uuid),
                            "volume_index": vol_idx,
                            "num_files": vol_sb.num_files,
                            "num_directories": vol_sb.num_directories,
                            "block_size": nx_sb.block_size,
                            "encrypted": true,
                        }),
                    )
                    .with_parent(artifact.id),
                );
                continue;
            }

            info!(
                "APFS Volume '{}': {} files, {} directories",
                vol_sb.vol_name, vol_sb.num_files, vol_sb.num_directories
            );

            // Emit volume metadata artifact
            let volume_artifact_idx = produced_artifacts.len();
            produced_artifacts.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::FileSystem,
                    Some(Arc::clone(data_source)),
                    json!({
                        "filesystem_type": "APFS",
                        "volume_name": vol_sb.vol_name,
                        "volume_uuid": format_uuid(&vol_sb.vol_uuid),
                        "volume_index": vol_idx,
                        "num_files": vol_sb.num_files,
                        "num_directories": vol_sb.num_directories,
                        "block_size": nx_sb.block_size,
                        "encrypted": false,
                    }),
                )
                .with_parent(artifact.id),
            );

            // Walk volume filesystem
            match walk_volume_filesystem(
                data_source,
                &nx_sb,
                &vol_sb,
                artifact.case_id,
                artifact.id,
            ) {
                Ok(walk) => {
                    info!(
                        "APFS volume '{}' traversal produced {} file entries",
                        vol_sb.vol_name,
                        walk.artifacts.len()
                    );
                    if walk.dir_entries_truncated {
                        warn!(
                            "APFS volume '{}' hit the {} directory-entry cap; listing is incomplete",
                            vol_sb.vol_name, MAX_DIR_ENTRIES
                        );
                        // Honesty flag on the volume: a short inventory must not
                        // read as a complete one (BUG-215).
                        produced_artifacts[volume_artifact_idx].metadata
                            ["directory_parse_incomplete"] = json!(true);
                        produced_artifacts[volume_artifact_idx].metadata
                            ["directory_parse_incomplete_reason"] = json!("apfs_max_dir_entries");
                    }
                    if walk.inodes_truncated {
                        warn!(
                            "APFS volume '{}' hit the {} inode cap; file inventory is incomplete",
                            vol_sb.vol_name, MAX_INODES
                        );
                        // Files exist that were never enumerated: say so on the
                        // volume rather than let a partial listing read as the
                        // whole filesystem (B2-097).
                        produced_artifacts[volume_artifact_idx].metadata["inventory_incomplete"] =
                            json!(true);
                        produced_artifacts[volume_artifact_idx].metadata
                            ["inventory_incomplete_reason"] = json!("apfs_max_inodes");
                    }
                    let outcome = inventory_outcome(walk.artifacts.len(), walk.subtrees_unwalked);
                    if walk.subtrees_unwalked > 0 {
                        // "A subset" is only honest when something survived. With
                        // an empty inventory the volume was not enumerated at all,
                        // and saying so is the difference between an examiner
                        // re-running the case and trusting an empty result
                        // (LIVE-012).
                        if outcome.is_subset() {
                            warn!(
                                "APFS volume '{}': {} FS B-tree subtree(s) could not be walked; \
                                 the file inventory is a subset of the volume",
                                vol_sb.vol_name, walk.subtrees_unwalked
                            );
                        } else {
                            warn!(
                                "APFS volume '{}': NONE of the file inventory was recovered — \
                                 all {} FS B-tree subtree(s) failed to walk, so this volume was \
                                 not enumerated. The volume superblock declares {} files and {} \
                                 directories; none of them are in this case.",
                                vol_sb.vol_name,
                                walk.subtrees_unwalked,
                                vol_sb.num_files,
                                vol_sb.num_directories
                            );
                        }
                        // Lost subtrees are lost FILES. Without this the short
                        // inventory is served as a complete volume listing and
                        // "not present" reads as "did not exist" (B2-133).
                        produced_artifacts[volume_artifact_idx].metadata["inventory_incomplete"] =
                            json!(true);
                        produced_artifacts[volume_artifact_idx].metadata["unwalked_subtrees"] =
                            json!(walk.subtrees_unwalked);
                        produced_artifacts[volume_artifact_idx].metadata["inventory_outcome"] =
                            json!(outcome.as_str());
                        // Do not overwrite a cap reason already recorded: both
                        // are true, and the cap is the coarser statement.
                        let reason = &mut produced_artifacts[volume_artifact_idx].metadata
                            ["inventory_incomplete_reason"];
                        if reason.is_null() {
                            *reason = json!(if outcome.is_subset() {
                                "apfs_unwalked_subtree"
                            } else {
                                "apfs_volume_not_enumerated"
                            });
                        }
                    }
                    // Snapshots are a second, older view of this volume. This
                    // parser resolves the LIVE tree only, so a file that exists
                    // only in a snapshot — including anything deleted since the
                    // snapshot was taken — is absent from the case. Silence
                    // here reads as "the volume held nothing else" (B7-006).
                    produced_artifacts[volume_artifact_idx].metadata["snapshot_count"] =
                        json!(walk.snapshot_count);
                    produced_artifacts[volume_artifact_idx].metadata["snapshots_enumerated"] =
                        json!(false);
                    if walk.snapshot_count > 0 {
                        warn!(
                            "APFS volume '{}' carries {} snapshot(s); only the live tree was \
                             walked, so content that exists only in a snapshot is NOT in this case",
                            vol_sb.vol_name, walk.snapshot_count
                        );
                        produced_artifacts[volume_artifact_idx].metadata["inventory_incomplete"] =
                            json!(true);
                        let reason = &mut produced_artifacts[volume_artifact_idx].metadata
                            ["inventory_incomplete_reason"];
                        if reason.is_null() {
                            *reason = json!("apfs_snapshots_not_enumerated");
                        }
                    }
                    // Publish this volume's in-image sidecars (`-wal`, `.LOG1`/`.LOG2`)
                    // and each `.tracev3`'s log tree. Per volume: two volumes list
                    // the same paths, and pairing across them would hand a file the
                    // other volume's sidecar.
                    let mut walked = walk.artifacts;
                    seance_core::data_source::attach_sibling_bundles(&mut walked);
                    let slack =
                        publish_file_slack(&walked, artifact, data_source, nx_sb.block_size);
                    produced_artifacts.extend(walked);
                    produced_artifacts.extend(slack);
                }
                Err(e) => {
                    warn!(
                        "APFS volume '{}' traversal failed, returning metadata only: {}",
                        vol_sb.vol_name, e
                    );
                    // A volume artifact with no files and no flag is read as an
                    // empty volume. It is not: the walk never ran.
                    produced_artifacts[volume_artifact_idx].metadata["inventory_incomplete"] =
                        json!(true);
                    produced_artifacts[volume_artifact_idx].metadata
                        ["inventory_incomplete_reason"] = json!("apfs_volume_walk_failed");
                    produced_artifacts[volume_artifact_idx].metadata["inventory_error"] =
                        json!(e.to_string());
                }
            }
        }

        // The container's own volume inventory is short. Nothing above can carry
        // that: the per-volume flags belong to volumes that WERE parsed, and the
        // volumes lost here produced no artifact to stamp. Without this record a
        // container whose later volumes were capped away, or whose volume
        // superblocks would not parse, presents the volumes it did read as the
        // whole container (B3-019).
        if nx_sb.fs_oid_slots_skipped > 0 || volumes_unreadable > 0 {
            let volumes_parsed = produced_artifacts
                .iter()
                .filter(|a| a.artifact_type == ArtifactType::FileSystem)
                .count();
            let reason = if nx_sb.fs_oid_slots_skipped > 0 {
                IncompleteReason::CapReached
            } else {
                IncompleteReason::UnresolvedStructure
            };
            let detail = format!(
                "the container declares {} volume slot(s); {} were beyond the {} volume parser cap \
                 or outside the superblock block, and {} named volume(s) could not be resolved or \
                 parsed, so {} volume(s) are reported out of the container",
                nx_sb.max_file_systems,
                nx_sb.fs_oid_slots_skipped,
                MAX_VOLUMES,
                volumes_unreadable,
                volumes_parsed
            );
            let mut meta = json!({
                "type": "ApfsContainerIncomplete",
                "subtype": "parse_incomplete",
                "status": "VolumeInventoryIncomplete",
                "filesystem_type": "APFS",
                "inventory_incomplete": true,
                "inventory_incomplete_reason": reason.as_str(),
                "content_incomplete": true,
                "content_incomplete_reason": reason.as_str(),
                "declared_volume_slots": nx_sb.max_file_systems,
                "volume_slots_skipped": nx_sb.fs_oid_slots_skipped,
                "volumes_unreadable": volumes_unreadable,
                "volumes_reported": volumes_parsed,
                "max_volumes": MAX_VOLUMES,
                "detail": detail,
                "name": format!("APFS container: incomplete volume inventory — {detail}"),
            });
            if let Some(err) = first_unreadable_error {
                meta["first_error"] = json!(err);
            }
            produced_artifacts.push(
                Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
                    .with_parent(artifact.id)
                    .with_subtype("parse_incomplete"),
            );
        }

        info!(
            "APFS parser produced {} total artifacts",
            produced_artifacts.len()
        );

        Ok(produced_artifacts)
    }
}

// --- Parsing Functions ---

fn parse_obj_phys(data: &[u8], offset: usize) -> Result<ObjPhys, ModuleError> {
    if data.len() < offset + OBJ_PHYS_SIZE {
        return Err(ModuleError::ParsingError(format!(
            "Not enough data for object header at offset {}",
            offset
        )));
    }
    let d = &data[offset..];
    Ok(ObjPhys {
        cksum: LittleEndian::read_u64(&d[0..8]),
        oid: LittleEndian::read_u64(&d[8..16]),
        xid: LittleEndian::read_u64(&d[16..24]),
        o_type: LittleEndian::read_u32(&d[24..28]),
        o_subtype: LittleEndian::read_u32(&d[28..32]),
    })
}

/// Read one whole APFS block by block number. The only APFS-specific part is the
/// block-number-to-byte-offset conversion; the fail-closed read itself is
/// `seance_core::io::read_exact_or_fail`.
///
/// Fails unless the WHOLE block was read. Callers parse records across the full
/// block, so a zero-padded tail would be decoded as fabricated records (BUG-155).
fn read_block(
    data_source: &dyn DataSource,
    block_num: u64,
    block_size: u32,
) -> Result<Vec<u8>, ModuleError> {
    // block_num comes from on-disk object identifiers; guard the multiply so a
    // bogus block number can't overflow the byte offset.
    let offset = block_num.checked_mul(block_size as u64).ok_or_else(|| {
        ModuleError::ParsingError(format!(
            "APFS block offset overflow: block {} * block_size {}",
            block_num, block_size
        ))
    })?;
    let mut buf = vec![0u8; block_size as usize];
    read_exact_or_fail(data_source, offset, &mut buf, "APFS block")?;
    Ok(buf)
}

/// APFS Fletcher-64 over an object's bytes after its 8-byte checksum field,
/// returning the value that should be stored in that field.
fn apfs_fletcher64(after_cksum: &[u8]) -> u64 {
    const M: u64 = 0xFFFF_FFFF;
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;
    for chunk in after_cksum.as_chunks::<4>().0.iter() {
        let v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
        sum1 = (sum1 + v) % M;
        sum2 = (sum2 + sum1) % M;
    }
    let c1 = M - ((sum1 + sum2) % M);
    let c2 = M - ((sum1 + c1) % M);
    (c2 << 32) | c1
}

/// True if a block's stored Fletcher-64 (first 8 bytes) matches its contents.
fn checksum_valid(block: &[u8]) -> bool {
    block.len() >= 8 && apfs_fletcher64(&block[8..]) == LittleEndian::read_u64(&block[0..8])
}

/// Given block 0's container superblock, scan the checkpoint descriptor ring and
/// return the buffer of the newest valid nx_superblock (highest xid). Falls back
/// to `block0` if the ring can't be scanned or holds nothing newer.
fn select_latest_checkpoint(
    data_source: &dyn DataSource,
    block0: Vec<u8>,
    block_size: u32,
) -> Vec<u8> {
    // nx_xp_desc_blocks @104, nx_xp_desc_base @112.
    if block0.len() < 120 || block_size < 512 {
        return block0;
    }
    let desc_blocks_raw = LittleEndian::read_u32(&block0[104..108]);
    let desc_base = LittleEndian::read_u64(&block0[112..120]);
    // Top bit set => the descriptor area is a tree (rare); we only walk the
    // common contiguous layout.
    if desc_blocks_raw & 0x8000_0000 != 0 || desc_base == 0 {
        return block0;
    }
    let count = (desc_blocks_raw as u64).min(4096); // bound the scan

    // Only enforce the checksum if we can reproduce block 0's own checksum
    // (guards against an implementation slip rejecting every candidate).
    let use_cksum = checksum_valid(&block0);

    let mut best = block0;
    let mut best_xid = LittleEndian::read_u64(&best[16..24]);
    for i in 0..count {
        let byte_off = desc_base
            .saturating_mul(block_size as u64)
            .saturating_add(i.saturating_mul(block_size as u64));
        let mut b = vec![0u8; block_size as usize];
        // A ring slot must be readable in full: `checksum_valid` runs over the
        // whole block and the fields below sit anywhere inside it, so a partially
        // read slot would be validated (and possibly adopted) with a zero tail.
        // Unreadable slots are skipped, exactly as before.
        if read_exact_or_fail(data_source, byte_off, &mut b, "APFS checkpoint descriptor").is_err()
        {
            continue;
        }
        let o_type = LittleEndian::read_u32(&b[24..28]) as u16;
        if o_type != OBJ_TYPE_NX_SUPERBLOCK || LittleEndian::read_u32(&b[32..36]) != NXSB_MAGIC {
            continue;
        }
        let xid = LittleEndian::read_u64(&b[16..24]);
        if xid <= best_xid || (use_cksum && !checksum_valid(&b)) {
            continue;
        }
        best_xid = xid;
        best = b;
    }
    best
}

fn parse_nx_superblock(data_source: &dyn DataSource) -> Result<NxSuperblock, ModuleError> {
    // Read block 0 — container superblock is always at the start.
    // We probe a generous buffer since we don't know block_size yet, so a short
    // read is tolerable here; truncate to the honest count so nothing below can
    // parse the unread tail as genuine zeros.
    let mut buf = vec![0u8; 4096];
    let n = read_full(data_source, 0, &mut buf);
    if n < 200 {
        return Err(ModuleError::ParsingError(
            "Not enough data for APFS container superblock".to_string(),
        ));
    }
    buf.truncate(n);

    let obj = parse_obj_phys(&buf, 0)?;

    // Magic at offset 32
    let magic = LittleEndian::read_u32(&buf[32..36]);
    if magic != NXSB_MAGIC {
        return Err(ModuleError::ParsingError(format!(
            "Invalid APFS container magic: 0x{:08X} (expected 0x{:08X})",
            magic, NXSB_MAGIC
        )));
    }

    let block_size = LittleEndian::read_u32(&buf[36..40]);
    // block_size is attacker-controlled and is used both to size allocations and
    // as a multiplier for every block offset. APFS uses power-of-two block sizes
    // (4096 standard); reject absurd values before resizing the buffer so a
    // header field can't drive an unbounded allocation.
    if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(ModuleError::ParsingError(format!(
            "Invalid APFS block size: {} (expected power of two in 512..=65536)",
            block_size
        )));
    }
    let block_count = LittleEndian::read_u64(&buf[40..48]);

    // If the block is larger than what the probe returned, re-read the whole
    // block. This must fail closed: the superblock fields and the Fletcher-64
    // below span the entire block, so a partial re-read would be parsed and
    // checksummed against a zero-padded tail.
    if block_size as usize > buf.len() {
        buf.resize(block_size as usize, 0);
        read_exact_or_fail(data_source, 0, &mut buf, "APFS container superblock")?;
    }

    // Block 0 is the container superblock written at format time; on a used
    // volume the CURRENT container state is the highest-xid nx_superblock in the
    // checkpoint descriptor area. Scan that ring and adopt the newest valid one
    // so we read the live volume/omap pointers, not a stale copy.
    let buf = select_latest_checkpoint(data_source, buf, block_size);

    // nx_omap_oid at offset 160 (physical OID of container object map)
    let omap_oid = LittleEndian::read_u64(&buf[160..168]);

    // nx_max_file_systems at offset 180. Offset 168 is nx_reaper_oid and 176 is
    // nx_test_type; reading the count from 168 yielded the reaper OID's low 32
    // bits — 1025 on every real container measured — so the parser believed
    // 925 volume slots had been skipped and stamped a bogus
    // "volume inventory incomplete" record on every APFS image it saw. A
    // warning that fires on every case teaches examiners to ignore warnings.
    let max_file_systems = LittleEndian::read_u32(&buf[180..184]);

    // nx_fs_oid array starts at offset 184
    // Each entry is u64, up to max_file_systems entries
    let mut fs_oid = Vec::new();
    let fs_oid_start = 184;
    let declared_slots = max_file_systems as usize;
    let max_fs = std::cmp::min(declared_slots, MAX_VOLUMES);
    // Slots the cap alone puts out of reach. Counted, not just clamped: a
    // container that declares more volumes than we will read must be able to say
    // so, or later volumes vanish with nothing to distinguish them from
    // volumes that were never there (B3-019).
    let mut slots_skipped = declared_slots.saturating_sub(max_fs);

    for i in 0..max_fs {
        let offset = fs_oid_start + i * 8;
        if offset + 8 > buf.len() {
            // The superblock block ends before the declared array does: every
            // remaining slot is unreadable, not empty.
            slots_skipped = slots_skipped.saturating_add(max_fs - i);
            break;
        }
        let oid = LittleEndian::read_u64(&buf[offset..offset + 8]);
        if oid != 0 {
            fs_oid.push(oid);
        }
    }

    Ok(NxSuperblock {
        obj,
        magic,
        block_size,
        block_count,
        omap_oid,
        fs_oid,
        max_file_systems,
        fs_oid_slots_skipped: u32::try_from(slots_skipped).unwrap_or(u32::MAX),
    })
}

fn parse_omap(
    data_source: &dyn DataSource,
    omap_paddr: u64,
    block_size: u32,
) -> Result<OmapPhys, ModuleError> {
    let buf = read_block(data_source, omap_paddr, block_size)?;
    let obj = parse_obj_phys(&buf, 0)?;

    // omap_phys_t after obj header:
    // flags at +32 (u32)
    let flags = LittleEndian::read_u32(&buf[32..36]);
    // snap_count at +36 (u32)
    let snap_count = LittleEndian::read_u32(&buf[36..40]);
    // tree_type at +40 (u32), skip
    // snapshot_tree_type at +44 (u32), skip
    // tree_oid at +48 (u64)
    let tree_oid = LittleEndian::read_u64(&buf[48..56]);

    Ok(OmapPhys {
        obj,
        flags,
        tree_oid,
        snap_count,
    })
}

fn parse_volume(
    data_source: &dyn DataSource,
    vol_paddr: u64,
    block_size: u32,
) -> Result<ApfsSuperblock, ModuleError> {
    let buf = read_block(data_source, vol_paddr, block_size)?;
    let obj = parse_obj_phys(&buf, 0)?;

    let magic = LittleEndian::read_u32(&buf[32..36]);
    if magic != APSB_MAGIC {
        return Err(ModuleError::ParsingError(format!(
            "Invalid APFS volume magic: 0x{:08X} (expected 0x{:08X})",
            magic, APSB_MAGIC
        )));
    }

    // fs_index at +36 (u32), skip
    // features at +40 (u64), skip
    // readonly_compatible_features at +48 (u64), skip
    // apfs_incompatible_features at +56 (u64). NOTE bit0 here is
    // APFS_INCOMPAT_CASE_INSENSITIVE, NOT encryption.
    let incompatible_features = LittleEndian::read_u64(&buf[56..64]);

    // Between incompatible_features (+56) and omap_oid sit unmount_time, the
    // reserve/quota/alloc block counts, meta_crypto (20B) and three tree-type
    // u32s. apfs_omap_oid at +128, apfs_root_tree_oid at +136.
    let omap_oid = read_u64_at(&buf, 128);
    let root_tree_oid = read_u64_at(&buf, 136);

    // apfs_num_files at +184, apfs_num_directories at +192.
    let num_files = read_u64_at(&buf, 184);
    let num_directories = read_u64_at(&buf, 192);

    // apfs_vol_uuid at +240 (16 bytes)
    let mut vol_uuid = [0u8; 16];
    if buf.len() >= 256 {
        vol_uuid.copy_from_slice(&buf[240..256]);
    }

    // apfs_fs_flags at +264 (u64): APFS_FS_UNENCRYPTED (0x1) set => unencrypted.
    let fs_flags = read_u64_at(&buf, 264);

    // apfs_volname at +704 (256 bytes, null-terminated UTF-8).
    let vol_name = if buf.len() >= 960 {
        let name_bytes = &buf[704..960];
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(256);
        String::from_utf8_lossy(&name_bytes[..end]).to_string()
    } else {
        String::new()
    };

    Ok(ApfsSuperblock {
        obj,
        magic,
        omap_oid,
        root_tree_oid,
        num_files,
        num_directories,
        vol_uuid,
        vol_name,
        incompatible_features,
        fs_flags,
    })
}

fn parse_btree_node(data: &[u8]) -> Result<BTreeNodePhys, ModuleError> {
    if data.len() < OBJ_PHYS_SIZE + 24 {
        return Err(ModuleError::ParsingError(
            "Not enough data for B-tree node header".to_string(),
        ));
    }

    let obj = parse_obj_phys(data, 0)?;

    // btree_node_phys_t fields after obj header:
    let flags = LittleEndian::read_u16(&data[32..34]);
    let level = LittleEndian::read_u16(&data[34..36]);
    let nkeys = LittleEndian::read_u32(&data[36..40]);
    let table_space_off = LittleEndian::read_u16(&data[40..42]);
    let table_space_len = LittleEndian::read_u16(&data[42..44]);
    let free_space_off = LittleEndian::read_u16(&data[44..46]);
    let free_space_len = LittleEndian::read_u16(&data[46..48]);
    let key_free_list_off = LittleEndian::read_u16(&data[48..50]);
    let key_free_list_len = LittleEndian::read_u16(&data[50..52]);
    let val_free_list_off = LittleEndian::read_u16(&data[52..54]);
    let val_free_list_len = LittleEndian::read_u16(&data[54..56]);

    Ok(BTreeNodePhys {
        obj,
        flags,
        level,
        nkeys,
        table_space_off,
        table_space_len,
        free_space_off,
        free_space_len,
        key_free_list_off,
        key_free_list_len,
        val_free_list_off,
        val_free_list_len,
    })
}

/// Extract key/value byte slices from a B-tree node.
///
/// Returns a vector of (key_bytes, val_bytes) for each entry in the node.
fn btree_node_entries<'a>(
    data: &'a [u8],
    node: &BTreeNodePhys,
    block_size: u32,
) -> Result<Vec<(&'a [u8], &'a [u8])>, ModuleError> {
    let is_root = (node.flags & BTNODE_ROOT) != 0;
    let is_leaf = (node.flags & BTNODE_LEAF) != 0;
    let is_fixed = (node.flags & BTNODE_FIXED_KV_SIZE) != 0;

    // TOC starts at offset 56 (sizeof btree_node_phys_t) + table_space_off
    let toc_start = 56 + node.table_space_off as usize;

    // Keys area starts after the TOC
    let keys_start = 56 + node.table_space_off as usize + node.table_space_len as usize;

    // Values area: for leaf nodes, values grow backwards from end of block
    // For root nodes, they grow backwards from (end_of_block - sizeof(btree_info_t))
    let vals_end = if is_root {
        (block_size as usize).saturating_sub(40) // btree_info_t is 40 bytes
    } else {
        block_size as usize
    };

    // nkeys is attacker-controlled; the TOC can physically hold at most
    // block_size/4 fixed entries, so bound the reservation to avoid a giant
    // allocation from a bogus nkeys.
    let cap = (node.nkeys as usize).min(block_size as usize / 4);
    let mut entries = Vec::with_capacity(cap);

    for i in 0..node.nkeys as usize {
        if is_fixed {
            // Fixed-size keys: TOC entries are kvoff_t = key_off(u16) + val_off(u16) = 4 bytes
            let toc_offset = toc_start + i * 4;
            // The TOC entry must lie within both the buffer and the TOC area
            // (which ends at keys_start); a bogus nkeys must not read TOC
            // entries out of the key area.
            if toc_offset + 4 > data.len() || toc_offset + 4 > keys_start {
                break;
            }
            let key_off = LittleEndian::read_u16(&data[toc_offset..toc_offset + 2]) as usize;
            let val_off = LittleEndian::read_u16(&data[toc_offset + 2..toc_offset + 4]) as usize;

            let key_start = keys_start + key_off;

            if is_leaf {
                // For omap nodes: key is 16 bytes (oid + xid), val is 16 bytes (flags + size + paddr)
                // We don't know sizes from the TOC for fixed-size, we need them from btree_info
                // For omap: key_size=16, val_size=16
                // Use 16 as default for omap, which is the main fixed-size btree
                let key_size = 16usize;
                let val_size = 16usize;

                if key_start + key_size > data.len() {
                    break;
                }
                // Values are stored at (value_area_end - v); v already points to
                // the start of the value, so do NOT subtract val_size again.
                if val_off > vals_end {
                    break;
                }
                let val_start = vals_end - val_off;
                if val_start + val_size > data.len() {
                    break;
                }

                entries.push((
                    &data[key_start..key_start + key_size],
                    &data[val_start..val_start + val_size],
                ));
            } else {
                // Internal node: value is a child pointer (u64 = 8 bytes)
                let key_size = 16usize;
                if val_off > vals_end {
                    break;
                }
                let val_start = vals_end - val_off;
                if key_start + key_size > data.len() || val_start + 8 > data.len() {
                    break;
                }
                entries.push((
                    &data[key_start..key_start + key_size],
                    &data[val_start..val_start + 8],
                ));
            }
        } else {
            // Variable-size keys: TOC entries are kvloc_t = key_off(u16) + key_len(u16) + val_off(u16) + val_len(u16) = 8 bytes
            let toc_offset = toc_start + i * 8;
            if toc_offset + 8 > data.len() || toc_offset + 8 > keys_start {
                break;
            }
            let key_off = LittleEndian::read_u16(&data[toc_offset..toc_offset + 2]) as usize;
            let key_len = LittleEndian::read_u16(&data[toc_offset + 2..toc_offset + 4]) as usize;
            let val_off = LittleEndian::read_u16(&data[toc_offset + 4..toc_offset + 6]) as usize;
            let val_len = LittleEndian::read_u16(&data[toc_offset + 6..toc_offset + 8]) as usize;

            let key_start = keys_start + key_off;
            if key_start + key_len > data.len() || key_len == 0 {
                break;
            }

            if is_leaf {
                // v points to the start of the value, measured from the end of
                // the value area — no extra val_len subtraction.
                if val_off > vals_end {
                    break;
                }
                let val_start = vals_end - val_off;
                if val_start + val_len > data.len() || val_len == 0 {
                    break;
                }
                entries.push((
                    &data[key_start..key_start + key_len],
                    &data[val_start..val_start + val_len],
                ));
            } else {
                // Internal node: val is an OID (8 bytes)
                if val_off > vals_end {
                    break;
                }
                let val_start = vals_end - val_off;
                if val_start + 8 > data.len() {
                    break;
                }
                entries.push((
                    &data[key_start..key_start + key_len],
                    &data[val_start..val_start + 8],
                ));
            }
        }
    }

    Ok(entries)
}

/// Look up a virtual OID in an object map B-tree.
/// Returns the physical block address if found.
fn omap_lookup(
    data_source: &dyn DataSource,
    omap_tree_paddr: u64,
    target_oid: u64,
    block_size: u32,
    _is_physical: bool,
) -> Result<Option<u64>, ModuleError> {
    walk_omap_btree(data_source, omap_tree_paddr, target_oid, block_size, 0)
}

fn walk_omap_btree(
    data_source: &dyn DataSource,
    node_paddr: u64,
    target_oid: u64,
    block_size: u32,
    depth: usize,
) -> Result<Option<u64>, ModuleError> {
    if depth > MAX_BTREE_DEPTH {
        return Err(ModuleError::ParsingError(
            "OMap B-tree depth exceeded maximum".to_string(),
        ));
    }

    let data = read_block(data_source, node_paddr, block_size)?;
    let node = parse_btree_node(&data)?;
    let entries = btree_node_entries(&data, &node, block_size)?;

    if (node.flags & BTNODE_LEAF) != 0 {
        // Leaf node: search for the entry with matching OID and highest XID
        let mut best_paddr: Option<u64> = None;
        let mut best_xid: u64 = 0;

        for (key_data, val_data) in &entries {
            if key_data.len() < 16 {
                continue;
            }
            let oid = LittleEndian::read_u64(&key_data[0..8]);
            let xid = LittleEndian::read_u64(&key_data[8..16]);

            if oid == target_oid && xid >= best_xid && val_data.len() >= 16 {
                // omap_val_t: flags(u32) + size(u32) + paddr(u64). A deleted
                // (ghost) mapping must never be resolved — otherwise a stale
                // higher-xid entry would shadow the live object and point at a
                // reclaimed block.
                let ov_flags = LittleEndian::read_u32(&val_data[0..4]);
                if ov_flags & OMAP_VAL_DELETED != 0 {
                    continue;
                }
                let paddr = LittleEndian::read_u64(&val_data[8..16]);
                best_paddr = Some(paddr);
                best_xid = xid;
            }
        }

        Ok(best_paddr)
    } else {
        // Internal node: find the child to descend into
        // Walk entries to find the last key where oid <= target_oid
        let mut child_paddr: Option<u64> = None;

        for (key_data, val_data) in &entries {
            if key_data.len() < 16 || val_data.len() < 8 {
                continue;
            }
            let oid = LittleEndian::read_u64(&key_data[0..8]);

            if oid <= target_oid {
                // This child could contain our target
                child_paddr = Some(LittleEndian::read_u64(&val_data[0..8]));
            } else {
                break;
            }
        }

        match child_paddr {
            Some(paddr) => walk_omap_btree(data_source, paddr, target_oid, block_size, depth + 1),
            None => Ok(None),
        }
    }
}

/// Extract the record type from j_key_t's obj_id_and_type field.
/// The upper 4 bits of the 8-byte field encode the type.
fn j_key_type(obj_id_and_type: u64) -> u8 {
    ((obj_id_and_type >> 60) & 0x0F) as u8
}

/// Extract the object ID from j_key_t's obj_id_and_type field.
/// The lower 60 bits encode the object ID.
fn j_key_oid(obj_id_and_type: u64) -> u64 {
    obj_id_and_type & 0x0FFF_FFFF_FFFF_FFFF
}

fn parse_j_inode_val(data: &[u8]) -> Option<JInodeVal> {
    if data.len() < 92 {
        return None;
    }

    let parent_id = LittleEndian::read_u64(&data[0..8]);
    let private_id = LittleEndian::read_u64(&data[8..16]);
    let create_time = LittleEndian::read_i64(&data[16..24]);
    let mod_time = LittleEndian::read_i64(&data[24..32]);
    let change_time = LittleEndian::read_i64(&data[32..40]);
    let access_time = LittleEndian::read_i64(&data[40..48]);
    let internal_flags = LittleEndian::read_u64(&data[48..56]);
    let nchildren_or_nlink = LittleEndian::read_i32(&data[56..60]);
    // default_protection_class at +60 (u32), skip
    // write_generation_counter at +64 (u32), skip
    // bsd_flags at +68 (u32), skip
    let owner = LittleEndian::read_u32(&data[72..76]);
    let group = LittleEndian::read_u32(&data[76..80]);
    let mode = LittleEndian::read_u16(&data[80..82]);
    // pad1 at +82 (u16), skip
    let uncompressed_size = if data.len() >= 92 {
        LittleEndian::read_u64(&data[84..92])
    } else {
        0
    };

    Some(JInodeVal {
        parent_id,
        private_id,
        create_time,
        mod_time,
        change_time,
        access_time,
        internal_flags,
        nchildren_or_nlink,
        owner,
        group,
        mode,
        uncompressed_size,
        dstream_size: extract_dstream_size(data),
    })
}

/// Extract the logical file size from an inode's DSTREAM extended field.
///
/// The extended fields follow the fixed j_inode_val fields at offset 92:
///   xf_blob: xf_num_exts(u16), xf_used_data(u16), then xf_num_exts x_field_t
///   headers (x_type u8, x_flags u8, x_size u16), then the field data (each
///   value padded to 8-byte alignment). DSTREAM (x_type=1) holds a j_dstream_t
///   whose first u64 is the logical size.
fn extract_dstream_size(data: &[u8]) -> Option<u64> {
    const INO_EXT_TYPE_DSTREAM: u8 = 8;
    if data.len() < 96 {
        return None;
    }
    let xf_num = LittleEndian::read_u16(&data[92..94]) as usize;
    let headers_start = 96;
    let mut val_off = headers_start + xf_num * 4;
    for i in 0..xf_num {
        let h = headers_start + i * 4;
        if h + 4 > data.len() {
            break;
        }
        let x_type = data[h];
        let x_size = LittleEndian::read_u16(&data[h + 2..h + 4]) as usize;
        if x_type == INO_EXT_TYPE_DSTREAM {
            if val_off + 8 <= data.len() {
                return Some(LittleEndian::read_u64(&data[val_off..val_off + 8]));
            }
            return None;
        }
        val_off += (x_size + 7) & !7; // 8-byte aligned
    }
    None
}

fn parse_j_drec_val(data: &[u8]) -> Option<JDrecVal> {
    if data.len() < 18 {
        return None;
    }

    let file_id = LittleEndian::read_u64(&data[0..8]);
    let date_added = LittleEndian::read_u64(&data[8..16]);
    let flags = LittleEndian::read_u16(&data[16..18]);

    Some(JDrecVal {
        file_id,
        date_added,
        flags,
    })
}

fn parse_j_drec_name(key_data: &[u8]) -> Option<String> {
    // j_drec_hashed_key_t:
    //   j_key_t: obj_id_and_type (u64) — 8 bytes
    //   name_len_and_hash (u32) — 4 bytes
    //   name (variable, null-terminated)
    if key_data.len() < 13 {
        return None;
    }

    let name_len_and_hash = LittleEndian::read_u32(&key_data[8..12]);
    let name_len = (name_len_and_hash & 0x000003FF) as usize;

    let name_start = 12;
    let name_end = std::cmp::min(name_start + name_len, key_data.len());
    if name_start >= name_end {
        return None;
    }

    let name_bytes = &key_data[name_start..name_end];
    // Remove trailing null if present
    let actual_end = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());

    if actual_end == 0 {
        return None;
    }

    Some(String::from_utf8_lossy(&name_bytes[..actual_end]).to_string())
}

fn parse_j_file_extent_val(data: &[u8]) -> Option<JFileExtentVal> {
    if data.len() < 24 {
        return None;
    }

    let len_and_flags = LittleEndian::read_u64(&data[0..8]);
    let phys_block_num = LittleEndian::read_u64(&data[8..16]);
    let crypto_id = LittleEndian::read_u64(&data[16..24]);

    Some(JFileExtentVal {
        logical_offset: 0, // Set by caller from key
        len_and_flags,
        phys_block_num,
        crypto_id,
    })
}

/// The value of a `j_xattr_val_t` record.
#[derive(Debug, Clone)]
enum ApfsXattrValue {
    /// `XATTR_DATA_EMBEDDED`: the attribute's bytes are in the record itself.
    Embedded(Vec<u8>),
    /// `XATTR_DATA_STREAM`: the attribute's bytes are a separate data stream,
    /// identified the same way a file's data stream is.
    Stream { stream_id: u64, size: u64 },
}

/// The extended attributes this parser retains for one inode.
///
/// Only the two that decide content are kept. A decmpfs-compressed file has no
/// data-stream extents of its own, so without these a sized regular file looks
/// exactly like one whose content could not be located (BUG-156).
#[derive(Debug, Clone, Default)]
struct ApfsInodeXattrs {
    decmpfs: Option<ApfsXattrValue>,
    resource_fork: Option<ApfsXattrValue>,
}

/// Extract the attribute name from a `j_xattr_key_t`.
///
/// Layout: `j_key_t` (8) + `name_len` (u16) + null-terminated name.
fn parse_j_xattr_name(key_data: &[u8]) -> Option<String> {
    if key_data.len() < 11 {
        return None;
    }
    let name_len = LittleEndian::read_u16(&key_data[8..10]) as usize;
    let start: usize = 10;
    let end = std::cmp::min(start.checked_add(name_len)?, key_data.len());
    if start >= end {
        return None;
    }
    let bytes = &key_data[start..end];
    let terminator = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if terminator == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..terminator]).to_string())
}

/// Parse a `j_xattr_val_t`.
///
/// Layout: `flags` (u16) + `xdata_len` (u16) + `xdata`. For a stream-backed
/// attribute the data is a `j_xattr_dstream_t`: the stream's object id followed
/// by a `j_dstream_t` whose first field is its logical size.
///
/// Returns `None` when the record is short or declares neither storage form —
/// an attribute we cannot read must not be reported as an empty one.
fn parse_j_xattr_val(data: &[u8]) -> Option<ApfsXattrValue> {
    if data.len() < 4 {
        return None;
    }
    let flags = LittleEndian::read_u16(&data[0..2]);
    let xdata_len = LittleEndian::read_u16(&data[2..4]) as usize;
    let body = data.get(4..4 + xdata_len)?;

    if (flags & XATTR_DATA_STREAM) != 0 {
        if body.len() < 16 {
            return None;
        }
        Some(ApfsXattrValue::Stream {
            stream_id: LittleEndian::read_u64(&body[0..8]),
            size: LittleEndian::read_u64(&body[8..16]),
        })
    } else if (flags & XATTR_DATA_EMBEDDED) != 0 {
        Some(ApfsXattrValue::Embedded(body.to_vec()))
    } else {
        None
    }
}

// Collected FS records from B-tree traversal
struct FsRecords {
    inodes: HashMap<u64, JInodeVal>,
    dir_entries: HashMap<u64, Vec<(String, JDrecVal)>>, // parent_ino -> [(name, drec)]
    // Keyed by the data-stream id (`j_inode_val.private_id`), which is what
    // APFS puts in the file-extent record key -- NOT the inode object id. They
    // coincide for ordinary files but differ for clones / shared streams
    // (BUG-206).
    extents: HashMap<u64, Vec<ApfsExtent>>, // stream private_id -> sorted extents
    /// `com.apple.decmpfs` / `com.apple.ResourceFork` per inode object id.
    /// Only inodes that carry one of those two attributes get an entry.
    xattrs: HashMap<u64, ApfsInodeXattrs>,
    /// Streams whose extent list hit MAX_EXTENTS: their tail is missing, so the
    /// reconstruction is incomplete and must not be presented as whole content
    /// (BUG-212).
    truncated_streams: std::collections::HashSet<u64>,
    /// Running total of collected directory entries (the MAX_DIR_ENTRIES cap is
    /// global, and re-summing every map value per record is quadratic).
    dir_entry_count: usize,
    /// True when the global directory-entry cap dropped entries: the directory
    /// inventory for this volume is incomplete (BUG-215).
    dir_entries_truncated: bool,
    /// True when the MAX_INODES cap dropped inode records: files exist on the
    /// volume that this walk never enumerated, so the file inventory must not be
    /// presented as the whole volume (B2-097).
    inodes_truncated: bool,
    /// Number of FS B-tree subtrees that could not be walked: the child OID was
    /// absent from the volume object map, the omap lookup failed, or the child
    /// node itself would not parse. Every one of them is a range of the
    /// filesystem this walk never saw, so the inventory is a subset of the
    /// volume, not the volume (B2-133).
    subtrees_unwalked: usize,
    /// Ceiling on collected inodes (MAX_INODES in production).
    max_inodes: usize,
}

impl FsRecords {
    fn new() -> Self {
        Self {
            inodes: HashMap::new(),
            dir_entries: HashMap::new(),
            extents: HashMap::new(),
            xattrs: HashMap::new(),
            truncated_streams: std::collections::HashSet::new(),
            dir_entry_count: 0,
            dir_entries_truncated: false,
            inodes_truncated: false,
            subtrees_unwalked: 0,
            max_inodes: MAX_INODES,
        }
    }

    /// Resolve the extent list backing an inode's data stream, plus whether that
    /// list was truncated by the MAX_EXTENTS cap.
    ///
    /// APFS keys `APFS_TYPE_FILE_EXTENT` records by the data-stream object id
    /// (`j_inode_val.private_id`), not by the inode object id. The two match for
    /// ordinary files but diverge for clones and other shared streams, so a
    /// lookup by inode number silently yields no content there (BUG-206). The
    /// inode-number fallback only covers inodes whose record carried no usable
    /// private_id.
    fn stream_extents(&self, ino: u64, private_id: u64) -> Option<(&Vec<ApfsExtent>, bool)> {
        let (key, extents) = match self.extents.get(&private_id) {
            Some(e) => (private_id, e),
            None => (ino, self.extents.get(&ino)?),
        };
        let truncated = self.truncated_streams.contains(&key);
        Some((extents, truncated))
    }
}

/// The byte runs an extent list occupies in the filesystem window, plus the two
/// conditions that make those runs unsafe to serve as content.
struct ExtentRuns {
    runs: Vec<(Option<u64>, u64)>,
    /// An extent's physical offset overflowed, so its bytes cannot be located.
    unmappable: bool,
    /// An extent's blocks are ciphertext (BUG-157).
    encrypted: bool,
}

/// Project an extent list onto filesystem-window byte runs.
///
/// One place decides what an extent means, so the rules cannot drift apart
/// between the plaintext path and the compressed-resource-fork path:
///   * a gap before an extent, and the tail past the last one, are holes;
///   * an extent at physical block 0 is APFS's own record of a hole, and is
///     emitted as one — a run at byte 0 would make a consumer re-serve the
///     container superblock as the file's bytes (B2-001);
///   * an extent whose physical offset overflows is emitted as a hole and
///     reported unmappable — zeros must never stand in for bytes that are
///     really there;
///   * an encrypted extent is emitted as a hole and reported encrypted — a run
///     over ciphertext would be re-served as plaintext (BUG-157).
fn extent_runs(extents: &[ApfsExtent], block_size: u32, total_size: u64) -> ExtentRuns {
    let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
    let mut pos = 0u64;
    let mut unmappable = false;
    let mut encrypted = false;
    for ext in extents {
        if ext.logical_offset > pos {
            runs.push((None, ext.logical_offset - pos));
        }
        if ext.is_encrypted() {
            encrypted = true;
            runs.push((None, ext.length));
        } else if ext.is_sparse() {
            runs.push((None, ext.length));
        } else {
            match ext.phys_offset(block_size, 0) {
                Some(phys) => runs.push((Some(phys), ext.length)),
                None => {
                    unmappable = true;
                    runs.push((None, ext.length));
                }
            }
        }
        pos = ext.logical_offset.saturating_add(ext.length);
    }
    if pos < total_size {
        runs.push((None, total_size - pos));
    }
    ExtentRuns {
        runs,
        unmappable,
        encrypted,
    }
}

/// Persist the filesystem-window byte runs for a file's extents.
///
/// A hole between extents is genuinely sparse and reads as zeros, but the tail
/// past the last extent is only sparse when the whole extent list is in hand:
/// when the MAX_EXTENTS cap dropped records, that tail is real data we no longer
/// know the location of, so the runs are marked incomplete instead of being
/// served as zeros (BUG-212).
///
/// An extent at physical block 0 is APFS's own record of a hole and is persisted
/// as a sparse run: persisting it as a run at byte 0 would make the content
/// resolver re-serve the container superblock as the file's bytes (B2-001). An
/// extent whose physical offset overflows cannot be located at all, so it is
/// persisted as a hole AND the runs are declared incomplete — zeros must never
/// be mistaken for the bytes that are really there.
fn apply_extent_metadata(
    metadata: &mut serde_json::Value,
    extents: &[ApfsExtent],
    block_size: u32,
    file_size: u64,
    stream_truncated: bool,
) {
    let ExtentRuns {
        runs,
        unmappable,
        encrypted,
    } = extent_runs(extents, block_size, file_size);
    let (runs_json, complete) = seance_core::data_source::byte_runs_to_metadata(&runs);
    metadata["data_runs"] = runs_json;
    metadata["data_runs_complete"] =
        json!(complete && !stream_truncated && !unmappable && !encrypted);
    if encrypted {
        metadata["content_encrypted"] = json!(true);
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!("apfs_extent_encrypted");
    } else if stream_truncated {
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!("apfs_max_extents");
    } else if unmappable {
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!("apfs_extent_offset_overflow");
    }
}

/// Walk the filesystem B-tree collecting inodes, directory entries, and file extents.
/// What a volume's filesystem walk actually recovered.
///
/// Exists so that a total failure is never described in the language of a partial
/// one. "The file inventory is a subset of the volume" is a true and useful thing
/// to say when some files were recovered and others were lost; said over an empty
/// inventory it invites an examiner to read a listing of nothing as a listing with
/// gaps (LIVE-012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InventoryOutcome {
    /// Every subtree the walk reached was walked. Includes a volume that
    /// genuinely holds no files.
    Complete,
    /// Subtrees were lost, but records were recovered: a real subset.
    Partial,
    /// Subtrees were lost and nothing at all was recovered.
    NotEnumerated,
}

impl InventoryOutcome {
    /// Whether "a subset of the volume" is an honest description.
    fn is_subset(self) -> bool {
        matches!(self, InventoryOutcome::Partial)
    }

    /// Stable identifier for the volume artifact's metadata.
    fn as_str(self) -> &'static str {
        match self {
            InventoryOutcome::Complete => "complete",
            InventoryOutcome::Partial => "partial",
            InventoryOutcome::NotEnumerated => "not_enumerated",
        }
    }
}

/// Classify a walk from the two counts the caller already holds.
fn inventory_outcome(produced: usize, unwalked: usize) -> InventoryOutcome {
    if unwalked == 0 {
        InventoryOutcome::Complete
    } else if produced == 0 {
        InventoryOutcome::NotEnumerated
    } else {
        InventoryOutcome::Partial
    }
}

fn walk_fs_btree(
    data_source: &dyn DataSource,
    node_paddr: u64,
    block_size: u32,
    vol_omap_tree_paddr: u64,
    // The tree's own root oid, which a hashed (sealed-volume) tree needs: its
    // index values store the child as an offset from this, not as an absolute
    // oid. Pass 0 for a tree that is not hashed; it is then unused.
    root_tree_oid: u64,
    records: &mut FsRecords,
    depth: usize,
    visited: &mut std::collections::HashSet<u64>,
) -> Result<(), ModuleError> {
    if depth > MAX_BTREE_DEPTH {
        return Err(ModuleError::ParsingError(
            "FS B-tree depth exceeded maximum".to_string(),
        ));
    }
    // A shared/cyclic node graph would otherwise be re-walked up to
    // branching^depth times (depth 16, branching in the hundreds); visiting each
    // physical node once makes the walk linear.
    if !visited.insert(node_paddr) {
        return Ok(());
    }

    let data = read_block(data_source, node_paddr, block_size)?;
    let node = parse_btree_node(&data)?;
    let entries = btree_node_entries(&data, &node, block_size)?;

    if (node.flags & BTNODE_LEAF) != 0 {
        // Leaf node: parse FS records
        for (key_data, val_data) in &entries {
            if key_data.len() < 8 {
                continue;
            }

            let obj_id_and_type = LittleEndian::read_u64(&key_data[0..8]);
            let record_type = j_key_type(obj_id_and_type);
            let oid = j_key_oid(obj_id_and_type);

            match record_type {
                APFS_TYPE_INODE => {
                    if records.inodes.len() >= records.max_inodes {
                        // Record that inodes were dropped rather than return a
                        // short inventory that reads as the whole volume
                        // (B2-097).
                        records.inodes_truncated = true;
                        continue;
                    }
                    if let Some(inode) = parse_j_inode_val(val_data) {
                        records.inodes.insert(oid, inode);
                    }
                }
                APFS_TYPE_DIR_REC => {
                    if records.dir_entry_count >= MAX_DIR_ENTRIES {
                        // Record that the listing is short rather than dropping
                        // entries silently (BUG-215).
                        records.dir_entries_truncated = true;
                        continue;
                    }
                    if let (Some(name), Some(drec)) =
                        (parse_j_drec_name(key_data), parse_j_drec_val(val_data))
                    {
                        records
                            .dir_entries
                            .entry(oid)
                            .or_default()
                            .push((name, drec));
                        records.dir_entry_count += 1;
                    }
                }
                APFS_TYPE_FILE_EXTENT => {
                    if let Some(mut fext) = parse_j_file_extent_val(val_data) {
                        // Logical offset is in the key's offset field (lower 60 bits of extra key data)
                        if key_data.len() >= 16 {
                            fext.logical_offset = LittleEndian::read_u64(&key_data[8..16]);
                        }
                        // lower 56 bits
                        let length = fext.len_and_flags & 0x00FF_FFFF_FFFF_FFFF;
                        // `oid` here is the data-stream id (private_id), not the
                        // inode object id (BUG-206).
                        let extents = records.extents.entry(oid).or_default();
                        if extents.len() < MAX_EXTENTS {
                            extents.push(ApfsExtent {
                                logical_offset: fext.logical_offset,
                                length,
                                phys_block_num: fext.phys_block_num,
                                // Carried, not dropped: without it a
                                // per-file-encrypted extent maps as clear
                                // content (BUG-157).
                                crypto_id: fext.crypto_id,
                            });
                        } else {
                            // Dropping extents silently would sparse-fill the
                            // tail with zeros that look like real content
                            // (BUG-212); remember the stream is short.
                            records.truncated_streams.insert(oid);
                        }
                    }
                }
                APFS_TYPE_XATTR => {
                    // Only the two attributes that decide file content are
                    // retained; everything else would grow the map without a
                    // consumer (BUG-156).
                    let Some(name) = parse_j_xattr_name(key_data) else {
                        continue;
                    };
                    let is_decmpfs = name == XATTR_NAME_DECMPFS;
                    let is_resource_fork = name == XATTR_NAME_RESOURCE_FORK;
                    if !is_decmpfs && !is_resource_fork {
                        continue;
                    }
                    if let Some(value) = parse_j_xattr_val(val_data) {
                        let slot = records.xattrs.entry(oid).or_default();
                        if is_decmpfs {
                            slot.decmpfs = Some(value);
                        } else {
                            slot.resource_fork = Some(value);
                        }
                    }
                }
                _ => {}
            }
        }
    } else {
        // Internal node: recurse into children
        //
        // On a sealed volume the FS tree is a *hashed* tree, and its index values
        // are btn_index_node_val_t: an 8-byte child reference followed by the
        // child's hash. That reference is an offset from the tree's own root oid,
        // not an absolute virtual oid, so it must be rebased before the omap can
        // answer for it. Resolving the raw field instead misses every child and
        // silently loses the whole volume — 0 of 203,258 files on a real macOS
        // 13.7.4 system volume (LIVE-011).
        //
        // Every macOS 11 and later system volume is sealed, Intel included, so
        // this is the ordinary case for a modern image and not an edge case.
        let hashed = (node.flags & BTNODE_HASHED) != 0;
        for (_key_data, val_data) in &entries {
            if val_data.len() < 8 {
                continue;
            }
            let child_ref = LittleEndian::read_u64(&val_data[0..8]);
            // saturating_add so a corrupt reference cannot wrap to a low oid that
            // happens to resolve, which would walk an unrelated subtree as if it
            // belonged to this volume.
            let child_oid = if hashed {
                root_tree_oid.saturating_add(child_ref)
            } else {
                child_ref
            };

            match omap_lookup(
                data_source,
                vol_omap_tree_paddr,
                child_oid,
                block_size,
                true,
            ) {
                Ok(Some(child_paddr)) => {
                    if let Err(e) = walk_fs_btree(
                        data_source,
                        child_paddr,
                        block_size,
                        vol_omap_tree_paddr,
                        root_tree_oid,
                        records,
                        depth + 1,
                        visited,
                    ) {
                        // A subtree that would not walk is a slice of the
                        // filesystem missing from the inventory. Counted, not
                        // just logged: a log line never reaches the examiner
                        // looking at the volume (B2-133).
                        records.subtrees_unwalked += 1;
                        debug!(
                            "Failed to walk FS B-tree child OID {} at paddr {}: {}",
                            child_oid, child_paddr, e
                        );
                    }
                }
                Ok(None) => {
                    records.subtrees_unwalked += 1;
                    debug!("FS B-tree child OID {} not found in volume omap", child_oid);
                }
                Err(e) => {
                    records.subtrees_unwalked += 1;
                    debug!("Failed to resolve FS B-tree child OID {}: {}", child_oid, e);
                }
            }
        }
    }

    Ok(())
}

/// Outcome of walking one APFS volume.
struct VolumeWalk {
    artifacts: Vec<Artifact>,
    /// True when the global directory-entry cap dropped records, so the file
    /// inventory for this volume is short (BUG-215).
    dir_entries_truncated: bool,
    /// True when the inode cap dropped records, so files are missing from the
    /// inventory entirely (B2-097).
    inodes_truncated: bool,
    /// Count of FS B-tree subtrees that could not be walked (B2-133).
    subtrees_unwalked: usize,
    /// `om_snap_count` from the volume object map. This parser walks the LIVE
    /// tree only, so every snapshot here holds file versions (and files deleted
    /// since) that are not in the case (B7-006).
    snapshot_count: u32,
}

/// Attach the content of one non-empty regular file and describe it in metadata.
///
/// Returns the `DataSource` when the file's bytes could be located, `None` when
/// they could not. Every `None` also stamps `content_incomplete` and a reason:
/// a FileEntry carrying a non-zero `size` with no content and no reason is
/// indistinguishable from a genuinely empty file, and an examiner would read the
/// absence as evidence that the file held nothing (B2-093).
fn attach_file_content(
    metadata: &mut serde_json::Value,
    records: &FsRecords,
    ino: u64,
    private_id: u64,
    file_size: u64,
    block_size: u32,
    data_source: &Arc<dyn DataSource>,
) -> Option<Arc<dyn DataSource>> {
    if file_size > MAX_FILE_SIZE {
        // Over the DataSource ceiling: the file is real and its bytes are on the
        // image, but this parser does not map them.
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!("apfs_file_too_large");
        metadata["content_incomplete_limit"] = json!(MAX_FILE_SIZE);
        return None;
    }

    // decmpfs first. A transparently compressed file has NO data-stream extents
    // of its own — its bytes are in the `com.apple.decmpfs` attribute or in the
    // resource fork — so the extent lookup below finds nothing and the file was
    // reported unreadable on every macOS volume (BUG-156). Checking here also
    // retires the `apfs_no_extent_records` flag for those files: a warning that
    // fires on every compressed file on the volume teaches examiners to ignore
    // warnings.
    if let Some(xattrs) = records.xattrs.get(&ino) {
        if xattrs.decmpfs.is_some() {
            return attach_decmpfs_content(
                metadata,
                records,
                xattrs,
                file_size,
                block_size,
                data_source,
            );
        }
    }

    match records.stream_extents(ino, private_id) {
        Some((extents, stream_truncated)) if !extents.is_empty() => {
            apply_extent_metadata(metadata, extents, block_size, file_size, stream_truncated);
            // BUG-157: extents whose `crypto_id` names a crypto state hold
            // ciphertext. `apply_extent_metadata` has already withheld their
            // byte runs and flagged the artifact; withholding the DataSource
            // too is what stops the ingest from hashing, indexing and exporting
            // those blocks as the file's plaintext.
            let encrypted_count = extents.iter().filter(|e| e.is_encrypted()).count();
            if encrypted_count > 0 {
                warn!(
                    "APFS inode {} has {} encrypted extent(s); content withheld",
                    ino, encrypted_count
                );
                metadata["encryption"] = json!("apfs_per_extent_crypto");
                metadata["encrypted_extent_count"] = json!(encrypted_count);
                metadata["encrypted_extents"] = encrypted_extent_metadata(extents, block_size);
                mark_content_missing(
                    metadata,
                    "apfs_extent_encrypted",
                    format!(
                        "{encrypted_count} of {} extent(s) carry a non-zero crypto_id, so their \
                         blocks are ciphertext",
                        extents.len()
                    ),
                );
                return None;
            }
            Some(Arc::new(ApfsFileSource::new(
                Arc::clone(data_source),
                block_size,
                file_size,
                extents.clone(),
                !stream_truncated,
            )))
        }
        // A sized file whose data stream has no extent records and no decmpfs
        // attribute: the content lives somewhere this parser does not read.
        _ => {
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] = json!("apfs_no_extent_records");
            None
        }
    }
}

/// File slack (HUNT-282): one `SlackSpace` region per live regular file whose
/// last allocation block holds bytes past the file's logical end, plus the
/// volume's slack summary.
///
/// The window comes from the whole-block run list `apply_extent_metadata`
/// persists, through the one adapter FAT, exFAT, ext4 and HFS+ share. A file
/// with a tail whose run list is incomplete, encrypted or cut short, and a
/// compressed file (its data stream is empty by design), is counted as "could
/// not locate" and never as "no slack". A file reached under several names is
/// one inode and is offered once. Offsets are in the container's coordinate
/// space, which is `source`'s.
fn publish_file_slack(
    walked: &[Artifact],
    fs: &Artifact,
    source: &Arc<dyn DataSource>,
    block_size: u32,
) -> Vec<Artifact> {
    let mut slack = seance_core::slack::SlackCollector::new(
        seance_core::slack::SlackLabels {
            filesystem: "apfs",
            offset_basis: "the start of this container, not the start of the evidence",
        },
        u64::from(block_size),
    );
    let mut offered_inodes = std::collections::HashSet::new();
    for file in walked
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
    {
        let inode = file.metadata.get("inode").and_then(|v| v.as_u64());
        if inode.is_some_and(|i| !offered_inodes.insert(i)) {
            continue;
        }
        seance_core::slack::offer_live_file(
            &mut slack,
            fs,
            source,
            file,
            u64::from(block_size),
            &["compression", "content_encrypted"],
        );
    }
    slack.finish(fs).0
}

/// Record that a file's bytes were not reconstructed, and why.
///
/// A FileEntry carrying a non-zero `size` with no content and no reason is
/// indistinguishable from a genuinely empty file (B2-093), and a bare reason
/// code with no detail is indistinguishable from a parser that gave up.
fn mark_content_missing(metadata: &mut serde_json::Value, reason: &str, detail: String) {
    metadata["content_incomplete"] = json!(true);
    metadata["content_incomplete_reason"] = json!(reason);
    metadata["content_incomplete_detail"] = json!(detail);
}

/// Describe the extents whose blocks are ciphertext.
///
/// Content is withheld for these, but their location must not be: an examiner
/// has to be able to find the encrypted blocks and decrypt them out of band.
/// Withholding the bytes AND the location would make an encrypted file
/// indistinguishable from one that was never there (BUG-157).
fn encrypted_extent_metadata(extents: &[ApfsExtent], block_size: u32) -> serde_json::Value {
    json!(extents
        .iter()
        .filter(|e| e.is_encrypted())
        .map(|e| json!({
            "logical_offset": e.logical_offset,
            "length": e.length,
            "physical_offset": e.phys_offset(block_size, 0),
            "crypto_id": e.crypto_id,
        }))
        .collect::<Vec<_>>())
}

/// Reconstruct the content of a decmpfs (transparently compressed) file.
///
/// The compressed bytes are read, decoded in full, and served as the file's
/// content. Anything that stops that — an algorithm this parser cannot decode,
/// a resource fork that will not read, a decode that does not produce exactly
/// the declared logical size — returns `None` with the reason recorded. The
/// compressed bytes are NEVER returned as a fallback: they would be hashed,
/// indexed and exported as though they were the file (BUG-156).
fn attach_decmpfs_content(
    metadata: &mut serde_json::Value,
    records: &FsRecords,
    xattrs: &ApfsInodeXattrs,
    file_size: u64,
    block_size: u32,
    data_source: &Arc<dyn DataSource>,
) -> Option<Arc<dyn DataSource>> {
    metadata["compression"] = json!("apfs_decmpfs");

    let header_bytes = match xattrs.decmpfs.as_ref() {
        Some(ApfsXattrValue::Embedded(bytes)) => bytes.as_slice(),
        Some(ApfsXattrValue::Stream { stream_id, size }) => {
            mark_content_missing(
                metadata,
                "apfs_decmpfs_header_unreadable",
                format!(
                    "the com.apple.decmpfs attribute is a {size}-byte data stream (id {stream_id}) \
                     rather than an embedded value, which this parser does not read"
                ),
            );
            return None;
        }
        None => {
            mark_content_missing(
                metadata,
                "apfs_decmpfs_header_unreadable",
                "the com.apple.decmpfs attribute is absent".to_string(),
            );
            return None;
        }
    };

    let header = match decmpfs::parse_header(header_bytes) {
        Some(h) => h,
        None => {
            mark_content_missing(
                metadata,
                "apfs_decmpfs_header_unreadable",
                format!(
                    "the com.apple.decmpfs attribute is {} byte(s) and does not carry the decmpfs \
                     magic",
                    header_bytes.len()
                ),
            );
            return None;
        }
    };
    metadata["decmpfs_compression_type"] = json!(header.compression_type);
    metadata["decmpfs_logical_size"] = json!(header.uncompressed_size);
    // The attribute value IS the content location: for inline storage it holds
    // the compressed stream itself, and for a resource fork it carries the
    // parameters the decoder needs to read one. It lives in the FS B-tree,
    // which nothing re-walks once ingest is over, so without it here a
    // compressed file has no recoverable location at all and can never be read,
    // exported or re-hashed after ingest (LIVE-001). Recorded even on the paths
    // that withhold content below, for the same reason encrypted extents keep
    // their location: the bytes are withheld, where they live is not. An
    // embedded xattr value is bounded by its u16 length field.
    metadata["decmpfs_attribute_b64"] = json!(BASE64.encode(header_bytes));

    // The inode and decmpfs must agree on how long the file is. If they do not,
    // decoding to either length would assert a size neither record supports.
    if header.uncompressed_size != file_size {
        mark_content_missing(
            metadata,
            "apfs_decmpfs_size_mismatch",
            format!(
                "the inode records {file_size} byte(s) but decmpfs records {}",
                header.uncompressed_size
            ),
        );
        return None;
    }

    let scheme = match decmpfs::scheme(header.compression_type) {
        Some(s) => s,
        None => {
            mark_content_missing(
                metadata,
                "apfs_decmpfs_unsupported_algorithm",
                format!(
                    "decmpfs compression type {} is not decoded by this parser (types 11 and 12 \
                     are LZFSE)",
                    header.compression_type
                ),
            );
            return None;
        }
    };
    metadata["compression_format"] = json!(scheme.format_label());
    metadata["compression_algorithm"] = json!(scheme.algorithm_label());
    metadata["compression_storage"] = json!(scheme.storage_label());

    if file_size > MAX_DECMPFS_DECODED {
        mark_content_missing(
            metadata,
            "apfs_decmpfs_too_large",
            format!(
                "decoding needs {file_size} byte(s) of memory, above this parser's ceiling of \
                 {MAX_DECMPFS_DECODED}"
            ),
        );
        metadata["content_incomplete_limit"] = json!(MAX_DECMPFS_DECODED);
        return None;
    }

    let payload: Vec<u8> = match scheme.storage {
        decmpfs::Storage::InlineXattr => {
            metadata["compressed_bytes"] = json!(header_bytes
                .len()
                .saturating_sub(decmpfs::DECMPFS_HEADER_LEN));
            header_bytes[decmpfs::DECMPFS_HEADER_LEN..].to_vec()
        }
        decmpfs::Storage::ResourceFork => {
            let (stream_id, stream_size) = match xattrs.resource_fork.as_ref() {
                Some(ApfsXattrValue::Stream { stream_id, size }) => (*stream_id, *size),
                _ => {
                    mark_content_missing(
                        metadata,
                        "apfs_decmpfs_resource_fork_missing",
                        "decmpfs stores this file in a resource fork, but com.apple.ResourceFork \
                         is absent or is not a data stream"
                            .to_string(),
                    );
                    return None;
                }
            };
            metadata["compressed_bytes"] = json!(stream_size);
            metadata["resource_fork_stream_id"] = json!(stream_id);

            if stream_size > MAX_DECMPFS_COMPRESSED {
                mark_content_missing(
                    metadata,
                    "apfs_decmpfs_resource_fork_too_large",
                    format!(
                        "the resource fork is {stream_size} byte(s), above this parser's ceiling \
                         of {MAX_DECMPFS_COMPRESSED}"
                    ),
                );
                return None;
            }

            let (extents, truncated) = match records.stream_extents(stream_id, stream_id) {
                Some((e, t)) if !e.is_empty() => (e, t),
                _ => {
                    mark_content_missing(
                        metadata,
                        "apfs_decmpfs_resource_fork_no_extents",
                        format!("resource-fork data stream {stream_id} has no extent records"),
                    );
                    return None;
                }
            };
            if truncated {
                mark_content_missing(
                    metadata,
                    "apfs_max_extents",
                    format!(
                        "the resource-fork extent list for stream {stream_id} hit the \
                         {MAX_EXTENTS}-extent cap, so the compressed stream is short"
                    ),
                );
                return None;
            }

            // Where the COMPRESSED bytes live. Deliberately NOT `data_runs`:
            // consumers read that key as the file's own bytes, and re-serving
            // these would hand back a compressed stream (BUG-156).
            let ExtentRuns {
                runs,
                unmappable,
                encrypted,
            } = extent_runs(extents, block_size, stream_size);
            let (runs_json, complete) = seance_core::data_source::byte_runs_to_metadata(&runs);
            metadata["compressed_data_runs"] = runs_json;
            metadata["compressed_data_runs_complete"] =
                json!(complete && !unmappable && !encrypted);

            if encrypted {
                let encrypted_count = extents.iter().filter(|e| e.is_encrypted()).count();
                metadata["content_encrypted"] = json!(true);
                metadata["encryption"] = json!("apfs_per_extent_crypto");
                metadata["encrypted_extent_count"] = json!(encrypted_count);
                metadata["encrypted_extents"] = encrypted_extent_metadata(extents, block_size);
                mark_content_missing(
                    metadata,
                    "apfs_extent_encrypted",
                    format!(
                        "resource-fork stream {stream_id} has {encrypted_count} encrypted extent(s)"
                    ),
                );
                return None;
            }
            if unmappable {
                mark_content_missing(
                    metadata,
                    "apfs_extent_offset_overflow",
                    format!("resource-fork stream {stream_id} has an unlocatable extent"),
                );
                return None;
            }

            let source = ApfsFileSource::new(
                Arc::clone(data_source),
                block_size,
                stream_size,
                extents.clone(),
                true,
            );
            let mut buf = vec![0u8; stream_size as usize];
            if let Err(e) = read_exact_or_fail(&source, 0, &mut buf, "APFS decmpfs resource fork") {
                mark_content_missing(
                    metadata,
                    "apfs_decmpfs_resource_fork_unreadable",
                    format!("resource-fork stream {stream_id} did not read: {e}"),
                );
                return None;
            }
            buf
        }
    };

    match decmpfs::decode(scheme, &payload, file_size as usize) {
        Ok(bytes) => {
            metadata["compressed"] = json!(true);
            Some(Arc::new(
                seance_core::data_source::ByteSliceDataSource::new(bytes),
            ))
        }
        Err(e) => {
            mark_content_missing(metadata, "apfs_decmpfs_decode_failed", e);
            None
        }
    }
}

/// Rebuild a decmpfs-compressed file's plaintext from the content location its
/// artifact records.
///
/// Ingest decodes a compressed file in memory, but that buffer is gone by the
/// time an examiner asks for the file. The artifact's own byte runs describe
/// nothing (a compressed file has no data-stream extents), so every
/// transparently compressed file on a macOS volume resolved to "no recorded
/// content location" — unreadable, unexportable, unhashable (LIVE-001). This is
/// the read side of the location `attach_decmpfs_content` persists: given the
/// same filesystem window the parser walked and the artifact metadata, it
/// reproduces exactly the bytes ingest hashed.
///
/// `fs_window` is the filesystem-window data source `compressed_data_runs`
/// offsets are relative to — the same coordinate space as `data_runs`.
///
/// Fail-closed, like the decoder underneath: every path either returns the
/// file's complete decoded bytes or an error naming why it could not. The
/// compressed bytes are never returned as a fallback (BUG-156).
pub fn reconstruct_decmpfs_content(
    fs_window: Arc<dyn DataSource>,
    metadata: &serde_json::Value,
) -> Result<Vec<u8>, String> {
    let encoded = metadata
        .get("decmpfs_attribute_b64")
        .and_then(|v| v.as_str())
        .ok_or(
            "the artifact records no decmpfs_attribute_b64, so the compressed content location is \
             unknown; re-ingest the evidence with the updated parser",
        )?;
    let attribute = BASE64
        .decode(encoded)
        .map_err(|e| format!("decmpfs_attribute_b64 is not valid base64: {e}"))?;
    let header = decmpfs::parse_header(&attribute).ok_or_else(|| {
        format!(
            "decmpfs_attribute_b64 holds {} byte(s) and does not carry the decmpfs magic",
            attribute.len()
        )
    })?;
    let scheme = decmpfs::scheme(header.compression_type).ok_or_else(|| {
        format!(
            "decmpfs compression type {} is not decoded by this parser (types 11 and 12 are LZFSE)",
            header.compression_type
        )
    })?;

    // The artifact's size and decmpfs's own must agree, exactly as the inode's
    // and decmpfs's had to at ingest: decoding to either length would assert a
    // size the other record does not support.
    if let Some(size) = metadata.get("size").and_then(|v| v.as_u64()) {
        if size != header.uncompressed_size {
            return Err(format!(
                "the artifact records {size} byte(s) but decmpfs records {}",
                header.uncompressed_size
            ));
        }
    }
    let logical = header.uncompressed_size;
    if logical > MAX_DECMPFS_DECODED {
        return Err(format!(
            "decoding needs {logical} byte(s) of memory, above this parser's ceiling of \
             {MAX_DECMPFS_DECODED}"
        ));
    }

    let payload: Vec<u8> = match scheme.storage {
        decmpfs::Storage::InlineXattr => attribute[decmpfs::DECMPFS_HEADER_LEN..].to_vec(),
        decmpfs::Storage::ResourceFork => {
            let stream_size = metadata
                .get("compressed_bytes")
                .and_then(|v| v.as_u64())
                .ok_or(
                    "decmpfs stores this file in a resource fork, but the artifact records no \
                     compressed_bytes length",
                )?;
            if stream_size > MAX_DECMPFS_COMPRESSED {
                return Err(format!(
                    "the resource fork is {stream_size} byte(s), above this parser's ceiling of \
                     {MAX_DECMPFS_COMPRESSED}"
                ));
            }
            // A run list the parser already declared short would decode to
            // whatever the missing bytes happened to leave behind, which is not
            // the file.
            if metadata
                .get("compressed_data_runs_complete")
                .and_then(|v| v.as_bool())
                != Some(true)
            {
                return Err(
                    "the compressed-stream run list is incomplete, so the resource fork cannot be \
                     read whole"
                        .to_string(),
                );
            }
            let runs = parse_metadata_runs(
                metadata
                    .get("compressed_data_runs")
                    .ok_or("the artifact records no compressed_data_runs")?,
            )?;
            // Short runs must fail rather than be zero-padded by the run source:
            // padding would hand the decoder fabricated bytes.
            let allocated = runs
                .iter()
                .fold(0u64, |acc, (_, len)| acc.saturating_add(*len));
            if allocated < stream_size {
                return Err(format!(
                    "compressed_data_runs describe {allocated} byte(s) of a {stream_size}-byte \
                     resource fork"
                ));
            }
            let source = seance_core::data_source::RunListDataSource::with_logical_size(
                fs_window,
                runs,
                stream_size,
            );
            let mut buf = vec![0u8; stream_size as usize];
            read_exact_or_fail(&source, 0, &mut buf, "APFS decmpfs resource fork")
                .map_err(|e| format!("the resource fork did not read: {e}"))?;
            buf
        }
    };

    decmpfs::decode(scheme, &payload, logical as usize)
}

/// Parse a persisted `[[offset|null, length], ...]` run list back into byte
/// runs, as `byte_runs_to_metadata` wrote it.
fn parse_metadata_runs(value: &serde_json::Value) -> Result<Vec<(Option<u64>, u64)>, String> {
    let arr = value
        .as_array()
        .ok_or("the recorded run list is not an array")?;
    let mut runs = Vec::with_capacity(arr.len());
    for run in arr {
        let pair = run
            .as_array()
            .filter(|p| p.len() == 2)
            .ok_or("a run is not an [offset, length] pair")?;
        let offset = if pair[0].is_null() {
            None
        } else {
            Some(pair[0].as_u64().ok_or("a run offset is not an integer")?)
        };
        let length = pair[1].as_u64().ok_or("a run length is not an integer")?;
        runs.push((offset, length));
    }
    Ok(runs)
}

/// Walk a complete APFS volume filesystem and produce FileEntry artifacts.
fn walk_volume_filesystem(
    data_source: &Arc<dyn DataSource>,
    nx_sb: &NxSuperblock,
    vol_sb: &ApfsSuperblock,
    case_id: uuid::Uuid,
    artifact_id: uuid::Uuid,
) -> Result<VolumeWalk, ModuleError> {
    // Read volume omap
    let vol_omap = parse_omap(data_source.as_ref(), vol_sb.omap_oid, nx_sb.block_size)?;
    debug!(
        "Volume '{}' OMap tree at physical block {}",
        vol_sb.vol_name, vol_omap.tree_oid
    );

    // Resolve FS tree root OID via volume omap
    let fs_root_paddr = omap_lookup(
        data_source.as_ref(),
        vol_omap.tree_oid,
        vol_sb.root_tree_oid,
        nx_sb.block_size,
        true,
    )?
    .ok_or_else(|| {
        ModuleError::ParsingError(format!(
            "FS tree root OID {} not found in volume omap",
            vol_sb.root_tree_oid
        ))
    })?;
    debug!(
        "FS tree root at physical block {} (OID {})",
        fs_root_paddr, vol_sb.root_tree_oid
    );

    // Walk FS B-tree
    let mut records = FsRecords::new();

    walk_fs_btree(
        data_source.as_ref(),
        fs_root_paddr,
        nx_sb.block_size,
        vol_omap.tree_oid,
        vol_sb.root_tree_oid,
        &mut records,
        0,
        &mut std::collections::HashSet::new(),
    )?;

    debug!(
        "Collected {} inodes, {} dir entry groups, {} extent groups",
        records.inodes.len(),
        records.dir_entries.len(),
        records.extents.len()
    );

    // Sort extents by logical offset for each inode
    for extents in records.extents.values_mut() {
        extents.sort_by_key(|e| e.logical_offset);
    }

    // Build path map by BFS from root directory (inode 2)
    let mut paths: HashMap<u64, String> = HashMap::new();
    paths.insert(APFS_ROOT_DIR_INO, "/".to_string());
    // Every name each inode is reachable under, in discovery order. A
    // hardlinked file has ONE inode record and several directory entries, so
    // overwriting `paths` kept only the last name and every other path the
    // file lived at vanished from the case (B7-007).
    let mut all_paths: HashMap<u64, Vec<String>> = HashMap::new();
    // `date_added` lives on the directory entry, not the inode, so a
    // hardlinked file can in principle carry a different value per name. The
    // canonical (first-discovered) entry is the one whose name and path win
    // in `paths` above, so its `date_added` is what is published on the
    // FileEntry — the same entry, not a second, independently-chosen one.
    let mut date_added_by_ino: HashMap<u64, u64> = HashMap::new();

    let mut queue: VecDeque<u64> = VecDeque::new();
    queue.push_back(APFS_ROOT_DIR_INO);

    while let Some(parent_ino) = queue.pop_front() {
        if let Some(entries) = records.dir_entries.get(&parent_ino) {
            let parent_path = paths.get(&parent_ino).cloned().unwrap_or_default();
            for (name, drec) in entries {
                if name == "." || name == ".." {
                    continue;
                }
                let child_ino = drec.file_id;
                let child_path = if parent_path == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", parent_path, name)
                };
                record_inode_path(&mut paths, &mut all_paths, child_ino, child_path);
                date_added_by_ino
                    .entry(child_ino)
                    .or_insert(drec.date_added);

                // If child is a directory, enqueue for further traversal
                let entry_type = drec.flags & 0x000F;
                if entry_type == DT_DIR {
                    queue.push_back(child_ino);
                }
            }
        }
    }

    // Generate FileEntry artifacts
    let mut produced_artifacts = Vec::new();
    let vol_name = &vol_sb.vol_name;
    let vol_uuid_str = format_uuid(&vol_sb.vol_uuid);

    for (ino, inode) in &records.inodes {
        let path = match paths.get(ino) {
            Some(p) => p.clone(),
            None => continue, // Orphan inode
        };

        let name = if path == "/" {
            "/".to_string()
        } else {
            std::path::Path::new(&path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        };

        let parent_path = std::path::Path::new(&path)
            .parent()
            .map(|p| {
                let s = p.to_string_lossy().to_string();
                if s.is_empty() {
                    "/".to_string()
                } else {
                    s
                }
            })
            .unwrap_or_else(|| "/".to_string());

        let is_directory = (inode.mode & 0o170000) == 0o040000;
        let is_regular_file = (inode.mode & 0o170000) == 0o100000;
        let is_symlink = (inode.mode & 0o170000) == 0o120000;

        let file_size = if is_regular_file {
            inode.dstream_size.unwrap_or(inode.uncompressed_size)
        } else {
            0
        };

        let mut metadata = json!({
            "name": name,
            "path": path,
            "parent_path": parent_path,
            "inode": ino,
            "mode": inode.mode,
            "uid": inode.owner,
            "gid": inode.group,
            "size": file_size,
            "created": format_apfs_timestamp(inode.create_time),
            "modified": format_apfs_timestamp(inode.mod_time),
            "changed": format_apfs_timestamp(inode.change_time),
            "accessed": format_apfs_timestamp(inode.access_time),
            "is_directory": is_directory,
            "is_symlink": is_symlink,
            "volume_name": vol_name,
            "volume_uuid": vol_uuid_str,
        });

        // `date_added` lives on the directory entry, not the inode, so the
        // root directory (which is nobody's child) has none — omitted rather
        // than published as an empty/zero string, the same not-there-vs-
        // could-not-look distinction the cap flags elsewhere in this walk draw.
        if let Some(&date_added) = date_added_by_ino.get(ino) {
            metadata["date_added"] = json!(format_apfs_timestamp(date_added as i64));
        }

        // Hardlink names. A directory's link count tracks its children, not
        // alternate names, so only files carry this (B7-007).
        if !is_directory {
            let names = all_paths.get(ino).map(|v| v.as_slice()).unwrap_or(&[]);
            if names.len() > 1 {
                metadata["hardlink_paths"] = json!(names);
            }
            let nlink = inode.nchildren_or_nlink.max(0) as usize;
            if nlink > 1 {
                let known = names.len().max(1);
                metadata["hardlink_paths_known"] = json!(known);
                metadata["hardlink_paths_complete"] = json!(known >= nlink);
                if known < nlink {
                    // The inode claims more names than the directory tree gave
                    // us; the missing ones are unresolved, not absent.
                    metadata["inventory_incomplete"] = json!(true);
                    metadata["inventory_incomplete_reason"] =
                        json!("apfs_hardlink_names_unresolved");
                }
            }
        }

        // Build DataSource for regular files with extents, and persist the
        // filesystem-window byte runs so the content resolver can re-serve the
        // file from the DB (not just during ingestion). Extents are keyed by the
        // inode's data-stream id, not its object id (BUG-206).
        let file_source = if is_regular_file && file_size > 0 {
            attach_file_content(
                &mut metadata,
                &records,
                *ino,
                inode.private_id,
                file_size,
                nx_sb.block_size,
                data_source,
            )
        } else {
            None
        };

        produced_artifacts.push(
            Artifact::new(case_id, ArtifactType::FileEntry, file_source, metadata)
                .with_parent(artifact_id),
        );
    }

    Ok(VolumeWalk {
        artifacts: produced_artifacts,
        dir_entries_truncated: records.dir_entries_truncated,
        inodes_truncated: records.inodes_truncated,
        subtrees_unwalked: records.subtrees_unwalked,
        snapshot_count: vol_omap.snap_count,
    })
}

// --- Utilities ---

/// Record one directory-entry path for `ino`.
///
/// A hardlinked file has ONE inode record and several directory entries. A
/// plain `paths.insert` kept only the last name seen, so every other path the
/// file lived at vanished from the case and "this file was never at path X"
/// could be answered falsely (B7-007). The first name discovered stays
/// canonical so the emitted path is stable; the rest are kept alongside it.
fn record_inode_path(
    paths: &mut HashMap<u64, String>,
    all_paths: &mut HashMap<u64, Vec<String>>,
    ino: u64,
    path: String,
) {
    all_paths.entry(ino).or_default().push(path.clone());
    paths.entry(ino).or_insert(path);
}

fn format_apfs_timestamp(nanos: i64) -> String {
    // Euclidean division so pre-1970 (negative) timestamps round toward
    // negative infinity with a non-negative nanosecond remainder.
    let secs = nanos.div_euclid(1_000_000_000);
    let nsec = nanos.rem_euclid(1_000_000_000) as u32;
    DateTime::from_timestamp(secs, nsec)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decmpfs::tests::{decmpfs_xattr, lzvn_resource_fork};
    use crate::lzvn::tests::{real_tail_chunk, real_tail_expected};
    use seance_core::data_source::ByteSliceDataSource;

    #[test]
    fn read_block_fails_closed_on_short_read() {
        // A backing source shorter than one block simulates a truncated image /
        // mid-block I/O error. read_block must refuse rather than hand callers a
        // zero-padded block they would parse as fabricated records (BUG-155).
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xABu8; 100]));
        let result = read_block(src.as_ref(), 0, 4096);
        assert!(
            result.is_err(),
            "a short read of an APFS block must fail closed"
        );
    }

    /// Real-volume regression: parse the APFS container inside the committed-only
    /// `test_data/apfs.dmg` (a GPT raw image; the APFS container begins at byte
    /// offset 20480). Exercises the real omap resolution and filesystem B-tree
    /// walk that synthetic single-node fixtures never reach. Gated on the image
    /// being present so CI (where test_data is absent) stays green.
    #[test]
    fn apfs_real_volume_parses() {
        use seance_core::data_source::{FileDataSource, WindowSource};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test_data/apfs.dmg");
        if !path.exists() {
            eprintln!(
                "skipping apfs_real_volume_parses: {} not present",
                path.display()
            );
            return;
        }
        let file_len = std::fs::metadata(&path).unwrap().len();
        const CONTAINER_OFFSET: u64 = 20480;
        let inner: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
        let window = WindowSource::new(inner, CONTAINER_OFFSET, file_len - CONTAINER_OFFSET);
        let src: Arc<dyn DataSource> = Arc::new(window);
        let art = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(src),
            json!({ "subtype": "apfs" }),
        );
        // Must not panic and must not hard-error on a well-formed real volume.
        let out = ApfsParser
            .process(&art)
            .expect("APFS process must not error on a real volume");
        eprintln!("apfs_real_volume_parses: produced {} artifacts", out.len());
        assert!(!out.is_empty(), "real APFS volume should yield artifacts");
    }

    /// A real FileVault-encrypted APFS volume must be parsed without panicking:
    /// the container/volume superblocks are readable but the filesystem records
    /// are encrypted, so the parser should surface what it can (container/volume
    /// structure) and not crash on the undecryptable B-tree. The assertion is
    /// simply that `process` returns (Ok or a clean error), never a panic.
    #[test]
    fn apfs_encrypted_volume_handled_gracefully() {
        use seance_core::data_source::{FileDataSource, WindowSource};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test_data/apfs_encrypted.dmg");
        if !path.exists() {
            eprintln!("skipping apfs_encrypted_volume_handled_gracefully: image not present");
            return;
        }
        let file_len = std::fs::metadata(&path).unwrap().len();
        const CONTAINER_OFFSET: u64 = 20480;
        let inner: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
        let window = WindowSource::new(inner, CONTAINER_OFFSET, file_len - CONTAINER_OFFSET);
        let src: Arc<dyn DataSource> = Arc::new(window);
        let art = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(src),
            json!({ "subtype": "apfs" }),
        );
        // Either outcome is acceptable; a panic (unwrap on encrypted records,
        // arithmetic overflow) is not.
        let result = ApfsParser.process(&art);
        eprintln!(
            "apfs_encrypted_volume_handled_gracefully: {:?}",
            result.as_ref().map(|v| v.len())
        );
    }

    #[test]
    fn test_module_metadata() {
        let module = ApfsParser;
        assert_eq!(module.id(), "plugin.filesystem.apfs");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(module.subscribes_to(), vec![ArtifactType::FileSystem]);
        assert_eq!(module.input_capability(), InputCapability::RandomAccess);
    }

    #[test]
    fn test_format_apfs_timestamp_negative_rounds_correctly() {
        // 1 ns before the epoch is 1969-12-31T23:59:59.999999999Z; truncating
        // division would produce a bogus 1970-01-01T00:00:00.000000001Z.
        let s = format_apfs_timestamp(-1);
        assert!(
            s.starts_with("1969-12-31T23:59:59.999999999"),
            "pre-1970 timestamp rounded wrong: {}",
            s
        );

        // -1.5s before the epoch
        let s = format_apfs_timestamp(-1_500_000_000);
        assert!(
            s.starts_with("1969-12-31T23:59:58.5"),
            "pre-1970 timestamp rounded wrong: {}",
            s
        );

        // Positive values are unaffected
        let s = format_apfs_timestamp(1_700_000_000_000_000_000);
        assert!(s.starts_with("2023-11-14"), "got {}", s);
    }

    #[test]
    fn test_parse_obj_phys() {
        let mut data = vec![0u8; 32];
        LittleEndian::write_u64(&mut data[0..8], 0xDEADBEEF); // cksum
        LittleEndian::write_u64(&mut data[8..16], 42); // oid
        LittleEndian::write_u64(&mut data[16..24], 100); // xid
        LittleEndian::write_u32(&mut data[24..28], 0x40000001); // o_type (physical NX superblock)
        LittleEndian::write_u32(&mut data[28..32], 0); // o_subtype

        let obj = parse_obj_phys(&data, 0).unwrap();
        assert_eq!(obj.cksum, 0xDEADBEEF);
        assert_eq!(obj.oid, 42);
        assert_eq!(obj.xid, 100);
        assert_eq!(obj.o_type, 0x40000001);
        assert_eq!(obj.o_subtype, 0);
    }

    #[test]
    fn test_parse_obj_phys_too_short() {
        let data = vec![0u8; 16];
        assert!(parse_obj_phys(&data, 0).is_err());
    }

    #[test]
    fn test_parse_nx_superblock() {
        let block_size: u32 = 4096;
        let mut data = vec![0u8; block_size as usize];

        // Object header
        LittleEndian::write_u64(&mut data[8..16], 1); // oid
        LittleEndian::write_u64(&mut data[16..24], 1); // xid
        LittleEndian::write_u32(&mut data[24..28], 0x40000001); // type

        // NX superblock fields
        LittleEndian::write_u32(&mut data[32..36], NXSB_MAGIC); // magic
        LittleEndian::write_u32(&mut data[36..40], block_size); // block_size
        LittleEndian::write_u64(&mut data[40..48], 1000); // block_count
        LittleEndian::write_u64(&mut data[160..168], 5); // omap_oid
        LittleEndian::write_u64(&mut data[168..176], 0xDEAD_BEEF); // nx_reaper_oid — NOT the count
        LittleEndian::write_u32(&mut data[180..184], 2); // max_file_systems

        // fs_oid array at offset 184
        LittleEndian::write_u64(&mut data[184..192], 100); // volume 0 OID
        LittleEndian::write_u64(&mut data[192..200], 200); // volume 1 OID

        let ds = ByteSliceDataSource::new(data);
        let sb = parse_nx_superblock(&ds).unwrap();

        assert_eq!(sb.magic, NXSB_MAGIC);
        assert_eq!(sb.block_size, block_size);
        assert_eq!(sb.block_count, 1000);
        assert_eq!(sb.omap_oid, 5);
        assert_eq!(sb.max_file_systems, 2);
        assert_eq!(sb.fs_oid, vec![100, 200]);
    }

    #[test]
    fn selects_latest_checkpoint_over_stale_block0() {
        // Block 0 is a stale container superblock (xid 2, omap 5). The checkpoint
        // descriptor area holds newer nx_superblocks; the parser must adopt the
        // highest-xid one (xid 9, omap 99), not block 0.
        let bs = 4096usize;
        let mut img = vec![0u8; bs * 4];
        let write_nxsb = |img: &mut [u8], blk: usize, xid: u64, omap: u64, desc_base: u64| {
            let o = blk * bs;
            LittleEndian::write_u64(&mut img[o + 16..o + 24], xid);
            LittleEndian::write_u32(
                &mut img[o + 24..o + 28],
                0x40000000 | OBJ_TYPE_NX_SUPERBLOCK as u32,
            );
            LittleEndian::write_u32(&mut img[o + 32..o + 36], NXSB_MAGIC);
            LittleEndian::write_u32(&mut img[o + 36..o + 40], bs as u32);
            LittleEndian::write_u64(&mut img[o + 40..o + 48], 1000);
            LittleEndian::write_u32(&mut img[o + 104..o + 108], 3); // desc_blocks
            LittleEndian::write_u64(&mut img[o + 112..o + 120], desc_base);
            LittleEndian::write_u64(&mut img[o + 160..o + 168], omap);
            LittleEndian::write_u64(&mut img[o + 184..o + 192], 100); // a volume oid
        };
        write_nxsb(&mut img, 0, 2, 5, 1); // block 0: stale, desc area starts at block 1
        write_nxsb(&mut img, 1, 5, 55, 1); // desc[0]: newer
        write_nxsb(&mut img, 2, 9, 99, 1); // desc[1]: newest
                                           // block 3 left as a non-NXSB block (all zeros) — must be ignored.

        let ds = ByteSliceDataSource::new(img);
        let sb = parse_nx_superblock(&ds).unwrap();
        assert_eq!(
            sb.omap_oid, 99,
            "must use the highest-xid checkpoint's omap"
        );
    }

    #[test]
    fn test_nx_superblock_bad_magic() {
        let mut data = vec![0u8; 4096];
        LittleEndian::write_u32(&mut data[32..36], 0xBADBAD); // wrong magic
        LittleEndian::write_u32(&mut data[36..40], 4096); // block_size

        let ds = ByteSliceDataSource::new(data);
        let result = parse_nx_superblock(&ds);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid APFS container magic"));
    }

    /// B3-019: `nx_max_file_systems` beyond the parser's own `MAX_VOLUMES` cap
    /// used to be silently clamped. What an examiner learns from the count: how
    /// many volumes the container names that this parse will not even attempt.
    /// A wrong answer looks like a container reported as holding 100 volumes
    /// when it declares 200, with no marker anywhere.
    #[test]
    fn declared_volume_slots_beyond_the_cap_are_counted_not_just_clamped() {
        let block_size: u32 = 4096;
        let mut data = vec![0u8; block_size as usize];
        LittleEndian::write_u32(&mut data[24..28], 0x4000_0001);
        LittleEndian::write_u32(&mut data[32..36], NXSB_MAGIC);
        LittleEndian::write_u32(&mut data[36..40], block_size);
        LittleEndian::write_u32(&mut data[180..184], (MAX_VOLUMES as u32) + 7);
        LittleEndian::write_u64(&mut data[184..192], 42); // one reachable volume OID

        let sb = parse_nx_superblock(&ByteSliceDataSource::new(data)).unwrap();
        assert_eq!(sb.fs_oid, vec![42]);
        assert_eq!(
            sb.fs_oid_slots_skipped, 7,
            "volume slots past the cap must be counted, not quietly dropped"
        );
    }

    /// B3-019: a container whose named volumes cannot be resolved produced a
    /// bare empty artifact list — indistinguishable from a container that holds
    /// no volumes. The container-level marker is what tells them apart.
    #[test]
    fn unresolvable_volumes_emit_a_container_incompleteness_marker() {
        let block_size: usize = 4096;
        let mut image = vec![0u8; block_size * 3];

        // Block 0: container superblock naming one volume OID and one more
        // volume slot than this parser will read.
        LittleEndian::write_u32(&mut image[24..28], 0x4000_0001);
        LittleEndian::write_u32(&mut image[32..36], NXSB_MAGIC);
        LittleEndian::write_u32(&mut image[36..40], block_size as u32);
        LittleEndian::write_u64(&mut image[40..48], 3); // block_count
        LittleEndian::write_u64(&mut image[160..168], 1); // nx_omap_oid -> block 1
        LittleEndian::write_u32(&mut image[180..184], (MAX_VOLUMES as u32) + 1);
        LittleEndian::write_u64(&mut image[184..192], 42); // fs_oid[0]

        // Block 1: container object map pointing at block 2.
        let b1 = block_size;
        LittleEndian::write_u32(&mut image[b1 + 24..b1 + 28], 0x4000_000B);
        LittleEndian::write_u64(&mut image[b1 + 48..b1 + 56], 2); // om_tree_oid

        // Block 2: an empty leaf B-tree node, so OID 42 resolves to nothing.
        let b2 = block_size * 2;
        LittleEndian::write_u32(&mut image[b2 + 24..b2 + 28], 0x4000_0003);
        LittleEndian::write_u16(
            &mut image[b2 + 32..b2 + 34],
            BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE,
        );

        let art = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::new(ByteSliceDataSource::new(image)) as Arc<dyn DataSource>),
            json!({ "subtype": "apfs" }),
        );
        let produced = ApfsParser.process(&art).expect("process ok");

        let marker = produced
            .iter()
            .find(|a| a.metadata["type"] == json!("ApfsContainerIncomplete"))
            .expect("a container that lost volumes must say so");
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(marker.metadata["volume_slots_skipped"], json!(1));
        assert_eq!(marker.metadata["volumes_unreadable"], json!(1));
        assert_eq!(marker.metadata["volumes_reported"], json!(0));
    }

    #[test]
    fn test_nx_superblock_absurd_block_size_rejected() {
        // Latent OOM: block_size = 0xFFFFFFFF would drive buf.resize() to a ~4 GiB
        // allocation. parse_nx_superblock must reject an out-of-range block size
        // before resizing.
        let mut data = vec![0u8; 4096];
        LittleEndian::write_u32(&mut data[32..36], NXSB_MAGIC);
        LittleEndian::write_u32(&mut data[36..40], 0xFFFF_FFFF); // block_size
        let ds = ByteSliceDataSource::new(data);
        let result = parse_nx_superblock(&ds);
        assert!(result.is_err(), "absurd block size must be rejected");
        assert!(
            result.unwrap_err().to_string().contains("block size"),
            "expected a block-size error"
        );
    }

    #[test]
    fn test_nx_superblock_short_block_reread_fails_closed() {
        // block_size (8192) exceeds what the image actually holds (4096). The
        // re-read that widens the probe buffer to a full block must fail closed:
        // the superblock fields and its Fletcher-64 span the whole block, so a
        // zero-padded tail would be parsed and checksummed as real content.
        let mut data = vec![0u8; 4096];
        LittleEndian::write_u32(&mut data[32..36], NXSB_MAGIC);
        LittleEndian::write_u32(&mut data[36..40], 8192); // block_size > image
        let ds = ByteSliceDataSource::new(data);
        let err = parse_nx_superblock(&ds)
            .expect_err("a container superblock larger than the image must not parse");
        assert!(
            err.to_string().contains("short read"),
            "expected a short-read error, got: {err}"
        );
    }

    #[test]
    fn test_truncated_checkpoint_slot_is_not_adopted() {
        // The checkpoint descriptor ring is scanned for the highest-xid
        // nx_superblock. A slot that is only partially present must be SKIPPED,
        // not adopted from a zero-padded buffer: its header bytes can look newer
        // than block 0 while every field past the truncation point reads as zero.
        let bs = 4096usize;
        let mut img = vec![0u8; bs + 100]; // block 0 whole, block 1 cut off at 100

        // Block 0: a valid stale superblock (xid 2) whose omap is 5.
        LittleEndian::write_u64(&mut img[16..24], 2); // xid
        LittleEndian::write_u32(
            &mut img[24..28],
            0x4000_0000 | OBJ_TYPE_NX_SUPERBLOCK as u32,
        );
        LittleEndian::write_u32(&mut img[32..36], NXSB_MAGIC);
        LittleEndian::write_u32(&mut img[36..40], bs as u32);
        LittleEndian::write_u64(&mut img[40..48], 1000); // block_count
        LittleEndian::write_u32(&mut img[104..108], 1); // desc_blocks
        LittleEndian::write_u64(&mut img[112..120], 1); // desc_base == block 1
        LittleEndian::write_u64(&mut img[160..168], 5); // omap_oid

        // Block 1: only the first 100 bytes exist, but they advertise a NEWER
        // superblock (xid 9). Everything beyond — including its omap_oid at
        // +160 — is absent.
        let o = bs;
        LittleEndian::write_u64(&mut img[o + 16..o + 24], 9); // xid
        LittleEndian::write_u32(
            &mut img[o + 24..o + 28],
            0x4000_0000 | OBJ_TYPE_NX_SUPERBLOCK as u32,
        );
        LittleEndian::write_u32(&mut img[o + 32..o + 36], NXSB_MAGIC);

        let ds = ByteSliceDataSource::new(img);
        let sb = parse_nx_superblock(&ds).unwrap();
        assert_eq!(
            sb.omap_oid, 5,
            "a truncated checkpoint slot must be skipped, not adopted with a zero omap"
        );
        assert_eq!(sb.obj.xid, 2, "block 0 stays authoritative");
    }

    #[test]
    fn test_apfs_read_block_offset_overflow_rejected() {
        // Reproduces the fuzz crash: block_num * block_size overflows u64 (the
        // crash used omap_oid 0x0100000000000000 * block_size 4096). read_block
        // must return Err rather than panic (debug) / wrap (release).
        let ds = ByteSliceDataSource::new(vec![0u8; 4096]);
        let result = read_block(&ds, 0x0100_0000_0000_0000, 4096);
        assert!(result.is_err(), "block offset overflow must be rejected");
    }

    #[test]
    fn test_parse_btree_node_header() {
        let block_size: u32 = 4096;
        let mut data = vec![0u8; block_size as usize];

        // Object header
        LittleEndian::write_u64(&mut data[8..16], 10); // oid
        LittleEndian::write_u64(&mut data[16..24], 5); // xid
        LittleEndian::write_u32(&mut data[24..28], 0x40000003); // type: physical btree node

        // B-tree node fields
        LittleEndian::write_u16(&mut data[32..34], BTNODE_ROOT | BTNODE_LEAF); // flags
        LittleEndian::write_u16(&mut data[34..36], 0); // level (leaf)
        LittleEndian::write_u32(&mut data[36..40], 3); // nkeys

        let node = parse_btree_node(&data).unwrap();
        assert_eq!(node.flags, BTNODE_ROOT | BTNODE_LEAF);
        assert_eq!(node.level, 0);
        assert_eq!(node.nkeys, 3);
    }

    /// Two directory entries naming the same inode are two hardlinks. Keeping
    /// only the last one discarded every other path the file lived at (B7-007).
    #[test]
    fn every_hardlink_name_of_an_inode_is_retained() {
        let mut paths = HashMap::new();
        let mut all_paths = HashMap::new();
        record_inode_path(&mut paths, &mut all_paths, 42, "/Users/a/orig".to_string());
        record_inode_path(&mut paths, &mut all_paths, 42, "/Users/b/link".to_string());

        assert_eq!(
            paths.get(&42).map(String::as_str),
            Some("/Users/a/orig"),
            "the first name discovered stays canonical"
        );
        assert_eq!(
            all_paths.get(&42).map(Vec::as_slice),
            Some(["/Users/a/orig".to_string(), "/Users/b/link".to_string()].as_slice()),
            "both hardlink names must survive"
        );
    }

    /// The object map records how many snapshots the volume carries. This
    /// parser walks the LIVE tree only, so that count is the difference between
    /// "the volume held nothing else" and "there is more we did not read"
    /// (B7-006). It was previously skipped outright.
    #[test]
    fn omap_snapshot_count_is_read_not_skipped() {
        let block_size = 4096u32;
        let mut block = vec![0u8; block_size as usize];
        // obj_phys header is 32 bytes; omap_phys fields follow.
        LittleEndian::write_u32(&mut block[32..36], 0); // om_flags
        LittleEndian::write_u32(&mut block[36..40], 3); // om_snap_count
        LittleEndian::write_u64(&mut block[48..56], 77); // om_tree_oid

        let ds = ByteSliceDataSource::new(block);
        let omap = parse_omap(&ds, 0, block_size).expect("omap parses");
        assert_eq!(omap.tree_oid, 77);
        assert_eq!(
            omap.snap_count, 3,
            "a volume with snapshots must not look like a volume without them"
        );
    }

    #[test]
    fn test_parse_omap_key_value() {
        // Simulate parsing omap key/value from raw bytes
        let mut key_data = [0u8; 16];
        LittleEndian::write_u64(&mut key_data[0..8], 42); // oid
        LittleEndian::write_u64(&mut key_data[8..16], 10); // xid

        let oid = LittleEndian::read_u64(&key_data[0..8]);
        let xid = LittleEndian::read_u64(&key_data[8..16]);
        assert_eq!(oid, 42);
        assert_eq!(xid, 10);

        let mut val_data = [0u8; 16];
        LittleEndian::write_u32(&mut val_data[0..4], 0); // flags
        LittleEndian::write_u32(&mut val_data[4..8], 4096); // size
        LittleEndian::write_u64(&mut val_data[8..16], 1000); // paddr

        let paddr = LittleEndian::read_u64(&val_data[8..16]);
        assert_eq!(paddr, 1000);
    }

    #[test]
    fn test_parse_j_inode_val() {
        let mut data = vec![0u8; 92];

        LittleEndian::write_u64(&mut data[0..8], 2); // parent_id (root)
        LittleEndian::write_u64(&mut data[8..16], 100); // private_id
        LittleEndian::write_i64(&mut data[16..24], 1_700_000_000_000_000_000); // create_time (nanos)
        LittleEndian::write_i64(&mut data[24..32], 1_700_000_100_000_000_000); // mod_time
        LittleEndian::write_i64(&mut data[32..40], 1_700_000_200_000_000_000); // change_time
        LittleEndian::write_i64(&mut data[40..48], 1_700_000_300_000_000_000); // access_time
        LittleEndian::write_u64(&mut data[48..56], 0); // internal_flags
        LittleEndian::write_i32(&mut data[56..60], 1); // nchildren_or_nlink
        LittleEndian::write_u32(&mut data[72..76], 501); // owner
        LittleEndian::write_u32(&mut data[76..80], 20); // group
        LittleEndian::write_u16(&mut data[80..82], 0o100644); // mode (regular file)
        LittleEndian::write_u64(&mut data[84..92], 1048576); // uncompressed_size

        let inode = parse_j_inode_val(&data).unwrap();
        assert_eq!(inode.parent_id, 2);
        assert_eq!(inode.private_id, 100);
        assert_eq!(inode.create_time, 1_700_000_000_000_000_000);
        assert_eq!(inode.mod_time, 1_700_000_100_000_000_000);
        assert_eq!(inode.owner, 501);
        assert_eq!(inode.group, 20);
        assert_eq!(inode.mode, 0o100644);
        assert_eq!(inode.uncompressed_size, 1048576);
    }

    #[test]
    fn test_parse_j_drec_val() {
        let mut data = vec![0u8; 18];
        LittleEndian::write_u64(&mut data[0..8], 54321); // file_id
        LittleEndian::write_u64(&mut data[8..16], 1_700_000_000_000_000_000); // date_added
        LittleEndian::write_u16(&mut data[16..18], DT_REG); // flags (regular file)

        let drec = parse_j_drec_val(&data).unwrap();
        assert_eq!(drec.file_id, 54321);
        assert_eq!(drec.date_added, 1_700_000_000_000_000_000);
        assert_eq!(drec.flags, DT_REG);
    }

    /// ROADMAP 5.12: `date_added` was decoded from the catalog directory
    /// record but never reached a FileEntry. This drives a synthetic volume
    /// (an omap leaf, its omap_phys header, and an FS leaf holding one inode
    /// plus the directory record naming it) through the real
    /// `walk_volume_filesystem` and pins the fifth timestamp appearing on the
    /// published record, formatted exactly like the inode's own four.
    #[test]
    fn test_date_added_surfaces_on_file_entry() {
        let bs: u32 = 4096;
        const ROOT_TREE_OID: u64 = 55;
        const FILE_INO: u64 = 100;
        const DATE_ADDED_NANOS: u64 = 1_700_000_500_000_000_000;

        // Block 0: the volume omap's B-tree leaf — one fixed-size entry
        // mapping the FS root tree's oid to the physical block (2) holding
        // the FS leaf below. Layout mirrors test_omap_lookup_leaf.
        let mut omap_leaf = vec![0u8; bs as usize];
        LittleEndian::write_u64(&mut omap_leaf[8..16], 1); // oid
        LittleEndian::write_u64(&mut omap_leaf[16..24], 1); // xid
        LittleEndian::write_u32(&mut omap_leaf[24..28], 0x40000003); // physical btree node
        let flags = BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE;
        LittleEndian::write_u16(&mut omap_leaf[32..34], flags);
        LittleEndian::write_u16(&mut omap_leaf[34..36], 0); // level (leaf)
        LittleEndian::write_u32(&mut omap_leaf[36..40], 1); // nkeys
        LittleEndian::write_u16(&mut omap_leaf[40..42], 0); // table_space_off
        LittleEndian::write_u16(&mut omap_leaf[42..44], 4); // table_space_len
        LittleEndian::write_u16(&mut omap_leaf[56..58], 0); // key_off
        LittleEndian::write_u16(&mut omap_leaf[58..60], 16); // val_off
        LittleEndian::write_u64(&mut omap_leaf[60..68], ROOT_TREE_OID); // key: oid
        LittleEndian::write_u64(&mut omap_leaf[68..76], 5); // key: xid
        let vals_end = bs as usize - 40;
        let val_start = vals_end - 16;
        LittleEndian::write_u32(&mut omap_leaf[val_start..val_start + 4], 0); // omap val flags
        LittleEndian::write_u32(&mut omap_leaf[val_start + 4..val_start + 8], bs); // size
        LittleEndian::write_u64(&mut omap_leaf[val_start + 8..val_start + 16], 2); // paddr

        // Block 1: the volume's omap_phys object, pointing at block 0.
        let mut omap_obj = vec![0u8; bs as usize];
        LittleEndian::write_u64(&mut omap_obj[48..56], 0); // tree_oid -> block 0

        // Block 2: the FS leaf — one inode record plus the directory record
        // that names it, carrying our `date_added`.
        let mut inode_val = vec![0u8; 92];
        LittleEndian::write_u16(&mut inode_val[80..82], 0o100644); // regular file
        let mut inode_key = vec![0u8; 8];
        LittleEndian::write_u64(&mut inode_key[0..8], j_key(APFS_TYPE_INODE, FILE_INO));

        let drec_key_bytes = drec_key(APFS_ROOT_DIR_INO, "evidence.txt");
        let mut drec_val_bytes = vec![0u8; 18];
        LittleEndian::write_u64(&mut drec_val_bytes[0..8], FILE_INO);
        LittleEndian::write_u64(&mut drec_val_bytes[8..16], DATE_ADDED_NANOS);
        LittleEndian::write_u16(&mut drec_val_bytes[16..18], DT_REG);

        let fs_leaf = build_fs_leaf(
            bs as usize,
            &[(inode_key, inode_val), (drec_key_bytes, drec_val_bytes)],
        );

        let mut image = vec![0u8; bs as usize * 3];
        image[..bs as usize].copy_from_slice(&omap_leaf);
        image[bs as usize..bs as usize * 2].copy_from_slice(&omap_obj);
        image[bs as usize * 2..].copy_from_slice(&fs_leaf);
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(image));

        let nx_sb = NxSuperblock {
            obj: ObjPhys {
                cksum: 0,
                oid: 1,
                xid: 1,
                o_type: 0x4000_0001,
                o_subtype: 0,
            },
            magic: NXSB_MAGIC,
            block_size: bs,
            block_count: 3,
            omap_oid: 0,
            fs_oid: vec![],
            max_file_systems: 1,
            fs_oid_slots_skipped: 0,
        };
        let vol_sb = ApfsSuperblock {
            obj: ObjPhys {
                cksum: 0,
                oid: 2,
                xid: 1,
                o_type: 0x4000_000D,
                o_subtype: 0,
            },
            magic: APSB_MAGIC,
            omap_oid: 1,
            root_tree_oid: ROOT_TREE_OID,
            num_files: 1,
            num_directories: 0,
            vol_uuid: [0u8; 16],
            vol_name: "TestVol".to_string(),
            incompatible_features: 0,
            fs_flags: 1,
        };

        let walk = walk_volume_filesystem(
            &ds,
            &nx_sb,
            &vol_sb,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        )
        .expect("walk must succeed");

        let entry = walk
            .artifacts
            .iter()
            .find(|a| a.metadata["name"] == json!("evidence.txt"))
            .expect("the file must be in the inventory");
        let expected = format_apfs_timestamp(DATE_ADDED_NANOS as i64);
        assert_eq!(entry.metadata["date_added"], json!(expected));
        assert!(
            entry.metadata["date_added"]
                .as_str()
                .unwrap()
                .starts_with("2023-11-14"),
            "got {}",
            entry.metadata["date_added"]
        );

        // The root directory has no directory entry of its own (nobody is its
        // parent), so it must not fabricate a date_added.
        let root = walk
            .artifacts
            .iter()
            .find(|a| a.metadata["path"] == json!("/"));
        if let Some(root) = root {
            assert!(
                root.metadata.get("date_added").is_none(),
                "the root directory has no directory entry and must not carry a date_added"
            );
        }
    }

    #[test]
    fn test_parse_j_drec_hashed_key() {
        // Build a j_drec_hashed_key_t
        let name = b"photo.jpg";
        let name_len = name.len();
        let total_len = 12 + name_len + 1; // key + name_len_and_hash + name + null
        let mut key_data = vec![0u8; total_len];

        // obj_id_and_type: type=DIR_REC(9), oid=2 (root dir)
        let obj_id_and_type: u64 = (APFS_TYPE_DIR_REC as u64) << 60 | 2;
        LittleEndian::write_u64(&mut key_data[0..8], obj_id_and_type);

        // name_len_and_hash: low 10 bits = name_len (including null terminator)
        let name_len_and_hash: u32 = (name_len as u32 + 1) & 0x3FF; // +1 for null
        LittleEndian::write_u32(&mut key_data[8..12], name_len_and_hash);

        // name
        key_data[12..12 + name_len].copy_from_slice(name);
        key_data[12 + name_len] = 0; // null terminator

        let parsed_name = parse_j_drec_name(&key_data).unwrap();
        assert_eq!(parsed_name, "photo.jpg");

        // Also verify type extraction
        let oid_and_type = LittleEndian::read_u64(&key_data[0..8]);
        assert_eq!(j_key_type(oid_and_type), APFS_TYPE_DIR_REC);
        assert_eq!(j_key_oid(oid_and_type), 2);
    }

    #[test]
    fn test_parse_j_file_extent_val() {
        let mut data = vec![0u8; 24];
        // len_and_flags: lower 56 bits = length = 4096
        LittleEndian::write_u64(&mut data[0..8], 4096);
        // phys_block_num
        LittleEndian::write_u64(&mut data[8..16], 500);
        // crypto_id
        LittleEndian::write_u64(&mut data[16..24], 0);

        let fext = parse_j_file_extent_val(&data).unwrap();
        let length = fext.len_and_flags & 0x00FF_FFFF_FFFF_FFFF;
        assert_eq!(length, 4096);
        assert_eq!(fext.phys_block_num, 500);
    }

    #[test]
    fn test_format_apfs_timestamp() {
        // 2023-11-14T22:13:20Z in nanoseconds
        let nanos: i64 = 1_700_000_000_000_000_000;
        let ts = format_apfs_timestamp(nanos);
        assert!(ts.contains("2023"));
        assert!(ts.contains("11"));

        // Epoch
        let ts_zero = format_apfs_timestamp(0);
        assert_eq!(ts_zero, "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn test_apfs_file_source_read() {
        // Create a mock data source with known content
        let block_size: u32 = 4096;
        let mut disk_data = vec![0u8; block_size as usize * 10];
        // Write "HELLO" at block 5, offset 0
        let block5_offset = 5 * block_size as usize;
        disk_data[block5_offset..block5_offset + 5].copy_from_slice(b"HELLO");

        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(disk_data));

        let source = ApfsFileSource::new(
            inner,
            block_size,
            5,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 5,
                phys_block_num: 5,
                crypto_id: 0,
            }],
            true,
        );

        let mut buf = vec![0u8; 5];
        let n = source.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"HELLO");
    }

    #[test]
    fn test_apfs_file_source_sparse() {
        let block_size: u32 = 4096;
        let disk_data = vec![0xFFu8; block_size as usize * 10];
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(disk_data));

        // File with a gap: extent at offset 4096, nothing at offset 0
        let source = ApfsFileSource::new(
            inner,
            block_size,
            8192,
            vec![ApfsExtent {
                logical_offset: 4096,
                length: 4096,
                phys_block_num: 2,
                crypto_id: 0,
            }],
            true,
        );

        // Read from the sparse gap (offset 0-4095)
        let mut buf = vec![0xFFu8; 10];
        let n = source.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 10);
        // Sparse region should be zeros
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_j_key_type_extraction() {
        // Type=3 (INODE), OID=12345
        let obj_id_and_type: u64 = (3u64 << 60) | 12345;
        assert_eq!(j_key_type(obj_id_and_type), 3);
        assert_eq!(j_key_oid(obj_id_and_type), 12345);

        // Type=9 (DIR_REC), OID=2
        let obj_id_and_type2: u64 = (9u64 << 60) | 2;
        assert_eq!(j_key_type(obj_id_and_type2), 9);
        assert_eq!(j_key_oid(obj_id_and_type2), 2);

        // Type=8 (FILE_EXTENT), OID=0x0FFF_FFFF_FFFF_FFFF (max)
        let obj_id_and_type3: u64 = (8u64 << 60) | 0x0FFF_FFFF_FFFF_FFFF;
        assert_eq!(j_key_type(obj_id_and_type3), 8);
        assert_eq!(j_key_oid(obj_id_and_type3), 0x0FFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn test_btree_toc_kvoff_parsing() {
        // Simulate parsing fixed-size kvoff_t entries from a TOC
        let mut toc_data = [0u8; 8]; // 2 entries of 4 bytes each

        // Entry 0: key_off=0, val_off=0
        LittleEndian::write_u16(&mut toc_data[0..2], 0); // key_off
        LittleEndian::write_u16(&mut toc_data[2..4], 0); // val_off

        // Entry 1: key_off=16, val_off=16
        LittleEndian::write_u16(&mut toc_data[4..6], 16); // key_off
        LittleEndian::write_u16(&mut toc_data[6..8], 16); // val_off

        let key_off_0 = LittleEndian::read_u16(&toc_data[0..2]);
        let val_off_0 = LittleEndian::read_u16(&toc_data[2..4]);
        let key_off_1 = LittleEndian::read_u16(&toc_data[4..6]);
        let val_off_1 = LittleEndian::read_u16(&toc_data[6..8]);

        assert_eq!(key_off_0, 0);
        assert_eq!(val_off_0, 0);
        assert_eq!(key_off_1, 16);
        assert_eq!(val_off_1, 16);
    }

    #[test]
    fn test_omap_lookup_leaf() {
        // Build a minimal omap B-tree with a single leaf node containing one entry
        let block_size: u32 = 4096;
        let mut data = vec![0u8; block_size as usize];

        // Object header
        LittleEndian::write_u64(&mut data[8..16], 1); // oid
        LittleEndian::write_u64(&mut data[16..24], 1); // xid
        LittleEndian::write_u32(&mut data[24..28], 0x40000003); // type: physical btree node

        // B-tree node fields
        let flags = BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE;
        LittleEndian::write_u16(&mut data[32..34], flags); // flags
        LittleEndian::write_u16(&mut data[34..36], 0); // level (leaf)
        LittleEndian::write_u32(&mut data[36..40], 1); // nkeys = 1
        LittleEndian::write_u16(&mut data[40..42], 0); // table_space_off
        LittleEndian::write_u16(&mut data[42..44], 4); // table_space_len (1 entry * 4 bytes)

        // TOC at offset 56: one kvoff_t entry. val_off is the distance from the
        // end of the value area to the START of the value; a 16-byte value at
        // the very end therefore has val_off=16.
        LittleEndian::write_u16(&mut data[56..58], 0); // key_off
        LittleEndian::write_u16(&mut data[58..60], 16); // val_off

        // Keys area starts at 56 + 0 + 4 = 60
        // Key: oid=42, xid=5
        LittleEndian::write_u64(&mut data[60..68], 42); // oid
        LittleEndian::write_u64(&mut data[68..76], 5); // xid

        // Values grow backwards from (block_size - 40) for root node:
        // val_start = vals_end - val_off = vals_end - 16.
        let vals_end = block_size as usize - 40;
        let val_start = vals_end - 16;
        LittleEndian::write_u32(&mut data[val_start..val_start + 4], 0); // flags
        LittleEndian::write_u32(&mut data[val_start + 4..val_start + 8], 4096); // size
        LittleEndian::write_u64(&mut data[val_start + 8..val_start + 16], 999); // paddr

        let ds = ByteSliceDataSource::new(data);

        // Look up OID 42 — should find paddr 999
        let result = omap_lookup(&ds, 0, 42, block_size, true).unwrap();
        assert_eq!(result, Some(999));

        // Look up OID 99 — should not be found
        let result2 = omap_lookup(&ds, 0, 99, block_size, true).unwrap();
        assert_eq!(result2, None);
    }

    #[test]
    fn test_format_uuid() {
        let bytes: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let uuid = format_uuid(&bytes);
        assert_eq!(uuid, "01234567-89ab-cdef-fedc-ba9876543210");
    }

    #[test]
    fn test_apfs_file_source_past_eof() {
        let block_size: u32 = 4096;
        let disk_data = vec![0u8; block_size as usize * 10];
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(disk_data));

        let source = ApfsFileSource::new(
            inner,
            block_size,
            100,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 100,
                phys_block_num: 1,
                crypto_id: 0,
            }],
            true,
        );

        // Read past EOF
        let mut buf = vec![0u8; 10];
        let n = source.read_at(100, &mut buf).unwrap();
        assert_eq!(n, 0);

        let n2 = source.read_at(200, &mut buf).unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn test_parse_j_drec_val_too_short() {
        let data = vec![0u8; 10]; // Less than 18 bytes
        assert!(parse_j_drec_val(&data).is_none());
    }

    #[test]
    fn test_parse_j_inode_val_too_short() {
        let data = vec![0u8; 50]; // Less than 92 bytes
        assert!(parse_j_inode_val(&data).is_none());
    }

    // --- B-tree / omap edge-case helpers and tests ---

    /// Build a fixed-KV omap node (leaf or internal) inside a `block_size`
    /// buffer. Entries are (oid, xid, ov_flags, paddr). Leaf values are the
    /// full 16-byte omap_val_t; internal values are the 8-byte child paddr.
    fn build_omap_node(
        block_size: usize,
        is_root: bool,
        is_leaf: bool,
        entries: &[(u64, u64, u32, u64)],
    ) -> Vec<u8> {
        let mut data = vec![0u8; block_size];
        LittleEndian::write_u32(&mut data[24..28], 0x40000003); // physical btree node
        let mut flags = BTNODE_FIXED_KV_SIZE;
        if is_root {
            flags |= BTNODE_ROOT;
        }
        if is_leaf {
            flags |= BTNODE_LEAF;
        }
        LittleEndian::write_u16(&mut data[32..34], flags);
        LittleEndian::write_u16(&mut data[34..36], if is_leaf { 0 } else { 1 }); // level
        LittleEndian::write_u32(&mut data[36..40], entries.len() as u32); // nkeys
        LittleEndian::write_u16(&mut data[40..42], 0); // table_space_off
        LittleEndian::write_u16(&mut data[42..44], (entries.len() * 4) as u16); // table_space_len

        let keys_start = 56 + entries.len() * 4;
        let vals_end = if is_root { block_size - 40 } else { block_size };
        let val_size = if is_leaf { 16usize } else { 8usize };

        for (i, &(oid, xid, vflags, paddr)) in entries.iter().enumerate() {
            let toc = 56 + i * 4;
            let key_off = i * 16;
            let val_off = (i + 1) * val_size;
            LittleEndian::write_u16(&mut data[toc..toc + 2], key_off as u16);
            LittleEndian::write_u16(&mut data[toc + 2..toc + 4], val_off as u16);

            let ks = keys_start + key_off;
            LittleEndian::write_u64(&mut data[ks..ks + 8], oid);
            LittleEndian::write_u64(&mut data[ks + 8..ks + 16], xid);

            let vs = vals_end - val_off;
            if is_leaf {
                LittleEndian::write_u32(&mut data[vs..vs + 4], vflags); // ov_flags
                LittleEndian::write_u32(&mut data[vs + 4..vs + 8], 0); // ov_size
                LittleEndian::write_u64(&mut data[vs + 8..vs + 16], paddr); // ov_paddr
            } else {
                LittleEndian::write_u64(&mut data[vs..vs + 8], paddr); // child paddr
            }
        }
        data
    }

    /// Build a variable-size (KVLOC) leaf B-tree node holding raw FS records.
    /// Build a variable-size (KVLOC) FS-tree **index** node.
    ///
    /// With `hashed` set this reproduces what a sealed volume's file-system tree
    /// looks like on disk (LIVE-011): the object header is left zeroed
    /// (`BTNODE_NOHEADER`), and each value is an 8-byte child reference followed
    /// by a `hash_len` child hash, where the reference is an offset from the
    /// tree's root oid rather than an absolute oid. With `hashed` clear it builds
    /// the ordinary form, whose value is the absolute child oid.
    fn build_fs_index(
        block_size: usize,
        level: u16,
        hashed: bool,
        hash_len: usize,
        children: &[(Vec<u8>, u64)],
    ) -> Vec<u8> {
        let mut data = vec![0u8; block_size];
        let mut flags = BTNODE_ROOT;
        if hashed {
            // A real sealed tree carries both; NOHEADER is why the first 32
            // bytes stay zero here rather than holding an obj_phys_t.
            flags |= BTNODE_HASHED | BTNODE_NOHEADER;
        } else {
            LittleEndian::write_u32(&mut data[24..28], 0x40000003);
        }
        LittleEndian::write_u16(&mut data[32..34], flags);
        LittleEndian::write_u16(&mut data[34..36], level);
        LittleEndian::write_u32(&mut data[36..40], children.len() as u32);
        LittleEndian::write_u16(&mut data[40..42], 0);
        LittleEndian::write_u16(&mut data[42..44], (children.len() * 8) as u16);

        let keys_start = 56 + children.len() * 8;
        let vals_end = block_size - 40; // root node: btree_info_t occupies the tail
        let val_len = if hashed { 8 + hash_len } else { 8 };
        let mut key_pos = 0usize;
        let mut val_off = 0usize;
        for (i, (key, child_ref)) in children.iter().enumerate() {
            let toc = 56 + i * 8;
            val_off += val_len;
            LittleEndian::write_u16(&mut data[toc..toc + 2], key_pos as u16);
            LittleEndian::write_u16(&mut data[toc + 2..toc + 4], key.len() as u16);
            LittleEndian::write_u16(&mut data[toc + 4..toc + 6], val_off as u16);
            LittleEndian::write_u16(&mut data[toc + 6..toc + 8], val_len as u16);

            let ks = keys_start + key_pos;
            data[ks..ks + key.len()].copy_from_slice(key);
            let vs = vals_end - val_off;
            LittleEndian::write_u64(&mut data[vs..vs + 8], *child_ref);
            // Filler standing in for the child hash, so a wrong value-length
            // assumption reads it and is caught rather than silently working.
            for b in data[vs + 8..vs + val_len].iter_mut() {
                *b = 0xAB;
            }
            key_pos += key.len();
        }
        data
    }

    fn build_fs_leaf(block_size: usize, records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut data = vec![0u8; block_size];
        LittleEndian::write_u32(&mut data[24..28], 0x40000003); // physical btree node
        LittleEndian::write_u16(&mut data[32..34], BTNODE_ROOT | BTNODE_LEAF);
        LittleEndian::write_u16(&mut data[34..36], 0); // level (leaf)
        LittleEndian::write_u32(&mut data[36..40], records.len() as u32); // nkeys
        LittleEndian::write_u16(&mut data[40..42], 0); // table_space_off
        LittleEndian::write_u16(&mut data[42..44], (records.len() * 8) as u16);

        let keys_start = 56 + records.len() * 8;
        let vals_end = block_size - 40; // root node: btree_info_t occupies the tail
        let mut key_pos = 0usize;
        let mut val_off = 0usize;
        for (i, (key, val)) in records.iter().enumerate() {
            let toc = 56 + i * 8;
            val_off += val.len();
            LittleEndian::write_u16(&mut data[toc..toc + 2], key_pos as u16);
            LittleEndian::write_u16(&mut data[toc + 2..toc + 4], key.len() as u16);
            LittleEndian::write_u16(&mut data[toc + 4..toc + 6], val_off as u16);
            LittleEndian::write_u16(&mut data[toc + 6..toc + 8], val.len() as u16);

            let ks = keys_start + key_pos;
            data[ks..ks + key.len()].copy_from_slice(key);
            let vs = vals_end - val_off;
            data[vs..vs + val.len()].copy_from_slice(val);
            key_pos += key.len();
        }
        data
    }

    fn j_key(record_type: u8, oid: u64) -> u64 {
        ((record_type as u64) << 60) | (oid & 0x0FFF_FFFF_FFFF_FFFF)
    }

    /// A j_drec_hashed_key_t for `name` under parent inode `parent`.
    fn drec_key(parent: u64, name: &str) -> Vec<u8> {
        let mut key = vec![0u8; 12 + name.len() + 1];
        LittleEndian::write_u64(&mut key[0..8], j_key(APFS_TYPE_DIR_REC, parent));
        LittleEndian::write_u32(&mut key[8..12], (name.len() + 1) as u32);
        key[12..12 + name.len()].copy_from_slice(name.as_bytes());
        key
    }

    fn drec_val(file_id: u64, flags: u16) -> Vec<u8> {
        let mut val = vec![0u8; 18];
        LittleEndian::write_u64(&mut val[0..8], file_id);
        LittleEndian::write_u16(&mut val[16..18], flags);
        val
    }

    /// BUG-206: file-extent records are keyed by the inode's data-stream id
    /// (`private_id`), not by the inode object id. A clone shares one stream
    /// between two inodes, so a lookup by inode number finds nothing and the
    /// file silently re-serves as empty.
    #[test]
    fn test_extent_lookup_uses_private_id() {
        let mut records = FsRecords::new();
        let stream = ApfsExtent {
            logical_offset: 0,
            length: 4096,
            phys_block_num: 77,
            crypto_id: 0,
        };
        // One data stream (private_id 9000) shared by two inodes: the original
        // (inode 500) and its clone (inode 501).
        records.extents.insert(9000, vec![stream]);

        for ino in [500u64, 501u64] {
            let (extents, truncated) = records
                .stream_extents(ino, 9000)
                .expect("clone must resolve its shared stream");
            assert_eq!(extents.len(), 1);
            assert_eq!(extents[0].phys_block_num, 77);
            assert!(!truncated);
        }

        // An inode whose stream simply has no extent records stays empty rather
        // than borrowing another inode's stream.
        assert!(records.stream_extents(502, 9001).is_none());
    }

    /// Volumes whose inode record carried no usable private_id still resolve
    /// through the inode number.
    #[test]
    fn test_extent_lookup_falls_back_to_inode_number() {
        let mut records = FsRecords::new();
        records.extents.insert(
            42,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 4096,
                phys_block_num: 12,
                crypto_id: 0,
            }],
        );
        let (extents, _) = records.stream_extents(42, 0).expect("fallback lookup");
        assert_eq!(extents[0].phys_block_num, 12);
    }

    /// BUG-212: when the MAX_EXTENTS cap drops a file's trailing extents the
    /// tail is sparse-filled with zeros. Those zeros are not the file's content,
    /// so the runs must be flagged incomplete instead of being served as whole.
    #[test]
    fn test_capped_extent_list_marks_content_incomplete() {
        let extents = vec![ApfsExtent {
            logical_offset: 0,
            length: 4096,
            phys_block_num: 20,
            crypto_id: 0,
        }];

        // Complete extent list: the sparse tail is a genuine hole.
        let mut whole = json!({});
        apply_extent_metadata(&mut whole, &extents, 4096, 8192, false);
        assert_eq!(whole["data_runs_complete"], true);
        assert!(whole.get("content_incomplete").is_none());

        // Truncated extent list: same runs, but they are not the whole file.
        let mut capped = json!({});
        apply_extent_metadata(&mut capped, &extents, 4096, 8192, true);
        assert_eq!(capped["data_runs_complete"], false);
        assert_eq!(capped["content_incomplete"], true);
        assert_eq!(capped["content_incomplete_reason"], "apfs_max_extents");
    }

    /// B2-001: APFS records a hole inside a file as an extent whose physical
    /// block number is 0. Block 0 of the container is the container superblock,
    /// so reading it hands the examiner container structures dressed up as the
    /// file's own bytes. The sparse range must read as zeros.
    #[test]
    fn sparse_extent_at_physical_block_zero_reads_as_zeros() {
        let block_size: u32 = 4096;
        // Block 0 is the container superblock: recognisable, and definitely not
        // this file's content.
        let mut disk = vec![0u8; block_size as usize * 4];
        disk[0..4].copy_from_slice(b"NXSB");
        disk[4..block_size as usize].fill(0x5A);
        // Block 2 holds the file's one real extent.
        let blk2 = 2 * block_size as usize;
        disk[blk2..blk2 + 4].copy_from_slice(b"REAL");

        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(disk));
        let source = ApfsFileSource::new(
            inner,
            block_size,
            2 * block_size as u64,
            vec![
                // An explicit hole: phys_block_num == 0.
                ApfsExtent {
                    logical_offset: 0,
                    length: block_size as u64,
                    phys_block_num: 0,
                    crypto_id: 0,
                },
                ApfsExtent {
                    logical_offset: block_size as u64,
                    length: block_size as u64,
                    phys_block_num: 2,
                    crypto_id: 0,
                },
            ],
            true,
        );

        let mut buf = vec![0xAAu8; 2 * block_size as usize];
        let n = source.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 2 * block_size as usize);
        assert!(
            buf[..block_size as usize].iter().all(|&b| b == 0),
            "a phys=0 extent must read as zeros, not as container block 0"
        );
        assert_eq!(&buf[block_size as usize..block_size as usize + 4], b"REAL");
    }

    /// B2-001, persisted form: a phys=0 extent must land in `data_runs` as a
    /// sparse run. Persisted as a run at byte 0 the content resolver would
    /// re-serve the container superblock as file content on every later read.
    #[test]
    fn sparse_extent_at_physical_block_zero_persists_as_a_hole() {
        let extents = vec![
            ApfsExtent {
                logical_offset: 0,
                length: 4096,
                phys_block_num: 0,
                crypto_id: 0,
            },
            ApfsExtent {
                logical_offset: 4096,
                length: 4096,
                phys_block_num: 7,
                crypto_id: 0,
            },
        ];
        let mut metadata = json!({});
        apply_extent_metadata(&mut metadata, &extents, 4096, 8192, false);
        assert_eq!(
            metadata["data_runs"],
            json!([[serde_json::Value::Null, 4096], [7 * 4096, 4096]]),
            "the phys=0 extent must persist as a hole, not as a run at byte 0"
        );
        assert_eq!(metadata["data_runs_complete"], true);
    }

    /// B2-035: extent fields come off the image. A physical block number whose
    /// byte offset overflows u64 must fail closed, not wrap into low container
    /// offsets and serve unrelated bytes as this file's content.
    #[test]
    fn overflowing_extent_offset_fails_closed_on_read() {
        let block_size: u32 = 4096;
        let inner: Arc<dyn DataSource> =
            Arc::new(ByteSliceDataSource::new(vec![0xEEu8; block_size as usize]));
        let source = ApfsFileSource::new(
            inner,
            block_size,
            16,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 16,
                phys_block_num: u64::MAX / 2,
                crypto_id: 0,
            }],
            true,
        );

        let mut buf = vec![0u8; 16];
        let err = source
            .read_at(0, &mut buf)
            .expect_err("an overflowing physical offset must not be read");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// B2-035, persisted form: an unmappable extent is persisted as a hole, but
    /// the runs must then declare themselves incomplete — zeros standing in for
    /// bytes we could not locate must never read as the file's real content.
    #[test]
    fn overflowing_extent_offset_marks_runs_incomplete() {
        let extents = vec![ApfsExtent {
            logical_offset: 0,
            length: 4096,
            phys_block_num: u64::MAX / 2,
            crypto_id: 0,
        }];
        let mut metadata = json!({});
        apply_extent_metadata(&mut metadata, &extents, 4096, 4096, false);
        assert_eq!(metadata["data_runs_complete"], false);
        assert_eq!(metadata["content_incomplete"], true);
        assert_eq!(
            metadata["content_incomplete_reason"],
            "apfs_extent_offset_overflow"
        );
    }

    /// B2-031: when MAX_EXTENTS truncated the extent list, everything past the
    /// last known extent is UNKNOWN, not a hole. The source must short-read
    /// there so a caller hashes only what was actually located; a complete list
    /// keeps zero-filling its genuine sparse tail.
    #[test]
    fn truncated_extent_list_short_reads_past_the_mapped_end() {
        let block_size: u32 = 4096;
        let mut disk = vec![0u8; block_size as usize * 4];
        let blk1 = block_size as usize;
        disk[blk1..blk1 + 4].copy_from_slice(b"HEAD");
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(disk));

        let extents = vec![ApfsExtent {
            logical_offset: 0,
            length: block_size as u64,
            phys_block_num: 1,
            crypto_id: 0,
        }];

        // Truncated list: the tail past 4096 is unknown.
        let capped = ApfsFileSource::new(
            Arc::clone(&inner),
            block_size,
            3 * block_size as u64,
            extents.clone(),
            false,
        );
        let mut buf = vec![0xAAu8; 3 * block_size as usize];
        let n = capped.read_at(0, &mut buf).unwrap();
        assert_eq!(
            n, block_size as usize,
            "a capped extent list must stop at the mapped end, not zero-fill the tail"
        );
        assert_eq!(&buf[..4], b"HEAD");

        // Reading entirely inside the unknown tail yields nothing at all.
        let mut tail = vec![0xAAu8; 16];
        assert_eq!(capped.read_at(block_size as u64, &mut tail).unwrap(), 0);
        assert!(
            tail.iter().all(|&b| b == 0xAA),
            "the unknown tail must not be overwritten with fabricated zeros"
        );

        // Complete list: the same tail is a genuine sparse hole and reads as zeros.
        let whole = ApfsFileSource::new(inner, block_size, 3 * block_size as u64, extents, true);
        let mut buf = vec![0xAAu8; 3 * block_size as usize];
        let n = whole.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 3 * block_size as usize);
        assert!(buf[block_size as usize..].iter().all(|&b| b == 0));
    }

    /// The extent cap records which stream was truncated, keyed the same way the
    /// extents themselves are.
    #[test]
    fn test_truncated_stream_surfaces_through_lookup() {
        let mut records = FsRecords::new();
        records.extents.insert(
            9000,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 4096,
                phys_block_num: 5,
                crypto_id: 0,
            }],
        );
        records.truncated_streams.insert(9000);
        let (_, truncated) = records.stream_extents(500, 9000).unwrap();
        assert!(truncated, "a capped stream must report itself incomplete");
    }

    /// BUG-215: past the global directory-entry cap further entries are dropped.
    /// The drop has to be recorded so the volume's inventory is not read as
    /// complete.
    #[test]
    fn test_dir_entry_cap_flags_incomplete() {
        let bs = 4096usize;
        let node = build_fs_leaf(bs, &[(drec_key(2, "evidence.txt"), drec_val(77, DT_REG))]);
        let ds = ByteSliceDataSource::new(node);

        // Under the cap: the entry is collected and nothing is flagged.
        let mut records = FsRecords::new();
        walk_fs_btree(
            &ds,
            0,
            bs as u32,
            0,
            0,
            &mut records,
            0,
            &mut std::collections::HashSet::new(),
        )
        .unwrap();
        assert_eq!(records.dir_entry_count, 1);
        assert_eq!(records.dir_entries[&2][0].0, "evidence.txt");
        assert!(!records.dir_entries_truncated);

        // At the cap: the entry is dropped, and that is recorded.
        let mut capped = FsRecords::new();
        capped.dir_entry_count = MAX_DIR_ENTRIES;
        walk_fs_btree(
            &ds,
            0,
            bs as u32,
            0,
            0,
            &mut capped,
            0,
            &mut std::collections::HashSet::new(),
        )
        .unwrap();
        assert!(capped.dir_entries.is_empty());
        assert!(
            capped.dir_entries_truncated,
            "hitting the directory-entry cap must set the incomplete flag"
        );
    }

    /// B2-093: a file over the DataSource ceiling gets no content. Metadata still
    /// carries its full size, so without an explicit reason the artifact is
    /// indistinguishable from an empty file — the examiner would conclude the
    /// file held nothing.
    #[test]
    fn oversized_file_declares_why_it_has_no_content() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 64]));
        let mut records = FsRecords::new();
        records.extents.insert(
            9000,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 4096,
                phys_block_num: 5,
                crypto_id: 0,
            }],
        );

        let mut metadata = json!({ "size": MAX_FILE_SIZE + 1 });
        let src = attach_file_content(
            &mut metadata,
            &records,
            500,
            9000,
            MAX_FILE_SIZE + 1,
            4096,
            &ds,
        );
        assert!(src.is_none(), "an oversized file gets no data source");
        assert_eq!(metadata["content_incomplete"], true);
        assert_eq!(metadata["content_incomplete_reason"], "apfs_file_too_large");
        assert_eq!(metadata["content_incomplete_limit"], MAX_FILE_SIZE);

        // The same file under the ceiling is served normally and flagged nothing.
        let mut metadata = json!({ "size": 4096 });
        let src = attach_file_content(&mut metadata, &records, 500, 9000, 4096, 4096, &ds);
        assert!(src.is_some());
        assert!(metadata.get("content_incomplete").is_none());
    }

    /// B2-093, second half: a sized file whose data stream carries no extent
    /// records must say so too, rather than emit a sized FileEntry with no bytes
    /// and no explanation.
    #[test]
    fn sized_file_without_extent_records_declares_content_missing() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 64]));
        let records = FsRecords::new();

        let mut metadata = json!({ "size": 8192 });
        let src = attach_file_content(&mut metadata, &records, 500, 9000, 8192, 4096, &ds);
        assert!(src.is_none());
        assert_eq!(metadata["content_incomplete"], true);
        assert_eq!(
            metadata["content_incomplete_reason"],
            "apfs_no_extent_records"
        );
    }

    /// B2-097: past the inode cap further inode records are dropped. The drop has
    /// LIVE-012: "a subset of the volume" is only true when something was
    /// recovered. On a real macOS 13.7.4 system volume the walk produced 0 of
    /// 203,258 files and still reported a "subset", which reads as a
    /// mostly-complete listing with gaps rather than a volume that yielded
    /// nothing. Both numbers are already in hand at that point, so the two cases
    /// are distinguishable.
    #[test]
    fn a_walk_that_recovered_nothing_is_not_reported_as_a_subset() {
        // The real case: every subtree lost, no entries produced.
        assert_eq!(
            inventory_outcome(0, 12),
            InventoryOutcome::NotEnumerated,
            "0 of 203,258 files is not a subset; the volume was not enumerated"
        );
        assert!(!inventory_outcome(0, 12).is_subset());
    }

    #[test]
    fn a_walk_that_recovered_some_entries_is_a_genuine_subset() {
        assert_eq!(inventory_outcome(784, 3), InventoryOutcome::Partial);
        assert!(inventory_outcome(784, 3).is_subset());
    }

    #[test]
    fn a_walk_with_every_subtree_reached_is_complete() {
        assert_eq!(inventory_outcome(784, 0), InventoryOutcome::Complete);
        // A volume that legitimately holds no files is complete, not a failure:
        // the real image's 'VM' and 'xART' volumes are empty by design.
        assert_eq!(inventory_outcome(0, 0), InventoryOutcome::Complete);
    }

    /// LIVE-011: a sealed volume's FS tree is a *hashed* tree, and its index
    /// values hold the child as an offset from the tree's root oid, not as an
    /// absolute oid. Resolving the raw field through the omap misses every child,
    /// which cost the entire 203,258-file inventory of a real macOS 13.7.4 system
    /// volume: the walk reported "0 file entries" while the volume superblock
    /// said 203,258.
    ///
    /// Layout: block 0 is the hashed index root, block 1 the volume omap, block 2
    /// the leaf. The child's real oid is 1003 and the root oid is 1000, so the
    /// stored reference is 3 — a number that resolves to nothing on its own.
    #[test]
    fn a_hashed_index_resolves_children_relative_to_the_tree_root_oid() {
        let bs = 4096usize;
        const ROOT_OID: u64 = 1000;
        const CHILD_OID: u64 = 1003;
        let child_ref = CHILD_OID - ROOT_OID;

        let root = build_fs_index(bs, 1, true, 32, &[(drec_key(2, "anchor"), child_ref)]);
        // The omap maps only the true oid. Nothing answers for the bare
        // reference, so a walk that forgets the base cannot accidentally pass.
        let omap = build_omap_node(bs, true, true, &[(CHILD_OID, 1, 0, 2)]);
        let leaf = build_fs_leaf(bs, &[(drec_key(2, "evidence.txt"), drec_val(77, DT_REG))]);

        let mut image = Vec::new();
        image.extend_from_slice(&root);
        image.extend_from_slice(&omap);
        image.extend_from_slice(&leaf);
        let ds = ByteSliceDataSource::new(image);

        let mut records = FsRecords::new();
        walk_fs_btree(
            &ds,
            0, // fs tree root at block 0
            bs as u32,
            1, // volume omap at block 1
            ROOT_OID,
            &mut records,
            0,
            &mut std::collections::HashSet::new(),
        )
        .unwrap();

        assert_eq!(
            records.subtrees_unwalked, 0,
            "the child must resolve; an unwalked subtree means the base was not applied"
        );
        assert_eq!(
            records.dir_entry_count, 1,
            "the leaf under the hashed index must be reached"
        );
        assert_eq!(records.dir_entries[&2][0].0, "evidence.txt");
    }

    /// The base must be applied *only* to hashed trees. An ordinary index node
    /// stores the absolute child oid, so adding the root oid to it would break
    /// every volume that works today — Preboot, Recovery and Hardware all walked
    /// correctly on the same real image.
    #[test]
    fn a_non_hashed_index_still_resolves_absolute_child_oids() {
        let bs = 4096usize;
        const ROOT_OID: u64 = 1000;
        const CHILD_OID: u64 = 1003;

        // Not hashed: the value is the absolute oid.
        let root = build_fs_index(bs, 1, false, 0, &[(drec_key(2, "anchor"), CHILD_OID)]);
        let omap = build_omap_node(bs, true, true, &[(CHILD_OID, 1, 0, 2)]);
        let leaf = build_fs_leaf(bs, &[(drec_key(2, "plain.txt"), drec_val(88, DT_REG))]);

        let mut image = Vec::new();
        image.extend_from_slice(&root);
        image.extend_from_slice(&omap);
        image.extend_from_slice(&leaf);
        let ds = ByteSliceDataSource::new(image);

        let mut records = FsRecords::new();
        // A non-zero root oid is passed deliberately: if the base leaked into the
        // non-hashed path it would turn 1003 into 2003 and lose the child.
        walk_fs_btree(
            &ds,
            0,
            bs as u32,
            1,
            ROOT_OID,
            &mut records,
            0,
            &mut std::collections::HashSet::new(),
        )
        .unwrap();

        assert_eq!(records.subtrees_unwalked, 0);
        assert_eq!(records.dir_entry_count, 1);
        assert_eq!(records.dir_entries[&2][0].0, "plain.txt");
    }

    /// to reach the volume artifact, or a partial file listing reads as the whole
    /// filesystem.
    #[test]
    fn inode_cap_flags_the_inventory_incomplete() {
        let bs = 4096usize;
        let mut inode_val = vec![0u8; 92];
        LittleEndian::write_u16(&mut inode_val[80..82], 0o100644); // regular file
        let mut key = vec![0u8; 8];
        LittleEndian::write_u64(&mut key[0..8], j_key(APFS_TYPE_INODE, 77));
        let node = build_fs_leaf(bs, &[(key, inode_val)]);
        let ds = ByteSliceDataSource::new(node);

        // Under the cap: the inode is collected and nothing is flagged.
        let mut records = FsRecords::new();
        walk_fs_btree(
            &ds,
            0,
            bs as u32,
            0,
            0,
            &mut records,
            0,
            &mut std::collections::HashSet::new(),
        )
        .unwrap();
        assert_eq!(records.inodes.len(), 1);
        assert!(!records.inodes_truncated);

        // At the cap: the inode is dropped, and that is recorded.
        let mut capped = FsRecords::new();
        capped.max_inodes = 0;
        walk_fs_btree(
            &ds,
            0,
            bs as u32,
            0,
            0,
            &mut capped,
            0,
            &mut std::collections::HashSet::new(),
        )
        .unwrap();
        assert!(capped.inodes.is_empty());
        assert!(
            capped.inodes_truncated,
            "hitting the inode cap must set the incomplete flag"
        );
    }

    #[test]
    fn test_btree_node_entries_empty() {
        // nkeys == 0 must yield no entries (not a panic, not a phantom read).
        let bs = 4096usize;
        let data = build_omap_node(bs, true, true, &[]);
        let node = parse_btree_node(&data).unwrap();
        let entries = btree_node_entries(&data, &node, bs as u32).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_btree_node_entries_fixed_leaf() {
        let bs = 4096usize;
        let data = build_omap_node(bs, true, true, &[(10, 1, 0, 111), (20, 2, 0, 222)]);
        let node = parse_btree_node(&data).unwrap();
        let entries = btree_node_entries(&data, &node, bs as u32).unwrap();
        assert_eq!(entries.len(), 2);
        let (k, v) = entries[1];
        assert_eq!(LittleEndian::read_u64(&k[0..8]), 20); // oid
        assert_eq!(LittleEndian::read_u64(&v[8..16]), 222); // paddr
    }

    #[test]
    fn test_btree_node_entries_variable_leaf() {
        // Variable-size (KVLOC) layout: key/val offsets+lengths in the TOC.
        let bs = 4096usize;
        let mut data = vec![0u8; bs];
        LittleEndian::write_u32(&mut data[24..28], 0x40000003);
        LittleEndian::write_u16(&mut data[32..34], BTNODE_ROOT | BTNODE_LEAF); // no FIXED flag
        LittleEndian::write_u16(&mut data[34..36], 0);
        LittleEndian::write_u32(&mut data[36..40], 1); // nkeys
        LittleEndian::write_u16(&mut data[40..42], 0); // table_space_off
        LittleEndian::write_u16(&mut data[42..44], 8); // table_space_len (1 kvloc)
        let keys_start = 56 + 8;
        let vals_end = bs - 40;
        // kvloc: key_off=0, key_len=8, val_off=8, val_len=8
        LittleEndian::write_u16(&mut data[56..58], 0);
        LittleEndian::write_u16(&mut data[58..60], 8);
        LittleEndian::write_u16(&mut data[60..62], 8);
        LittleEndian::write_u16(&mut data[62..64], 8);
        LittleEndian::write_u64(&mut data[keys_start..keys_start + 8], 0xAABB);
        LittleEndian::write_u64(&mut data[vals_end - 8..vals_end], 0xCCDD);

        let node = parse_btree_node(&data).unwrap();
        let entries = btree_node_entries(&data, &node, bs as u32).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(LittleEndian::read_u64(entries[0].0), 0xAABB);
        assert_eq!(LittleEndian::read_u64(entries[0].1), 0xCCDD);
    }

    #[test]
    fn test_btree_node_entries_bad_val_off_skipped() {
        // A value offset larger than the value area must be rejected, not
        // underflow-panic.
        let bs = 4096usize;
        let mut data = build_omap_node(bs, true, true, &[(10, 1, 0, 111)]);
        LittleEndian::write_u16(&mut data[58..60], 0xFFFF); // corrupt val_off
        let node = parse_btree_node(&data).unwrap();
        let entries = btree_node_entries(&data, &node, bs as u32).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_btree_node_entries_huge_nkeys_bounded() {
        // A hostile nkeys must not drive a giant allocation or read TOC entries
        // out of the key area.
        let bs = 4096usize;
        let mut data = build_omap_node(bs, true, true, &[(10, 1, 0, 111)]);
        LittleEndian::write_u32(&mut data[36..40], u32::MAX); // claim ~4B entries
        let node = parse_btree_node(&data).unwrap();
        let entries = btree_node_entries(&data, &node, bs as u32).unwrap();
        // table_space_len only covers one entry, so exactly one is in-bounds.
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_btree_node_entries_small_block_no_panic() {
        // A root node told block_size < 40 would underflow the backward value
        // area without the saturating guard.
        let data = build_omap_node(4096, true, true, &[]);
        let node = parse_btree_node(&data).unwrap();
        let entries = btree_node_entries(&data, &node, 16).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_btree_node_truncated_errors() {
        // Fewer than the fixed node-header bytes must be an Err, never a panic.
        let data = vec![0u8; 40];
        assert!(parse_btree_node(&data).is_err());
    }

    #[test]
    fn test_omap_lookup_short_block_errors() {
        // A source shorter than a block yields a short read -> Err (not panic).
        let ds = ByteSliceDataSource::new(vec![0u8; 16]);
        assert!(omap_lookup(&ds, 0, 42, 4096, true).is_err());
    }

    #[test]
    fn test_omap_lookup_multi_level() {
        // Root internal node at block 0 descends into a leaf at block 1.
        let bs = 4096usize;
        let root = build_omap_node(bs, true, false, &[(0, 0, 0, 1)]);
        let leaf = build_omap_node(bs, false, true, &[(42, 7, 0, 999)]);
        let mut img = root;
        img.extend_from_slice(&leaf);
        let ds = ByteSliceDataSource::new(img);
        assert_eq!(omap_lookup(&ds, 0, 42, bs as u32, true).unwrap(), Some(999));
    }

    #[test]
    fn test_omap_lookup_selects_highest_xid() {
        // Multiple xids for one oid: the greatest xid (latest state) wins.
        let bs = 4096usize;
        let leaf = build_omap_node(bs, true, true, &[(42, 3, 0, 100), (42, 9, 0, 200)]);
        let ds = ByteSliceDataSource::new(leaf);
        assert_eq!(omap_lookup(&ds, 0, 42, bs as u32, true).unwrap(), Some(200));
    }

    #[test]
    fn test_omap_lookup_skips_deleted_ghost() {
        // A deleted (ghost) mapping with a HIGHER xid must not shadow the live
        // object; the live lower-xid paddr must be returned.
        let bs = 4096usize;
        let leaf = build_omap_node(
            bs,
            true,
            true,
            &[(42, 5, 0, 100), (42, 9, OMAP_VAL_DELETED, 200)],
        );
        let ds = ByteSliceDataSource::new(leaf);
        assert_eq!(omap_lookup(&ds, 0, 42, bs as u32, true).unwrap(), Some(100));
    }

    #[test]
    fn test_omap_lookup_cyclic_child_bounded() {
        // An internal node whose child points back to itself must terminate via
        // the depth guard with an Err, never loop forever.
        let bs = 4096usize;
        let root = build_omap_node(bs, true, false, &[(0, 0, 0, 0)]);
        let ds = ByteSliceDataSource::new(root);
        assert!(omap_lookup(&ds, 0, 42, bs as u32, true).is_err());
    }

    /// A subtree of the FS B-tree that cannot be reached is a slice of the
    /// filesystem missing from the inventory. Before this it was a `debug!`
    /// line only, so the volume artifact reported a partial file list with no
    /// mark on it: absent files were indistinguishable from files that never
    /// existed on the volume (B2-133).
    #[test]
    fn unreachable_fs_subtrees_are_counted_not_only_logged() {
        let bs = 4096usize;
        // Block 0: FS B-tree internal root with one child, virtual OID 777.
        // Block 1: the volume object map, which does NOT map OID 777.
        let mut disk = vec![0u8; bs * 2];
        let root = build_omap_node(bs, true, false, &[(0, 0, 0, 777)]);
        disk[..bs].copy_from_slice(&root);
        let omap = build_omap_node(bs, true, true, &[(1, 1, 0, 1)]);
        disk[bs..bs * 2].copy_from_slice(&omap);
        let ds = ByteSliceDataSource::new(disk);

        let mut records = FsRecords::new();
        walk_fs_btree(
            &ds,
            0,
            bs as u32,
            1, // volume omap tree at block 1
            0,
            &mut records,
            0,
            &mut std::collections::HashSet::new(),
        )
        .expect("an unreachable child does not abort the whole walk");

        assert!(records.inodes.is_empty());
        assert_eq!(
            records.subtrees_unwalked, 1,
            "the unresolved subtree must be counted so the volume can be flagged"
        );
    }

    /// The same walk with a fully resolvable tree must report NOTHING unwalked
    /// — an incompleteness flag that is always on tells an examiner nothing.
    #[test]
    fn a_fully_walked_fs_tree_reports_no_unwalked_subtrees() {
        let bs = 4096usize;
        // Block 0: internal root pointing at virtual OID 777.
        // Block 1: omap mapping 777 -> physical block 2.
        // Block 2: an FS leaf with one directory record.
        let mut disk = vec![0u8; bs * 3];
        let root = build_omap_node(bs, true, false, &[(0, 0, 0, 777)]);
        disk[..bs].copy_from_slice(&root);
        let omap = build_omap_node(bs, true, true, &[(777, 1, 0, 2)]);
        disk[bs..bs * 2].copy_from_slice(&omap);
        let leaf = build_fs_leaf(bs, &[(drec_key(2, "file.txt"), drec_val(16, 8))]);
        disk[bs * 2..bs * 3].copy_from_slice(&leaf);
        let ds = ByteSliceDataSource::new(disk);

        let mut records = FsRecords::new();
        walk_fs_btree(
            &ds,
            0,
            bs as u32,
            1,
            0,
            &mut records,
            0,
            &mut std::collections::HashSet::new(),
        )
        .expect("walk failed");

        assert_eq!(records.subtrees_unwalked, 0);
        assert_eq!(records.dir_entry_count, 1);
    }

    // ---- BUG-156: decmpfs (transparent APFS compression) ----

    /// A `j_xattr_key_t` for `name` on inode `oid`.
    fn xattr_key(oid: u64, name: &str) -> Vec<u8> {
        let mut key = vec![0u8; 10];
        LittleEndian::write_u64(&mut key[0..8], j_key(APFS_TYPE_XATTR, oid));
        LittleEndian::write_u16(&mut key[8..10], (name.len() + 1) as u16);
        key.extend_from_slice(name.as_bytes());
        key.push(0);
        key
    }

    /// A `j_xattr_val_t` carrying an embedded value.
    fn xattr_val_embedded(data: &[u8]) -> Vec<u8> {
        let mut val = vec![0u8; 4];
        LittleEndian::write_u16(&mut val[0..2], XATTR_DATA_EMBEDDED);
        LittleEndian::write_u16(&mut val[2..4], data.len() as u16);
        val.extend_from_slice(data);
        val
    }

    /// A `j_xattr_val_t` carrying a `j_xattr_dstream_t` (48 bytes: the stream's
    /// object id followed by a `j_dstream_t`).
    fn xattr_val_stream(stream_id: u64, size: u64) -> Vec<u8> {
        let mut val = vec![0u8; 4 + 48];
        LittleEndian::write_u16(&mut val[0..2], XATTR_DATA_STREAM);
        LittleEndian::write_u16(&mut val[2..4], 48);
        LittleEndian::write_u64(&mut val[4..12], stream_id);
        LittleEndian::write_u64(&mut val[12..20], size); // j_dstream_t.size
        LittleEndian::write_u64(&mut val[20..28], size); // alloced_size
        val
    }

    /// The xattr records of the real fixture file, as `FsRecords` would hold
    /// them: `com.apple.decmpfs` type 8 plus a resource fork in stream 18.
    fn decmpfs_records(
        ino: u64,
        stream_id: u64,
        logical_size: u64,
        rfork: &[u8],
        block_size: u32,
    ) -> (FsRecords, Arc<dyn DataSource>) {
        let mut image = vec![0u8; block_size as usize * 2];
        image[block_size as usize..block_size as usize + rfork.len()].copy_from_slice(rfork);
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(image));

        let mut records = FsRecords::new();
        records.xattrs.insert(
            ino,
            ApfsInodeXattrs {
                decmpfs: Some(ApfsXattrValue::Embedded(decmpfs_xattr(
                    8,
                    logical_size,
                    &[],
                ))),
                resource_fork: Some(ApfsXattrValue::Stream {
                    stream_id,
                    size: rfork.len() as u64,
                }),
            },
        );
        records.extents.insert(
            stream_id,
            vec![ApfsExtent {
                logical_offset: 0,
                length: block_size as u64,
                phys_block_num: 1,
                crypto_id: 0,
            }],
        );
        (records, ds)
    }

    /// BUG-156. A decmpfs-compressed file has NO data-stream extents of its
    /// own, so the parser reported every compressed file on every macOS volume
    /// as content-less — and when content *was* served from the resource fork
    /// it would have been the compressed stream, hashed as though it were the
    /// file. The resource fork here was produced by macOS
    /// (`ditto --hfsCompression`), so this is real evidence, not a round trip.
    #[test]
    fn decmpfs_file_serves_its_decoded_bytes_not_the_compressed_stream() {
        let expected = real_tail_expected();
        let rfork = lzvn_resource_fork(&[real_tail_chunk()]);
        let (records, ds) = decmpfs_records(17, 18, expected.len() as u64, &rfork, 4096);

        let mut metadata = json!({ "size": expected.len() });
        let source = attach_file_content(
            &mut metadata,
            &records,
            17,
            17,
            expected.len() as u64,
            4096,
            &ds,
        )
        .expect("a decmpfs file must yield its content");

        assert_eq!(source.size(), expected.len() as u64);
        let mut buf = vec![0u8; expected.len()];
        read_exact_or_fail(source.as_ref(), 0, &mut buf, "decmpfs content").unwrap();
        assert_eq!(buf, expected, "the file must read as its DECODED bytes");
        assert_ne!(
            &buf[..rfork.len().min(buf.len())],
            &rfork[..rfork.len().min(buf.len())],
            "the compressed stream must never be served as the file"
        );

        // The residual false flag is retired: this file is not "missing".
        assert!(
            metadata.get("content_incomplete").is_none(),
            "a decoded decmpfs file must not be flagged incomplete: {metadata}"
        );
        assert_eq!(metadata["compressed"], true);
        assert_eq!(metadata["compression"], "apfs_decmpfs");
        assert_eq!(metadata["compression_format"], "decmpfs_lzvn_rsrc");
        assert_eq!(metadata["decmpfs_compression_type"], 8);
        assert_eq!(metadata["compressed_bytes"], rfork.len());

        // The COMPRESSED clusters are recorded under their own key. Writing
        // them as `data_runs` would have consumers re-serve the compressed
        // stream as the file's bytes.
        assert!(
            metadata.get("data_runs").is_none(),
            "compressed clusters must not be published as the file's own runs"
        );
        assert_eq!(metadata["compressed_data_runs_complete"], true);
        assert_eq!(metadata["compressed_data_runs"][0][0], 4096);
        assert_eq!(metadata["resource_fork_stream_id"], 18);
    }

    /// LIVE-001. Ingest decoded the file into memory, but nothing on the
    /// artifact said where the compressed bytes were, so once the walk was over
    /// the file had no retrievable content at all: every transparently
    /// compressed file on a macOS volume returned "no recorded content
    /// location" when an examiner asked to read, export or hash it. The
    /// recorded metadata plus the filesystem window must rebuild exactly the
    /// bytes ingest served.
    #[test]
    fn decmpfs_content_rebuilds_from_recorded_metadata_after_ingest() {
        let expected = real_tail_expected();
        let rfork = lzvn_resource_fork(&[real_tail_chunk()]);
        let (records, ds) = decmpfs_records(17, 18, expected.len() as u64, &rfork, 4096);

        let mut metadata = json!({ "size": expected.len() });
        let ingest = attach_file_content(
            &mut metadata,
            &records,
            17,
            17,
            expected.len() as u64,
            4096,
            &ds,
        )
        .expect("a decmpfs file must yield its content at ingest");
        let mut ingested = vec![0u8; expected.len()];
        read_exact_or_fail(ingest.as_ref(), 0, &mut ingested, "decmpfs content").unwrap();

        // Nothing but the persisted metadata and the filesystem window: the
        // parser's in-memory records are long gone when the content is asked
        // for.
        let rebuilt = reconstruct_decmpfs_content(Arc::clone(&ds), &metadata)
            .expect("the recorded content location must rebuild the file");
        assert_eq!(rebuilt, expected);
        assert_eq!(
            rebuilt, ingested,
            "the bytes exported later must be the bytes hashed at ingest"
        );
        let head = rfork.len().min(rebuilt.len());
        assert_ne!(
            &rebuilt[..head],
            &rfork[..head],
            "the compressed stream must never be handed back as the file"
        );
    }

    /// The same, for the storage form that keeps the whole file inside the
    /// attribute: the compressed stream is in the FS B-tree, which nothing
    /// re-walks after ingest, so the attribute has to be on the artifact.
    #[test]
    fn inline_decmpfs_content_rebuilds_from_recorded_metadata_after_ingest() {
        let plain = b"SEANCE decmpfs test. ".repeat(40);
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 8192]));
        let mut records = FsRecords::new();
        records.xattrs.insert(
            17,
            ApfsInodeXattrs {
                // Type 9: stored verbatim inside com.apple.decmpfs.
                decmpfs: Some(ApfsXattrValue::Embedded(decmpfs_xattr(
                    9,
                    plain.len() as u64,
                    &plain,
                ))),
                resource_fork: None,
            },
        );

        let mut metadata = json!({ "size": plain.len() });
        attach_file_content(
            &mut metadata,
            &records,
            17,
            17,
            plain.len() as u64,
            4096,
            &ds,
        )
        .expect("an inline decmpfs file must yield its content at ingest");

        let rebuilt = reconstruct_decmpfs_content(Arc::clone(&ds), &metadata)
            .expect("the recorded attribute must rebuild the file");
        assert_eq!(rebuilt, plain);
    }

    /// The rebuild is fail-closed for the same reason the decode is: a location
    /// that cannot be read whole must produce an error naming why, never the
    /// compressed bytes and never a short buffer that would hash as the file.
    #[test]
    fn decmpfs_reconstruction_fails_closed_rather_than_returning_partial_content() {
        let expected = real_tail_expected();
        let rfork = lzvn_resource_fork(&[real_tail_chunk()]);
        let (records, ds) = decmpfs_records(17, 18, expected.len() as u64, &rfork, 4096);

        let mut metadata = json!({ "size": expected.len() });
        attach_file_content(
            &mut metadata,
            &records,
            17,
            17,
            expected.len() as u64,
            4096,
            &ds,
        )
        .expect("a decmpfs file must yield its content at ingest");

        // The recorded location over a window whose compressed bytes are not
        // there.
        let blank: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 8192]));
        assert!(
            reconstruct_decmpfs_content(blank, &metadata).is_err(),
            "unreadable compressed bytes must not decode to anything"
        );

        // A run list the parser already declared short.
        let mut short = metadata.clone();
        short["compressed_data_runs_complete"] = json!(false);
        assert!(
            reconstruct_decmpfs_content(Arc::clone(&ds), &short).is_err(),
            "an incomplete compressed-run list must not be read"
        );

        // An artifact ingested before the location was recorded: the answer is
        // an error, not an empty file.
        assert!(
            reconstruct_decmpfs_content(Arc::clone(&ds), &json!({ "size": expected.len() }))
                .is_err(),
            "a missing content location must be reported, not read as empty"
        );
    }

    /// An algorithm this parser cannot decode (LZFSE is types 11 and 12, and is
    /// common on modern macOS) must be named, not passed through: serving the
    /// compressed bytes is exactly the defect.
    #[test]
    fn decmpfs_unsupported_algorithm_fails_closed() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 8192]));
        let mut records = FsRecords::new();
        records.xattrs.insert(
            17,
            ApfsInodeXattrs {
                decmpfs: Some(ApfsXattrValue::Embedded(decmpfs_xattr(
                    11,
                    4096,
                    &[0xAA; 32],
                ))),
                resource_fork: None,
            },
        );

        let mut metadata = json!({ "size": 4096 });
        let source = attach_file_content(&mut metadata, &records, 17, 17, 4096, 4096, &ds);
        assert!(source.is_none(), "LZFSE content must not be served raw");
        assert_eq!(metadata["content_incomplete"], true);
        assert_eq!(
            metadata["content_incomplete_reason"],
            "apfs_decmpfs_unsupported_algorithm"
        );
        assert_eq!(metadata["decmpfs_compression_type"], 11);
        assert!(metadata.get("data_runs").is_none());
    }

    /// A corrupt compressed stream must produce no content at all. Serving the
    /// prefix that happened to decode would be hashed and exported as the file.
    #[test]
    fn decmpfs_corrupt_stream_yields_no_partial_content() {
        let expected_len = real_tail_expected().len();
        let mut chunk = real_tail_chunk();
        chunk[66] ^= 0xFF; // shorten a large-match opcode
        let rfork = lzvn_resource_fork(&[chunk]);
        let (records, ds) = decmpfs_records(17, 18, expected_len as u64, &rfork, 4096);

        let mut metadata = json!({ "size": expected_len });
        let source = attach_file_content(
            &mut metadata,
            &records,
            17,
            17,
            expected_len as u64,
            4096,
            &ds,
        );
        assert!(source.is_none(), "a corrupt block must yield no content");
        assert_eq!(
            metadata["content_incomplete_reason"],
            "apfs_decmpfs_decode_failed"
        );
    }

    /// The inode's size and decmpfs's own size must agree before anything is
    /// decoded; disagreeing records cannot both be the file's length.
    #[test]
    fn decmpfs_size_disagreement_fails_closed() {
        let expected_len = real_tail_expected().len();
        let rfork = lzvn_resource_fork(&[real_tail_chunk()]);
        // decmpfs says 5696; the inode is told 9999.
        let (records, ds) = decmpfs_records(17, 18, expected_len as u64, &rfork, 4096);

        let mut metadata = json!({ "size": 9999 });
        let source = attach_file_content(&mut metadata, &records, 17, 17, 9999, 4096, &ds);
        assert!(source.is_none());
        assert_eq!(
            metadata["content_incomplete_reason"],
            "apfs_decmpfs_size_mismatch"
        );
    }

    /// The B-tree walk must actually collect the two attributes that decide
    /// content; without this the whole decmpfs path is unreachable in the
    /// product.
    #[test]
    fn the_fs_walk_collects_the_decmpfs_and_resource_fork_attributes() {
        let bs = 4096usize;
        let decmpfs_value = decmpfs_xattr(8, 4_200_000, &[]);
        let node = build_fs_leaf(
            bs,
            &[
                (
                    xattr_key(17, XATTR_NAME_DECMPFS),
                    xattr_val_embedded(&decmpfs_value),
                ),
                (
                    xattr_key(17, XATTR_NAME_RESOURCE_FORK),
                    xattr_val_stream(18, 33_622),
                ),
                // An attribute with no bearing on content is not retained.
                (
                    xattr_key(17, "com.apple.provenance"),
                    xattr_val_embedded(&[1, 2, 3]),
                ),
            ],
        );
        let ds = ByteSliceDataSource::new(node);

        let mut records = FsRecords::new();
        walk_fs_btree(
            &ds,
            0,
            bs as u32,
            0,
            0,
            &mut records,
            0,
            &mut std::collections::HashSet::new(),
        )
        .expect("walk failed");

        let xattrs = records
            .xattrs
            .get(&17)
            .expect("the decmpfs attributes must reach FsRecords");
        match xattrs.decmpfs.as_ref() {
            Some(ApfsXattrValue::Embedded(bytes)) => {
                let header = crate::decmpfs::parse_header(bytes).expect("header must parse");
                assert_eq!(header.compression_type, 8);
                assert_eq!(header.uncompressed_size, 4_200_000);
            }
            other => panic!("decmpfs attribute not collected: {other:?}"),
        }
        match xattrs.resource_fork.as_ref() {
            Some(ApfsXattrValue::Stream { stream_id, size }) => {
                assert_eq!(*stream_id, 18);
                assert_eq!(*size, 33_622);
            }
            other => panic!("resource fork attribute not collected: {other:?}"),
        }
    }

    #[test]
    fn xattr_records_parse_from_their_on_disk_layout() {
        let key = xattr_key(17, XATTR_NAME_DECMPFS);
        assert_eq!(
            parse_j_xattr_name(&key).as_deref(),
            Some(XATTR_NAME_DECMPFS)
        );
        assert_eq!(
            j_key_type(LittleEndian::read_u64(&key[0..8])),
            APFS_TYPE_XATTR
        );

        match parse_j_xattr_val(&xattr_val_stream(18, 33_622)) {
            Some(ApfsXattrValue::Stream { stream_id, size }) => {
                assert_eq!(stream_id, 18);
                assert_eq!(size, 33_622);
            }
            other => panic!("stream xattr misparsed: {other:?}"),
        }
        match parse_j_xattr_val(&xattr_val_embedded(&[9, 8, 7])) {
            Some(ApfsXattrValue::Embedded(bytes)) => assert_eq!(bytes, vec![9, 8, 7]),
            other => panic!("embedded xattr misparsed: {other:?}"),
        }
        // A record that declares more data than it holds is unreadable, not
        // empty.
        let mut short = xattr_val_embedded(&[1, 2, 3]);
        LittleEndian::write_u16(&mut short[2..4], 64);
        assert!(parse_j_xattr_val(&short).is_none());
    }

    // ---- BUG-157: per-extent crypto_id ----

    /// The negative control that made this fix safe to ship. Every extent on
    /// every unencrypted APFS volume measured carries `crypto_id == 0`; a
    /// threshold that treated that as encryption would flag every file on every
    /// normal volume, which is why this finding was held until a control
    /// existed.
    #[test]
    fn clear_extents_are_never_flagged_as_encrypted() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEE; 8192]));
        let mut records = FsRecords::new();
        records.extents.insert(
            9000,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 4096,
                phys_block_num: 1,
                crypto_id: CRYPTO_ID_NONE,
            }],
        );

        let mut metadata = json!({ "size": 4096 });
        let source = attach_file_content(&mut metadata, &records, 500, 9000, 4096, 4096, &ds)
            .expect("a clear file must still serve its content");
        let mut buf = vec![0u8; 4096];
        assert_eq!(source.read_at(0, &mut buf).unwrap(), 4096);
        assert!(buf.iter().all(|&b| b == 0xEE));

        assert!(metadata.get("content_encrypted").is_none());
        assert!(metadata.get("encryption").is_none());
        assert!(metadata.get("content_incomplete").is_none());
        assert_eq!(metadata["data_runs_complete"], true);
    }

    /// `APFS_UNASSIGNED_CRYPTO_ID` is Apple's "no key assigned" sentinel, not a
    /// key. Treating it as encryption would withhold content that is in fact
    /// clear.
    #[test]
    fn the_unassigned_crypto_id_sentinel_is_not_encryption() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEE; 8192]));
        let mut records = FsRecords::new();
        records.extents.insert(
            9000,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 4096,
                phys_block_num: 1,
                crypto_id: APFS_UNASSIGNED_CRYPTO_ID,
            }],
        );

        let mut metadata = json!({ "size": 4096 });
        assert!(
            attach_file_content(&mut metadata, &records, 500, 9000, 4096, 4096, &ds).is_some(),
            "the unassigned sentinel must not withhold clear content"
        );
        assert!(metadata.get("content_encrypted").is_none());
    }

    /// BUG-157. `crypto_id` was parsed and thrown away, so an extent whose
    /// blocks are ciphertext mapped as clear content: the file was exported and
    /// hashed as plaintext with no warning anywhere.
    #[test]
    fn encrypted_extents_withhold_content_and_record_where_it_is() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEE; 8192]));
        let mut records = FsRecords::new();
        records.extents.insert(
            9000,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 4096,
                phys_block_num: 1,
                crypto_id: 0x1234,
            }],
        );

        let mut metadata = json!({ "size": 4096 });
        let source = attach_file_content(&mut metadata, &records, 500, 9000, 4096, 4096, &ds);
        assert!(
            source.is_none(),
            "ciphertext must never be served as the file's plaintext"
        );
        assert_eq!(metadata["content_encrypted"], true);
        assert_eq!(metadata["encryption"], "apfs_per_extent_crypto");
        assert_eq!(metadata["content_incomplete"], true);
        assert_eq!(
            metadata["content_incomplete_reason"],
            "apfs_extent_encrypted"
        );
        // The run list must not be servable...
        assert_eq!(metadata["data_runs_complete"], false);
        // ... but the location of the ciphertext is still on the record.
        assert_eq!(metadata["encrypted_extent_count"], 1);
        assert_eq!(metadata["encrypted_extents"][0]["physical_offset"], 4096);
        assert_eq!(metadata["encrypted_extents"][0]["crypto_id"], 0x1234);
        assert_eq!(metadata["encrypted_extents"][0]["length"], 4096);
    }

    /// Structural guard: whatever builds an `ApfsFileSource`, an encrypted
    /// extent is refused at read time. Fixing only the metadata path would
    /// leave every future caller free to reintroduce the defect.
    #[test]
    fn the_file_source_refuses_to_read_an_encrypted_extent() {
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xEE; 8192]));
        let source = ApfsFileSource::new(
            inner,
            4096,
            4096,
            vec![ApfsExtent {
                logical_offset: 0,
                length: 4096,
                phys_block_num: 1,
                crypto_id: 7,
            }],
            true,
        );
        let mut buf = vec![0u8; 4096];
        let err = source
            .read_at(0, &mut buf)
            .expect_err("an encrypted extent must not read as plaintext");
        assert!(err.to_string().contains("encrypted"), "{err}");
    }

    /// An extent list carrying ciphertext must not publish servable byte runs:
    /// a consumer reading `data_runs` from the database would otherwise rebuild
    /// the file out of encrypted blocks and present it as content.
    #[test]
    fn encrypted_extents_are_not_published_as_servable_runs() {
        let extents = vec![ApfsExtent {
            logical_offset: 0,
            length: 4096,
            phys_block_num: 9,
            crypto_id: 42,
        }];
        let mut metadata = json!({});
        apply_extent_metadata(&mut metadata, &extents, 4096, 4096, false);
        assert_eq!(metadata["data_runs_complete"], false);
        assert_eq!(metadata["content_encrypted"], true);
        assert_eq!(
            metadata["content_incomplete_reason"],
            "apfs_extent_encrypted"
        );
        // The single run must be a hole, not a pointer at block 9.
        assert_eq!(metadata["data_runs"][0][0], serde_json::Value::Null);
    }

    // ---- container volume-slot count ----

    /// `nx_max_file_systems` lives at offset 180; offset 168 is `nx_reaper_oid`.
    /// Reading the count from 168 returned the reaper OID's low 32 bits — 1025
    /// on every real container measured — so the parser believed 925 volume
    /// slots had been skipped and stamped a "volume inventory incomplete"
    /// record on every APFS image. A warning that fires on every case teaches
    /// examiners to ignore warnings.
    #[test]
    fn a_normal_container_reports_no_skipped_volume_slots() {
        let block_size: u32 = 4096;
        let mut data = vec![0u8; block_size as usize];
        LittleEndian::write_u32(&mut data[24..28], 0x4000_0001);
        LittleEndian::write_u32(&mut data[32..36], NXSB_MAGIC);
        LittleEndian::write_u32(&mut data[36..40], block_size);
        LittleEndian::write_u64(&mut data[40..48], 12_278);
        LittleEndian::write_u64(&mut data[160..168], 700);
        // Exactly the layout a real container has: reaper OID 1025 at +168,
        // test type 0 at +176, one declared volume slot at +180.
        LittleEndian::write_u64(&mut data[168..176], 1025);
        LittleEndian::write_u32(&mut data[176..180], 0);
        LittleEndian::write_u32(&mut data[180..184], 1);
        LittleEndian::write_u64(&mut data[184..192], 1026);

        let sb = parse_nx_superblock(&ByteSliceDataSource::new(data)).unwrap();
        assert_eq!(sb.max_file_systems, 1);
        assert_eq!(sb.fs_oid, vec![1026]);
        assert_eq!(
            sb.fs_oid_slots_skipped, 0,
            "a container declaring one volume must not report skipped slots"
        );
    }

    /// Real-image regression for BUG-156, gated on the fixture being present.
    /// `apfs_compressed.dmg` holds a 4,200,000-byte decmpfs file in ~36 KB of
    /// resource fork plus an incompressible control; the control is what proves
    /// the fix does not mislabel ordinary files.
    #[test]
    fn apfs_compressed_volume_decodes_its_compressed_file() {
        use seance_core::data_source::{FileDataSource, WindowSource};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test_data/apfs_compressed.dmg");
        if !path.exists() {
            eprintln!("skipping apfs_compressed_volume_decodes_its_compressed_file: image absent");
            return;
        }
        let file_len = std::fs::metadata(&path).unwrap().len();
        const CONTAINER_OFFSET: u64 = 20480;
        let inner: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
        let window = WindowSource::new(inner, CONTAINER_OFFSET, file_len - CONTAINER_OFFSET);
        let src: Arc<dyn DataSource> = Arc::new(window);
        let art = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(src),
            json!({ "subtype": "apfs" }),
        );
        let out = ApfsParser.process(&art).expect("process must not error");

        // No container-level incompleteness marker on a well-formed container.
        assert!(
            !out.iter()
                .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                    == Some("VolumeInventoryIncomplete")),
            "a normal container must not be reported as having an incomplete volume inventory"
        );

        let compressed = out
            .iter()
            .find(|a| {
                a.metadata.get("name").and_then(|v| v.as_str()) == Some("highly_compressible.txt")
            })
            .expect("the compressed file must be in the inventory");
        assert_eq!(compressed.metadata["size"], 4_200_000u64);
        assert_eq!(compressed.metadata["compression"], "apfs_decmpfs");
        assert_eq!(
            compressed.metadata["compression_format"],
            "decmpfs_lzvn_rsrc"
        );
        assert!(
            compressed.metadata.get("content_incomplete").is_none(),
            "the decoded file must not be flagged incomplete: {}",
            compressed.metadata
        );

        let data = compressed
            .data
            .as_ref()
            .expect("the compressed file must carry content");
        assert_eq!(data.size(), 4_200_000);
        let mut buf = vec![0u8; 4_200_000];
        read_exact_or_fail(data.as_ref(), 0, &mut buf, "decmpfs file").unwrap();
        let pattern = b"SEANCE decmpfs test. ";
        assert!(
            buf.iter()
                .enumerate()
                .all(|(i, &b)| b == pattern[i % pattern.len()]),
            "the decoded bytes must be the known plaintext, not the compressed stream"
        );

        // The incompressible control must be untouched by the compression path.
        let control = out
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("incompressible.bin"))
            .expect("the control file must be in the inventory");
        assert_eq!(control.metadata["size"], 2_097_152u64);
        assert!(
            control.metadata.get("compression").is_none(),
            "an ordinary file must not be labelled compressed"
        );
        assert!(
            control.metadata.get("content_encrypted").is_none()
                && control.metadata.get("encryption").is_none(),
            "an ordinary file on an unencrypted volume must not be flagged encrypted"
        );
        assert!(control.metadata.get("content_incomplete").is_none());
        assert_eq!(control.metadata["data_runs_complete"], true);
    }

    /// A live file entry as the walk emits it: size, inode and the persisted
    /// whole-block run list `apply_extent_metadata` writes.
    fn walked_file(name: &str, inode: u64, size: u64, runs: serde_json::Value) -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({
                "name": name,
                "path": format!("/{name}"),
                "inode": inode,
                "size": size,
                "is_directory": false,
                "data_runs": runs,
                "data_runs_complete": true,
            }),
        )
    }

    /// HUNT-282. The tail of a live APFS file's last block, past its logical
    /// end, is published as a `SlackSpace` region holding exactly the bytes
    /// there; a file reached under two names is offered once, a file whose
    /// run list is incomplete is counted as not located rather than as having
    /// no slack, and an all-zero tail raises nothing. SYNTHETIC entries and
    /// bytes: the real-volume test is `tests/real_slack_test.rs`.
    #[test]
    fn a_live_files_planted_tail_is_published_as_a_slack_region() {
        const BS: u64 = 4096;
        let mut volume = vec![0u8; 8 * BS as usize];
        // File A: 100 bytes in block 2, tail planted from byte 100.
        volume[2 * BS as usize..2 * BS as usize + 100].fill(b'a');
        let planted = b"PLANTED-TAIL-0123456789";
        let at = 2 * BS as usize + 100;
        volume[at..at + planted.len()].copy_from_slice(planted);
        // File B: 10 bytes in block 4, zero tail.
        volume[4 * BS as usize..4 * BS as usize + 10].fill(b'b');
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(volume.clone()));
        let fs = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::clone(&source)),
            json!({ "filesystem_type": "APFS" }),
        );
        let a = walked_file("a.txt", 20, 100, json!([[2 * BS, BS]]));
        // The same inode under a second name: offered once.
        let a_link = walked_file("a-link.txt", 20, 100, json!([[2 * BS, BS]]));
        let b = walked_file("b.txt", 21, 10, json!([[4 * BS, BS]]));
        // Run list incomplete: a tail exists and nobody can say where.
        let mut c = walked_file("c.txt", 22, 100, json!([[6 * BS, BS]]));
        c.metadata["data_runs_complete"] = json!(false);
        let walked = vec![a, a_link, b, c];

        let out = publish_file_slack(&walked, &fs, &source, BS as u32);
        let regions: Vec<&Artifact> = out
            .iter()
            .filter(|x| x.artifact_type == ArtifactType::SlackSpace)
            .collect();
        assert_eq!(regions.len(), 1, "{out:#?}");
        let r = regions[0];
        assert_eq!(r.metadata["filesystem"], json!("apfs"));
        assert_eq!(r.metadata["source"], json!("file_slack"));
        assert_eq!(r.metadata["parent_file"], json!("a.txt"));
        assert_eq!(r.metadata["offset_bytes"], json!(2 * BS + 100));
        assert_eq!(r.metadata["size_bytes"], json!(BS - 100));
        assert_eq!(r.metadata["cluster_size"], json!(BS));
        let src = r.data.as_ref().expect("a region carries its bytes");
        let mut got = vec![0u8; src.size() as usize];
        src.read_at(0, &mut got).unwrap();
        assert_eq!(got, volume[at..(3 * BS) as usize].to_vec());

        let summary = out
            .iter()
            .find(|x| x.metadata.get("type") == Some(&json!("SlackSpaceSummary")))
            .expect("the summary is always published");
        assert_eq!(summary.metadata["filesystem"], json!("apfs"));
        assert_eq!(
            summary.metadata["files_offered"],
            json!(2),
            "a and b once each"
        );
        assert_eq!(summary.metadata["regions_emitted"], json!(1));
        assert_eq!(summary.metadata["zero_tails"], json!(1));
        assert_eq!(summary.metadata["files_not_located"], json!(1));
    }
}
