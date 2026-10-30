#![forbid(unsafe_code)]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
// Btrfs Filesystem Parser
//
// Implements full B-tree traversal, chunk mapping, and filesystem walking to
// produce FileEntry artifacts from a Btrfs filesystem image.
//
// References:
// - Btrfs On-disk Format: https://btrfs.readthedocs.io/en/stable/dev/On-disk-format.html
// - Btrfs Data Structures: https://btrfs.wiki.kernel.org/index.php/Data_Structures
// - Btrfs B-trees: https://btrfs.readthedocs.io/en/latest/dev/dev-btrees.html

use byteorder::{ByteOrder, LittleEndian};
use chrono::{DateTime, Utc};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::{read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::io;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Maps a btrfs device id (dev_item.devid) to the DataSource for that device.
/// Always contains the opened (primary) device; sibling devices of a
/// multi-device filesystem are added when discoverable so striped/mirrored
/// content can be reconstructed across images.
type DeviceMap = std::collections::HashMap<u64, Arc<dyn DataSource>>;

// --- Constants ---

const BTRFS_MAGIC: &[u8; 8] = b"_BHRfS_M";
const BTRFS_SUPERBLOCK_OFFSET_1: u64 = 0x10000; // 64 KiB
const BTRFS_SUPERBLOCK_OFFSET_2: u64 = 0x4000000; // 64 MiB
const BTRFS_SUPERBLOCK_OFFSET_3: u64 = 0x4000000000; // 256 GiB

const BTRFS_SUPERBLOCK_SIZE: usize = 4096;

// Key type constants. The full table from the on-disk format, kept whole so
// it reads as the specification does; the walker does not branch on every one.
#[allow(dead_code)]
const BTRFS_DIR_ITEM_KEY: u8 = 84;
const BTRFS_INODE_ITEM_KEY: u8 = 1;
const BTRFS_DIR_INDEX_KEY: u8 = 96;
const BTRFS_EXTENT_DATA_KEY: u8 = 108;
const BTRFS_ROOT_ITEM_KEY: u8 = 132;
const BTRFS_CHUNK_ITEM_KEY: u8 = 228;

// Object IDs. Same rule as the key table above.
#[allow(dead_code)]
const BTRFS_ROOT_TREE_OBJECTID: u64 = 1;
const BTRFS_FS_TREE_OBJECTID: u64 = 5;
const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;
const BTRFS_LAST_FREE_OBJECTID: u64 = u64::MAX - 255; // -256, exclusive of reserved high trees
const BTRFS_ROOT_DIR_OBJECTID: u64 = 256;

// Safety limits
const MAX_DIR_ENTRIES: usize = 500_000;
const MAX_EXTENTS: usize = 100_000;
const MAX_BTREE_DEPTH: usize = 8;
const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4 GB
                                                   // btrfs nodesize is a power of two in [sectorsize, 64 KiB]. It is read straight
                                                   // from the (attacker-controlled) superblock and used as `vec![0u8; nodesize]`
                                                   // for every B-tree node, so a bogus value causes an unbounded allocation (OOM).
                                                   // Cap generously at 256 KiB and refuse anything larger.
const MAX_NODESIZE: u32 = 256 * 1024;
// btrfs requires nodesize >= 4096 (it is a power of two, at least the sectorsize,
// itself at least 4096). A superblock declaring anything smaller is corrupt, and
// parsing must reject it BEFORE slicing the 101-byte node header out of the
// buffer: a `nodesize` of 1..=100 passed the zero check, made a buffer too short
// for the header, and panicked `node_data[48..56]` (a slice-range panic that
// unwound the whole btrfs parse). Found by fuzzing.
const MIN_NODESIZE: u32 = 4096;
// Hard ceiling on the number of nodes visited in a single B-tree traversal.
// With the per-address visited set this only trips on pathological/cyclic node
// graphs; it bounds total work and the accumulated result set regardless.
const MAX_BTREE_NODES: usize = 1_000_000;

// --- Data Structures ---

#[derive(Debug, Clone)]
struct BtrfsKey {
    objectid: u64,
    key_type: u8,
    offset: u64,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug)]
struct BtrfsHeader {
    bytenr: u64,
    generation: u64,
    owner: u64,
    nritems: u32,
    level: u8,
}

#[derive(Debug)]
struct BtrfsItem {
    key: BtrfsKey,
    offset: u32,
    size: u32,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug)]
struct BtrfsKeyPointer {
    key: BtrfsKey,
    blockptr: u64,
    generation: u64,
}

#[derive(Debug, Clone)]
struct BtrfsChunkItem {
    length: u64,
    type_flags: u64,
    stripe_len: u64,
    num_stripes: u16,
    stripes: Vec<BtrfsStripe>,
}

// btrfs block-group / chunk profile flags. RAID1 and DUP are mirrored
// profiles: stripe 0 is a whole copy, so the chunk map needs no branch for
// them and they are listed only to keep the table whole.
const BTRFS_BLOCK_GROUP_RAID0: u64 = 1 << 3;
#[allow(dead_code)]
const BTRFS_BLOCK_GROUP_RAID1: u64 = 1 << 4;
#[allow(dead_code)]
const BTRFS_BLOCK_GROUP_DUP: u64 = 1 << 5;
const BTRFS_BLOCK_GROUP_RAID10: u64 = 1 << 6;
const BTRFS_BLOCK_GROUP_RAID5: u64 = 1 << 7;
const BTRFS_BLOCK_GROUP_RAID6: u64 = 1 << 8;
/// Profiles that stripe data across devices (data is split, not mirrored).
const BTRFS_STRIPED_PROFILES: u64 = BTRFS_BLOCK_GROUP_RAID0
    | BTRFS_BLOCK_GROUP_RAID10
    | BTRFS_BLOCK_GROUP_RAID5
    | BTRFS_BLOCK_GROUP_RAID6;

#[derive(Debug, Clone)]
struct BtrfsStripe {
    devid: u64,
    offset: u64,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct BtrfsDirItem {
    location: BtrfsKey,
    name: String,
    dir_type: u8,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct BtrfsInodeItem {
    generation: u64,
    size: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    atime_sec: i64,
    mtime_sec: i64,
    ctime_sec: i64,
    /// btrfs otime: real inode creation time (0 when unset)
    otime_sec: i64,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct BtrfsExtentData {
    generation: u64,
    ram_bytes: u64,
    compression: u8,
    /// `btrfs_file_extent_item.encryption` (+17). Non-zero means the extent
    /// payload is ciphertext this parser cannot decrypt, so anything we map or
    /// hash for it is not plaintext (BUG-181).
    encryption: u8,
    extent_type: u8, // 0=inline, 1=regular, 2=prealloc
    // For regular/prealloc extents:
    disk_bytenr: u64,
    disk_num_bytes: u64,
    /// Offset into the (decompressed, for compressed extents) extent data that
    /// this file_extent references. Kept separate from disk_bytenr because you
    /// cannot byte-seek into a compressed extent.
    extent_offset: u64,
    offset: u64,
    num_bytes: u64,
    // For inline extents (and materialized-decompressed regular extents):
    inline_data: Vec<u8>,
}

// Decoded in full from the on-disk record. Fields the walker does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
enum BtrfsNode {
    Internal {
        header: BtrfsHeader,
        pointers: Vec<BtrfsKeyPointer>,
    },
    Leaf {
        header: BtrfsHeader,
        items: Vec<BtrfsItem>,
        data: Vec<u8>,
    },
}

#[derive(Debug)]
struct BtrfsSuperblock {
    fsid: [u8; 16],
    total_bytes: u64,
    bytes_used: u64,
    generation: u64,
    root: u64,
    chunk_root: u64,
    num_devices: u64,
    sectorsize: u32,
    nodesize: u32,
    label: String,
}

// --- BtrfsFileSource (DataSource for file content) ---

struct BtrfsFileSource {
    devices: Arc<DeviceMap>,
    chunk_map: Vec<(u64, u64, BtrfsChunkItem)>,
    size: u64,
    extents: Vec<BtrfsExtentData>,
    /// True when `extents` is the file's COMPLETE extent list. When false the
    /// MAX_EXTENTS cap dropped records, so everything past the last known extent
    /// is unknown rather than a sparse hole (BUG-212 / B2-032).
    extents_complete: bool,
    /// One past the highest file offset any known extent covers.
    mapped_end: u64,
}

impl BtrfsFileSource {
    fn new(
        devices: Arc<DeviceMap>,
        chunk_map: Vec<(u64, u64, BtrfsChunkItem)>,
        size: u64,
        extents: Vec<BtrfsExtentData>,
        extents_complete: bool,
    ) -> Self {
        let mapped_end = extents
            .iter()
            .map(|e| e.offset.saturating_add(e.covered_bytes()))
            .max()
            .unwrap_or(0);
        Self {
            devices,
            chunk_map,
            size,
            extents,
            extents_complete,
            mapped_end,
        }
    }
}

impl BtrfsExtentData {
    /// Number of file bytes this extent accounts for: the inline payload for an
    /// inline extent, `num_bytes` for a regular/prealloc one.
    fn covered_bytes(&self) -> u64 {
        if self.extent_type == 0 {
            self.inline_data.len() as u64
        } else {
            self.num_bytes
        }
    }
}

/// The error returned when an extent's bytes are still compressed.
///
/// Serving them would put a compressed blob under the file's name, size and
/// hash; an examiner comparing that hash against a known-file set would get a
/// miss that looks like evidence the file differs from the known copy.
fn compressed_content_error(compression: u8) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "btrfs extent is compressed (codec {compression}) and was not decompressed; \
             refusing to serve compressed bytes as file content"
        ),
    )
}

impl std::fmt::Debug for BtrfsFileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtrfsFileSource")
            .field("size", &self.size)
            .field("extents", &self.extents.len())
            .finish()
    }
}

impl DataSource for BtrfsFileSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }

        let to_read = std::cmp::min(buf.len() as u64, self.size - offset) as usize;
        let mut bytes_read = 0;

        while bytes_read < to_read {
            let file_offset = offset + bytes_read as u64;
            let mut found = false;

            for ext in &self.extents {
                if ext.extent_type == 0 {
                    // Inline extent: data is stored directly
                    let ext_start = ext.offset; // file offset for this extent (from key.offset)
                                                // Saturating: extent offsets come off the image and a wrapped
                                                // end would make an unrelated range look like this extent.
                    let ext_end = ext_start.saturating_add(ext.inline_data.len() as u64);
                    if file_offset >= ext_start && file_offset < ext_end {
                        // A still-compressed inline payload is not the file's
                        // bytes. Copying it out would hash and index a
                        // compressed blob as plaintext (B2-003).
                        if ext.compression != BTRFS_COMPRESS_NONE {
                            return Err(compressed_content_error(ext.compression));
                        }
                        let offset_in_data = (file_offset - ext_start) as usize;
                        let available = ext.inline_data.len() - offset_in_data;
                        let chunk = std::cmp::min(to_read - bytes_read, available);
                        buf[bytes_read..bytes_read + chunk].copy_from_slice(
                            &ext.inline_data[offset_in_data..offset_in_data + chunk],
                        );
                        bytes_read += chunk;
                        found = true;
                        break;
                    }
                } else if ext.extent_type == 1 || ext.extent_type == 2 {
                    // Regular or prealloc extent
                    let ext_file_start = ext.offset;
                    let ext_file_end = ext_file_start.saturating_add(ext.num_bytes);
                    if file_offset >= ext_file_start && file_offset < ext_file_end {
                        let offset_in_extent = file_offset - ext_file_start;
                        // disk_bytenr is the raw extent start; the file_extent's
                        // own offset into it (uncompressed) adds here. Saturating:
                        // a wrapped logical address would resolve to an unrelated
                        // chunk and serve its bytes as this file's content.
                        let logical_addr = ext
                            .disk_bytenr
                            .saturating_add(ext.extent_offset)
                            .saturating_add(offset_in_extent);

                        // A prealloc extent (type 2) is allocated but never
                        // written: the kernel returns zeros for it, so serving
                        // the bytes at disk_bytenr would hand back residual
                        // data as file content (BUG-209).
                        if ext.disk_bytenr == 0 || ext.extent_type == 2 {
                            // Sparse/hole or preallocated
                            let available = (ext_file_end - file_offset) as usize;
                            let chunk = std::cmp::min(to_read - bytes_read, available);
                            for b in &mut buf[bytes_read..bytes_read + chunk] {
                                *b = 0;
                            }
                            bytes_read += chunk;
                            found = true;
                            break;
                        }

                        // The extent is compressed and was never materialized
                        // (over the materialize cap, an unsupported codec, or a
                        // failed decompression). `disk_bytenr + extent_offset`
                        // addresses the COMPRESSED stream, so mapping a logical
                        // file offset onto it serves compressed bytes — and
                        // neighbouring extent bytes past its end — as if they
                        // were the file's plaintext. Refuse instead: a wrong
                        // hash over a compressed blob is indistinguishable from
                        // the hash of the real file (B2-003).
                        if ext.compression != BTRFS_COMPRESS_NONE {
                            return Err(compressed_content_error(ext.compression));
                        }

                        // Read the logical range via the device map. read_logical
                        // follows stripe/device boundaries (RAID0/10) and reports
                        // false when any part of the range could not be fetched:
                        // an unmapped logical address, a device we do not have,
                        // or a short read on a device we do have. It zero-fills
                        // those regions internally, so serving the buffer anyway
                        // would hand back fabricated zeros as file content and
                        // hash them as if the file were whole (BUG-241).
                        let available = (ext_file_end - file_offset) as usize;
                        let chunk = std::cmp::min(to_read - bytes_read, available);
                        let complete = read_logical(
                            logical_addr,
                            &self.devices,
                            &self.chunk_map,
                            &mut buf[bytes_read..bytes_read + chunk],
                        );
                        if !complete {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "btrfs logical range at {logical_addr} could not be fully \
                                     read; refusing to serve zero-filled bytes as file content"
                                ),
                            ));
                        }
                        bytes_read += chunk;
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                // No extent covers this offset. Inside a complete extent list
                // that is a genuine hole and reads as zeros. Past the last known
                // extent of a TRUNCATED list it is unknown data, so short-read
                // rather than fabricate zeros the caller would hash and export
                // as content (B2-032).
                if !self.extents_complete && file_offset >= self.mapped_end {
                    break;
                }
                // Zero the whole hole up to the next known extent in one go.
                let next_start = self
                    .extents
                    .iter()
                    .map(|e| e.offset)
                    .filter(|&o| o > file_offset)
                    .min()
                    .unwrap_or(self.size);
                let gap = next_start.saturating_sub(file_offset);
                let chunk = std::cmp::min((to_read - bytes_read) as u64, gap) as usize;
                if chunk == 0 {
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

// --- Module Implementation ---

pub struct BtrfsParser;

impl ForensicsModule for BtrfsParser {
    fn id(&self) -> &str {
        "plugin.filesystem.btrfs"
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
        // Check if this is a Btrfs filesystem
        let subtype = artifact.metadata.get("subtype").and_then(|v| v.as_str());

        if subtype != Some("btrfs") {
            return Ok(Vec::new());
        }

        info!(
            "Btrfs parser processing filesystem artifact ID: {}",
            artifact.id
        );

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("Btrfs parser requires a data source".to_string())
        })?;

        // Load the superblock from the primary copy, falling back to the mirrors.
        // The raw bytes come back with it: the system chunk array and the
        // device's own devid are read out of the SAME copy the superblock was
        // parsed from, never re-read from the primary offset (see
        // `load_btrfs_superblock`).
        let (superblock, sb_data, sb_offset) = load_btrfs_superblock(data_source.as_ref())
            .map_err(|e| {
                ModuleError::ParsingError(format!(
                    "Failed to parse Btrfs superblock (artifact ID: {}): {}",
                    artifact.id, e
                ))
            })?;

        debug!(
            "Btrfs Superblock @0x{:X}: generation={}, total_bytes={}, num_devices={}, label='{}'",
            sb_offset,
            superblock.generation,
            superblock.total_bytes,
            superblock.num_devices,
            superblock.label
        );

        let mut produced_artifacts = vec![];

        // Emit filesystem metadata artifact
        let fs_artifact_idx = produced_artifacts.len();
        produced_artifacts.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::FileSystem,
                Some(Arc::clone(data_source)),
                json!({
                    "filesystem_type": "Btrfs",
                    "total_bytes": superblock.total_bytes,
                    "bytes_used": superblock.bytes_used,
                    "generation": superblock.generation,
                    "num_devices": superblock.num_devices,
                    "sector_size": superblock.sectorsize,
                    "node_size": superblock.nodesize,
                    "label": superblock.label,
                    "fsid": format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                                   superblock.fsid[0], superblock.fsid[1], superblock.fsid[2], superblock.fsid[3],
                                   superblock.fsid[4], superblock.fsid[5], superblock.fsid[6], superblock.fsid[7],
                                   superblock.fsid[8], superblock.fsid[9], superblock.fsid[10], superblock.fsid[11],
                                   superblock.fsid[12], superblock.fsid[13], superblock.fsid[14], superblock.fsid[15]),
                    // Which superblock copy this reconstruction came from. A
                    // mirror means the primary was damaged or wiped, which an
                    // examiner needs to see: the mirror can be an older
                    // generation than the volume's last committed state.
                    "superblock_offset": sb_offset,
                    "superblock_is_mirror": sb_offset != BTRFS_SUPERBLOCK_OFFSET_1,
                }),
            ).with_parent(artifact.id)
        );

        // Filesystem image path (if known): lets us discover sibling device
        // images of a multi-device btrfs filesystem in the same directory.
        let fs_path = ["path", "source_path", "container_path"]
            .iter()
            .find_map(|k| artifact.metadata.get(*k).and_then(|v| v.as_str()));

        // Attempt full B-tree traversal and filesystem walking
        match walk_filesystem(
            data_source,
            &superblock,
            &sb_data,
            artifact.case_id,
            artifact.id,
            fs_path,
        ) {
            Ok(walk) => {
                info!(
                    "Btrfs B-tree traversal produced {} file entries",
                    walk.artifacts.len()
                );
                if let Some(reason) = walk.btree_incomplete_reason {
                    warn!(
                        "Btrfs B-tree traversal was cut short ({}); the file inventory is a prefix of the filesystem",
                        reason
                    );
                    // Files and whole subtrees were never visited: say so rather
                    // than let a partial walk read as a full one (B2-095).
                    produced_artifacts[fs_artifact_idx].metadata["inventory_incomplete"] =
                        json!(true);
                    produced_artifacts[fs_artifact_idx].metadata["inventory_incomplete_reason"] =
                        json!(reason);
                }
                if walk.dir_entries_truncated {
                    warn!(
                        "Btrfs walk hit the {} directory-entry cap; listing is incomplete",
                        MAX_DIR_ENTRIES
                    );
                    // Honesty flag on the filesystem artifact: a short inventory
                    // must not read as a complete one (BUG-215).
                    produced_artifacts[fs_artifact_idx].metadata["directory_parse_incomplete"] =
                        json!(true);
                    produced_artifacts[fs_artifact_idx].metadata
                        ["directory_parse_incomplete_reason"] = json!("btrfs_max_dir_entries");
                }
                if !walk.unresolved_subvolumes.is_empty() {
                    // Each of these is a whole subvolume the trees name but
                    // whose files never entered the case (B7-009).
                    produced_artifacts[fs_artifact_idx].metadata["unresolved_subvolumes"] =
                        json!(walk.unresolved_subvolumes);
                }
                produced_artifacts.extend(walk.artifacts);
            }
            Err(e) => {
                warn!(
                    "Btrfs B-tree traversal failed, returning metadata only: {}",
                    e
                );
                // A FileSystem artifact with no files and no flag reads as an
                // empty-but-complete volume. It is not: the walk never ran, so
                // every file on it is missing from the case (B7-008). APFS
                // already stamps its volume artifact this way.
                produced_artifacts[fs_artifact_idx].metadata["inventory_incomplete"] = json!(true);
                produced_artifacts[fs_artifact_idx].metadata["inventory_incomplete_reason"] =
                    json!("btrfs_tree_walk_failed");
                produced_artifacts[fs_artifact_idx].metadata["inventory_error"] =
                    json!(e.to_string());
            }
        }

        info!("Btrfs parser found filesystem: {} bytes total, {} devices, label='{}', {} total artifacts",
              superblock.total_bytes, superblock.num_devices, superblock.label, produced_artifacts.len());

        Ok(produced_artifacts)
    }
}

// --- Superblock Parsing ---

/// Load the superblock from the first readable copy, returning it together with
/// the RAW BYTES of that copy and the offset they came from.
///
/// The three copies (64 KiB, 64 MiB, 256 GiB) are tried in order, matching the
/// offsets the partition-layer detector probes: a volume recognised as btrfs
/// from a mirror must be parseable from that same mirror, or detection promises
/// an inventory the parser then refuses to produce.
///
/// Returning the bytes is the point. `walk_filesystem` reads the system chunk
/// array and the device's own `devid` out of them, and reading those from the
/// PRIMARY offset while the superblock came from a mirror pairs a current
/// chunk_root with a stale (or wiped, hence all-zero) chunk array — every
/// logical address then resolves to the wrong physical bytes, or to none at
/// all, on exactly the damaged images where the mirror path exists to help.
fn load_btrfs_superblock(
    data_source: &dyn DataSource,
) -> Result<(BtrfsSuperblock, Vec<u8>, u64), ModuleError> {
    let mut errors = Vec::new();
    for offset in [
        BTRFS_SUPERBLOCK_OFFSET_1,
        BTRFS_SUPERBLOCK_OFFSET_2,
        BTRFS_SUPERBLOCK_OFFSET_3,
    ] {
        // A mirror beyond the end of the volume is not a failure worth
        // reporting: btrfs only writes the copies the device is large enough to
        // hold.
        if offset.saturating_add(BTRFS_SUPERBLOCK_SIZE as u64) > data_source.size() {
            continue;
        }
        match parse_btrfs_superblock(data_source, offset) {
            Ok((sb, raw)) => return Ok((sb, raw, offset)),
            Err(e) => {
                debug!("btrfs superblock at 0x{:X} unusable: {}", offset, e);
                errors.push(format!("0x{offset:X}: {e}"));
            }
        }
    }
    Err(ModuleError::ParsingError(format!(
        "no readable Btrfs superblock copy ({})",
        if errors.is_empty() {
            "volume too small to contain one".to_string()
        } else {
            errors.join("; ")
        }
    )))
}

fn parse_btrfs_superblock(
    data_source: &dyn DataSource,
    offset: u64,
) -> Result<(BtrfsSuperblock, Vec<u8>), ModuleError> {
    let mut sb_data = vec![0u8; BTRFS_SUPERBLOCK_SIZE];
    // Fail closed on a short read: a zero-padded superblock could parse
    // fabricated root/chunk pointers (BUG-155). One `read_at` is allowed to
    // return less than asked for — a windowed or container-backed image does it
    // routinely — so gather the whole structure first and only then decide it is
    // missing; failing on the first partial read would reject sound evidence.
    let n = read_full(data_source, offset, &mut sb_data);
    if n < BTRFS_SUPERBLOCK_SIZE {
        return Err(ModuleError::ParsingError(format!(
            "Btrfs superblock short read ({} of {} bytes) at offset 0x{:x}",
            n, BTRFS_SUPERBLOCK_SIZE, offset
        )));
    }

    // Check magic at offset 0x40 (64 bytes)
    if &sb_data[0x40..0x48] != BTRFS_MAGIC {
        return Err(ModuleError::ParsingError(format!(
            "Invalid Btrfs magic at offset 0x{:x}",
            offset
        )));
    }

    // Parse superblock fields (little-endian)
    let mut fsid = [0u8; 16];
    fsid.copy_from_slice(&sb_data[0x20..0x30]);

    let generation = LittleEndian::read_u64(&sb_data[0x48..0x50]);
    let root = LittleEndian::read_u64(&sb_data[0x50..0x58]);
    let chunk_root = LittleEndian::read_u64(&sb_data[0x58..0x60]);
    let total_bytes = LittleEndian::read_u64(&sb_data[0x70..0x78]);
    let bytes_used = LittleEndian::read_u64(&sb_data[0x78..0x80]);
    let num_devices = LittleEndian::read_u64(&sb_data[0x88..0x90]);
    let sectorsize = LittleEndian::read_u32(&sb_data[0x90..0x94]);
    let nodesize = LittleEndian::read_u32(&sb_data[0x94..0x98]);

    // label at offset 0x12b (256 bytes, null-terminated)
    let label_bytes = &sb_data[0x12b..0x22b];
    let label_end = label_bytes.iter().position(|&b| b == 0).unwrap_or(256);
    let label = String::from_utf8_lossy(&label_bytes[..label_end]).to_string();

    Ok((
        BtrfsSuperblock {
            fsid,
            total_bytes,
            bytes_used,
            generation,
            root,
            chunk_root,
            num_devices,
            sectorsize,
            nodesize,
            label,
        },
        sb_data,
    ))
}

// --- Key Parsing ---

fn parse_key(data: &[u8]) -> Option<BtrfsKey> {
    if data.len() < 17 {
        return None;
    }
    Some(BtrfsKey {
        objectid: LittleEndian::read_u64(&data[0..8]),
        key_type: data[8],
        offset: LittleEndian::read_u64(&data[9..17]),
    })
}

// --- System Chunk Array Parsing ---

fn parse_system_chunk_array(sb_data: &[u8]) -> Vec<(u64, u64, BtrfsChunkItem)> {
    let mut chunks = Vec::new();

    if sb_data.len() < 0xa4 {
        return chunks;
    }

    // sys_chunk_array_size is at superblock offset 0xa0 (a prior bug read it at
    // 0xc4, which is csum_type — always tiny/zero — so no system chunks parsed
    // and the whole logical->physical bootstrap failed).
    let sys_chunk_array_size = LittleEndian::read_u32(&sb_data[0xa0..0xa4]) as usize;
    let array_start = 0x32b;
    let array_end = std::cmp::min(array_start + sys_chunk_array_size, sb_data.len());

    let mut pos = array_start;

    while pos + 17 <= array_end {
        // Parse the key (17 bytes)
        let key = match parse_key(&sb_data[pos..]) {
            Some(k) => k,
            None => break,
        };
        pos += 17;

        // Parse chunk item header (48 bytes minimum before stripes)
        if pos + 48 > array_end {
            break;
        }

        let length = LittleEndian::read_u64(&sb_data[pos..pos + 8]);
        // owner at +8 (skip)
        let stripe_len = LittleEndian::read_u64(&sb_data[pos + 16..pos + 24]);
        let type_flags = LittleEndian::read_u64(&sb_data[pos + 24..pos + 32]);
        // opt_io_align, opt_io_width, sector_size at +32..+44 (skip)
        let num_stripes = LittleEndian::read_u16(&sb_data[pos + 44..pos + 46]);
        // sub_stripes at +46 (skip)
        pos += 48;

        // Parse stripes: each is devid(8) + offset(8) + dev_uuid(16) = 32 bytes
        let mut stripes = Vec::new();
        for _ in 0..num_stripes {
            if pos + 32 > array_end {
                break;
            }
            let devid = LittleEndian::read_u64(&sb_data[pos..pos + 8]);
            let stripe_offset = LittleEndian::read_u64(&sb_data[pos + 8..pos + 16]);
            // dev_uuid at +16 (16 bytes, skip)
            stripes.push(BtrfsStripe {
                devid,
                offset: stripe_offset,
            });
            pos += 32;
        }

        let chunk_item = BtrfsChunkItem {
            length,
            type_flags,
            stripe_len,
            num_stripes,
            stripes,
        };

        chunks.push((key.offset, length, chunk_item));
    }

    chunks
}

// --- Logical to Physical Address Resolution ---

/// Map a logical address to the device id and physical offset that hold it.
/// Returns the (devid, physical) for the stripe under EVERY profile; the devid
/// is present in `devices` whenever a readable copy exists there. Callers look
/// the devid up in `devices` and zero-fill (flagging the file) only when that
/// device is genuinely absent.
///
/// - Non-striped (SINGLE/DUP/RAID1/RAID1C3/4): every stripe is a full linear
///   copy; pick one whose devid is in `devices` (else the first).
/// - RAID0: data is interleaved in `stripe_len` units across the stripes; the
///   stripe's own devid+offset are returned.
/// - RAID10: mirror + stripe (sub_stripes=2); pick a mirror of the correct data
///   stripe, preferring one whose devid is in `devices`.
/// - RAID5/6: data columns rotate one device per full-stripe row, matching the
///   kernel's `(row + data_col) % num_stripes` placement; parity is not
///   reconstructed.
///
/// Every offset is computed with saturating arithmetic: stripe offsets and chunk
/// lengths come off the image, and a wrapped physical offset would silently read
/// unrelated bytes instead of failing.
fn logical_to_physical(
    logical: u64,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
    devices: &DeviceMap,
) -> Option<(u64, u64)> {
    for (chunk_logical, chunk_length, chunk_item) in chunk_map {
        if logical < *chunk_logical || logical >= chunk_logical.saturating_add(*chunk_length) {
            continue;
        }
        let off = logical - *chunk_logical;
        let flags = chunk_item.type_flags;
        let sl = chunk_item.stripe_len.max(1);
        let ns = chunk_item.num_stripes as u64;
        if ns == 0 {
            return None;
        }

        // Pure RAID0 stripe (no mirror/parity): interleave by stripe_len.
        if flags & BTRFS_BLOCK_GROUP_RAID0 != 0
            && flags
                & (BTRFS_BLOCK_GROUP_RAID10 | BTRFS_BLOCK_GROUP_RAID5 | BTRFS_BLOCK_GROUP_RAID6)
                == 0
        {
            let stripe_nr = off / sl;
            let stripe = chunk_item.stripes.get((stripe_nr % ns) as usize)?;
            let physical = stripe
                .offset
                .saturating_add((stripe_nr / ns).saturating_mul(sl))
                .saturating_add(off % sl);
            return Some((stripe.devid, physical));
        }

        // RAID10: mirror + stripe. btrfs sub_stripes is always 2. The data is
        // striped across `factor = num_stripes / 2` stripe columns; each column
        // is mirrored on 2 stripe slots. Pick a mirror in the map when possible.
        if flags & BTRFS_BLOCK_GROUP_RAID10 != 0 {
            let sub: u64 = 2;
            let factor = ns / sub;
            if factor == 0 {
                return None;
            }
            let stripe_nr = off / sl;
            let col = (stripe_nr % factor) * sub;
            let within = (stripe_nr / factor)
                .saturating_mul(sl)
                .saturating_add(off % sl);
            let stripe = pick_stripe(chunk_item, col as usize, sub as usize, devices)?;
            return Some((stripe.devid, stripe.offset.saturating_add(within)));
        }

        // RAID5/6: data columns rotate one slot per full-stripe row so parity is
        // spread over every device. The kernel resolves a read as
        // `(row + data_col) % num_stripes` (fs/btrfs/volumes.c, "we distribute
        // the parity blocks across stripes"). Indexing `stripes[data_col]`
        // instead reads the parity block — or another device's data — for every
        // row but the first, and serves it as file content. Parity is not
        // reconstructed here; only the data column is located.
        if flags & (BTRFS_BLOCK_GROUP_RAID5 | BTRFS_BLOCK_GROUP_RAID6) != 0 {
            let nparity: u64 = if flags & BTRFS_BLOCK_GROUP_RAID6 != 0 {
                2
            } else {
                1
            };
            if ns <= nparity {
                return None;
            }
            let ndata = ns - nparity;
            let stripe_nr = off / sl;
            let col = stripe_nr % ndata;
            let row = stripe_nr / ndata;
            let dev_index = (row.saturating_add(col)) % ns;
            let stripe = chunk_item.stripes.get(dev_index as usize)?;
            let physical = stripe
                .offset
                .saturating_add(row.saturating_mul(sl))
                .saturating_add(off % sl);
            return Some((stripe.devid, physical));
        }

        // Non-striped copy: prefer a copy whose device is present in the map.
        let stripe = pick_stripe(chunk_item, 0, chunk_item.stripes.len(), devices)?;
        return Some((stripe.devid, stripe.offset.saturating_add(off)));
    }
    None
}

/// From `chunk_item.stripes[base .. base+count)`, pick the first stripe whose
/// devid is present in `devices`; fall back to the first stripe in the range.
fn pick_stripe<'a>(
    chunk_item: &'a BtrfsChunkItem,
    base: usize,
    count: usize,
    devices: &DeviceMap,
) -> Option<&'a BtrfsStripe> {
    let end = (base + count).min(chunk_item.stripes.len());
    let slice = chunk_item.stripes.get(base..end)?;
    slice
        .iter()
        .find(|s| devices.contains_key(&s.devid))
        .or_else(|| slice.first())
}

/// Number of bytes from `logical` that form one contiguous physical run on a
/// single device: bounded by the stripe unit for striped profiles and by the
/// chunk boundary otherwise. Returns 0 when `logical` is in no chunk.
fn contiguous_run(logical: u64, chunk_map: &[(u64, u64, BtrfsChunkItem)]) -> u64 {
    for (cl, len, ci) in chunk_map {
        if logical < *cl || logical >= cl.saturating_add(*len) {
            continue;
        }
        let off = logical - *cl;
        let chunk_remaining = cl.saturating_add(*len) - logical;
        let striped = ci.type_flags & BTRFS_STRIPED_PROFILES != 0;
        if striped {
            let sl = ci.stripe_len.max(1);
            return (sl - (off % sl)).min(chunk_remaining);
        }
        return chunk_remaining;
    }
    0
}

/// Fill `buf` with the content of the logical range [logical, logical+buf.len()),
/// following stripe/device boundaries via the chunk map and device map. Regions
/// on a device we don't have (or that cannot be mapped) are zero-filled.
/// Returns true when every byte came from a real device.
fn read_logical(
    logical: u64,
    devices: &DeviceMap,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
    buf: &mut [u8],
) -> bool {
    let total = buf.len();
    let mut done = 0usize;
    let mut complete = true;
    while done < total {
        let cur = logical.saturating_add(done as u64);
        let run = contiguous_run(cur, chunk_map);
        if run == 0 {
            // Unmapped: zero-fill the remainder and stop.
            for b in &mut buf[done..] {
                *b = 0;
            }
            return false;
        }
        let want = std::cmp::min(total - done, run as usize);
        match logical_to_physical(cur, chunk_map, devices) {
            Some((devid, phys)) => match devices.get(&devid) {
                Some(dev) => {
                    let mut got = 0usize;
                    while got < want {
                        match dev.read_at(
                            phys.saturating_add(got as u64),
                            &mut buf[done + got..done + want],
                        ) {
                            Ok(0) => break,
                            Ok(n) => got += n,
                            Err(_) => break,
                        }
                    }
                    if got < want {
                        for b in &mut buf[done + got..done + want] {
                            *b = 0;
                        }
                        complete = false;
                    }
                }
                None => {
                    // A device we don't have: zero-fill this run.
                    for b in &mut buf[done..done + want] {
                        *b = 0;
                    }
                    complete = false;
                }
            },
            None => {
                for b in &mut buf[done..done + want] {
                    *b = 0;
                }
                complete = false;
            }
        }
        done += want;
    }
    complete
}

/// True if every byte of a regular extent lives on a device we HAVE (present in
/// `devices`). Samples the extent's logical range at stripe-length granularity
/// (the striping unit), so a striped extent whose start is on a device we have
/// but whose tail lands on a missing device is correctly reported incomplete.
fn extent_all_available(
    e: &BtrfsExtentData,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
    devices: &DeviceMap,
) -> bool {
    if e.extent_type == 0 || e.disk_bytenr == 0 {
        return true; // inline data or a hole: nothing to fetch off-device
    }
    let base = e.disk_bytenr.saturating_add(e.extent_offset);
    let step = chunk_map
        .iter()
        .find(|(l, len, _)| base >= *l && base < l.saturating_add(*len))
        .map(|(_, _, c)| c.stripe_len.max(4096))
        .unwrap_or(4096);
    let have = |logical: u64| -> bool {
        matches!(
            logical_to_physical(logical, chunk_map, devices),
            Some((devid, _)) if devices.contains_key(&devid)
        )
    };
    let mut off = 0u64;
    let mut checks = 0u32;
    while off < e.num_bytes {
        if !have(base.saturating_add(off)) {
            return false;
        }
        off = off.saturating_add(step);
        checks += 1;
        if checks > 16384 {
            break; // bounded; a huge all-available-so-far extent is taken as available
        }
    }
    // Always check the final byte in case the range didn't land on a boundary.
    e.num_bytes == 0 || have(base.saturating_add(e.num_bytes - 1))
}

// --- B-tree Node Parsing ---

fn parse_btree_node(
    data_source: &dyn DataSource,
    physical_offset: u64,
    nodesize: u32,
) -> Result<BtrfsNode, ModuleError> {
    // Bound the allocation: a corrupt/malicious superblock can declare a
    // multi-GB nodesize, turning this into an OOM. Real values are <= 64 KiB.
    if !(MIN_NODESIZE..=MAX_NODESIZE).contains(&nodesize) {
        return Err(ModuleError::ParsingError(format!(
            "implausible btrfs nodesize: {} (valid range {}..={})",
            nodesize, MIN_NODESIZE, MAX_NODESIZE
        )));
    }
    let mut node_data = vec![0u8; nodesize as usize];
    // A single `read_at` may deliver less than a whole node on a windowed or
    // container-backed image without anything being wrong; keep asking until the
    // node is in hand or the source stops producing bytes.
    let bytes_read = read_full(data_source, physical_offset, &mut node_data);
    // Fail closed unless the WHOLE node was read: item pointers below index the
    // full `nodesize`, so a short read (previously accepted at just 101 bytes)
    // would parse fabricated zero items from the unread tail (BUG-155).
    if bytes_read < nodesize as usize {
        return Err(ModuleError::ParsingError(format!(
            "B-tree node short read at physical offset 0x{:X}: {} of {} bytes",
            physical_offset, bytes_read, nodesize
        )));
    }

    // Parse header
    // csum: 32 bytes at +0
    // fsid: 16 bytes at +32
    // bytenr: u64 at +48
    let bytenr = LittleEndian::read_u64(&node_data[48..56]);
    // flags: u64 at +56
    // chunk_tree_uuid: 16 bytes at +64
    // generation: u64 at +80
    let generation = LittleEndian::read_u64(&node_data[80..88]);
    // owner: u64 at +88
    let owner = LittleEndian::read_u64(&node_data[88..96]);
    // nritems: u32 at +96
    let nritems = LittleEndian::read_u32(&node_data[96..100]);
    // level: u8 at +100
    let level = node_data[100];

    let header = BtrfsHeader {
        bytenr,
        generation,
        owner,
        nritems,
        level,
    };

    if level > 0 {
        // Internal node: key pointers start at offset 101
        // Each key pointer: key(17) + blockptr(8) + generation(8) = 33 bytes
        let mut pointers = Vec::new();
        for i in 0..nritems as usize {
            let kp_offset = 101 + i * 33;
            if kp_offset + 33 > node_data.len() {
                break;
            }
            let key = match parse_key(&node_data[kp_offset..]) {
                Some(k) => k,
                None => break,
            };
            let blockptr = LittleEndian::read_u64(&node_data[kp_offset + 17..kp_offset + 25]);
            let gen = LittleEndian::read_u64(&node_data[kp_offset + 25..kp_offset + 33]);
            pointers.push(BtrfsKeyPointer {
                key,
                blockptr,
                generation: gen,
            });
        }
        Ok(BtrfsNode::Internal { header, pointers })
    } else {
        // Leaf node: items start at offset 101
        // Each item: key(17) + offset(4) + size(4) = 25 bytes
        let mut items = Vec::new();
        for i in 0..nritems as usize {
            let item_offset = 101 + i * 25;
            if item_offset + 25 > node_data.len() {
                break;
            }
            let key = match parse_key(&node_data[item_offset..]) {
                Some(k) => k,
                None => break,
            };
            let data_offset =
                LittleEndian::read_u32(&node_data[item_offset + 17..item_offset + 21]);
            let data_size = LittleEndian::read_u32(&node_data[item_offset + 21..item_offset + 25]);
            items.push(BtrfsItem {
                key,
                offset: data_offset,
                size: data_size,
            });
        }

        // The data area is the rest of the node after the header (the items reference
        // offsets relative to the start of the leaf data area, which begins right
        // after the fixed header at byte 101).
        let data = if node_data.len() > 101 {
            node_data[101..].to_vec()
        } else {
            Vec::new()
        };

        Ok(BtrfsNode::Leaf {
            header,
            items,
            data,
        })
    }
}

// --- B-tree Leaf Walking ---

/// Shared state for a single B-tree traversal: guards against re-walking a node
/// (cyclic/self-referential blockptrs) and bounds the total number of nodes
/// visited so a malicious node graph cannot loop or accumulate unboundedly.
struct BtreeWalk {
    visited: std::collections::HashSet<u64>,
    nodes_walked: usize,
    limit_hit: bool,
    /// True when a child subtree could not be walked (unresolvable address,
    /// unreadable node, depth exceeded). Those files are missing from the
    /// results exactly like budget-dropped ones, so the walk is incomplete.
    subtree_failed: bool,
}

impl BtreeWalk {
    fn new() -> Self {
        Self {
            visited: std::collections::HashSet::new(),
            nodes_walked: 0,
            limit_hit: false,
            subtree_failed: false,
        }
    }

    /// Why this traversal is short of the whole tree, or `None` when it isn't.
    /// The string is the stable identifier stored in artifact metadata.
    fn incomplete_reason(&self) -> Option<&'static str> {
        if self.limit_hit {
            Some("btrfs_max_btree_nodes")
        } else if self.subtree_failed {
            Some("btrfs_btree_subtree_unreadable")
        } else {
            None
        }
    }
}

/// Walk every leaf of one B-tree, returning its items and — when the traversal
/// did not cover the whole tree — why.
///
/// That reason is the difference between "this tree holds these items" and
/// "this tree holds at least these items". Dropping it turns a partial inventory
/// into what looks like a complete one, so callers must carry it all the way to
/// the artifact (B2-095).
fn walk_btree_leaves(
    devices: &DeviceMap,
    logical_addr: u64,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
    nodesize: u32,
    depth: usize,
) -> Result<(Vec<(BtrfsKey, Vec<u8>)>, Option<&'static str>), ModuleError> {
    let mut walk = BtreeWalk::new();
    let mut results = Vec::new();
    walk_btree_leaves_inner(
        devices,
        logical_addr,
        chunk_map,
        nodesize,
        depth,
        &mut walk,
        &mut results,
    )?;
    if walk.limit_hit {
        warn!(
            "btrfs B-tree traversal hit the {}-node limit; results are truncated",
            MAX_BTREE_NODES
        );
    }
    Ok((results, walk.incomplete_reason()))
}

fn walk_btree_leaves_inner(
    devices: &DeviceMap,
    logical_addr: u64,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
    nodesize: u32,
    depth: usize,
    walk: &mut BtreeWalk,
    results: &mut Vec<(BtrfsKey, Vec<u8>)>,
) -> Result<(), ModuleError> {
    if depth > MAX_BTREE_DEPTH {
        return Err(ModuleError::ParsingError(
            "B-tree depth exceeded maximum".to_string(),
        ));
    }

    // Cycle guard: never walk the same logical block twice within one traversal.
    if !walk.visited.insert(logical_addr) {
        return Ok(());
    }
    // Global node budget: stop once we have walked too many nodes.
    if walk.nodes_walked >= MAX_BTREE_NODES {
        walk.limit_hit = true;
        return Ok(());
    }
    walk.nodes_walked += 1;

    let (devid, physical) =
        logical_to_physical(logical_addr, chunk_map, devices).ok_or_else(|| {
            ModuleError::ParsingError(format!(
                "Cannot resolve logical address 0x{:X} to physical",
                logical_addr
            ))
        })?;
    let data_source = devices.get(&devid).ok_or_else(|| {
        ModuleError::ParsingError(format!(
            "Logical address 0x{:X} maps to device {} which is not available",
            logical_addr, devid
        ))
    })?;

    let node = parse_btree_node(data_source.as_ref(), physical, nodesize)?;

    match node {
        BtrfsNode::Internal {
            header: _,
            pointers,
        } => {
            for ptr in &pointers {
                if walk.nodes_walked >= MAX_BTREE_NODES {
                    walk.limit_hit = true;
                    break;
                }
                if let Err(e) = walk_btree_leaves_inner(
                    devices,
                    ptr.blockptr,
                    chunk_map,
                    nodesize,
                    depth + 1,
                    walk,
                    results,
                ) {
                    // The subtree's files are missing from `results` just as
                    // surely as budget-dropped ones. Record it so the caller
                    // cannot present this walk as a full inventory (B2-095).
                    walk.subtree_failed = true;
                    debug!(
                        "Failed to walk B-tree child at logical 0x{:X}: {}",
                        ptr.blockptr, e
                    );
                }
            }
            Ok(())
        }
        BtrfsNode::Leaf {
            header: _,
            items,
            data,
        } => {
            for item in &items {
                // Item offsets are relative to the end of the fixed header (byte 101).
                // The data vec starts at byte 101, so item.offset indexes directly into data.
                let start = item.offset as usize;
                let end = start + item.size as usize;
                if end <= data.len() {
                    results.push((item.key.clone(), data[start..end].to_vec()));
                }
            }
            Ok(())
        }
    }
}

// --- Chunk Tree Parsing ---

/// Build the logical->physical chunk map. Also reports whether the chunk tree
/// walk was cut short: an incomplete chunk map means later logical addresses may
/// be unresolvable, so the truncation must reach the filesystem artifact
/// (B2-095).
fn parse_chunk_tree(
    devices: &DeviceMap,
    superblock: &BtrfsSuperblock,
    system_chunks: &[(u64, u64, BtrfsChunkItem)],
) -> Result<(Vec<(u64, u64, BtrfsChunkItem)>, Option<&'static str>), ModuleError> {
    // Start with the system chunk array as bootstrap
    let mut chunk_map: Vec<(u64, u64, BtrfsChunkItem)> = system_chunks.to_vec();

    // Walk the chunk tree using the bootstrap chunk map to resolve addresses
    let (items, incomplete_reason) = walk_btree_leaves(
        devices,
        superblock.chunk_root,
        &chunk_map,
        superblock.nodesize,
        0,
    )?;

    // Collect all CHUNK_ITEM entries
    for (key, data) in &items {
        if key.key_type == BTRFS_CHUNK_ITEM_KEY {
            if let Some(chunk) = parse_chunk_item_data(data) {
                let logical = key.offset;
                let length = chunk.length;
                // Only add if not already in the map
                let already_present = chunk_map.iter().any(|(l, _, _)| *l == logical);
                if !already_present {
                    chunk_map.push((logical, length, chunk));
                }
            }
        }
    }

    Ok((chunk_map, incomplete_reason))
}

fn parse_chunk_item_data(data: &[u8]) -> Option<BtrfsChunkItem> {
    if data.len() < 48 {
        return None;
    }

    let length = LittleEndian::read_u64(&data[0..8]);
    // owner at +8 (skip)
    let stripe_len = LittleEndian::read_u64(&data[16..24]);
    let type_flags = LittleEndian::read_u64(&data[24..32]);
    // opt_io_align, opt_io_width, sector_size at +32..+44 (skip)
    let num_stripes = LittleEndian::read_u16(&data[44..46]);
    // sub_stripes at +46 (skip)

    let mut stripes = Vec::new();
    let mut pos = 48;
    for _ in 0..num_stripes {
        if pos + 32 > data.len() {
            break;
        }
        let devid = LittleEndian::read_u64(&data[pos..pos + 8]);
        let stripe_offset = LittleEndian::read_u64(&data[pos + 8..pos + 16]);
        // dev_uuid at +16 (16 bytes, skip)
        stripes.push(BtrfsStripe {
            devid,
            offset: stripe_offset,
        });
        pos += 32;
    }

    Some(BtrfsChunkItem {
        length,
        type_flags,
        stripe_len,
        num_stripes,
        stripes,
    })
}

// --- Root Tree Parsing ---

/// Return the root node (logical bytenr) of every file tree: the default FS
/// tree (objectid 5) plus every subvolume and snapshot (objectid in
/// [FIRST_FREE, LAST_FREE]). Reserved trees (extent, chunk, csum, ...) are
/// skipped. The FS tree is returned first so its mount points seed subvolume
/// path resolution. The ROOT_ITEM's root node bytenr is at offset 176.
fn parse_root_tree_roots(
    devices: &DeviceMap,
    superblock: &BtrfsSuperblock,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
) -> Result<(Vec<(u64, u64)>, Option<&'static str>), ModuleError> {
    let (items, incomplete_reason) =
        walk_btree_leaves(devices, superblock.root, chunk_map, superblock.nodesize, 0)?;

    let mut roots: Vec<(u64, u64)> = Vec::new();
    for (key, data) in &items {
        if key.key_type != BTRFS_ROOT_ITEM_KEY {
            continue;
        }
        let is_fs_tree = key.objectid == BTRFS_FS_TREE_OBJECTID;
        let is_subvol =
            key.objectid >= BTRFS_FIRST_FREE_OBJECTID && key.objectid <= BTRFS_LAST_FREE_OBJECTID;
        if !(is_fs_tree || is_subvol) {
            continue;
        }
        if data.len() >= 184 {
            let bytenr = LittleEndian::read_u64(&data[176..184]);
            if bytenr != 0 {
                debug!(
                    "Found file tree {} root at logical 0x{:X}",
                    key.objectid, bytenr
                );
                roots.push((key.objectid, bytenr));
            }
        }
    }
    roots.sort_by_key(|(oid, _)| {
        if *oid == BTRFS_FS_TREE_OBJECTID {
            0
        } else {
            *oid
        }
    });
    Ok((roots, incomplete_reason))
}

// --- Inode Item Parsing ---

fn parse_inode_item(data: &[u8]) -> Option<BtrfsInodeItem> {
    if data.len() < 160 {
        return None;
    }

    let generation = LittleEndian::read_u64(&data[0..8]);
    // transid at +8 (skip)
    let size = LittleEndian::read_u64(&data[16..24]);
    // nbytes at +24 (skip)
    // block_group at +32 (skip)
    let nlink = LittleEndian::read_u32(&data[40..44]);
    let uid = LittleEndian::read_u32(&data[44..48]);
    let gid = LittleEndian::read_u32(&data[48..52]);
    let mode = LittleEndian::read_u32(&data[52..56]);
    // rdev at +56 (skip)
    // flags at +64 (skip)
    // sequence at +72 (skip)
    // reserved at +80 (32 bytes, skip)
    let atime_sec = LittleEndian::read_i64(&data[112..120]);
    let ctime_sec = LittleEndian::read_i64(&data[124..132]);
    let mtime_sec = LittleEndian::read_i64(&data[136..144]);
    let otime_sec = LittleEndian::read_i64(&data[148..156]);

    Some(BtrfsInodeItem {
        generation,
        size,
        nlink,
        uid,
        gid,
        mode,
        atime_sec,
        mtime_sec,
        ctime_sec,
        otime_sec,
    })
}

// --- Dir Item Parsing ---

fn parse_dir_item(data: &[u8]) -> Option<BtrfsDirItem> {
    if data.len() < 30 {
        return None;
    }

    // location key: 17 bytes
    let location = parse_key(&data[0..17])?;
    // transid at +17 (8 bytes, skip)
    let _data_len = LittleEndian::read_u16(&data[25..27]);
    let name_len = LittleEndian::read_u16(&data[27..29]) as usize;
    let dir_type = data[29];

    if data.len() < 30 + name_len {
        return None;
    }

    let name = String::from_utf8_lossy(&data[30..30 + name_len]).to_string();

    Some(BtrfsDirItem {
        location,
        name,
        dir_type,
    })
}

// --- Extent Data Parsing ---

use seance_core::compression::{
    btrfs_decompress_blob, BTRFS_COMPRESS_NONE, BTRFS_COMPRESS_ZLIB, BTRFS_COMPRESS_ZSTD,
};

// Don't eagerly decompress files larger than this at ingest (avoid unbounded
// memory); re-serving is handled by the resolver via the extent descriptor.
const MATERIALIZE_CAP: u64 = 256 * 1024 * 1024;

/// Convert compressed extents into materialized inline extents holding the
/// decompressed file bytes, so the normal inline read path serves real content
/// instead of raw compressed bytes. Returns (any_compressed, any_unsupported).
fn materialize_compressed_extents(
    extents: &mut [BtrfsExtentData],
    devices: &DeviceMap,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
) -> (bool, bool) {
    let mut any_compressed = false;
    let mut any_unsupported = false;
    for ext in extents.iter_mut() {
        if ext.compression == BTRFS_COMPRESS_NONE {
            continue;
        }
        any_compressed = true;
        if ext.extent_type == 0 {
            // Compressed inline extent: inline_data is the compressed stream.
            match btrfs_decompress_blob(ext.compression, &ext.inline_data, ext.ram_bytes as usize) {
                // The stream must decode to exactly ram_bytes. One that ends
                // early is a truncated or corrupt extent, and serving it would
                // present a short file as the whole one (CR-047).
                Some(d) if d.len() as u64 == ext.ram_bytes => {
                    ext.inline_data = d;
                    ext.compression = BTRFS_COMPRESS_NONE;
                }
                _ => any_unsupported = true,
            }
        } else if ext.disk_bytenr != 0 {
            // Compressed regular extent: read disk_num_bytes compressed bytes
            // (following stripe/device boundaries), decompress, then take
            // num_bytes starting at extent_offset.
            // disk_num_bytes/ram_bytes come from the extent item (attacker-
            // controlled) and are NOT bounded by the inode.size materialize gate,
            // so a crafted extent could otherwise OOM at ingest. A compressed
            // blob for a materialized (<=256 MiB) file can't legitimately exceed
            // that; anything larger is treated as unsupported rather than read.
            if ext.disk_num_bytes > MATERIALIZE_CAP || ext.ram_bytes > MATERIALIZE_CAP {
                any_unsupported = true;
                continue;
            }
            let mut comp = vec![0u8; ext.disk_num_bytes as usize];
            if !read_logical(ext.disk_bytenr, devices, chunk_map, &mut comp) {
                // A device holding part of the compressed blob is missing.
                any_unsupported = true;
                continue;
            }
            match btrfs_decompress_blob(ext.compression, &comp, ext.ram_bytes as usize) {
                // Same exactness rule as the inline case above (CR-047).
                Some(dec) if dec.len() as u64 == ext.ram_bytes => {
                    // extent_offset and num_bytes are attacker-controlled u64 from
                    // the file_extent_item and are NOT bounded by the materialize
                    // gate above. Computing `start + num_bytes` directly overflows
                    // (debug panic) or wraps so end < start (release), which then
                    // panics `dec[start..end]`. Guard start first, then clamp the
                    // end with saturating arithmetic.
                    let start = ext.extent_offset as usize;
                    if start > dec.len() {
                        any_unsupported = true;
                    } else {
                        let end = start.saturating_add(ext.num_bytes as usize).min(dec.len());
                        ext.inline_data = dec[start..end].to_vec();
                        ext.extent_type = 0; // now materialized as inline
                        ext.compression = BTRFS_COMPRESS_NONE;
                    }
                }
                _ => any_unsupported = true,
            }
        }
    }
    (any_compressed, any_unsupported)
}

/// Physical offset of a logical address ON the primary device only. The content
/// resolver runs later with just the primary device, so runs that physically
/// live on a sibling device cannot be re-served from it. Returns:
/// - `Some(Some(phys))` — resolvable on the primary device,
/// - `Some(None)` — maps to another device (persist as a hole; the file carries
///   the `data_incomplete_multi_device` flag),
/// - `None` — not resolvable at all.
fn primary_physical(
    logical: u64,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
    devices: &DeviceMap,
    primary_devid: u64,
) -> Option<Option<u64>> {
    match logical_to_physical(logical, chunk_map, devices) {
        Some((devid, phys)) if devid == primary_devid => Some(Some(phys)),
        Some(_) => Some(None),
        None => None,
    }
}

/// Record that part of a file's persisted content location is a hole standing
/// in for bytes on a sibling device.
///
/// The content resolver only ever has the primary device, so those ranges
/// re-serve as ZEROS. At ingest the same file was read across every available
/// device, so its stored hash covers the real bytes: re-exporting or
/// hash-verifying later silently produces different content. What an examiner
/// must never see is a file whose runs claim to describe it completely when a
/// span of it is a fabricated zero region (B2-134).
fn mark_off_primary(metadata: &mut serde_json::Value, off_primary: bool) {
    if !off_primary {
        return;
    }
    metadata["data_incomplete_multi_device"] = json!(true);
    metadata["data_runs_complete"] = json!(false);
    metadata["content_incomplete"] = json!(true);
    if metadata.get("content_incomplete_reason").is_none() {
        metadata["content_incomplete_reason"] = json!("btrfs_extent_off_primary_device");
    }
}

/// Persist a file's content location into metadata so the API content resolver
/// can re-serve it from the DB. `extents` are the ORIGINAL (pre-materialization)
/// extents. Uncompressed on-disk extents become `data_runs`; zlib/zstd extents
/// become a `btrfs_extents` compression descriptor the resolver decompresses on
/// demand (no size cap); inline content is stored as `resident_data_b64`.
///
/// The resolver only ever has the primary device, so for a multi-device striped
/// file the regions that live on a sibling device are persisted as holes and the
/// file is left flagged `data_incomplete_multi_device`. Single-device files map
/// every extent to the primary and are unaffected.
fn persist_btrfs_content(
    metadata: &mut serde_json::Value,
    extents: &[BtrfsExtentData],
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
    size: u64,
    src: &dyn DataSource,
    devices: &DeviceMap,
    primary_devid: u64,
    extents_truncated: bool,
) {
    const RESIDENT_CAP: u64 = 16 * 1024 * 1024;

    // Set when any extent physically lives on a sibling device. Those ranges
    // are written out as holes, so the persisted location describes LESS than
    // the file even though every extent was resolvable at ingest.
    let mut off_primary = false;

    // The MAX_EXTENTS cap dropped part of this file's extent list. Whatever is
    // reconstructed below stops short of the real file and its tail is
    // zero-filled, so mark it rather than let the gap read as genuine sparse
    // content (BUG-212).
    if extents_truncated {
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!("btrfs_max_extents");
    }

    // Preallocated (never written) extents are served as zeros, not as the
    // residual bytes at their disk_bytenr (BUG-209).
    if extents.iter().any(|e| e.extent_type == 2) {
        metadata["has_prealloc_extents"] = json!(true);
    }

    // Honesty flag: a non-zero per-extent encryption byte means the bytes these
    // runs/descriptors point at are ciphertext we do not decrypt. Emit a
    // machine-readable marker so exported/hashed content is not mistaken for
    // plaintext (BUG-181; mirrors the ext4/F2FS fscrypt markers).
    if extents.iter().any(|e| e.encryption != 0) {
        metadata["encrypted"] = json!(true);
        metadata["content_ciphertext"] = json!("btrfs_extent_encryption");
        // `content_incomplete` is the flag the API, export and integrity-verify
        // paths read; `content_ciphertext` is display only. Without it the
        // ciphertext is hashed and exported under the file's real size and its
        // digest is recorded as the digest of the file's actual bytes (B2-136).
        metadata["content_incomplete"] = json!(true);
        if metadata.get("content_incomplete_reason").is_none() {
            metadata["content_incomplete_reason"] = json!(IncompleteReason::Encrypted.as_str());
        }
    }

    // An unsupported codec (LZO) cannot be decompressed on re-serve.
    if extents.iter().any(|e| {
        !matches!(
            e.compression,
            BTRFS_COMPRESS_NONE | BTRFS_COMPRESS_ZLIB | BTRFS_COMPRESS_ZSTD
        )
    }) {
        metadata["compression_unsupported"] = json!(true);
        return;
    }

    // Prealloc (type 2) extents map like holes rather than like their
    // disk_bytenr, so a file mixing regular and prealloc extents is still fully
    // describable as runs/descriptors (BUG-209).
    let all_mapped = extents
        .iter()
        .all(|e| e.extent_type == 1 || e.extent_type == 2);
    let any_compressed = extents.iter().any(|e| e.compression != BTRFS_COMPRESS_NONE);

    if all_mapped && any_compressed {
        // Per-extent compression descriptor: [file_off, phys|null, disk_len,
        // ram_len, comp, ext_off, num_bytes]. Resolver reads disk_len at phys,
        // decompresses (comp) to ram_len, takes num_bytes from ext_off. A null
        // phys is a hole the resolver zero-fills (also used for off-device runs).
        let mut arr: Vec<serde_json::Value> = Vec::new();
        let mut ok = true;
        for e in extents {
            if e.disk_bytenr == 0 || e.extent_type == 2 {
                arr.push(json!([
                    e.offset,
                    serde_json::Value::Null,
                    0,
                    0,
                    0,
                    0,
                    e.num_bytes
                ]));
            } else if e.compression == BTRFS_COMPRESS_NONE {
                match primary_physical(
                    e.disk_bytenr + e.extent_offset,
                    chunk_map,
                    devices,
                    primary_devid,
                ) {
                    Some(Some(phys)) => arr.push(json!([
                        e.offset,
                        phys,
                        e.num_bytes,
                        e.num_bytes,
                        0,
                        0,
                        e.num_bytes
                    ])),
                    // Off-device: persist as a hole; the flag records the gap.
                    Some(None) => {
                        off_primary = true;
                        arr.push(json!([
                            e.offset,
                            serde_json::Value::Null,
                            0,
                            0,
                            0,
                            0,
                            e.num_bytes
                        ]))
                    }
                    None => {
                        ok = false;
                        break;
                    }
                }
            } else {
                match primary_physical(e.disk_bytenr, chunk_map, devices, primary_devid) {
                    Some(Some(phys)) => arr.push(json!([
                        e.offset,
                        phys,
                        e.disk_num_bytes,
                        e.ram_bytes,
                        e.compression,
                        e.extent_offset,
                        e.num_bytes
                    ])),
                    Some(None) => {
                        off_primary = true;
                        arr.push(json!([
                            e.offset,
                            serde_json::Value::Null,
                            0,
                            0,
                            0,
                            0,
                            e.num_bytes
                        ]))
                    }
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
        }
        if ok {
            metadata["compression"] = json!("btrfs");
            metadata["btrfs_extents"] = json!(arr);
            if extents_truncated {
                metadata["data_runs_complete"] = json!(false);
            }
            mark_off_primary(metadata, off_primary);
            return;
        }
    } else if all_mapped {
        // Uncompressed on-disk extents: plain byte runs.
        let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
        let mut pos = 0u64;
        let mut ok = true;
        for e in extents {
            if e.offset > pos {
                runs.push((None, e.offset - pos));
            }
            if e.disk_bytenr == 0 || e.extent_type == 2 {
                // Hole, or preallocated and never written: reads as zeros.
                runs.push((None, e.num_bytes));
            } else {
                match primary_physical(
                    e.disk_bytenr + e.extent_offset,
                    chunk_map,
                    devices,
                    primary_devid,
                ) {
                    Some(Some(phys)) => runs.push((Some(phys), e.num_bytes)),
                    // Off-device run: a hole for the primary-only resolver.
                    Some(None) => {
                        off_primary = true;
                        runs.push((None, e.num_bytes))
                    }
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            pos = e.offset + e.num_bytes;
        }
        if ok {
            if pos < size {
                runs.push((None, size - pos));
            }
            let (runs_json, complete) = seance_core::data_source::byte_runs_to_metadata(&runs);
            metadata["data_runs"] = runs_json;
            // A capped extent list makes the trailing zero-fill above a guess,
            // not a hole: never present it as complete (BUG-212).
            metadata["data_runs_complete"] = json!(complete && !extents_truncated && !off_primary);
            mark_off_primary(metadata, off_primary);
            return;
        }
    }

    // Inline / mixed / unresolvable: inline the materialized bytes if small.
    if size <= RESIDENT_CAP {
        let n = size as usize;
        let mut buf = vec![0u8; n];
        let mut o = 0usize;
        while o < n {
            match src.read_at(o as u64, &mut buf[o..]) {
                Ok(0) => break,
                Ok(k) => o += k,
                Err(_) => break,
            }
        }
        buf.truncate(o);
        use base64::Engine as _;
        metadata["resident_data_b64"] =
            json!(base64::engine::general_purpose::STANDARD.encode(&buf));
        // Short of the inode's size: the stored bytes are a prefix (or nothing
        // at all when the source refused to serve compressed/unavailable
        // extents). Stored unflagged they would re-serve as the whole file.
        if o < n {
            metadata["content_incomplete"] = json!(true);
            if metadata.get("content_incomplete_reason").is_none() {
                metadata["content_incomplete_reason"] = json!("btrfs_resident_short_read");
            }
            metadata["resident_data_bytes"] = json!(o);
        }
    } else {
        metadata["compression_unsupported"] = json!(true);
    }
}

fn parse_extent_data(data: &[u8], file_offset: u64) -> Option<BtrfsExtentData> {
    if data.len() < 21 {
        return None;
    }

    let generation = LittleEndian::read_u64(&data[0..8]);
    let ram_bytes = LittleEndian::read_u64(&data[8..16]);
    let compression = data[16];
    let encryption = data[17];
    // other_encoding at +18 (skip)
    let extent_type = data[20];

    if extent_type == 0 {
        // Inline extent: data follows at +21
        let inline_data = data[21..].to_vec();
        Some(BtrfsExtentData {
            generation,
            ram_bytes,
            compression,
            encryption,
            extent_type,
            disk_bytenr: 0,
            disk_num_bytes: 0,
            extent_offset: 0,
            offset: file_offset,
            num_bytes: inline_data.len() as u64,
            inline_data,
        })
    } else if extent_type == 1 || extent_type == 2 {
        // Regular or prealloc extent
        if data.len() < 53 {
            return None;
        }
        let disk_bytenr = LittleEndian::read_u64(&data[21..29]);
        let disk_num_bytes = LittleEndian::read_u64(&data[29..37]);
        let extent_offset = LittleEndian::read_u64(&data[37..45]);
        let num_bytes = LittleEndian::read_u64(&data[45..53]);

        Some(BtrfsExtentData {
            generation,
            ram_bytes,
            compression,
            encryption,
            extent_type,
            disk_bytenr,
            disk_num_bytes,
            extent_offset,
            offset: file_offset,
            num_bytes,
            inline_data: Vec::new(),
        })
    } else {
        None
    }
}

// --- File Content Attachment ---

/// Attach the content of one non-empty regular file and describe it in metadata.
///
/// Returns the `DataSource` when the file's bytes could be located, `None` when
/// they could not. Every `None` also stamps `content_incomplete` and a reason:
/// a FileEntry carrying a non-zero `size` with no content and no reason is
/// indistinguishable from a genuinely empty file, and an examiner would read the
/// absence as evidence that the file held nothing (B2-094).
fn attach_file_content(
    metadata: &mut serde_json::Value,
    file_extents: Option<&Vec<BtrfsExtentData>>,
    extents_truncated: bool,
    size: u64,
    devices: &Arc<DeviceMap>,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
    primary_devid: u64,
) -> Option<Arc<dyn DataSource>> {
    if size > MAX_FILE_SIZE {
        // Over the DataSource ceiling: the file is real and its bytes are on the
        // image, but this parser does not map them.
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!("btrfs_file_too_large");
        metadata["content_incomplete_limit"] = json!(MAX_FILE_SIZE);
        return None;
    }

    let extents = match file_extents {
        Some(e) if !e.is_empty() => e,
        // A sized file with no extent records at all: its content was never
        // located, which is not the same as the file being empty.
        _ => {
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] = json!("btrfs_no_extent_records");
            return None;
        }
    };

    let mut extents = extents.clone();
    extents.sort_by_key(|e| e.offset);
    // Keep the original (pre-materialization) extents: they carry the per-extent
    // compression info the resolver needs.
    let original = extents.clone();
    // On a multi-device filesystem some of a file's extents may physically live
    // on a device we do not have (striped RAID0/10/5/6 with a missing image).
    // Flag such files ONLY when a device is genuinely absent: their served
    // content has those regions zero-filled, not the real bytes. Sample each
    // extent across its whole range at stripe granularity so a large striped
    // extent (present start, missing tail) is caught.
    let data_incomplete = original
        .iter()
        .any(|e| !extent_all_available(e, chunk_map, devices));
    if data_incomplete {
        metadata["data_incomplete_multi_device"] = json!(true);
        // A genuinely absent device means the served bytes for those ranges are
        // zero-fill, not the file. Say so with the flag every consumer reads,
        // not only with a btrfs-specific one (B2-134).
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!("btrfs_missing_device");
    }
    // Encrypted extent payloads are ciphertext: never feed them to the
    // decompressor, whose output would be meaningless bytes served as file
    // content (BUG-181).
    let any_encrypted = original.iter().any(|e| e.encryption != 0);
    if extents.iter().any(|e| e.compression != BTRFS_COMPRESS_NONE) {
        metadata["compressed"] = json!(true);
        // Decompress in memory for ingest indexing (bounded).
        if !any_encrypted && size <= MATERIALIZE_CAP {
            materialize_compressed_extents(&mut extents, devices, chunk_map);
        }
    }
    // Check if all extents are inline (materialized ones now are). A still-
    // compressed inline payload must NOT take the ByteSlice shortcut: that would
    // hand the compressed blob straight out as the file's bytes (B2-003).
    let all_inline = extents.iter().all(|e| e.extent_type == 0);
    let all_plain = extents.iter().all(|e| e.compression == BTRFS_COMPRESS_NONE);
    let src: Arc<dyn DataSource> = if all_inline && all_plain && extents.len() == 1 {
        Arc::new(seance_core::data_source::ByteSliceDataSource::new(
            extents[0].inline_data.clone(),
        ))
    } else {
        Arc::new(BtrfsFileSource::new(
            Arc::clone(devices),
            chunk_map.to_vec(),
            size,
            extents.clone(),
            !extents_truncated,
        ))
    };
    // Persist content location (from the original extents) so the resolver can
    // re-serve: data_runs for uncompressed on-disk extents, a per-extent
    // compression descriptor for zlib/zstd, inline bytes for inline content.
    persist_btrfs_content(
        metadata,
        &original,
        chunk_map,
        size,
        src.as_ref(),
        devices,
        primary_devid,
        extents_truncated,
    );
    // Extents still compressed after materialization (over the cap, encrypted,
    // an unsupported codec, a failed decompression) have no plaintext anywhere:
    // the source refuses to serve them rather than pass compressed bytes off as
    // content (B2-003). That is only recoverable when persist left a descriptor
    // the resolver can decompress from; without one the content is unavailable
    // and the artifact must say so.
    let still_compressed = extents.iter().any(|e| e.compression != BTRFS_COMPRESS_NONE);
    if still_compressed && metadata.get("btrfs_extents").is_none() {
        metadata["content_incomplete"] = json!(true);
        if metadata.get("content_incomplete_reason").is_none() {
            metadata["content_incomplete_reason"] = json!("btrfs_compressed_not_decompressed");
        }
    }
    Some(src)
}

// --- FS Tree Walking ---

/// Outcome of walking one btrfs file tree.
struct FsTreeWalk {
    artifacts: Vec<Artifact>,
    /// Nested subvolume/snapshot mount points (root objectid, mount path).
    nested_subvols: Vec<(u64, String)>,
    /// True when the global directory-entry cap dropped entries (BUG-215).
    dir_entries_truncated: bool,
    /// Set when the B-tree traversal did not cover the whole tree (node budget
    /// exhausted, or a subtree that could not be read), so files and whole
    /// subtrees are missing from the inventory (B2-095).
    btree_incomplete_reason: Option<&'static str>,
}

/// Walk one file tree rooted at `fs_root_logical`, producing FileEntry
/// artifacts. `prefix` is the mount path of this tree ("" for the default FS
/// tree, "/subvol1" for a subvolume); paths are built beneath it. Returns the
/// artifacts plus any nested subvolume/snapshot mount points discovered
/// (their root objectid and resolved mount path) for the caller to walk.
fn walk_fs_tree(
    devices: &Arc<DeviceMap>,
    fs_root_logical: u64,
    chunk_map: &[(u64, u64, BtrfsChunkItem)],
    nodesize: u32,
    case_id: uuid::Uuid,
    artifact_id: uuid::Uuid,
    prefix: &str,
    primary_devid: u64,
) -> Result<FsTreeWalk, ModuleError> {
    let (items, btree_incomplete_reason) =
        walk_btree_leaves(devices.as_ref(), fs_root_logical, chunk_map, nodesize, 0)?;

    // Build maps: inode -> inode_item, inode -> dir_entries, inode -> extents
    let mut inode_items: std::collections::HashMap<u64, BtrfsInodeItem> =
        std::collections::HashMap::new();
    let mut dir_entries: std::collections::HashMap<u64, Vec<BtrfsDirItem>> =
        std::collections::HashMap::new();
    let mut extent_map: std::collections::HashMap<u64, Vec<BtrfsExtentData>> =
        std::collections::HashMap::new();
    let mut dir_entry_count = 0usize;
    // Inodes whose extent list hit MAX_EXTENTS, and whether the global
    // directory-entry cap dropped any entries: both make the reconstruction
    // short, and both must be flagged rather than skipped silently.
    let mut truncated_extents: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut dir_entries_truncated = false;

    for (key, data) in &items {
        match key.key_type {
            BTRFS_INODE_ITEM_KEY => {
                if let Some(inode) = parse_inode_item(data) {
                    inode_items.insert(key.objectid, inode);
                }
            }
            BTRFS_DIR_INDEX_KEY => {
                if dir_entry_count >= MAX_DIR_ENTRIES {
                    // Record the drop instead of returning a short listing that
                    // looks complete (BUG-215).
                    dir_entries_truncated = true;
                    continue;
                }
                if let Some(dir_item) = parse_dir_item(data) {
                    dir_entries.entry(key.objectid).or_default().push(dir_item);
                    dir_entry_count += 1;
                }
            }
            BTRFS_EXTENT_DATA_KEY => {
                if let Some(extent) = parse_extent_data(data, key.offset) {
                    let extents = extent_map.entry(key.objectid).or_default();
                    if extents.len() < MAX_EXTENTS {
                        extents.push(extent);
                    } else {
                        // Dropping extents silently would sparse-fill the tail
                        // with zeros that read as real content (BUG-212).
                        truncated_extents.insert(key.objectid);
                    }
                }
            }
            _ => {}
        }
    }

    // Build path map by walking from root directory (inode 256). The tree's
    // root directory sits at `prefix` ("/" for the default FS tree).
    let root_path = if prefix.is_empty() {
        "/".to_string()
    } else {
        prefix.to_string()
    };
    let mut paths: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    paths.insert(BTRFS_ROOT_DIR_OBJECTID, root_path);
    // Every name each inode is reachable under, in discovery order.
    let mut all_paths: std::collections::HashMap<u64, Vec<String>> =
        std::collections::HashMap::new();

    // Subvolume/snapshot mount points found while walking this tree.
    let mut nested_subvols: Vec<(u64, String)> = Vec::new();

    // BFS to resolve all paths. `visited` stops cycles from a corrupted tree
    // (and the subvolume objectid/inode-number collision) from looping forever.
    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
    visited.insert(BTRFS_ROOT_DIR_OBJECTID);
    let mut queue: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    queue.push_back(BTRFS_ROOT_DIR_OBJECTID);

    while let Some(parent_ino) = queue.pop_front() {
        if let Some(entries) = dir_entries.get(&parent_ino) {
            let parent_path = paths.get(&parent_ino).cloned().unwrap_or_default();
            for entry in entries {
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                let child_path = if parent_path == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{}/{}", parent_path, entry.name)
                };
                // A subvolume/snapshot mount: its target lives in a separate
                // tree (location type ROOT_ITEM) and its objectid reuses this
                // tree's inode numbering, so it must not be treated as a local
                // inode. Record the mount and let the caller walk that tree.
                if entry.location.key_type == BTRFS_ROOT_ITEM_KEY {
                    nested_subvols.push((entry.location.objectid, child_path));
                    continue;
                }
                let child_ino = entry.location.objectid;
                // A hardlinked inode has ONE inode item and several names.
                // Overwriting the map entry kept only the last name seen, so
                // every other path the file lived at vanished from the case and
                // "this file was never at path X" could be answered falsely
                // (B7-007). Keep the first as canonical and record them all.
                record_inode_path(&mut paths, &mut all_paths, child_ino, child_path);
                // Enqueue each directory once.
                if let Some(inode) = inode_items.get(&child_ino) {
                    if (inode.mode & 0o170000) == 0o040000 && visited.insert(child_ino) {
                        queue.push_back(child_ino);
                    }
                }
            }
        }
    }

    // Generate artifacts
    let mut produced_artifacts = Vec::new();

    for (ino, inode) in &inode_items {
        let path = match paths.get(ino) {
            Some(p) => p.clone(),
            None => continue, // Orphan inode, skip
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

        let permissions = format!("{:o}", inode.mode & 0o7777);

        let mut metadata = json!({
            "name": name,
            "path": path,
            "parent_path": parent_path,
            "inode": ino,
            "mode": inode.mode,
            "permissions": permissions,
            "uid": inode.uid,
            "gid": inode.gid,
            "size": inode.size,
            "nlink": inode.nlink,
            // btrfs ctime is the inode *change* time, not creation time
            "changed": format_timestamp(inode.ctime_sec),
            "modified": format_timestamp(inode.mtime_sec),
            "accessed": format_timestamp(inode.atime_sec),
            "is_directory": is_directory,
            "is_symlink": is_symlink,
        });

        // Real creation time comes from otime; absent when unset
        if inode.otime_sec != 0 {
            metadata["created"] = json!(format_timestamp(inode.otime_sec));
        }

        // Hardlink names. A directory's nlink counts its subdirectories, not
        // alternate names, so only files carry this (B7-007).
        if !is_directory {
            let names = all_paths.get(ino).map(|v| v.as_slice()).unwrap_or(&[]);
            if names.len() > 1 {
                metadata["hardlink_paths"] = json!(names);
            }
            if inode.nlink > 1 {
                let known = names.len().max(1) as u32;
                metadata["hardlink_paths_known"] = json!(known);
                metadata["hardlink_paths_complete"] = json!(known >= inode.nlink);
                if known < inode.nlink {
                    // The inode says it has more names than the directory tree
                    // gave us; the missing ones are not "absent from the disk".
                    metadata["inventory_incomplete"] = json!(true);
                    metadata["inventory_incomplete_reason"] =
                        json!("btrfs_hardlink_names_unresolved");
                }
            }
        }

        let file_source = if is_regular_file && inode.size > 0 {
            attach_file_content(
                &mut metadata,
                extent_map.get(ino),
                truncated_extents.contains(ino),
                inode.size,
                devices,
                chunk_map,
                primary_devid,
            )
        } else {
            None
        };

        let artifact = Artifact::new(case_id, ArtifactType::FileEntry, file_source, metadata)
            .with_parent(artifact_id);

        produced_artifacts.push(artifact);
    }

    Ok(FsTreeWalk {
        artifacts: produced_artifacts,
        nested_subvols,
        dir_entries_truncated,
        btree_incomplete_reason,
    })
}

// --- Top-level Filesystem Walking ---

/// Build the device map: the opened (primary) device plus any sibling device
/// images that belong to the SAME filesystem (matching fsid). Siblings are
/// looked for in the primary image's directory when `fs_path` is known. Without
/// a path, only the primary device is used (single-device behavior).
fn build_device_map(
    primary: &Arc<dyn DataSource>,
    primary_devid: u64,
    primary_fsid: &[u8; 16],
    fs_path: Option<&str>,
) -> DeviceMap {
    let mut map: DeviceMap = DeviceMap::new();
    map.insert(primary_devid, Arc::clone(primary));

    let Some(path) = fs_path else {
        return map;
    };
    let Some(parent) = std::path::Path::new(path).parent() else {
        return map;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return map;
    };

    let mut scanned = 0u32;
    for entry in entries {
        if scanned >= 64 {
            break; // bound the scan
        }
        let Ok(entry) = entry else { continue };
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        scanned += 1;
        let p = entry.path();
        let Ok(ds) = seance_core::data_source::FileDataSource::new(p.clone()) else {
            continue;
        };

        // Read the candidate's primary superblock and validate magic. A single
        // `read_at` may deliver less than the whole block; accepting the
        // zero-padded remainder would read `devid` out of bytes that were never
        // on disk and register the sibling under the wrong device number, so its
        // extents would resolve to another device's content.
        let mut sb = vec![0u8; BTRFS_SUPERBLOCK_SIZE];
        if read_full(&ds, BTRFS_SUPERBLOCK_OFFSET_1, &mut sb) < BTRFS_SUPERBLOCK_SIZE {
            continue;
        }
        if &sb[0x40..0x48] != BTRFS_MAGIC {
            continue;
        }
        // Same filesystem?
        if sb[0x20..0x30] != primary_fsid[..] {
            continue;
        }
        let devid = u64::from_le_bytes(sb[0xc9..0xc9 + 8].try_into().unwrap());
        // Skip the primary and any device already mapped (also skips re-opening
        // the primary file itself, whose devid is already present).
        if map.contains_key(&devid) {
            continue;
        }
        debug!(
            "btrfs: discovered sibling device {} at {}",
            devid,
            p.display()
        );
        map.insert(devid, Arc::new(ds) as Arc<dyn DataSource>);
    }
    map
}

/// Record one directory-entry path for `ino`.
///
/// A hardlinked inode has ONE inode item and several directory entries. A plain
/// `paths.insert` kept only the last name seen, so every other path the file
/// lived at vanished from the case and "this file was never at path X" could be
/// answered falsely (B7-007). The first name discovered stays canonical so the
/// emitted path is stable; the rest are kept alongside it.
fn record_inode_path(
    paths: &mut std::collections::HashMap<u64, String>,
    all_paths: &mut std::collections::HashMap<u64, Vec<String>>,
    ino: u64,
    path: String,
) {
    all_paths.entry(ino).or_default().push(path.clone());
    paths.entry(ino).or_insert(path);
}

/// Outcome of walking the whole filesystem.
struct FilesystemWalk {
    artifacts: Vec<Artifact>,
    /// True when the global directory-entry cap dropped entries (BUG-215).
    dir_entries_truncated: bool,
    /// Set when any B-tree traversal stopped short: the inventory is a prefix
    /// of the filesystem, not the filesystem (B2-095).
    btree_incomplete_reason: Option<&'static str>,
    /// Subvolume object ids named by the trees but with no root item to walk.
    /// Their contents are absent from the case entirely (B7-009).
    unresolved_subvolumes: Vec<u64>,
}

fn walk_filesystem(
    data_source: &Arc<dyn DataSource>,
    superblock: &BtrfsSuperblock,
    sb_data: &[u8],
    case_id: uuid::Uuid,
    artifact_id: uuid::Uuid,
    fs_path: Option<&str>,
) -> Result<FilesystemWalk, ModuleError> {
    // The opened device's own id (dev_item.devid at superblock offset 0xc9).
    let primary_devid = if sb_data.len() >= 0xc9 + 8 {
        u64::from_le_bytes(sb_data[0xc9..0xc9 + 8].try_into().unwrap())
    } else {
        1
    };

    // Build the device map. On a multi-device fs we try to discover the sibling
    // images so striped/mirrored content reconstructs across devices; devices we
    // cannot find are simply absent and their regions get flagged + zero-filled.
    let devices = Arc::new(build_device_map(
        data_source,
        primary_devid,
        &superblock.fsid,
        fs_path,
    ));
    if superblock.num_devices > 1 {
        debug!(
            "btrfs multi-device fs: {} devices declared, {} available (primary devid {})",
            superblock.num_devices,
            devices.len(),
            primary_devid
        );
    }

    // Step 1: Parse system chunk array from superblock
    let system_chunks = parse_system_chunk_array(sb_data);
    debug!(
        "Parsed {} system chunks from superblock",
        system_chunks.len()
    );

    if system_chunks.is_empty() {
        return Err(ModuleError::ParsingError(
            "No system chunks found in superblock".to_string(),
        ));
    }

    // Step 2: Parse chunk tree to build complete chunk map
    let (chunk_map, chunk_incomplete) =
        parse_chunk_tree(devices.as_ref(), superblock, &system_chunks)?;
    debug!("Built chunk map with {} entries", chunk_map.len());

    // Step 3: Enumerate every file tree (default FS tree + subvolumes/snapshots)
    let (roots, root_incomplete) = parse_root_tree_roots(devices.as_ref(), superblock, &chunk_map)?;
    if !roots.iter().any(|(oid, _)| *oid == BTRFS_FS_TREE_OBJECTID) {
        return Err(ModuleError::ParsingError(
            "FS tree root (objectid=5) not found in root tree".to_string(),
        ));
    }
    let root_map: std::collections::HashMap<u64, u64> = roots.iter().cloned().collect();

    // Step 4: Walk the FS tree, then each subvolume/snapshot at its mount path.
    // `visited_trees` guards against a subvolume cycle re-walking a tree.
    let mut artifacts = Vec::new();
    let mut dir_entries_truncated = false;
    let mut btree_incomplete_reason = chunk_incomplete.or(root_incomplete);
    // Subvolume object ids named by the trees but absent from the root map.
    // Each one is a whole file tree that never got walked.
    let mut unresolved_subvolumes: Vec<u64> = Vec::new();
    let mut visited_trees: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<(u64, String)> = std::collections::VecDeque::new();
    queue.push_back((BTRFS_FS_TREE_OBJECTID, String::new()));

    while let Some((oid, prefix)) = queue.pop_front() {
        if !visited_trees.insert(oid) {
            continue;
        }
        let Some(&bytenr) = root_map.get(&oid) else {
            // The FS tree names this subvolume, but the root tree holds no root
            // item for it: its whole file tree is missing from the case. Left
            // as a bare `continue` the inventory read as complete (B7-009).
            warn!(
                "Btrfs subvolume {} is referenced at '{}' but has no root item; \
                 its contents are NOT in this case",
                oid, prefix
            );
            unresolved_subvolumes.push(oid);
            continue;
        };
        let walk = walk_fs_tree(
            &devices,
            bytenr,
            &chunk_map,
            superblock.nodesize,
            case_id,
            artifact_id,
            &prefix,
            primary_devid,
        )?;
        artifacts.extend(walk.artifacts);
        dir_entries_truncated |= walk.dir_entries_truncated;
        btree_incomplete_reason = btree_incomplete_reason.or(walk.btree_incomplete_reason);
        for (sub_oid, mount_path) in walk.nested_subvols {
            if !visited_trees.contains(&sub_oid) {
                queue.push_back((sub_oid, mount_path));
            }
        }
    }

    // Subvolumes/snapshots not referenced by any mount point (orphaned or
    // detached) still hold recoverable content; walk them under a synthetic
    // path so nothing is silently dropped.
    for (oid, _) in &roots {
        if visited_trees.contains(oid) {
            continue;
        }
        let prefix = format!("/<subvolume_{}>", oid);
        let Some(&bytenr) = root_map.get(oid) else {
            warn!(
                "Btrfs subvolume {} has no root item; its contents are NOT in this case",
                oid
            );
            unresolved_subvolumes.push(*oid);
            continue;
        };
        visited_trees.insert(*oid);
        let walk = walk_fs_tree(
            &devices,
            bytenr,
            &chunk_map,
            superblock.nodesize,
            case_id,
            artifact_id,
            &prefix,
            primary_devid,
        )?;
        artifacts.extend(walk.artifacts);
        dir_entries_truncated |= walk.dir_entries_truncated;
        btree_incomplete_reason = btree_incomplete_reason.or(walk.btree_incomplete_reason);
    }

    if !unresolved_subvolumes.is_empty() {
        unresolved_subvolumes.sort_unstable();
        unresolved_subvolumes.dedup();
        warn!(
            "Btrfs: {} subvolume(s) could not be resolved to a root item; \
             their contents are absent from this case",
            unresolved_subvolumes.len()
        );
        btree_incomplete_reason = btree_incomplete_reason.or(Some("btrfs_subvolume_unresolved"));
    }

    Ok(FilesystemWalk {
        artifacts,
        dir_entries_truncated,
        btree_incomplete_reason,
        unresolved_subvolumes,
    })
}

// --- Utilities ---

fn format_timestamp(secs: i64) -> String {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_metadata() {
        let module = BtrfsParser;
        assert_eq!(module.id(), "plugin.filesystem.btrfs");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));

        let subscriptions = module.subscribes_to();
        assert!(subscriptions.contains(&ArtifactType::FileSystem));
    }

    #[test]
    fn test_btrfs_magic() {
        assert_eq!(BTRFS_MAGIC, b"_BHRfS_M");
    }

    /// A corrupt superblock can declare a `nodesize` too small to hold even the
    /// 101-byte B-tree node header. The zero-check alone let 1..=100 through, so
    /// the buffer was shorter than the header and `node_data[48..56]` panicked —
    /// a slice-range panic that unwound the whole btrfs parse. It must be a
    /// clean parse error, not a panic. Found by fuzzing.
    #[test]
    fn a_nodesize_too_small_for_the_header_is_refused_not_panicked() {
        let ds = seance_core::data_source::ByteSliceDataSource::new(vec![0u8; 4096]);
        for bad in [1u32, 48, 100, MIN_NODESIZE - 1] {
            let out = parse_btree_node(&ds, 0, bad);
            assert!(
                matches!(out, Err(ModuleError::ParsingError(_))),
                "nodesize {bad} must be a parse error, not a panic or a node"
            );
        }
        // The smallest valid nodesize is accepted as far as the size gate (it
        // then fails later on content, which is fine — it did not panic on the
        // header slice).
        let _ = parse_btree_node(&ds, 0, MIN_NODESIZE);
    }

    /// Build a 4 KiB superblock copy with the given generation and devid, and a
    /// system chunk array size that lets `parse_system_chunk_array` be told
    /// apart from a zeroed block.
    fn superblock_copy(generation: u64, devid: u64, sys_chunk_array_size: u32) -> Vec<u8> {
        let mut sb = vec![0u8; BTRFS_SUPERBLOCK_SIZE];
        sb[0x40..0x48].copy_from_slice(BTRFS_MAGIC);
        LittleEndian::write_u64(&mut sb[0x48..0x50], generation);
        LittleEndian::write_u32(&mut sb[0x90..0x94], 4096); // sectorsize
        LittleEndian::write_u32(&mut sb[0x94..0x98], 16384); // nodesize
        LittleEndian::write_u32(&mut sb[0xa0..0xa4], sys_chunk_array_size);
        LittleEndian::write_u64(&mut sb[0xc9..0xc9 + 8], devid);
        sb
    }

    /// The raw bytes the parser goes on to read the system chunk array and the
    /// device's own `devid` out of must come from the SAME copy the superblock
    /// was parsed from.
    ///
    /// A wiped primary is exactly when the mirror path matters, and re-reading
    /// the primary offset for those bytes hands a current `chunk_root` an
    /// all-zero chunk array: every logical address becomes unresolvable and the
    /// volume reports no files, on the damaged images the fallback exists for.
    #[test]
    fn superblock_bytes_come_from_the_copy_that_parsed() {
        // Primary wiped, 64 MiB mirror intact and naming devid 7.
        let mut img = vec![0u8; (BTRFS_SUPERBLOCK_OFFSET_2 as usize) + BTRFS_SUPERBLOCK_SIZE];
        let mirror = superblock_copy(99, 7, 97);
        img[BTRFS_SUPERBLOCK_OFFSET_2 as usize..].copy_from_slice(&mirror);
        let ds = seance_core::data_source::ByteSliceDataSource::new(img);

        let (sb, raw, offset) = load_btrfs_superblock(&ds).expect("mirror copy must be usable");
        assert_eq!(offset, BTRFS_SUPERBLOCK_OFFSET_2);
        assert_eq!(sb.generation, 99);
        assert_eq!(
            LittleEndian::read_u64(&raw[0xc9..0xc9 + 8]),
            7,
            "devid must come from the mirror, not from the wiped primary"
        );
        assert_eq!(
            LittleEndian::read_u32(&raw[0xa0..0xa4]),
            97,
            "the system chunk array size must come from the mirror copy"
        );
    }

    /// An intact primary is still preferred, and is reported as the primary so
    /// a "this came off a mirror" marker means something.
    #[test]
    fn intact_primary_is_used_and_not_flagged_as_a_mirror() {
        let mut img = vec![0u8; (BTRFS_SUPERBLOCK_OFFSET_1 as usize) + BTRFS_SUPERBLOCK_SIZE];
        img[BTRFS_SUPERBLOCK_OFFSET_1 as usize..].copy_from_slice(&superblock_copy(5, 1, 97));
        let ds = seance_core::data_source::ByteSliceDataSource::new(img);

        let (sb, _, offset) = load_btrfs_superblock(&ds).unwrap();
        assert_eq!(offset, BTRFS_SUPERBLOCK_OFFSET_1);
        assert_eq!(sb.generation, 5);
    }

    /// No readable copy anywhere is an error, never a default superblock: a
    /// zeroed one would parse a `chunk_root` of 0 and a `nodesize` of 0 and
    /// present the volume as empty.
    #[test]
    fn no_readable_superblock_copy_is_an_error() {
        let ds = seance_core::data_source::ByteSliceDataSource::new(vec![
            0u8;
            (BTRFS_SUPERBLOCK_OFFSET_1
                as usize)
                + BTRFS_SUPERBLOCK_SIZE
        ]);
        assert!(load_btrfs_superblock(&ds).is_err());

        // Too small to hold even the primary copy: also an error, not silence.
        let tiny = seance_core::data_source::ByteSliceDataSource::new(vec![0u8; 4096]);
        assert!(load_btrfs_superblock(&tiny).is_err());
    }

    /// A btrfs volume whose B-tree walk fails produced a bare FileSystem
    /// artifact with no files and no flag, which reads as an empty-but-complete
    /// volume. The walk never ran: every file on it is missing from the case
    /// (B7-008). APFS already stamps its volume artifact this way.
    #[test]
    fn a_failed_tree_walk_marks_the_filesystem_inventory_incomplete() {
        // Valid superblock, but an empty system chunk array: nothing can be
        // mapped, so `walk_filesystem` errors out.
        let mut img = vec![0u8; (BTRFS_SUPERBLOCK_OFFSET_1 as usize) + BTRFS_SUPERBLOCK_SIZE];
        img[BTRFS_SUPERBLOCK_OFFSET_1 as usize..].copy_from_slice(&superblock_copy(5, 1, 0));
        let ds: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(img));
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(ds),
            json!({ "subtype": "btrfs" }),
        );

        let produced = BtrfsParser.process(&artifact).unwrap();
        let fs = produced
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileSystem)
            .expect("filesystem artifact");
        assert_eq!(fs.metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            fs.metadata["inventory_incomplete_reason"],
            json!("btrfs_tree_walk_failed")
        );
        assert!(fs.metadata["inventory_error"].is_string());
    }

    /// Two directory entries naming the same inode are two hardlinks. Keeping
    /// only the last one discarded every other path the file lived at (B7-007).
    #[test]
    fn every_hardlink_name_of_an_inode_is_retained() {
        let mut paths = std::collections::HashMap::new();
        let mut all_paths = std::collections::HashMap::new();
        record_inode_path(&mut paths, &mut all_paths, 257, "/a/original".to_string());
        record_inode_path(&mut paths, &mut all_paths, 257, "/b/alias".to_string());

        assert_eq!(
            paths.get(&257).map(String::as_str),
            Some("/a/original"),
            "the first name discovered stays canonical"
        );
        assert_eq!(
            all_paths.get(&257).map(Vec::as_slice),
            Some(["/a/original".to_string(), "/b/alias".to_string()].as_slice()),
            "both hardlink names must survive"
        );
    }

    #[test]
    fn test_parse_key() {
        let mut data = [0u8; 17];
        // objectid = 256 (0x100)
        LittleEndian::write_u64(&mut data[0..8], 256);
        // key_type = 1 (INODE_ITEM)
        data[8] = 1;
        // offset = 0
        LittleEndian::write_u64(&mut data[9..17], 0);

        let key = parse_key(&data).unwrap();
        assert_eq!(key.objectid, 256);
        assert_eq!(key.key_type, 1);
        assert_eq!(key.offset, 0);
    }

    #[test]
    fn test_parse_key_with_large_values() {
        let mut data = [0u8; 17];
        LittleEndian::write_u64(&mut data[0..8], 0xFFFF_FFFF_FFFF_FFFF);
        data[8] = 228;
        LittleEndian::write_u64(&mut data[9..17], 0x1234_5678_9ABC_DEF0);

        let key = parse_key(&data).unwrap();
        assert_eq!(key.objectid, 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(key.key_type, 228);
        assert_eq!(key.offset, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_parse_key_too_short() {
        let data = [0u8; 10];
        assert!(parse_key(&data).is_none());
    }

    #[test]
    fn test_parse_system_chunk_array() {
        // Build a minimal superblock with one system chunk entry
        let mut sb_data = vec![0u8; BTRFS_SUPERBLOCK_SIZE];

        // Set magic
        sb_data[0x40..0x48].copy_from_slice(BTRFS_MAGIC);

        // sys_chunk_array_size at 0xa0 (real btrfs layout): one entry =
        // 17 (key) + 48 (chunk header) + 32 (one stripe) = 97
        let entry_size: u32 = 17 + 48 + 32;
        LittleEndian::write_u32(&mut sb_data[0xa0..0xa4], entry_size);

        // System chunk array starts at 0x32b
        let pos = 0x32b;

        // Key: objectid=256, type=CHUNK_ITEM(228), offset=0x100000 (logical address)
        LittleEndian::write_u64(&mut sb_data[pos..pos + 8], 256);
        sb_data[pos + 8] = BTRFS_CHUNK_ITEM_KEY;
        LittleEndian::write_u64(&mut sb_data[pos + 9..pos + 17], 0x100000);

        // Chunk item at pos+17
        let chunk_pos = pos + 17;
        // length
        LittleEndian::write_u64(&mut sb_data[chunk_pos..chunk_pos + 8], 0x200000);
        // owner (skip)
        // stripe_len (skip)
        // type_flags at +24
        LittleEndian::write_u64(&mut sb_data[chunk_pos + 24..chunk_pos + 32], 0x02); // DATA type
                                                                                     // num_stripes at +44
        LittleEndian::write_u16(&mut sb_data[chunk_pos + 44..chunk_pos + 46], 1);

        // Stripe at chunk_pos+48
        let stripe_pos = chunk_pos + 48;
        // devid
        LittleEndian::write_u64(&mut sb_data[stripe_pos..stripe_pos + 8], 1);
        // offset (physical)
        LittleEndian::write_u64(&mut sb_data[stripe_pos + 8..stripe_pos + 16], 0x500000);
        // dev_uuid (16 bytes, zeros)

        let chunks = parse_system_chunk_array(&sb_data);
        assert_eq!(chunks.len(), 1);

        let (logical, length, chunk) = &chunks[0];
        assert_eq!(*logical, 0x100000);
        assert_eq!(*length, 0x200000);
        assert_eq!(chunk.type_flags, 0x02);
        assert_eq!(chunk.num_stripes, 1);
        assert_eq!(chunk.stripes.len(), 1);
        assert_eq!(chunk.stripes[0].devid, 1);
        assert_eq!(chunk.stripes[0].offset, 0x500000);
    }

    #[test]
    fn test_parse_btree_node_rejects_huge_nodesize() {
        // Regression: nodesize comes straight from the superblock. A ~4 GiB
        // value must be rejected before `vec![0u8; nodesize]` allocates it.
        let ds = seance_core::data_source::ByteSliceDataSource::new(vec![0u8; 4096]);
        assert!(parse_btree_node(&ds, 0, u32::MAX).is_err());
        assert!(parse_btree_node(&ds, 0, MAX_NODESIZE + 1).is_err());
        // A sane nodesize is still accepted (node is zero-filled => header parses).
        assert!(parse_btree_node(&ds, 0, 4096).is_ok());
    }

    #[test]
    fn test_walk_btree_leaves_bounds_cyclic_graph() {
        // Regression: a self-referential internal node (blockptr pointing back to
        // its own logical address) must not loop or accumulate unboundedly. The
        // per-address visited set makes the traversal terminate immediately.
        let nodesize: u32 = 4096;
        // One SINGLE-profile chunk mapping logical [0, 0x100000) to device 1 at
        // physical 0 (non-striped => physical == logical).
        let chunk = BtrfsChunkItem {
            length: 0x100000,
            type_flags: 0,
            stripe_len: 0x10000,
            num_stripes: 1,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0,
            }],
        };
        let chunk_map = vec![(0u64, 0x100000u64, chunk)];

        // Internal node at physical 0: level=1, nritems=1, one key pointer whose
        // blockptr is 0 (points at itself).
        let mut img = vec![0u8; nodesize as usize];
        LittleEndian::write_u32(&mut img[96..100], 1); // nritems = 1
        img[100] = 1; // level = 1 => internal node
                      // key pointer at 101: key(17) then blockptr(8) at +17.
        LittleEndian::write_u64(&mut img[118..126], 0); // blockptr = 0 (self)

        let mut devices = DeviceMap::new();
        let ds: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(img));
        devices.insert(1, ds);

        // Must terminate (no infinite loop / OOM) and yield no leaf items.
        let (items, incomplete) = walk_btree_leaves(&devices, 0, &chunk_map, nodesize, 0).unwrap();
        assert!(items.is_empty());
        assert_eq!(
            incomplete, None,
            "the cycle guard ends this walk cleanly; nothing was dropped"
        );
    }

    /// B2-095: hitting the node budget stops the walk mid-tree. The flag saying
    /// so is the only difference between "the filesystem holds these files" and
    /// "the filesystem holds at least these files", so the walk must report it
    /// rather than log and return a prefix that reads as a full inventory.
    #[test]
    fn btree_node_budget_reports_a_truncated_walk() {
        let nodesize: u32 = 4096;
        let chunk_map = identity_chunk_map();

        // A leaf holding one item.
        let mut img = vec![0u8; nodesize as usize];
        LittleEndian::write_u32(&mut img[96..100], 1); // nritems = 1
        img[100] = 0; // level = 0 => leaf
        LittleEndian::write_u64(&mut img[101..109], 256); // key.objectid
        img[109] = BTRFS_INODE_ITEM_KEY;
        LittleEndian::write_u32(&mut img[118..122], 500); // item data offset
        LittleEndian::write_u32(&mut img[122..126], 4); // item data size
        img[601..605].copy_from_slice(b"ITEM");

        let mut devices = DeviceMap::new();
        let ds: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(img));
        devices.insert(1, ds);

        // Within budget: the item comes back and nothing is flagged.
        let (items, incomplete) = walk_btree_leaves(&devices, 0, &chunk_map, nodesize, 0).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, b"ITEM");
        assert_eq!(incomplete, None);

        // At the budget: the node is never visited, and the walk says so.
        let mut walk = BtreeWalk::new();
        walk.nodes_walked = MAX_BTREE_NODES;
        let mut results = Vec::new();
        walk_btree_leaves_inner(
            &devices,
            0,
            &chunk_map,
            nodesize,
            0,
            &mut walk,
            &mut results,
        )
        .unwrap();
        assert!(results.is_empty());
        assert_eq!(
            walk.incomplete_reason(),
            Some("btrfs_max_btree_nodes"),
            "exhausting the node budget must be reported, not just logged"
        );
    }

    /// A subtree that cannot be read (unresolvable address, unreadable node)
    /// drops its files from the results exactly like the node budget does. The
    /// walk must report that too, or a damaged image yields a short file list
    /// that reads as the complete filesystem.
    #[test]
    fn unreadable_subtree_reports_a_truncated_walk() {
        let nodesize: u32 = 4096;
        let chunk_map = identity_chunk_map();

        // An internal node whose only child points outside every chunk.
        let mut img = vec![0u8; nodesize as usize];
        LittleEndian::write_u32(&mut img[96..100], 1); // nritems = 1
        img[100] = 1; // level = 1 => internal
        LittleEndian::write_u64(&mut img[118..126], 0xFFFF_0000_0000); // unmappable child

        let mut devices = DeviceMap::new();
        let ds: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(img));
        devices.insert(1, ds);

        let (items, incomplete) = walk_btree_leaves(&devices, 0, &chunk_map, nodesize, 0).unwrap();
        assert!(items.is_empty());
        assert_eq!(
            incomplete,
            Some("btrfs_btree_subtree_unreadable"),
            "a subtree that could not be walked must not be silently dropped"
        );
    }

    #[test]
    fn test_materialize_compressed_extent_huge_num_bytes_no_panic() {
        // Regression: extent_offset and num_bytes are attacker-controlled u64 from
        // the file_extent_item and are not bounded by the materialize gate. A
        // regular compressed extent with a small in-bounds extent_offset and
        // num_bytes == u64::MAX previously overflowed `start + num_bytes` (debug
        // panic) or wrapped to end < start (release slice panic) in
        // materialize_compressed_extents. It must now return without panicking.
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        // A valid zlib blob for 8 known bytes.
        let plain: [u8; 8] = *b"ABCDEFGH";
        let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&plain).unwrap();
        let comp = enc.finish().unwrap();

        // One SINGLE-profile chunk mapping logical [0, 0x100000) to device 1 at
        // physical == logical (non-striped, stripe offset 0).
        let chunk = BtrfsChunkItem {
            length: 0x100000,
            type_flags: 0,
            stripe_len: 0x10000,
            num_stripes: 1,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0,
            }],
        };
        let chunk_map = vec![(0u64, 0x100000u64, chunk)];

        // Device 1 holds the compressed blob at physical (== logical) 0x1000.
        let disk_bytenr: u64 = 0x1000;
        let mut dev_bytes = vec![0u8; disk_bytenr as usize + comp.len()];
        dev_bytes[disk_bytenr as usize..].copy_from_slice(&comp);
        let mut devices = DeviceMap::new();
        let ds: Arc<dyn DataSource> = Arc::new(seance_core::data_source::ByteSliceDataSource::new(
            dev_bytes,
        ));
        devices.insert(1, ds);

        let mut extents = vec![BtrfsExtentData {
            generation: 0,
            ram_bytes: plain.len() as u64,
            compression: seance_core::compression::BTRFS_COMPRESS_ZLIB,
            encryption: 0,
            extent_type: 1, // regular (non-inline) => disk_bytenr branch
            disk_bytenr,
            disk_num_bytes: comp.len() as u64,
            extent_offset: 1,    // small, in-bounds start (start >= 1 is required to
            offset: 0,           // overflow the old `start + num_bytes`)
            num_bytes: u64::MAX, // attacker-controlled: must not overflow/panic
            inline_data: Vec::new(),
        }];

        let (any_compressed, _any_unsupported) =
            materialize_compressed_extents(&mut extents, &devices, &chunk_map);
        assert!(any_compressed);
        // With the fix the extent materializes to dec[1..8] (7 bytes) instead of
        // panicking.
        assert_eq!(extents[0].inline_data, plain[1..].to_vec());
        assert_eq!(
            extents[0].compression,
            seance_core::compression::BTRFS_COMPRESS_NONE
        );
    }

    /// CR-047. SYNTHETIC: a valid zlib stream that decodes to 8 bytes while the
    /// extent item claims `ram_bytes` of 8 + k. A stream that ends early is a
    /// truncated or corrupt extent; materializing it would serve a short file
    /// as the whole one. It must stay compressed and count as unsupported.
    fn zlib_eight_bytes() -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"ABCDEFGH").unwrap();
        enc.finish().unwrap()
    }

    fn regular_zlib_extent(comp_len: usize, ram_bytes: u64) -> BtrfsExtentData {
        BtrfsExtentData {
            generation: 0,
            ram_bytes,
            compression: seance_core::compression::BTRFS_COMPRESS_ZLIB,
            encryption: 0,
            extent_type: 1,
            disk_bytenr: 0x1000,
            disk_num_bytes: comp_len as u64,
            extent_offset: 0,
            offset: 0,
            num_bytes: 8,
            inline_data: Vec::new(),
        }
    }

    fn one_device_holding(comp: &[u8]) -> (DeviceMap, Vec<(u64, u64, BtrfsChunkItem)>) {
        let chunk = BtrfsChunkItem {
            length: 0x100000,
            type_flags: 0,
            stripe_len: 0x10000,
            num_stripes: 1,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0,
            }],
        };
        let mut dev_bytes = vec![0u8; 0x1000 + comp.len()];
        dev_bytes[0x1000..].copy_from_slice(comp);
        let mut devices = DeviceMap::new();
        let ds: Arc<dyn DataSource> = Arc::new(seance_core::data_source::ByteSliceDataSource::new(
            dev_bytes,
        ));
        devices.insert(1, ds);
        (devices, vec![(0u64, 0x100000u64, chunk)])
    }

    #[test]
    fn a_regular_extent_that_decodes_short_of_ram_bytes_is_not_materialized() {
        let comp = zlib_eight_bytes();
        let (devices, chunk_map) = one_device_holding(&comp);
        let mut extents = vec![regular_zlib_extent(comp.len(), 8 + 4)];
        let (any_compressed, any_unsupported) =
            materialize_compressed_extents(&mut extents, &devices, &chunk_map);
        assert!(any_compressed);
        assert!(any_unsupported, "a short decode must be reported");
        assert_eq!(
            extents[0].compression,
            seance_core::compression::BTRFS_COMPRESS_ZLIB,
            "the extent stays marked compressed"
        );
        assert!(extents[0].inline_data.is_empty());
    }

    #[test]
    fn a_regular_extent_that_decodes_to_ram_bytes_is_materialized() {
        let comp = zlib_eight_bytes();
        let (devices, chunk_map) = one_device_holding(&comp);
        let mut extents = vec![regular_zlib_extent(comp.len(), 8)];
        let (_, any_unsupported) =
            materialize_compressed_extents(&mut extents, &devices, &chunk_map);
        assert!(!any_unsupported);
        assert_eq!(extents[0].inline_data, b"ABCDEFGH".to_vec());
    }

    #[test]
    fn an_inline_extent_that_decodes_short_of_ram_bytes_is_not_materialized() {
        let comp = zlib_eight_bytes();
        let mut short = regular_zlib_extent(comp.len(), 8 + 4);
        short.extent_type = 0;
        short.inline_data = comp.clone();
        let mut exact = regular_zlib_extent(comp.len(), 8);
        exact.extent_type = 0;
        exact.inline_data = comp.clone();
        let (devices, chunk_map) = one_device_holding(&comp);

        let mut extents = vec![short];
        let (_, any_unsupported) =
            materialize_compressed_extents(&mut extents, &devices, &chunk_map);
        assert!(any_unsupported);
        assert_eq!(
            extents[0].inline_data, comp,
            "the compressed bytes are kept"
        );
        assert_eq!(
            extents[0].compression,
            seance_core::compression::BTRFS_COMPRESS_ZLIB
        );

        let mut extents = vec![exact];
        let (_, any_unsupported) =
            materialize_compressed_extents(&mut extents, &devices, &chunk_map);
        assert!(!any_unsupported);
        assert_eq!(extents[0].inline_data, b"ABCDEFGH".to_vec());
    }

    /// A device map holding the given devids, each backed by a tiny dummy
    /// source (logical_to_physical only inspects the keys).
    fn dev_map(ids: &[u64]) -> DeviceMap {
        let mut m = DeviceMap::new();
        for &id in ids {
            let ds: Arc<dyn DataSource> =
                Arc::new(seance_core::data_source::ByteSliceDataSource::new(vec![
                    0u8;
                    16
                ]));
            m.insert(id, ds);
        }
        m
    }

    #[test]
    fn test_logical_to_physical() {
        let chunk_map = vec![
            (
                0x100000u64,
                0x200000u64,
                BtrfsChunkItem {
                    length: 0x200000,
                    type_flags: 0x02,
                    stripe_len: 0x10000,
                    num_stripes: 1,
                    stripes: vec![BtrfsStripe {
                        devid: 1,
                        offset: 0x500000,
                    }],
                },
            ),
            (
                0x400000u64,
                0x100000u64,
                BtrfsChunkItem {
                    length: 0x100000,
                    type_flags: 0x01,
                    stripe_len: 0x10000,
                    num_stripes: 1,
                    stripes: vec![BtrfsStripe {
                        devid: 1,
                        offset: 0x800000,
                    }],
                },
            ),
        ];
        let devices = dev_map(&[1]);

        // Address within first chunk
        let phys = logical_to_physical(0x150000, &chunk_map, &devices);
        assert_eq!(phys, Some((1, 0x550000))); // 0x500000 + (0x150000 - 0x100000)

        // Address at start of first chunk
        let phys2 = logical_to_physical(0x100000, &chunk_map, &devices);
        assert_eq!(phys2, Some((1, 0x500000)));

        // Address within second chunk
        let phys3 = logical_to_physical(0x480000, &chunk_map, &devices);
        assert_eq!(phys3, Some((1, 0x880000))); // 0x800000 + (0x480000 - 0x400000)

        // Address not in any chunk
        let phys4 = logical_to_physical(0x900000, &chunk_map, &devices);
        assert!(phys4.is_none());

        // Address before all chunks
        let phys5 = logical_to_physical(0x50000, &chunk_map, &devices);
        assert!(phys5.is_none());
    }

    #[test]
    fn test_logical_to_physical_raid0() {
        // One RAID0 data chunk, 2 stripes of 64 KiB, on devid 1 and 2.
        let sl = 0x10000u64;
        let chunk_map = vec![(
            0u64,
            0x100000u64,
            BtrfsChunkItem {
                length: 0x100000,
                type_flags: BTRFS_BLOCK_GROUP_RAID0,
                stripe_len: sl,
                num_stripes: 2,
                stripes: vec![
                    BtrfsStripe {
                        devid: 1,
                        offset: 0xA00000,
                    },
                    BtrfsStripe {
                        devid: 2,
                        offset: 0xB00000,
                    },
                ],
            },
        )];
        let devices = dev_map(&[1, 2]);

        // stripe 0 -> dev 1, first stripe unit
        assert_eq!(
            logical_to_physical(0x0, &chunk_map, &devices),
            Some((1, 0xA00000))
        );
        // stripe 1 -> dev 2, first unit on that device
        assert_eq!(
            logical_to_physical(0x10000, &chunk_map, &devices),
            Some((2, 0xB00000))
        );
        // mid stripe 1 -> dev 2 + 0x8000
        assert_eq!(
            logical_to_physical(0x18000, &chunk_map, &devices),
            Some((2, 0xB08000))
        );
        // stripe 2 wraps back to dev 1, second unit
        assert_eq!(
            logical_to_physical(0x20000, &chunk_map, &devices),
            Some((1, 0xA10000))
        );

        // A stripe's devid is returned even when that device is absent, so the
        // caller can flag the file rather than read garbage.
        let only1 = dev_map(&[1]);
        assert_eq!(
            logical_to_physical(0x10000, &chunk_map, &only1),
            Some((2, 0xB00000))
        );

        // Contiguous run stops at the stripe boundary for striped chunks.
        assert_eq!(contiguous_run(0x0, &chunk_map), sl);
        assert_eq!(contiguous_run(0x8000, &chunk_map), sl - 0x8000);
    }

    #[test]
    fn test_parse_btree_header() {
        // Build a minimal leaf node (level=0, nritems=0) at the start of a buffer
        let nodesize: u32 = 4096;
        let mut node_data = vec![0u8; nodesize as usize];

        // csum: 32 bytes at +0 (zeros)
        // fsid: 16 bytes at +32 (zeros)
        // bytenr at +48
        LittleEndian::write_u64(&mut node_data[48..56], 0xABCD0000);
        // flags at +56
        LittleEndian::write_u64(&mut node_data[56..64], 1);
        // chunk_tree_uuid at +64 (zeros)
        // generation at +80
        LittleEndian::write_u64(&mut node_data[80..88], 42);
        // owner at +88
        LittleEndian::write_u64(&mut node_data[88..96], 5);
        // nritems at +96
        LittleEndian::write_u32(&mut node_data[96..100], 0);
        // level at +100
        node_data[100] = 0;

        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(
            node_data,
        ));
        let node = parse_btree_node(ds.as_ref(), 0, nodesize).unwrap();

        match node {
            BtrfsNode::Leaf { header, items, .. } => {
                assert_eq!(header.bytenr, 0xABCD0000);
                assert_eq!(header.generation, 42);
                assert_eq!(header.owner, 5);
                assert_eq!(header.nritems, 0);
                assert_eq!(header.level, 0);
                assert!(items.is_empty());
            }
            BtrfsNode::Internal { .. } => {
                panic!("Expected leaf node, got internal node");
            }
        }
    }

    #[test]
    fn test_parse_btree_internal_node() {
        let nodesize: u32 = 4096;
        let mut node_data = vec![0u8; nodesize as usize];

        // Header
        LittleEndian::write_u64(&mut node_data[48..56], 0x1000); // bytenr
        LittleEndian::write_u64(&mut node_data[80..88], 10); // generation
        LittleEndian::write_u64(&mut node_data[88..96], 1); // owner
        LittleEndian::write_u32(&mut node_data[96..100], 2); // nritems
        node_data[100] = 1; // level = 1 (internal)

        // Key pointer 0 at offset 101: key(17) + blockptr(8) + generation(8) = 33
        let kp0 = 101;
        LittleEndian::write_u64(&mut node_data[kp0..kp0 + 8], 100); // key.objectid
        node_data[kp0 + 8] = 1; // key.type
        LittleEndian::write_u64(&mut node_data[kp0 + 9..kp0 + 17], 0); // key.offset
        LittleEndian::write_u64(&mut node_data[kp0 + 17..kp0 + 25], 0x2000); // blockptr
        LittleEndian::write_u64(&mut node_data[kp0 + 25..kp0 + 33], 5); // generation

        // Key pointer 1 at offset 134
        let kp1 = 134;
        LittleEndian::write_u64(&mut node_data[kp1..kp1 + 8], 200); // key.objectid
        node_data[kp1 + 8] = 1;
        LittleEndian::write_u64(&mut node_data[kp1 + 9..kp1 + 17], 0);
        LittleEndian::write_u64(&mut node_data[kp1 + 17..kp1 + 25], 0x3000); // blockptr
        LittleEndian::write_u64(&mut node_data[kp1 + 25..kp1 + 33], 6); // generation

        let ds = Arc::new(seance_core::data_source::ByteSliceDataSource::new(
            node_data,
        ));
        let node = parse_btree_node(ds.as_ref(), 0, nodesize).unwrap();

        match node {
            BtrfsNode::Internal { header, pointers } => {
                assert_eq!(header.level, 1);
                assert_eq!(header.nritems, 2);
                assert_eq!(pointers.len(), 2);
                assert_eq!(pointers[0].key.objectid, 100);
                assert_eq!(pointers[0].blockptr, 0x2000);
                assert_eq!(pointers[0].generation, 5);
                assert_eq!(pointers[1].key.objectid, 200);
                assert_eq!(pointers[1].blockptr, 0x3000);
                assert_eq!(pointers[1].generation, 6);
            }
            BtrfsNode::Leaf { .. } => {
                panic!("Expected internal node, got leaf");
            }
        }
    }

    #[test]
    fn test_format_timestamp() {
        let ts = format_timestamp(1700000000);
        assert!(ts.contains("2023"));
        assert!(ts.contains("11")); // November

        let ts2 = format_timestamp(0);
        assert_eq!(ts2, "1970-01-01T00:00:00+00:00");

        let ts3 = format_timestamp(1609459200);
        assert!(ts3.contains("2021-01-01"));
    }

    #[test]
    fn test_parse_inode_item() {
        let mut data = vec![0u8; 160];

        // generation at +0
        LittleEndian::write_u64(&mut data[0..8], 42);
        // size at +16
        LittleEndian::write_u64(&mut data[16..24], 4096);
        // nlink at +40
        LittleEndian::write_u32(&mut data[40..44], 1);
        // uid at +44
        LittleEndian::write_u32(&mut data[44..48], 1000);
        // gid at +48
        LittleEndian::write_u32(&mut data[48..52], 1000);
        // mode at +52: regular file 0o100644
        LittleEndian::write_u32(&mut data[52..56], 0o100644);
        // atime at +112
        LittleEndian::write_i64(&mut data[112..120], 1700000000);
        // ctime at +124
        LittleEndian::write_i64(&mut data[124..132], 1700000100);
        // mtime at +136
        LittleEndian::write_i64(&mut data[136..144], 1700000200);
        // otime (creation time) at +148
        LittleEndian::write_i64(&mut data[148..156], 1690000000);

        let inode = parse_inode_item(&data).unwrap();
        assert_eq!(inode.generation, 42);
        assert_eq!(inode.size, 4096);
        assert_eq!(inode.nlink, 1);
        assert_eq!(inode.uid, 1000);
        assert_eq!(inode.gid, 1000);
        assert_eq!(inode.mode, 0o100644);
        assert_eq!(inode.atime_sec, 1700000000);
        assert_eq!(inode.ctime_sec, 1700000100);
        assert_eq!(inode.mtime_sec, 1700000200);
        assert_eq!(
            inode.otime_sec, 1690000000,
            "otime (real creation time) must be parsed"
        );
    }

    #[test]
    fn test_parse_dir_item() {
        let name = b"hello.txt";
        let name_len = name.len();
        let total_len = 30 + name_len;
        let mut data = vec![0u8; total_len];

        // location key: objectid=257, type=INODE_ITEM(1), offset=0
        LittleEndian::write_u64(&mut data[0..8], 257);
        data[8] = BTRFS_INODE_ITEM_KEY;
        LittleEndian::write_u64(&mut data[9..17], 0);
        // transid at +17 (skip)
        // data_len at +25
        LittleEndian::write_u16(&mut data[25..27], 0);
        // name_len at +27
        LittleEndian::write_u16(&mut data[27..29], name_len as u16);
        // dir_type at +29
        data[29] = 1; // regular file
                      // name at +30
        data[30..30 + name_len].copy_from_slice(name);

        let dir_item = parse_dir_item(&data).unwrap();
        assert_eq!(dir_item.location.objectid, 257);
        assert_eq!(dir_item.location.key_type, BTRFS_INODE_ITEM_KEY);
        assert_eq!(dir_item.name, "hello.txt");
        assert_eq!(dir_item.dir_type, 1);
    }

    #[test]
    fn test_parse_extent_data_inline() {
        let content = b"Hello Btrfs!";
        let total_len = 21 + content.len();
        let mut data = vec![0u8; total_len];

        // generation at +0
        LittleEndian::write_u64(&mut data[0..8], 10);
        // ram_bytes at +8
        LittleEndian::write_u64(&mut data[8..16], content.len() as u64);
        // compression at +16
        data[16] = 0;
        // extent_type at +20
        data[20] = 0; // inline
                      // data at +21
        data[21..].copy_from_slice(content);

        let extent = parse_extent_data(&data, 0).unwrap();
        assert_eq!(extent.extent_type, 0);
        assert_eq!(extent.generation, 10);
        assert_eq!(extent.ram_bytes, 12);
        assert_eq!(extent.inline_data, content);
    }

    #[test]
    fn test_parse_extent_data_regular() {
        let mut data = vec![0u8; 53];

        // generation at +0
        LittleEndian::write_u64(&mut data[0..8], 20);
        // ram_bytes at +8
        LittleEndian::write_u64(&mut data[8..16], 4096);
        // compression at +16
        data[16] = 0;
        // extent_type at +20
        data[20] = 1; // regular
                      // disk_bytenr at +21
        LittleEndian::write_u64(&mut data[21..29], 0x100000);
        // disk_num_bytes at +29
        LittleEndian::write_u64(&mut data[29..37], 4096);
        // offset at +37
        LittleEndian::write_u64(&mut data[37..45], 0);
        // num_bytes at +45
        LittleEndian::write_u64(&mut data[45..53], 4096);

        let extent = parse_extent_data(&data, 0).unwrap();
        assert_eq!(extent.extent_type, 1);
        assert_eq!(extent.disk_bytenr, 0x100000);
        assert_eq!(extent.disk_num_bytes, 4096);
        assert_eq!(extent.num_bytes, 4096);
        assert_eq!(extent.encryption, 0);
    }

    /// BUG-181: `btrfs_file_extent_item.encryption` (+17) must be kept, and a
    /// non-zero value must mark the served/hashed content as ciphertext instead
    /// of mapping the extent as if it were plaintext.
    #[test]
    fn test_encrypted_extent_is_flagged_as_ciphertext() {
        let mut data = vec![0u8; 53];
        LittleEndian::write_u64(&mut data[0..8], 20); // generation
        LittleEndian::write_u64(&mut data[8..16], 4096); // ram_bytes
        data[16] = 0; // compression: none
        data[17] = 1; // encryption: non-zero
        data[20] = 1; // extent_type: regular
        LittleEndian::write_u64(&mut data[21..29], 0x100000); // disk_bytenr
        LittleEndian::write_u64(&mut data[29..37], 4096); // disk_num_bytes
        LittleEndian::write_u64(&mut data[37..45], 0); // extent_offset
        LittleEndian::write_u64(&mut data[45..53], 4096); // num_bytes

        let extent = parse_extent_data(&data, 0).expect("extent parses");
        assert_eq!(extent.encryption, 1, "encryption byte must be kept");

        // One SINGLE chunk mapping logical == physical on the primary device.
        let chunk_map = vec![(
            0u64,
            0x1000000u64,
            BtrfsChunkItem {
                length: 0x1000000,
                type_flags: 0,
                stripe_len: 0x10000,
                num_stripes: 1,
                stripes: vec![BtrfsStripe {
                    devid: 1,
                    offset: 0,
                }],
            },
        )];
        let devices = dev_map(&[1]);
        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(vec![
                0u8;
                64
            ]));

        let mut metadata = json!({});
        persist_btrfs_content(
            &mut metadata,
            std::slice::from_ref(&extent),
            &chunk_map,
            4096,
            src.as_ref(),
            &devices,
            1,
            false,
        );
        assert_eq!(metadata["encrypted"], json!(true));
        assert_eq!(
            metadata["content_ciphertext"],
            json!("btrfs_extent_encryption")
        );

        // An unencrypted extent must not carry the marker.
        let mut plain = extent;
        plain.encryption = 0;
        let mut metadata = json!({});
        persist_btrfs_content(
            &mut metadata,
            &[plain],
            &chunk_map,
            4096,
            src.as_ref(),
            &devices,
            1,
            false,
        );
        assert!(metadata.get("encrypted").is_none());
    }

    /// A chunk map whose second chunk lives on devid 2, so logical addresses
    /// in it resolve to a device the content resolver will never have.
    fn two_device_chunk_map() -> Vec<(u64, u64, BtrfsChunkItem)> {
        vec![
            (
                0u64,
                0x10000u64,
                BtrfsChunkItem {
                    length: 0x10000,
                    type_flags: 0,
                    stripe_len: 0x10000,
                    num_stripes: 1,
                    stripes: vec![BtrfsStripe {
                        devid: 1,
                        offset: 0,
                    }],
                },
            ),
            (
                0x10000u64,
                0x10000u64,
                BtrfsChunkItem {
                    length: 0x10000,
                    type_flags: 0,
                    stripe_len: 0x10000,
                    num_stripes: 1,
                    stripes: vec![BtrfsStripe {
                        devid: 2,
                        offset: 0,
                    }],
                },
            ),
        ]
    }

    /// B2-134: the content resolver only ever has the primary device, so an
    /// extent living on a sibling device is persisted as a HOLE. Persisted
    /// unflagged, that hole re-serves as zeros under the file's real size and
    /// hash-verify silently compares fabricated zeros against the ingest digest
    /// taken across every device. The persisted location must say it describes
    /// less than the file.
    #[test]
    fn off_primary_extents_are_never_persisted_as_a_complete_location() {
        let chunk_map = two_device_chunk_map();
        let devices = dev_map(&[1, 2]);
        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(vec![
                0u8;
                0x2000
            ]));

        // First 0x1000 on devid 1, second 0x1000 at logical 0x10000 on devid 2.
        let extents = vec![
            regular_extent(0, 0x1000, 0x1000),
            regular_extent(0x1000, 0x10000, 0x1000),
        ];

        let mut metadata = json!({});
        persist_btrfs_content(
            &mut metadata,
            &extents,
            &chunk_map,
            0x2000,
            src.as_ref(),
            &devices,
            1,
            false,
        );
        assert_eq!(
            metadata["data_runs_complete"],
            json!(false),
            "a run list with a stand-in hole is not a complete location"
        );
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(
            metadata["content_incomplete_reason"],
            json!("btrfs_extent_off_primary_device")
        );
        assert_eq!(metadata["data_incomplete_multi_device"], json!(true));

        // The same file entirely on the primary device stays complete: a flag
        // that is always on tells an examiner nothing.
        let mut metadata = json!({});
        persist_btrfs_content(
            &mut metadata,
            &[regular_extent(0, 0x1000, 0x1000)],
            &chunk_map,
            0x1000,
            src.as_ref(),
            &devices,
            1,
            false,
        );
        assert_eq!(metadata["data_runs_complete"], json!(true));
        assert!(metadata.get("content_incomplete").is_none());
        assert!(metadata.get("data_incomplete_multi_device").is_none());
    }

    /// B2-136: an encrypted extent is served and hashed as ciphertext under the
    /// file's real size. `content_ciphertext` alone is display-only — the flag
    /// every consumer reads is `content_incomplete`.
    #[test]
    fn encrypted_extents_set_the_standard_incomplete_flag() {
        let mut enc = regular_extent(0, 0x1000, 0x1000);
        enc.encryption = 1;
        let devices = dev_map(&[1]);
        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(vec![
                0u8;
                0x1000
            ]));

        let mut metadata = json!({});
        persist_btrfs_content(
            &mut metadata,
            &[enc],
            &identity_chunk_map(),
            0x1000,
            src.as_ref(),
            &devices,
            1,
            false,
        );
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(metadata["content_incomplete_reason"], json!("encrypted"));
    }

    /// A SINGLE chunk that maps logical addresses 1:1 onto the primary device.
    fn identity_chunk_map() -> Vec<(u64, u64, BtrfsChunkItem)> {
        vec![(
            0u64,
            0x1000000u64,
            BtrfsChunkItem {
                length: 0x1000000,
                type_flags: 0,
                stripe_len: 0x10000,
                num_stripes: 1,
                stripes: vec![BtrfsStripe {
                    devid: 1,
                    offset: 0,
                }],
            },
        )]
    }

    fn regular_extent(file_offset: u64, disk_bytenr: u64, num_bytes: u64) -> BtrfsExtentData {
        BtrfsExtentData {
            generation: 1,
            ram_bytes: num_bytes,
            compression: BTRFS_COMPRESS_NONE,
            encryption: 0,
            extent_type: 1,
            disk_bytenr,
            disk_num_bytes: num_bytes,
            extent_offset: 0,
            offset: file_offset,
            num_bytes,
            inline_data: Vec::new(),
        }
    }

    /// BUG-209: a prealloc extent (`extent_type == 2`) is allocated but never
    /// written. The kernel returns zeros for it, so reading its `disk_bytenr`
    /// serves residual disk data as file content.
    #[test]
    fn test_prealloc_extent_reads_as_zeros() {
        let mut backing = vec![0u8; 0x20000];
        backing[0x1000..0x1004].copy_from_slice(b"real");
        // Residual bytes still sitting in the preallocated range.
        backing[0x2000..0x2008].copy_from_slice(b"RESIDUAL");
        let dev: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(backing));
        let mut devices = DeviceMap::new();
        devices.insert(1, dev);

        let written = regular_extent(0, 0x1000, 0x1000);
        let mut prealloc = regular_extent(0x1000, 0x2000, 0x1000);
        prealloc.extent_type = 2;

        let source = BtrfsFileSource::new(
            Arc::new(devices),
            identity_chunk_map(),
            0x2000,
            vec![written, prealloc],
            true,
        );

        let mut buf = vec![0xAAu8; 0x2000];
        assert_eq!(source.read_at(0, &mut buf).unwrap(), 0x2000);
        assert_eq!(&buf[0..4], b"real");
        assert!(
            buf[0x1000..].iter().all(|&b| b == 0),
            "prealloc extent must read as zeros, got residual disk bytes"
        );
    }

    /// BUG-241: `read_logical` zero-fills whatever it could not fetch and says
    /// so through its return value. The file source used to discard that and
    /// report a full, successful read, so a truncated image hashed fabricated
    /// zeros as the file's content.
    #[test]
    fn test_short_device_read_is_not_served_as_file_content() {
        // The device ends half-way through the extent's range.
        let dev: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(vec![0xCDu8; 0x1000 + 0x800]),
        );
        let mut devices = DeviceMap::new();
        devices.insert(1, dev);

        let source = BtrfsFileSource::new(
            Arc::new(devices),
            identity_chunk_map(),
            0x1000,
            vec![regular_extent(0, 0x1000, 0x1000)],
            true,
        );

        let mut buf = vec![0xAAu8; 0x1000];
        let err = source
            .read_at(0, &mut buf)
            .expect_err("a short device read must not be served as complete content");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// A device that is entirely absent (missing image in a multi-device
    /// volume) must fail the same way rather than serve a zero-filled file.
    #[test]
    fn test_missing_device_is_not_served_as_zeros() {
        // devid 1 is referenced by the chunk map but absent from the map.
        let source = BtrfsFileSource::new(
            Arc::new(DeviceMap::new()),
            identity_chunk_map(),
            0x1000,
            vec![regular_extent(0, 0x1000, 0x1000)],
            true,
        );

        let mut buf = vec![0xAAu8; 0x1000];
        let err = source
            .read_at(0, &mut buf)
            .expect_err("a missing device must not be served as zeros");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// The persisted runs must also treat prealloc as a hole, or a later
    /// re-serve from the DB resurrects the residual bytes.
    #[test]
    fn test_prealloc_extent_persists_as_sparse_run() {
        let chunk_map = identity_chunk_map();
        let devices = dev_map(&[1]);
        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(vec![
                0u8;
                64
            ]));

        let written = regular_extent(0, 0x1000, 0x1000);
        let mut prealloc = regular_extent(0x1000, 0x2000, 0x1000);
        prealloc.extent_type = 2;

        let mut metadata = json!({});
        persist_btrfs_content(
            &mut metadata,
            &[written, prealloc],
            &chunk_map,
            0x2000,
            src.as_ref(),
            &devices,
            1,
            false,
        );

        assert_eq!(
            metadata["data_runs"],
            json!([[0x1000, 0x1000], [serde_json::Value::Null, 0x1000]])
        );
        assert_eq!(metadata["data_runs_complete"], json!(true));
        assert_eq!(metadata["has_prealloc_extents"], json!(true));
    }

    /// BUG-212: when the MAX_EXTENTS cap drops a file's trailing extents the
    /// tail is zero-filled. Those zeros are a guess, not content, so the runs
    /// must be flagged incomplete.
    #[test]
    fn test_capped_extent_list_marks_content_incomplete() {
        let chunk_map = identity_chunk_map();
        let devices = dev_map(&[1]);
        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(vec![
                0u8;
                64
            ]));
        let extents = vec![regular_extent(0, 0x1000, 0x1000)];

        // Whole extent list: the trailing zero-fill is a genuine hole.
        let mut whole = json!({});
        persist_btrfs_content(
            &mut whole,
            &extents,
            &chunk_map,
            0x2000,
            src.as_ref(),
            &devices,
            1,
            false,
        );
        assert_eq!(whole["data_runs_complete"], json!(true));
        assert!(whole.get("content_incomplete").is_none());

        // Capped extent list: same runs, but they are not the whole file.
        let mut capped = json!({});
        persist_btrfs_content(
            &mut capped,
            &extents,
            &chunk_map,
            0x2000,
            src.as_ref(),
            &devices,
            1,
            true,
        );
        assert_eq!(capped["data_runs_complete"], json!(false));
        assert_eq!(capped["content_incomplete"], json!(true));
        assert_eq!(
            capped["content_incomplete_reason"],
            json!("btrfs_max_extents")
        );
    }

    /// B2-003: a compressed extent that was never materialized has no plaintext
    /// on disk. `disk_bytenr + extent_offset` addresses the COMPRESSED stream, so
    /// mapping file offsets onto it hands back compressed bytes — and whatever
    /// follows them — under the file's name, size and hash.
    #[test]
    fn unmaterialized_compressed_extent_is_not_served_as_plaintext() {
        let dev: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(vec![0x78u8; 0x4000]),
        );
        let mut devices = DeviceMap::new();
        devices.insert(1, dev);

        let mut compressed = regular_extent(0, 0x1000, 0x1000);
        compressed.compression = seance_core::compression::BTRFS_COMPRESS_ZLIB;

        let source = BtrfsFileSource::new(
            Arc::new(devices),
            identity_chunk_map(),
            0x1000,
            vec![compressed],
            true,
        );

        let mut buf = vec![0xAAu8; 0x1000];
        let err = source
            .read_at(0, &mut buf)
            .expect_err("compressed bytes must not be served as file content");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The same rule for an inline extent whose payload is still compressed
    /// (unsupported codec, or a decompression that failed): copying it out would
    /// index and hash a compressed blob as the file's text.
    #[test]
    fn compressed_inline_extent_is_not_served_as_plaintext() {
        let mut inline = BtrfsExtentData {
            generation: 1,
            ram_bytes: 16,
            compression: seance_core::compression::BTRFS_COMPRESS_ZSTD,
            encryption: 0,
            extent_type: 0,
            disk_bytenr: 0,
            disk_num_bytes: 0,
            extent_offset: 0,
            offset: 0,
            num_bytes: 8,
            inline_data: vec![0x28, 0xB5, 0x2F, 0xFD, 0, 0, 0, 0],
        };
        inline.num_bytes = inline.inline_data.len() as u64;

        let source = BtrfsFileSource::new(
            Arc::new(DeviceMap::new()),
            identity_chunk_map(),
            16,
            vec![inline],
            true,
        );

        let mut buf = vec![0u8; 8];
        let err = source
            .read_at(0, &mut buf)
            .expect_err("a compressed inline payload must not be served as content");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// B2-032: when MAX_EXTENTS truncated the extent list, everything past the
    /// last known extent is UNKNOWN, not a hole. The source must short-read
    /// there; a complete list keeps zero-filling its genuine sparse tail.
    #[test]
    fn truncated_extent_list_short_reads_past_the_mapped_end() {
        let mut backing = vec![0u8; 0x4000];
        backing[0x1000..0x1004].copy_from_slice(b"HEAD");
        let dev: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(backing));
        let mut devices = DeviceMap::new();
        devices.insert(1, dev);
        let devices = Arc::new(devices);

        let extents = vec![regular_extent(0, 0x1000, 0x1000)];

        // Truncated list: the tail past 0x1000 is unknown.
        let capped = BtrfsFileSource::new(
            Arc::clone(&devices),
            identity_chunk_map(),
            0x3000,
            extents.clone(),
            false,
        );
        let mut buf = vec![0xAAu8; 0x3000];
        let n = capped.read_at(0, &mut buf).unwrap();
        assert_eq!(
            n, 0x1000,
            "a capped extent list must stop at the mapped end, not zero-fill the tail"
        );
        assert_eq!(&buf[..4], b"HEAD");
        assert!(
            buf[0x1000..].iter().all(|&b| b == 0xAA),
            "the unknown tail must not be overwritten with fabricated zeros"
        );

        // Complete list: the same tail is a genuine sparse hole and reads as zeros.
        let whole = BtrfsFileSource::new(devices, identity_chunk_map(), 0x3000, extents, true);
        let mut buf = vec![0xAAu8; 0x3000];
        let n = whole.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 0x3000);
        assert!(buf[0x1000..].iter().all(|&b| b == 0));
    }

    /// B2-033: btrfs rotates the parity column one device per full-stripe row, so
    /// a data column's device is `(row + col) % num_stripes` (the kernel's
    /// "distribute the parity blocks across stripes"). Reading `stripes[col]`
    /// instead lands on the parity block from row 1 onwards, and that parity
    /// would be served and hashed as file content.
    #[test]
    fn raid5_data_columns_follow_the_parity_rotation() {
        let sl = 0x10000u64;
        // 3 devices, RAID5: 2 data columns + 1 parity per row.
        let chunk_map = vec![(
            0u64,
            0x100000u64,
            BtrfsChunkItem {
                length: 0x100000,
                type_flags: BTRFS_BLOCK_GROUP_RAID5,
                stripe_len: sl,
                num_stripes: 3,
                stripes: vec![
                    BtrfsStripe {
                        devid: 1,
                        offset: 0,
                    },
                    BtrfsStripe {
                        devid: 2,
                        offset: 0,
                    },
                    BtrfsStripe {
                        devid: 3,
                        offset: 0,
                    },
                ],
            },
        )];
        let devices = dev_map(&[1, 2, 3]);

        // Row 0: parity on device 3; data columns 0,1 on devices 1,2.
        assert_eq!(logical_to_physical(0, &chunk_map, &devices), Some((1, 0)));
        assert_eq!(logical_to_physical(sl, &chunk_map, &devices), Some((2, 0)));
        // Row 1: rotation moves parity to device 1; data columns land on
        // devices 2 and 3, one stripe unit down each device.
        assert_eq!(
            logical_to_physical(2 * sl, &chunk_map, &devices),
            Some((2, sl))
        );
        assert_eq!(
            logical_to_physical(3 * sl, &chunk_map, &devices),
            Some((3, sl))
        );
        // Row 2: parity moves to device 2; data on devices 3 and 1.
        assert_eq!(
            logical_to_physical(4 * sl, &chunk_map, &devices),
            Some((3, 2 * sl))
        );
        assert_eq!(
            logical_to_physical(5 * sl, &chunk_map, &devices),
            Some((1, 2 * sl))
        );
        // Mid-stripe offsets keep their position inside the unit.
        assert_eq!(
            logical_to_physical(2 * sl + 0x1234, &chunk_map, &devices),
            Some((2, sl + 0x1234))
        );
    }

    /// RAID6 carries two parity columns, so the same rotation runs over
    /// `num_stripes` with only `num_stripes - 2` data columns per row.
    #[test]
    fn raid6_data_columns_follow_the_parity_rotation() {
        let sl = 0x10000u64;
        let chunk_map = vec![(
            0u64,
            0x100000u64,
            BtrfsChunkItem {
                length: 0x100000,
                type_flags: BTRFS_BLOCK_GROUP_RAID6,
                stripe_len: sl,
                num_stripes: 4,
                stripes: (1..=4)
                    .map(|devid| BtrfsStripe { devid, offset: 0 })
                    .collect(),
            },
        )];
        let devices = dev_map(&[1, 2, 3, 4]);

        // Row 0: data on devices 1,2 (P and Q on 3,4).
        assert_eq!(logical_to_physical(0, &chunk_map, &devices), Some((1, 0)));
        assert_eq!(logical_to_physical(sl, &chunk_map, &devices), Some((2, 0)));
        // Row 1: rotated by one.
        assert_eq!(
            logical_to_physical(2 * sl, &chunk_map, &devices),
            Some((2, sl))
        );
        assert_eq!(
            logical_to_physical(3 * sl, &chunk_map, &devices),
            Some((3, sl))
        );
    }

    /// A chunk whose stripe offset sits near the top of the address space must
    /// saturate rather than wrap: a wrapped physical offset reads unrelated
    /// bytes near the start of the device and serves them as content.
    #[test]
    fn absurd_stripe_offset_saturates_instead_of_wrapping() {
        let chunk_map = vec![(
            0u64,
            0x1000u64,
            BtrfsChunkItem {
                length: 0x1000,
                type_flags: 0,
                stripe_len: 0x10000,
                num_stripes: 1,
                stripes: vec![BtrfsStripe {
                    devid: 1,
                    offset: u64::MAX - 8,
                }],
            },
        )];
        let devices = dev_map(&[1]);
        assert_eq!(
            logical_to_physical(0x100, &chunk_map, &devices),
            Some((1, u64::MAX)),
            "an overflowing physical offset must saturate, not wrap to a low offset"
        );
    }

    /// B2-094: a file over the DataSource ceiling gets no content. Metadata still
    /// carries its full size, so without an explicit reason the artifact is
    /// indistinguishable from an empty file — the examiner would conclude the
    /// file held nothing.
    #[test]
    fn oversized_file_declares_why_it_has_no_content() {
        let devices = Arc::new(dev_map(&[1]));
        let chunk_map = identity_chunk_map();
        let extents = vec![regular_extent(0, 0x1000, 0x1000)];

        let mut metadata = json!({ "size": MAX_FILE_SIZE + 1 });
        let src = attach_file_content(
            &mut metadata,
            Some(&extents),
            false,
            MAX_FILE_SIZE + 1,
            &devices,
            &chunk_map,
            1,
        );
        assert!(src.is_none(), "an oversized file gets no data source");
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(
            metadata["content_incomplete_reason"],
            json!("btrfs_file_too_large")
        );
        assert_eq!(metadata["content_incomplete_limit"], json!(MAX_FILE_SIZE));

        // The same file under the ceiling is served normally and flagged nothing.
        let mut metadata = json!({ "size": 0x1000 });
        let src = attach_file_content(
            &mut metadata,
            Some(&extents),
            false,
            0x1000,
            &devices,
            &chunk_map,
            1,
        );
        assert!(src.is_some());
        assert!(metadata.get("content_incomplete").is_none());
    }

    /// B2-094, second half: a sized file with no extent records must say so too,
    /// rather than emit a sized FileEntry with no bytes and no explanation.
    #[test]
    fn sized_file_without_extent_records_declares_content_missing() {
        let devices = Arc::new(dev_map(&[1]));
        let chunk_map = identity_chunk_map();

        let mut metadata = json!({ "size": 0x1000 });
        let src = attach_file_content(&mut metadata, None, false, 0x1000, &devices, &chunk_map, 1);
        assert!(src.is_none());
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(
            metadata["content_incomplete_reason"],
            json!("btrfs_no_extent_records")
        );

        // An empty (but present) extent list is the same situation.
        let mut metadata = json!({ "size": 0x1000 });
        let empty: Vec<BtrfsExtentData> = Vec::new();
        let src = attach_file_content(
            &mut metadata,
            Some(&empty),
            false,
            0x1000,
            &devices,
            &chunk_map,
            1,
        );
        assert!(src.is_none());
        assert_eq!(
            metadata["content_incomplete_reason"],
            json!("btrfs_no_extent_records")
        );
    }

    /// B2-003: an LZO extent cannot be decompressed here and cannot be described
    /// for the resolver either, so the file has no plaintext anywhere. It must be
    /// flagged rather than left looking like ordinary content.
    #[test]
    fn undecompressable_codec_flags_the_content_unavailable() {
        let devices = Arc::new(dev_map(&[1]));
        let chunk_map = identity_chunk_map();
        let mut lzo = regular_extent(0, 0x1000, 0x1000);
        // BTRFS_COMPRESS_LZO is 2 (zlib is 1, zstd is 3); this codec has no
        // decompressor here and no resolver descriptor either.
        lzo.compression = 2;

        let extents = vec![lzo];
        let mut metadata = json!({ "size": 0x1000 });
        let src = attach_file_content(
            &mut metadata,
            Some(&extents),
            false,
            0x1000,
            &devices,
            &chunk_map,
            1,
        );
        assert!(
            src.is_some(),
            "a source is still attached, but it fails closed"
        );
        assert_eq!(metadata["compressed"], json!(true));
        assert_eq!(metadata["compression_unsupported"], json!(true));
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(
            metadata["content_incomplete_reason"],
            json!("btrfs_compressed_not_decompressed")
        );

        // And the attached source refuses to serve the compressed bytes.
        let mut buf = vec![0u8; 0x1000];
        assert_eq!(
            src.unwrap().read_at(0, &mut buf).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// B2-003 / B2-094 companion: `persist_btrfs_content` falls back to storing
    /// the file's bytes inline. When the source refuses to serve them (still
    /// compressed, device missing) the stored prefix must be flagged, or the
    /// resolver re-serves a truncated file as the whole thing.
    #[test]
    fn resident_fallback_flags_a_short_read() {
        let chunk_map = identity_chunk_map();
        let devices = dev_map(&[1]);
        // A source that yields nothing: stands in for content we cannot serve.
        let src: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(Vec::new()),
        );

        // An inline extent forces the resident fallback (not all_mapped).
        let inline = BtrfsExtentData {
            generation: 1,
            ram_bytes: 32,
            compression: BTRFS_COMPRESS_NONE,
            encryption: 0,
            extent_type: 0,
            disk_bytenr: 0,
            disk_num_bytes: 0,
            extent_offset: 0,
            offset: 0,
            num_bytes: 32,
            inline_data: vec![0u8; 32],
        };

        let mut metadata = json!({});
        persist_btrfs_content(
            &mut metadata,
            &[inline],
            &chunk_map,
            32,
            src.as_ref(),
            &devices,
            1,
            false,
        );
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(
            metadata["content_incomplete_reason"],
            json!("btrfs_resident_short_read")
        );
        assert_eq!(metadata["resident_data_bytes"], json!(0));
    }

    #[test]
    fn test_parse_chunk_item_data() {
        let mut data = vec![0u8; 80];

        // length at +0
        LittleEndian::write_u64(&mut data[0..8], 0x400000);
        // type_flags at +24
        LittleEndian::write_u64(&mut data[24..32], 0x01); // SYSTEM
                                                          // num_stripes at +44
        LittleEndian::write_u16(&mut data[44..46], 1);
        // stripe at +48: devid(8) + offset(8) + dev_uuid(16)
        LittleEndian::write_u64(&mut data[48..56], 1); // devid
        LittleEndian::write_u64(&mut data[56..64], 0x200000); // offset

        let chunk = parse_chunk_item_data(&data).unwrap();
        assert_eq!(chunk.length, 0x400000);
        assert_eq!(chunk.type_flags, 0x01);
        assert_eq!(chunk.num_stripes, 1);
        assert_eq!(chunk.stripes.len(), 1);
        assert_eq!(chunk.stripes[0].devid, 1);
        assert_eq!(chunk.stripes[0].offset, 0x200000);
    }

    #[test]
    fn test_logical_to_physical_edge_cases() {
        let chunk_map = vec![(
            0u64,
            0x1000u64,
            BtrfsChunkItem {
                length: 0x1000,
                type_flags: 0x01,
                stripe_len: 0x10000,
                num_stripes: 1,
                stripes: vec![BtrfsStripe {
                    devid: 1,
                    offset: 0x2000,
                }],
            },
        )];

        let devices = dev_map(&[1]);
        // Exact start
        assert_eq!(
            logical_to_physical(0, &chunk_map, &devices),
            Some((1, 0x2000))
        );
        // Last byte
        assert_eq!(
            logical_to_physical(0xFFF, &chunk_map, &devices),
            Some((1, 0x2FFF))
        );
        // One past end
        assert_eq!(logical_to_physical(0x1000, &chunk_map, &devices), None);
        // Empty chunk map
        assert_eq!(logical_to_physical(0, &[], &devices), None);
    }

    #[test]
    fn test_logical_to_physical_no_stripes() {
        let chunk_map = vec![(
            0u64,
            0x1000u64,
            BtrfsChunkItem {
                length: 0x1000,
                type_flags: 0x01,
                stripe_len: 0x10000,
                num_stripes: 0,
                stripes: vec![],
            },
        )];

        // Chunk with no stripes should return None
        assert_eq!(logical_to_physical(0x500, &chunk_map, &dev_map(&[1])), None);
    }
}
