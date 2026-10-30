#![forbid(unsafe_code)]
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    free_space::{emit_free_regions, AllocationBitmap, BitMeaning, FreeSpaceLabels},
    io::{read_exact_or_fail, read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::{CancellationHandle, ProgressReporter},
};
use serde_json::json;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Cap on data runs persisted in FileEntry metadata (contract with the API layer)
use seance_core::data_source::MAX_METADATA_DATA_RUNS;
/// Maximum buckets in a downsampled allocation bitmap (contract with the API layer)
const MAX_ALLOCATION_BUCKETS: u64 = 65536;
/// EXT4_ENCRYPT_FL: the inode's data is fscrypt-encrypted, so its extent/block
/// pointers reference ciphertext this parser does not decrypt.
const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;
/// EXT4_INLINE_DATA_FL: the inode keeps its content (or a small directory's
/// dirents) inside `i_block` and the `system.data` xattr. `i_block` then holds
/// bytes, not extent headers or block pointers, so it must never be decoded as
/// either.
const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;
/// Incompat feature bit EXT4_FEATURE_INCOMPAT_INLINE_DATA.
const EXT4_INCOMPAT_INLINE_DATA: u32 = 0x8000;
/// EXT4_BG_BLOCK_UNINIT: the group's block bitmap on disk is not valid (the
/// kernel computes it on demand). Only meaningful when the volume has
/// `uninit_bg`/`metadata_csum`, see [`Superblock::honours_group_flags`].
const EXT4_BG_BLOCK_UNINIT: u16 = 0x0002;
/// EXT4_FEATURE_INCOMPAT_META_BG.
const EXT4_INCOMPAT_META_BG: u32 = 0x10;
/// EXT4_FEATURE_RO_COMPAT_GDT_CSUM (`uninit_bg`) and METADATA_CSUM: the volumes
/// whose group-descriptor flags are valid.
const EXT4_RO_COMPAT_GDT_CSUM: u32 = 0x10;
const EXT4_RO_COMPAT_METADATA_CSUM: u32 = 0x400;
/// EXT4_FEATURE_RO_COMPAT_BIGALLOC: bitmap bits are clusters, not blocks.
const EXT4_RO_COMPAT_BIGALLOC: u32 = 0x200;
/// Cap on how many bytes of a single directory's on-disk dirents we scan, to
/// bound memory on hostile or very large directories. Exceeding it truncates the
/// scan and sets `directory_parse_incomplete` on the directory artifact.
const EXT4_MAX_DIR_BYTES: u64 = 1024 * 1024;

// ext4_dir_entry_2::file_type values (linux/fs/ext4/ext4.h FT_*; identical to
// the ext2/ext3 predecessor). Named so a dirent's claimed type and an inode's
// own mode bits (`ext4_file_type_from_mode`) can be compared by name rather
// than by a bare digit repeated at each call site.
const EXT4_FT_UNKNOWN: u8 = 0;
const EXT4_FT_REG_FILE: u8 = 1;
const EXT4_FT_DIR: u8 = 2;
const EXT4_FT_CHRDEV: u8 = 3;
const EXT4_FT_BLKDEV: u8 = 4;
const EXT4_FT_FIFO: u8 = 5;
const EXT4_FT_SOCK: u8 = 6;
const EXT4_FT_SYMLINK: u8 = 7;

/// Bound on entries the orphaned-directory-block scan (§5.6) will emit across
/// the whole volume. Free space filled with plausible-looking dirent chains
/// is not something a crafted or simply very fragmented image can be assumed
/// not to have, and each entry costs an inode read; this is the same class of
/// safety cap as `MAX_SLACK_ENTRIES_PER_ENTRY`, sized for the whole pass
/// rather than one entry's slack. Reported on the scan's summary record when
/// hit, never silently.
const MAX_ORPHANED_DIRECTORY_ENTRIES: usize = 100_000;

/// Longest run of consecutive free blocks the orphaned-directory scan reads in
/// one call (1 MiB at 4 KiB blocks): per-call I/O, not the dirent heuristic,
/// dominates the cost of scanning a large mostly-free volume.
const ORPHAN_SCAN_CHUNK_BLOCKS: u64 = 256;

pub struct Ext4Parser {
    max_recursion_depth: usize,
    progress: Option<ProgressReporter>,
    cancellation: Option<CancellationHandle>,
}

impl Ext4Parser {
    pub fn new() -> Self {
        Self {
            max_recursion_depth: 20,
            progress: None,
            cancellation: None,
        }
    }

    pub fn with_depth(depth: usize) -> Self {
        Self {
            max_recursion_depth: depth,
            progress: None,
            cancellation: None,
        }
    }

    /// Attach a progress reporter; inode enumeration emits ModuleProgress
    /// events in "files" (rate-limited by the reporter to ~1/sec).
    pub fn with_progress(mut self, reporter: ProgressReporter) -> Self {
        self.progress = Some(reporter);
        self
    }

    /// Attach a cancellation handle; the inode walk stops cooperatively when it
    /// fires and returns the artifacts parsed so far.
    pub fn with_cancellation(mut self, handle: CancellationHandle) -> Self {
        self.cancellation = Some(handle);
        self
    }
}

impl Default for Ext4Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for Ext4Parser {
    fn id(&self) -> &str {
        "plugin.fs.ext4"
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
        // Accept ext2/ext3/ext4 by subtype or filesystem_type, case-insensitively
        // (detectors emit lowercase, but a caller passing "EXT4" must not silently
        // skip the whole volume).
        let is_ext = |s: &str| {
            s.eq_ignore_ascii_case("ext4")
                || s.eq_ignore_ascii_case("ext3")
                || s.eq_ignore_ascii_case("ext2")
        };
        if let Some(subtype) = artifact.subtype() {
            if !is_ext(subtype) {
                return Ok(Vec::new()); // Early exit - wrong filesystem type
            }
        }

        // Fallback: check filesystem_type metadata
        let fs_type = artifact
            .metadata
            .get("filesystem_type")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if !fs_type.is_empty() && !is_ext(fs_type) {
            return Ok(Vec::new());
        }

        debug!("Ext4Parser processing artifact ID: {}", artifact.id);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("Ext4 parser requires a data source".to_string())
        })?;

        let mut produced_artifacts = Vec::new();

        // 1. Parse Superblock
        let superblock = Superblock::parse(data_source.as_ref())
            .map_err(|e| ModuleError::ParsingError(format!("Failed to parse superblock: {}", e)))?;

        info!("Ext4 Superblock: Inodes: {}, Blocks: {}, Block Size: {}, Inodes/Group: {}, Blocks/Group: {}, Desc Size: {}, Features: {:x}",
              superblock.inodes_count, superblock.blocks_count, superblock.block_size,
              superblock.inodes_per_group, superblock.blocks_per_group, superblock.desc_size, superblock.incompat_features);

        // 2. Parse Block Group Descriptors
        let groups =
            BlockGroupDescriptor::parse_table(data_source.as_ref(), &superblock).map_err(|e| {
                ModuleError::ParsingError(format!("Failed to parse block group descriptors: {}", e))
            })?;

        // Honest denominator for progress: total inode slots from the superblock.
        let total_inodes = superblock.inodes_count as u64;

        // 3. Start traversal from Root Inode (Inode 2)
        let root_inode_num = 2;
        let mut context = ParsingContext {
            artifact_id: artifact.id,
            case_id: artifact.case_id,
            data_source: data_source.clone(),
            superblock: &superblock,
            groups: &groups,
            produced_artifacts: &mut produced_artifacts,
            max_recursion_depth: self.max_recursion_depth,
            depth: 0,
            visited_dirs: std::collections::HashSet::new(),
            listing_gaps: ListingGaps::default(),
            progress: &self.progress,
            cancellation: &self.cancellation,
            total_inodes,
        };

        // Without a readable root there is no walk, and a volume with no
        // files and no marker reads as an empty one. Say it could not be read.
        let root_problem = match parse_inode(&mut context, root_inode_num, "/") {
            Ok(InodeWalk::Emitted) => produced_artifacts
                .first()
                .filter(|root| root.metadata["is_directory"] == json!(false))
                .map(|_| format!("root inode ({root_inode_num}) is not a directory")),
            Ok(InodeWalk::Cancelled) => None,
            Ok(InodeWalk::Unallocated) => Some(format!(
                "root inode ({root_inode_num}) is unallocated (mode 0)"
            )),
            Ok(InodeWalk::DepthLimit) => Some(format!(
                "the recursion limit ({}) stopped the walk at the root",
                self.max_recursion_depth
            )),
            Err(e) => Some(e.to_string()),
        };
        let walk_cancelled = self
            .cancellation
            .as_ref()
            .is_some_and(|c| c.is_cancelled(artifact.case_id));
        if let Some(error) = root_problem {
            warn!("ext4 root inode unusable: {}", error);
            produced_artifacts.push(volume_status_record(
                artifact,
                "ext4_root_status",
                &format!(
                    "The root inode of this ext volume could not be used ({error}), so no file \
                     or directory under it is listed. The absence of files is a failure to start \
                     the walk, not evidence that the volume is empty. Deleted names found by the \
                     orphaned-directory and journal passes are still reported."
                ),
                json!({
                    "root_inode_readable": false,
                    "root_inode_error": error,
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                }),
            ));
        }

        // A cancelled walk returns the prefix it reached. Without this record
        // that prefix reads as the whole inventory.
        if walk_cancelled {
            produced_artifacts.push(volume_status_record(
                artifact,
                "ext4_walk_status",
                "The walk of this ext volume was cancelled before it finished, so the file \
                 inventory is a prefix of the volume, not all of it. A file missing from it \
                 was not examined; its absence is not evidence that it is not there.",
                json!({
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": "cancelled",
                }),
            ));
        }

        // Final progress update so the bar completes (or reflects the point of
        // cancellation).
        if let Some(reporter) = &self.progress {
            reporter.report_now_for_case(
                artifact.case_id,
                artifact.id,
                produced_artifacts.len() as u64,
                Some(total_inodes),
                "files",
            );
        }

        // Publish in-image sidecars (`-wal`, `.LOG1`/`.LOG2`) through
        // `open_sibling`, so registry log replay and WAL-aware SQLite spills
        // work for evidence inside a disk image, not only for loose files and
        // ZIP entries (BUG-257).
        seance_core::data_source::attach_sibling_bundles(&mut produced_artifacts);

        // Emit the volume allocation map built from the block-group block
        // bitmaps. Omitted entirely when any bitmap is unavailable.
        if superblock.is_bigalloc() && superblock.cluster_bits.is_none() {
            produced_artifacts.push(volume_status_record(
                artifact,
                "ext4_free_space_status",
                "This volume uses bigalloc, but its cluster size and clusters-per-group fields \
                 do not agree with its block size and blocks-per-group, so which blocks a \
                 block-bitmap bit covers is not known. The allocation map, the free-space \
                 regions and the orphaned-directory scan are omitted. Their absence is not \
                 evidence that the volume has no free space.",
                json!({"allocation_map_unavailable": true}),
            ));
        }
        if let Some((map_artifact, free_regions)) = build_allocation_map_artifact(
            artifact.case_id,
            artifact.id,
            data_source.as_ref(),
            data_source,
            &superblock,
            &groups,
        ) {
            produced_artifacts.push(map_artifact);
            // The free blocks as regions the automatic carver reads (§5.4).
            produced_artifacts.extend(free_regions);
        }

        // Deleted-directory contents (§5.6): scan the blocks the volume's own
        // bitmaps say are free for one that still holds an orphaned
        // directory's dirents, and recover what can honestly be attributed to
        // each inode named there. A second, independent read of the (small)
        // group bitmaps from the one above — cheap next to the per-block scan
        // itself — so this pass is omitted on exactly the same "bitmap
        // unavailable" condition as the allocation map, rather than assuming
        // the map's success.
        if let Some(bitmaps) = GroupBitmaps::read(data_source.as_ref(), &superblock, &groups) {
            let mut scan_context = ParsingContext {
                artifact_id: artifact.id,
                case_id: artifact.case_id,
                data_source: data_source.clone(),
                superblock: &superblock,
                groups: &groups,
                produced_artifacts: &mut produced_artifacts,
                max_recursion_depth: self.max_recursion_depth,
                depth: 0,
                visited_dirs: std::collections::HashSet::new(),
                listing_gaps: ListingGaps::default(),
                progress: &None,
                cancellation: &self.cancellation,
                total_inodes,
            };
            scan_orphaned_directory_blocks(&mut scan_context, &bitmaps);
        } else {
            debug!("ext4 orphaned-directory-block scan omitted: block bitmap unavailable");
        }

        // File slack (HUNT-124): one region per live regular file whose tail
        // holds bytes. A file reached under two names (a hard link) is one
        // inode and is offered once.
        let mut slack = seance_core::slack::SlackCollector::new(
            seance_core::slack::SlackLabels {
                filesystem: "ext4",
                offset_basis: "the start of this volume, not the start of the evidence",
            },
            u64::from(superblock.block_size),
        );
        let mut offered_inodes = std::collections::HashSet::new();
        for file in produced_artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        {
            // Only an entry `offer_live_file` can act on may consume its inode:
            // a stale slack-recovered name for inode X is walked before the
            // live entry for X and must not use up X's one offer.
            let flag = |key: &str| file.metadata.get(key).and_then(|v| v.as_bool()) == Some(true);
            if !flag("deleted") && !flag("is_directory") {
                let inode = file.metadata.get("inode").and_then(|v| v.as_u64());
                if inode.is_some_and(|i| !offered_inodes.insert(i)) {
                    continue;
                }
            }
            seance_core::slack::offer_live_file(
                &mut slack,
                artifact,
                data_source,
                file,
                u64::from(superblock.block_size),
                &[],
            );
        }
        let (slack_artifacts, _) = slack.finish(artifact);
        produced_artifacts.extend(slack_artifacts);

        // Enumerate committed JBD2 journal transactions (omitted only when the
        // filesystem declares no journal; an unreadable journal yields a status
        // record).
        if let Some(journal_artifact) = build_journal_artifacts(
            artifact.case_id,
            artifact.id,
            data_source,
            &superblock,
            &groups,
        ) {
            produced_artifacts.push(journal_artifact);
        }

        Ok(produced_artifacts)
    }
}

/// The bitmap an uninitialised group would have if it were initialised, derived
/// the way libext2fs (`mark_uninit_bg_group_blocks`) and the kernel
/// (`ext4_init_block_bitmap`) derive it: the group's backup superblock,
/// descriptor blocks and reserved descriptor blocks, plus the block bitmap,
/// inode bitmap and inode table of every BLOCK_UNINIT group wherever they sit
/// (flex_bg puts them in other groups). A group the kernel marks BLOCK_UNINIT
/// has had no block allocated, so nothing else is in use.
///
/// Fills `bitmaps[g]` and clears `uninit[g]` for every group it derives, and
/// returns which. It derives all or none: a group whose layout cannot be
/// derived (group 0, a meta_bg group that carries descriptor duties, a location
/// outside the volume) may have marks to place in another group's bitmap, so
/// one failure leaves every BLOCK_UNINIT group unassessed.
fn synthesize_block_uninit(
    sb: &Superblock,
    groups: &[BlockGroupDescriptor],
    bitmaps: &mut [Vec<u8>],
    uninit: &mut [bool],
) -> Vec<bool> {
    let mut synthesized = vec![false; uninit.len()];
    let candidates: Vec<usize> = uninit
        .iter()
        .enumerate()
        .filter(|(_, u)| **u)
        .map(|(i, _)| i)
        .collect();
    if candidates.is_empty() {
        return synthesized;
    }
    let bpg = sb.blocks_per_group as u64;
    let block_size = sb.block_size as u64;
    let first = sb.first_data_block as u64;
    let end = sb.blocks_count;
    let Some(cluster_bits) = sb.cluster_bits else {
        return synthesized;
    };
    if bpg == 0
        || (bpg >> cluster_bits) > block_size * 8
        || sb.desc_size == 0
        || groups.len() != uninit.len()
        || end <= first
    {
        return synthesized;
    }
    let group_count = (end - first).div_ceil(bpg);
    let desc_per_block = block_size / sb.desc_size as u64;
    if desc_per_block == 0 {
        return synthesized;
    }
    let desc_blocks = group_count.div_ceil(desc_per_block);
    let meta_bg = sb.incompat_features & EXT4_INCOMPAT_META_BG != 0;
    let itable_blocks = (sb.inodes_per_group as u64 * sb.inode_size as u64).div_ceil(block_size);

    let mut maps: std::collections::HashMap<usize, Vec<u8>> = candidates
        .iter()
        .map(|&g| (g, vec![0u8; block_size as usize]))
        .collect();
    // Mark `len` blocks from `start`; false when any falls outside the volume.
    let mut mark = |start: u64, len: u64| -> bool {
        if len == 0 {
            return true;
        }
        let Some(last) = start.checked_add(len - 1) else {
            return false;
        };
        if start < first || last >= end {
            return false;
        }
        for block in start..=last {
            let group = ((block - first) / bpg) as usize;
            if let Some(map) = maps.get_mut(&group) {
                let bit = ((block - first) % bpg) >> cluster_bits;
                map[(bit / 8) as usize] |= 1 << (bit % 8);
            }
        }
        true
    };

    for &g in &candidates {
        // Group 0 holds the primary superblock and descriptors, and no volume
        // marks it BLOCK_UNINIT: a flag there is not believed.
        if g == 0 {
            return synthesized;
        }
        let start = first + g as u64 * bpg;
        let has_super = sb.has_superblock(g as u64);
        if meta_bg {
            // The meta_bg descriptor placement (first, second and last group
            // of a meta-group) is not graded against a volume that has it on a
            // BLOCK_UNINIT group, so a group with any such duty stays
            // unassessed.
            let rem = g as u64 % desc_per_block;
            if has_super || rem == 0 || rem == 1 || rem == desc_per_block - 1 {
                return synthesized;
            }
        } else if has_super {
            let old_desc_blocks = desc_blocks + sb.reserved_gdt_blocks as u64;
            if !mark(start, 1) || !mark(start + 1, old_desc_blocks) {
                return synthesized;
            }
        }
        let group = &groups[g];
        let (bb, ib, it) = (
            group.get_block_bitmap_block(),
            group.get_inode_bitmap_block(),
            group.get_inode_table_block(),
        );
        if !mark(bb, 1) || !mark(ib, 1) || !mark(it, itable_blocks) {
            return synthesized;
        }
    }

    for (g, map) in maps {
        bitmaps[g] = map;
        uninit[g] = false;
        synthesized[g] = true;
    }
    synthesized
}

/// What a set of group block bitmaps can say about one block. Three answers,
/// not two: a byte a truncated group bitmap does not hold is neither free nor
/// allocated, and treating it as either would be a claim the bitmap never
/// made — see [`GroupBitmaps::is_allocated`] vs [`GroupBitmaps::state`].
enum BlockState {
    Free,
    InUse,
    Unassessed,
}

/// Every block group's block bitmap, read once and queryable by block number.
/// Shared by the volume allocation map (`build_allocation_map_artifact`) and
/// the orphaned-directory-block scan (§5.6, `scan_orphaned_directory_blocks`)
/// so both answer "is this block free" from the same reading of the volume's
/// own free-space metadata, rather than one of them re-deriving it.
struct GroupBitmaps {
    bitmaps: Vec<Vec<u8>>,
    blocks_per_group: u64,
    first_data_block: u64,
    /// Set when some group's bitmap was read but short of a full block:
    /// blocks past its reach are `Unassessed`, never `Free`.
    short: bool,
    /// Per group: BLOCK_UNINIT, so the on-disk bitmap is not valid and was not
    /// read, and no bitmap could be derived either. Every block of such a group
    /// is `Unassessed`.
    uninit: Vec<bool>,
    /// Per group: BLOCK_UNINIT, and the bitmap held here was derived from the
    /// superblock and descriptors (what libext2fs and the kernel compute), not
    /// read from disk.
    synthesized: Vec<bool>,
    /// log2(blocks per bitmap bit): 0 except on a bigalloc volume.
    cluster_bits: u32,
}

impl GroupBitmaps {
    /// Read every block group's block bitmap up front. `None` when any group
    /// has no bitmap block recorded, or its bitmap could not be read at all —
    /// callers omit whatever they were building rather than guess at missing
    /// free-space metadata.
    fn read(
        source: &dyn DataSource,
        sb: &Superblock,
        groups: &[BlockGroupDescriptor],
    ) -> Option<Self> {
        let blocks_per_group = sb.blocks_per_group as u64;
        if blocks_per_group == 0 || groups.is_empty() {
            return None;
        }
        // Bigalloc bitmap bits are clusters. Indexing them as blocks would map
        // every block to the wrong bit and report allocated data as free.
        let Some(cluster_bits) = sb.cluster_bits else {
            warn!(
                "ext4 bigalloc volume with inconsistent cluster fields: free-space reads omitted"
            );
            return None;
        };
        let block_size = sb.block_size as u64;
        let mut bitmaps: Vec<Vec<u8>> = Vec::with_capacity(groups.len());
        let mut uninit: Vec<bool> = Vec::with_capacity(groups.len());
        let mut short = false;
        for (i, group) in groups.iter().enumerate() {
            // A BLOCK_UNINIT group's on-disk bitmap is stale or zeroed: the
            // kernel computes the real one. Reading it would report the
            // group's metadata and used blocks as free.
            if sb.honours_group_flags() && group.block_uninit() {
                bitmaps.push(Vec::new());
                uninit.push(true);
                continue;
            }
            uninit.push(false);
            let bitmap_block = group.get_block_bitmap_block();
            if bitmap_block == 0 {
                debug!("Group {} has no block bitmap; omitting free-space read", i);
                return None;
            }
            let mut buf = vec![0u8; sb.block_size as usize];
            // A truncated bitmap reports its unread tail as free space, and free
            // space reads as "nothing was ever written here", so gather the whole
            // block rather than accept whatever one `read_at` happened to deliver.
            let n = read_full(source, bitmap_block.saturating_mul(block_size), &mut buf);
            if n == 0 {
                debug!(
                    "Failed to read block bitmap for group {}; omitting free-space read",
                    i
                );
                return None;
            }
            if n < buf.len() {
                // A partially read bitmap reports its unread tail as free space.
                short = true;
            }
            buf.truncate(n);
            bitmaps.push(buf);
        }
        let synthesized = synthesize_block_uninit(sb, groups, &mut bitmaps, &mut uninit);
        Some(GroupBitmaps {
            bitmaps,
            blocks_per_group,
            first_data_block: sb.first_data_block as u64,
            short,
            uninit,
            synthesized,
            cluster_bits,
        })
    }

    /// How many BLOCK_UNINIT groups have a derived bitmap.
    fn synthesized_groups(&self) -> usize {
        self.synthesized.iter().filter(|&&u| u).count()
    }

    fn is_uninit_group(&self, group: usize) -> bool {
        self.uninit.get(group).copied().unwrap_or(false)
    }

    /// How many groups are BLOCK_UNINIT (their bitmaps were not read).
    fn uninit_groups(&self) -> usize {
        self.uninit.iter().filter(|&&u| u).count()
    }

    /// Bit i of group g's bitmap covers block `first_data_block +
    /// g*blocks_per_group + i`. Blocks below `first_data_block` (the boot
    /// area) count as allocated. A block a missing/short group bitmap cannot
    /// reach reads as free here — this is the two-answer view used for the
    /// downsampled allocation-map display; [`Self::state`] is the three-answer
    /// view used wherever "unassessed" must not be conflated with "free".
    fn is_allocated(&self, block: u64) -> bool {
        if block < self.first_data_block {
            return true;
        }
        let relative = block - self.first_data_block;
        let group = (relative / self.blocks_per_group) as usize;
        let bit = (relative % self.blocks_per_group) >> self.cluster_bits;
        // Not known free: the two-answer view never calls an uninitialised
        // group's blocks free.
        if self.is_uninit_group(group) {
            return true;
        }
        match self.bitmaps.get(group) {
            Some(bitmap) => {
                let byte = bitmap.get((bit / 8) as usize).copied().unwrap_or(0);
                byte & (1 << (bit % 8)) != 0
            }
            None => false,
        }
    }

    /// The three-answer view of one block: free, in use, or unassessed
    /// (a truncated/missing group bitmap does not reach it, so it is neither).
    fn state(&self, block: u64) -> BlockState {
        // The boot area is not free space.
        if block < self.first_data_block {
            return BlockState::InUse;
        }
        let relative = block - self.first_data_block;
        let group = (relative / self.blocks_per_group) as usize;
        let bit = (relative % self.blocks_per_group) >> self.cluster_bits;
        if self.is_uninit_group(group) {
            return BlockState::Unassessed;
        }
        match self.bitmaps.get(group) {
            Some(bitmap) => match bitmap.get((bit / 8) as usize) {
                Some(byte) => {
                    if byte & (1 << (bit % 8)) != 0 {
                        BlockState::InUse
                    } else {
                        BlockState::Free
                    }
                }
                // This group's bitmap was read short and does not reach this
                // block. Not free.
                None => BlockState::Unassessed,
            },
            None => BlockState::Unassessed,
        }
    }
}

/// The volume-wide block count that can actually be described: `blocks_count`
/// and `blocks_per_group` are both attacker-controlled and a loop over either
/// would be a CPU and memory DoS, so the count is bounded by what the group
/// descriptors cover AND by the blocks that physically fit in the image
/// (`image_size`). Returns 0 when there is nothing to describe. A caller that
/// sees the bound fall short of `blocks_count` must say the rest is unknown.
fn total_blocks_bound(sb: &Superblock, groups: &[BlockGroupDescriptor], image_size: u64) -> u64 {
    let blocks_per_group = sb.blocks_per_group as u64;
    if blocks_per_group == 0 {
        return 0;
    }
    let max_blocks = (groups.len() as u64).saturating_mul(blocks_per_group);
    let image_blocks = image_size.div_ceil(sb.block_size.max(1) as u64);
    sb.blocks_count.min(max_blocks).min(image_blocks)
}

/// Read every block group's block bitmap and emit the downsampled volume
/// allocation map as a ParsedRecord child of the FileSystem artifact.
/// Returns None (omitting the artifact) when any bitmap cannot be read.
fn build_allocation_map_artifact(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    source: &dyn DataSource,
    source_arc: &Arc<dyn DataSource>,
    sb: &Superblock,
    groups: &[BlockGroupDescriptor],
) -> Option<(Artifact, Vec<Artifact>)> {
    let block_size = sb.block_size as u64;
    if groups.is_empty() {
        return None;
    }
    let blocks_per_group = sb.blocks_per_group as u64;
    if blocks_per_group == 0 {
        return None;
    }
    let total_blocks = total_blocks_bound(sb, groups, source.size());
    if total_blocks == 0 {
        return None;
    }
    // Blocks the descriptors or the image cannot describe are NOT free space.
    // Clamping the total silently redefined the volume as smaller, and
    // everything past the clamp rendered as free — which an examiner reads as
    // "nothing was ever written here" (B5-004 class).
    let short_blocks = sb.blocks_count > total_blocks;
    let bitmaps = GroupBitmaps::read(source, sb, groups)?;
    let short_bitmaps = bitmaps.short;
    let uninit_groups = bitmaps.uninit_groups();
    let synthesized_groups = bitmaps.synthesized_groups();

    let clusters_per_bucket = total_blocks.div_ceil(MAX_ALLOCATION_BUCKETS).max(1);
    let bucket_count = total_blocks.div_ceil(clusters_per_bucket);
    let mut buckets = Vec::with_capacity(bucket_count as usize);
    let mut block: u64 = 0;
    while block < total_blocks {
        let in_bucket = clusters_per_bucket.min(total_blocks - block);
        let mut allocated: u64 = 0;
        for b in block..block + in_bucket {
            if bitmaps.is_allocated(b) {
                allocated += 1;
            }
        }
        buckets.push(((allocated * 255) / in_bucket) as u8);
        block += in_bucket;
    }

    let mut metadata = json!({
        "type": "allocation_map",
        "allocation_bitmap_b64": BASE64.encode(&buckets),
        "allocation_clusters_per_bucket": clusters_per_bucket,
        "allocation_total_clusters": total_blocks,
        "allocation_cluster_size": block_size,
    });
    if short_blocks || short_bitmaps || uninit_groups > 0 {
        let reason = if short_bitmaps {
            IncompleteReason::ShortRead
        } else {
            IncompleteReason::UnresolvedStructure
        };
        warn!(
            "ext4 allocation map covers {} of {} blocks declared by the superblock \
             ({}); the uncovered range is NOT known to be free space",
            total_blocks,
            sb.blocks_count,
            reason.as_str()
        );
        metadata["allocation_map_incomplete"] = json!(true);
        metadata["allocation_blocks_declared"] = json!(sb.blocks_count);
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!(reason.as_str());
        if uninit_groups > 0 {
            metadata["allocation_block_uninit_groups"] = json!(uninit_groups);
        }
    }
    if synthesized_groups > 0 {
        // Derived, not read: say so on the map, and keep the count apart from
        // the groups that stayed unassessed.
        metadata["allocation_block_uninit_groups_synthesized"] = json!(synthesized_groups);
        metadata["allocation_block_uninit_basis"] = json!(
            "BLOCK_UNINIT groups have no valid bitmap on disk; theirs was derived from the \
             superblock and the group descriptors (backup superblock and descriptor blocks, \
             and the bitmaps and inode tables the descriptors name), not read from disk"
        );
    }
    // The same reading turned into free regions the carver reads (§5.4).
    //
    // ext4 keeps one block bitmap per group, so the bits are stitched from
    // every group through `GroupBitmaps::state` — which, unlike `is_allocated` above,
    // has a third answer. A block a truncated group bitmap cannot reach is
    // synthesised as **in use**, so no region covers it: it is excluded rather
    // than carved, and counted here so the record can say how many. The blocks
    // of a BLOCK_UNINIT group (whose bitmap was not read) are excluded the same
    // way.
    let mut bits = vec![0u8; (total_blocks as usize).div_ceil(8)];
    let mut unassessed_blocks = 0u64;
    for block in 0..total_blocks {
        let set = match bitmaps.state(block) {
            BlockState::Free => false,
            BlockState::InUse => true,
            BlockState::Unassessed => {
                unassessed_blocks += 1;
                true
            }
        };
        if set {
            bits[(block / 8) as usize] |= 1u8 << (block % 8);
        }
    }
    let parent = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata);
    let bitmap_view = AllocationBitmap {
        bits: &bits,
        total_clusters: total_blocks,
        cluster_size: block_size,
        // Bit 0 of the synthesised map is block 0, which is byte 0 of the
        // volume: unlike exFAT and FAT, ext4 numbers from the volume's start
        // and the boot area is part of it.
        first_cluster: 0,
        first_cluster_offset: 0,
        bit_meaning: BitMeaning::SetIsAllocated,
    };
    let (free_regions, free_outcome) = emit_free_regions(
        &parent,
        source_arc,
        &bitmap_view,
        FreeSpaceLabels {
            filesystem: "ext4",
            offset_basis: "the start of this volume, not the start of the evidence",
        },
    );
    let mut metadata = parent.metadata.clone();
    if let (Some(map), Some(fields)) =
        (metadata.as_object_mut(), free_outcome.to_json().as_object())
    {
        for (key, value) in fields {
            map.insert(key.clone(), value.clone());
        }
    }
    if unassessed_blocks > 0 {
        metadata["free_space_blocks_short_group_bitmaps"] = json!(unassessed_blocks);
        metadata["free_space_short_group_bitmaps_detail"] = json!(format!(
            "{unassessed_blocks} block(s) fall in a group bitmap that was read short, or in a \
             BLOCK_UNINIT group whose on-disk bitmap is not valid ({uninit_groups} such group(s)). \
             They are NOT free space and no region covers them -- a zero bit means free, so \
             treating an unread byte as one would carve blocks nobody assessed"
        ));
        metadata["free_space_complete"] = json!(false);
    }
    Some((
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id),
        free_regions
            .into_iter()
            .map(|region| region.with_parent(parent_id))
            .collect(),
    ))
}

/// A volume-level status record: something the volume declares or needs that
/// this parser could not do, stated so its absence from the listing is never
/// read as "nothing there". `extra` is merged into the record.
fn volume_status_record(
    fs: &Artifact,
    kind: &str,
    detail: &str,
    extra: serde_json::Value,
) -> Artifact {
    let mut metadata = json!({
        "type": kind,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "content_incomplete_detail": detail,
    });
    if let (Some(map), Some(fields)) = (metadata.as_object_mut(), extra.as_object()) {
        for (key, value) in fields {
            map.insert(key.clone(), value.clone());
        }
    }
    Artifact::new(fs.case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(fs.id)
}

// --- Data Structures ---

#[derive(Debug)]
struct Superblock {
    inodes_count: u32,
    blocks_count: u64,
    block_size: u32,
    inode_size: u16,
    inodes_per_group: u32,
    blocks_per_group: u32,
    first_data_block: u32,
    desc_size: u16, // Size of group descriptors (default 32, 64 for 64-bit)
    compat_features: u32,
    incompat_features: u32,
    ro_compat_features: u32,
    /// s_journal_inum: inode holding the internal JBD2 journal (0 if unset;
    /// the on-disk default is inode 8).
    journal_inum: u32,
    /// s_first_meta_bg: with META_BG, meta-groups below this index keep their
    /// descriptors in the classic contiguous GDT.
    first_meta_bg: u32,
    /// s_reserved_gdt_blocks (offset 0xCE): GDT blocks reserved for online
    /// growth, which follow the descriptors in every backup group.
    reserved_gdt_blocks: u16,
    /// log2(blocks per cluster) on a bigalloc volume, 0 otherwise: each bit of
    /// a block bitmap covers `1 << cluster_bits` blocks. `None` on a bigalloc
    /// volume whose cluster fields disagree with its block fields, so the
    /// bitmaps cannot be indexed.
    cluster_bits: Option<u32>,
}

impl Superblock {
    fn parse(source: &dyn DataSource) -> Result<Self> {
        let mut buf = vec![0u8; 1024];
        // Superblock is always at offset 1024. Fail closed on a short read: the
        // buffer is pre-zeroed, so a truncated image would still pass the magic
        // check while block size, inode size, desc_size and the 64-bit high
        // fields came back as fabricated zeros — mis-sizing the whole
        // filesystem and mislocating every inode table (BUG-243).
        read_exact_or_fail(source, 1024, &mut buf, "ext4 superblock")?;
        let mut cursor = Cursor::new(&buf);

        let inodes_count = cursor.read_u32::<LittleEndian>()?;
        let blocks_count_lo = cursor.read_u32::<LittleEndian>()?;
        let _r_blocks_count_lo = cursor.read_u32::<LittleEndian>()?;
        let _free_blocks_count_lo = cursor.read_u32::<LittleEndian>()?;
        let _free_inodes_count = cursor.read_u32::<LittleEndian>()?;
        let first_data_block = cursor.read_u32::<LittleEndian>()?;
        let log_block_size = cursor.read_u32::<LittleEndian>()?;
        let log_cluster_size = cursor.read_u32::<LittleEndian>()?;
        let blocks_per_group = cursor.read_u32::<LittleEndian>()?;
        let clusters_per_group = cursor.read_u32::<LittleEndian>()?;
        let inodes_per_group = cursor.read_u32::<LittleEndian>()?;
        let _mtime = cursor.read_u32::<LittleEndian>()?;
        let _wtime = cursor.read_u32::<LittleEndian>()?;
        let _mnt_count = cursor.read_u16::<LittleEndian>()?;
        let _max_mnt_count = cursor.read_u16::<LittleEndian>()?;
        let magic = cursor.read_u16::<LittleEndian>()?;

        if magic != 0xEF53 {
            return Err(anyhow!("Invalid Ext4 magic number: {:04X}", magic));
        }

        // s_rev_level (offset 76). Revision 0 (GOOD_OLD_REV) has no
        // s_inode_size field: its inodes are always 128 bytes.
        let rev_level = LittleEndian::read_u32(&buf[76..80]);
        cursor.seek(SeekFrom::Start(88))?;
        let inode_size_field = cursor.read_u16::<LittleEndian>()?;

        cursor.seek(SeekFrom::Start(92))?;
        let compat_features = cursor.read_u32::<LittleEndian>()?;
        let incompat_features = cursor.read_u32::<LittleEndian>()?;
        let ro_compat_features = cursor.read_u32::<LittleEndian>()?;

        // s_journal_inum at offset 224 (0xE0); buf is 1024 bytes so the read is
        // always in-bounds.
        cursor.seek(SeekFrom::Start(224))?;
        let journal_inum = cursor.read_u32::<LittleEndian>()?;
        let first_meta_bg = LittleEndian::read_u32(&buf[0x104..0x108]);
        let reserved_gdt_blocks = LittleEndian::read_u16(&buf[0xCE..0xD0]);

        // Check for 64-bit feature (0x80)
        let is_64bit = (incompat_features & 0x80) != 0;

        let mut blocks_count = blocks_count_lo as u64;
        let mut desc_size = 32;

        if is_64bit {
            cursor.seek(SeekFrom::Start(254))?;
            desc_size = cursor.read_u16::<LittleEndian>()?;

            cursor.seek(SeekFrom::Start(336))?; // s_blocks_count_hi
            let blocks_count_hi = cursor.read_u32::<LittleEndian>()?;
            blocks_count = (blocks_count_lo as u64) | ((blocks_count_hi as u64) << 32);
        }

        // log_block_size is an unvalidated superblock field; ext4 only defines
        // 0..=6 (1 KiB..64 KiB). A larger value overflows the shift (panic in
        // debug, a wrapped bogus block size in release) so reject it outright.
        if log_block_size > 6 {
            return Err(anyhow!(
                "Invalid ext4 log_block_size: {} (must be 0..=6)",
                log_block_size
            ));
        }
        let block_size = 1024u32 << log_block_size;

        // inode_size is an attacker-controlled divisor-like field: the kernel
        // accepts only a power of two from 128 up to the block size. Refuse
        // anything else with a stated reason rather than fail every inode read.
        let inode_size = if rev_level == 0 {
            128
        } else if inode_size_field < 128
            || !inode_size_field.is_power_of_two()
            || inode_size_field as u32 > block_size
        {
            return Err(anyhow!(
                "ext4 superblock has invalid inode_size {} (must be a power of two from 128 to the block size)",
                inode_size_field
            ));
        } else {
            inode_size_field
        };

        // Bigalloc: s_blocks_per_group stays in blocks and the bitmaps hold one
        // bit per cluster, `1 << (log_cluster_size - log_block_size)` blocks.
        // The cluster fields are believed only when they agree with the block
        // fields; otherwise the bitmaps are not indexed at all.
        let cluster_bits = if ro_compat_features & EXT4_RO_COMPAT_BIGALLOC == 0 {
            Some(0)
        } else {
            log_cluster_size
                .checked_sub(log_block_size)
                .filter(|bits| *bits <= 16)
                .filter(|bits| {
                    clusters_per_group != 0
                        && (blocks_per_group as u64) == (clusters_per_group as u64) << bits
                })
        };

        Ok(Superblock {
            inodes_count,
            blocks_count,
            block_size,
            inode_size,
            inodes_per_group,
            blocks_per_group,
            first_data_block,
            desc_size,
            compat_features,
            incompat_features,
            ro_compat_features,
            journal_inum,
            first_meta_bg,
            reserved_gdt_blocks,
            cluster_bits,
        })
    }

    /// Bigalloc: block-bitmap bits are clusters, not blocks.
    fn is_bigalloc(&self) -> bool {
        self.ro_compat_features & EXT4_RO_COMPAT_BIGALLOC != 0
    }

    /// Group-descriptor flags (BLOCK_UNINIT, ...) are only valid on volumes with
    /// `uninit_bg` (GDT_CSUM) or `metadata_csum`.
    fn honours_group_flags(&self) -> bool {
        self.ro_compat_features & (EXT4_RO_COMPAT_GDT_CSUM | EXT4_RO_COMPAT_METADATA_CSUM) != 0
    }

    fn has_superblock(&self, group: u64) -> bool {
        // SPARSE_SUPER is 0x1 in ro_compat
        if (self.ro_compat_features & 0x1) == 0 {
            return true; // All groups have SB if sparse_super is not set
        }

        if group == 0 || group == 1 {
            return true;
        }

        let mut g = group;
        while g > 1 {
            if g.is_multiple_of(3) {
                g /= 3;
                continue;
            }
            if g.is_multiple_of(5) {
                g /= 5;
                continue;
            }
            if g.is_multiple_of(7) {
                g /= 7;
                continue;
            }
            return false;
        }
        true
    }
}

#[derive(Debug)]
struct BlockGroupDescriptor {
    block_bitmap_lo: u32,
    block_bitmap_hi: u32,
    inode_bitmap_lo: u32,
    inode_bitmap_hi: u32,
    inode_table_lo: u32,
    inode_table_hi: u32,
    flags: u16,
}

impl BlockGroupDescriptor {
    /// Decode one group descriptor from `buf` (at least `desc_size` bytes).
    fn decode(buf: &[u8], desc_size: u16) -> Result<Self> {
        let mut cursor = Cursor::new(buf);

        let block_bitmap_lo = cursor.read_u32::<LittleEndian>()?;
        let inode_bitmap_lo = cursor.read_u32::<LittleEndian>()?;
        let inode_table_lo = cursor.read_u32::<LittleEndian>()?;
        let _free_blocks = cursor.read_u16::<LittleEndian>()?;
        let _free_inodes = cursor.read_u16::<LittleEndian>()?;
        let _used_dirs = cursor.read_u16::<LittleEndian>()?;
        let flags = cursor.read_u16::<LittleEndian>()?;

        let mut block_bitmap_hi = 0;
        let mut inode_bitmap_hi = 0;
        let mut inode_table_hi = 0;
        if desc_size >= 64 {
            cursor.seek(SeekFrom::Start(0x20))?;
            block_bitmap_hi = cursor.read_u32::<LittleEndian>()?;
            inode_bitmap_hi = cursor.read_u32::<LittleEndian>()?;
            cursor.seek(SeekFrom::Start(0x28))?;
            inode_table_hi = cursor.read_u32::<LittleEndian>()?;
        }

        Ok(BlockGroupDescriptor {
            block_bitmap_lo,
            block_bitmap_hi,
            inode_bitmap_lo,
            inode_bitmap_hi,
            inode_table_lo,
            inode_table_hi,
            flags,
        })
    }

    fn parse_table(source: &dyn DataSource, sb: &Superblock) -> Result<Vec<Self>> {
        // blocks_per_group comes from the superblock (attacker-controlled) and is
        // a divisor; zero is malformed and would divide-by-zero.
        if sb.blocks_per_group == 0 {
            return Err(anyhow::anyhow!("ext4 superblock has blocks_per_group = 0"));
        }
        let num_groups = sb.blocks_count.div_ceil(sb.blocks_per_group as u64);
        // blocks_count is attacker-controlled, so num_groups can be billions and
        // accumulate descriptors until OOM. A filesystem cannot have more block
        // groups than it has blocks that physically fit in the image; cap to that
        // (plus an absolute ceiling) so a crafted superblock can't exhaust memory.
        let max_groups = source
            .size()
            .div_ceil((sb.block_size.max(1) as u64) * sb.blocks_per_group as u64)
            .saturating_add(1)
            .min(1 << 22);
        let num_groups = num_groups.min(max_groups);
        let mut groups = Vec::new();

        let use_meta_bg = (sb.incompat_features & EXT4_INCOMPAT_META_BG) != 0;
        // META_BG: a descriptor block holds `desc_per_block` descriptors, and
        // meta-groups from `first_meta_bg` up keep theirs at the head of their
        // own group range instead of in the classic GDT.
        let desc_per_block = if use_meta_bg {
            // desc_size is an attacker-controlled superblock field used as a
            // divisor; zero or larger-than-a-block yields desc_per_block == 0
            // and a later divide-by-zero.
            if sb.desc_size == 0 || (sb.block_size as u64) < sb.desc_size as u64 {
                return Err(anyhow::anyhow!(
                    "ext4 superblock has invalid desc_size {}",
                    sb.desc_size
                ));
            }
            sb.block_size as u64 / sb.desc_size as u64
        } else {
            0
        };

        // Classic contiguous GDT: right after the superblock's block.
        let table_start_block = if sb.block_size == 1024 { 2 } else { 1 };
        let table_offset = (table_start_block as u64).saturating_mul(sb.block_size as u64);
        let mut legacy_buf = vec![0u8; sb.desc_size as usize];
        let mut meta_buf = vec![0u8; sb.block_size as usize];
        let mut current_block_num = u64::MAX;

        for i in 0..num_groups {
            let meta_group = if use_meta_bg { i / desc_per_block } else { 0 };
            let legacy = !use_meta_bg || meta_group < sb.first_meta_bg as u64;
            if legacy {
                let offset = table_offset.saturating_add(i.saturating_mul(sb.desc_size as u64));
                // Fail closed: `legacy_buf` is reused, so a short read would
                // re-present the previous descriptor as this group's (BUG-243).
                read_exact_or_fail(source, offset, &mut legacy_buf, "ext4 group descriptor")?;
                groups.push(Self::decode(&legacy_buf, sb.desc_size)?);
                continue;
            }

            let index_in_block = (i % desc_per_block) as usize;
            // The GDT block is the first block of the meta-group (plus SB offset)
            let first_group_in_meta = meta_group * desc_per_block;
            let start_block_of_meta =
                sb.first_data_block as u64 + (first_group_in_meta * sb.blocks_per_group as u64);

            let mut gdt_block = start_block_of_meta;
            if sb.has_superblock(first_group_in_meta) {
                gdt_block += 1; // Skip SB
            }

            // Optimization: Only read block if it changed
            if gdt_block != current_block_num {
                let offset = gdt_block.saturating_mul(sb.block_size as u64);
                // Fail closed: `meta_buf` is reused across iterations, so a short
                // read leaves the PREVIOUS meta-group's descriptors in place
                // and silently duplicates them onto this group — bitmaps and
                // inode tables located from the wrong block (BUG-243).
                read_exact_or_fail(source, offset, &mut meta_buf, "ext4 GDT block")?;
                current_block_num = gdt_block;
            }

            let desc_offset = index_in_block * sb.desc_size as usize;
            groups.push(Self::decode(&meta_buf[desc_offset..], sb.desc_size)?);
        }

        Ok(groups)
    }

    /// EXT4_BG_BLOCK_UNINIT: the on-disk block bitmap is not valid.
    fn block_uninit(&self) -> bool {
        self.flags & EXT4_BG_BLOCK_UNINIT != 0
    }

    fn get_inode_table_block(&self) -> u64 {
        (self.inode_table_lo as u64) | ((self.inode_table_hi as u64) << 32)
    }

    fn get_inode_bitmap_block(&self) -> u64 {
        (self.inode_bitmap_lo as u64) | ((self.inode_bitmap_hi as u64) << 32)
    }

    fn get_block_bitmap_block(&self) -> u64 {
        (self.block_bitmap_lo as u64) | ((self.block_bitmap_hi as u64) << 32)
    }
}

#[derive(Debug)]
struct Inode {
    mode: u16,
    uid: u16,
    size_lo: u32,
    atime: u32,
    ctime: u32,
    mtime: u32,
    dtime: u32,
    gid: u16,
    links_count: u16,
    /// i_blocks (lo): kept as the on-disk layout record; nothing reads it.
    #[allow(dead_code)]
    blocks_lo: u32,
    flags: u32,
    block: [u8; 60], // i_block array (extents or direct blocks)
    // ... extra fields
    size_hi: u32,
    // Extended fields past the 128-byte base inode. None when the inode is
    // 128 bytes or i_extra_isize does not cover the field.
    atime_extra: Option<u32>,
    ctime_extra: Option<u32>,
    mtime_extra: Option<u32>,
    crtime: Option<(u32, u32)>, // (i_crtime, i_crtime_extra)
    /// i_extra_isize: bytes of the extended inode area in use past the 128-byte
    /// base. In-inode xattrs (if any) begin at 128 + i_extra_isize.
    i_extra_isize: u16,
    /// i_file_acl (lo | hi<<32): block holding this inode's external xattrs,
    /// or 0 when there is no xattr block.
    file_acl: u64,
    /// The raw inode bytes (inode_size long), retained so in-inode xattrs can be
    /// parsed from the extended area without re-reading.
    raw: Vec<u8>,
}

/// Decode an ext4 timestamp pair (i_xtime, i_xtime_extra).
///
/// The base field is signed 32-bit seconds. The low 2 bits of `extra` extend
/// the epoch by multiples of 2^32 seconds (post-2038 support) and the upper
/// 30 bits carry nanoseconds.
fn decode_extra_time(secs: u32, extra: u32) -> (i64, u32) {
    let epoch_bits = (extra & 0x3) as i64;
    ((secs as i32 as i64) + (epoch_bits << 32), extra >> 2)
}

impl Inode {
    fn parse(
        source: &dyn DataSource,
        sb: &Superblock,
        groups: &[BlockGroupDescriptor],
        inode_num: u32,
    ) -> Result<Self> {
        if inode_num < 1 {
            return Err(anyhow!("Invalid inode number: {}", inode_num));
        }

        // inodes_per_group is an attacker-controlled superblock divisor.
        if sb.inodes_per_group == 0 {
            return Err(anyhow!("ext4 superblock has inodes_per_group = 0"));
        }
        let group_idx = (inode_num - 1) / sb.inodes_per_group;
        let index_in_group = (inode_num - 1) % sb.inodes_per_group;

        if group_idx as usize >= groups.len() {
            return Err(anyhow!(
                "Inode {} out of range (group {})",
                inode_num,
                group_idx
            ));
        }

        let group = &groups[group_idx as usize];
        let inode_table_block = group.get_inode_table_block();
        // Byte offsets derive from attacker-controlled block/inode fields;
        // saturate rather than overflow (the read is bounded by the source).
        let inode_table_offset = inode_table_block.saturating_mul(sb.block_size as u64);
        let inode_offset = inode_table_offset
            .saturating_add((index_in_group as u64).saturating_mul(sb.inode_size as u64));

        debug!(
            "Inode {}: Group {}, Index {}, Table Block {}, Offset {}",
            inode_num, group_idx, index_in_group, inode_table_block, inode_offset
        );

        let mut buf = vec![0u8; sb.inode_size as usize];
        // Gather the whole inode before judging it short: one `read_at` handing
        // back fewer bytes than asked for is ordinary on a windowed or
        // container-backed image, and rejecting the inode on that basis would
        // drop a perfectly readable file from the inventory.
        let bytes_read = read_full(source, inode_offset, &mut buf);

        if bytes_read < sb.inode_size as usize {
            // Fail closed: a short read leaves the inode's tail zero-filled and
            // the parser below would decode those fabricated zeros as real
            // (empty) size/extent fields. Match the fail-closed policy HFS+/ISO
            // already use instead of emitting plausible-but-wrong metadata
            // (BUG-155).
            return Err(anyhow!(
                "Inode {}: short read ({} of {} bytes) at offset {}; refusing to parse zero-padded inode",
                inode_num,
                bytes_read,
                sb.inode_size,
                inode_offset
            ));
        }

        // An all-zero inode is unallocated (or its table block is unwritten).
        if buf.iter().all(|&b| b == 0) {
            warn!(
                "Inode {} raw data is all zeros at offset {} (potential issue)",
                inode_num, inode_offset
            );
        }
        let mut cursor = Cursor::new(&buf);

        let mode = cursor.read_u16::<LittleEndian>()?;
        let uid = cursor.read_u16::<LittleEndian>()?;
        let size_lo = cursor.read_u32::<LittleEndian>()?;
        let atime = cursor.read_u32::<LittleEndian>()?;
        let ctime = cursor.read_u32::<LittleEndian>()?;
        let mtime = cursor.read_u32::<LittleEndian>()?;
        let dtime = cursor.read_u32::<LittleEndian>()?;
        let gid = cursor.read_u16::<LittleEndian>()?;
        let links_count = cursor.read_u16::<LittleEndian>()?;
        let blocks_lo = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;
        let _osd1 = cursor.read_u32::<LittleEndian>()?;

        let mut block = [0u8; 60];
        cursor.read_exact(&mut block)?;

        let _generation = cursor.read_u32::<LittleEndian>()?;
        let file_acl_lo = cursor.read_u32::<LittleEndian>()?;
        let size_hi = cursor.read_u32::<LittleEndian>()?;

        // i_file_acl_hi lives in the Linux osd2 area (l_i_file_acl_high at
        // offset 118); combine with the low half for the xattr block number.
        let file_acl_hi = if buf.len() >= 120 {
            LittleEndian::read_u16(&buf[118..120]) as u32
        } else {
            0
        };
        let file_acl = (file_acl_lo as u64) | ((file_acl_hi as u64) << 32);

        // i_extra_isize (offset 128) marks where the extended area ends and any
        // in-inode xattrs begin. Zero for 128-byte inodes.
        let i_extra_isize = if sb.inode_size > 128 && buf.len() >= 130 {
            LittleEndian::read_u16(&buf[128..130])
        } else {
            0
        };

        // Extended timestamp fields (inode size > 128, gated by i_extra_isize):
        // 128 i_extra_isize, 132 i_ctime_extra, 136 i_mtime_extra,
        // 140 i_atime_extra, 144 i_crtime, 148 i_crtime_extra
        let mut atime_extra = None;
        let mut ctime_extra = None;
        let mut mtime_extra = None;
        let mut crtime = None;
        if sb.inode_size > 128 && buf.len() >= 130 {
            let extra_end = (128 + LittleEndian::read_u16(&buf[128..130]) as usize).min(buf.len());
            if extra_end >= 136 {
                ctime_extra = Some(LittleEndian::read_u32(&buf[132..136]));
            }
            if extra_end >= 140 {
                mtime_extra = Some(LittleEndian::read_u32(&buf[136..140]));
            }
            if extra_end >= 144 {
                atime_extra = Some(LittleEndian::read_u32(&buf[140..144]));
            }
            if extra_end >= 148 {
                let crtime_secs = LittleEndian::read_u32(&buf[144..148]);
                let crtime_ex = if extra_end >= 152 {
                    LittleEndian::read_u32(&buf[148..152])
                } else {
                    0
                };
                crtime = Some((crtime_secs, crtime_ex));
            }
        }

        Ok(Inode {
            mode,
            uid,
            size_lo,
            atime,
            ctime,
            mtime,
            dtime,
            gid,
            links_count,
            blocks_lo,
            flags,
            block,
            size_hi,
            atime_extra,
            ctime_extra,
            mtime_extra,
            crtime,
            i_extra_isize,
            file_acl,
            raw: buf,
        })
    }

    fn atime_ts(&self) -> (i64, u32) {
        decode_extra_time(self.atime, self.atime_extra.unwrap_or(0))
    }

    /// ext4 ctime is the inode *change* time, not creation time.
    fn ctime_ts(&self) -> (i64, u32) {
        decode_extra_time(self.ctime, self.ctime_extra.unwrap_or(0))
    }

    fn mtime_ts(&self) -> (i64, u32) {
        decode_extra_time(self.mtime, self.mtime_extra.unwrap_or(0))
    }

    /// Real creation time (i_crtime), only present on filesystems whose
    /// inodes carry the extended fields. None when absent or unset.
    fn crtime_ts(&self) -> Option<(i64, u32)> {
        self.crtime.and_then(|(secs, extra)| {
            if secs == 0 && extra == 0 {
                None
            } else {
                Some(decode_extra_time(secs, extra))
            }
        })
    }

    fn is_dir(&self) -> bool {
        (self.mode & 0xF000) == 0x4000
    }

    fn is_file(&self) -> bool {
        (self.mode & 0xF000) == 0x8000
    }

    /// fscrypt-encrypted (EXT4_ENCRYPT_FL): the extent/block pointers we serve
    /// and hash reference ciphertext we do not decrypt, so the content is opaque.
    fn is_encrypted(&self) -> bool {
        (self.flags & EXT4_ENCRYPT_FL) != 0
    }

    fn size(&self) -> u64 {
        (self.size_lo as u64) | ((self.size_hi as u64) << 32)
    }

    fn uses_extents(&self) -> bool {
        (self.flags & 0x80000) != 0
    }

    /// Inline data (EXT4_INLINE_DATA_FL): `i_block` holds content bytes, not
    /// extents or block pointers.
    fn has_inline_data(&self) -> bool {
        (self.flags & EXT4_INLINE_DATA_FL) != 0
    }

    /// Collect this inode's extended attributes from both locations: the
    /// in-inode area (past `128 + i_extra_isize`) and the dedicated block
    /// referenced by `i_file_acl`. Returns (full name, raw value) pairs. Every
    /// offset and length is bounds-checked against the inode/block; malformed
    /// values yield fewer pairs rather than a panic.
    fn collect_xattrs(&self, source: &dyn DataSource, sb: &Superblock) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();

        // In-inode xattrs: ext4_xattr_ibody_header { __le32 h_magic } sits at
        // 128 + i_extra_isize, entries begin right after it (IFIRST) and value
        // offsets are measured from IFIRST.
        if sb.inode_size > 128 {
            let hdr = 128usize.saturating_add(self.i_extra_isize as usize);
            let end = (sb.inode_size as usize).min(self.raw.len());
            if hdr.saturating_add(4) <= end
                && LittleEndian::read_u32(&self.raw[hdr..hdr + 4]) == EXT4_XATTR_MAGIC
            {
                let ifirst = hdr + 4;
                parse_xattr_entries(&self.raw, ifirst, ifirst, end, &mut out);
            }
        }

        // Block xattrs: an ext4_xattr_header (32 bytes) at the start of the
        // i_file_acl block; entries follow and value offsets are measured from
        // the start of the block.
        if self.file_acl != 0 {
            let block_size = sb.block_size as usize;
            let offset = self.file_acl.saturating_mul(sb.block_size as u64);
            let mut buf = vec![0u8; block_size];
            // Value offsets in an xattr block are measured from the start of the
            // block, so a partial read silently drops attributes that live in the
            // tail. Gather the block before parsing it.
            let n = read_full(source, offset, &mut buf);
            if n >= 32 && LittleEndian::read_u32(&buf[0..4]) == EXT4_XATTR_MAGIC {
                parse_xattr_entries(&buf[..n], 32, 0, n, &mut out);
            }
        }

        out
    }
}

/// ext4 extended-attribute header magic (`h_magic`), stored little-endian in
/// both the in-inode ibody header and the dedicated xattr block.
const EXT4_XATTR_MAGIC: u32 = 0xEA02_0000;

/// Map an `e_name_index` to its standard attribute-name prefix. The full
/// attribute name is this prefix followed by the entry's stored name.
fn xattr_prefix(index: u8) -> Option<&'static str> {
    match index {
        1 => Some("user."),
        2 => Some("system.posix_acl_access"),
        3 => Some("system.posix_acl_default"),
        4 => Some("trusted."),
        6 => Some("security."),
        7 => Some("system."),
        8 => Some("system.richacl"),
        _ => None,
    }
}

/// Walk a NUL-terminated list of `ext4_xattr_entry` records inside `region`.
///
/// * `entries_start` -- byte offset in `region` where the first entry begins.
/// * `value_base` -- byte offset that each `e_value_offs` is measured from
///   (0 for block xattrs, IFIRST for in-inode xattrs).
/// * `region_end` -- exclusive upper bound for all reads.
///
/// Each entry is `16 + name_len` bytes rounded up to 4. The list ends at the
/// first entry whose leading 4 bytes are zero. Out-of-bounds names/values are
/// skipped rather than trusted; a per-call cap prevents pathological loops.
fn parse_xattr_entries(
    region: &[u8],
    entries_start: usize,
    value_base: usize,
    region_end: usize,
    out: &mut Vec<(String, Vec<u8>)>,
) {
    let end = region_end.min(region.len());
    let mut pos = entries_start;
    // A well-formed xattr area holds far fewer entries than this; the cap only
    // guards against a crafted region that never reaches the terminator.
    for _ in 0..4096 {
        // Need 4 bytes to test the terminator.
        if pos.saturating_add(4) > end {
            break;
        }
        if region[pos] == 0 && region[pos + 1] == 0 && region[pos + 2] == 0 && region[pos + 3] == 0
        {
            break; // IS_LAST_ENTRY: leading __u32 is zero
        }
        // Need the full 16-byte fixed entry header.
        if pos.saturating_add(16) > end {
            break;
        }

        let name_len = region[pos] as usize;
        let name_index = region[pos + 1];
        let value_offs = LittleEndian::read_u16(&region[pos + 2..pos + 4]) as usize;
        let value_inum = LittleEndian::read_u32(&region[pos + 4..pos + 8]);
        let value_size = LittleEndian::read_u32(&region[pos + 8..pos + 12]) as usize;

        let name_start = pos + 16;
        let name_end = match name_start.checked_add(name_len) {
            Some(e) if e <= end => e,
            _ => break, // name runs past the region: stop
        };

        let mut full = String::new();
        full.push_str(xattr_prefix(name_index).unwrap_or(""));
        full.push_str(&String::from_utf8_lossy(&region[name_start..name_end]));

        // Values stored in a separate EA inode (value_inum != 0) are not inlined
        // here; the name is still recorded with an empty value.
        let value = if value_inum != 0 || value_size == 0 {
            Vec::new()
        } else {
            match value_base
                .checked_add(value_offs)
                .and_then(|s| value_size.checked_add(s).map(|e| (s, e)))
            {
                Some((s, e)) if e <= end => region[s..e].to_vec(),
                _ => Vec::new(), // value out of bounds: skip it, keep the name
            }
        };

        out.push((full, value));

        // Advance to the next entry (4-byte aligned). name_len <= 255 so this
        // cannot overflow.
        pos += (16 + name_len).div_ceil(4) * 4;
    }
}

/// Render collected xattrs as a JSON object mapping full name to value. Values
/// that are valid UTF-8 become plain strings; binary values become a
/// `base64:<...>` string so the JSON stays lossless.
fn xattrs_to_json(pairs: &[(String, Vec<u8>)]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (name, value) in pairs {
        let v = match std::str::from_utf8(value) {
            Ok(s) => json!(s),
            Err(_) => json!(format!("base64:{}", BASE64.encode(value))),
        };
        map.insert(name.clone(), v);
    }
    serde_json::Value::Object(map)
}

// --- Ext4 File DataSource ---

/// `ee_len` values above this mark an unwritten (preallocated) extent; the real
/// length is `ee_len - 32768` and the range reads as zeros until written.
const EXT4_EXT_UNWRITTEN_MARK: u16 = 32768;

/// ext4 extent trees are at most ~5 levels deep; a larger depth is malformed
/// and traversal would otherwise recurse without bound.
const MAX_EXTENT_TREE_DEPTH: u8 = 5;

/// One extent-tree leaf entry, in blocks.
#[derive(Debug, Clone, Copy)]
struct ExtentLeaf {
    logical: u64,
    physical: u64,
    blocks: u64,
    /// Preallocated but never written: reads as zeros, not as the residual
    /// bytes sitting at `physical`.
    unwritten: bool,
}

/// Result of enumerating a file's data runs.
#[derive(Debug)]
struct CollectedRuns {
    runs: Vec<(Option<u64>, u64)>,
    /// False when a safety cap truncated the run list.
    complete: bool,
    /// True when at least one run came from an unwritten (preallocated) extent
    /// and was therefore emitted as zeros rather than as its physical blocks.
    unwritten: bool,
}

/// Where a logical block range of an extent-mapped file lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtentMap {
    /// `blocks` contiguous blocks of real on-disk data starting at
    /// `physical_block`.
    Mapped { physical_block: u64, blocks: u64 },
    /// `blocks` blocks that read as zeros: a sparse hole, or an unwritten
    /// (preallocated) extent whose residual disk bytes are not file content.
    Zeros { blocks: u64 },
}

/// Extent-tree node magic (`eh_magic`).
const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
/// Size in bytes of an extent header and of every extent / index entry.
const EXTENT_RECORD_SIZE: usize = 12;
/// Cap on distinct tree blocks one file's extent tree may read. A valid tree
/// needs one block per 340 extents, so this admits ~22M extents and still
/// bounds the work a crafted tree can demand.
const MAX_EXTENT_TREE_NODES: usize = 1 << 16;
/// Cap on extents collected from one tree.
const MAX_EXTENT_LEAVES: usize = 1 << 20;

fn extent_invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

/// Validate an extent node's header and return `(entries_count, depth)`.
/// `depth_budget` is how many more index levels the caller will descend.
fn parse_extent_header(node: &[u8], depth_budget: u8) -> std::io::Result<(u16, u16)> {
    if node.len() < EXTENT_RECORD_SIZE {
        return Err(extent_invalid("Extent node too small"));
    }
    let header_magic = LittleEndian::read_u16(&node[0..2]);
    if header_magic != EXT4_EXTENT_MAGIC {
        return Err(extent_invalid(format!(
            "Invalid extent header magic: found 0x{:04X}, expected 0x{:04X}",
            header_magic, EXT4_EXTENT_MAGIC
        )));
    }
    let entries_count = LittleEndian::read_u16(&node[2..4]);
    let depth = LittleEndian::read_u16(&node[6..8]);
    if depth > 0 && depth_budget == 0 {
        return Err(extent_invalid(format!(
            "Extent tree depth {} exceeds maximum",
            depth
        )));
    }
    Ok((entries_count, depth))
}

/// The `i`th 12-byte entry after the header, or `None` past the node's end.
fn extent_entry(node: &[u8], i: u16) -> Option<&[u8]> {
    let start = EXTENT_RECORD_SIZE + i as usize * EXTENT_RECORD_SIZE;
    node.get(start..start + EXTENT_RECORD_SIZE)
}

/// Decode a leaf entry (`ee_block`, `ee_len`, 48-bit `ee_start`). `None` for a
/// zero-length entry. `ee_len` above 32768 marks an unwritten (preallocated)
/// extent whose real length is `ee_len - 32768` and whose content is zeros.
fn decode_extent_leaf(entry: &[u8]) -> Option<ExtentLeaf> {
    let raw_len = LittleEndian::read_u16(&entry[4..6]);
    let unwritten = raw_len > EXT4_EXT_UNWRITTEN_MARK;
    let blocks = if unwritten {
        (raw_len - EXT4_EXT_UNWRITTEN_MARK) as u64
    } else {
        raw_len as u64
    };
    if blocks == 0 {
        return None;
    }
    let start_hi = LittleEndian::read_u16(&entry[6..8]) as u64;
    let start_lo = LittleEndian::read_u32(&entry[8..12]) as u64;
    Some(ExtentLeaf {
        logical: LittleEndian::read_u32(&entry[0..4]) as u64,
        physical: start_lo | (start_hi << 32),
        blocks,
        unwritten,
    })
}

/// The child block an index entry names (`ei_leaf_lo` | `ei_leaf_hi` << 32).
fn decode_index_child(entry: &[u8]) -> u64 {
    let lo = LittleEndian::read_u32(&entry[4..8]) as u64;
    let hi = LittleEndian::read_u16(&entry[8..10]) as u64;
    lo | (hi << 32)
}

#[derive(Debug)]
pub struct Ext4FileSource {
    inner: Arc<dyn DataSource>,
    block_size: u32,
    inode_blocks: [u8; 60],
    size: u64,
    uses_extents: bool,
}

impl Ext4FileSource {
    fn new(inner: Arc<dyn DataSource>, block_size: u32, inode: &Inode) -> Self {
        Self {
            inner,
            block_size,
            inode_blocks: inode.block,
            size: inode.size(),
            uses_extents: inode.uses_extents(),
        }
    }

    /// Serve an extent-mapped file by resolving one logical block range at a
    /// time. Ranges with no covering extent (sparse holes) and ranges covered
    /// by an *unwritten* extent both read as zeros — the kernel never exposes
    /// the residual on-disk bytes behind a `fallocate`d extent, so neither may
    /// we (BUG-207, BUG-211).
    fn read_extent_based(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let block_size = self.block_size as u64;
        if block_size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Zero block size",
            ));
        }
        let total_blocks = self.size.div_ceil(block_size);
        let to_read = std::cmp::min(buf.len() as u64, self.size - offset) as usize;
        let mut bytes_read = 0usize;

        while bytes_read < to_read {
            let file_offset = offset + bytes_read as u64;
            let logical_block = file_offset / block_size;
            let offset_in_block = file_offset % block_size;
            let bound = total_blocks.saturating_sub(logical_block);
            if bound == 0 {
                break;
            }

            let mapping = self.map_extent_block(
                &self.inode_blocks,
                MAX_EXTENT_TREE_DEPTH,
                logical_block,
                bound,
            )?;

            let span = match mapping {
                ExtentMap::Mapped { blocks, .. } | ExtentMap::Zeros { blocks } => blocks
                    .saturating_mul(block_size)
                    .saturating_sub(offset_in_block),
            };
            let chunk = std::cmp::min((to_read - bytes_read) as u64, span) as usize;
            if chunk == 0 {
                break;
            }

            match mapping {
                ExtentMap::Mapped { physical_block, .. } => {
                    let physical_offset = physical_block
                        .saturating_mul(block_size)
                        .saturating_add(offset_in_block);
                    let n = self
                        .inner
                        .read_at(physical_offset, &mut buf[bytes_read..bytes_read + chunk])?;
                    if n == 0 {
                        // Short read on the backing image: stop and report the
                        // honest partial length rather than padding with zeros.
                        break;
                    }
                    bytes_read += n;
                }
                ExtentMap::Zeros { .. } => {
                    buf[bytes_read..bytes_read + chunk].fill(0);
                    bytes_read += chunk;
                }
            }
        }

        Ok(bytes_read)
    }

    /// Map one logical block of an extent-mapped file.
    ///
    /// `bound` is the number of logical blocks, starting at `logical_block`,
    /// that `node` is responsible for; a hole is never reported past it so a
    /// subtree can never fabricate zeros over a sibling's range.
    fn map_extent_block(
        &self,
        node: &[u8],
        depth_budget: u8,
        logical_block: u64,
        bound: u64,
    ) -> std::io::Result<ExtentMap> {
        let (entries_count, depth) = parse_extent_header(node, depth_budget)?;

        if depth == 0 {
            // Leaf: find the extent covering this logical block.
            let mut next_start: Option<u64> = None;
            for i in 0..entries_count {
                let Some(entry) = extent_entry(node, i) else {
                    break;
                };
                let Some(leaf) = decode_extent_leaf(entry) else {
                    continue;
                };
                let (ee_block, len) = (leaf.logical, leaf.blocks);

                if logical_block >= ee_block && logical_block < ee_block.saturating_add(len) {
                    let offset_in_extent = logical_block - ee_block;
                    let blocks = std::cmp::min(len - offset_in_extent, bound);
                    return Ok(if leaf.unwritten {
                        ExtentMap::Zeros { blocks }
                    } else {
                        ExtentMap::Mapped {
                            physical_block: leaf.physical.saturating_add(offset_in_extent),
                            blocks,
                        }
                    });
                }
                if ee_block > logical_block {
                    next_start = Some(match next_start {
                        Some(prev) => std::cmp::min(prev, ee_block),
                        None => ee_block,
                    });
                }
            }
            // Hole: zeros up to the next extent in this node, or to the end of
            // the range this node covers.
            let gap = next_start
                .map(|s| s - logical_block)
                .unwrap_or(bound)
                .min(bound);
            return Ok(ExtentMap::Zeros { blocks: gap });
        }

        // Index node: descend into the child whose range covers this block.
        for i in 0..entries_count {
            let Some(entry) = extent_entry(node, i) else {
                break;
            };
            let ei_block = LittleEndian::read_u32(&entry[0..4]) as u64;
            let next_ei_block = match extent_entry(node, i + 1) {
                Some(next) if i + 1 < entries_count => LittleEndian::read_u32(&next[0..4]) as u64,
                _ => u64::MAX,
            };
            if logical_block < ei_block {
                // Blocks before the first covering index entry are a hole.
                return Ok(ExtentMap::Zeros {
                    blocks: (ei_block - logical_block).min(bound),
                });
            }
            if logical_block >= next_ei_block {
                continue;
            }

            let child = self.read_extent_child(decode_index_child(entry))?;
            let child_bound = std::cmp::min(bound, next_ei_block.saturating_sub(logical_block));
            return self.map_extent_block(&child, depth_budget - 1, logical_block, child_bound);
        }

        // No index entry covers this block: hole to the end of this range.
        Ok(ExtentMap::Zeros { blocks: bound })
    }

    /// Read one extent-tree block. Fail closed: a short read leaves the tail
    /// zero, and the truncated entry list would still pass the 0xF30A magic
    /// check. The extents that were cut off then map as "no covering extent",
    /// i.e. a hole, and real content is served as zeros or persisted as sparse
    /// runs (BUG-272).
    fn read_extent_child(&self, leaf_block: u64) -> std::io::Result<Vec<u8>> {
        let mut child = vec![0u8; self.block_size as usize];
        read_exact_or_fail(
            self.inner.as_ref(),
            leaf_block.saturating_mul(self.block_size as u64),
            &mut child,
            "ext4 extent tree block",
        )?;
        Ok(child)
    }

    /// Resolve a logical block index >= 12 via indirect block chain.
    /// i_block[12] = single indirect, i_block[13] = double indirect, i_block[14] = triple indirect.
    fn resolve_indirect_block(&self, logical_block_index: u64) -> std::io::Result<u32> {
        let ptrs_per_block = self.block_size as u64 / 4; // u32 pointers per block

        let single_start = 12u64;
        let single_end = single_start + ptrs_per_block;
        let double_end = single_end + ptrs_per_block * ptrs_per_block;
        let triple_end = double_end + ptrs_per_block * ptrs_per_block * ptrs_per_block;

        if logical_block_index < single_end {
            // Single indirect: i_block[12] -> block of pointers
            let indirect_block = LittleEndian::read_u32(&self.inode_blocks[48..52]);
            if indirect_block == 0 {
                return Ok(0); // sparse
            }
            let index = logical_block_index - single_start;
            self.read_block_pointer(indirect_block, index)
        } else if logical_block_index < double_end {
            // Double indirect: i_block[13] -> block of indirect block ptrs -> block of ptrs
            let dind_block = LittleEndian::read_u32(&self.inode_blocks[52..56]);
            if dind_block == 0 {
                return Ok(0);
            }
            let adjusted = logical_block_index - single_end;
            let l1_index = adjusted / ptrs_per_block;
            let l2_index = adjusted % ptrs_per_block;

            let ind_block = self.read_block_pointer(dind_block, l1_index)?;
            if ind_block == 0 {
                return Ok(0);
            }
            self.read_block_pointer(ind_block, l2_index)
        } else if logical_block_index < triple_end {
            // Triple indirect: i_block[14] -> block of dind ptrs -> block of ind ptrs -> block of ptrs
            let tind_block = LittleEndian::read_u32(&self.inode_blocks[56..60]);
            if tind_block == 0 {
                return Ok(0);
            }
            let adjusted = logical_block_index - double_end;
            let l1_index = adjusted / (ptrs_per_block * ptrs_per_block);
            let l2_index = (adjusted / ptrs_per_block) % ptrs_per_block;
            let l3_index = adjusted % ptrs_per_block;

            let dind_block = self.read_block_pointer(tind_block, l1_index)?;
            if dind_block == 0 {
                return Ok(0);
            }
            let ind_block = self.read_block_pointer(dind_block, l2_index)?;
            if ind_block == 0 {
                return Ok(0);
            }
            self.read_block_pointer(ind_block, l3_index)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Logical block index {} exceeds triple indirect range",
                    logical_block_index
                ),
            ))
        }
    }

    /// Read a u32 block pointer from a given block at the specified index.
    fn read_block_pointer(&self, block_num: u32, index: u64) -> std::io::Result<u32> {
        // Indirect block pointers come straight from the image. A wrapping
        // multiply lands on a low device offset, so the pointer read back
        // belongs to unrelated data and the file is assembled from the WRONG
        // image bytes (B5-006). Sibling paths in this crate already saturate.
        let offset = (block_num as u64)
            .saturating_mul(self.block_size as u64)
            .saturating_add(index.saturating_mul(4));
        let mut buf = [0u8; 4];
        // Looped: one `read_at` handing back fewer than four bytes is ordinary
        // on a windowed or container-backed image, and erroring on it would make
        // every indirect-block-mapped (legacy ext2/3) file unreadable.
        if read_full(self.inner.as_ref(), offset, &mut buf) < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Short read on indirect block pointer",
            ));
        }
        Ok(LittleEndian::read_u32(&buf))
    }

    /// Read from a legacy (direct/indirect block-mapped) inode.
    ///
    /// Every cursor advances by the number of bytes the backing image actually
    /// delivered, never by the number requested. `read_at` may legitimately
    /// return short; advancing by the full request would leave the shortfall as
    /// pre-existing buffer bytes AND place every later block at the wrong
    /// offset in the returned buffer. An examiner would then see a file whose
    /// bytes are not merely truncated but shifted — and it still hashes, so the
    /// corruption is invisible. The extent-mapped path already behaves this way
    /// (BUG-207); this is the same contract for the legacy path.
    fn read_block_mapped(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = 0;
        let mut current_offset = offset;
        let mut buf_offset = 0;
        let remaining_len = std::cmp::min(buf.len() as u64, self.size - offset);
        let mut remaining_to_read = remaining_len;

        while remaining_to_read > 0 {
            let logical_block_index = current_offset / self.block_size as u64;
            let offset_in_block = current_offset % self.block_size as u64;
            let to_read =
                std::cmp::min(remaining_to_read, self.block_size as u64 - offset_in_block);

            let physical_block = if logical_block_index < 12 {
                // Direct blocks: i_block[0..11]
                let block_ptr_offset = (logical_block_index as usize) * 4;
                LittleEndian::read_u32(&self.inode_blocks[block_ptr_offset..block_ptr_offset + 4])
            } else {
                self.resolve_indirect_block(logical_block_index)?
            };

            // How much of `to_read` this iteration actually produced.
            let advanced = if physical_block == 0 {
                // Sparse block: a genuine hole reads back as zeros.
                buf[buf_offset..buf_offset + to_read as usize].fill(0);
                to_read
            } else {
                debug!(
                    "Mapped logical block {} to physical block {}",
                    logical_block_index, physical_block
                );
                // Same contract as the pointer read above: a hostile or
                // corrupt block number must never wrap into a low, valid
                // device offset (B5-006).
                let physical_offset = (physical_block as u64)
                    .saturating_mul(self.block_size as u64)
                    .saturating_add(offset_in_block);
                let n = self.inner.read_at(
                    physical_offset,
                    &mut buf[buf_offset..buf_offset + to_read as usize],
                )?;
                if n == 0 {
                    // The image cannot deliver this block: stop and report the
                    // honest partial length rather than padding with zeros.
                    break;
                }
                n as u64
            };

            bytes_read += advanced as usize;
            buf_offset += advanced as usize;
            current_offset += advanced;
            remaining_to_read -= advanced;
        }

        Ok(bytes_read)
    }

    /// Enumerate the file's data runs as (byte offset within the filesystem
    /// window | None for sparse, byte length) pairs in logical file order.
    /// Adjacent contiguous runs are coalesced and the list is capped at
    /// MAX_METADATA_DATA_RUNS; `complete` is false when the cap truncated it and
    /// `unwritten` is true when the file carries preallocated extents that were
    /// emitted as zero runs rather than as their physical blocks (BUG-207).
    fn collect_runs(&self) -> std::io::Result<CollectedRuns> {
        let block_size = self.block_size as u64;
        let total_blocks = self.size.div_ceil(block_size);
        if total_blocks == 0 {
            return Ok(CollectedRuns {
                runs: Vec::new(),
                complete: true,
                unwritten: false,
            });
        }

        if self.uses_extents {
            let mut extents: Vec<ExtentLeaf> = Vec::new();
            self.collect_extents(
                &self.inode_blocks,
                MAX_EXTENT_TREE_DEPTH,
                &mut extents,
                &mut std::collections::HashSet::new(),
                MAX_EXTENT_LEAVES,
            )?;
            extents.sort_by_key(|e| e.logical);
            let has_unwritten = extents.iter().any(|e| e.unwritten);

            let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
            let mut expected_logical: u64 = 0;
            for leaf in extents {
                if leaf.logical > expected_logical {
                    // Hole between extents -> sparse run
                    push_run(
                        &mut runs,
                        None,
                        (leaf.logical - expected_logical).saturating_mul(block_size),
                    );
                }
                // An unwritten (preallocated) extent has physical blocks but no
                // file content: it must re-serve as zeros, never as the residual
                // bytes still on disk.
                let offset = if leaf.unwritten {
                    None
                } else {
                    Some(leaf.physical.saturating_mul(block_size))
                };
                push_run(&mut runs, offset, leaf.blocks.saturating_mul(block_size));
                expected_logical = leaf.logical.saturating_add(leaf.blocks);
            }
            if expected_logical < total_blocks {
                // Sparse tail beyond the last extent
                push_run(
                    &mut runs,
                    None,
                    (total_blocks - expected_logical).saturating_mul(block_size),
                );
            }

            let complete = runs.len() <= MAX_METADATA_DATA_RUNS;
            runs.truncate(MAX_METADATA_DATA_RUNS);
            Ok(CollectedRuns {
                runs,
                complete,
                unwritten: has_unwritten,
            })
        } else {
            // Legacy block-mapped file: walk direct/indirect pointers
            let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
            let mut complete = true;
            // total_blocks derives from the inode size (attacker-controlled);
            // coalescing can keep runs.len() below the cap indefinitely, so bound
            // the iteration itself to avoid a huge-inode hang.
            const MAX_LEGACY_BLOCKS: u64 = 1 << 20;
            let loop_blocks = total_blocks.min(MAX_LEGACY_BLOCKS);
            if total_blocks > MAX_LEGACY_BLOCKS {
                complete = false;
            }
            for logical_block in 0..loop_blocks {
                let physical_block = if logical_block < 12 {
                    let ptr_offset = (logical_block as usize) * 4;
                    LittleEndian::read_u32(&self.inode_blocks[ptr_offset..ptr_offset + 4])
                } else {
                    self.resolve_indirect_block(logical_block)?
                };
                let offset = if physical_block == 0 {
                    None // sparse block
                } else {
                    Some((physical_block as u64).saturating_mul(block_size))
                };
                push_run(&mut runs, offset, block_size);
                if runs.len() > MAX_METADATA_DATA_RUNS {
                    complete = false;
                    runs.truncate(MAX_METADATA_DATA_RUNS);
                    break;
                }
            }
            Ok(CollectedRuns {
                runs,
                complete,
                unwritten: false,
            })
        }
    }

    /// Walk the extent tree collecting leaves. Index nodes are read from disk
    /// recursively.
    ///
    /// A valid tree never names a block twice, so `visited` (every child block
    /// read so far) refuses a crafted tree whose entries share children, which
    /// would otherwise cost exponential work from a handful of real blocks; the
    /// node and `max_leaves` caps bound the rest. A tree that trips either is
    /// an error, never a partial list: a truncated extent list would be
    /// persisted as sparse runs over real content.
    fn collect_extents(
        &self,
        node: &[u8],
        depth_budget: u8,
        out: &mut Vec<ExtentLeaf>,
        visited: &mut std::collections::HashSet<u64>,
        max_leaves: usize,
    ) -> std::io::Result<()> {
        let (entries_count, depth) = parse_extent_header(node, depth_budget)?;

        for i in 0..entries_count {
            let Some(entry) = extent_entry(node, i) else {
                break;
            };
            if depth == 0 {
                if let Some(leaf) = decode_extent_leaf(entry) {
                    if out.len() >= max_leaves {
                        return Err(extent_invalid(format!(
                            "extent tree holds more than {max_leaves} extents"
                        )));
                    }
                    out.push(leaf);
                }
            } else {
                let leaf_block = decode_index_child(entry);
                if !visited.insert(leaf_block) {
                    return Err(extent_invalid(format!(
                        "extent tree names block {leaf_block} more than once"
                    )));
                }
                if visited.len() > MAX_EXTENT_TREE_NODES {
                    return Err(extent_invalid(format!(
                        "extent tree spans more than {MAX_EXTENT_TREE_NODES} blocks"
                    )));
                }
                let child = self.read_extent_child(leaf_block)?;
                self.collect_extents(&child, depth_budget - 1, out, visited, max_leaves)?;
            }
        }
        Ok(())
    }
}

/// Append a byte run, coalescing with the previous run when contiguous
/// (adjacent physical runs, or consecutive sparse runs).
fn push_run(runs: &mut Vec<(Option<u64>, u64)>, offset: Option<u64>, len: u64) {
    if len == 0 {
        return;
    }
    if let Some(last) = runs.last_mut() {
        let contiguous = match (last.0, offset) {
            (Some(last_offset), Some(offset)) => last_offset + last.1 == offset,
            (None, None) => true,
            _ => false,
        };
        if contiguous {
            last.1 += len;
            return;
        }
    }
    runs.push((offset, len));
}

impl DataSource for Ext4FileSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }

        if self.uses_extents {
            self.read_extent_based(offset, buf)
        } else {
            self.read_block_mapped(offset, buf)
        }
    }

    fn size(&self) -> u64 {
        self.size
    }
}

struct ParsingContext<'a> {
    artifact_id: uuid::Uuid,
    case_id: uuid::Uuid,
    data_source: Arc<dyn DataSource>,
    superblock: &'a Superblock,
    groups: &'a Vec<BlockGroupDescriptor>,
    produced_artifacts: &'a mut Vec<Artifact>,
    max_recursion_depth: usize,
    /// Explicit directory-recursion depth. The path-slash heuristic proved
    /// unreliable (a crafted directory tree recursed ~128 levels and overflowed
    /// the stack), so descent is bounded by this counter directly.
    depth: usize,
    /// Directory inodes already descended into. A corrupt/cyclic directory
    /// graph (A->B->C->A, or a branching cycle) would otherwise re-descend the
    /// same directories -- the depth counter stops the stack overflow but a
    /// branching cycle can still blow up exponentially; visiting each directory
    /// at most once makes it linear.
    visited_dirs: std::collections::HashSet<u32>,
    /// What the directory currently being listed failed to cover. Each
    /// directory walk takes this over (leaving the parent's) and stamps the
    /// result on its own artifact, so a gap is attributed to the directory that
    /// holds the entry, not to its ancestors.
    listing_gaps: ListingGaps,
    progress: &'a Option<ProgressReporter>,
    cancellation: &'a Option<CancellationHandle>,
    total_inodes: u64,
}

impl ParsingContext<'_> {
    /// Cooperative cancellation: has this case's work been cancelled?
    fn cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|c| c.is_cancelled(self.case_id))
    }

    /// Emit a data-less `FileEntry` (a name-only record) under the filesystem.
    fn push_file_entry(&mut self, metadata: serde_json::Value) {
        self.produced_artifacts.push(
            Artifact::new(self.case_id, ArtifactType::FileEntry, None, metadata)
                .with_parent(self.artifact_id),
        );
    }
}

/// Why one directory's listing does not cover everything it holds. Any
/// non-zero field means the listing must not read as complete.
#[derive(Debug, Default, Clone, Copy)]
struct ListingGaps {
    /// Live entries whose inode could not be resolved or whose name could not
    /// be followed; each was recorded by name only.
    unresolved_entries: usize,
    /// Live entries not walked because the recursion cap was reached.
    capped_entries: usize,
    /// Places the entry chain could not be read past (a corrupt `rec_len` or
    /// name, or a directory this parser cannot list at all, e.g. inline data).
    corrupt: usize,
    /// Live entries not walked because the case was cancelled first.
    cancelled: usize,
}

impl ListingGaps {
    /// The reason to stamp on the directory, or `None` when nothing was missed.
    fn reason(&self) -> Option<IncompleteReason> {
        if self.unresolved_entries > 0 || self.corrupt > 0 || self.cancelled > 0 {
            Some(IncompleteReason::UnresolvedStructure)
        } else if self.capped_entries > 0 {
            Some(IncompleteReason::CapReached)
        } else {
            None
        }
    }
}

/// Where a directory entry was found: in the live chain the kernel maintains,
/// or in the slack a widened `rec_len` hides. A slack entry is a deleted name
/// whatever its inode looks like now — the inode may since have been reused
/// by a live file, and then the name is stale for that inode's content.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryOrigin {
    Live,
    DirectorySlack,
}

/// What walking one inode produced. Only `Emitted` put a record in the
/// inventory: every other outcome is a name the caller must account for, never
/// a silent `Ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InodeWalk {
    /// A record for the inode was emitted (and, for a live directory, listed).
    Emitted,
    /// Cancellation was requested; the walk stopped without a record.
    Cancelled,
    /// The recursion cap stopped the walk before the inode was read.
    DepthLimit,
    /// The inode is readable but carries no file type (mode 0), so no record
    /// can honestly be built from it.
    Unallocated,
}

fn parse_inode(ctx: &mut ParsingContext, inode_num: u32, path: &str) -> Result<InodeWalk> {
    parse_inode_from(ctx, inode_num, path, EntryOrigin::Live)
}

/// Record that a file's content cannot be taken at face value. The flag is
/// always set; the reason and detail only when none is already recorded, since
/// an earlier one describes a defect in the reconstruction itself.
fn mark_content_incomplete(
    metadata: &mut serde_json::Value,
    reason: IncompleteReason,
    detail: &str,
) {
    metadata["content_incomplete"] = json!(true);
    if metadata.get("content_incomplete_reason").is_none() {
        metadata["content_incomplete_reason"] = json!(reason.as_str());
    }
    if metadata.get("content_incomplete_detail").is_none() {
        metadata["content_incomplete_detail"] = json!(detail);
    }
}

/// What an inline-data inode holds: the bytes in `i_block`, the bytes in the
/// `system.data` xattr, and how many bytes `i_size` promises beyond both.
struct InlinePayload {
    in_inode: Vec<u8>,
    in_xattr: Vec<u8>,
    shortfall: u64,
}

/// Split an inline-data inode into its two stores. A regular file keeps its
/// first `min(size, 60)` bytes in `i_block` and the rest in `system.data`; a
/// directory keeps all 60 bytes of `i_block` (a 4-byte parent word and dirents)
/// and its continuation dirents in `system.data`. Bytes the size promises and
/// neither store holds are counted in `shortfall`, never invented.
fn inline_payload(inode: &Inode, xattrs: &[(String, Vec<u8>)]) -> InlinePayload {
    let size = inode.size();
    let in_inode_len = if inode.is_dir() {
        60
    } else {
        size.min(60) as usize
    };
    let in_inode = inode.block[..in_inode_len].to_vec();
    let wanted = size.saturating_sub(60) as usize;
    let mut in_xattr = xattrs
        .iter()
        .find(|(n, _)| n == "system.data")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    in_xattr.truncate(wanted);
    let shortfall = (wanted - in_xattr.len()) as u64;
    InlinePayload {
        in_inode,
        in_xattr,
        shortfall,
    }
}

/// Persist a regular file's data runs so the API layer can serve content
/// straight from the image (metadata contract: data_runs). A file whose runs
/// cannot be enumerated is flagged, never left looking like an empty one.
fn attach_data_runs(metadata: &mut serde_json::Value, source: &Ext4FileSource, inode_num: u32) {
    match source.collect_runs() {
        Ok(collected) if !collected.runs.is_empty() => {
            let runs_json: Vec<serde_json::Value> =
                collected.runs.iter().map(|&(o, l)| json!([o, l])).collect();
            metadata["data_runs"] = json!(runs_json);
            metadata["data_runs_complete"] = json!(collected.complete);
            // Honesty flag: preallocated ranges are served as zeros, so the
            // file's hash covers zeros where fallocate reserved blocks that
            // were never written (BUG-207).
            if collected.unwritten {
                metadata["has_unwritten_extents"] = json!(true);
            }
        }
        Ok(_) => {}
        Err(e) => {
            warn!("Failed to collect data runs for inode {}: {}", inode_num, e);
            metadata["data_runs_error"] = json!(e.to_string());
            mark_content_incomplete(
                metadata,
                IncompleteReason::UnresolvedStructure,
                &format!(
                    "the file's extent or indirect-block structure could not be read ({e}); \
                     where its content lives is unknown"
                ),
            );
        }
    }
}

fn parse_inode_from(
    ctx: &mut ParsingContext,
    inode_num: u32,
    path: &str,
    origin: EntryOrigin,
) -> Result<InodeWalk> {
    // Prevent infinite recursion / cyclic directories. The explicit depth
    // counter is authoritative; the path-slash heuristic is kept as a cheap
    // secondary bound. The caller is told, so the directory that held this
    // name is not reported as complete.
    if ctx.depth > ctx.max_recursion_depth || path.matches('/').count() > ctx.max_recursion_depth {
        return Ok(InodeWalk::DepthLimit);
    }

    // Cooperative cancellation: stop descending and return what we have.
    if ctx.cancelled() {
        return Ok(InodeWalk::Cancelled);
    }

    let inode = Inode::parse(
        ctx.data_source.as_ref(),
        ctx.superblock,
        ctx.groups,
        inode_num,
    )?;

    // A cleared mode (with or without a dtime) names no file type, so no
    // record can honestly be built; the caller decides how loudly to say so.
    if inode.mode == 0 {
        return Ok(InodeWalk::Unallocated);
    }
    let inode_looks_deleted = inode.dtime != 0 || inode.links_count == 0;

    // A name found in directory slack was unlinked whatever the inode says
    // now: the kernel hid the entry, which is the deletion. An inode that
    // looks live under a slack name has been reused, and the name is stale
    // for the content it now maps — said on the record below.
    let is_deleted = inode_looks_deleted || origin == EntryOrigin::DirectorySlack;
    let name_from_slack = origin == EntryOrigin::DirectorySlack;
    let inode_reused = name_from_slack && !inode_looks_deleted;

    debug!(
        "Parsing inode {} at {} (Mode: {:o}, Size: {}, Flags: {:x}, Deleted: {})",
        inode_num,
        path,
        inode.mode,
        inode.size(),
        inode.flags,
        is_deleted
    );

    // Create artifact for this inode
    let name = std::path::Path::new(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let parent_path = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let (ctime_s, ctime_n) = inode.ctime_ts();
    let (mtime_s, mtime_n) = inode.mtime_ts();
    let (atime_s, atime_n) = inode.atime_ts();

    let mut metadata = json!({
        "name": name,
        "path": path,
        "parent_path": parent_path,
        "inode": inode_num,
        "mode": inode.mode,
        "uid": inode.uid,
        "gid": inode.gid,
        "size": inode.size(),
        // ext4 ctime is the inode *change* time, not creation time
        "changed": format_timestamp_full(ctime_s, ctime_n),
        "modified": format_timestamp_full(mtime_s, mtime_n),
        "accessed": format_timestamp_full(atime_s, atime_n),
        "is_directory": inode.is_dir(),
    });

    // Real creation time only when the inode carries i_crtime
    if let Some((crtime_s, crtime_n)) = inode.crtime_ts() {
        metadata["created"] = json!(format_timestamp_full(crtime_s, crtime_n));
    }

    if is_deleted {
        metadata["deleted"] = json!(true);
        metadata["deleted_recovery_source"] = json!(if name_from_slack {
            "directory_slack"
        } else {
            "ext4_inode"
        });
        if inode_reused {
            // The directory still remembers this name for this inode number,
            // but the inode now belongs to a live file: the content reached
            // through it is that file's, not this name's.
            metadata["inode_reused"] = json!(true);
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] = json!("unresolved_structure");
            metadata["content_incomplete_detail"] = json!(
                "this name was recovered from directory slack and its inode has since been \
                 reallocated to a live file; the bytes reachable through it belong to that \
                 file, not to this name"
            );
        }
        if inode.dtime != 0 {
            metadata["deleted_time"] = json!(format_timestamp(inode.dtime));
        }
        // The extents name where the file's blocks were. They do not establish
        // that those blocks still hold its data: ext4 frees them on unlink, and
        // a reallocated block serves another file's bytes under this name.
        //
        // `content_incomplete` is what the API, export and integrity-verify
        // paths read, so without it the digest of whatever now occupies those
        // blocks is recorded as this file's. The FAT reader marks its deleted
        // recoveries for the same reason (B2-160).
        metadata["deleted_content_caveat"] = json!("blocks_may_be_reallocated");
        if metadata.get("content_incomplete").is_none() {
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] =
                json!(IncompleteReason::UnresolvedStructure.as_str());
        }
    }

    // Extended attributes (in-inode and/or i_file_acl block). Only attached
    // when the inode actually carries any.
    let xattrs = inode.collect_xattrs(ctx.data_source.as_ref(), ctx.superblock);
    if !xattrs.is_empty() {
        metadata["xattrs"] = xattrs_to_json(&xattrs);
    }

    // Inline data keeps the content in i_block and the system.data xattr, never
    // as extents or block pointers: decoding i_block either way would serve
    // unrelated disk blocks as the file's content. It is read only on a volume
    // that declares the INLINE_DATA feature (the flag is meaningless without
    // it) and only for a live inode (a freed inode's body is not recoverable
    // content), and is refused, said on the record, in every other case.
    let inline = inode.has_inline_data();
    let mut inline_dir: Option<InlinePayload> = None;
    let mut file_source: Option<Arc<dyn DataSource>> = None;
    if inline {
        metadata["inline_data"] = json!(true);
        let readable = !is_deleted
            && ctx.superblock.incompat_features & EXT4_INCOMPAT_INLINE_DATA != 0
            && (inode.is_file() || inode.is_dir());
        if !readable {
            mark_content_incomplete(
                &mut metadata,
                IncompleteReason::UnresolvedStructure,
                "this inode stores its content inline (inline_data) but it cannot be read here: \
                 the inode is deleted (a freed inode body is not recovered), the volume does not \
                 declare the inline_data feature, or it is not a file or directory; no content \
                 is served and, for a directory, no entries are listed",
            );
        } else {
            let payload = inline_payload(&inode, &xattrs);
            metadata["inline_data_bytes_in_inode"] = json!(payload.in_inode.len());
            metadata["inline_data_bytes_in_xattr"] = json!(payload.in_xattr.len());
            if payload.shortfall > 0 {
                mark_content_incomplete(
                    &mut metadata,
                    IncompleteReason::UnresolvedStructure,
                    &format!(
                        "inode size is {} bytes but i_block and the system.data xattr hold {}; \
                         the missing {} bytes are not served and not padded",
                        inode.size(),
                        payload.in_inode.len() + payload.in_xattr.len(),
                        payload.shortfall
                    ),
                );
            }
            if inode.is_dir() {
                metadata["inline_dir_parent_inode"] =
                    json!(LittleEndian::read_u32(&payload.in_inode[0..4]));
                inline_dir = Some(payload);
            } else {
                let mut content = payload.in_inode;
                content.extend_from_slice(&payload.in_xattr);
                file_source = Some(Arc::new(ByteSliceDataSource::new(content)));
            }
        }
    }

    // Create Ext4FileSource (supports both extents and direct blocks)
    // Only for regular files and directories
    if (inode.is_file() || inode.is_dir()) && !inline {
        let source =
            Ext4FileSource::new(ctx.data_source.clone(), ctx.superblock.block_size, &inode);

        if inode.is_file() && inode.size() > 0 {
            attach_data_runs(&mut metadata, &source, inode_num);
        }

        file_source = Some(Arc::new(source) as Arc<dyn DataSource>);
    }

    // Honesty flag: fscrypt-encrypted inodes (EXT4_ENCRYPT_FL) still expose
    // data_runs, but those bytes are ciphertext we do not decrypt. Mark them so
    // the served/hashed content is not mistaken for plaintext (BUG-180; mirrors
    // the F2FS and btrfs markers).
    if inode.is_encrypted() {
        metadata["encrypted"] = json!(true);
        metadata["content_ciphertext"] = json!("ext4_fscrypt");
        // `content_incomplete` is the flag the API, export and integrity-verify
        // paths read; the marker above is for display. Without it ciphertext
        // travels the same code path as plaintext and its digest is recorded as
        // the digest of the file's actual bytes (B2-135). An already-set reason
        // describes a defect in the reconstruction itself and is left alone.
        metadata["content_incomplete"] = json!(true);
        if metadata.get("content_incomplete_reason").is_none() {
            metadata["content_incomplete_reason"] = json!(IncompleteReason::Encrypted.as_str());
        }
    }

    let artifact = Artifact::new(
        ctx.case_id,
        ArtifactType::FileEntry,
        file_source.clone(),
        metadata,
    )
    .with_parent(ctx.artifact_id);

    ctx.produced_artifacts.push(artifact);

    // Per-inode progress (rate-limited internally to ~1/sec). During the walk
    // produced_artifacts holds exactly the file entries emitted so far.
    if let Some(reporter) = ctx.progress {
        reporter.report_for_case(
            ctx.case_id,
            ctx.artifact_id,
            ctx.produced_artifacts.len() as u64,
            Some(ctx.total_inodes),
            "files",
        );
    }

    if inode.is_dir() {
        // A name from directory slack is stale: its inode may now be a live
        // directory linked elsewhere, whose children belong at that path.
        // Descending here would attribute them to the stale name and make the
        // real walk skip them at the cycle guard below.
        if origin == EntryOrigin::DirectorySlack {
            return Ok(InodeWalk::Emitted);
        }
        // Cycle guard: a directory reached a second time in this walk is a
        // corrupt/cyclic structure (A->B->C->A). Its own entry was already
        // emitted above; do NOT re-descend, or a branching cycle explodes.
        if !ctx.visited_dirs.insert(inode_num) {
            if let Some(obj) = ctx
                .produced_artifacts
                .last_mut()
                .and_then(|a| a.metadata.as_object_mut())
            {
                obj.insert("duplicate_directory_visit".to_string(), json!(true));
                obj.insert(
                    "duplicate_directory_visit_note".to_string(),
                    json!(
                        "this directory inode was already listed under another name (a hard \
                         link or a corrupt directory graph); it is not listed again here"
                    ),
                );
            }
            return Ok(InodeWalk::Emitted);
        }
        // The directory's own artifact was just pushed above; remember its slot
        // so a total parse failure can be flagged on it instead of silently
        // yielding zero entries.
        let dir_artifact_index = ctx.produced_artifacts.len().saturating_sub(1);
        // This directory's listing accounts for its own gaps; the parent's are
        // set aside and restored below.
        let outer_gaps = std::mem::take(&mut ctx.listing_gaps);
        // An inline directory has no source; it is listed from its payload.
        let complete = if inline {
            // An inline directory: parent word, then dirents in i_block[4..60],
            // then more in system.data. The two regions are parsed separately,
            // since no entry crosses from one to the other. A directory that
            // could not be read at all is a gap.
            match &inline_dir {
                Some(p) => {
                    let mut whole = p.shortfall == 0;
                    if parse_directory_entries(ctx, &p.in_inode[4..], path).is_err() {
                        whole = false;
                    }
                    if parse_directory_entries(ctx, &p.in_xattr, path).is_err() {
                        whole = false;
                    }
                    whole
                }
                None => {
                    ctx.listing_gaps.corrupt += 1;
                    false
                }
            }
        } else if let Some(source) = file_source {
            // Check if directory uses hash tree (INDEX flag = 0x1000)
            let uses_htree = (inode.flags & 0x1000) != 0;

            // Every path below decides whether the listing we produced covers the
            // whole directory. Anything less is marked on the directory artifact
            // so an examiner never reads a truncated listing as complete
            // (BUG-178/BUG-179).
            if uses_htree {
                // Parse hash tree directory
                debug!("Directory {} uses htree", path);
                // A tree whose every leaf failed yielded nothing usable: treat it
                // like a parse error and retry linearly (BUG-178).
                let mut htree_partial = false;
                let fallback_reason = match parse_htree_directory(ctx, source.as_ref(), path) {
                    Ok(outcome) if outcome.total_failure() => {
                        Some("every leaf block failed to parse".to_string())
                    }
                    Ok(outcome) => {
                        if outcome.incomplete() {
                            warn!(
                                "Htree directory {}: {} of {} leaf blocks unreadable, entries may be missing",
                                path, outcome.leaves_failed, outcome.leaves_total
                            );
                            htree_partial = true;
                        }
                        None
                    }
                    Err(e) => Some(e.to_string()),
                };

                match fallback_reason {
                    None => !htree_partial,
                    Some(reason) => {
                        warn!(
                            "Htree parse of directory {} failed ({}), falling back to linear scan",
                            path, reason
                        );
                        let (recovered, whole) =
                            parse_linear_directory(ctx, source.as_ref(), path, inode.size());
                        if !recovered {
                            // Both the htree parse and the linear reparse failed: this
                            // directory's entries could not be recovered. Surface the
                            // loss rather than returning an empty (apparently complete)
                            // directory.
                            warn!(
                                "Directory {} could not be parsed (htree failed and linear reparse failed); entries may be missing",
                                path
                            );
                        }
                        recovered && whole
                    }
                }
            } else {
                // Linear directory - read the dirent blocks (capped).
                let (recovered, whole) =
                    parse_linear_directory(ctx, source.as_ref(), path, inode.size());
                if !recovered {
                    warn!("Failed to read directory inode {}", inode_num);
                }
                recovered && whole
            }
        } else {
            ctx.listing_gaps.corrupt += 1;
            false
        };
        let gaps = std::mem::replace(&mut ctx.listing_gaps, outer_gaps);

        if !complete || gaps.reason().is_some() {
            if let Some(obj) = ctx
                .produced_artifacts
                .get_mut(dir_artifact_index)
                .and_then(|a| a.metadata.as_object_mut())
            {
                obj.insert("directory_parse_incomplete".to_string(), json!(true));
                if let Some(reason) = gaps.reason() {
                    obj.insert(
                        "directory_parse_incomplete_reason".to_string(),
                        json!(reason.as_str()),
                    );
                }
                if gaps.cancelled > 0 {
                    obj.insert("directory_walk_cancelled".to_string(), json!(true));
                }
                if gaps.unresolved_entries > 0 {
                    obj.insert(
                        "directory_entries_unresolved".to_string(),
                        json!(gaps.unresolved_entries),
                    );
                }
            }
        }
    }

    Ok(InodeWalk::Emitted)
}

/// Read a directory's dirent data linearly and emit its children.
///
/// Returns `(parsed, whole)`: `parsed` is false when nothing could be read or
/// the dirent walk errored; `whole` is false when the listing cannot cover the
/// directory — the directory is larger than `EXT4_MAX_DIR_BYTES`, or the source
/// returned fewer bytes than asked for. `whole == false` is what makes the
/// caller stamp `directory_parse_incomplete` (BUG-179): a truncated listing must
/// never look like a complete one.
fn parse_linear_directory(
    ctx: &mut ParsingContext,
    source: &dyn DataSource,
    path: &str,
    dir_size: u64,
) -> (bool, bool) {
    let capped = std::cmp::min(dir_size, EXT4_MAX_DIR_BYTES);
    if capped == 0 {
        return (false, dir_size == 0);
    }
    let mut whole = dir_size <= EXT4_MAX_DIR_BYTES;
    if !whole {
        warn!(
            "Directory {} is {} bytes; only the first {} bytes of dirents are scanned",
            path, dir_size, EXT4_MAX_DIR_BYTES
        );
    }

    let mut dir_data = vec![0u8; capped as usize];
    // Gather the whole directory before concluding it is short: the shortfall
    // below sets `whole = false`, which tells an examiner that entries are
    // missing. One partial `read_at` on a windowed source is not that.
    let n = read_full(source, 0, &mut dir_data);
    if n == 0 {
        warn!("Read 0 bytes from directory {}", path);
        return (false, false);
    }
    if (n as u64) < capped {
        // Short read: the tail of the directory is missing, so entries stored
        // there are lost. Do not let the zero tail pass as "no more entries".
        warn!(
            "Short read of directory {} ({} of {} bytes); later entries are missing",
            path, n, capped
        );
        whole = false;
    }

    if path == "/" {
        let preview_len = std::cmp::min(n, 80);
        debug!(
            "Directory {} content (first {} bytes): {:02X?}",
            path,
            preview_len,
            &dir_data[..preview_len]
        );
    }

    match parse_directory_entries(ctx, &dir_data[..n], path) {
        Ok(()) => (true, whole),
        Err(e) => {
            warn!("Failed to walk dirents of {}: {}", path, e);
            (false, false)
        }
    }
}

/// Byte offset of `dx_root_info` inside a dx_root block.
///
/// `.` and `..` are stored as FIXED 12-byte fake dirents (`EXT4_DIR_REC_LEN(1)`
/// and `EXT4_DIR_REC_LEN(2)`), so the info block always starts at 24. `..`'s
/// `rec_len` is deliberately set to `blocksize - 12` by the kernel so a
/// non-htree-aware reader sees the rest of the block as one empty record — it
/// must NOT be used to step over the entry (BUG-177).
const DX_ROOT_INFO_OFFSET: usize = 24;
/// Each dx_entry is `{ __le32 hash; __le32 block; }`.
const DX_ENTRY_SIZE: usize = 8;
/// Cap on directory blocks pulled in through one hash tree.
const MAX_HTREE_BLOCKS: usize = 65536;

/// What an htree walk actually covered. Any unreadable index/leaf block, or a
/// capped entry list, means the emitted listing is a subset of the directory.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct HtreeOutcome {
    /// Leaf blocks the tree pointed at.
    leaves_total: usize,
    /// Leaf blocks that could not be read or walked.
    leaves_failed: usize,
    /// An index node was unreadable/invalid, or a cap was hit.
    truncated: bool,
}

impl HtreeOutcome {
    /// The listing does not cover the whole directory.
    fn incomplete(&self) -> bool {
        self.truncated || self.leaves_failed > 0
    }

    /// Nothing at all was recovered from the tree: no leaf was reachable, or
    /// every leaf we did reach failed. The caller retries with a linear scan.
    fn total_failure(&self) -> bool {
        self.leaves_total == 0 || self.leaves_failed == self.leaves_total
    }
}

/// Read the dx_entries out of one hash-tree block.
///
/// `entries_offset` is where `entries[]` begins in the block (24 + info_length
/// for a dx_root, 8 for a dx_node — both sit after a fake dirent header). The
/// first entry's `hash` field is overlaid by `struct dx_countlimit { limit,
/// count }`, and `count` is authoritative for how many entries follow — scanning
/// until a zero hash/block pair silently stops at the first sparse entry
/// (BUG-178).
fn read_dx_entries(block: &[u8], entries_offset: usize, block_size: usize) -> Result<Vec<u32>> {
    if entries_offset + DX_ENTRY_SIZE > block_size || block.len() < block_size {
        return Err(anyhow!(
            "dx block too small for entries at offset {}",
            entries_offset
        ));
    }
    let limit = LittleEndian::read_u16(&block[entries_offset..entries_offset + 2]) as usize;
    let count = LittleEndian::read_u16(&block[entries_offset + 2..entries_offset + 4]) as usize;
    let max_entries = (block_size - entries_offset) / DX_ENTRY_SIZE;
    if count == 0 || count > limit || limit > max_entries {
        return Err(anyhow!(
            "dx_countlimit out of range (count={}, limit={}, max={})",
            count,
            limit,
            max_entries
        ));
    }

    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let base = entries_offset + i * DX_ENTRY_SIZE;
        // entries[0].hash is the countlimit overlay; every entry's block number
        // lives in the second word.
        blocks.push(LittleEndian::read_u32(&block[base + 4..base + 8]));
    }
    Ok(blocks)
}

/// Read one interior htree node (dx_node) and return the blocks it points at.
/// A dx_node starts with an 8-byte fake dirent, then `entries[]`.
fn read_dx_node(
    source: &dyn DataSource,
    logical_block: u32,
    block_size: usize,
) -> Result<Vec<u32>> {
    let mut buf = vec![0u8; block_size];
    let offset = (logical_block as u64).saturating_mul(block_size as u64);
    let n = read_full(source, offset, &mut buf);
    if n < block_size {
        return Err(anyhow!(
            "short read of htree index block {} ({} of {} bytes)",
            logical_block,
            n,
            block_size
        ));
    }
    read_dx_entries(&buf, 8, block_size)
}

fn parse_htree_directory(
    ctx: &mut ParsingContext,
    source: &dyn DataSource,
    current_path: &str,
) -> Result<HtreeOutcome> {
    // Read first block (root of htree)
    let block_size = ctx.superblock.block_size as usize;
    if block_size <= DX_ROOT_INFO_OFFSET + 8 + DX_ENTRY_SIZE {
        return Err(anyhow!("block size {} too small for an htree", block_size));
    }
    let mut root_block = vec![0u8; block_size];
    let root_bytes = read_full(source, 0, &mut root_block);
    // Anything short of a full block cannot be trusted: the zero tail would be
    // read as dx entries pointing at block 0.
    if root_bytes < block_size {
        return Err(anyhow!(
            "short read of htree root block ({} of {} bytes)",
            root_bytes,
            block_size
        ));
    }

    // "." fake dirent: inode(4) rec_len(2) name_len(1) file_type(1) then the name.
    let dot_rec_len = LittleEndian::read_u16(&root_block[4..6]);
    if dot_rec_len != 12 || root_block[6] != 1 || &root_block[8..9] != b"." {
        return Err(anyhow!("dx_root '.' entry malformed"));
    }
    // ".." fake dirent, fixed 12 bytes in a dx_root (its rec_len spans the block).
    if root_block[18] != 2 || &root_block[20..22] != b".." {
        return Err(anyhow!("dx_root '..' entry malformed"));
    }

    // dx_root_info
    let reserved_zero = LittleEndian::read_u32(&root_block[24..28]);
    let hash_version = root_block[28];
    let info_length = root_block[29] as usize;
    let indirect_levels = root_block[30];
    let _unused_flags = root_block[31];

    debug!(
        "Htree directory {}: hash_version={}, info_length={}, indirect_levels={}",
        current_path, hash_version, info_length, indirect_levels
    );

    // Sanity-gate the header before trusting the entry array: a non-dx block
    // (corrupt, or an INDEX flag left on a linear directory) must fail here so
    // the caller falls back to a linear scan instead of walking garbage blocks.
    if reserved_zero != 0 {
        return Err(anyhow!("dx_root_info reserved field is not zero"));
    }
    // DX_HASH_LEGACY(0) .. DX_HASH_SIPHASH(6)
    if hash_version > 6 {
        return Err(anyhow!("unknown htree hash version {}", hash_version));
    }
    if info_length < 8 || DX_ROOT_INFO_OFFSET + info_length + DX_ENTRY_SIZE > block_size {
        return Err(anyhow!("dx_root_info length {} out of range", info_length));
    }
    if indirect_levels > 2 {
        return Err(anyhow!(
            "Htree indirect levels {} too deep",
            indirect_levels
        ));
    }

    let mut outcome = HtreeOutcome::default();

    // Root entries. For indirect_levels > 0 these address interior nodes, not
    // leaf directory blocks, so descend one level per indirect level.
    let mut level = read_dx_entries(&root_block, DX_ROOT_INFO_OFFSET + info_length, block_size)?;
    for depth in 0..indirect_levels {
        let mut next: Vec<u32> = Vec::new();
        for block_num in &level {
            if next.len() >= MAX_HTREE_BLOCKS {
                warn!(
                    "Htree directory {}: index level {} exceeded {} blocks, truncating",
                    current_path, depth, MAX_HTREE_BLOCKS
                );
                outcome.truncated = true;
                break;
            }
            match read_dx_node(source, *block_num, block_size) {
                Ok(children) => next.extend(children),
                Err(e) => {
                    warn!(
                        "Htree directory {}: index block {} unusable: {}",
                        current_path, block_num, e
                    );
                    outcome.truncated = true;
                }
            }
        }
        level = next;
    }

    // Distinct leaf blocks, in tree order. A crafted tree can name the same
    // block repeatedly; walking it once keeps the emitted listing honest.
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let leaf_blocks: Vec<u32> = level.into_iter().filter(|b| seen.insert(*b)).collect();

    debug!(
        "Htree directory {} has {} leaf blocks",
        current_path,
        leaf_blocks.len()
    );
    outcome.leaves_total = leaf_blocks.len();

    // Read each leaf block and parse directory entries
    for block_num in leaf_blocks {
        let mut block_data = vec![0u8; block_size];
        let offset = (block_num as u64).saturating_mul(block_size as u64);

        // Gather the whole leaf block. `outcome.truncated` tells an examiner that
        // entries are missing from this listing; one partial `read_at` on a
        // windowed image is not evidence of that, so keep asking first.
        let n = read_full(source, offset, &mut block_data);
        if n < 8 {
            debug!(
                "Htree leaf block {} in {} unreadable ({} bytes)",
                block_num, current_path, n
            );
            outcome.leaves_failed += 1;
        } else if let Err(e) = parse_directory_entries(ctx, &block_data[..n], current_path) {
            // A failed block is counted, never silently dropped.
            debug!(
                "Skipping htree leaf block {} in {}: {}",
                block_num, current_path, e
            );
            outcome.leaves_failed += 1;
        } else if n < block_size {
            outcome.truncated = true;
        }
    }

    Ok(outcome)
}

// Note: `read_slack_dirent` and `recognize_directory_block` below re-implement
// closely related dirent-validation logic for their own contexts (unallocated
// slack and orphaned directory blocks) rather than sharing this function's walk —
// flagged by an independent code review on 2026-09-18 as worth unifying if this
// file is revisited; not done here since all three are pinned by passing tests
// and unifying them without full re-verification carries real regression risk.
fn parse_directory_entries(
    ctx: &mut ParsingContext,
    data: &[u8],
    current_path: &str,
) -> Result<()> {
    let mut cursor = Cursor::new(data);
    let len = data.len() as u64;

    while cursor.position() + 8 <= len {
        let start_pos = cursor.position();

        let inode = cursor.read_u32::<LittleEndian>()?;
        let rec_len = cursor.read_u16::<LittleEndian>()?;
        let name_len = cursor.read_u8()?;
        let file_type = cursor.read_u8()?;

        // The smallest real entry is 12 bytes (8-byte header + a 1-byte name,
        // padded). A shorter rec_len cannot be stepped over sensibly (zero would
        // loop forever), and everything after it in this block is unread: the
        // directory's listing is incomplete, not finished.
        if rec_len < 8 {
            warn!(
                "Directory {}: corrupt rec_len {} at byte {}; the rest of this block was not read",
                current_path, rec_len, start_pos
            );
            ctx.listing_gaps.corrupt += 1;
            break;
        }

        // The kernel's own check (ext4_check_dir_entry): a record is 4-byte
        // aligned, large enough for its own name, and ends inside the block it
        // starts in. One that fails cannot be stepped over or believed, so it is
        // not walked, the directory is flagged, and the walk resumes at the next
        // block boundary (the same rules the slack walker applies).
        let block_size = (ctx.superblock.block_size as u64).max(8);
        let block_end = (start_pos / block_size + 1) * block_size;
        let needed = (8 + name_len as u64).div_ceil(4) * 4;
        if rec_len % 4 != 0
            || (rec_len as u64) < needed
            || start_pos + rec_len as u64 > block_end.min(len)
        {
            warn!(
                "Directory {}: invalid rec_len {} (name_len {}) at byte {}; the rest of this block was not read",
                current_path, rec_len, name_len, start_pos
            );
            ctx.listing_gaps.corrupt += 1;
            if block_end >= len {
                break;
            }
            cursor.seek(SeekFrom::Start(block_end))?;
            continue;
        }

        if inode != 0 {
            // Check that name fits within the data
            if cursor.position() + name_len as u64 > len {
                warn!(
                    "Directory {}: entry at byte {} has a name running past the block; the rest of this block was not read",
                    current_path, start_pos
                );
                ctx.listing_gaps.corrupt += 1;
                break;
            }
            let mut name_buf = vec![0u8; name_len as usize];
            cursor.read_exact(&mut name_buf)?;
            let name = String::from_utf8_lossy(&name_buf).to_string();

            // Debug: Log directory entry details for root directory
            if current_path == "/" {
                debug!(
                    "  Dir entry: inode={}, rec_len={}, name_len={}, name='{}'",
                    inode, rec_len, name_len, name
                );
            }

            if name != "." && name != ".." {
                walk_live_child(ctx, inode, file_type, &name_buf, current_path);
            }
        } else if name_len > 0 {
            // An entry the kernel left in the live chain with its inode number
            // zeroed but its name intact: a deleted file the directory still
            // records, not swallowed into any neighbour's slack, so the two
            // paths above and below never reach it (HUNT-080). Recover the name
            // the same way the slack walker does, under the same validation —
            // a printable name, no NUL/slash, that fits the record.
            let name_start = start_pos as usize + 8;
            if name_start + name_len as usize <= data.len() {
                let name_bytes = &data[name_start..name_start + name_len as usize];
                if name_bytes.iter().all(|&b| b != 0 && b != b'/' && b >= 0x20) {
                    let name = String::from_utf8_lossy(name_bytes).to_string();
                    if name != "." && name != ".." {
                        push_name_only_deletion(ctx, &name, current_path, file_type == 2, 0);
                    }
                }
            }
        }

        // The kernel deletes an entry by widening its predecessor's rec_len
        // over it and leaves the bytes in place. Everything between this
        // entry's real end and where rec_len points is that slack, and the
        // names in it are the directory's deleted files (HUNT-066). Only
        // files are recovered from slack: descending into a deleted
        // directory's blocks would read whatever now occupies them.
        let real_len = (8usize + name_len as usize).div_ceil(4) * 4;
        let slack_start = start_pos as usize + real_len;
        let slack_end = (start_pos as usize)
            .saturating_add(rec_len as usize)
            .min(data.len());
        if slack_start + 8 <= slack_end {
            walk_directory_slack(ctx, &data[slack_start..slack_end], current_path);
        }

        // Advance to next record
        cursor.seek(SeekFrom::Start(start_pos + rec_len as u64))?;
    }

    Ok(())
}

/// `parent` + `name` as a path.
fn child_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", parent, name)
    }
}

/// Walk one live dirent's child, and account for it when it cannot be walked:
/// a live name the directory records must never silently vanish from its
/// listing. A name no path can represent (a `/` or NUL, or empty) is recorded
/// escaped and not followed; an inode that cannot be resolved is recorded by
/// name; a child past the recursion cap is counted. Each stamps the directory
/// being listed through `ctx.listing_gaps`.
fn walk_live_child(
    ctx: &mut ParsingContext,
    inode: u32,
    file_type: u8,
    name_bytes: &[u8],
    current_path: &str,
) {
    let name = String::from_utf8_lossy(name_bytes).to_string();
    if name_bytes.is_empty() || name_bytes.iter().any(|&b| b == 0 || b == b'/') {
        ctx.listing_gaps.unresolved_entries += 1;
        let mut record = unresolved_live_entry(
            &name.replace('/', "%2F").replace('\0', "%00"),
            current_path,
            inode,
            file_type,
            "this directory entry's name contains a '/' or NUL byte (or is empty), which no \
             path can represent; the entry was not followed, so its metadata and content were \
             not read",
        );
        record["name_invalid"] = json!(true);
        ctx.push_file_entry(record);
        return;
    }

    let new_path = child_path(current_path, &name);
    // Recurse one directory level deeper.
    let child_index = ctx.produced_artifacts.len();
    ctx.depth += 1;
    let walked = parse_inode(ctx, inode, &new_path);
    ctx.depth -= 1;
    let unresolved = match walked {
        Ok(InodeWalk::Emitted) => {
            // The child's own record is the first one it pushed. A dirent whose
            // file_type byte names a different type from the inode's mode is
            // kept and marked: either the directory or the inode was altered,
            // and which one is not decidable here.
            if let Some(rec) = ctx
                .produced_artifacts
                .get_mut(child_index)
                .and_then(|a| a.metadata.as_object_mut())
            {
                let inode_type = rec
                    .get("mode")
                    .and_then(|m| m.as_u64())
                    .and_then(|m| ext4_file_type_from_mode(m as u16));
                if file_type != 0 && inode_type.is_some_and(|t| t != file_type) {
                    rec.insert("dirent_file_type_mismatch".to_string(), json!(true));
                    rec.insert("dirent_file_type".to_string(), json!(file_type));
                    rec.insert("inode_file_type".to_string(), json!(inode_type));
                }
            }
            return;
        }
        Ok(InodeWalk::Cancelled) => {
            ctx.listing_gaps.cancelled += 1;
            return;
        }
        Ok(InodeWalk::DepthLimit) => {
            ctx.listing_gaps.capped_entries += 1;
            return;
        }
        Ok(InodeWalk::Unallocated) => {
            "this directory entry names an inode that carries no file type (mode 0); the \
             entry is live but nothing about the file could be read through it"
                .to_string()
        }
        Err(e) => {
            warn!("Failed to parse inode {} at {}: {}", inode, new_path, e);
            format!(
                "this directory entry names inode {inode}, which could not be read ({e}); the \
                 entry is live but nothing about the file could be read through it"
            )
        }
    };
    ctx.listing_gaps.unresolved_entries += 1;
    let record = unresolved_live_entry(&name, current_path, inode, file_type, &unresolved);
    ctx.push_file_entry(record);
}

/// The name-only record for a live directory entry that could not be walked:
/// the inode number is kept, nothing about the file's size, times or content
/// is claimed, and the record says so.
fn unresolved_live_entry(
    name: &str,
    current_path: &str,
    inode: u32,
    file_type: u8,
    detail: &str,
) -> serde_json::Value {
    json!({
        "name": name,
        "path": child_path(current_path, name),
        "parent_path": current_path,
        "inode": inode,
        "is_directory": file_type == EXT4_FT_DIR,
        "metadata_unavailable": true,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "content_incomplete_detail": detail,
    })
}

/// Emit the name-only deletion record for a directory entry whose file cannot
/// be read through it. Two shapes share it: the ext2/ext4 entry whose inode
/// number was zeroed but whose name survives (`inode == 0`; the main directory
/// walk's inode-0 entry, HUNT-080, and the slack walker's), and a hidden entry
/// whose nonzero inode now yields no record (zeroed, reallocated or unreadable;
/// `inode` is kept so the name stays tied to the number the directory recorded).
///
/// `is_dir` is the entry's file_type == 2. Nothing about the file's size,
/// times or content is reachable through such an entry, and the record says so.
fn push_name_only_deletion(
    ctx: &mut ParsingContext,
    name: &str,
    current_path: &str,
    is_dir: bool,
    inode: u32,
) {
    let (inode_value, detail) = if inode == 0 {
        (
            serde_json::Value::Null,
            "this name was recovered from a directory entry whose inode number was zeroed on \
             deletion; the file's size, timestamps and content are not reachable through this \
             entry"
                .to_string(),
        )
    } else {
        (
            json!(inode),
            format!(
                "this name was recovered from a directory entry that names inode {inode}, but \
                 that inode is zeroed, has been reallocated or could not be read; the file's \
                 size, timestamps and content are not reachable through this entry"
            ),
        )
    };
    ctx.push_file_entry(json!({
        "name": name,
        "path": child_path(current_path, name),
        "parent_path": current_path,
        "inode": inode_value,
        "deleted": true,
        "deleted_recovery_source": "directory_slack",
        "is_directory": is_dir,
        "metadata_unavailable": true,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "content_incomplete_detail": detail,
    }));
}

/// Read a `dirent` header + name at `pos`, or `None` when `pos` does not hold a
/// plausible one. The validation is the kernel's own invariants: a 4-aligned
/// `rec_len` at least the entry's real length, an inode in range (or zero for a
/// deletion that cleared it), and a printable name with no NUL or slash that
/// fits the buffer. Shared by both passes of the slack walk.
fn read_slack_dirent(slack: &[u8], pos: usize, inode_count: u32) -> Option<SlackDirent> {
    if pos + 8 > slack.len() {
        return None;
    }
    let inode = LittleEndian::read_u32(&slack[pos..pos + 4]);
    let rec_len = LittleEndian::read_u16(&slack[pos + 4..pos + 6]) as usize;
    let name_len = slack[pos + 6] as usize;
    let file_type = slack[pos + 7];
    let real_len = (8 + name_len).div_ceil(4) * 4;
    if inode > inode_count
        || name_len == 0
        || rec_len < real_len
        || !rec_len.is_multiple_of(4)
        || pos + 8 + name_len > slack.len()
    {
        return None;
    }
    let name_bytes = &slack[pos + 8..pos + 8 + name_len];
    if name_bytes.iter().any(|&b| b == 0 || b == b'/' || b < 0x20) {
        return None;
    }
    let name = String::from_utf8_lossy(name_bytes).to_string();
    if name == "." || name == ".." {
        return None;
    }
    Some(SlackDirent {
        inode,
        rec_len,
        file_type,
        name,
    })
}

struct SlackDirent {
    inode: u32,
    rec_len: usize,
    file_type: u8,
    name: String,
}

/// Recover the deleted names hidden in a live entry's slack.
///
/// Slack is walked by each hidden entry's own `rec_len`, which is still the
/// length it had when live. Every field is checked before it is believed —
/// the name must fit, the inode must be within the filesystem, the length must
/// be sane — because slack also holds whatever the block held before it was a
/// directory. A hidden entry is never descended, whatever its inode is now: a
/// deleted directory's blocks, or an inode number since reused as a directory
/// linked elsewhere, belong to whatever has them now. A name whose inode yields
/// no record is still recorded by name.
///
/// Two passes, because a churned directory block does not hide its deleted
/// entries in one clean chain:
///
/// - **Pass 1 follows `rec_len`.** For an entry the walk lands on squarely it
///   recovers the full record — a zeroed inode becomes a name-only deletion, a
///   live inode is followed (with reuse detection) for its size and times. This
///   is how a single live-adjacent deletion is recorded.
///
/// - **Pass 2 is a 4-byte-aligned carve** for the names pass 1 stepped over.
///   The kernel widens one entry's `rec_len` to swallow the entries it deletes,
///   and a later deletion can nest a hidden entry *inside* another hidden
///   entry's span, off the `rec_len` chain entirely. On DFR `dfr-09-ext` that
///   left `xB0247-5.txt` — a recoverable name `debugfs` sees — unreached by the
///   chain (`HUNT-080`). The carve visits every 4-byte offset (ext dirents are
///   4-aligned) and emits, name-only, any valid dirent whose name pass 1 did
///   not already record. Name-only rather than inode-followed, because a
///   carved offset's inode number is not trustworthy enough to read a record
///   from; the name is the directory's own evidence the file existed.
fn walk_directory_slack(ctx: &mut ParsingContext, slack: &[u8], current_path: &str) {
    let inode_count = ctx.superblock.inodes_count;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Pass 1: the rec_len chain.
    let mut pos = 0usize;
    let mut found = 0usize;
    while pos + 8 <= slack.len() && found < MAX_SLACK_ENTRIES_PER_ENTRY {
        let Some(entry) = read_slack_dirent(slack, pos, inode_count) else {
            break;
        };
        found += 1;
        seen.insert(entry.name.clone());
        let is_dir = entry.file_type == EXT4_FT_DIR;
        if entry.inode == 0 || is_dir {
            // A zeroed inode has nothing behind it; a deleted directory's
            // blocks are not read. Either way the name is the evidence.
            push_name_only_deletion(ctx, &entry.name, current_path, is_dir, entry.inode);
        } else {
            let new_path = child_path(current_path, &entry.name);
            ctx.depth += 1;
            let walked = parse_inode_from(ctx, entry.inode, &new_path, EntryOrigin::DirectorySlack);
            ctx.depth -= 1;
            match walked {
                Ok(InodeWalk::Emitted) | Ok(InodeWalk::Cancelled) => {}
                // Nothing was emitted for this name, and the carve pass below
                // skips names already seen: record it here or it is lost.
                Ok(InodeWalk::DepthLimit) | Ok(InodeWalk::Unallocated) => {
                    push_name_only_deletion(ctx, &entry.name, current_path, false, entry.inode)
                }
                Err(e) => {
                    debug!(
                        "Slack entry {} at {} did not parse: {}",
                        entry.inode, new_path, e
                    );
                    push_name_only_deletion(ctx, &entry.name, current_path, false, entry.inode)
                }
            }
        }
        pos = pos.saturating_add(entry.rec_len);
    }

    // Pass 2: the 4-byte-aligned carve for names the chain could not reach.
    let mut pos = 0usize;
    let mut carved = 0usize;
    while pos + 8 <= slack.len() && carved < MAX_SLACK_ENTRIES_PER_ENTRY {
        if let Some(entry) = read_slack_dirent(slack, pos, inode_count) {
            if seen.insert(entry.name.clone()) {
                carved += 1;
                // The inode number at a carved offset is recorded as found, not
                // followed: it is not trustworthy enough to read a record from.
                push_name_only_deletion(
                    ctx,
                    &entry.name,
                    current_path,
                    entry.file_type == EXT4_FT_DIR,
                    entry.inode,
                );
            }
        }
        pos += 4;
    }
}

/// Bound on hidden entries recovered from one live entry's slack, so a block
/// of garbage that happens to parse cannot enumerate forever.
const MAX_SLACK_ENTRIES_PER_ENTRY: usize = 512;

/// Map an inode's `i_mode` type bits (`S_IFMT`) to the `ext4_dir_entry_2`
/// `file_type` value the kernel would have written for it. `None` when the
/// mode bits do not name a known type — in particular `mode == 0`, an inode
/// currently carrying no metadata at all.
fn ext4_file_type_from_mode(mode: u16) -> Option<u8> {
    match mode & 0xF000 {
        0x1000 => Some(EXT4_FT_FIFO),
        0x2000 => Some(EXT4_FT_CHRDEV),
        0x4000 => Some(EXT4_FT_DIR),
        0x6000 => Some(EXT4_FT_BLKDEV),
        0x8000 => Some(EXT4_FT_REG_FILE),
        0xA000 => Some(EXT4_FT_SYMLINK),
        0xC000 => Some(EXT4_FT_SOCK),
        _ => None,
    }
}

/// One dirent recovered from an orphaned directory block, past the leading
/// `.`/`..` pair. `inode` is never 0 here: a within-block deletion (the
/// kernel zeroing an entry's inode in place) is the same shape the live-chain
/// and slack passes already recover, and this block has no live directory
/// for either of those recoveries to attach a path under, so it is left to
/// them where they can reach it and not duplicated here.
struct OrphanedDirent {
    inode: u32,
    name: String,
    file_type: u8,
}

/// Judge whether `data` — one whole block this crate's own free-space reading
/// says is unallocated — still holds a directory's dirents, and if so return
/// every entry past the `.`/`..` pair with a live inode number.
///
/// This is content-based recognition, the same class of heuristic
/// `seance_plugin_carver`'s format signatures use: a real `ext4_dir_entry_2`
/// chain must open with `.` then `..` (every ext4 directory's first block
/// does, deleted or not — a later block of a multi-block directory, or an
/// htree leaf, does not, and neither is recognised by this function) and its
/// `rec_len` fields must chain cleanly to land exactly on the end of the
/// block. A run of bytes that merely resembles a dirent here and there is
/// rejected the moment a `rec_len` is invalid, an inode number exceeds the
/// filesystem's own inode count, a name is not printable, or the chain does
/// not end flush with the block boundary — real limits of a single-block,
/// content-only test, not a claim to recognise every orphaned directory
/// block there could be.
fn recognize_directory_block(data: &[u8], inode_count: u32) -> Option<Vec<OrphanedDirent>> {
    let block_size = data.len();
    // Smaller than a minimal "." (12 bytes) + ".." (12 bytes) pair.
    if block_size < 24 {
        return None;
    }
    let mut pos = 0usize;
    let mut entries = Vec::new();
    let mut seen_dotdot = false;

    while pos + 8 <= block_size {
        let inode = LittleEndian::read_u32(&data[pos..pos + 4]);
        let rec_len = LittleEndian::read_u16(&data[pos + 4..pos + 6]) as usize;
        let name_len = data[pos + 6] as usize;
        let file_type = data[pos + 7];
        let real_len = (8 + name_len).div_ceil(4) * 4;

        // A real dirent's rec_len is 4-aligned, at least its own encoded
        // length, and never runs past the block. Anything else means these
        // bytes are not an ext4 dirent chain.
        if rec_len == 0
            || !rec_len.is_multiple_of(4)
            || rec_len < real_len
            || pos + rec_len > block_size
        {
            return None;
        }
        if inode > inode_count || file_type > EXT4_FT_SYMLINK {
            return None;
        }

        if inode == 0 {
            // "." and ".." are never themselves the kernel's in-place
            // deletion (that clears everything *but* the leading pair) —
            // seeing one zeroed here means this is not a directory's first
            // block after all.
            if !seen_dotdot {
                return None;
            }
            // A later zeroed entry is an in-place deletion within a block
            // that also has no live directory pointing at it; left to the
            // live-chain/slack passes where one does (see the doc comment on
            // `OrphanedDirent`).
        } else {
            if pos + 8 + name_len > block_size {
                return None;
            }
            let name_bytes = &data[pos + 8..pos + 8 + name_len];
            if name_len == 0 || name_bytes.iter().any(|&b| b == 0 || b == b'/' || b < 0x20) {
                return None;
            }
            let name = String::from_utf8_lossy(name_bytes).to_string();

            if pos == 0 {
                if name != "." || file_type != EXT4_FT_DIR {
                    return None;
                }
            } else if !seen_dotdot {
                if name != ".." || file_type != EXT4_FT_DIR {
                    return None;
                }
                seen_dotdot = true;
            } else {
                entries.push(OrphanedDirent {
                    inode,
                    name,
                    file_type,
                });
            }
        }

        pos += rec_len;
    }

    // The chain must consume the block exactly, and both `.` and `..` must
    // have been seen — otherwise these are bytes that merely parsed a few
    // records deep by chance, not a real directory block.
    if pos != block_size || !seen_dotdot {
        return None;
    }
    Some(entries)
}

/// Build the record for one dirent recovered from an orphaned directory
/// block: resolve its inode when the inode still looks like this file, or
/// report it as an orphaned name with an unresolved target when it does not.
/// Never both for the same entry, and never the content of whatever now
/// occupies the inode presented as this dirent's file (ROADMAP §5.6).
///
/// Resolution reuses the same reuse test `parse_inode_from` applies to a
/// slack-recovered name (mode cleared or a deletion marker set on the inode
/// itself), plus a check that test does not need: a slack entry's dirent
/// lives in a directory whose own identity is not in question, but an
/// orphaned block's does not, so the dirent's claimed `file_type` is checked
/// against the inode's own mode bits before either is trusted.
fn emit_orphaned_directory_entry(ctx: &mut ParsingContext, block: u64, entry: &OrphanedDirent) {
    let mut metadata = json!({
        "name": entry.name,
        "inode": entry.inode,
        "deleted": true,
        "deleted_recovery_source": "orphaned_directory_block",
        "orphaned_directory_block": block,
        "is_directory": entry.file_type == EXT4_FT_DIR,
        // The containing directory's own name and original path are not
        // known here: this block was found by content in unallocated space,
        // not reached through any live parent. Recovering the directory's
        // own name (when its parent's dirent survives) is a separate
        // mechanism this crate already has; correlating the two is not
        // attempted here, so a fabricated path is never reported in its place.
        "path": serde_json::Value::Null,
        "parent_path": serde_json::Value::Null,
    });

    let inode = match Inode::parse(
        ctx.data_source.as_ref(),
        ctx.superblock,
        ctx.groups,
        entry.inode,
    ) {
        Ok(inode) => inode,
        Err(e) => {
            debug!(
                "Orphaned directory block {}: inode {} for '{}' unreadable: {}",
                block, entry.inode, entry.name, e
            );
            metadata["inode_status"] = json!("unreadable");
            metadata["metadata_unavailable"] = json!(true);
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] =
                json!(IncompleteReason::UnresolvedStructure.as_str());
            metadata["content_incomplete_detail"] = json!(format!(
                "inode {} could not be read; this name's file cannot be resolved",
                entry.inode
            ));
            ctx.produced_artifacts.push(
                Artifact::new(ctx.case_id, ArtifactType::FileEntry, None, metadata)
                    .with_parent(ctx.artifact_id),
            );
            return;
        }
    };

    // mode == 0: the inode currently carries no metadata at all (never
    // reused since this dirent's directory died, or reused and freed again).
    // Either way there is nothing on it to attribute to this name.
    let unallocated = inode.mode == 0;
    let looks_deleted = if unallocated {
        false
    } else {
        inode.dtime != 0 || inode.links_count == 0
    };
    let mode_type = ext4_file_type_from_mode(inode.mode);
    // A dirent that did not record a type (EXT4_FT_UNKNOWN) cannot be refuted
    // by this check; only a *recorded* mismatch is evidence of reuse.
    let type_consistent = match mode_type {
        Some(t) => entry.file_type == EXT4_FT_UNKNOWN || t == entry.file_type,
        None => false,
    };

    if unallocated {
        metadata["inode_status"] = json!("unallocated");
        metadata["metadata_unavailable"] = json!(true);
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] =
            json!(IncompleteReason::UnresolvedStructure.as_str());
        metadata["content_incomplete_detail"] = json!(
            "this inode currently holds no metadata; this dirent's file cannot be resolved \
             through it"
        );
    } else if !type_consistent || !looks_deleted {
        // Either the inode is now a different kind of thing than this dirent
        // names (type_consistent false), or it looks live — allocated, no
        // deletion marker of its own — which an inode named only from a block
        // with no live directory pointing at it has no business being. Either
        // way the bytes reachable through this inode number belong to
        // whatever put them there now, not to this name.
        metadata["inode_status"] = json!("reused");
        metadata["inode_reused"] = json!(true);
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] =
            json!(IncompleteReason::UnresolvedStructure.as_str());
        metadata["content_incomplete_detail"] = json!(
            "this inode has since been reallocated, or now holds a different kind of thing than \
             this dirent names; the content reachable through it belongs to that, not to this \
             name"
        );
    } else {
        // Type-consistent and the inode itself carries a deletion marker: as
        // confident an identification as this crate makes of any recovered
        // inode elsewhere (parse_inode_from's own is_deleted test). Report the
        // same metadata the live path would for an ordinary file here.
        metadata["inode_status"] = json!("resolved");
        metadata["mode"] = json!(inode.mode);
        metadata["uid"] = json!(inode.uid);
        metadata["gid"] = json!(inode.gid);
        metadata["size"] = json!(inode.size());
        let (ctime_s, ctime_n) = inode.ctime_ts();
        let (mtime_s, mtime_n) = inode.mtime_ts();
        let (atime_s, atime_n) = inode.atime_ts();
        metadata["changed"] = json!(format_timestamp_full(ctime_s, ctime_n));
        metadata["modified"] = json!(format_timestamp_full(mtime_s, mtime_n));
        metadata["accessed"] = json!(format_timestamp_full(atime_s, atime_n));
        if let Some((crtime_s, crtime_n)) = inode.crtime_ts() {
            metadata["created"] = json!(format_timestamp_full(crtime_s, crtime_n));
        }
        if inode.dtime != 0 {
            metadata["deleted_time"] = json!(format_timestamp(inode.dtime));
        }
        // Same caveat the live deleted-inode path carries (B2-160 class): the
        // extents name where the file's blocks were, not proof they still
        // hold its data.
        metadata["deleted_content_caveat"] = json!("blocks_may_be_reallocated");
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] =
            json!(IncompleteReason::UnresolvedStructure.as_str());

        let mut file_source: Option<Arc<dyn DataSource>> = None;
        // Inline data keeps its bytes in i_block, which is not a block map.
        let inline = inode.has_inline_data();
        if inline {
            metadata["inline_data"] = json!(true);
        }
        if (inode.is_file() || inode.is_dir()) && !inline {
            let source =
                Ext4FileSource::new(ctx.data_source.clone(), ctx.superblock.block_size, &inode);
            if inode.is_file() && inode.size() > 0 {
                attach_data_runs(&mut metadata, &source, entry.inode);
            }
            file_source = Some(Arc::new(source) as Arc<dyn DataSource>);
        }
        if inode.is_encrypted() {
            metadata["encrypted"] = json!(true);
            metadata["content_ciphertext"] = json!("ext4_fscrypt");
        }

        ctx.produced_artifacts.push(
            Artifact::new(ctx.case_id, ArtifactType::FileEntry, file_source, metadata)
                .with_parent(ctx.artifact_id),
        );
        return;
    }

    ctx.produced_artifacts.push(
        Artifact::new(ctx.case_id, ArtifactType::FileEntry, None, metadata)
            .with_parent(ctx.artifact_id),
    );
}

/// Scan the blocks this volume's own bitmaps say are free for orphaned
/// directory content and recover what each names (ROADMAP §5.6). The kernel
/// clears a deleted directory's inode block pointers but never touches the
/// block itself, so a directory's dirents can survive in unallocated space
/// until something else claims those blocks — exactly the NIST DFR `dfr-11`
/// scenario, and the gap `LINUX_DESIGN.md` records: this crate recovered a
/// deleted directory's *name* (from its parent's surviving dirent) but not
/// its *contents*.
///
/// A summary `ParsedRecord` is always pushed when any orphaned block was
/// found, or when the entry cap below was hit, so the pass's reach is on the
/// record even when it recovers nothing.
fn scan_orphaned_directory_blocks(ctx: &mut ParsingContext, bitmaps: &GroupBitmaps) {
    let block_size = ctx.superblock.block_size as u64;
    if block_size == 0 {
        return;
    }
    let total_blocks = total_blocks_bound(ctx.superblock, ctx.groups, ctx.data_source.size());
    let first_data_block = ctx.superblock.first_data_block as u64;
    let inode_count = ctx.superblock.inodes_count;

    let mut blocks_found = 0u64;
    let mut entries_found = 0usize;
    let mut cap_hit = false;
    let mut chunk = vec![0u8; (ORPHAN_SCAN_CHUNK_BLOCKS * block_size) as usize];

    let mut block = first_data_block;
    while block < total_blocks && !cap_hit && !ctx.cancelled() {
        if !matches!(bitmaps.state(block), BlockState::Free) {
            block += 1;
            continue;
        }
        // Take the whole run of consecutive free blocks (up to one chunk) and
        // read it in one call: per-block reads of a mostly-free volume are
        // dominated by I/O overhead, not by the heuristic below.
        let mut run = 1u64;
        while run < ORPHAN_SCAN_CHUNK_BLOCKS
            && block + run < total_blocks
            && matches!(bitmaps.state(block + run), BlockState::Free)
        {
            run += 1;
        }
        let want = (run * block_size) as usize;
        let n = read_full(
            ctx.data_source.as_ref(),
            block * block_size,
            &mut chunk[..want],
        );
        for k in 0..run {
            let start = (k * block_size) as usize;
            let end = start + block_size as usize;
            if end > n {
                // A partially read free block cannot be judged whole; skip rather
                // than test a truncated tail against the full-block rule below.
                break;
            }
            let Some(entries) = recognize_directory_block(&chunk[start..end], inode_count) else {
                continue;
            };
            if entries.is_empty() {
                continue;
            }
            let this_block = block + k;
            blocks_found += 1;
            for dirent in &entries {
                if entries_found >= MAX_ORPHANED_DIRECTORY_ENTRIES {
                    cap_hit = true;
                    break;
                }
                emit_orphaned_directory_entry(ctx, this_block, dirent);
                entries_found += 1;
            }
            if cap_hit {
                break;
            }
        }
        block += run;
    }

    if blocks_found > 0 || cap_hit {
        let mut metadata = json!({
            "type": "orphaned_directory_scan",
            "orphaned_directory_blocks_found": blocks_found,
            "orphaned_directory_entries_recovered": entries_found,
        });
        if cap_hit {
            metadata["orphaned_directory_entries_cap"] = json!(MAX_ORPHANED_DIRECTORY_ENTRIES);
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] = json!(IncompleteReason::CapReached.as_str());
        }
        ctx.produced_artifacts.push(
            Artifact::new(ctx.case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(ctx.artifact_id),
        );
    }
}

fn format_timestamp(ts: u32) -> String {
    if let Some(dt) = Utc.timestamp_opt(ts as i64, 0).single() {
        dt.to_rfc3339()
    } else {
        String::new()
    }
}

/// Format a decoded ext4 timestamp (64-bit seconds + nanoseconds).
fn format_timestamp_full(secs: i64, nanos: u32) -> String {
    if let Some(dt) = Utc.timestamp_opt(secs, nanos).single() {
        dt.to_rfc3339()
    } else {
        String::new()
    }
}

// --- JBD2 journal (GAP 2) ---
//
// The ext journal is an internal inode (s_journal_inum, default 8) whose file
// content is the JBD2 log. All JBD2 on-disk integers are big-endian. We do not
// replay the journal; we enumerate committed transactions and the filesystem
// blocks they touched (plus revoked blocks) for forensic visibility.

const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_COMMIT_BLOCK: u32 = 2;
const JBD2_SUPERBLOCK_V1: u32 = 3;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const JBD2_REVOKE_BLOCK: u32 = 5;

const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x2;
const JBD2_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x8;
const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x10;

const JBD2_FLAG_SAME_UUID: u32 = 0x2;
const JBD2_FLAG_LAST_TAG: u32 = 0x8;

/// EXT4_FEATURE_COMPAT_HAS_JOURNAL.
const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x4;

/// Safety caps so a crafted journal cannot exhaust memory or spin.
const MAX_JOURNAL_TXNS: usize = 100_000;
const MAX_JOURNAL_TAGS_PER_DESC: usize = 8192;
const MAX_JOURNAL_REVOKES_PER_BLOCK: usize = 8192;
const MAX_JOURNAL_BLOCKS_PER_TXN: usize = 1 << 20;

/// Parsed JBD2 journal superblock (block 0 of the journal).
struct JournalSuperblock {
    blocksize: u32,
    maxlen: u32,
    first: u32,
    sequence: u32,
    start: u32,
    feature_incompat: u32,
}

impl JournalSuperblock {
    fn parse(block0: &[u8]) -> Option<Self> {
        if block0.len() < 44 {
            return None;
        }
        if BigEndian::read_u32(&block0[0..4]) != JBD2_MAGIC {
            return None;
        }
        let blocktype = BigEndian::read_u32(&block0[4..8]);
        if blocktype != JBD2_SUPERBLOCK_V2 && blocktype != JBD2_SUPERBLOCK_V1 {
            return None;
        }
        // Feature flags are only meaningful in a v2 superblock.
        let feature_incompat = if blocktype == JBD2_SUPERBLOCK_V2 {
            BigEndian::read_u32(&block0[40..44])
        } else {
            0
        };
        Some(Self {
            blocksize: BigEndian::read_u32(&block0[12..16]),
            maxlen: BigEndian::read_u32(&block0[16..20]),
            first: BigEndian::read_u32(&block0[20..24]),
            sequence: BigEndian::read_u32(&block0[24..28]),
            start: BigEndian::read_u32(&block0[28..32]),
            feature_incompat,
        })
    }

    fn is_64bit(&self) -> bool {
        self.feature_incompat & JBD2_FEATURE_INCOMPAT_64BIT != 0
    }

    fn is_csum_v2(&self) -> bool {
        self.feature_incompat & JBD2_FEATURE_INCOMPAT_CSUM_V2 != 0
    }

    fn is_csum_v3(&self) -> bool {
        self.feature_incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0
    }

    /// Size in bytes of one `journal_block_tag` in a descriptor block (the
    /// kernel's `journal_tag_bytes`).
    fn tag_bytes(&self) -> usize {
        if self.is_csum_v3() {
            return 16; // journal_block_tag3_t
        }
        // journal_block_tag_t: t_blocknr, t_checksum(2), t_flags(2),
        // t_blocknr_high = 12 bytes, plus the other half of a 32-bit checksum
        // under CSUM_V2.
        let size = if self.is_csum_v2() { 14 } else { 12 };
        if self.is_64bit() {
            size
        } else {
            size - 4 // no t_blocknr_high
        }
    }
}

/// One committed transaction enumerated from the journal.
struct JournalTransaction {
    sequence: u32,
    /// Filesystem blocks journaled by this transaction's descriptor tags.
    blocks: Vec<u64>,
    /// Filesystem blocks revoked by this transaction.
    revoked: Vec<u64>,
}

/// Parse the filesystem block numbers listed by a descriptor block's tags.
/// One tag == one journaled data block, so the returned length also tells the
/// caller how many data blocks follow this descriptor in the log.
///
/// The second return value reports whether the tag list actually ended with a
/// `JBD2_FLAG_LAST_TAG` tag. It matters far beyond this one block: the caller
/// steps over `1 + tags` blocks to reach the next journal record, so an
/// undercounted tag list lands the ring cursor on a data block and every
/// subsequent transaction is dropped or attributed to the wrong sequence. A
/// `false` here means "the count is not trustworthy", not merely "some tags are
/// missing".
fn parse_descriptor_tags(
    block: &[u8],
    tag_bytes: usize,
    csum_v3: bool,
    is_64bit: bool,
) -> (Vec<u64>, bool) {
    let mut out = Vec::new();
    let mut last_tag_seen = false;
    let mut pos = 12usize; // past journal_header_t
    let len = block.len();
    while out.len() < MAX_JOURNAL_TAGS_PER_DESC {
        if pos.saturating_add(tag_bytes) > len {
            break;
        }
        let block_low = BigEndian::read_u32(&block[pos..pos + 4]) as u64;
        let (flags, block_high) = if csum_v3 {
            let f = BigEndian::read_u32(&block[pos + 4..pos + 8]);
            let h = if is_64bit {
                BigEndian::read_u32(&block[pos + 8..pos + 12]) as u64
            } else {
                0
            };
            (f, h)
        } else {
            // journal_block_tag_t: t_checksum(2) then t_flags(2) at pos+6.
            let f = BigEndian::read_u16(&block[pos + 6..pos + 8]) as u32;
            let h = if is_64bit {
                BigEndian::read_u32(&block[pos + 8..pos + 12]) as u64
            } else {
                0
            };
            (f, h)
        };

        out.push((block_high << 32) | block_low);
        pos = pos.saturating_add(tag_bytes);
        if flags & JBD2_FLAG_SAME_UUID == 0 {
            pos = pos.saturating_add(16); // a 16-byte UUID follows this tag
        }
        if flags & JBD2_FLAG_LAST_TAG != 0 {
            last_tag_seen = true;
            break;
        }
    }
    (out, last_tag_seen)
}

/// Parse the revoked filesystem block numbers from a revoke block.
///
/// The second return value is false when the per-block cap stopped the scan, so
/// the caller can say the revoke list is a prefix rather than the whole set. A
/// missing revoke entry makes a journaled block look replayable when the
/// filesystem had already discarded it.
fn parse_revoke_block(block: &[u8], is_64bit: bool) -> (Vec<u64>, bool) {
    let mut out = Vec::new();
    if block.len() < 16 {
        return (out, true);
    }
    // r_count is the number of bytes used in the block, including the 16-byte
    // jbd2_journal_revoke_header_t; clamp it to the block we actually read.
    let r_count = (BigEndian::read_u32(&block[12..16]) as usize).min(block.len());
    let rec = if is_64bit { 8 } else { 4 };
    let mut pos = 16usize;
    while pos + rec <= r_count {
        if out.len() >= MAX_JOURNAL_REVOKES_PER_BLOCK {
            return (out, false);
        }
        let b = if is_64bit {
            BigEndian::read_u64(&block[pos..pos + 8])
        } else {
            BigEndian::read_u32(&block[pos..pos + 4]) as u64
        };
        out.push(b);
        pos += rec;
    }
    (out, true)
}

/// Map a running journal block number back into the log ring [first, maxlen).
fn wrap_journal_block(b: u64, first: u64, maxlen: u64) -> u64 {
    if maxlen <= first || b < maxlen {
        return b;
    }
    let ring = maxlen - first;
    first + ((b.saturating_sub(first)) % ring)
}

/// The outcome of a JBD2 log walk.
///
/// `incomplete` is the difference between "this is every committed transaction
/// the log holds" and "this is what we managed to read before a cap, a short
/// read or a malformed record stopped us". Presented without it, a truncated
/// journal summary reads as a full account of the filesystem's recent history —
/// an examiner would conclude that no later write happened.
struct JournalWalk {
    transactions: Vec<JournalTransaction>,
    incomplete: Option<IncompleteReason>,
}

/// Walk the JBD2 log from `s_start`, following descriptor -> data blocks ->
/// commit, collecting each committed transaction. Bounded by the ring size so a
/// corrupt log cannot loop forever; any inconsistency ends the walk and is
/// reported through `JournalWalk::incomplete`.
fn walk_journal(journal: &dyn DataSource, jsb: &JournalSuperblock) -> JournalWalk {
    let mut txns = Vec::new();
    let mut incomplete: Option<IncompleteReason> = None;
    let bs = jsb.blocksize as u64;
    let first = jsb.first as u64;
    let maxlen = jsb.maxlen as u64;
    // A clean journal (s_start == 0) has nothing to replay.
    if bs == 0 || maxlen <= first || jsb.start == 0 {
        return JournalWalk {
            transactions: txns,
            incomplete: None,
        };
    }

    let tag_bytes = jsb.tag_bytes();
    let mut next_block = wrap_journal_block(jsb.start as u64, first, maxlen);
    let mut next_seq = jsb.sequence;
    let mut current: Option<JournalTransaction> = None;
    let mut buf = vec![0u8; jsb.blocksize as usize];

    // Never process more blocks than the ring holds, and never more than the
    // journal file physically contains: a crafted s_maxlen is independent of the
    // inode size, so bound the walk by both to avoid a spin on a tiny log that
    // claims a huge ring.
    let file_blocks = journal.size().div_ceil(bs).max(1);
    let scan_limit = maxlen.min(file_blocks);
    let mut ended_naturally = false;
    for _ in 0..scan_limit {
        // A journal record occupies a whole journal block. Anything less and the
        // tag list is a prefix of the real one, which both loses tags and
        // desynchronises the ring cursor for every record after it, so refuse to
        // parse the partial block at all.
        let n = read_full(journal, next_block.saturating_mul(bs), &mut buf);
        if n < 12 || BigEndian::read_u32(&buf[0..4]) != JBD2_MAGIC {
            ended_naturally = true;
            break; // end of log / non-journal block
        }
        if n < buf.len() {
            warn!(
                "ext4 journal: short read of block {} ({} of {} bytes); stopping the walk",
                next_block,
                n,
                buf.len()
            );
            incomplete = Some(IncompleteReason::ShortRead);
            break;
        }
        let blocktype = BigEndian::read_u32(&buf[4..8]);
        if BigEndian::read_u32(&buf[8..12]) != next_seq {
            ended_naturally = true;
            break; // sequence no longer matches: transaction chain ended
        }

        match blocktype {
            JBD2_DESCRIPTOR_BLOCK => {
                let (targets, last_tag_seen) =
                    parse_descriptor_tags(&buf, tag_bytes, jsb.is_csum_v3(), jsb.is_64bit());
                let num_tags = targets.len() as u64;
                let txn = current.get_or_insert_with(|| JournalTransaction {
                    sequence: next_seq,
                    blocks: Vec::new(),
                    revoked: Vec::new(),
                });
                let mut capped = false;
                for t in targets {
                    if txn.blocks.len() >= MAX_JOURNAL_BLOCKS_PER_TXN {
                        capped = true;
                        break;
                    }
                    txn.blocks.push(t);
                }
                if capped {
                    incomplete = Some(IncompleteReason::CapReached);
                }
                if !last_tag_seen {
                    // Without the terminating tag the journaled-block count is
                    // unknown, so the next record's position is unknown too.
                    // Guessing would mis-attribute every later transaction.
                    warn!(
                        "ext4 journal: descriptor block {} has no final tag; ring position is unrecoverable",
                        next_block
                    );
                    incomplete = Some(IncompleteReason::UnresolvedStructure);
                    break;
                }
                // Skip the descriptor plus its journaled data blocks.
                next_block = wrap_journal_block(next_block + 1 + num_tags, first, maxlen);
            }
            JBD2_REVOKE_BLOCK => {
                let (revoked, revokes_complete) = parse_revoke_block(&buf, jsb.is_64bit());
                let txn = current.get_or_insert_with(|| JournalTransaction {
                    sequence: next_seq,
                    blocks: Vec::new(),
                    revoked: Vec::new(),
                });
                let mut capped = !revokes_complete;
                for r in revoked {
                    if txn.revoked.len() >= MAX_JOURNAL_BLOCKS_PER_TXN {
                        capped = true;
                        break;
                    }
                    txn.revoked.push(r);
                }
                if capped {
                    incomplete = Some(IncompleteReason::CapReached);
                }
                next_block = wrap_journal_block(next_block + 1, first, maxlen);
            }
            JBD2_COMMIT_BLOCK => {
                let txn = current.take().unwrap_or(JournalTransaction {
                    sequence: next_seq,
                    blocks: Vec::new(),
                    revoked: Vec::new(),
                });
                txns.push(txn);
                if txns.len() >= MAX_JOURNAL_TXNS {
                    incomplete = Some(IncompleteReason::CapReached);
                    break;
                }
                next_seq = next_seq.wrapping_add(1);
                next_block = wrap_journal_block(next_block + 1, first, maxlen);
            }
            _ => {
                ended_naturally = true;
                break; // superblock or unknown block type: stop
            }
        }
    }

    // Falling out of the loop without a terminating condition means the ring
    // bound stopped us, not the log: there may be more committed transactions.
    if incomplete.is_none() && !ended_naturally {
        incomplete = Some(IncompleteReason::CapReached);
    }

    JournalWalk {
        transactions: txns,
        incomplete,
    }
}

/// Parse the internal JBD2 journal and emit a single ParsedRecord summarizing
/// its committed transactions. Returns None only when the filesystem does not
/// declare a journal (`COMPAT_HAS_JOURNAL` clear). Every read or format failure
/// on a declared journal returns a status record with `journal_unreadable` and
/// `content_incomplete` set, so a journal that could not be read never reads as
/// a clean one.
fn build_journal_artifacts(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    source: &Arc<dyn DataSource>,
    sb: &Superblock,
    groups: &[BlockGroupDescriptor],
) -> Option<Artifact> {
    if sb.compat_features & EXT4_FEATURE_COMPAT_HAS_JOURNAL == 0 {
        return None;
    }
    let journal_inum = if sb.journal_inum != 0 {
        sb.journal_inum
    } else {
        8 // on-disk default
    };

    // The COMPAT bit says this volume HAS a journal. From here on, returning
    // None would publish "nothing to note about the journal" for a journal we
    // simply could not read — a clean empty journal reports `clean: true`, so
    // the two were indistinguishable (B7-012). Every failure below emits a
    // status record instead.
    let unreadable = |reason: &str| -> Option<Artifact> {
        warn!(
            "ext4 journal (inode {}) could not be read: {}; the volume declares \
             a journal, so its transaction history is MISSING from this case",
            journal_inum, reason
        );
        Some(
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "ext4_journal",
                    "journal_inode": journal_inum,
                    "journal_unreadable": reason,
                    "transaction_count": 0,
                    "transactions": [],
                    "journal_walk_incomplete": true,
                    "journal_walk_incomplete_reason":
                        IncompleteReason::UnresolvedStructure.as_str(),
                    // Standard pair: the census, report and artifact UI read
                    // these; the journal_* keys are ext4-specific (B7-011).
                    "content_incomplete": true,
                    "content_incomplete_reason":
                        IncompleteReason::UnresolvedStructure.as_str(),
                    "inventory_incomplete": true,
                }),
            )
            .with_parent(parent_id),
        )
    };

    let Ok(inode) = Inode::parse(source.as_ref(), sb, groups, journal_inum) else {
        return unreadable("journal inode could not be parsed");
    };
    if inode.size() == 0 {
        return unreadable("journal inode has zero size");
    }
    let jsource = Ext4FileSource::new(source.clone(), sb.block_size, &inode);

    let mut block0 = vec![0u8; sb.block_size as usize];
    // Fail closed: a partial journal superblock would decode maxlen/first/start
    // from a zero tail and send the ring walk to fabricated offsets.
    if read_exact_or_fail(&jsource, 0, &mut block0, "ext4 journal superblock").is_err() {
        return unreadable("journal superblock could not be read");
    }
    let Some(jsb) = JournalSuperblock::parse(&block0) else {
        return unreadable("journal superblock magic/format not recognised");
    };

    // The journal is addressed in filesystem blocks through `jsource`, and the
    // log is walked in journal blocks: a disagreement puts every record at the
    // wrong offset, and an absurd value would be allocated as the read buffer.
    if jsb.blocksize != sb.block_size {
        return unreadable(&format!(
            "journal block size ({}) does not match the filesystem block size ({})",
            jsb.blocksize, sb.block_size
        ));
    }

    let walk = walk_journal(&jsource, &jsb);
    let transactions: Vec<serde_json::Value> = walk
        .transactions
        .iter()
        .map(|t| {
            json!({
                "sequence": t.sequence,
                "blocks": t.blocks,
                "revoked": t.revoked,
            })
        })
        .collect();

    let mut metadata = json!({
        "type": "ext4_journal",
        "journal_inode": journal_inum,
        "journal_blocksize": jsb.blocksize,
        "journal_maxlen": jsb.maxlen,
        "journal_first": jsb.first,
        "journal_sequence": jsb.sequence,
        "journal_start": jsb.start,
        "clean": jsb.start == 0,
        "transaction_count": transactions.len(),
        "transactions": transactions,
    });
    if let Some(reason) = walk.incomplete {
        // The list below is a prefix of the log, not the log. Without this an
        // examiner would read "these are the transactions" where the truth is
        // "these are the transactions we got to" (BUG-238 class).
        metadata["journal_walk_incomplete"] = json!(true);
        metadata["journal_walk_incomplete_reason"] = json!(reason.as_str());
        // The ext4-specific keys above are read by nothing outside this crate.
        // The incompleteness census, the court report and the artifact UI all
        // key off the standard pair, so a truncated journal history was absent
        // from every one of them (B7-011).
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!(reason.as_str());
        metadata["inventory_incomplete"] = json!(true);
    }

    Some(Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id))
}

#[cfg(test)]
mod tests;
