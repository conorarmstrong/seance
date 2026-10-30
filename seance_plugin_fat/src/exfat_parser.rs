// exFAT parser implementation

use super::exfat_structs::*;
use super::fat_parser::{
    build_allocation_buckets_from_bitmap, cluster_chain_to_runs, fat_slack_collector,
    offer_file_slack, MAX_BITMAP_BYTES,
};
use super::fat_structs::DirectoryEntry;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use byteorder::{ByteOrder, LittleEndian};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    free_space::{emit_free_regions, AllocationBitmap, BitMeaning, FreeSpaceLabels},
    io::{read_exact_or_fail, read_full},
};
use serde_json::json;
use std::collections::HashSet;
use std::fmt::Debug;
use std::io;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Safety cap on the number of clusters walked in a single exFAT chain.
const MAX_EXFAT_CHAIN_CLUSTERS: usize = 100_000;

pub fn parse_exfat_filesystem(
    artifact: &Artifact,
    data_source: Arc<dyn DataSource>,
) -> Result<Vec<Artifact>> {
    let mut produced_artifacts = Vec::new();

    // Read boot sector. A short `read_at` would leave the pre-zeroed tail to be
    // decoded as real geometry: cluster heap offset, cluster size and cluster
    // count all come from bytes past offset 64, so a partial sector places every
    // later read at a fabricated offset.
    let mut boot_sector_data = vec![0u8; 512];
    read_exact_or_fail(
        data_source.as_ref(),
        0,
        &mut boot_sector_data,
        "exFAT boot sector",
    )?;

    // Parse exFAT boot sector
    let boot_sector = match ExFatBootSector::parse(&boot_sector_data) {
        Ok(bs) => bs,
        Err(e) => {
            debug!("Failed to parse exFAT boot sector: {}", e);
            return Ok(Vec::new());
        }
    };

    info!(
        "Detected exFAT filesystem: {} clusters, root at cluster {}",
        boot_sector.cluster_count, boot_sector.root_directory_cluster
    );

    // The FileSystem artifact is this module's input (created by the partition
    // plugin); emit files and the allocation map as its children. Minting a
    // second FileSystem re-triggers the FAT module on our own output and
    // cascades without bound. exFAT geometry rides on the allocation-map record.
    let fs_id = artifact.id;

    // Read FAT table for cluster chain traversal
    let fat_table = match ExFatTable::read(&boot_sector, &data_source) {
        Ok(table) => table,
        Err(e) => {
            warn!("Failed to read FAT table: {}", e);
            return Ok(produced_artifacts);
        }
    };

    // Allocation map from the on-disk Allocation Bitmap (bit 0 = cluster 2).
    // Omitted when the bitmap entry or its clusters cannot be read.
    let bitmap_entry = find_allocation_bitmap(&boot_sector, &data_source, &fat_table);
    if let Some(bitmap_entry) = &bitmap_entry {
        if let Some(map_artifact) = build_exfat_allocation_map(
            artifact.case_id,
            fs_id,
            &boot_sector,
            &data_source,
            &fat_table,
            bitmap_entry,
        ) {
            produced_artifacts.push(map_artifact.0);
            // The free clusters as regions the automatic carver reads (§5.4).
            produced_artifacts.extend(map_artifact.1);
        }
    }

    // Parse root directory
    let (root_entries, root_complete) = match parse_exfat_directory(
        &boot_sector,
        &data_source,
        &fat_table,
        boot_sector.root_directory_cluster,
    ) {
        Ok(result) => result,
        Err(e) => {
            warn!("Failed to parse root directory: {}", e);
            return Ok(produced_artifacts);
        }
    };

    info!("Found {} entries in root directory", root_entries.len());

    if !root_complete {
        // The allocation-map record is this module's volume-level artifact, so
        // it carries the honesty flag for the root listing. It is not guaranteed
        // to exist — the bitmap entry lives in the root directory, which is
        // exactly what was cut short — so mint a record when it is absent. A
        // flag that only appears when some other artifact happens to be present
        // is not a flag: an unmarked root listing reads as the whole of the
        // volume's top level.
        warn!("exFAT root directory listing is incomplete");
        let map_idx = produced_artifacts.iter().position(|a| {
            a.metadata.get("type").and_then(|t| t.as_str()) == Some("allocation_map")
        });
        match map_idx {
            Some(i) => {
                produced_artifacts[i].metadata["directory_parse_incomplete"] = json!(true);
                produced_artifacts[i].metadata["directory_parse_incomplete_reason"] =
                    json!("exfat_root_chain_incomplete");
            }
            None => produced_artifacts.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "exfat_volume_walk",
                        "directory_parse_incomplete": true,
                        "directory_parse_incomplete_reason": "exfat_root_chain_incomplete",
                    }),
                )
                .with_parent(artifact.id),
            ),
        }
    }

    // Process directory entries recursively
    // The trailing bool: the set was read out of a deleted directory (HUNT-278).
    let to_process: Vec<(ExFatDirectoryEntrySet, Uuid, String, bool)> = root_entries
        .into_iter()
        .map(|e| {
            let name = e.get_filename();
            let path = format!("/{}", name);
            (e, fs_id, path, false)
        })
        .collect();

    // Directory clusters already descended, so a corrupt or hostile image whose
    // directory points back at an ancestor cannot loop forever.
    let mut visited_dirs: HashSet<u32> = HashSet::new();

    // File slack (HUNT-124): one region per live file whose tail holds bytes.
    let slack_cluster_size =
        boot_sector.sectors_per_cluster as u64 * boot_sector.bytes_per_sector as u64;
    let mut slack = fat_slack_collector("exFAT", slack_cluster_size);

    // Live entry sets are taken before any deleted one, so that a deleted directory whose first
    // cluster was handed to a new directory when it was freed finds that directory already read
    // and says so, instead of being skipped silently or read as the live directory's twin.
    let (initially_deleted, initially_live): (Vec<_>, Vec<_>) = to_process
        .into_iter()
        .partition(|(entry_set, _, _, in_deleted)| entry_set.deleted || *in_deleted);
    let mut to_process = initially_live;
    let mut deferred = initially_deleted;
    // Entry sets already listed, by (first cluster, length, name), so the orphan scan below names only
    // what no listing reached.
    let mut listed: HashSet<(u32, u64, String)> = HashSet::new();
    let mut orphan_scan_done = false;
    loop {
        while let Some((mut entry_set, parent_id, path, in_deleted_directory)) =
            to_process.pop().or_else(|| deferred.pop())
        {
            listed.insert((
                entry_set.stream_extension.first_cluster,
                entry_set.stream_extension.data_length,
                entry_set.get_filename(),
            ));
            // Everything read out of a deleted directory is deleted, whatever its
            // own type bytes say.
            entry_set.deleted |= in_deleted_directory;
            if let Some(mut file_artifact) = create_exfat_artifact(
                artifact.case_id,
                parent_id,
                &entry_set,
                &path,
                &data_source,
                &boot_sector,
                &fat_table,
            ) {
                let is_directory = entry_set.file_entry.is_directory();
                if !is_directory && !entry_set.deleted {
                    offer_file_slack(
                        &mut slack,
                        artifact,
                        &data_source,
                        &file_artifact,
                        slack_cluster_size,
                    );
                }
                let dir_artifact_index = produced_artifacts.len();
                if entry_set.after_end_marker {
                    file_artifact.metadata["recovered_from_directory_slack"] = json!(true);
                    file_artifact.metadata["directory_slack_basis"] = json!(
                        "read from the cluster of the end-of-directory marker, behind the marker, \
                     state unknown: an earlier state of this directory left behind, so whether \
                     this entry was ever live, or when, is not shown; its SetChecksum verifies"
                    );
                }
                if let Some(head) = orphan_head_of(&path) {
                    file_artifact.metadata["orphan_directory_head_cluster"] = json!(head);
                    file_artifact.metadata["orphan_directory_basis"] = json!(
                        "found by scanning the free clusters for a deleted entry set no directory \
                     lists; the directory that held it is not named by any entry, so its path, \
                     name and length are unknown, and the listing runs to the end of the FAT \
                     chain the driver left"
                    );
                }
                if in_deleted_directory {
                    file_artifact.metadata["directory_content_basis"] =
                        json!("set_checksum_validated");
                    file_artifact.metadata["directory_content_basis_detail"] = json!(
                        "read from a deleted directory's clusters, which are assumed to be the \
                     consecutive clusters its NoFatChain stream extension described, or the \
                     clusters the FAT entries it left behind lead through (the directory record \
                     says which: directory_chain_basis); this entry set's own SetChecksum verifies"
                    );
                }
                produced_artifacts.push(file_artifact);

                // If this is a directory we have not seen, parse its contents.
                let dir_cluster = entry_set.stream_extension.first_cluster;
                if is_directory
                    && entry_set.deleted
                    && dir_cluster >= 2
                    && visited_dirs.contains(&dir_cluster)
                {
                    // First cluster already the first cluster of a directory the walk read.
                    let meta = &mut produced_artifacts[dir_artifact_index].metadata;
                    meta["directory_parse_incomplete"] = json!(true);
                    meta["directory_parse_incomplete_reason"] =
                        json!("exfat_deleted_directory_unverified");
                    meta["directory_content_reallocated"] = json!(true);
                    meta["directory_content_basis"] = json!(
                        "the first cluster of this deleted directory is now the first cluster of \
                     another directory on the volume, so nothing was read from it as this \
                     directory's content; its entries cannot be listed from this volume"
                    );
                } else if is_directory && dir_cluster >= 2 && visited_dirs.insert(dir_cluster) {
                    let meta_index = dir_artifact_index;
                    let scan = if entry_set.deleted {
                        // A deleted directory's clusters may since have been
                        // reallocated; what they hold now is not that directory's
                        // listing. Its FAT chain, if it had one, is freed, so only a
                        // NoFatChain directory can be located at all; the first
                        // cluster must still be free in the allocation bitmap, and
                        // every set read must verify its own SetChecksum.
                        let first_cluster_zero = exfat_first_cluster_is_zero(
                            &boot_sector,
                            &data_source,
                            dir_cluster,
                            bitmap_entry.as_ref().is_some_and(|b| {
                                exfat_cluster_in_use(
                                    &boot_sector,
                                    &data_source,
                                    &fat_table,
                                    b,
                                    dir_cluster,
                                ) == Some(false)
                            }),
                        );
                        let meta = &mut produced_artifacts[meta_index].metadata;
                        let stream = &entry_set.stream_extension;
                        if first_cluster_zero {
                            // Free in the bitmap and all zero: nothing to read, and nothing
                            // there to mistake for another file's bytes. An empty directory
                            // looks the same; the volume cannot tell which it was.
                            meta["directory_parse_incomplete"] = json!(true);
                            meta["directory_parse_incomplete_reason"] =
                                json!("exfat_deleted_directory_zeroed");
                            meta["directory_content_zero"] = json!(true);
                            meta["directory_content_basis"] = json!(
                            "the first cluster of this deleted directory is free in the allocation \
                             bitmap and entirely zero, so there is no entry set to read: the \
                             directory held none, or its content was wiped (the Windows 11 exFAT \
                             driver was observed to zero a deleted directory's clusters); which it \
                             was cannot be told from this volume"
                        );
                            None
                        } else if bitmap_entry.as_ref().is_some_and(|b| {
                            exfat_cluster_in_use(
                                &boot_sector,
                                &data_source,
                                &fat_table,
                                b,
                                dir_cluster,
                            ) != Some(false)
                        }) {
                            meta["directory_parse_incomplete"] = json!(true);
                            meta["directory_parse_incomplete_reason"] =
                                json!("exfat_deleted_directory_unverified");
                            meta["directory_content_reallocated"] = json!(true);
                            None
                        } else {
                            let cluster_size = u64::from(boot_sector.sectors_per_cluster)
                                * u64::from(boot_sector.bytes_per_sector);
                            let count = stream.data_length.div_ceil(cluster_size.max(1)).max(1);
                            let clusters = if stream.is_contiguous() {
                                ExFatDirClusters::ContiguousDeleted {
                                    start: dir_cluster,
                                    count: count.min(u64::from(u32::MAX)) as u32,
                                }
                            } else {
                                let (clusters, complete) =
                                    stale_fat_chain(&fat_table, dir_cluster, count, |c| {
                                        bitmap_entry.as_ref().is_some_and(|b| {
                                            exfat_cluster_in_use(
                                                &boot_sector,
                                                &data_source,
                                                &fat_table,
                                                b,
                                                c,
                                            ) == Some(false)
                                        })
                                    });
                                meta["directory_chain_basis"] = json!("stale_fat_chain");
                                meta["directory_clusters_read"] = json!(clusters.len());
                                ExFatDirClusters::StaleChain { clusters, complete }
                            };
                            Some(scan_exfat_directory(
                                &boot_sector,
                                &data_source,
                                &fat_table,
                                clusters,
                            ))
                        }
                    } else {
                        Some(scan_exfat_directory(
                            &boot_sector,
                            &data_source,
                            &fat_table,
                            ExFatDirClusters::Chain(dir_cluster),
                        ))
                    };
                    match scan {
                        None => {}
                        Some(Ok(scan)) => {
                            let meta = &mut produced_artifacts[meta_index].metadata;
                            if entry_set.deleted
                                && scan.entry_sets.is_empty()
                                && scan.checksum_refused == 0
                            {
                                // The cluster is free, is not all zero (that case is caught before
                                // the scan) and yielded no entry set: it holds something other than
                                // this directory's entries now, so an empty list says nothing about
                                // what the directory held.
                                meta["directory_parse_incomplete"] = json!(true);
                                meta["directory_parse_incomplete_reason"] =
                                    json!("exfat_deleted_directory_unverified");
                                meta["directory_content_unrecognised"] = json!(true);
                                meta["directory_content_basis"] = json!(
                                "the first cluster of this deleted directory is free but holds no \
                                 entry set and is not all zero, so nothing was read from it"
                            );
                            }
                            if !scan.complete {
                                // A prefix of the directory must never read as the
                                // whole of it (B2-096).
                                meta["directory_parse_incomplete"] = json!(true);
                                meta["directory_parse_incomplete_reason"] =
                                    json!("exfat_chain_incomplete");
                            }
                            if scan.checksum_refused > 0 {
                                meta["directory_entry_sets_refused"] = json!(scan.checksum_refused);
                                meta["directory_entry_sets_refused_reason"] =
                                    json!("set_checksum_mismatch");
                                if meta.get("directory_parse_incomplete").is_none() {
                                    meta["directory_parse_incomplete"] = json!(true);
                                    meta["directory_parse_incomplete_reason"] =
                                        json!("exfat_deleted_directory_sets_refused");
                                }
                            }
                            for subentry in scan.entry_sets {
                                let subname = subentry.get_filename();
                                let subpath = format!("{}/{}", path, subname);
                                // Flat model: parent every entry to the FileSystem,
                                // hierarchy in the path string (see file-entry-flat-
                                // model). Parenting to the directory breaks content
                                // resolution.
                                let item = (subentry, fs_id, subpath, entry_set.deleted);
                                if entry_set.deleted {
                                    deferred.push(item);
                                } else {
                                    to_process.push(item);
                                }
                            }
                        }
                        Some(Err(e)) => {
                            warn!("Failed to parse subdirectory at {}: {}", path, e);
                        }
                    }
                }
            }
        }

        // Deleted directories no entry points to (HUNT-278): looked for once, after every listing is read.
        if orphan_scan_done {
            break;
        }
        orphan_scan_done = true;
        let Some(bitmap) = bitmap_entry
            .as_ref()
            .and_then(|b| read_bitmap_bytes(&boot_sector, &data_source, &fat_table, b))
            .filter(|(_, complete, read)| {
                *complete && *read as u64 >= bitmap_entry.as_ref().map_or(0, |b| b.data_length)
            })
            .map(|(bytes, _, _)| bytes)
        else {
            break;
        };
        let (heads, capped) =
            orphan_directory_heads(&boot_sector, &data_source, &fat_table, &bitmap);
        if capped {
            produced_artifacts.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "exfat_orphan_scan",
                        "orphan_scan_incomplete": true,
                        "orphan_scan_incomplete_reason": "free_cluster_cap",
                        "orphan_scan_clusters_examined": MAX_ORPHAN_CLUSTERS_EXAMINED,
                    }),
                )
                .with_parent(artifact.id),
            );
        }
        for head in heads {
            let is_free = |c: u32| cluster_is_free(&bitmap, c);
            let (clusters, complete) =
                stale_fat_chain(&fat_table, head, MAX_DELETED_EXFAT_DIR_CLUSTERS, is_free);
            let Ok(scan) = scan_exfat_directory(
                &boot_sector,
                &data_source,
                &fat_table,
                ExFatDirClusters::StaleChain { clusters, complete },
            ) else {
                continue;
            };
            for set in scan.entry_sets {
                let key = (
                    set.stream_extension.first_cluster,
                    set.stream_extension.data_length,
                    set.get_filename(),
                );
                if listed.contains(&key) {
                    continue;
                }
                let path = format!("/{ORPHAN_ROOT_PREFIX}{head}]/{}", set.get_filename());
                deferred.push((set, fs_id, path, true));
            }
        }
        if deferred.is_empty() {
            break;
        }
    }

    let (slack_artifacts, _) = slack.finish(artifact);
    produced_artifacts.extend(slack_artifacts);

    Ok(produced_artifacts)
}

/// The path segment an orphaned directory's entries are listed under: `[orphan cluster N]`.
const ORPHAN_ROOT_PREFIX: &str = "[orphan cluster ";

/// The head cluster of the orphaned directory a path was listed under, if it was.
fn orphan_head_of(path: &str) -> Option<u32> {
    path.strip_prefix('/')?
        .strip_prefix(ORPHAN_ROOT_PREFIX)?
        .split(']')
        .next()?
        .parse()
        .ok()
}

/// Free clusters whose first bytes are examined for an orphaned directory, at most.
const MAX_ORPHAN_CLUSTERS_EXAMINED: u64 = 2_000_000;

/// Whether the allocation bitmap marks `cluster` free (bit 0 is cluster 2). A cluster past the bitmap
/// is not free: nothing is claimed of it.
fn cluster_is_free(bitmap: &[u8], cluster: u32) -> bool {
    let Some(index) = cluster.checked_sub(2) else {
        return false;
    };
    bitmap
        .get(index as usize / 8)
        .is_some_and(|b| b >> (index % 8) & 1 == 0)
}

/// The first clusters of deleted directories nothing lists: a free cluster that starts a deleted file
/// entry set (`0x05`, a `0x40` stream extension, a `0x41` name) and that no free cluster's stale FAT link
/// leads to, so it is the head of its chain and not a later cluster of a directory already read. The
/// second value is true when the cap on clusters examined stopped the scan.
fn orphan_directory_heads(
    boot_sector: &ExFatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &ExFatTable,
    bitmap: &[u8],
) -> (Vec<u32>, bool) {
    let last = u64::from(boot_sector.cluster_count).min(bitmap.len() as u64 * 8) + 1;
    let mut linked_to: HashSet<u32> = HashSet::new();
    let mut candidates: Vec<u32> = Vec::new();
    let mut examined = 0u64;
    let mut capped = false;
    for cluster in 2..=last.min(u64::from(u32::MAX)) as u32 {
        if !cluster_is_free(bitmap, cluster) {
            continue;
        }
        if let Some(next) = fat_table.get_next_cluster(cluster) {
            linked_to.insert(next);
        }
        if examined >= MAX_ORPHAN_CLUSTERS_EXAMINED {
            capped = true;
            continue;
        }
        examined += 1;
        let mut head = [0u8; 96];
        if read_full(
            data_source.as_ref(),
            boot_sector.cluster_to_offset(cluster),
            &mut head,
        ) < head.len()
        {
            continue;
        }
        let secondary = head[1];
        if head[0] == 0x05 && (2..=18).contains(&secondary) && head[32] == 0x40 && head[64] == 0x41
        {
            candidates.push(cluster);
        }
    }
    candidates.retain(|c| !linked_to.contains(c));
    (candidates, capped)
}

/// The clusters of a deleted directory that used a FAT chain, followed through the FAT entries
/// its driver left: at most `count` (what its DataLength needs), stopping at a link that is not a
/// cluster of the heap, a cluster already taken, or a cluster that is in use again
/// (`is_free`). The second value is false when fewer than `count` were found, so the listing
/// is flagged as a prefix rather than read as the whole directory.
pub(crate) fn stale_fat_chain(
    fat_table: &ExFatTable,
    start: u32,
    count: u64,
    is_free: impl Fn(u32) -> bool,
) -> (Vec<u32>, bool) {
    let count = count.min(MAX_DELETED_EXFAT_DIR_CLUSTERS);
    let mut clusters: Vec<u32> = Vec::new();
    let mut current = start;
    while (clusters.len() as u64) < count {
        if current < 2 || clusters.contains(&current) || !is_free(current) {
            break;
        }
        clusters.push(current);
        match fat_table.get_next_cluster(current) {
            Some(next) => current = next,
            None => break,
        }
    }
    let complete = clusters.len() as u64 == count;
    (clusters, complete)
}

/// Whether a deleted directory's first cluster is free (`free_in_bitmap`, from the allocation
/// bitmap) and every byte of it is zero.
fn exfat_first_cluster_is_zero(
    boot_sector: &ExFatBootSector,
    data_source: &Arc<dyn DataSource>,
    cluster: u32,
    free_in_bitmap: bool,
) -> bool {
    if !free_in_bitmap {
        return false;
    }
    let cluster_size =
        boot_sector.sectors_per_cluster as usize * boot_sector.bytes_per_sector as usize;
    let offset = boot_sector.cluster_to_offset(cluster);
    let mut bytes = vec![0u8; cluster_size];
    seance_core::io::read_exact_or_fail(
        data_source.as_ref(),
        offset,
        &mut bytes,
        "deleted exFAT directory first cluster",
    )
    .is_ok()
        && bytes.iter().all(|&b| b == 0)
}

// exFAT FAT table for cluster chain traversal
pub(crate) struct ExFatTable {
    pub(crate) table_data: Vec<u8>,
}

impl ExFatTable {
    fn read(boot_sector: &ExFatBootSector, data_source: &Arc<dyn DataSource>) -> Result<Self> {
        // fat_length and bytes_per_sector are attacker-controlled header fields;
        // a bogus pair (e.g. 0xFFFFFFFF * 4096) would request a multi-terabyte
        // allocation and abort the process (OOM is not caught by catch_unwind).
        // Compute with checked arithmetic and never allocate more than the data
        // source can provide. Mirrors FatTable::read in fat_parser.rs.
        let fat_size_bytes = (boot_sector.fat_length as u64)
            .checked_mul(boot_sector.bytes_per_sector as u64)
            .ok_or_else(|| anyhow::anyhow!("exFAT FAT size overflow"))?
            .min(data_source.size()) as usize;
        let fat_offset = boot_sector.fat_offset as u64 * boot_sector.bytes_per_sector as u64;

        let mut table_data = vec![0u8; fat_size_bytes];
        // Fail closed on a short read: a zero-padded tail reads as free/terminated
        // clusters and silently truncates chains through the missing region
        // (BUG-155). `read_full` gathers the table first, because a single
        // `read_at` returning less than the whole FAT is ordinary on a windowed
        // source and must not be mistaken for a damaged volume.
        let n = read_full(data_source.as_ref(), fat_offset, &mut table_data);
        if n < fat_size_bytes {
            return Err(anyhow::anyhow!(
                "exFAT FAT table short read ({} of {} bytes) at offset {}",
                n,
                fat_size_bytes,
                fat_offset
            ));
        }

        Ok(ExFatTable { table_data })
    }

    fn get_next_cluster(&self, cluster: u32) -> Option<u32> {
        let offset = (cluster as usize) * 4;
        if offset + 4 > self.table_data.len() {
            return None;
        }

        let value = LittleEndian::read_u32(&self.table_data[offset..offset + 4]);

        // exFAT uses full 32-bit entries
        // End of chain: 0xFFFFFFFF
        // Bad cluster: 0xFFFFFFF7
        // Free cluster: 0x00000000
        if value >= 0xFFFFFFF7 || value == 0 {
            None
        } else {
            Some(value)
        }
    }

    /// Follow a cluster chain, returning the clusters plus whether the walk
    /// reached a real end-of-chain marker. `false` means the safety cap or a
    /// cycle cut the chain short, so it does not cover the whole file
    /// (BUG-210).
    fn follow_chain(&self, start_cluster: u32) -> (Vec<u32>, bool) {
        let mut clusters = Vec::new();
        let mut visited = HashSet::new();
        let mut current = start_cluster;
        let mut complete = true;

        loop {
            // Safety cap: the chain continues past this point on disk, so what
            // we collected is an incomplete view of the file.
            if clusters.len() >= MAX_EXFAT_CHAIN_CLUSTERS {
                complete = false;
                break;
            }

            if current < 2 {
                break;
            }

            // A cluster chain must never revisit a cluster; break at the first
            // repeat so a cyclic/self-referential FAT (crafted evidence) cannot
            // re-read the same cluster up to the iteration cap. Such a chain
            // never terminates properly, so it is not complete either.
            if !visited.insert(current) {
                complete = false;
                break;
            }

            clusters.push(current);

            match self.get_next_cluster(current) {
                Some(next) => current = next,
                None => break,
            }
        }

        (clusters, complete)
    }
}

// DataSource for exFAT file content - reads from cluster chain
#[derive(Debug)]
struct ExFatFileDataSource {
    underlying: Arc<dyn DataSource>,
    boot_sector: ExFatBootSector,
    cluster_chain: Vec<u32>,
    file_size: u64,
    /// ValidDataLength: how far into the stream user data was actually written.
    /// The exFAT specification (7.4.4) says the bytes in
    /// `[ValidDataLength, DataLength)` are NOT file data and that an
    /// implementation "shall return zeros" for reads beyond it — those clusters
    /// still hold whatever the previous tenant left there. Serving that residue
    /// as file content disagrees with every OS reader and corrupts the hash of
    /// the file (BUG-273).
    valid_size: u64,
}

impl ExFatFileDataSource {
    fn new(
        underlying: Arc<dyn DataSource>,
        boot_sector: ExFatBootSector,
        cluster_chain: Vec<u32>,
        file_size: u64,
        valid_size: u64,
    ) -> Self {
        Self {
            underlying,
            boot_sector,
            cluster_chain,
            file_size,
            valid_size: valid_size.min(file_size),
        }
    }
}

impl DataSource for ExFatFileDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.file_size {
            return Ok(0);
        }

        let cluster_size = (self.boot_sector.sectors_per_cluster as u64)
            * (self.boot_sector.bytes_per_sector as u64);
        let to_read = std::cmp::min(buf.len() as u64, self.file_size - offset) as usize;

        // Past ValidDataLength the file has no data: zero-fill instead of
        // handing back the residue still sitting in the allocated clusters.
        if offset >= self.valid_size {
            for b in &mut buf[..to_read] {
                *b = 0;
            }
            return Ok(to_read);
        }
        let valid_to_read = std::cmp::min(to_read as u64, self.valid_size - offset) as usize;

        let mut bytes_read = 0;
        let mut current_offset = offset;

        while bytes_read < valid_to_read {
            let cluster_index = (current_offset / cluster_size) as usize;
            if cluster_index >= self.cluster_chain.len() {
                break;
            }

            let cluster = self.cluster_chain[cluster_index];
            let offset_in_cluster = current_offset % cluster_size;
            let remaining_in_cluster = cluster_size - offset_in_cluster;
            let to_read_this_iteration =
                std::cmp::min(remaining_in_cluster, (valid_to_read - bytes_read) as u64) as usize;

            let cluster_offset = self.boot_sector.cluster_to_offset(cluster);
            let read_offset = cluster_offset + offset_in_cluster;

            let target_buf = &mut buf[bytes_read..bytes_read + to_read_this_iteration];
            let read = self.underlying.read_at(read_offset, target_buf)?;

            if read == 0 {
                break;
            }

            bytes_read += read;
            current_offset += read as u64;
        }

        // The unwritten tail inside this request is zeros, not residue.
        if bytes_read == valid_to_read && to_read > valid_to_read {
            for b in &mut buf[valid_to_read..to_read] {
                *b = 0;
            }
            return Ok(to_read);
        }

        Ok(bytes_read)
    }

    fn size(&self) -> u64 {
        self.file_size
    }
}

/// Scan the root directory for the Allocation Bitmap entry (type 0x81).
fn find_allocation_bitmap(
    boot_sector: &ExFatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &ExFatTable,
) -> Option<ExFatAllocationBitmap> {
    if boot_sector.root_directory_cluster < 2 {
        return None;
    }
    // Only a prefix of the root chain is needed to find the bitmap entry, which
    // lives in the first cluster of a conforming volume; an incomplete chain
    // simply means the entry may not be found, and the caller omits the map.
    let (cluster_chain, _chain_complete) =
        fat_table.follow_chain(boot_sector.root_directory_cluster);
    let cluster_size =
        boot_sector.sectors_per_cluster as usize * boot_sector.bytes_per_sector as usize;
    let entries_per_cluster = cluster_size / 32;

    for cluster in cluster_chain {
        let cluster_offset = boot_sector.cluster_to_offset(cluster);
        for i in 0..entries_per_cluster {
            // A partially read entry is not an entry: its zero tail would decode
            // as EndOfDirectory and abandon the search for the bitmap, leaving
            // the volume with no allocation map at all.
            let mut entry_data = [0u8; 32];
            if read_full(
                data_source.as_ref(),
                cluster_offset + (i as u64 * 32),
                &mut entry_data,
            ) < 32
            {
                return None;
            }
            match ExFatEntryType::from(entry_data[0]) {
                ExFatEntryType::EndOfDirectory => return None,
                ExFatEntryType::AllocationBitmap => {
                    if let Ok(entry) = ExFatAllocationBitmap::parse(&entry_data) {
                        if entry.is_first_bitmap() {
                            return Some(entry);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// The allocation bitmap's bytes, whether its FAT chain reached an end, and how many bytes were read.
/// `None` when it has no clusters or nothing could be read.
fn read_bitmap_bytes(
    boot_sector: &ExFatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &ExFatTable,
    bitmap_entry: &ExFatAllocationBitmap,
) -> Option<(Vec<u8>, bool, usize)> {
    if bitmap_entry.first_cluster < 2 || bitmap_entry.data_length == 0 {
        return None;
    }
    let (chain, chain_complete) = fat_table.follow_chain(bitmap_entry.first_cluster);
    if chain.is_empty() {
        return None;
    }

    let read_len = bitmap_entry.data_length.min(MAX_BITMAP_BYTES);
    // The allocation bitmap has no ValidDataLength of its own: every byte of it
    // is live metadata, so the valid length is its whole length.
    let source = ExFatFileDataSource::new(
        data_source.clone(),
        boot_sector.clone(),
        chain,
        read_len,
        read_len,
    );
    let mut bitmap = vec![0u8; read_len as usize];
    // Gather the whole bitmap: a short read from the underlying image ends
    // `ExFatFileDataSource::read_at` early, and the shortfall below drives
    // `allocation_map_incomplete`. A bitmap cut short would report the rest of
    // the volume as free space, which an examiner reads as "nothing was ever
    // written here".
    let bytes_read = read_full(&source, 0, &mut bitmap);
    if bytes_read == 0 {
        return None;
    }
    bitmap.truncate(bytes_read);
    Some((bitmap, chain_complete, bytes_read))
}

/// Read the Allocation Bitmap cluster chain and emit the downsampled
/// allocation map as a ParsedRecord child of the FileSystem artifact.
#[allow(clippy::type_complexity)]
fn build_exfat_allocation_map(
    case_id: Uuid,
    fs_id: Uuid,
    boot_sector: &ExFatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &ExFatTable,
    bitmap_entry: &ExFatAllocationBitmap,
) -> Option<(Artifact, Vec<Artifact>)> {
    let (bitmap, chain_complete, bytes_read) =
        read_bitmap_bytes(boot_sector, data_source, fat_table, bitmap_entry)?;

    // Bit i (LSB-first) covers cluster i + 2
    let total_clusters = (boot_sector.cluster_count as u64).min(bitmap.len() as u64 * 8);
    if total_clusters == 0 {
        return None;
    }
    let (buckets, clusters_per_bucket) =
        build_allocation_buckets_from_bitmap(total_clusters, &bitmap);

    let cluster_size = boot_sector.sectors_per_cluster as u64 * boot_sector.bytes_per_sector as u64;
    let mut metadata = json!({
        "type": "allocation_map",
        "allocation_bitmap_b64": BASE64.encode(&buckets),
        "allocation_clusters_per_bucket": clusters_per_bucket,
        "allocation_total_clusters": total_clusters,
        "allocation_cluster_size": cluster_size,
        // exFAT geometry, kept here since this module no longer mints its
        // own FileSystem artifact (the partition plugin owns that).
        "fs_type": "exFAT",
        "bytes_per_sector": boot_sector.bytes_per_sector,
        "sectors_per_cluster": boot_sector.sectors_per_cluster,
        "cluster_count": boot_sector.cluster_count,
        "volume_serial": format!("{:08X}", boot_sector.volume_serial_number),
    });
    // A bitmap read from a truncated chain (or capped at MAX_BITMAP_BYTES)
    // describes only the clusters it covers. Unread clusters would otherwise
    // render as free space an examiner could take as "nothing was ever here".
    if !chain_complete || bytes_read < bitmap_entry.data_length as usize {
        metadata["allocation_map_incomplete"] = json!(true);
    }

    // The same bytes as regions the carver reads (ROADMAP §5.4).
    //
    // exFAT's first bit is cluster **2** and cluster 2 sits at the start of the
    // cluster heap, not at the start of the volume, so the base is
    // `cluster_to_offset(2)` and not zero. A base of zero here would be a
    // plausible offset in the wrong place for every region on the volume.
    //
    // `cluster_count` rather than the clamped `total_clusters` above: the
    // volume's own geometry is what it has, and the emitter works out for
    // itself how much of it the held bytes can speak for.
    let parent = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata);
    let bitmap_view = AllocationBitmap {
        bits: &bitmap,
        total_clusters: (boot_sector.cluster_count as u64).saturating_add(2),
        cluster_size,
        first_cluster: 2,
        first_cluster_offset: boot_sector.cluster_to_offset(2),
        bit_meaning: BitMeaning::SetIsAllocated,
    };
    let (free_regions, free_outcome) = emit_free_regions(
        &parent,
        data_source,
        &bitmap_view,
        FreeSpaceLabels {
            filesystem: "exFAT",
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
    Some((
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(fs_id),
        free_regions
            .into_iter()
            .map(|region| region.with_parent(fs_id))
            .collect(),
    ))
}

/// Read exactly one 32-byte directory entry at `offset`.
///
/// A short read is a hard failure: the zero-padded tail would otherwise parse as
/// a real entry (an end-of-directory marker, or a fabricated name/size/cluster)
/// (BUG-187).
fn read_dir_entry(data_source: &dyn DataSource, offset: u64) -> io::Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    let mut filled = 0usize;
    while filled < 32 {
        match data_source.read_at(offset + filled as u64, &mut buf[filled..])? {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "short read of exFAT directory entry at offset {} ({} of 32 bytes)",
                        offset, filled
                    ),
                ))
            }
            n => filled += n,
        }
    }
    Ok(buf)
}

/// Parse an exFAT directory, returning its entry sets plus whether the listing
/// covers the whole directory.
///
/// `false` means the walk stopped before the directory did: the FAT chain hit
/// the safety cap or a cycle, an entry could not be read, or an entry set ran
/// past the clusters the chain describes. The caller stamps the directory so a
/// silent prefix is never presented as a complete listing — the file-content
/// path already refuses to do that, and a directory listing is evidence of
/// absence in exactly the same way.
fn parse_exfat_directory(
    boot_sector: &ExFatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &ExFatTable,
    first_cluster: u32,
) -> Result<(Vec<ExFatDirectoryEntrySet>, bool)> {
    let scan = scan_exfat_directory(
        boot_sector,
        data_source,
        fat_table,
        ExFatDirClusters::Chain(first_cluster),
    )?;
    Ok((scan.entry_sets, scan.complete))
}

/// Where a directory's clusters come from.
#[derive(Clone)]
enum ExFatDirClusters {
    /// Follow the FAT chain from the first cluster, as for a live directory.
    Chain(u32),
    /// A deleted directory that carried the NoFatChain flag: `count`
    /// consecutive clusters from `start`, its FAT entries having never existed.
    /// Entry sets are then kept only if their SetChecksum verifies.
    ContiguousDeleted { start: u32, count: u32 },
    /// A deleted directory that used a FAT chain, followed through the FAT entries its driver
    /// left behind (Linux's `exfat` frees the clusters in the allocation bitmap and leaves the
    /// FAT as it was). `complete` is false when the walk stopped before the clusters its
    /// DataLength needs. Entry sets are kept only if their SetChecksum verifies.
    StaleChain { clusters: Vec<u32>, complete: bool },
}

/// What reading an exFAT directory produced.
struct ExFatDirScan {
    entry_sets: Vec<ExFatDirectoryEntrySet>,
    complete: bool,
    /// Entry sets that were read and refused because their SetChecksum did not
    /// verify (only counted for [`ExFatDirClusters::ContiguousDeleted`]).
    checksum_refused: u64,
}

/// The exFAT SetChecksum of an entry set: a 16-bit rotate-right-and-add over
/// every byte of the set except bytes 2 and 3 of the primary entry, which hold
/// the checksum itself.
pub(crate) fn exfat_set_checksum(raw: &[[u8; 32]]) -> u16 {
    let mut sum: u16 = 0;
    for (e, entry) in raw.iter().enumerate() {
        for (b, &byte) in entry.iter().enumerate() {
            if e == 0 && (b == 2 || b == 3) {
                continue;
            }
            sum = sum.rotate_right(1).wrapping_add(u16::from(byte));
        }
    }
    sum
}

/// True when `stored` is the set's checksum either as the bytes stand or as
/// they stood before deletion cleared bit 7 (InUse) of every type byte. A driver
/// that deletes a set clears those bits and need not recompute the checksum, so
/// a deleted set verifies against the in-use form of its own bytes.
fn exfat_set_checksum_verifies(raw: &[[u8; 32]], stored: u16) -> bool {
    if exfat_set_checksum(raw) == stored {
        return true;
    }
    let mut in_use = raw.to_vec();
    for entry in &mut in_use {
        entry[0] |= 0x80;
    }
    exfat_set_checksum(&in_use) == stored
}

/// Whether the allocation bitmap marks `cluster` in use; `None` when the bit
/// cannot be read. Bit 0 of the bitmap is cluster 2.
fn exfat_cluster_in_use(
    boot_sector: &ExFatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &ExFatTable,
    bitmap: &ExFatAllocationBitmap,
    cluster: u32,
) -> Option<bool> {
    let index = u64::from(cluster.checked_sub(2)?);
    let byte_index = index / 8;
    if byte_index >= bitmap.data_length {
        return None;
    }
    let cluster_size =
        u64::from(boot_sector.sectors_per_cluster) * u64::from(boot_sector.bytes_per_sector);
    let (chain, _) = fat_table.follow_chain(bitmap.first_cluster);
    let holder = *chain.get(usize::try_from(byte_index / cluster_size.max(1)).ok()?)?;
    let mut byte = [0u8; 1];
    let at = boot_sector.cluster_to_offset(holder) + byte_index % cluster_size.max(1);
    if read_full(data_source.as_ref(), at, &mut byte) < 1 {
        return None;
    }
    Some(byte[0] >> (index % 8) & 1 == 1)
}

/// Clusters a deleted NoFatChain directory is read over, at most.
const MAX_DELETED_EXFAT_DIR_CLUSTERS: u64 = 4096;

fn scan_exfat_directory(
    boot_sector: &ExFatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &ExFatTable,
    clusters: ExFatDirClusters,
) -> Result<ExFatDirScan> {
    let mut entry_sets = Vec::new();
    let mut checksum_refused = 0u64;
    let validate = !matches!(clusters, ExFatDirClusters::Chain(_));

    let (cluster_chain, chain_complete) = match clusters {
        ExFatDirClusters::Chain(first_cluster) => {
            if first_cluster < 2 {
                return Ok(ExFatDirScan {
                    entry_sets,
                    complete: true,
                    checksum_refused,
                });
            }
            // Follow cluster chain for large directories
            fat_table.follow_chain(first_cluster)
        }
        ExFatDirClusters::StaleChain { clusters, complete } => (clusters, complete),
        ExFatDirClusters::ContiguousDeleted { start, count } => {
            let count = u64::from(count).min(MAX_DELETED_EXFAT_DIR_CLUSTERS);
            let end = u64::from(start) + count;
            // Past the cluster heap is not a directory; stop at the heap.
            let last = u64::from(boot_sector.cluster_count) + 1;
            let chain: Vec<u32> = (u64::from(start)..end.min(last + 1))
                .map(|c| c as u32)
                .collect();
            let complete = chain.len() as u64 == count;
            (chain, complete)
        }
    };
    let mut complete = chain_complete;
    let cluster_size =
        boot_sector.sectors_per_cluster as usize * boot_sector.bytes_per_sector as usize;
    let entries_per_cluster = cluster_size / 32;
    if entries_per_cluster == 0 || cluster_chain.is_empty() {
        return Ok(ExFatDirScan {
            entry_sets,
            complete,
            checksum_refused,
        });
    }

    // Entries are addressed by their index in the WHOLE chain. An entry set
    // (file entry + stream extension + name entries) can straddle a cluster
    // boundary, and the directory continues in the next FAT-chain cluster, not
    // the next physically adjacent one (BUG-187).
    let total_entries = cluster_chain.len().saturating_mul(entries_per_cluster);
    let entry_offset = |index: usize| -> u64 {
        let cluster = cluster_chain[index / entries_per_cluster];
        boot_sector.cluster_to_offset(cluster) + ((index % entries_per_cluster) as u64 * 32)
    };

    let mut i = 0usize;
    // Once the end marker is found, the entries behind it in its own cluster, up to this index.
    let mut slack_end: Option<usize> = None;
    while i < total_entries {
        if slack_end.is_some_and(|end| i >= end) {
            break;
        }
        let entry_data = match read_dir_entry(data_source.as_ref(), entry_offset(i)) {
            Ok(data) => data,
            Err(e) => {
                debug!("Failed to read directory entry {}: {}", i, e);
                complete = false;
                break;
            }
        };

        let entry_type = ExFatEntryType::from(entry_data[0]);

        match entry_type {
            ExFatEntryType::EndOfDirectory if slack_end.is_none() => {
                // What the marker's own cluster holds behind it may be an earlier state of the
                // directory; later clusters are not read.
                slack_end = Some((i / entries_per_cluster + 1) * entries_per_cluster);
                i += 1;
                continue;
            }
            // A zeroed tail behind the marker is the normal case and says nothing.
            ExFatEntryType::EndOfDirectory => {}
            ExFatEntryType::FileEntry | ExFatEntryType::DeletedFileEntry => {
                // A deleted set is byte-for-byte a live one with bit 7 of
                // each type byte cleared; it is read the same way and the
                // record says which it was (HUNT-067).
                let deleted = entry_type == ExFatEntryType::DeletedFileEntry || slack_end.is_some();
                // Parse file directory entry set
                let Ok(file_entry) = ExFatFileEntry::parse(&entry_data) else {
                    i += 1;
                    continue;
                };
                let secondary_count = file_entry.secondary_count as usize;
                if secondary_count == 0 {
                    // No stream extension: nothing describes the file's data.
                    debug!("exFAT file entry {} declares no secondary entries", i);
                    i += 1;
                    continue;
                }
                if slack_end.is_some_and(|end| i + secondary_count >= end) {
                    // Behind the marker a set must lie whole inside the marker's cluster.
                    i += 1;
                    continue;
                }
                if i + secondary_count >= total_entries {
                    // The set runs past the end of the directory's clusters.
                    // Emitting it would mean inventing the missing entries.
                    warn!(
                        "exFAT entry set at index {} needs {} secondary entries but the directory holds {}",
                        i, secondary_count, total_entries
                    );
                    complete = false;
                    break;
                }

                // Stream extension (first secondary entry).
                let stream_data = match read_dir_entry(data_source.as_ref(), entry_offset(i + 1)) {
                    Ok(data) => data,
                    Err(e) => {
                        warn!("Failed to read stream extension at entry {}: {}", i + 1, e);
                        complete = false;
                        break;
                    }
                };

                match ExFatStreamExtension::parse(&stream_data) {
                    Ok(stream_ext) => {
                        // File name entries (remaining secondary entries).
                        let mut file_names = Vec::new();
                        let mut raw_set = vec![entry_data, stream_data];
                        let mut unreadable = false;
                        for k in 1..secondary_count {
                            match read_dir_entry(data_source.as_ref(), entry_offset(i + 1 + k)) {
                                Ok(name_data) => {
                                    raw_set.push(name_data);
                                    if let Ok(name_entry) = ExFatFileName::parse(&name_data) {
                                        file_names.push(name_entry);
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to read name entry {} of the set at {}: {}",
                                        i + 1 + k,
                                        i,
                                        e
                                    );
                                    unreadable = true;
                                    break;
                                }
                            }
                        }
                        if unreadable {
                            // A half-read set yields a silently truncated file
                            // name; drop it rather than record a wrong one.
                            complete = false;
                            break;
                        }

                        if (validate || slack_end.is_some())
                            && !exfat_set_checksum_verifies(&raw_set, file_entry.set_checksum)
                        {
                            // Read from clusters only assumed to be this
                            // directory's: a set whose own checksum fails is
                            // not shown to be one. Behind the end marker a refusal is the
                            // ordinary case and counts against nothing.
                            if slack_end.is_none() {
                                checksum_refused += 1;
                            }
                            if slack_end.is_some() {
                                i += 1;
                                continue;
                            }
                        } else {
                            entry_sets.push(ExFatDirectoryEntrySet {
                                file_entry,
                                stream_extension: stream_ext,
                                file_names,
                                deleted,
                                after_end_marker: slack_end.is_some(),
                            });
                        }
                    }
                    Err(e) => debug!("Invalid stream extension at entry {}: {}", i + 1, e),
                }

                // The whole set is consumed whether or not it parsed.
                i += 1 + secondary_count;
                continue;
            }
            ExFatEntryType::VolumeLabel
            | ExFatEntryType::AllocationBitmap
            | ExFatEntryType::UpCaseTable
            | ExFatEntryType::VolumeGuid => {
                // Skip metadata entries
                debug!("Skipping metadata entry type: {:?}", entry_type);
            }
            _ => {
                // Skip unknown entries
            }
        }

        i += 1;
    }

    Ok(ExFatDirScan {
        entry_sets,
        complete,
        checksum_refused,
    })
}

fn create_exfat_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    entry_set: &ExFatDirectoryEntrySet,
    path: &str,
    underlying_source: &Arc<dyn DataSource>,
    boot_sector: &ExFatBootSector,
    fat_table: &ExFatTable,
) -> Option<Artifact> {
    let filename = entry_set.get_filename();

    // Skip "." and ".." if they exist
    if filename == "." || filename == ".." {
        return None;
    }

    let file_entry = &entry_set.file_entry;
    let stream_ext = &entry_set.stream_extension;

    // Parent directory path per the metadata contract
    let parent_path = match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    };

    let mut metadata = json!({
        "name": filename,
        "path": path,
        "parent_path": parent_path,
        "size": stream_ext.data_length,
        "valid_size": stream_ext.valid_data_length,
        "first_cluster": stream_ext.first_cluster,
        "is_directory": file_entry.is_directory(),
        "is_contiguous": stream_ext.is_contiguous(),
        "in_use": !entry_set.deleted,
        "attributes": {
            "read_only": (file_entry.file_attributes & 0x0001) != 0,
            "hidden": (file_entry.file_attributes & 0x0002) != 0,
            "system": (file_entry.file_attributes & 0x0004) != 0,
            "directory": (file_entry.file_attributes & 0x0010) != 0,
            "archive": (file_entry.file_attributes & 0x0020) != 0,
        },
        // RFC 3339 strings, matching ext4/FAT and what the grid row mapper
        // (Option<String>) expects — a raw integer 500s the file-grid query.
        "created": unix_to_rfc3339(exfat_timestamp_to_unix(file_entry.create_timestamp, file_entry.create_10ms, file_entry.create_utc_offset)),
        "modified": unix_to_rfc3339(exfat_timestamp_to_unix(file_entry.modify_timestamp, file_entry.modify_10ms, file_entry.modify_utc_offset)),
        "accessed": unix_to_rfc3339(exfat_timestamp_to_unix(file_entry.access_timestamp, 0, file_entry.access_utc_offset)),
    });

    if entry_set.deleted {
        // The directory still holds the whole entry — name, size, times, first
        // cluster — so those are reported as read. The clusters are another
        // matter: exFAT frees them on deletion and anything may hold them now,
        // so the content reachable through this record is not vouched for, in
        // the vocabulary every other filesystem parser uses for the same fact.
        metadata["deleted"] = json!(true);
        metadata["deleted_recovery_source"] = json!("exfat_directory_entry");
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] =
            json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str());
        metadata["content_incomplete_detail"] = json!(
            "this entry's InUse bits were cleared by deletion; its name, size and timestamps \
             are as the directory recorded them, but its clusters were freed and may since \
             hold another file's data"
        );
    }

    // When the per-timestamp UTC offset bytes are not marked valid, the
    // timestamps are local wall-clock time of an unknown timezone.
    if !(utc_offset_valid(file_entry.create_utc_offset)
        && utc_offset_valid(file_entry.modify_utc_offset)
        && utc_offset_valid(file_entry.access_utc_offset))
    {
        metadata["timezone"] = json!("local");
    }

    // Create DataSource for file content (not for directories)
    let data_source = if !file_entry.is_directory()
        && stream_ext.data_length > 0
        && stream_ext.first_cluster >= 2
    {
        // For contiguous files, we can optimize by creating a simple chain
        let (cluster_chain, chain_complete) = if stream_ext.is_contiguous() {
            // Calculate number of clusters needed
            let cluster_size = (boot_sector.sectors_per_cluster as u64
                * boot_sector.bytes_per_sector as u64)
                .max(1);
            // data_length is an attacker-controlled u64; with a small cluster_size
            // an inflated length would make num_clusters ~u32::MAX and collect()
            // allocate gigabytes. Cap by the clusters the volume could hold, and
            // stop the chain on cluster-number overflow (checked_add).
            let max_clusters = (underlying_source.size() / cluster_size).saturating_add(1);
            let needed = stream_ext.data_length.div_ceil(cluster_size);
            let num_clusters = needed.min(max_clusters) as u32;
            let chain: Vec<u32> = (0..num_clusters)
                .map_while(|i| stream_ext.first_cluster.checked_add(i))
                .collect();
            // The volume-size clamp (or a cluster-number overflow) can leave the
            // chain short of the recorded data_length; say so rather than let
            // the resolver zero-fill the tail.
            let covered = chain.len() as u64 >= needed;
            (chain, covered)
        } else {
            // Follow FAT chain for fragmented files
            fat_table.follow_chain(stream_ext.first_cluster)
        };

        if !cluster_chain.is_empty() {
            // Persist the cluster runs so the API can serve content from the image
            let cluster_size =
                boot_sector.sectors_per_cluster as u64 * boot_sector.bytes_per_sector as u64;
            // Bytes past ValidDataLength are not file data (exFAT spec 7.4.4):
            // they persist as a SPARSE run so the content resolver zero-fills
            // them, exactly as Windows/macOS read them, instead of re-serving
            // the residue of whatever previously occupied those clusters
            // (BUG-273). `valid_size` stays in the metadata either way, so the
            // residue is still locatable for a deliberate slack examination.
            //
            // A ValidDataLength of ZERO on a non-empty file is the one case not
            // acted on: per spec it means nothing was ever written, but it is
            // also what an implementation that never maintains the field leaves
            // behind, and zeroing a whole real file would destroy evidence
            // instead of merely over-reporting a tail. That ambiguity is
            // recorded and the clusters are served.
            let declared_valid = stream_ext.valid_data_length.min(stream_ext.data_length);
            if declared_valid == 0 && stream_ext.data_length > 0 {
                metadata["valid_data_length_zero"] = json!(true);
            }
            let valid_len = if declared_valid == 0 {
                stream_ext.data_length
            } else {
                declared_valid
            };
            let (runs_json, complete) = if valid_len < stream_ext.data_length {
                let mut runs: Vec<(Option<u64>, u64)> = Vec::new();
                let mut remaining = valid_len;
                for &cluster in &cluster_chain {
                    if remaining == 0 {
                        break;
                    }
                    let len = cluster_size.min(remaining);
                    runs.push((Some(boot_sector.cluster_to_offset(cluster)), len));
                    remaining -= len;
                }
                runs.push((None, stream_ext.data_length - valid_len));
                let (json_runs, runs_complete) =
                    seance_core::data_source::byte_runs_to_metadata(&runs);
                (json_runs, runs_complete && chain_complete && remaining == 0)
            } else {
                cluster_chain_to_runs(&cluster_chain, cluster_size, chain_complete, |c| {
                    boot_sector.cluster_to_offset(c)
                })
            };
            metadata["data_runs"] = runs_json;
            metadata["data_runs_complete"] = json!(complete);
            if !chain_complete {
                metadata["cluster_chain_incomplete"] = json!(true);
            }
            if valid_len < stream_ext.data_length {
                // Honesty flag: this file's tail hashes as zeros, not as the
                // bytes still present on the media.
                metadata["has_unwritten_tail"] = json!(true);
                metadata["unwritten_tail_bytes"] = json!(stream_ext.data_length - valid_len);
            }

            Some(Arc::new(ExFatFileDataSource::new(
                underlying_source.clone(),
                boot_sector.clone(),
                cluster_chain,
                stream_ext.data_length,
                valid_len,
            )) as Arc<dyn DataSource>)
        } else {
            None
        }
    } else {
        None
    };

    Some(
        Artifact::new(case_id, ArtifactType::FileEntry, data_source, metadata)
            .with_parent(parent_id),
    )
}

/// Decode an exFAT timestamp field to Unix seconds.
///
/// The 32-bit value is a DOS-style packed bitfield, NOT seconds since 1980:
///   bits 31-25 = years since 1980, 24-21 = month, 20-16 = day,
///   bits 15-11 = hour, 10-5 = minute, 4-0 = seconds/2.
/// The high 16 bits match the FAT date word and the low 16 bits the FAT time
/// word, so decoding reuses `DirectoryEntry::decode_datetime`.
///
/// `increment_10ms` (0-199, create/modify only) adds up to 1.99s of extra
/// precision; only whole seconds survive since metadata stores Unix seconds.
///
/// `utc_offset`: bit 7 = valid flag, bits 0-6 = signed offset from UTC in
/// 15-minute units. When valid, the stored local time is converted to true
/// UTC. When invalid, the value is local wall-clock time of an unknown zone
/// (the caller records "timezone": "local").
///
/// Returns None for zero/invalid timestamps rather than a fake epoch date.
fn exfat_timestamp_to_unix(timestamp: u32, increment_10ms: u8, utc_offset: u8) -> Option<i64> {
    let date = (timestamp >> 16) as u16;
    let time = (timestamp & 0xFFFF) as u16;
    let dt = DirectoryEntry::decode_datetime(date, time)?;

    let mut secs = dt.timestamp();
    secs += (increment_10ms as i64) * 10 / 1000;

    if utc_offset & 0x80 != 0 {
        // Sign-extend the 7-bit offset (15-minute units) and convert local -> UTC
        let units = ((utc_offset << 1) as i8) >> 1;
        secs -= units as i64 * 15 * 60;
    }

    Some(secs)
}

fn utc_offset_valid(utc_offset: u8) -> bool {
    utc_offset & 0x80 != 0
}

/// Render Unix seconds as an RFC 3339 string (None passes through), so file
/// metadata carries the same timestamp shape as ext4/FAT.
fn unix_to_rfc3339(secs: Option<i64>) -> Option<String> {
    use chrono::TimeZone;
    secs.and_then(|s| chrono::Utc.timestamp_opt(s, 0).single())
        .map(|dt| dt.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    /// Pack year/month/day/hour/min/sec into the exFAT 32-bit timestamp bitfield.
    fn pack(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> u32 {
        let date = ((year - 1980) << 9) | (month << 5) | day;
        let time = (hour << 11) | (min << 5) | (sec / 2);
        (date << 16) | time
    }

    #[test]
    fn decodes_packed_bitfield_not_seconds_since_1980() {
        let ts = pack(2021, 5, 15, 10, 30, 20);
        let expected = Utc
            .with_ymd_and_hms(2021, 5, 15, 10, 30, 20)
            .unwrap()
            .timestamp();
        assert_eq!(exfat_timestamp_to_unix(ts, 0, 0), Some(expected));
    }

    #[test]
    fn applies_10ms_increment_whole_seconds() {
        let ts = pack(2021, 5, 15, 10, 30, 20);
        let base = Utc
            .with_ymd_and_hms(2021, 5, 15, 10, 30, 20)
            .unwrap()
            .timestamp();
        // 150 * 10ms = 1.5s -> +1 whole second
        assert_eq!(exfat_timestamp_to_unix(ts, 150, 0), Some(base + 1));
        // 50 * 10ms = 0.5s -> +0
        assert_eq!(exfat_timestamp_to_unix(ts, 50, 0), Some(base));
    }

    #[test]
    fn applies_positive_utc_offset() {
        // UTC+2 = +8 units of 15 min; valid bit set
        let ts = pack(2021, 5, 15, 10, 30, 20);
        let base = Utc
            .with_ymd_and_hms(2021, 5, 15, 10, 30, 20)
            .unwrap()
            .timestamp();
        assert_eq!(
            exfat_timestamp_to_unix(ts, 0, 0x80 | 8),
            Some(base - 2 * 3600)
        );
    }

    #[test]
    fn applies_negative_utc_offset() {
        // UTC-5 = -20 units; 7-bit two's complement of -20 = 108 (0x6C)
        let ts = pack(2021, 5, 15, 10, 30, 20);
        let base = Utc
            .with_ymd_and_hms(2021, 5, 15, 10, 30, 20)
            .unwrap()
            .timestamp();
        assert_eq!(
            exfat_timestamp_to_unix(ts, 0, 0x80 | 0x6C),
            Some(base + 5 * 3600)
        );
    }

    #[test]
    fn invalid_offset_byte_leaves_value_unconverted() {
        let ts = pack(2021, 5, 15, 10, 30, 20);
        let base = Utc
            .with_ymd_and_hms(2021, 5, 15, 10, 30, 20)
            .unwrap()
            .timestamp();
        // Valid bit clear: offset bits must be ignored
        assert_eq!(exfat_timestamp_to_unix(ts, 0, 0x08), Some(base));
    }

    #[test]
    fn zero_timestamp_is_none() {
        assert_eq!(exfat_timestamp_to_unix(0, 0, 0), None);
    }

    #[derive(Debug)]
    struct TinySource(u64);
    impl DataSource for TinySource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let start = offset.min(self.0);
            let n = ((self.0 - start) as usize).min(buf.len());
            buf[..n].fill(0);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.0
        }
    }

    fn test_boot_sector() -> ExFatBootSector {
        ExFatBootSector {
            bytes_per_sector_shift: 9,
            sectors_per_cluster_shift: 0,
            number_of_fats: 1,
            fat_offset: 0,
            fat_length: 0xFFFF_FFFF,
            cluster_heap_offset: 0,
            cluster_count: 0,
            root_directory_cluster: 2,
            volume_serial_number: 0,
            volume_flags: 0,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
        }
    }

    /// Regression: fat_length * bytes_per_sector is attacker-controlled and can
    /// exceed the volume by orders of magnitude. ExFatTable::read must clamp the
    /// allocation to the data source length rather than OOM-aborting.
    #[test]
    fn exfat_fat_table_read_allocation_is_bounded() {
        let bs = test_boot_sector(); // fat_length 0xFFFFFFFF * 512 ~= 2 TB
        let src: Arc<dyn DataSource> = Arc::new(TinySource(8192));
        let table = ExFatTable::read(&bs, &src).expect("read");
        assert!(table.table_data.len() as u64 <= src.size());
    }

    /// Regression: a cyclic FAT (cluster 2 -> 3 -> 2) must terminate at the first
    /// revisit, not re-read to the 100 000-iteration cap. The chain never
    /// reaches an end-of-chain marker, so it is not complete.
    #[test]
    fn exfat_follow_chain_terminates_on_cycle() {
        let mut table_data = vec![0u8; 32];
        LittleEndian::write_u32(&mut table_data[2 * 4..], 3);
        LittleEndian::write_u32(&mut table_data[3 * 4..], 2);
        let table = ExFatTable { table_data };
        let (chain, complete) = table.follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert!(!complete, "a cyclic chain is not a complete chain");
    }

    /// BUG-210: a chain longer than the exFAT safety cap must report incomplete
    /// so `data_runs_complete` is false and the resolver refuses to zero-fill
    /// the tail. A chain ending on the end-of-chain marker stays complete.
    #[test]
    fn exfat_follow_chain_reports_incomplete_at_safety_cap() {
        let entries = MAX_EXFAT_CHAIN_CLUSTERS + 8;
        let mut table_data = vec![0u8; entries * 4];
        for n in 2..entries - 1 {
            LittleEndian::write_u32(&mut table_data[n * 4..], (n + 1) as u32);
        }
        let table = ExFatTable { table_data };
        let (chain, complete) = table.follow_chain(2);
        assert_eq!(chain.len(), MAX_EXFAT_CHAIN_CLUSTERS);
        assert!(!complete, "chain cut short by the safety cap is incomplete");

        // Contiguous clusters coalesce into one run, so the run-count cap alone
        // would have (wrongly) reported the run list as complete.
        let (_runs, runs_complete) =
            cluster_chain_to_runs(&chain, 512, complete, |c| c as u64 * 512);
        assert!(
            !runs_complete,
            "a truncated cluster chain must not be published as a complete run list"
        );
    }

    #[test]
    fn exfat_follow_chain_reports_complete_on_end_marker() {
        let mut table_data = vec![0u8; 32];
        LittleEndian::write_u32(&mut table_data[2 * 4..], 3);
        LittleEndian::write_u32(&mut table_data[3 * 4..], 0xFFFF_FFFF);
        let table = ExFatTable { table_data };
        let (chain, complete) = table.follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert!(complete);
    }

    /// 512-byte clusters starting at byte 0 (cluster 2 -> offset 0), 16
    /// directory entries per cluster.
    fn packed_boot_sector() -> ExFatBootSector {
        ExFatBootSector {
            bytes_per_sector_shift: 9,
            sectors_per_cluster_shift: 0,
            number_of_fats: 1,
            fat_offset: 0,
            fat_length: 0,
            cluster_heap_offset: 0,
            cluster_count: 8,
            root_directory_cluster: 2,
            volume_serial_number: 0,
            volume_flags: 0,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
        }
    }

    /// A 32-byte file directory entry (0x85) declaring `secondary_count`.
    fn file_entry_bytes(secondary_count: u8) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0] = 0x85;
        e[1] = secondary_count;
        LittleEndian::write_u16(&mut e[4..6], 0x0020); // archive
        e
    }

    /// A 32-byte stream extension entry (0xC0).
    fn stream_entry_bytes(name_length: u8, first_cluster: u32, data_length: u64) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0] = 0xC0;
        e[1] = 0x02; // NoFatChain (contiguous)
        e[3] = name_length;
        LittleEndian::write_u64(&mut e[8..16], data_length); // valid_data_length
        LittleEndian::write_u32(&mut e[20..24], first_cluster);
        LittleEndian::write_u64(&mut e[24..32], data_length);
        e
    }

    /// A 32-byte file name entry (0xC1) holding up to 15 UTF-16 chars.
    fn name_entry_bytes(part: &str) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0] = 0xC1;
        for (i, ch) in part.encode_utf16().take(15).enumerate() {
            LittleEndian::write_u16(&mut e[2 + i * 2..4 + i * 2], ch);
        }
        e
    }

    /// BUG-187: an entry set that starts in the last slot of a cluster continues
    /// in the NEXT CLUSTER OF THE FAT CHAIN. Reading `cluster_offset + i * 32`
    /// past the cluster end lands in whatever cluster physically follows (here a
    /// zeroed, unrelated one), yielding an empty name and a zero-length stream.
    #[test]
    fn exfat_entry_set_follows_cluster_chain_across_boundary() {
        let bs = packed_boot_sector();
        // Root chain: cluster 2 -> cluster 5 (cluster 3 is NOT part of it).
        let mut table_data = vec![0u8; 64];
        LittleEndian::write_u32(&mut table_data[2 * 4..], 5);
        LittleEndian::write_u32(&mut table_data[5 * 4..], 0xFFFF_FFFF);
        let fat_table = ExFatTable { table_data };

        let mut image = vec![0u8; 4096];
        // Cluster 2 (offset 0): 15 skippable entries, then the file entry in the
        // last slot of the cluster.
        for i in 0..15 {
            image[i * 32] = 0x83; // volume label: skipped
        }
        image[15 * 32..16 * 32].copy_from_slice(&file_entry_bytes(2));
        // Cluster 3 (offset 512) stays zeroed: the wrong place to continue.
        // Cluster 5 (offset 1536): stream extension + name entry.
        let c5 = bs.cluster_to_offset(5) as usize;
        image[c5..c5 + 32].copy_from_slice(&stream_entry_bytes(11, 7, 10));
        image[c5 + 32..c5 + 64].copy_from_slice(&name_entry_bytes("spanner.txt"));

        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let (sets, complete) =
            parse_exfat_directory(&bs, &src, &fat_table, 2).expect("directory parses");

        assert!(complete, "the chain reached a real end-of-chain marker");
        assert_eq!(sets.len(), 1, "one entry set expected");
        assert_eq!(sets[0].get_filename(), "spanner.txt");
        assert_eq!(sets[0].stream_extension.data_length, 10);
        assert_eq!(sets[0].stream_extension.first_cluster, 7);
    }

    /// HUNT-067. exFAT deletes a file by clearing bit 7 of each entry's type
    /// byte — 0x85 becomes 0x05, 0xC0 becomes 0x40, 0xC1 becomes 0x41 — and
    /// leaves the whole set in place: name, size, timestamps, first cluster.
    /// The parser mapped those types to `Unknown` and skipped them, so the
    /// NIST DFR set's exFAT scenarios recovered nothing while its FAT ones
    /// recovered every deleted file. A cleared bit is the deletion, not the
    /// absence of an entry.
    #[test]
    fn an_exfat_entry_set_with_its_in_use_bits_cleared_is_a_deleted_file() {
        let bs = packed_boot_sector();
        let mut table_data = vec![0u8; 64];
        LittleEndian::write_u32(&mut table_data[2 * 4..], 0xFFFF_FFFF);
        let fat_table = ExFatTable { table_data };

        let mut image = vec![0u8; 512];
        // A live file first, then the deleted one behind it.
        image[0..32].copy_from_slice(&file_entry_bytes(2));
        image[32..64].copy_from_slice(&stream_entry_bytes(8, 5, 100));
        image[64..96].copy_from_slice(&name_entry_bytes("live.txt"));
        let mut gone_file = file_entry_bytes(2);
        gone_file[0] = 0x05;
        let mut gone_stream = stream_entry_bytes(14, 7, 712);
        gone_stream[0] = 0x40;
        let mut gone_name = name_entry_bytes("Betelgeuse.txt");
        gone_name[0] = 0x41;
        image[96..128].copy_from_slice(&gone_file);
        image[128..160].copy_from_slice(&gone_stream);
        image[160..192].copy_from_slice(&gone_name);

        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let (sets, complete) =
            parse_exfat_directory(&bs, &src, &fat_table, 2).expect("directory parses");
        assert!(complete);
        assert_eq!(
            sets.len(),
            2,
            "the deleted set is recovered beside the live one"
        );
        let live = &sets[0];
        let gone = &sets[1];
        assert!(!live.deleted);
        assert!(gone.deleted, "cleared InUse bits are the deletion");
        assert_eq!(gone.get_filename(), "Betelgeuse.txt");
        assert_eq!(gone.stream_extension.data_length, 712);
        assert_eq!(gone.stream_extension.first_cluster, 7);

        // And the artifact built from it says so, in the key every other
        // filesystem parser uses.
        let art = create_exfat_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            gone,
            "/Betelgeuse.txt",
            &src,
            &bs,
            &fat_table,
        )
        .expect("artifact");
        assert_eq!(art.metadata["deleted"], true);
        assert_eq!(
            art.metadata["deleted_recovery_source"],
            "exfat_directory_entry"
        );
        // Its clusters may have been reallocated since: the content is not
        // vouched for.
        assert_eq!(art.metadata["content_incomplete"], true);
    }

    /// BUG-187: a `read_at` that returns fewer than 32 bytes must not be padded
    /// with zeros and parsed — that fabricates a name from half an entry.
    #[test]
    fn exfat_short_read_drops_partial_entry_set() {
        let bs = packed_boot_sector();
        let mut table_data = vec![0u8; 64];
        LittleEndian::write_u32(&mut table_data[2 * 4..], 0xFFFF_FFFF);
        let fat_table = ExFatTable { table_data };

        // The image ends in the middle of the set's name entry.
        let mut image = vec![0u8; 80];
        image[0..32].copy_from_slice(&file_entry_bytes(2));
        image[32..64].copy_from_slice(&stream_entry_bytes(4, 2, 8));
        let partial = name_entry_bytes("evil");
        image[64..80].copy_from_slice(&partial[..16]);

        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let (sets, complete) =
            parse_exfat_directory(&bs, &src, &fat_table, 2).expect("directory parses");

        assert!(
            sets.is_empty(),
            "a set whose name entry could not be fully read must be dropped"
        );
        assert!(
            !complete,
            "dropping the set makes the listing a prefix, and it must say so"
        );
    }

    /// Regression: a contiguous stream claiming data_length = u64::MAX must not
    /// build a multi-GB cluster Vec nor overflow first_cluster + i; the chain is
    /// capped by the data source length. Without the fix this panics in debug on
    /// the `first_cluster + i` overflow.
    #[test]
    fn exfat_contiguous_chain_is_bounded() {
        let bs = test_boot_sector(); // 512 B cluster
        let src: Arc<dyn DataSource> = Arc::new(TinySource(8192)); // 16 clusters
        let entry_set = ExFatDirectoryEntrySet {
            file_entry: ExFatFileEntry {
                entry_type: 0x85,
                secondary_count: 2,
                set_checksum: 0,
                file_attributes: 0,
                create_timestamp: 0,
                modify_timestamp: 0,
                access_timestamp: 0,
                create_10ms: 0,
                modify_10ms: 0,
                create_utc_offset: 0,
                modify_utc_offset: 0,
                access_utc_offset: 0,
            },
            stream_extension: ExFatStreamExtension {
                entry_type: 0xC0,
                flags: 0x02, // contiguous (NoFatChain)
                name_length: 4,
                name_hash: 0,
                valid_data_length: u64::MAX,
                first_cluster: 2,
                data_length: u64::MAX,
            },
            file_names: vec![ExFatFileName {
                entry_type: 0xC1,
                flags: 0,
                name_chars: "test".encode_utf16().collect(),
            }],
            deleted: false,
            after_end_marker: false,
        };
        let fat_table = ExFatTable { table_data: vec![] };
        let art = create_exfat_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &entry_set,
            "/test",
            &src,
            &bs,
            &fat_table,
        )
        .expect("artifact");
        let runs = art.metadata.get("data_runs").and_then(|v| v.as_array());
        assert!(runs.is_some());
        // Coalesced contiguous run length must be bounded by the volume (plus at
        // most one partial trailing cluster), not the declared u64::MAX.
        if let Some(first) = runs.and_then(|r| r.first()).and_then(|v| v.as_array()) {
            let len = first[1].as_u64().unwrap();
            assert!(
                len <= src.size() + 512,
                "run length ({len}) must be bounded by the volume size"
            );
        }
    }

    /// Build an entry set for a contiguous file of `data_length` bytes whose
    /// first `valid_data_length` bytes were actually written.
    fn entry_set_with_valid_length(
        data_length: u64,
        valid_data_length: u64,
    ) -> ExFatDirectoryEntrySet {
        ExFatDirectoryEntrySet {
            file_entry: ExFatFileEntry {
                entry_type: 0x85,
                secondary_count: 2,
                set_checksum: 0,
                file_attributes: 0,
                create_timestamp: 0,
                modify_timestamp: 0,
                access_timestamp: 0,
                create_10ms: 0,
                modify_10ms: 0,
                create_utc_offset: 0,
                modify_utc_offset: 0,
                access_utc_offset: 0,
            },
            stream_extension: ExFatStreamExtension {
                entry_type: 0xC0,
                flags: 0x02, // contiguous (NoFatChain)
                name_length: 8,
                name_hash: 0,
                valid_data_length,
                first_cluster: 2,
                data_length,
            },
            file_names: vec![ExFatFileName {
                entry_type: 0xC1,
                flags: 0,
                name_chars: "note.txt".encode_utf16().collect(),
            }],
            deleted: false,
            after_end_marker: false,
        }
    }

    /// BUG-273: exFAT records both DataLength and ValidDataLength. Per the spec
    /// (7.4.4) the bytes in `[ValidDataLength, DataLength)` are not file data and
    /// read back as zeros; serving the residue still in those clusters would
    /// disagree with every OS reader and poison the file's hash.
    #[test]
    fn exfat_content_past_valid_data_length_reads_as_zeros() {
        // 512-byte clusters, cluster 2 at offset 0.
        let bs = test_boot_sector();
        // Two clusters of residue from a previous, larger file.
        let image = vec![0xABu8; 2048];
        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let fat_table = ExFatTable { table_data: vec![] };

        let art = create_exfat_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &entry_set_with_valid_length(1024, 512),
            "/note.txt",
            &src,
            &bs,
            &fat_table,
        )
        .expect("artifact");

        assert_eq!(art.metadata["size"], json!(1024));
        assert_eq!(art.metadata["valid_size"], json!(512));
        assert_eq!(art.metadata["has_unwritten_tail"], json!(true));
        assert_eq!(art.metadata["unwritten_tail_bytes"], json!(512));

        // The persisted runs place the residual tail in a SPARSE run so the API
        // resolver zero-fills it instead of re-reading the media.
        let runs = art.metadata["data_runs"].as_array().expect("runs");
        assert_eq!(runs.len(), 2, "one real run plus the unwritten tail");
        assert_eq!(runs[0][0].as_u64(), Some(0));
        assert_eq!(runs[0][1].as_u64(), Some(512));
        assert!(runs[1][0].is_null(), "the tail must be a sparse run");
        assert_eq!(runs[1][1].as_u64(), Some(512));

        // And the live content source agrees.
        let content = art.data.as_ref().expect("content source");
        assert_eq!(content.size(), 1024);
        let mut buf = vec![0u8; 1024];
        let n = content.read_at(0, &mut buf).expect("read");
        assert_eq!(n, 1024);
        assert!(
            buf[..512].iter().all(|&b| b == 0xAB),
            "written data must be served verbatim"
        );
        assert!(
            buf[512..].iter().all(|&b| b == 0),
            "residual bytes past ValidDataLength must not be served as file content"
        );

        // A read that starts inside the unwritten region is all zeros too.
        let mut tail = vec![0xFFu8; 256];
        let n = content.read_at(700, &mut tail).expect("read");
        assert_eq!(n, 256);
        assert!(tail.iter().all(|&b| b == 0));
    }

    /// ValidDataLength == 0 on a non-empty file is ambiguous (truly
    /// preallocated, or an implementation that never maintains the field), so
    /// the clusters are still served and the ambiguity is recorded.
    #[test]
    fn exfat_zero_valid_data_length_still_serves_content() {
        let bs = test_boot_sector();
        let src: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(vec![0xCDu8; 2048]),
        );
        let fat_table = ExFatTable { table_data: vec![] };

        let art = create_exfat_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &entry_set_with_valid_length(1024, 0),
            "/note.txt",
            &src,
            &bs,
            &fat_table,
        )
        .expect("artifact");

        assert_eq!(art.metadata["valid_data_length_zero"], json!(true));
        assert!(art.metadata.get("has_unwritten_tail").is_none());
        let content = art.data.as_ref().expect("content source");
        let mut buf = vec![0u8; 1024];
        assert_eq!(content.read_at(0, &mut buf).unwrap(), 1024);
        assert!(
            buf.iter().all(|&b| b == 0xCD),
            "a zero ValidDataLength must not blank a whole file"
        );
    }

    /// A fully written file (ValidDataLength == DataLength) is untouched: no
    /// sparse tail, no flag, every byte served from the media.
    #[test]
    fn exfat_fully_written_file_serves_all_clusters() {
        let bs = test_boot_sector();
        let src: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(vec![0xCDu8; 2048]),
        );
        let fat_table = ExFatTable { table_data: vec![] };

        let art = create_exfat_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &entry_set_with_valid_length(1024, 1024),
            "/note.txt",
            &src,
            &bs,
            &fat_table,
        )
        .expect("artifact");

        assert!(art.metadata.get("has_unwritten_tail").is_none());
        let content = art.data.as_ref().expect("content source");
        let mut buf = vec![0u8; 1024];
        assert_eq!(content.read_at(0, &mut buf).unwrap(), 1024);
        assert!(buf.iter().all(|&b| b == 0xCD));
    }

    /// HUNT-124: a live exFAT file whose allocation is fully described offers
    /// its slack; one with an unwritten tail does not.
    #[test]
    fn exfat_slack_region_for_live_file_with_nonzero_tail() {
        let bs = test_boot_sector();
        // 512-byte clusters, cluster 2 at offset 0: a 1000-byte file on
        // clusters 2-3 leaves 24 bytes of slack at 1000..1024.
        let mut image = vec![0u8; 4096];
        image[..1000].fill(b'f');
        image[1010] = 0x4D;
        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));
        let fat_table = ExFatTable { table_data: vec![] };
        let fs = Artifact::new(Uuid::new_v4(), ArtifactType::FileSystem, None, json!({}));
        let file = create_exfat_artifact(
            fs.case_id,
            fs.id,
            &entry_set_with_valid_length(1000, 1000),
            "/note.txt",
            &src,
            &bs,
            &fat_table,
        )
        .expect("artifact");
        let mut slack = fat_slack_collector("exFAT", 512);
        offer_file_slack(&mut slack, &fs, &src, &file, 512);
        let (out, outcome) = slack.finish(&fs);
        assert_eq!(outcome.regions_emitted, 1);
        let r = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::SlackSpace)
            .unwrap();
        assert_eq!(r.metadata["offset_bytes"], 1000);
        assert_eq!(r.metadata["size_bytes"], 24);
        assert_eq!(r.metadata["filesystem"], "exFAT");
        assert_eq!(r.metadata["parent_path"], "/note.txt");

        // ValidDataLength short of DataLength: the persisted runs end in a
        // sparse run, which is not the allocation, so nothing is offered.
        let file = create_exfat_artifact(
            fs.case_id,
            fs.id,
            &entry_set_with_valid_length(1000, 512),
            "/note.txt",
            &src,
            &bs,
            &fat_table,
        )
        .expect("artifact");
        let mut slack = fat_slack_collector("exFAT", 512);
        offer_file_slack(&mut slack, &fs, &src, &file, 512);
        assert_eq!(slack.outcome().files_offered, 0);
    }
}
