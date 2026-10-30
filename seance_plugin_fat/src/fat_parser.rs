use super::fat_structs::*;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    free_space::{emit_free_regions, AllocationBitmap, BitMeaning, FreeSpaceLabels},
    io::{read_exact_or_fail, read_full},
    slack::{SlackCollector, SlackLabels},
};
use serde_json::json;
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::io;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Cap on data runs persisted in FileEntry metadata (contract with the API
/// layer): the shared one, so every filesystem truncates at the same point.
pub(crate) use seance_core::data_source::MAX_METADATA_DATA_RUNS;
/// Safety cap on the number of clusters walked in a single FAT chain.
pub(crate) const MAX_CHAIN_CLUSTERS: usize = 10_000;
/// Maximum buckets in a downsampled allocation bitmap (contract with the API layer)
pub(crate) const MAX_ALLOCATION_BUCKETS: u64 = 65536;
/// Safety cap when reading an allocation bitmap into memory
pub(crate) const MAX_BITMAP_BYTES: u64 = 64 * 1024 * 1024;

/// Convert a cluster chain into coalesced [offset_bytes, length_bytes] runs
/// (byte offsets within the filesystem window), capped at
/// MAX_METADATA_DATA_RUNS. Returns the JSON array plus a completeness flag.
///
/// `chain_complete` reports whether the caller's cluster list covers the whole
/// file. A chain truncated by the walker's own safety cap (or by a cyclic FAT)
/// must NOT be published as a complete run list: the content resolver treats
/// any shortfall against the recorded size as a sparse hole and zero-fills it,
/// which would serve fabricated zeros in place of real clusters (BUG-210).
pub(crate) fn cluster_chain_to_runs(
    chain: impl IntoIterator<Item = impl Borrow<u32>>,
    cluster_size: u64,
    chain_complete: bool,
    cluster_to_offset: impl Fn(u32) -> u64,
) -> (serde_json::Value, bool) {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for cluster in chain {
        let offset = cluster_to_offset(*cluster.borrow());
        if let Some(last) = runs.last_mut() {
            if last.0 + last.1 == offset {
                last.1 += cluster_size;
                continue;
            }
        }
        runs.push((offset, cluster_size));
    }
    runs_to_json(runs, chain_complete)
}

/// Publish `(offset, length)` runs as the persisted JSON array, capped at
/// MAX_METADATA_DATA_RUNS; the flag is false when the cap cut the list.
fn runs_to_json(mut runs: Vec<(u64, u64)>, chain_complete: bool) -> (serde_json::Value, bool) {
    let complete = chain_complete && runs.len() <= MAX_METADATA_DATA_RUNS;
    runs.truncate(MAX_METADATA_DATA_RUNS);
    let json_runs: Vec<serde_json::Value> = runs.iter().map(|&(o, l)| json!([o, l])).collect();
    (json!(json_runs), complete)
}

/// Offer one emitted FAT or exFAT `FileEntry`'s slack window (HUNT-124).
///
/// Only a live, non-directory file whose persisted run list is whole clusters
/// and complete is offered: a deleted entry's chain is a guess, a chain cut
/// short does not say where the tail is, and an exFAT file with an unwritten
/// tail (`ValidDataLength` < `DataLength`) persists a sparse run that is not
/// its allocation. A live file that has a tail but is refused for one of those
/// reasons is counted through [`SlackCollector::not_located`], so the summary
/// gives a number for "could not look".
pub(crate) fn offer_file_slack(
    collector: &mut SlackCollector,
    fs: &Artifact,
    source: &Arc<dyn DataSource>,
    file: &Artifact,
    cluster_size: u64,
) {
    seance_core::slack::offer_live_file(
        collector,
        fs,
        source,
        file,
        cluster_size,
        &["cluster_chain_incomplete", "has_unwritten_tail"],
    );
}

/// The slack collector for one FAT-family volume.
pub(crate) fn fat_slack_collector(filesystem: &'static str, cluster_size: u64) -> SlackCollector {
    SlackCollector::new(
        SlackLabels {
            filesystem,
            offset_basis: "the start of this volume, not the start of the evidence",
        },
        cluster_size,
    )
}

/// Downsample an allocation bitmap (bit `i`, LSB first, is cluster `i`) into
/// at most MAX_ALLOCATION_BUCKETS buckets of 0..=255. Bits past the end of the
/// bitmap count as unallocated, as the per-cluster walk read them.
pub(crate) fn build_allocation_buckets_from_bitmap(
    total_clusters: u64,
    bits: &[u8],
) -> (Vec<u8>, u64) {
    let clusters_per_bucket = total_clusters.div_ceil(MAX_ALLOCATION_BUCKETS).max(1);
    let bucket_count = total_clusters.div_ceil(clusters_per_bucket);
    let mut buckets = Vec::with_capacity(bucket_count as usize);
    let mut cluster: u64 = 0;
    while cluster < total_clusters {
        let in_bucket = clusters_per_bucket.min(total_clusters - cluster);
        let allocated = count_set_bits(bits, cluster, cluster + in_bucket);
        buckets.push(((allocated * 255) / in_bucket) as u8);
        cluster += in_bucket;
    }
    (buckets, clusters_per_bucket)
}

/// Set bits in `bits[start..end)` (bit positions, LSB first); positions past
/// the slice count as clear. Whole bytes go through `count_ones`, so the cost
/// is per byte rather than per bit.
fn count_set_bits(bits: &[u8], start: u64, end: u64) -> u64 {
    let end = end.min(bits.len() as u64 * 8);
    if start >= end {
        return 0;
    }
    let low_mask = |n: u64| ((1u16 << n) - 1) as u8;
    let (first_byte, first_bit) = ((start / 8) as usize, start % 8);
    let (last_byte, last_bit) = ((end / 8) as usize, end % 8);
    if first_byte == last_byte {
        return u64::from(
            (bits[first_byte] & low_mask(last_bit) & !low_mask(first_bit)).count_ones(),
        );
    }
    let mut count = u64::from((bits[first_byte] & !low_mask(first_bit)).count_ones());
    count += bits[first_byte + 1..last_byte]
        .iter()
        .map(|b| u64::from(b.count_ones()))
        .sum::<u64>();
    if last_bit > 0 {
        count += u64::from((bits[last_byte] & low_mask(last_bit)).count_ones());
    }
    count
}

pub fn parse_fat_filesystem(
    artifact: &Artifact,
    data_source: Arc<dyn DataSource>,
) -> Result<Vec<Artifact>> {
    let mut produced_artifacts = Vec::new();

    // Read boot sector. A single `read_at` may return short on a windowed or
    // container-backed source, leaving the pre-zeroed tail to be parsed as real
    // BPB geometry — fabricated cluster sizes, or a 0x55AA signature that reads
    // as absent so a perfectly good volume is skipped entirely.
    let mut boot_sector_data = vec![0u8; 512];
    read_exact_or_fail(
        data_source.as_ref(),
        0,
        &mut boot_sector_data,
        "FAT boot sector",
    )?;

    // Verify FAT boot sector signature
    if boot_sector_data[510] != 0x55 || boot_sector_data[511] != 0xAA {
        debug!(
            "Invalid boot sector signature: found [0x{:02X}, 0x{:02X}], expected [0x55, 0xAA]",
            boot_sector_data[510], boot_sector_data[511]
        );
        return Ok(Vec::new());
    }

    // Check for exFAT signature
    if &boot_sector_data[3..11] == b"EXFAT   " {
        debug!("Detected exFAT filesystem, using exFAT parser");
        return super::exfat_parser::parse_exfat_filesystem(artifact, data_source);
    }

    // Parse BPB
    let bpb = match BiosParameterBlock::parse(&boot_sector_data) {
        Ok(bpb) => bpb,
        Err(e) => {
            debug!("Failed to parse BPB: {}", e);
            return Ok(Vec::new());
        }
    };

    // Validate BPB values. Per the MS FAT spec bytes_per_sector is a power of
    // two in 512..=4096 and sectors_per_cluster is a power of two. Rejecting
    // non-power-of-two geometry both guards the later divisions (nonzero) and
    // closes crafted boot sectors (e.g. bytes_per_sector=1) that make the
    // cluster size tiny and inflate attacker-controlled cluster counts.
    let bps = bpb.bytes_per_sector;
    let spc = bpb.sectors_per_cluster;
    if bps == 0
        || spc == 0
        || (bps & (bps - 1)) != 0
        || (spc & (spc - 1)) != 0
        || !(512..=4096).contains(&bps)
    {
        debug!(
            "Invalid BPB geometry: bytes_per_sector={}, sectors_per_cluster={} (must be powers of two, bytes_per_sector in 512..=4096)",
            bpb.bytes_per_sector, bpb.sectors_per_cluster
        );
        return Ok(Vec::new());
    }

    // Determine FAT type and parse extended BPB
    let sectors_per_fat = if bpb.sectors_per_fat_16 != 0 {
        bpb.sectors_per_fat_16 as u32
    } else {
        // FAT32 - read from extended BPB
        match Fat32ExtendedBpb::parse(&boot_sector_data) {
            Ok(ext) => ext.sectors_per_fat_32,
            Err(e) => {
                debug!("Failed to parse FAT32 extended BPB: {}", e);
                return Ok(Vec::new());
            }
        }
    };

    let fat_type = bpb.determine_fat_type(sectors_per_fat);

    let (extended_bpb, volume_label, volume_label_decode) = match fat_type {
        FatType::Fat32 => {
            let ext = Fat32ExtendedBpb::parse(&boot_sector_data).map_err(|e| anyhow::anyhow!(e))?;
            let label = ext.volume_label.clone();
            let decode = ext.volume_label_decode;
            (FatExtendedBpb::Fat32(ext), label, decode)
        }
        FatType::Fat12 | FatType::Fat16 => {
            let ext = Fat16ExtendedBpb::parse(&boot_sector_data).map_err(|e| anyhow::anyhow!(e))?;
            let label = ext.volume_label.clone();
            let decode = ext.volume_label_decode;
            (FatExtendedBpb::Fat16(ext), label, decode)
        }
    };

    let boot_sector = FatBootSector {
        bpb: bpb.clone(),
        extended: extended_bpb,
        fat_type,
    };

    info!(
        "Detected {:?} filesystem, volume: {}, clusters: {}",
        fat_type,
        volume_label,
        bpb.total_clusters(sectors_per_fat)
    );

    // The FileSystem artifact is this module's INPUT — the partition plugin
    // already created it. Emit files and the allocation map as its children.
    // Creating another FileSystem here would re-trigger this module (which runs
    // on FileSystem artifacts) against our own output and cascade without
    // bound. This mirrors the ext4 module's contract. FAT geometry that isn't
    // on the input artifact is recorded on the allocation-map record below.
    let fs_id = artifact.id;

    // Read FAT table for cluster chain traversal
    let fat_table = match FatTable::read(&boot_sector, &data_source) {
        Ok(table) => table,
        Err(e) => {
            warn!("Failed to read FAT table: {}", e);
            return Ok(produced_artifacts);
        }
    };

    // Allocation map derived from the in-memory FAT: an entry <= 1 is free.
    // Data clusters are numbered from 2.
    //
    // `total_clusters` is what the BPB declares; header fields alone can make it
    // billions. Everything that allocates or loops per cluster is sized by
    // `effective_clusters`, the clusters the FAT actually holds an entry for, so
    // a hostile boot sector cannot buy a CPU stall or a memory spike. The
    // declared count still spans the downsampled picture.
    let total_clusters = bpb.total_clusters(sectors_per_fat) as u64;
    let effective_clusters = total_clusters.min(fat_table.entry_count().saturating_sub(2));
    if total_clusters > 0 {
        let fat_bits = fat_table.allocation_bitmaps(effective_clusters);
        let (buckets, clusters_per_bucket) =
            build_allocation_buckets_from_bitmap(total_clusters, &fat_bits.allocated);
        let mut map_metadata = json!({
            "type": "allocation_map",
            "allocation_bitmap_b64": BASE64.encode(&buckets),
            "allocation_clusters_per_bucket": clusters_per_bucket,
            "allocation_total_clusters": total_clusters,
            "allocation_cluster_size": boot_sector.cluster_size_bytes() as u64,
            // FAT geometry, kept here since this module no longer mints its
            // own FileSystem artifact (the partition plugin owns that).
            "fat_type": format!("{:?}", fat_type),
            "volume_label": volume_label,
            "bytes_per_sector": bpb.bytes_per_sector,
            "sectors_per_cluster": bpb.sectors_per_cluster,
            "total_sectors": bpb.total_sectors(),
            "total_sectors_source": bpb.total_sectors_source(),
            "sectors_per_fat": sectors_per_fat,
        });
        if effective_clusters < total_clusters {
            // The BPB declares more data clusters than the FAT holds entries
            // for; the clusters past it were not assessed.
            map_metadata["allocation_fat_covered_clusters"] = json!(effective_clusters);
        }
        // The layout (which BPB fields exist) and the cluster count disagree
        // about the width: the layout won, and the record says so.
        let by_count = bpb.fat_type_by_cluster_count(sectors_per_fat);
        if by_count != fat_type {
            map_metadata["fat_type_note"] = json!(format!(
                "the BPB is laid out as {fat_type:?} but its cluster count alone says \
                 {by_count:?}; read as {fat_type:?}"
            ));
        }
        // The volume label is stored as OEM bytes with no encoding declaration.
        // When it held a byte outside ASCII the label above is this build's
        // reading under an assumed code page, not text read off the disk: the
        // same bytes on a volume formatted under another OEM code page spell a
        // different name. Naming the table stops the label being quoted as the
        // literal name of the exhibit.
        if let Some(code_page) = volume_label_decode {
            map_metadata["path_decode"] = json!(code_page);
        }
        // The FAT turned into free regions the carver reads (ROADMAP §5.4).
        //
        // The FAT *is* this filesystem's allocation map, so the bits are
        // synthesised from it rather than read: bit `c - 2` set means cluster
        // `c` is in use. Three readings, and only the first is free space:
        //
        // * a **zero** entry is a free cluster;
        // * any other value is in use — which includes the bad-cluster marker
        //   and the reserved value 1, neither of which is free and neither of
        //   which may be carved as though it were;
        // * **no entry at all**, past what the FAT actually holds, is
        //   unassessed. A FAT read short would otherwise report the rest of
        //   the volume as free, which is the same trap as a short bitmap's
        //   zero tail.
        let bits = fat_bits.in_use;
        let cluster_size = boot_sector.cluster_size_bytes() as u64;
        let parent = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            map_metadata,
        );
        let bitmap_view = AllocationBitmap {
            bits: &bits,
            total_clusters: total_clusters.saturating_add(2),
            cluster_size,
            first_cluster: 2,
            first_cluster_offset: boot_sector.cluster_to_offset(2),
            bit_meaning: BitMeaning::SetIsAllocated,
        };
        let (free_regions, free_outcome) = emit_free_regions(
            &parent,
            &data_source,
            &bitmap_view,
            FreeSpaceLabels {
                filesystem: match fat_type {
                    FatType::Fat12 => "FAT12",
                    FatType::Fat16 => "FAT16",
                    FatType::Fat32 => "FAT32",
                },
                offset_basis: "the start of this volume, not the start of the evidence",
            },
        );
        let mut map_metadata = parent.metadata.clone();
        if let (Some(map), Some(fields)) = (
            map_metadata.as_object_mut(),
            free_outcome.to_json().as_object(),
        ) {
            for (key, value) in fields {
                map.insert(key.clone(), value.clone());
            }
        }
        let map_artifact = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            map_metadata,
        )
        .with_parent(fs_id);
        produced_artifacts.push(map_artifact);
        produced_artifacts.extend(
            free_regions
                .into_iter()
                .map(|region| region.with_parent(fs_id)),
        );
    }

    // Parse root directory
    let (root_entries, root_incomplete, mut slack_rejected_total) =
        match parse_root_directory(&boot_sector, &data_source, &fat_table) {
            Ok(result) => result,
            Err(e) => {
                warn!("Failed to parse root directory: {}", e);
                return Ok(produced_artifacts);
            }
        };

    info!("Found {} entries in root directory", root_entries.len());

    if let Some(reason) = root_incomplete {
        // The allocation-map record is this module's volume-level artifact, so
        // it carries the honesty flag for the root listing: without it a root
        // directory cut short by a broken chain looks fully enumerated.
        warn!("FAT root directory listing is incomplete");
        let map_idx = produced_artifacts.iter().position(|a| {
            a.metadata.get("type").and_then(|t| t.as_str()) == Some("allocation_map")
        });
        match map_idx {
            Some(i) => {
                produced_artifacts[i].metadata["directory_parse_incomplete"] = json!(true);
                produced_artifacts[i].metadata["directory_parse_incomplete_reason"] = json!(reason);
            }
            // The map is omitted on a volume reporting zero clusters, so mint a
            // record instead: a flag that only appears when another artifact
            // happens to exist is not a flag, and an unmarked root listing reads
            // as the whole of the volume's top level.
            None => produced_artifacts.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "fat_volume_walk",
                        "directory_parse_incomplete": true,
                        "directory_parse_incomplete_reason": reason,
                    }),
                )
                .with_parent(fs_id),
            ),
        }
    }

    // Process directory entries recursively. The trailing bool tracks whether an
    // ancestor directory was deleted: such entries live in unallocated space
    // with a freed FAT chain even when their own name byte is intact, so they
    // must be recovered like deleted files (contiguous read), not by following
    // the FAT.
    //
    // Live entries are all taken before any deleted one (`deferred`), so that when a
    // deleted directory's first cluster turns out to be a live directory's too (a
    // freed cluster is the first one the driver gives the next new directory) the
    // live directory has already been read and the deleted one can say so, instead of
    // reading the live directory's entries as its own or being skipped silently.
    let to_process: Vec<(
        ParsedDirectoryEntry,
        Uuid,
        String,
        bool,
        Option<OrphanDirectory>,
    )> = root_entries
        .into_iter()
        .map(|e| {
            let name = e.long_name.as_ref().unwrap_or(&e.short_name).clone();
            let path = format!("/{}", name);
            (e, fs_id, path, false, None)
        })
        .collect();

    // Directory clusters already descended, so a corrupt or hostile image whose
    // directory points back at an ancestor (or at itself) cannot loop forever.
    let mut visited_dirs: HashSet<u32> = HashSet::new();
    // The path of each directory the live walk reached, by first cluster; 0 is the root.
    let mut live_dir_paths: HashMap<u32, String> = HashMap::from([(0, "/".to_string())]);

    // File slack (HUNT-124): one region per live file whose tail holds bytes.
    let slack_cluster_size = boot_sector.cluster_size_bytes() as u64;
    let mut slack = fat_slack_collector(
        match fat_type {
            FatType::Fat12 => "FAT12",
            FatType::Fat16 => "FAT16",
            FatType::Fat32 => "FAT32",
        },
        slack_cluster_size,
    );

    let mut deferred: Vec<(
        ParsedDirectoryEntry,
        Uuid,
        String,
        bool,
        Option<OrphanDirectory>,
    )> = Vec::new();
    // Root entries already marked deleted are deferred like every other deleted entry.
    let (initially_deleted, initially_live): (Vec<_>, Vec<_>) = to_process
        .into_iter()
        .partition(|(entry, _, _, deleted_ancestor, _)| entry.deleted || *deleted_ancestor);
    let mut to_process = initially_live;
    deferred.extend(initially_deleted);
    let mut orphan_scan_done = false;
    loop {
        while let Some((mut entry, parent_id, path, deleted_ancestor, orphan)) =
            to_process.pop().or_else(|| deferred.pop())
        {
            // Inherit deletion from a deleted ancestor directory.
            let effective_deleted = entry.deleted || deleted_ancestor;
            entry.deleted = effective_deleted;

            if let Some(file_artifact) = create_file_artifact(
                artifact.case_id,
                parent_id,
                &entry,
                &path,
                &data_source,
                &boot_sector,
                &fat_table,
            ) {
                let is_directory = entry.dir_entry.is_directory();
                if !is_directory && !effective_deleted {
                    offer_file_slack(
                        &mut slack,
                        artifact,
                        &data_source,
                        &file_artifact,
                        slack_cluster_size,
                    );
                }
                let dir_artifact_index = produced_artifacts.len();
                let mut file_artifact = file_artifact;
                if let Some(found) = &orphan {
                    found.stamp(&mut file_artifact.metadata);
                }
                produced_artifacts.push(file_artifact);

                // If this is a directory we have not seen, parse its contents.
                if is_directory {
                    let dir_cluster = entry.dir_entry.first_cluster();
                    if effective_deleted && dir_cluster >= 2 && visited_dirs.contains(&dir_cluster)
                    {
                        // The deleted directory's first cluster is the first cluster of a
                        // directory the walk has already read: it was given to a new
                        // directory when this one was freed. Nothing of this one is left to
                        // read there, and what is there is not its content.
                        let meta = &mut produced_artifacts[dir_artifact_index].metadata;
                        meta["directory_parse_incomplete"] = json!(true);
                        meta["directory_parse_incomplete_reason"] =
                            json!("fat_deleted_directory_unverified");
                        meta["directory_content_reallocated"] = json!(true);
                        meta["directory_content_basis"] = json!(
                            "the first cluster of this deleted directory is now the first cluster \
                             of another directory on the volume, so nothing was read from it as \
                             this directory's content; its entries cannot be listed from this volume"
                        );
                    } else if dir_cluster >= 2 && visited_dirs.insert(dir_cluster) {
                        if !effective_deleted {
                            live_dir_paths.insert(dir_cluster, path.clone());
                        }
                        let listing = if effective_deleted {
                            parse_deleted_directory(
                                &boot_sector,
                                &data_source,
                                &fat_table,
                                dir_cluster,
                                &visited_dirs,
                            )
                        } else {
                            parse_directory(&boot_sector, &data_source, &fat_table, dir_cluster)
                        };
                        match listing {
                            Ok(listing) => {
                                slack_rejected_total += listing.slack_rejected;
                                visited_dirs.extend(listing.assumed_later_clusters.iter().copied());
                                let meta = &mut produced_artifacts[dir_artifact_index].metadata;
                                listing.stamp_directory(meta);
                                for subentry in listing.entries {
                                    let subname = subentry
                                        .long_name
                                        .as_ref()
                                        .unwrap_or(&subentry.short_name)
                                        .clone();
                                    let subpath = format!("{}/{}", path, subname);
                                    let orphan = orphan.clone();
                                    // Flat model: every entry is parented to the
                                    // FileSystem, hierarchy lives in the path string.
                                    // Parenting to the directory instead breaks
                                    // content resolution (the resolver walks the
                                    // parent chain and hits a directory with no
                                    // data_runs) — see file-entry-flat-model.
                                    let item =
                                        (subentry, fs_id, subpath, effective_deleted, orphan);
                                    if effective_deleted {
                                        deferred.push(item);
                                    } else {
                                        to_process.push(item);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse subdirectory at {}: {}", path, e);
                            }
                        }
                    }
                }
            }
        }

        if orphan_scan_done {
            break;
        }
        orphan_scan_done = true;
        // Directories whose parent entry is gone (HUNT-275): found by their own
        // `.` entry in a cluster the FAT calls free, after the live walk so the
        // clusters it already descended are excluded.
        let scan = scan_orphan_directories(
            &boot_sector,
            &data_source,
            &fat_table,
            effective_clusters,
            &visited_dirs,
        );
        if let Some(map) = produced_artifacts
            .iter_mut()
            .find(|a| a.metadata.get("type").and_then(|t| t.as_str()) == Some("allocation_map"))
        {
            scan.stamp_summary(&mut map.metadata);
        }
        for mut found in scan.directories {
            visited_dirs.insert(found.cluster);
            found.parent_path_now = live_dir_paths.get(&found.parent_cluster).cloned();
            let listing = if found.fat_state == OrphanFatState::Free {
                parse_deleted_directory(
                    &boot_sector,
                    &data_source,
                    &fat_table,
                    found.cluster,
                    &visited_dirs,
                )
            } else {
                parse_directory(&boot_sector, &data_source, &fat_table, found.cluster)
            };
            let Ok(listing) = listing else {
                continue;
            };
            slack_rejected_total += listing.slack_rejected;
            visited_dirs.extend(listing.assumed_later_clusters.iter().copied());
            found.listing_incomplete = listing.incomplete;
            let entries = listing.entries;
            let base = format!("/[orphaned directory, cluster {}]", found.cluster);
            for e in entries {
                let name = e.long_name.as_ref().unwrap_or(&e.short_name).clone();
                let deleted = found.fat_state == OrphanFatState::Free;
                let item = (
                    e,
                    fs_id,
                    format!("{base}/{name}"),
                    deleted,
                    Some(found.clone()),
                );
                if deleted {
                    deferred.push(item);
                } else {
                    to_process.push(item);
                }
            }
        }
        // Then the free clusters that read as directory entries and are anchored to nothing
        // (HUNT-278): the parent's entry is gone and so is, or so does not name, the `.`.
        let headless = scan_headless_directories(
            &boot_sector,
            &data_source,
            &fat_table,
            effective_clusters,
            &visited_dirs,
        );
        if let Some(map) = produced_artifacts
            .iter_mut()
            .find(|a| a.metadata.get("type").and_then(|t| t.as_str()) == Some("allocation_map"))
        {
            map.metadata["headless_directory_scan"] = json!({
                "directories_found": headless.directories.len(),
                "free_clusters_examined": headless.clusters_examined,
                "free_clusters_not_examined": headless.clusters_not_examined,
                "unreadable_clusters": headless.unreadable_clusters,
            });
        }
        for found in headless.directories {
            visited_dirs.insert(found.cluster);
            let base = boot_sector.cluster_to_offset(found.cluster);
            let slots_per_cluster = boot_sector.cluster_size_bytes() as u64 / 32;
            let offsets = (0..slots_per_cluster).map(move |i| base + i * 32);
            let seed = read_cluster_slots(&boot_sector, &data_source, found.cluster)
                .map(|slots| {
                    stitch_seed(
                        &boot_sector,
                        &data_source,
                        &fat_table,
                        &visited_dirs,
                        found.cluster,
                        &slots,
                    )
                })
                .unwrap_or_default();
            let Ok(scan) = scan_slots_seeded(&data_source, offsets, None, u32::MAX, seed) else {
                continue;
            };
            let entries = scan.entries;
            let label = format!("/[headless directory entries, cluster {}]", found.cluster);
            for e in entries {
                let name = e.long_name.as_ref().unwrap_or(&e.short_name).clone();
                deferred.push((
                    e,
                    fs_id,
                    format!("{label}/{name}"),
                    true,
                    Some(found.clone()),
                ));
            }
        }
        if to_process.is_empty() && deferred.is_empty() {
            break;
        }
    }

    if let Some(map) = produced_artifacts
        .iter_mut()
        .find(|a| a.metadata.get("type").and_then(|t| t.as_str()) == Some("allocation_map"))
    {
        map.metadata["directory_slack_slots_rejected"] = json!(slack_rejected_total);
    }

    let (slack_artifacts, _) = slack.finish(artifact);
    produced_artifacts.extend(slack_artifacts);

    Ok(produced_artifacts)
}

/// Clusters examined for an orphaned directory, at most, free and allocated
/// together: free clusters first, allocated ones from what remains. The scan
/// reads 64 bytes per cluster, so on a large volume it is bounded rather than
/// exhaustive, and the allocation-map record says how far it got.
pub(crate) const MAX_ORPHAN_SCAN_CLUSTERS: u64 = 1 << 20;

/// What the FAT says about the cluster an orphaned directory begins in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrphanFatState {
    /// The FAT calls the cluster free: the directory was deleted, or its
    /// chain was.
    Free,
    /// The FAT still calls it allocated, and no entry the walk reached leads
    /// to it. Nothing the volume shows says it was deleted; it is unreachable.
    Allocated,
}

impl OrphanFatState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Allocated => "allocated",
        }
    }
}

/// A directory found by its own `.` entry in a cluster no directory entry
/// reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrphanDirectory {
    /// The cluster its own `.` entry names.
    pub cluster: u32,
    /// The cluster its `..` entry names (0 is the root).
    pub parent_cluster: u32,
    /// What the FAT said about `cluster` when it was found.
    pub fat_state: OrphanFatState,
    /// The path the `..` cluster is a live directory at *now*, when the walk
    /// reached it. Filled after the scan.
    pub parent_path_now: Option<String>,
    /// Why the listing read from this directory may stop short of it. Filled
    /// after the scan.
    pub listing_incomplete: Option<&'static str>,
    /// Set when the cluster was found by its entries alone, not by a `.` that names it
    /// (`HUNT-278`): the cluster holds directory entries a driver wrote, and nothing
    /// anchors it to a directory. `Some(None)` has no `.`/`..` pair; `Some(Some(c))`
    /// has one whose `.` names cluster `c`, a cluster other than this (a copy of a
    /// directory's cluster, or a directory whose own cluster was reused).
    pub headless: Option<Option<u32>>,
}

impl OrphanDirectory {
    /// Provenance every entry recovered from the directory carries: its parent's
    /// name is not known, so the path is a label and not a location.
    fn stamp(&self, metadata: &mut serde_json::Value) {
        if let Some(dot) = self.headless {
            metadata["recovered_from_free_space"] = json!(true);
            metadata["orphan_fat_state"] = json!(self.fat_state.as_str());
            metadata["orphan_directory_cluster"] = json!(self.cluster);
            metadata["orphan_directory_headless"] = json!(true);
            if let Some(named) = dot {
                metadata["orphan_directory_dot_names_cluster"] = json!(named);
            }
            metadata["path_basis"] = json!(
                "no directory entry leads to this cluster and no '.' entry names it: it is a free \
                 cluster whose slots all read as directory entries, so the path names the cluster, \
                 not a folder, and which directory it belonged to is not stated"
            );
            return;
        }
        metadata["recovered_from_free_space"] = json!(self.fat_state == OrphanFatState::Free);
        metadata["orphan_fat_state"] = json!(self.fat_state.as_str());
        metadata["orphan_directory_cluster"] = json!(self.cluster);
        metadata["orphan_parent_cluster"] = json!(self.parent_cluster);
        if let Some(reason) = self.listing_incomplete {
            metadata["orphan_directory_listing_incomplete"] = json!(true);
            metadata["orphan_directory_listing_incomplete_reason"] = json!(reason);
        }
        if let Some(path) = &self.parent_path_now {
            metadata["orphan_parent_path_now"] = json!(path);
            metadata["orphan_parent_path_basis"] = json!(
                "the '..' entry's cluster is, today, this live directory; that is where the \
                 volume says the cluster is now, not where the directory sat when it was \
                 deleted, since the cluster may have been reused"
            );
        }
        metadata["path_basis"] = json!(match self.fat_state {
            OrphanFatState::Free => {
                "the parent directory's entry was not found; the directory was located by its \
                 own '.' entry in a free cluster, so the path names the cluster, not a folder"
            }
            OrphanFatState::Allocated => {
                "the parent directory's entry was not found; the directory was located by its \
                 own '.' entry in a cluster the FAT still shows allocated, so the path names \
                 the cluster, not a folder, and nothing here says the directory was deleted"
            }
        });
    }
}

/// What a scan of the free clusters for orphaned directories found.
#[derive(Debug, Default)]
pub(crate) struct OrphanScan {
    pub directories: Vec<OrphanDirectory>,
    pub free_clusters_examined: u64,
    /// Free clusters left unexamined at [`MAX_ORPHAN_SCAN_CLUSTERS`].
    pub free_clusters_not_examined: u64,
    /// Allocated clusters no walked directory leads to, examined with what the
    /// free clusters left of the same budget.
    pub allocated_clusters_examined: u64,
    pub allocated_clusters_not_examined: u64,
    pub unreadable_clusters: u64,
}

impl OrphanScan {
    fn stamp_summary(&self, metadata: &mut serde_json::Value) {
        metadata["orphan_directory_scan"] = json!({
            "directories_found": self.directories.len(),
            "free_clusters_examined": self.free_clusters_examined,
            "free_clusters_not_examined": self.free_clusters_not_examined,
            "allocated_clusters_examined": self.allocated_clusters_examined,
            "allocated_clusters_not_examined": self.allocated_clusters_not_examined,
            "directories_in_allocated_clusters": self
                .directories
                .iter()
                .filter(|d| d.fat_state == OrphanFatState::Allocated)
                .count(),
            "unreadable_clusters": self.unreadable_clusters,
            "max_clusters_examined": MAX_ORPHAN_SCAN_CLUSTERS,
            "scope": "clusters beginning with '.' and '..' entries, free first and then \
                      allocated clusters no walked directory leads to (reported as unreachable, \
                      not as deleted); a free directory is followed into the next clusters only \
                      while they are free and hold plausible entries (a contiguity assumption, \
                      stamped on each record); a directory whose first cluster is reallocated or \
                      overwritten is not found, and neither are its later clusters",
        });
        // Two different ways to fall short, and either one means the scan is
        // not exhaustive: the budget ran out, or a candidate cluster could not
        // be read (a truncated image chunk) so a directory may have sat in it.
        let bound = self.free_clusters_not_examined + self.allocated_clusters_not_examined > 0;
        let unreadable = self.unreadable_clusters > 0;
        let reason = match (bound, unreadable) {
            (false, false) => return,
            (true, false) => "bound",
            (false, true) => "unreadable_clusters",
            (true, true) => "bound_and_unreadable_clusters",
        };
        metadata["orphan_directory_scan_incomplete"] = json!(true);
        metadata["orphan_directory_scan_incomplete_reason"] = json!(reason);
    }
}

/// True when `entry` is the dot entry named `dots` of a directory.
fn is_dot_entry(entry: &[u8; 32], dots: &[u8; 11]) -> bool {
    &entry[..11] == dots && entry[11] & 0x10 != 0 && entry[11] != ATTR_LONG_NAME
}

/// Look for directories no entry leads to: a cluster whose first two entries
/// are `.` pointing at that very cluster and `..`. Free clusters are tried
/// first (a deleted directory), then allocated ones (an unreachable one, not
/// reported as deleted). A directory the live walk reached (`reached`) is
/// excluded.
fn scan_orphan_directories(
    boot_sector: &FatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &FatTable,
    total_clusters: u64,
    reached: &HashSet<u32>,
) -> OrphanScan {
    const DOT: [u8; 11] = *b".          ";
    const DOTDOT: [u8; 11] = *b"..         ";
    let mut scan = OrphanScan::default();
    // Free clusters first, so the budget goes to what the scan always found;
    // then the allocated clusters no walked directory leads to.
    for state in [OrphanFatState::Free, OrphanFatState::Allocated] {
        for cluster in 2..total_clusters.saturating_add(2) {
            let Ok(cluster) = u32::try_from(cluster) else {
                break;
            };
            let in_state = match (state, fat_table.raw_entry(cluster)) {
                (OrphanFatState::Free, Some(0)) => true,
                (OrphanFatState::Allocated, Some(v)) => v != 0,
                _ => false,
            };
            if !in_state || reached.contains(&cluster) {
                continue;
            }
            let examined = scan.free_clusters_examined + scan.allocated_clusters_examined;
            if examined >= MAX_ORPHAN_SCAN_CLUSTERS {
                match state {
                    OrphanFatState::Free => scan.free_clusters_not_examined += 1,
                    OrphanFatState::Allocated => scan.allocated_clusters_not_examined += 1,
                }
                continue;
            }
            match state {
                OrphanFatState::Free => scan.free_clusters_examined += 1,
                OrphanFatState::Allocated => scan.allocated_clusters_examined += 1,
            }
            let offset = boot_sector.cluster_to_offset(cluster);
            let (Ok(first), Ok(second)) = (
                read_dir_entry(data_source, offset),
                read_dir_entry(data_source, offset + 32),
            ) else {
                scan.unreadable_clusters += 1;
                continue;
            };
            if !is_dot_entry(&first, &DOT) || !is_dot_entry(&second, &DOTDOT) {
                continue;
            }
            let (Ok(dot), Ok(dotdot)) = (
                DirectoryEntry::parse(&first),
                DirectoryEntry::parse(&second),
            ) else {
                continue;
            };
            if dot.first_cluster() == cluster {
                scan.directories.push(OrphanDirectory {
                    cluster,
                    parent_cluster: dotdot.first_cluster(),
                    fat_state: state,
                    parent_path_now: None,
                    listing_incomplete: None,
                    headless: None,
                });
            }
        }
    }
    scan
}

/// Free clusters examined for directory entries no `.` anchors, at most (`HUNT-278`): a
/// slot read per cluster, then the whole cluster for the few whose first slot reads as an entry.
pub(crate) const MAX_HEADLESS_SCAN_CLUSTERS: u64 = 1 << 20;

/// What a scan of the free clusters for headless directory clusters found.
#[derive(Debug, Default)]
pub(crate) struct HeadlessScan {
    pub directories: Vec<OrphanDirectory>,
    pub clusters_examined: u64,
    pub clusters_not_examined: u64,
    pub unreadable_clusters: u64,
}

/// Whether the slots of one cluster read as a directory's entries and nothing else: every slot
/// before the end marker (or every slot, when there is none) passes [`plausible_dir_slot`], at
/// least two of them are short entries (not long-name slots, not `.`/`..`), and the cluster
/// does not start at its end marker. Strict by design: file bytes that pass are read as names.
pub(crate) fn headless_cluster_qualifies(slots: &[[u8; 32]], last_data_cluster: u32) -> bool {
    if slots.is_empty() || slots[0][0] == 0x00 {
        return false;
    }
    let mut short_entries = 0usize;
    for slot in slots {
        if slot[0] == 0x00 {
            break;
        }
        if !plausible_dir_slot(slot, last_data_cluster) {
            return false;
        }
        let is_dot = slot[0] == b'.';
        if slot[11] != ATTR_LONG_NAME && !is_dot {
            short_entries += 1;
        }
    }
    short_entries >= 2
}

/// Look for directory entries in free clusters no directory leads to and no `.` names:
/// clusters (not in `anchored`) that [`headless_cluster_qualifies`], found by reading each free
/// cluster's first slot and then the rest of the few that start as an entry.
fn scan_headless_directories(
    boot_sector: &FatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &FatTable,
    total_clusters: u64,
    anchored: &HashSet<u32>,
) -> HeadlessScan {
    const DOT: [u8; 11] = *b".          ";
    const DOTDOT: [u8; 11] = *b"..         ";
    let mut scan = HeadlessScan::default();
    let last_data_cluster = fat_table.last_data_cluster().min(u64::from(u32::MAX)) as u32;
    for cluster in 2..total_clusters.saturating_add(2) {
        let Ok(cluster) = u32::try_from(cluster) else {
            break;
        };
        if fat_table.raw_entry(cluster) != Some(0) || anchored.contains(&cluster) {
            continue;
        }
        if scan.clusters_examined >= MAX_HEADLESS_SCAN_CLUSTERS {
            scan.clusters_not_examined += 1;
            continue;
        }
        scan.clusters_examined += 1;
        let offset = boot_sector.cluster_to_offset(cluster);
        let Ok(first) = read_dir_entry(data_source, offset) else {
            scan.unreadable_clusters += 1;
            continue;
        };
        if first[0] == 0x00 || !plausible_dir_slot(&first, last_data_cluster) {
            continue;
        }
        let Some(slots) = read_cluster_slots(boot_sector, data_source, cluster) else {
            scan.unreadable_clusters += 1;
            continue;
        };
        // A cluster too thin to qualify alone (a single entry, the last of a directory) is taken
        // when it is the verified continuation of a name that began in the cluster before it.
        let continues_a_name = || {
            slots
                .iter()
                .take_while(|s| s[0] != 0x00)
                .all(|s| plausible_dir_slot(s, last_data_cluster))
                && !stitch_seed(
                    boot_sector,
                    data_source,
                    fat_table,
                    anchored,
                    cluster,
                    &slots,
                )
                .is_empty()
        };
        if !headless_cluster_qualifies(&slots, last_data_cluster) && !continues_a_name() {
            continue;
        }
        let dot =
            (slots.len() >= 2 && is_dot_entry(&slots[0], &DOT) && is_dot_entry(&slots[1], &DOTDOT))
                .then(|| {
                    DirectoryEntry::parse(&slots[0])
                        .ok()
                        .map(|d| d.first_cluster())
                })
                .flatten();
        scan.directories.push(OrphanDirectory {
            cluster,
            parent_cluster: 0,
            fat_state: OrphanFatState::Free,
            parent_path_now: None,
            listing_incomplete: None,
            headless: Some(dot),
        });
    }
    scan
}

/// Directory clusters looked back over for the one before a headless cluster, at most.
const STITCH_LOOKBACK_CLUSTERS: u32 = 4096;

/// The long-name slots that end the directory cluster before `cluster`, when they are the head
/// of the name whose deleted short entry sits in this cluster (`HUNT-278`).
///
/// A long name's slots precede its short entry, so a name written across a cluster boundary has
/// its tail slots (the head of the name) in one cluster and its short entry in the next. A
/// deleted directory whose clusters are not adjacent cannot be followed, so each cluster is read
/// on its own and such a name comes back cut short. The nearest directory-like free cluster
/// below is taken as the one before, and its trailing slots are joined to this cluster's leading
/// ones only if all of these hold, otherwise nothing is joined:
///
/// * the first entry of the cluster is a deleted short entry whose name does not open this
///   cluster complete: either no name slots before it, or leading ones whose first lacks the
///   terminator of a finished name;
/// * every slot of both halves carries the same 8.3 checksum;
/// * the first byte of the short name that checksum implies (the entry's own is the deletion
///   marker, and the checksum is a bijection in it) is what the driver writes for the name's
///   first character: its upper-case form, when that is an ASCII letter or digit.
fn stitch_seed(
    boot_sector: &FatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &FatTable,
    anchored: &HashSet<u32>,
    cluster: u32,
    slots: &[[u8; 32]],
) -> Vec<LfnEntry> {
    let last_data_cluster = fat_table.last_data_cluster().min(u64::from(u32::MAX)) as u32;
    let Some(short_at) = slots.iter().position(|s| s[11] != ATTR_LONG_NAME) else {
        return Vec::new();
    };
    let short = &slots[short_at];
    // A deleted short entry (`0xE5`) is joined on the checksum; one a driver left unmarked (Haiku's) is
    // joined on the checksum of its own name and on the ordinals, which then say exactly what is missing.
    let kept = short[0] != 0xE5;
    if (kept && !short_name_plausible(short)) || short[11] & ATTR_VOLUME_ID != 0 {
        return Vec::new();
    }
    let leading: Vec<LfnEntry> = slots[..short_at]
        .iter()
        .filter_map(|s| LfnEntry::parse(s).ok())
        .collect();
    let name_complete = |l: &LfnEntry| {
        l.opens_chain_by_ordinal()
            .unwrap_or_else(|| l.is_terminated())
    };
    if leading.first().is_some_and(name_complete) {
        return Vec::new();
    }
    let mut previous = None;
    for back in 1..=STITCH_LOOKBACK_CLUSTERS.min(cluster.saturating_sub(2)) {
        let candidate = cluster - back;
        if fat_table.raw_entry(candidate) != Some(0) {
            continue;
        }
        // File data between two clusters of a directory is passed over on its first slot.
        if !anchored.contains(&candidate)
            && !read_dir_entry(data_source, boot_sector.cluster_to_offset(candidate)).is_ok_and(
                |first| first[0] != 0x00 && plausible_dir_slot(&first, last_data_cluster),
            )
        {
            continue;
        }
        let Some(candidate_slots) = read_cluster_slots(boot_sector, data_source, candidate) else {
            continue;
        };
        if anchored.contains(&candidate)
            || headless_cluster_qualifies(&candidate_slots, last_data_cluster)
        {
            previous = Some(candidate_slots);
            break;
        }
    }
    let Some(previous) = previous else {
        return Vec::new();
    };
    let tail: Vec<LfnEntry> = previous
        .iter()
        .rev()
        .take_while(|s| s[11] == ATTR_LONG_NAME)
        .filter_map(|s| LfnEntry::parse(s).ok())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let Some(last_of_tail) = tail.last() else {
        return Vec::new();
    };
    let checksum = last_of_tail.checksum;
    if !tail.iter().chain(&leading).all(|l| l.checksum == checksum) {
        return Vec::new();
    }
    if kept {
        return if kept_ordinals_join(&tail, &leading, short) {
            tail
        } else {
            Vec::new()
        };
    }
    // The name's first character is in the slot nearest the short entry.
    let first_char = leading
        .last()
        .unwrap_or(last_of_tail)
        .get_name_part()
        .chars()
        .next();
    let implied_first_byte = (0..=255u8).find(|&b| {
        let mut name = [0u8; 11];
        name.copy_from_slice(&short[..11]);
        name[0] = b;
        lfn_checksum_of(&name) == checksum
    });
    let consistent = match (implied_first_byte, first_char) {
        (Some(b), Some(c)) if c.is_ascii_alphanumeric() => b == c.to_ascii_uppercase() as u8,
        (Some(_), Some(_)) => true,
        _ => false,
    };
    if consistent {
        tail
    } else {
        Vec::new()
    }
}

/// A short entry whose first byte was not replaced: an 8.3 name of printable bytes.
fn short_name_plausible(short: &[u8; 32]) -> bool {
    short[..11].iter().all(|&b| b >= 0x20 && b != 0x7F)
}

/// Whether the head `tail` (the end of the cluster before) and the `leading` slots of this cluster are
/// one name, from slots that kept their ordinals: every ordinal is present, the head opens the chain, the
/// positions count down by one to the slot beside the short entry, and the checksum every slot carries is
/// the one of the short entry's own, unmarked name.
fn kept_ordinals_join(tail: &[LfnEntry], leading: &[LfnEntry], short: &[u8; 32]) -> bool {
    let chain: Vec<&LfnEntry> = tail.iter().chain(leading).collect();
    let Some(head) = chain.first() else {
        return false;
    };
    let mut name = [0u8; 11];
    name.copy_from_slice(&short[..11]);
    head.opens_chain_by_ordinal() == Some(true)
        && chain
            .iter()
            .skip(1)
            .all(|l| l.opens_chain_by_ordinal() == Some(false))
        && chain
            .iter()
            .zip((1..=chain.len() as u8).rev())
            .all(|(l, position)| l.ordinal_position() == position)
        && chain.iter().all(|l| l.checksum == lfn_checksum_of(&name))
}

/// The most clusters a deleted file's reconstruction will list one by one. A deleted file's size is the
/// directory entry's own and can claim gigabytes; past this the clusters are taken as one contiguous run.
const SKIP_SCAN_MAX_CLUSTERS: u64 = 1 << 16;

/// A deleted file's clusters as its freed chain can be guessed: from its start cluster upward, in order, skipping
/// every cluster the FAT calls allocated now (it belongs to a file written since), until the recorded size is
/// covered or the volume ends. Returns the clusters and how many allocated ones were skipped. This is what
/// The Sleuth Kit does, and on the Canon camera card of `HUNT-278` it recovered three erased photos a strictly
/// contiguous read could not: the later photos had taken clusters in the middle of the old run. It is still a
/// guess, and the caller says so.
fn clusters_skipping_allocated(
    fat_table: &FatTable,
    start: u32,
    needed: u64,
) -> Option<(Vec<u32>, u64)> {
    if start < 2 || needed == 0 || needed > SKIP_SCAN_MAX_CLUSTERS {
        return None;
    }
    let last = fat_table.last_data_cluster();
    let mut clusters = Vec::with_capacity(needed as usize);
    let mut skipped = 0u64;
    let mut cluster = u64::from(start);
    while (clusters.len() as u64) < needed && cluster <= last {
        if cluster == u64::from(start) || fat_table.raw_entry(cluster as u32) == Some(0) {
            clusters.push(cluster as u32);
        } else {
            skipped += 1;
        }
        cluster += 1;
    }
    Some((clusters, skipped))
}

/// The 8-bit checksum a long name's slots carry for an 11-byte short name.
fn lfn_checksum_of(name: &[u8; 11]) -> u8 {
    name.iter().fold(0u8, |sum, &b| {
        (sum >> 1)
            .wrapping_add(if sum & 1 != 0 { 0x80 } else { 0 })
            .wrapping_add(b)
    })
}

/// Read exactly one 32-byte FAT directory entry at `offset`.
///
/// A short read is a hard failure. `read_at` may legitimately return fewer bytes
/// than requested; leaving the tail zeroed would either fabricate a directory
/// entry out of half a record or forge the 0x00 end-of-directory marker
/// (BUG-188).
fn read_dir_entry(data_source: &Arc<dyn DataSource>, offset: u64) -> io::Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    let mut filled = 0usize;
    while filled < 32 {
        match data_source.read_at(offset + filled as u64, &mut buf[filled..])? {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "short read of FAT directory entry at offset {} ({} of 32 bytes)",
                        offset, filled
                    ),
                ))
            }
            n => filled += n,
        }
    }
    Ok(buf)
}

/// Parse the volume's root directory, returning its entries plus why the
/// listing is short, when it is (`None` means whole; see [`parse_directory`]
/// for what a short listing costs an examiner). The reason is the token the
/// caller stamps on the volume record.
fn parse_root_directory(
    boot_sector: &FatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &FatTable,
) -> Result<(Vec<ParsedDirectoryEntry>, Option<&'static str>, u64)> {
    let bpb = &boot_sector.bpb;

    // A BPB that is half FAT32 and half FAT12/16 does not say where the root
    // directory is. Reading it as empty would be "nothing found" for "could not
    // look".
    if let Some(reason) = bpb.layout_inconsistency() {
        return Ok((Vec::new(), Some(reason), 0));
    }

    match boot_sector.fat_type {
        FatType::Fat32 => {
            // FAT32: Root directory is a cluster chain — use the same logic as subdirectories
            let root_cluster = match &boot_sector.extended {
                FatExtendedBpb::Fat32(ext) => ext.root_cluster,
                _ => return Err(anyhow::anyhow!("Invalid extended BPB for FAT32")),
            };
            // Cluster 0 and 1 are not data clusters: the root could not be
            // located, which is not the same as the root being empty.
            if root_cluster < 2 {
                return Ok((Vec::new(), Some("fat_root_cluster_invalid"), 0));
            }
            let listing = parse_directory(boot_sector, data_source, fat_table, root_cluster)?;
            Ok((
                listing.entries,
                listing.incomplete.map(|_| "fat_root_chain_incomplete"),
                listing.slack_rejected,
            ))
        }
        FatType::Fat12 | FatType::Fat16 => {
            // FAT12/16: Root directory is at a fixed location after the FATs
            let fat_size = bpb.sectors_per_fat() * bpb.num_fats as u32;
            let root_dir_sector = bpb.reserved_sectors as u32 + fat_size;
            let root_dir_byte_offset = root_dir_sector as u64 * bpb.bytes_per_sector as u64;
            let slots = (0..bpb.root_entries as u64).map(|i| root_dir_byte_offset + i * 32);
            let (entries, complete) = parse_directory_slots(data_source, slots)?;
            Ok((
                entries,
                (!complete).then_some("fat_root_chain_incomplete"),
                0,
            ))
        }
    }
}

/// Decode directory entries from the 32-byte slots at `slot_offsets`, in order,
/// until the end-of-directory marker or a slot the source cannot deliver.
///
/// One lazy iterator over every slot of the directory, so LFN buffering carries
/// across cluster boundaries. Returns the entries plus whether the walk ended
/// on the marker (`true`) or on a read error (`false`): an unreadable slot is
/// not the end of the directory, only the end of what this image can tell us.
fn parse_directory_slots(
    data_source: &Arc<dyn DataSource>,
    slot_offsets: impl Iterator<Item = u64>,
) -> Result<(Vec<ParsedDirectoryEntry>, bool)> {
    let scan = scan_slots(data_source, slot_offsets, None, u32::MAX)?;
    Ok((scan.entries, scan.complete))
}

/// What reading a directory's slots produced.
struct SlotScan {
    entries: Vec<ParsedDirectoryEntry>,
    /// The walk ended on the marker or the end of the slots, not a read error.
    complete: bool,
    /// Slots behind the end marker that were examined and refused.
    slack_rejected: u64,
}

/// [`parse_directory_slots`], optionally also reading what sits behind the
/// `0x00` end marker (HUNT-278). With `slack_cluster_slots = Some(n)`, the
/// slots of the marker's own cluster after the marker (`n` slots per cluster,
/// counted from the first slot given) are tried as directory entries, and a slot
/// is kept only if [`plausible_dir_slot`] accepts it; each kept entry is flagged
/// `after_end_marker` and deleted. Clusters after the marker's are not read.
fn scan_slots(
    data_source: &Arc<dyn DataSource>,
    slot_offsets: impl Iterator<Item = u64>,
    slack_cluster_slots: Option<u64>,
    last_data_cluster: u32,
) -> Result<SlotScan> {
    scan_slots_seeded(
        data_source,
        slot_offsets,
        slack_cluster_slots,
        last_data_cluster,
        Vec::new(),
    )
}

/// [`scan_slots`] starting with `seed`, the long-name slots that end the cluster before the
/// first one given (in the order they lie on disk), for a directory cluster whose first name
/// began in another.
fn scan_slots_seeded(
    data_source: &Arc<dyn DataSource>,
    slot_offsets: impl Iterator<Item = u64>,
    slack_cluster_slots: Option<u64>,
    last_data_cluster: u32,
    seed: Vec<LfnEntry>,
) -> Result<SlotScan> {
    let mut entries = Vec::new();
    let mut seeded = !seed.is_empty();
    let mut lfn_buffer: Vec<LfnEntry> = seed;
    let mut slack_rejected = 0u64;
    // Slots left behind the marker in its cluster, once it is found.
    let mut slack_left: Option<u64> = None;
    let mut slot_index = 0u64;

    for entry_offset in slot_offsets {
        slot_index += 1;
        if slack_left == Some(0) {
            break;
        }
        let mut entry_data = match read_dir_entry(data_source, entry_offset) {
            Ok(data) => data,
            Err(e) => {
                debug!(
                    "Failed to read directory entry at offset {}: {}",
                    entry_offset, e
                );
                return Ok(SlotScan {
                    entries,
                    complete: false,
                    slack_rejected,
                });
            }
        };

        // The end-of-directory marker is decided from the same decoded record
        // the rest of this loop already builds, not a second inline reading of
        // byte 0 (see `is_end_of_directory`).
        let candidate = DirectoryEntry::parse(&entry_data).map_err(|e| anyhow::anyhow!(e))?;
        if let Some(left) = slack_left.as_mut() {
            *left -= 1;
            if entry_data[0] == 0x00 {
                // A zeroed tail is the normal case and says nothing.
                lfn_buffer.clear();
                continue;
            }
            if !plausible_dir_slot(&entry_data, last_data_cluster) {
                slack_rejected += 1;
                lfn_buffer.clear();
                continue;
            }
        } else if candidate.is_end_of_directory() {
            match slack_cluster_slots {
                Some(per_cluster) if per_cluster > 0 => {
                    slack_left = Some(per_cluster - (slot_index - 1) % per_cluster - 1);
                    lfn_buffer.clear();
                    continue;
                }
                _ => break,
            }
        }
        let after_end_marker = slack_left.is_some();

        // Deleted entries (0xE5 marker); behind the end marker every entry is
        // an earlier state, so none is presented as live.
        let first_byte_marked = entry_data[0] == 0xE5;
        let is_deleted = first_byte_marked || after_end_marker;
        if first_byte_marked {
            entry_data[0] = b'_';
        }

        if entry_data[11] == ATTR_LONG_NAME {
            // The ordinal is read from the byte the driver left: a marked slot keeps `0xE5` here, which
            // says the ordinal is gone, and an unmarked one keeps the ordinal itself.
            let mut raw = entry_data;
            if first_byte_marked {
                raw[0] = 0xE5;
            }
            if let Ok(lfn_entry) = LfnEntry::parse(&raw) {
                lfn_buffer.push(lfn_entry);
            }
            continue;
        }

        if let Ok(dir_entry) = DirectoryEntry::parse(&entry_data) {
            if dir_entry.is_volume_label() {
                lfn_buffer.clear();
                continue;
            }

            // Reconstruct long filename only from an LFN chain that actually
            // belongs to this short entry (validated 8.3 checksum) (BUG-163).
            let chain_used = lfn_chain_matches(&lfn_buffer, &dir_entry, is_deleted);
            // A kept ordinal says outright whether the name's head is here; a deleted slot lost it, and the
            // terminator is then the only sign of a finished name.
            let chain_cut = match lfn_buffer.first().map(LfnEntry::opens_chain_by_ordinal) {
                Some(Some(opens)) => !opens,
                Some(None) => is_deleted && lfn_buffer.first().is_some_and(|l| !l.is_terminated()),
                None => false,
            };
            let stitched = std::mem::take(&mut seeded);
            let long_name = if chain_used {
                lfn_buffer.reverse();
                Some(
                    lfn_buffer
                        .iter()
                        .map(|lfn| lfn.get_name_part())
                        .collect::<String>(),
                )
            } else {
                None
            };

            lfn_buffer.clear();

            let (short_name, short_name_decoded) = dir_entry.get_short_name();
            entries.push(ParsedDirectoryEntry {
                short_name,
                short_name_decoded,
                long_name,
                dir_entry,
                deleted: is_deleted,
                slot_offset: entry_offset,
                after_end_marker,
                chain_basis: None,
                long_name_stitched: chain_used && stitched,
                long_name_possibly_truncated: chain_used && chain_cut,
            });
        }
    }

    Ok(SlotScan {
        entries,
        complete: true,
        slack_rejected,
    })
}

/// True when a 32-byte slot behind a directory's end marker, or in a cluster
/// only assumed to belong to a deleted directory, could be a directory entry
/// some FAT driver wrote. Strict by design: a slot that fails is refused, never
/// guessed at, because the alternative is reading file bytes as file names.
///
/// A short entry passes when its name bytes are legal in an 8.3 name (or the
/// slot is a long-name slot with a legal ordinal and zero type and cluster
/// fields), its attribute byte has neither of the two reserved top bits, its
/// dates and times are zero or in range, its first cluster is inside the
/// volume, a directory records size 0 and a file with a size has a cluster.
pub(crate) fn plausible_dir_slot(slot: &[u8; 32], last_data_cluster: u32) -> bool {
    if slot[0] == 0x00 {
        return false;
    }
    let attr = slot[11];
    if attr == ATTR_LONG_NAME {
        let ordinal = slot[0] & 0x3F;
        let ordinal_ok = slot[0] == 0xE5 || (1..=20).contains(&ordinal);
        return ordinal_ok && slot[12] == 0 && slot[26] == 0 && slot[27] == 0;
    }
    if attr & 0xC0 != 0 || (attr & ATTR_VOLUME_ID != 0 && attr & ATTR_DIRECTORY != 0) {
        return false;
    }
    const ILLEGAL: &[u8] = b"\"*+,/:;<=>?[\\]|";
    for (i, &b) in slot[..11].iter().enumerate() {
        let first_marker = i == 0 && (b == 0xE5 || b == 0x05);
        if !first_marker && (b < 0x20 || b == 0x7F || ILLEGAL.contains(&b)) {
            return false;
        }
    }
    let date_ok = |d: u16| d == 0 || ((1..=12).contains(&((d >> 5) & 0xF)) && (d & 0x1F) >= 1);
    let time_ok = |t: u16| (t >> 11) < 24 && ((t >> 5) & 0x3F) < 60 && (t & 0x1F) < 30;
    let le16 = |at: usize| u16::from_le_bytes([slot[at], slot[at + 1]]);
    if !(time_ok(le16(14))
        && date_ok(le16(16))
        && date_ok(le16(18))
        && time_ok(le16(22))
        && date_ok(le16(24)))
    {
        return false;
    }
    let cluster = (u32::from(le16(20)) << 16) | u32::from(le16(26));
    let size = u32::from_le_bytes([slot[28], slot[29], slot[30], slot[31]]);
    if cluster > last_data_cluster {
        return false;
    }
    if attr & ATTR_DIRECTORY != 0 {
        return size == 0;
    }
    size == 0 || cluster >= 2
}

/// True when a buffered LFN slot chain legitimately belongs to `dir_entry`.
///
/// Every slot of one long name stores the same 8.3 checksum byte. Reject a
/// buffer whose slots disagree (a torn chain, or a free slot left over from a
/// different file) and, for a live entry, one whose checksum does not match the
/// short entry it precedes. Deleted short names lose their first byte to the
/// 0xE5 marker, so only the internal-consistency check applies there (BUG-163).
pub(crate) fn lfn_chain_matches(
    lfn_buffer: &[LfnEntry],
    dir_entry: &DirectoryEntry,
    is_deleted: bool,
) -> bool {
    let Some(first) = lfn_buffer.first() else {
        return false;
    };
    let cs = first.checksum;
    if !lfn_buffer.iter().all(|l| l.checksum == cs) {
        return false;
    }
    is_deleted || cs == dir_entry.lfn_checksum()
}

/// Parse a directory's entries by following its FAT cluster chain.
///
/// Returns the entries plus, in `incomplete`, why the listing may not cover the
/// whole directory (`None` when it does). Set means the chain walk stopped early — the safety cap, a cyclic FAT, or
/// a cluster the image cannot deliver — so entries after that point exist on
/// disk but are not in the returned list. The caller must stamp the directory's
/// artifact rather than present a silent prefix as a complete listing: an
/// examiner who cannot see the difference will testify that a file was not
/// there.
fn parse_directory(
    boot_sector: &FatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &FatTable,
    first_cluster: u32,
) -> Result<DirListing> {
    // Skip invalid cluster numbers
    if first_cluster < 2 {
        return Ok(DirListing::default());
    }

    // Follow cluster chain for the directory
    let (cluster_chain, chain_incomplete) = fat_table.follow_chain(first_cluster);
    let slots_per_cluster = (boot_sector.cluster_size_bytes() / 32) as u64;

    // Byte offset of each slot in the filesystem window. Use the boot sector
    // helper, which accounts for the FAT12/16 fixed root-directory region; a
    // naive reserved+FATs sum lands subdirectory reads back in the root
    // directory and recurses forever.
    let slots = cluster_chain.into_iter().flat_map(|cluster| {
        let base = boot_sector.cluster_to_offset(cluster);
        (0..slots_per_cluster).map(move |i| base + i * 32)
    });
    let scan = scan_slots(
        data_source,
        slots,
        Some(slots_per_cluster),
        fat_table.last_data_cluster().min(u64::from(u32::MAX)) as u32,
    )?;
    Ok(DirListing {
        entries: scan.entries,
        incomplete: (!scan.complete || chain_incomplete.is_some())
            .then_some("fat_chain_incomplete"),
        slack_rejected: scan.slack_rejected,
        ..DirListing::default()
    })
}

/// Clusters a deleted directory may be extended over when its FAT chain is
/// gone, at most. A directory this large is read as far as this and flagged.
const MAX_DELETED_DIR_CLUSTERS: usize = 4096;

/// A directory's entries and what is known about how complete they are.
#[derive(Default)]
struct DirListing {
    entries: Vec<ParsedDirectoryEntry>,
    /// Why the listing may stop short of the directory; `None` when it covers it.
    incomplete: Option<&'static str>,
    /// The directory's first cluster did not hold the directory's own `.` and
    /// `..`, so nothing was read from it. `Some(true)` when the FAT also shows
    /// the cluster in use again (reallocated), `Some(false)` when it is free
    /// but holds something else.
    content_refused: Option<bool>,
    /// The directory's first cluster is free and every byte of it is zero, so no entry
    /// can be read. Either the directory held no entries or its content was wiped
    /// (Windows 11's drivers were observed to zero a deleted directory's clusters).
    content_zero: bool,
    /// Clusters read on the assumption that a deleted directory was contiguous.
    assumed_clusters: usize,
    /// The clusters after the first that were read that way: they are part of this listing, so no
    /// scan for directory clusters nothing leads to may read them again.
    assumed_later_clusters: Vec<u32>,
    /// Slots behind an end marker that were examined and refused.
    slack_rejected: u64,
}

impl DirListing {
    /// Say on the directory's own record how far its listing can be trusted, so
    /// a short or refused listing is never read as the whole directory.
    fn stamp_directory(&self, meta: &mut serde_json::Value) {
        if let Some(reason) = self.incomplete {
            meta["directory_parse_incomplete"] = json!(true);
            meta["directory_parse_incomplete_reason"] = json!(reason);
        }
        if self.content_zero {
            meta["directory_content_zero"] = json!(true);
            meta["directory_content_basis"] = json!(
                "the first cluster of this deleted directory is free and entirely zero, so there \
                 is no entry to read: the directory held none, or its content was wiped (the \
                 Windows 11 FAT drivers were observed to zero a deleted directory's clusters); \
                 which it was cannot be told from this volume"
            );
        }
        match self.content_refused {
            Some(true) => {
                meta["directory_content_reallocated"] = json!(true);
                meta["directory_content_basis"] = json!(
                    "the first cluster of this deleted directory no longer begins with its own \
                     '.' and '..' entries and the FAT shows it in use again, so nothing was read \
                     from it; its entries cannot be listed from this volume"
                );
            }
            Some(false) => {
                meta["directory_content_unrecognised"] = json!(true);
                meta["directory_content_basis"] = json!(
                    "the first cluster of this deleted directory is free but no longer begins \
                     with its own '.' and '..' entries, so nothing was read from it"
                );
            }
            None => {}
        }
        if self.assumed_clusters > 1 {
            meta["directory_chain_basis"] = json!("contiguous_assumed");
            meta["directory_clusters_read"] = json!(self.assumed_clusters);
        }
    }
}

/// Read the slots of one cluster, or `None` when any cannot be delivered.
fn read_cluster_slots(
    boot_sector: &FatBootSector,
    data_source: &Arc<dyn DataSource>,
    cluster: u32,
) -> Option<Vec<[u8; 32]>> {
    let base = boot_sector.cluster_to_offset(cluster);
    let slots = (boot_sector.cluster_size_bytes() / 32) as u64;
    (0..slots)
        .map(|i| read_dir_entry(data_source, base + i * 32).ok())
        .collect()
}

/// Parse a deleted directory, whose FAT chain was freed when it was deleted.
///
/// Three things the live parse does not have to ask:
///
/// * Is this still the directory? Its first cluster must begin with the `.`
///   entry naming that very cluster and a `..` entry. If it does not, the
///   cluster was reallocated or overwritten, and reading it as a directory would
///   turn another file's bytes into file names; nothing is read and the
///   directory is flagged.
/// * Where did it go on? With the chain freed, a directory whose first cluster
///   has no `0x00` marker is extended over the *next* cluster only while that
///   cluster is free, not already claimed, and every slot before its own marker
///   passes [`plausible_dir_slot`]. That is a contiguity assumption, stamped on
///   every entry read that way as `directory_chain_basis`.
/// * Did it end? A directory whose last cluster read has no marker and whose
///   next cluster failed the test is flagged incomplete: later clusters may
///   exist and are not found.
///
/// A directory whose FAT chain is still intact (the entry was marked deleted but
/// the FAT was not freed) is followed through the FAT as a live one is.
fn parse_deleted_directory(
    boot_sector: &FatBootSector,
    data_source: &Arc<dyn DataSource>,
    fat_table: &FatTable,
    first_cluster: u32,
    reached: &HashSet<u32>,
) -> Result<DirListing> {
    const DOT: [u8; 11] = *b".          ";
    const DOTDOT: [u8; 11] = *b"..         ";
    if first_cluster < 2 {
        return Ok(DirListing::default());
    }
    let first_offset = boot_sector.cluster_to_offset(first_cluster);
    let first_free = fat_table.raw_entry(first_cluster) == Some(0);
    let names_itself = match (
        read_dir_entry(data_source, first_offset),
        read_dir_entry(data_source, first_offset + 32),
    ) {
        (Ok(a), Ok(b)) => {
            is_dot_entry(&a, &DOT)
                && is_dot_entry(&b, &DOTDOT)
                && DirectoryEntry::parse(&a).is_ok_and(|d| d.first_cluster() == first_cluster)
        }
        _ => false,
    };
    if !names_itself {
        // A free first cluster that is all zero has nothing in it to be mistaken for another
        // file's bytes: say that, not "unverified".
        let cluster_len = boot_sector.cluster_size_bytes();
        let mut cluster = vec![0u8; cluster_len];
        let zero = first_free
            && seance_core::io::read_exact_or_fail(
                data_source.as_ref(),
                first_offset,
                &mut cluster,
                "deleted directory first cluster",
            )
            .is_ok()
            && cluster.iter().all(|&b| b == 0);
        if zero {
            return Ok(DirListing {
                incomplete: Some("fat_deleted_directory_zeroed"),
                content_zero: true,
                ..DirListing::default()
            });
        }
        return Ok(DirListing {
            incomplete: Some("fat_deleted_directory_unverified"),
            content_refused: Some(!first_free),
            ..DirListing::default()
        });
    }
    if !first_free {
        return parse_directory(boot_sector, data_source, fat_table, first_cluster);
    }

    let cluster_size = boot_sector.cluster_size_bytes() as u64;
    let slots_per_cluster = cluster_size / 32;
    let last_data_cluster = fat_table.last_data_cluster().min(u64::from(u32::MAX)) as u32;
    let mut clusters = vec![first_cluster];
    let mut incomplete = None;
    loop {
        let current = *clusters.last().unwrap_or(&first_cluster);
        let Some(slots) = read_cluster_slots(boot_sector, data_source, current) else {
            incomplete = Some("fat_chain_incomplete");
            break;
        };
        if slots.iter().any(|s| s[0] == 0x00) {
            break;
        }
        let next = current.saturating_add(1);
        if clusters.len() >= MAX_DELETED_DIR_CLUSTERS {
            incomplete = Some("fat_deleted_chain_unverified");
            break;
        }
        let continues = u64::from(next) <= u64::from(last_data_cluster)
            && fat_table.raw_entry(next) == Some(0)
            && !reached.contains(&next)
            && read_cluster_slots(boot_sector, data_source, next).is_some_and(|slots| {
                !slots.is_empty()
                    && slots
                        .iter()
                        .take_while(|s| s[0] != 0x00)
                        .all(|s| plausible_dir_slot(s, last_data_cluster))
                    && slots[0][0] != 0x00
            });
        if !continues {
            incomplete = Some("fat_deleted_chain_unverified");
            break;
        }
        clusters.push(next);
    }

    let slots = clusters.iter().flat_map(|&cluster| {
        let base = boot_sector.cluster_to_offset(cluster);
        (0..slots_per_cluster).map(move |i| base + i * 32)
    });
    let mut scan = scan_slots(
        data_source,
        slots,
        Some(slots_per_cluster),
        last_data_cluster,
    )?;
    if !scan.complete {
        incomplete = incomplete.or(Some("fat_chain_incomplete"));
    }
    for entry in &mut scan.entries {
        if entry.slot_offset >= first_offset + cluster_size {
            entry.chain_basis = Some("contiguous_assumed");
        }
    }
    Ok(DirListing {
        entries: scan.entries,
        incomplete,
        content_refused: None,
        content_zero: false,
        assumed_clusters: clusters.len(),
        assumed_later_clusters: clusters.iter().skip(1).copied().collect(),
        slack_rejected: scan.slack_rejected,
    })
}

/// Cluster allocation read off the FAT in one pass, in the two readings the
/// parser publishes. They differ only on the reserved value 1: the downsampled
/// map has always counted it free, the free-region emitter has always counted
/// it in use, and neither may be changed under an existing report.
struct FatAllocationBits {
    /// Bit `c - 2` set: cluster `c`'s entry is greater than 1.
    allocated: Vec<u8>,
    /// Bit `c - 2` set: cluster `c`'s entry is non-zero.
    in_use: Vec<u8>,
    /// How many clusters from 2 the FAT holds an entry for, capped at the
    /// volume's cluster count. Clusters past it are unassessed, not free.
    /// `in_use` is sized from it; the tests hold it to the per-cluster walk.
    #[cfg_attr(not(test), allow(dead_code))]
    speakable: u64,
}

/// FAT table reader for following cluster chains
struct FatTable {
    fat_type: FatType,
    table_data: Vec<u8>,
    /// Data clusters the BPB declares (numbered from 2). The FAT is padded to
    /// whole sectors and usually holds entries past the last data cluster; a
    /// chain naming one points outside the volume. `None` bounds nothing.
    data_clusters: Option<u64>,
}

impl FatTable {
    /// A table over `table_data` with no bound on the cluster numbers a chain
    /// may name beyond the entries the table holds.
    fn new(fat_type: FatType, table_data: Vec<u8>) -> Self {
        Self {
            fat_type,
            table_data,
            data_clusters: None,
        }
    }

    /// The highest cluster number that is a data cluster of this volume.
    fn last_data_cluster(&self) -> u64 {
        self.data_clusters
            .map_or(u64::MAX, |clusters| clusters.saturating_add(1))
    }

    /// How many entries, counting from cluster 0, the table holds: the clusters
    /// `raw_entry` answers for.
    fn entry_count(&self) -> u64 {
        let len = self.table_data.len() as u64;
        match self.fat_type {
            // Clusters (2k, 2k+1) share bytes 3k..3k+3; a two-byte tail still
            // answers the even cluster.
            FatType::Fat12 => {
                let even = if len >= 2 { (len - 2) / 3 + 1 } else { 0 };
                let odd = if len >= 3 { (len - 3) / 3 + 1 } else { 0 };
                even + odd
            }
            FatType::Fat16 => len / 2,
            FatType::Fat32 => len / 4,
        }
    }

    /// Read the FAT table from the data source
    fn read(boot_sector: &FatBootSector, data_source: &Arc<dyn DataSource>) -> Result<Self> {
        let bpb = &boot_sector.bpb;

        // Calculate FAT size
        let sectors_per_fat = match &boot_sector.extended {
            FatExtendedBpb::Fat32(ext) => ext.sectors_per_fat_32,
            FatExtendedBpb::Fat16(_) => bpb.sectors_per_fat_16 as u32,
        };

        // sectors_per_fat and bytes_per_sector are attacker-controlled header
        // fields; a bogus pair (e.g. 0xFFFFFFFF * 0xFFFF) would request a
        // multi-terabyte allocation. Compute with checked arithmetic and never
        // allocate more than the data source can actually provide.
        let fat_size_bytes = (sectors_per_fat as u64)
            .checked_mul(bpb.bytes_per_sector as u64)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "FAT size overflow: {} sectors * {} bytes/sector",
                    sectors_per_fat,
                    bpb.bytes_per_sector
                )
            })?;
        let fat_size_bytes = fat_size_bytes.min(data_source.size()) as usize;
        let fat_offset = bpb.reserved_sectors as u64 * bpb.bytes_per_sector as u64;

        // Read first FAT table
        let mut table_data = vec![0u8; fat_size_bytes];
        // Fail closed on a short read: the unread tail would stay zero, and a
        // zero FAT entry reads as a free/terminated cluster, silently truncating
        // every chain that runs through the missing region (BUG-155). Gather the
        // table with `read_full` first — one `read_at` returning less than the
        // whole FAT is ordinary on a windowed or container-backed source, and
        // rejecting the volume on that basis would lose a readable filesystem.
        let n = read_full(data_source.as_ref(), fat_offset, &mut table_data);
        if n < fat_size_bytes {
            return Err(anyhow::anyhow!(
                "FAT table short read ({} of {} bytes) at offset {}",
                n,
                fat_size_bytes,
                fat_offset
            ));
        }

        Ok(FatTable {
            data_clusters: Some(u64::from(bpb.total_clusters(sectors_per_fat))),
            ..FatTable::new(boot_sector.fat_type, table_data)
        })
    }

    /// Raw FAT entry value for a cluster, without end-of-chain interpretation.
    /// None when the cluster is outside the table.
    fn raw_entry(&self, cluster: u32) -> Option<u32> {
        match self.fat_type {
            FatType::Fat12 => {
                let offset = (cluster as usize * 3) / 2;
                if offset + 1 >= self.table_data.len() {
                    return None;
                }
                let value = if cluster & 1 == 0 {
                    u16::from_le_bytes([self.table_data[offset], self.table_data[offset + 1]])
                        & 0x0FFF
                } else {
                    u16::from_le_bytes([self.table_data[offset], self.table_data[offset + 1]]) >> 4
                };
                Some(value as u32)
            }
            FatType::Fat16 => {
                let offset = cluster as usize * 2;
                if offset + 1 >= self.table_data.len() {
                    return None;
                }
                Some(
                    u16::from_le_bytes([self.table_data[offset], self.table_data[offset + 1]])
                        as u32,
                )
            }
            FatType::Fat32 => {
                let offset = cluster as usize * 4;
                if offset + 3 >= self.table_data.len() {
                    return None;
                }
                Some(
                    u32::from_le_bytes([
                        self.table_data[offset],
                        self.table_data[offset + 1],
                        self.table_data[offset + 2],
                        self.table_data[offset + 3],
                    ]) & FAT32_CLUSTER_MASK,
                )
            }
        }
    }

    /// The data clusters' FAT entries as bitmaps, decoded in one sequential
    /// pass. Bit `c - 2` describes cluster `c`.
    fn allocation_bitmaps(&self, total_clusters: u64) -> FatAllocationBits {
        let mut allocated = vec![0u8; (total_clusters as usize).div_ceil(8)];
        let mut in_use = vec![0u8; (total_clusters as usize).div_ceil(8)];
        let mut index: u64 = 0;
        let mut record = |value: u32| {
            if value != 0 {
                in_use[(index / 8) as usize] |= 1u8 << (index % 8);
            }
            if value > 1 {
                allocated[(index / 8) as usize] |= 1u8 << (index % 8);
            }
            index += 1;
        };
        let data = &self.table_data;
        match self.fat_type {
            // Clusters (2k, 2k+1) share bytes 3k..3k+3; a two-byte tail still
            // answers the even cluster, as `raw_entry` does.
            FatType::Fat12 => {
                let mut offset = 3usize;
                let mut remaining = total_clusters;
                while remaining > 0 && offset + 1 < data.len() {
                    let even = u16::from_le_bytes([data[offset], data[offset + 1]]) & 0x0FFF;
                    record(u32::from(even));
                    remaining -= 1;
                    if remaining == 0 || offset + 2 >= data.len() {
                        break;
                    }
                    let odd = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) >> 4;
                    record(u32::from(odd));
                    remaining -= 1;
                    offset += 3;
                }
            }
            FatType::Fat16 => data
                .get(4..)
                .unwrap_or(&[])
                .as_chunks::<2>()
                .0
                .iter()
                .take(total_clusters as usize)
                .for_each(|c| record(u32::from(u16::from_le_bytes(*c)))),
            FatType::Fat32 => data
                .get(8..)
                .unwrap_or(&[])
                .as_chunks::<4>()
                .0
                .iter()
                .take(total_clusters as usize)
                .for_each(|c| record(u32::from_le_bytes(*c) & FAT32_CLUSTER_MASK)),
        }
        let speakable = index;
        in_use.truncate((speakable as usize).div_ceil(8));
        FatAllocationBits {
            allocated,
            in_use,
            speakable,
        }
    }

    /// A cluster is allocated when its FAT entry is neither free (0) nor
    /// reserved (1). The per-cluster reading `allocation_bitmaps` is held to.
    #[cfg(test)]
    fn is_cluster_allocated(&self, cluster: u32) -> bool {
        matches!(self.raw_entry(cluster), Some(value) if value > 1)
    }

    /// The end-of-chain threshold for this FAT width. Values at or above it
    /// terminate a chain; the value one below is the bad-cluster marker and the
    /// eight below that are reserved.
    fn eoc_min(&self) -> u32 {
        match self.fat_type {
            FatType::Fat12 => u32::from(FAT12_END_OF_CHAIN),
            FatType::Fat16 => u32::from(FAT16_END_OF_CHAIN),
            FatType::Fat32 => FAT32_END_OF_CHAIN,
        }
    }

    /// Classify the FAT entry for `cluster`.
    ///
    /// The distinction this draws is the whole point: `EndOfChain` is the file
    /// ending, everything else is the chain being CUT. Collapsing them into one
    /// "no next cluster" answer publishes a truncated file as a whole one
    /// (B2-154).
    fn next_entry(&self, cluster: u32) -> FatEntry {
        let eoc_min = self.eoc_min();
        let Some(value) = self.raw_entry(cluster) else {
            return FatEntry::OutOfRange;
        };
        match value {
            0 => FatEntry::Free,
            1 => FatEntry::Reserved,
            v if v >= eoc_min => FatEntry::EndOfChain,
            v if v == eoc_min - 1 => FatEntry::Bad,
            v if v >= eoc_min - 8 => FatEntry::Reserved,
            v => FatEntry::Next(v),
        }
    }

    /// Follow a cluster chain and return all clusters in order, plus why the
    /// walk stopped short when it did.
    ///
    /// `None` means the walk ended on a real end-of-chain marker: the clusters
    /// returned ARE the file. Any `Some(reason)` means they are a prefix — the
    /// safety cap, a cycle, a free/reserved/bad FAT entry mid-chain, or a
    /// cluster number the FAT does not cover. All of those used to look exactly
    /// like a clean end-of-chain, and the file was published with
    /// `data_runs_complete: true` over content that stops early (B2-154).
    fn follow_chain(&self, start_cluster: u32) -> (Vec<u32>, Option<&'static str>) {
        let mut clusters = Vec::new();
        let mut visited = HashSet::new();
        let mut current = start_cluster;

        loop {
            // Prevent unbounded walks over a hostile or corrupt FAT. The chain
            // continues past this point on disk, so the result is incomplete.
            if clusters.len() >= MAX_CHAIN_CLUSTERS {
                return (clusters, Some("chain_cap_reached"));
            }

            if current < 2 {
                // Cluster 0/1 are not data clusters. As a start cluster this is
                // an empty (or unallocated) file; reached mid-chain it means the
                // previous entry pointed nowhere.
                let reason = if clusters.is_empty() {
                    None
                } else {
                    Some("chain_points_below_first_cluster")
                };
                return (clusters, reason);
            }

            // A cluster chain must never revisit a cluster; a self-referential
            // or looping FAT (crafted evidence) would otherwise re-read the same
            // cluster up to the cap, flooding artifacts. Stop at the first
            // repeat. The chain never reaches an end-of-chain marker, so what we
            // collected is not the whole file either.
            if !visited.insert(current) {
                return (clusters, Some("chain_cycle"));
            }

            // A cluster the FAT does not cover is not a cluster of this volume.
            // Serving its bytes would splice an unrelated region of the image
            // into the file, so stop before collecting it.
            // The same goes for a cluster past the volume's last data cluster,
            // which the FAT's sector padding still holds an entry for.
            if self.raw_entry(current).is_none() || u64::from(current) > self.last_data_cluster() {
                return (clusters, Some("chain_entry_out_of_range"));
            }

            clusters.push(current);

            match self.next_entry(current) {
                FatEntry::Next(next) => current = next,
                FatEntry::EndOfChain => return (clusters, None),
                // A freed entry mid-chain is the signature of a deleted or
                // corrupt file: the rest of its clusters are no longer named
                // anywhere, so this is a prefix, not the file.
                FatEntry::Free => return (clusters, Some("chain_entry_free")),
                FatEntry::Reserved => return (clusters, Some("chain_entry_reserved")),
                // 0x?FF7 marks a cluster the volume declared unreadable. It is
                // NOT a cluster number, and following it reads an unrelated
                // region of the image as this file's content.
                FatEntry::Bad => return (clusters, Some("chain_entry_bad_cluster")),
                FatEntry::OutOfRange => return (clusters, Some("chain_entry_out_of_range")),
            }
        }
    }
}

/// One FAT table entry, classified.
///
/// Only `EndOfChain` means the file ended here. Every other non-`Next` variant
/// means the chain was cut and the clusters walked so far are a prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FatEntry {
    /// The next cluster of the chain.
    Next(u32),
    /// End-of-chain marker (>= 0x?FF8): the file ends here.
    EndOfChain,
    /// Free (0): this cluster is not allocated to anything.
    Free,
    /// Reserved (1, or 0x?FF0..0x?FF6): not a cluster number.
    Reserved,
    /// Bad-cluster marker (0x?FF7): the volume declared this cluster unreadable.
    Bad,
    /// The FAT is not large enough to hold an entry for this cluster.
    OutOfRange,
}

/// The clusters a FAT file's content is read from.
#[derive(Debug)]
enum ClusterChain {
    /// A chain followed through the FAT (bounded by `MAX_CHAIN_CLUSTERS`).
    Listed(Vec<u32>),
    /// A deleted file's contiguous reconstruction: `count` consecutive clusters
    /// from `start`. Held as a range because the count follows the recorded
    /// file size, which a crafted entry can make millions of clusters long.
    Contiguous { start: u32, count: u32 },
}

impl ClusterChain {
    fn len(&self) -> usize {
        match self {
            Self::Listed(clusters) => clusters.len(),
            Self::Contiguous { count, .. } => *count as usize,
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, index: usize) -> Option<u32> {
        match self {
            Self::Listed(clusters) => clusters.get(index).copied(),
            Self::Contiguous { start, count } if index < *count as usize => {
                start.checked_add(index as u32)
            }
            Self::Contiguous { .. } => None,
        }
    }
}

// DataSource for FAT file content - reads from cluster chain
#[derive(Debug)]
struct FatFileDataSource {
    underlying: Arc<dyn DataSource>,
    boot_sector: FatBootSector,
    cluster_chain: ClusterChain,
    file_size: u64,
}

impl FatFileDataSource {
    fn new(
        underlying: Arc<dyn DataSource>,
        boot_sector: FatBootSector,
        cluster_chain: ClusterChain,
        file_size: u64,
    ) -> Self {
        Self {
            underlying,
            boot_sector,
            cluster_chain,
            file_size,
        }
    }
}

impl DataSource for FatFileDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.file_size {
            return Ok(0);
        }

        let cluster_size = self.boot_sector.cluster_size_bytes() as u64;
        let to_read = std::cmp::min(buf.len() as u64, self.file_size - offset) as usize;

        let mut bytes_read = 0;
        let mut current_offset = offset;

        while bytes_read < to_read {
            let cluster_index = (current_offset / cluster_size) as usize;
            let Some(cluster) = self.cluster_chain.get(cluster_index) else {
                break;
            };
            let offset_in_cluster = current_offset % cluster_size;
            let remaining_in_cluster = cluster_size - offset_in_cluster;
            let to_read_this_iteration =
                std::cmp::min(remaining_in_cluster, (to_read - bytes_read) as u64) as usize;

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

        Ok(bytes_read)
    }

    fn size(&self) -> u64 {
        self.file_size
    }
}

fn create_file_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    entry: &ParsedDirectoryEntry,
    path: &str,
    underlying_source: &Arc<dyn DataSource>,
    boot_sector: &FatBootSector,
    fat_table: &FatTable,
) -> Option<Artifact> {
    let dir_entry = &entry.dir_entry;

    let filename = entry.long_name.as_ref().unwrap_or(&entry.short_name);

    // Skip "." and ".." entries
    if filename == "." || filename == ".." {
        return None;
    }

    // Both files and directories use FileEntry type in our artifact model
    let artifact_type = ArtifactType::FileEntry;

    // Parent directory path per the metadata contract
    let parent_path = match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    };

    let mut metadata = json!({
        "name": filename,
        "path": path,
        "parent_path": parent_path,
        "short_name": entry.short_name,
        "size": dir_entry.file_size,
        "first_cluster": dir_entry.first_cluster(),
        "is_directory": dir_entry.is_directory(),
        "attributes": {
            "read_only": (dir_entry.attributes & ATTR_READ_ONLY) != 0,
            "hidden": (dir_entry.attributes & ATTR_HIDDEN) != 0,
            "system": (dir_entry.attributes & ATTR_SYSTEM) != 0,
            "archive": (dir_entry.attributes & ATTR_ARCHIVE) != 0,
        },
    });

    // Add timestamps. FAT stores local wall-clock time with no timezone
    // information; mark the artifact so these are not mistaken for UTC.
    // Store timestamps as RFC 3339 strings, matching the ext4 parser and what
    // the file-grid row mapper (Option<String>) and the frontend expect. An
    // integer here makes the grid query fail to decode and 500. FAT clocks are
    // local wall-clock, flagged via "timezone" below.
    let mut has_timestamp = false;
    if let Some(created) = dir_entry.creation_datetime() {
        metadata["created"] = json!(created.to_rfc3339());
        has_timestamp = true;
    }
    if let Some(modified) = dir_entry.modification_datetime() {
        metadata["modified"] = json!(modified.to_rfc3339());
        has_timestamp = true;
    }
    if let Some(accessed) = dir_entry.access_date() {
        metadata["accessed"] = json!(accessed.to_rfc3339());
        has_timestamp = true;
    }
    if has_timestamp {
        metadata["timezone"] = json!("local");
    }

    // The 8.3 short name is raw OEM bytes with no encoding declaration. When it
    // held a byte outside ASCII the `short_name` above -- and the `name`/`path`
    // too, whenever no long-name entry survived to supply them -- is this
    // build's reading under an assumed code page, not text read off the disk.
    // Say which table was used: without it, a name that matched no keyword
    // search reads as proof the file was called something else.
    if entry.short_name_decoded {
        metadata["path_decode"] = json!(FAT_OEM_CODE_PAGE.name());
    }

    if let Some(basis) = entry.chain_basis {
        metadata["directory_chain_basis"] = json!(basis);
    }
    if entry.long_name_stitched {
        metadata["long_name_basis"] = json!("stitched_across_clusters");
        metadata["long_name_basis_detail"] = json!(
            "the head of this deleted entry's long name was read from the end of the nearest earlier \
             directory cluster, joined by the 8.3 checksum every slot carries and by the first byte \
             of the short name that checksum implies; the directory's clusters are not adjacent and \
             their order is inferred, not read from a chain"
        );
    }
    if entry.long_name_possibly_truncated {
        metadata["long_name_possibly_truncated"] = json!(true);
        metadata["long_name_basis_detail"] = json!(
            "the last name slot before this deleted entry has no terminator, so the end of the \
             long name may lie in a directory cluster that was not found; the name shown may be \
             cut short (deleted slots lose their ordinal, so a cut chain cannot be told otherwise)"
        );
    }
    if entry.after_end_marker {
        metadata["recovered_from_directory_slack"] = json!(true);
        metadata["directory_slack_basis"] = json!(
            "read from a slot after the end-of-directory marker, state unknown: an earlier state \
             of this directory left behind, so whether this entry was ever live, or when, is not \
             shown"
        );
    }

    // Mark deleted entries
    if entry.deleted {
        metadata["deleted"] = json!(true);
        metadata["deleted_recovery_source"] = json!("fat_directory");
    }

    // How many allocated clusters a deleted file's reconstruction stepped over (0 when it read contiguously).
    let mut deleted_clusters_skipped = 0u64;
    // Create DataSource for file content (not for directories)
    let data_source =
        if !dir_entry.is_directory() && dir_entry.file_size > 0 && dir_entry.first_cluster() >= 2 {
            let cluster_size = boot_sector.cluster_size_bytes() as u64;
            // Two different questions, and conflating them either serves wrong bytes
            // or refuses right ones:
            //
            // * `runs_cover_file` — do the persisted runs span the recorded size?
            //   The content resolver REFUSES to serve a run list flagged short, so
            //   this must stay true whenever the span really does cover the file.
            //   A deleted file recovered contiguously is exactly that case, and
            //   marking it short would withdraw every recovered deleted file on
            //   every FAT volume from the examiner.
            // * `chain_incomplete` — are those runs certainly the file's own
            //   clusters? For a deleted entry they are a documented GUESS, so the
            //   artifact carries `content_incomplete` even though the span is
            //   full-length.
            let (cluster_chain, chain_incomplete, runs_cover_file): (
                ClusterChain,
                Option<&'static str>,
                bool,
            ) = if entry.deleted {
                // A deleted FAT entry has its cluster chain freed in the FAT, so
                // follow_chain() stops after the first cluster. Recover the file by
                // reading its clusters CONTIGUOUSLY from the start cluster (the
                // standard undelete heuristic, matching TSK icat). Correct for
                // non-fragmented files; fragmented files cannot be recovered this
                // way (chain metadata is gone) and are flagged below.
                //
                // file_size is an attacker-controlled u32 (up to ~4 GiB) and the
                // start cluster is as free: the run must lie inside the volume's
                // data clusters, so it is clamped to them, and held as a
                // (start, count) range rather than a per-cluster list. A start
                // outside the data area leaves nothing to read.
                let needed = (dir_entry.file_size as u64).div_ceil(cluster_size.max(1));
                let start = dir_entry.first_cluster();
                let available = fat_table
                    .last_data_cluster()
                    .saturating_add(1)
                    .saturating_sub(u64::from(start));
                let count = if start < 2 { 0 } else { needed.min(available) };
                // The volume-size clamp (or a start outside the volume) can leave
                // the reconstruction short of the recorded file size; say so
                // rather than let the resolver zero-fill the tail.
                let covered = count >= needed;
                // The chain is a GUESS: the FAT no longer records where this
                // file's clusters were, so a fragmented original re-serves
                // another file's bytes under this name. The span may be
                // full-length and still not be this file's content (B2-160).
                let reason = if covered {
                    "deleted_contiguous_assumed"
                } else {
                    "deleted_reconstruction_short"
                };
                // Clusters later files took out of the middle of the old run are stepped over, as The Sleuth
                // Kit does, when any lie in it; with none the run is the contiguous one it always was.
                match clusters_skipping_allocated(fat_table, start, needed) {
                    Some((clusters, skipped)) if skipped > 0 => {
                        deleted_clusters_skipped = skipped;
                        let covered = clusters.len() as u64 >= needed;
                        let reason = if covered {
                            "deleted_clusters_assumed_in_order"
                        } else {
                            "deleted_reconstruction_short"
                        };
                        (ClusterChain::Listed(clusters), Some(reason), covered)
                    }
                    _ => {
                        // `count` is bounded by the u32 cluster numbers it lies within.
                        let chain = ClusterChain::Contiguous {
                            start,
                            count: count as u32,
                        };
                        (chain, Some(reason), covered)
                    }
                }
            } else {
                let (chain, incomplete) = fat_table.follow_chain(dir_entry.first_cluster());
                // A live chain cut short by a free/reserved/bad entry, a cycle or
                // the cap really does stop before the end of the file.
                let covered = incomplete.is_none();
                (ClusterChain::Listed(chain), incomplete, covered)
            };
            if !cluster_chain.is_empty() {
                // Persist the cluster runs so the API can serve content from the image
                let (runs_json, complete) = match &cluster_chain {
                    ClusterChain::Listed(chain) => {
                        cluster_chain_to_runs(chain, cluster_size, runs_cover_file, |c| {
                            boot_sector.cluster_to_offset(c)
                        })
                    }
                    // Consecutive clusters are one run; no per-cluster walk.
                    ClusterChain::Contiguous { start, count } => runs_to_json(
                        vec![(
                            boot_sector.cluster_to_offset(*start),
                            u64::from(*count) * cluster_size,
                        )],
                        runs_cover_file,
                    ),
                };
                metadata["data_runs"] = runs_json;
                metadata["data_runs_complete"] = json!(complete);
                if let Some(reason) = chain_incomplete {
                    metadata["cluster_chain_incomplete"] = json!(true);
                    // `content_incomplete` is the flag the API, export and
                    // integrity-verify paths read. Without it a chain cut by a
                    // free/reserved/bad entry — or a deleted file's guessed
                    // contiguous span — is served and hashed as the whole file
                    // (B2-154, B2-160).
                    metadata["content_incomplete"] = json!(true);
                    metadata["content_incomplete_reason"] = json!(reason);
                }
                if entry.deleted {
                    // Content is a best-effort contiguous reconstruction; it will be
                    // wrong if the original file was fragmented (unknowable now).
                    if deleted_clusters_skipped > 0 {
                        metadata["deleted_recovery_method"] =
                            json!("unallocated_clusters_in_order");
                        metadata["deleted_clusters_skipped"] = json!(deleted_clusters_skipped);
                    } else {
                        metadata["deleted_recovery_method"] = json!("contiguous_assumed");
                    }
                }

                Some(Arc::new(FatFileDataSource::new(
                    underlying_source.clone(),
                    boot_sector.clone(),
                    cluster_chain,
                    dir_entry.file_size as u64,
                )) as Arc<dyn DataSource>)
            } else {
                // A sized file whose chain yielded nothing: the start cluster is
                // outside the FAT, or the chain was refused before a single cluster
                // was collected. No content and no marker would read as "this file
                // was empty", so say what actually happened (B2-154).
                metadata["data_runs_complete"] = json!(false);
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] =
                    json!(chain_incomplete.unwrap_or("chain_yielded_no_clusters"));
                None
            }
        } else {
            None
        };

    let artifact =
        Artifact::new(case_id, artifact_type, data_source, metadata).with_parent(parent_id);

    Some(artifact)
}

#[derive(Debug, Clone)]
struct ParsedDirectoryEntry {
    short_name: String,
    /// Whether `short_name` holds a character this build interpreted from an
    /// OEM byte rather than read directly (see `DirectoryEntry::get_short_name`).
    short_name_decoded: bool,
    long_name: Option<String>,
    dir_entry: DirectoryEntry,
    deleted: bool,
    /// Byte offset of the short entry's slot in the volume window.
    slot_offset: u64,
    /// Read from a slot after the directory's `0x00` end marker (HUNT-278):
    /// what an earlier state of the directory left behind, state unknown.
    after_end_marker: bool,
    /// Set when the entry sits in a cluster the chain was only assumed to reach.
    chain_basis: Option<&'static str>,
    /// The long name's head was taken from the end of an earlier directory cluster
    /// ([`stitch_seed`]): the two halves agree on the 8.3 checksum and on the first byte
    /// that checksum implies for the deleted short name.
    long_name_stitched: bool,
    /// A deleted entry whose name chain has no terminator in its last slot: the slots
    /// that hold the end of the name may be in a cluster that was not found. Deleted
    /// slots lose their ordinal, so this is the only sign a chain is cut.
    long_name_possibly_truncated: bool,
}

#[cfg(test)]
mod read_bound_tests {
    use super::*;
    use crate::fat_structs::{
        BiosParameterBlock, Fat32ExtendedBpb, FatBootSector, FatExtendedBpb, FatType,
    };

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

    #[test]
    fn test_fat_table_read_allocation_is_bounded() {
        // sectors_per_fat * bytes_per_sector = 0xFFFFFFFF * 0xFFFF is ~280 TB.
        // FatTable::read must bound the allocation to the data source length
        // rather than attempting an unbounded (OOM) allocation from the header.
        let bpb = BiosParameterBlock {
            bytes_per_sector: 0xFFFF,
            sectors_per_cluster: 1,
            reserved_sectors: 0,
            num_fats: 1,
            root_entries: 0,
            total_sectors_16: 0,
            media_descriptor: 0xF8,
            sectors_per_fat_16: 0,
            sectors_per_track: 0,
            num_heads: 0,
            hidden_sectors: 0,
            total_sectors_32: 0,
            total_sectors_64: 0,
        };
        let ext = Fat32ExtendedBpb {
            sectors_per_fat_32: 0xFFFF_FFFF,
            flags: 0,
            version: 0,
            root_cluster: 2,
            fsinfo_sector: 0,
            backup_boot_sector: 0,
            drive_number: 0,
            volume_id: 0,
            volume_label: String::new(),
            volume_label_decode: None,
            filesystem_type: String::new(),
        };
        let boot = FatBootSector {
            bpb,
            extended: FatExtendedBpb::Fat32(ext),
            fat_type: FatType::Fat32,
        };
        let source: Arc<dyn DataSource> = Arc::new(TinySource(4096));
        let table = FatTable::read(&boot, &source).expect("read must succeed, not OOM");
        assert!(
            table.table_data.len() as u64 <= source.size(),
            "FAT allocation must be bounded by the data source length"
        );
    }

    /// Regression: a cyclic FAT (cluster 2 -> 3 -> 2) must terminate at the first
    /// revisit, returning [2, 3], instead of re-reading the cycle up to the
    /// 10 000-cluster cap (which floods duplicate artifacts for a directory).
    /// The chain never reaches an end-of-chain marker, so it is not complete.
    /// The FAT is padded to whole sectors, so it holds entries past the last
    /// data cluster; a chain naming one points outside the volume.
    #[test]
    fn follow_chain_refuses_a_cluster_past_the_last_data_cluster() {
        let mut table_data = vec![0u8; 64];
        table_data[8..12].copy_from_slice(&5u32.to_le_bytes()); // FAT[2] = 5
        table_data[20..24].copy_from_slice(&6u32.to_le_bytes()); // FAT[5] = 6
        table_data[24..28].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[6] = end
        let mut table = FatTable::new(FatType::Fat32, table_data);
        // Four data clusters: 2..=5. Cluster 6 has an entry but is not one.
        table.data_clusters = Some(4);
        let (chain, incomplete) = table.follow_chain(2);
        assert_eq!(chain, vec![2, 5]);
        assert_eq!(incomplete, Some("chain_entry_out_of_range"));
    }

    /// `entry_count` is exactly the clusters `raw_entry` answers for, at every
    /// width and every ragged tail.
    #[test]
    fn entry_count_matches_what_raw_entry_answers() {
        for fat_type in [FatType::Fat12, FatType::Fat16, FatType::Fat32] {
            for len in 0..40usize {
                let table = FatTable::new(fat_type, vec![0u8; len]);
                let held = table.entry_count();
                let answered = (0..64u32)
                    .take_while(|c| table.raw_entry(*c).is_some())
                    .count() as u64;
                assert_eq!(held, answered, "{fat_type:?} with {len} bytes");
                assert!(
                    (held..64).all(|c| table.raw_entry(c as u32).is_none()),
                    "{fat_type:?} with {len} bytes answers past its count"
                );
            }
        }
    }

    /// A deleted file's reconstruction steps over the clusters the FAT calls allocated now, as The Sleuth Kit
    /// does (the Canon camera card of `HUNT-278`), and counts them.
    #[test]
    fn a_deleted_files_clusters_skip_the_allocated_ones_and_count_them() {
        let mut table_data = vec![0u8; 64];
        table_data[16..20].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[4]: a later file
        table_data[20..24].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[5]: a later file
        let mut table = FatTable::new(FatType::Fat32, table_data);
        table.data_clusters = Some(8); // clusters 2..=9
        assert_eq!(
            clusters_skipping_allocated(&table, 2, 4),
            Some((vec![2, 3, 6, 7], 2))
        );
        // Nothing allocated in the way: the contiguous run, none skipped.
        assert_eq!(
            clusters_skipping_allocated(&table, 6, 3),
            Some((vec![6, 7, 8], 0))
        );
        // Short when the volume ends first; refused for a size that claims too much or a start outside the data.
        assert_eq!(
            clusters_skipping_allocated(&table, 8, 4),
            Some((vec![8, 9], 0))
        );
        assert_eq!(
            clusters_skipping_allocated(&table, 2, SKIP_SCAN_MAX_CLUSTERS + 1),
            None
        );
        assert_eq!(clusters_skipping_allocated(&table, 1, 2), None);
    }

    #[test]
    fn follow_chain_terminates_on_cyclic_fat() {
        let mut table_data = vec![0u8; 32];
        table_data[8..12].copy_from_slice(&3u32.to_le_bytes()); // FAT[2] = 3
        table_data[12..16].copy_from_slice(&2u32.to_le_bytes()); // FAT[3] = 2
        let table = FatTable::new(FatType::Fat32, table_data);
        let (chain, incomplete) = table.follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert_eq!(
            incomplete,
            Some("chain_cycle"),
            "a cyclic chain is not a complete chain"
        );
    }

    /// BUG-210: a chain longer than the safety cap must report incomplete, and
    /// that must reach `data_runs_complete` so the resolver refuses to serve a
    /// zero-filled tail. A normally-terminated chain stays complete.
    #[test]
    fn follow_chain_reports_incomplete_at_safety_cap() {
        // FAT[n] = n + 1 for n in 2..=(MAX_CHAIN_CLUSTERS + 3): a chain far
        // longer than the cap, with no end-of-chain marker inside it.
        let entries = MAX_CHAIN_CLUSTERS + 8;
        let mut table_data = vec![0u8; entries * 4];
        for n in 2..entries - 1 {
            table_data[n * 4..n * 4 + 4].copy_from_slice(&((n + 1) as u32).to_le_bytes());
        }
        let table = FatTable::new(FatType::Fat32, table_data);
        let (chain, incomplete) = table.follow_chain(2);
        assert_eq!(chain.len(), MAX_CHAIN_CLUSTERS);
        assert_eq!(
            incomplete,
            Some("chain_cap_reached"),
            "chain cut short by the safety cap is incomplete"
        );

        // The clusters are contiguous, so they coalesce to a single run: the
        // run-count cap alone would have called this "complete".
        let (runs, runs_complete) =
            cluster_chain_to_runs(&chain, 512, incomplete.is_none(), |c| c as u64 * 512);
        assert_eq!(runs.as_array().unwrap().len(), 1);
        assert!(
            !runs_complete,
            "a truncated cluster chain must not be published as a complete run list"
        );
    }

    /// A short chain that ends on an end-of-chain marker is complete.
    #[test]
    fn follow_chain_reports_complete_on_end_marker() {
        let mut table_data = vec![0u8; 32];
        table_data[8..12].copy_from_slice(&3u32.to_le_bytes()); // FAT[2] = 3
        table_data[12..16].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[3] = EOC
        let table = FatTable::new(FatType::Fat32, table_data);
        let (chain, incomplete) = table.follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert_eq!(incomplete, None);
    }

    /// B2-154: `get_next_cluster` used to answer `None` for a free entry, a
    /// reserved entry, a bad-cluster marker and a cluster outside the FAT, and
    /// `follow_chain` treated every one of them as a clean end-of-chain. A file
    /// whose chain was cut mid-way was published with `data_runs_complete:
    /// true` over a prefix of its content.
    #[test]
    fn a_chain_cut_mid_way_is_never_reported_as_ended() {
        let fat32 = |entries: &[(usize, u32)]| {
            let mut table_data = vec![0u8; 64];
            for &(n, v) in entries {
                table_data[n * 4..n * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
            FatTable::new(FatType::Fat32, table_data)
        };

        // FAT[2] = 3, FAT[3] = 0 (free): the rest of the file is no longer
        // named anywhere.
        let (chain, incomplete) = fat32(&[(2, 3), (3, 0)]).follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert_eq!(incomplete, Some("chain_entry_free"));

        // FAT[3] = 1 (reserved): not a cluster number.
        let (chain, incomplete) = fat32(&[(2, 3), (3, 1)]).follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert_eq!(incomplete, Some("chain_entry_reserved"));

        // FAT[3] = 0x0FFFFFF7 (bad cluster). Following it as a cluster number
        // would read cluster 268435447 — an unrelated region of the image —
        // as this file's content.
        let (chain, incomplete) = fat32(&[(2, 3), (3, 0x0FFF_FFF7)]).follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert_eq!(incomplete, Some("chain_entry_bad_cluster"));

        // FAT[3] points at cluster 900, whose entry lies past the end of this
        // 16-entry table. Cluster 900 is not collected: reading it would splice
        // an unrelated region of the image into the file.
        let (chain, incomplete) = fat32(&[(2, 3), (3, 900)]).follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert_eq!(incomplete, Some("chain_entry_out_of_range"));

        // And the clean ending still reads as complete.
        let (chain, incomplete) = fat32(&[(2, 3), (3, 0x0FFF_FFFF)]).follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert_eq!(incomplete, None);
    }

    /// The same classification on FAT12 and FAT16, whose markers sit at
    /// different widths (0xFF7/0xFF8 and 0xFFF7/0xFFF8).
    #[test]
    fn bad_cluster_and_end_markers_are_width_specific() {
        // FAT16: FAT[2] = 3, FAT[3] = 0xFFF7 (bad).
        let mut table_data = vec![0u8; 32];
        table_data[4..6].copy_from_slice(&3u16.to_le_bytes());
        table_data[6..8].copy_from_slice(&0xFFF7u16.to_le_bytes());
        let table = FatTable::new(FatType::Fat16, table_data);
        let (chain, incomplete) = table.follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert_eq!(incomplete, Some("chain_entry_bad_cluster"));

        // FAT16: 0xFFF8 is the end of the file, not a defect.
        let mut table_data = vec![0u8; 32];
        table_data[4..6].copy_from_slice(&3u16.to_le_bytes());
        table_data[6..8].copy_from_slice(&0xFFF8u16.to_le_bytes());
        let table = FatTable::new(FatType::Fat16, table_data);
        assert_eq!(table.follow_chain(2), (vec![2, 3], None));

        // FAT12: cluster 2 -> 3, cluster 3 marked bad (0xFF7). Entries are
        // 12-bit: cluster 2 occupies bytes 3..4 (low nibble pair), cluster 3
        // the high nibbles of bytes 4..5.
        let mut table_data = vec![0u8; 32];
        // FAT[2] = 0x003 at byte offset 3 (even cluster -> low 12 bits).
        table_data[3] = 0x03;
        table_data[4] = 0x00;
        // FAT[3] = 0xFF7 at byte offset 4 (odd cluster -> high 12 bits).
        table_data[4] |= 0x70;
        table_data[5] = 0xFF;
        let table = FatTable::new(FatType::Fat12, table_data);
        let (chain, incomplete) = table.follow_chain(2);
        assert_eq!(chain, vec![2, 3]);
        assert_eq!(incomplete, Some("chain_entry_bad_cluster"));
    }
}

/// ROADMAP §5.10: the FAT-derived allocation map, measured and held to the
/// per-cluster walk it replaced.
#[cfg(test)]
mod allocation_map_from_fat_tests {
    use super::*;
    use crate::fat_structs::FatType;
    use std::time::Instant;

    /// A FAT whose entries are drawn from a fixed xorshift stream, so free (0),
    /// reserved (1), bad and chained values all occur.
    fn synthetic_table(fat_type: FatType, entries: usize) -> FatTable {
        let mut state = 0x2545F4914F6CDD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let table_data = match fat_type {
            FatType::Fat32 => (0..entries)
                .flat_map(|_| ((next() % 5) as u32 * 0x0301_0001).to_le_bytes())
                .collect(),
            FatType::Fat16 => (0..entries)
                .flat_map(|_| ((next() % 5) as u16 * 0x0301).to_le_bytes())
                .collect(),
            FatType::Fat12 => (0..entries.div_ceil(2))
                .flat_map(|_| {
                    let a = (next() % 5) as u16 * 0x301;
                    let b = (next() % 5) as u16 * 0x301;
                    let packed = u32::from(a & 0xFFF) | (u32::from(b & 0xFFF) << 12);
                    [packed as u8, (packed >> 8) as u8, (packed >> 16) as u8]
                })
                .collect(),
        };
        FatTable::new(fat_type, table_data)
    }

    /// The two walks as they were, one FAT entry decode per cluster each.
    fn reference_per_cluster(table: &FatTable, total_clusters: u64) -> FatAllocationBits {
        let last_speakable = (2..2u64.saturating_add(total_clusters))
            .take_while(|c| table.raw_entry(*c as u32).is_some())
            .last();
        let speakable = last_speakable.map(|c| c - 1).unwrap_or(0);
        let mut in_use = vec![0u8; (speakable as usize).div_ceil(8)];
        for index in 0..speakable {
            if table.raw_entry((index + 2) as u32) != Some(0) {
                in_use[(index / 8) as usize] |= 1u8 << (index % 8);
            }
        }
        let mut allocated = vec![0u8; (total_clusters as usize).div_ceil(8)];
        for index in 0..total_clusters {
            if table.is_cluster_allocated((index + 2) as u32) {
                allocated[(index / 8) as usize] |= 1u8 << (index % 8);
            }
        }
        FatAllocationBits {
            allocated,
            in_use,
            speakable,
        }
    }

    fn assert_same(actual: &FatAllocationBits, expected: &FatAllocationBits, what: &str) {
        assert_eq!(actual.speakable, expected.speakable, "{what}: speakable");
        assert_eq!(actual.in_use, expected.in_use, "{what}: in_use bits");
        assert_eq!(
            actual.allocated.len(),
            expected.allocated.len(),
            "{what}: allocated length"
        );
        assert_eq!(
            actual.allocated, expected.allocated,
            "{what}: allocated bits"
        );
    }

    #[test]
    fn fat_bitmaps_match_the_per_cluster_walk_for_every_width() {
        for fat_type in [FatType::Fat12, FatType::Fat16, FatType::Fat32] {
            for entries in [2usize, 3, 4, 5, 9, 10, 11, 100, 1001, 4096, 4097] {
                let table = synthetic_table(fat_type, entries);
                for total_clusters in [
                    0u64,
                    1,
                    entries as u64 - 2,
                    entries as u64,
                    2 * entries as u64 + 3,
                ] {
                    let actual = table.allocation_bitmaps(total_clusters);
                    let expected = reference_per_cluster(&table, total_clusters);
                    assert_same(
                        &actual,
                        &expected,
                        &format!("{fat_type:?} with {entries} entries, {total_clusters} clusters"),
                    );
                }
            }
        }
    }

    #[test]
    fn a_fat_cut_short_leaves_the_odd_tail_as_the_walk_did() {
        // A FAT12 table one and two bytes past a full 3-byte group: the walk
        // answered the even cluster from the two-byte tail and refused the odd.
        for extra in 0..3usize {
            let mut table = synthetic_table(FatType::Fat12, 40);
            table.table_data.truncate(30 + extra);
            let actual = table.allocation_bitmaps(64);
            let expected = reference_per_cluster(&table, 64);
            assert_same(&actual, &expected, &format!("FAT12 tail of {extra}"));
        }
        for (fat_type, width) in [(FatType::Fat16, 2usize), (FatType::Fat32, 4)] {
            for extra in 0..width {
                let mut table = synthetic_table(fat_type, 40);
                table.table_data.truncate(20 * width + extra);
                let actual = table.allocation_bitmaps(64);
                let expected = reference_per_cluster(&table, 64);
                assert_same(&actual, &expected, &format!("{fat_type:?} tail of {extra}"));
            }
        }
    }

    /// Not an assertion, a measurement: a 512 GB FAT32 volume at 32 KiB
    /// clusters has 16 Mi FAT entries. Recorded on 2026-09-19 (this host,
    /// debug / release): per cluster, buckets 423 ms / 47 ms plus free-region
    /// bits 1.04 s / 44 ms; one pass, see the run.
    #[test]
    fn measure_fat32_allocation_map_from_a_half_terabyte_fat() {
        let entries = 16 * 1024 * 1024;
        let table = synthetic_table(FatType::Fat32, entries + 2);
        let total_clusters = entries as u64;
        let start = Instant::now();
        let reference = reference_per_cluster(&table, total_clusters);
        let per_cluster = start.elapsed();
        let start = Instant::now();
        let bits = table.allocation_bitmaps(total_clusters);
        let (buckets, cpb) = build_allocation_buckets_from_bitmap(total_clusters, &bits.allocated);
        let one_pass = start.elapsed();
        assert_same(&bits, &reference, "FAT32 at scale");
        eprintln!(
            "FAT32 {entries} entries, {} buckets of cpb {cpb}: per cluster {per_cluster:?}, \
             one pass {one_pass:?}",
            buckets.len()
        );
    }
}
