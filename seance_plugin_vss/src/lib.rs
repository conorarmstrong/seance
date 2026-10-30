#![forbid(unsafe_code)]
//! VSS (Volume Shadow Copy Service) Enumerator Module
//!
//! Parses Windows VSS catalog to enumerate shadow copy snapshots
//! and create VssDataSource artifacts for accessing shadow copy data.
//!
//! Based on libvshadow specification: <https://github.com/libyal/libvshadow>

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    guid::format_guid,
    io::{read_exact_or_fail, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod prior_versions;
pub mod vss_source;
pub mod vss_structs;

use vss_structs::*;

pub struct VssEnumerator;

impl VssEnumerator {
    /// Parse VSS volume header from a volume data source
    fn parse_volume_header(&self, source: &Arc<dyn DataSource>) -> Result<VssVolumeHeader> {
        let mut buf = vec![0u8; VSS_VOLUME_HEADER_SIZE];
        // Structural read: a short read would leave a zero tail that parses as a
        // real (zero) catalog offset / volume GUID, so fail closed (BUG-242).
        read_exact_or_fail(
            source.as_ref(),
            VSS_VOLUME_HEADER_OFFSET,
            &mut buf,
            "VSS volume header",
        )
        .context("Failed to read VSS volume header")?;

        let mut cursor = std::io::Cursor::new(&buf);

        let mut identifier = [0u8; 16];
        cursor.read_exact(&mut identifier)?;

        let version = cursor.read_u32::<LittleEndian>()?;
        let record_type = cursor.read_u32::<LittleEndian>()?;
        let current_offset = cursor.read_u64::<LittleEndian>()?;
        let unknown_offset = cursor.read_u64::<LittleEndian>()?;

        // Skip to catalog offset at position 48
        cursor.seek(SeekFrom::Start(48))?;
        let catalog_offset = cursor.read_u64::<LittleEndian>()?;
        let max_size = cursor.read_u64::<LittleEndian>()?;

        let mut volume_identifier = [0u8; 16];
        cursor.read_exact(&mut volume_identifier)?;

        let mut storage_volume_identifier = [0u8; 16];
        cursor.read_exact(&mut storage_volume_identifier)?;

        Ok(VssVolumeHeader {
            identifier,
            version,
            record_type,
            current_offset,
            unknown_offset,
            catalog_offset,
            max_size,
            volume_identifier,
            storage_volume_identifier,
        })
    }

    /// Parse a catalog block header
    fn parse_catalog_block_header(&self, buf: &[u8]) -> Result<VssCatalogBlockHeader> {
        let mut cursor = std::io::Cursor::new(buf);

        let mut identifier = [0u8; 16];
        cursor.read_exact(&mut identifier)?;

        let version = cursor.read_u32::<LittleEndian>()?;
        let record_type = cursor.read_u32::<LittleEndian>()?;
        let relative_offset = cursor.read_u64::<LittleEndian>()?;
        let current_offset = cursor.read_u64::<LittleEndian>()?;
        let next_offset = cursor.read_u64::<LittleEndian>()?;

        Ok(VssCatalogBlockHeader {
            identifier,
            version,
            record_type,
            relative_offset,
            current_offset,
            next_offset,
        })
    }

    /// Parse a snapshot catalog entry (type 0x02)
    fn parse_snapshot_entry(&self, buf: &[u8]) -> Result<VssSnapshotEntry> {
        let mut cursor = std::io::Cursor::new(buf);

        let _entry_type = cursor.read_u64::<LittleEndian>()?;
        let volume_size = cursor.read_u64::<LittleEndian>()?;

        let mut store_identifier = [0u8; 16];
        cursor.read_exact(&mut store_identifier)?;

        // Cursor is now at offset 32: stack position, then flags @40, then the
        // creation FILETIME @48.
        let stack_position = cursor.read_u64::<LittleEndian>()?;
        let attribute_flags = cursor.read_u64::<LittleEndian>()?;
        let creation_timestamp = cursor.read_u64::<LittleEndian>()?;

        Ok(VssSnapshotEntry {
            store_identifier,
            volume_size,
            stack_position,
            attribute_flags,
            creation_timestamp,
        })
    }

    /// Parse a store catalog entry (type 0x03)
    fn parse_store_entry(&self, buf: &[u8]) -> Result<VssStoreEntry> {
        let mut cursor = std::io::Cursor::new(buf);

        let _entry_type = cursor.read_u64::<LittleEndian>()?;
        let block_list_offset = cursor.read_u64::<LittleEndian>()?;

        let mut store_identifier = [0u8; 16];
        cursor.read_exact(&mut store_identifier)?;

        let store_header_offset = cursor.read_u64::<LittleEndian>()?;
        let block_range_list_offset = cursor.read_u64::<LittleEndian>()?;
        let bitmap_offset = cursor.read_u64::<LittleEndian>()?;

        // Skip to previous bitmap offset at position 72
        cursor.seek(SeekFrom::Start(72))?;
        let previous_bitmap_offset = cursor.read_u64::<LittleEndian>()?;

        Ok(VssStoreEntry {
            block_list_offset,
            store_identifier,
            store_header_offset,
            block_range_list_offset,
            bitmap_offset,
            previous_bitmap_offset,
        })
    }

    /// Parse a store's diff-area table chain into a block map:
    /// original_volume_offset -> data_block_offset_in_store (both volume-relative,
    /// 16 KiB aligned). Only *regular* pre-copy entries are mapped; forwarder
    /// (0x1), overlay (0x2) and ignore (0x4) entries are skipped (they need the
    /// shadow-copy chain / sub-block bitmap, which single-store reconstruction
    /// does not resolve). Each diff-area table is a 16 KiB shadow block: 16-byte
    /// diff-area GUID, type at +20 (==3), volume offset at +32, next at +40,
    /// then 32-byte entries from +0x80.
    fn parse_block_list(
        &self,
        source: &Arc<dyn DataSource>,
        diff_area_offset: u64,
    ) -> Result<std::collections::BTreeMap<u64, u64>> {
        use std::collections::BTreeMap;

        let mut block_map = BTreeMap::new();
        let mut current_offset = diff_area_offset;
        let mut tables_parsed = 0;
        let max_tables = 100_000; // safety bound on the chain length

        while current_offset > 0 && tables_parsed < max_tables {
            tables_parsed += 1;
            let mut block = vec![0u8; VSS_BLOCK_SIZE as usize];
            // A partially read table would present its zero tail as "no more
            // entries", silently under-counting the diff area (BUG-242).
            read_exact_or_fail(
                source.as_ref(),
                current_offset,
                &mut block,
                "VSS diff-area table block",
            )
            .context("Failed to read diff-area table block")?;

            // Validate the diff-area GUID and block type (3 = diff area table).
            if block[..16] != VSS_DIFF_AREA_GUID {
                break;
            }
            let rd32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
            let rd64 = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
            let block_type = rd32(&block[20..24]);
            let block_vol_off = rd64(&block[32..40]);
            let next_offset = rd64(&block[40..48]);
            if block_type != VSS_RECORD_TYPE_DIFF_AREA_TABLE || block_vol_off != current_offset {
                break;
            }

            let mut pos = VSS_BLOCK_HEADER_SIZE;
            while pos + 32 <= block.len() {
                let e = &block[pos..pos + 32];
                let original = rd64(&e[0..8]);
                let store_off = rd64(&e[8..16]);
                let data_vol_off = rd64(&e[16..24]);
                let flags = rd32(&e[24..28]);
                pos += 32;

                // End of entries in this table.
                if data_vol_off == 0 && flags == 0 {
                    break;
                }
                let _ = store_off;
                // Regular pre-copy entry: the original block's pre-modification
                // data physically lives at data_block_volume_offset in the diff
                // area. (Correctly *serving* a snapshot still needs the store
                // chain + bitmaps; this map only counts/locates this store's
                // own preserved blocks.)
                if flags & 0x7 == 0 {
                    block_map.insert(original, data_vol_off);
                }
            }

            current_offset = next_offset;
        }

        debug!("Parsed diff area: {} regular entries", block_map.len());
        Ok(block_map)
    }

    /// Parse all catalog blocks and extract snapshot information
    fn parse_catalog(
        &self,
        source: &Arc<dyn DataSource>,
        catalog_offset: u64,
    ) -> Result<(Vec<VssSnapshot>, CatalogWalk)> {
        let mut snapshots = Vec::new();
        let mut snapshot_map: HashMap<String, VssSnapshotEntry> = HashMap::new();
        let mut store_map: HashMap<String, VssStoreEntry> = HashMap::new();

        let mut current_offset = catalog_offset;

        // The catalog is a singly-linked chain of blocks; next_offset is read
        // straight from attacker-controlled evidence. Bound the walk and record
        // visited offsets so a self-referential or cyclic chain terminates
        // instead of hanging the worker (an infinite loop escapes catch_unwind).
        let mut visited: HashSet<u64> = HashSet::new();
        let max_blocks = 100_000; // safety bound on the chain length
        let mut walk = CatalogWalk::default();

        // Parse catalog blocks
        while current_offset > 0 {
            if visited.len() >= max_blocks {
                // The chain is longer than the bound: catalog blocks beyond it,
                // and every shadow copy they list, were never examined.
                walk.max_blocks_reached = true;
                break;
            }
            if !visited.insert(current_offset) {
                // The chain loops. Snapshots listed past the loop point, if any,
                // are unreachable through it.
                walk.cycle_detected = true;
                break;
            }
            let mut block_buf = vec![0u8; VSS_BLOCK_SIZE as usize];
            // Fail closed: a zero-padded catalog block drops the snapshots whose
            // entries fell in the unread tail and invents a zero next_offset,
            // which would look identical to "the catalog ends here" (BUG-242).
            read_exact_or_fail(
                source.as_ref(),
                current_offset,
                &mut block_buf,
                "VSS catalog block",
            )
            .context("Failed to read catalog block")?;

            // Parse block header
            let header = self.parse_catalog_block_header(&block_buf[..VSS_BLOCK_HEADER_SIZE])?;

            debug!(
                "Catalog block at offset {}: next={}",
                current_offset, header.next_offset
            );

            // Parse catalog entries (after the 128-byte header)
            let mut entry_offset = VSS_BLOCK_HEADER_SIZE;
            while entry_offset + VSS_CATALOG_ENTRY_SIZE <= block_buf.len() {
                let entry_buf = &block_buf[entry_offset..entry_offset + VSS_CATALOG_ENTRY_SIZE];

                // Entry type is the first 4 bytes; byte 4 is the snapshot
                // priority, so reading 8 bytes here would fold a non-zero
                // priority into the type and misclassify the entry.
                let mut entry_cursor = std::io::Cursor::new(entry_buf);
                let entry_type = entry_cursor.read_u32::<LittleEndian>().unwrap_or(0) as u64;

                match entry_type {
                    VSS_CATALOG_ENTRY_TYPE_SNAPSHOT => {
                        if let Ok(snapshot_entry) = self.parse_snapshot_entry(entry_buf) {
                            let store_id = format_guid(&snapshot_entry.store_identifier);
                            debug!("Found snapshot entry: store_id={}", store_id);
                            snapshot_map.insert(store_id, snapshot_entry);
                        }
                    }
                    VSS_CATALOG_ENTRY_TYPE_STORE => {
                        if let Ok(store_entry) = self.parse_store_entry(entry_buf) {
                            let store_id = format_guid(&store_entry.store_identifier);
                            debug!(
                                "Found store entry: store_id={}, header_offset={}",
                                store_id, store_entry.store_header_offset
                            );
                            store_map.insert(store_id, store_entry);
                        }
                    }
                    VSS_CATALOG_ENTRY_TYPE_UNUSED => {
                        // Skip unused entries
                    }
                    _ => {
                        // Unknown entry type or end of entries
                        if entry_type != 0 {
                            debug!("Unknown catalog entry type: 0x{:x}", entry_type);
                        }
                    }
                }

                entry_offset += VSS_CATALOG_ENTRY_SIZE;
            }

            // Move to next catalog block
            current_offset = header.next_offset;
            if current_offset == 0 {
                break;
            }
        }

        // Emit a snapshot for every type-2 catalog entry. A shadow copy is
        // enumerable from its type-2 entry alone (store GUID, volume size,
        // timestamp); the type-3 "store" entry only supplies the diff-area
        // offsets needed to *read* its data and may be absent (e.g. a snapshot
        // with no diff area yet). Requiring a type-3 match here silently dropped
        // every snapshot on real volumes whose catalog held only type-2 entries.
        for (store_id, snapshot_entry) in snapshot_map {
            let store_entry = store_map.get(&store_id);
            // Zero/pre-epoch FILETIMEs stay "unknown" instead of a fake 1970 date
            let creation_time =
                seance_core::time::filetime_to_unix_secs(snapshot_entry.creation_timestamp)
                    .and_then(|unix_ts| chrono::DateTime::from_timestamp(unix_ts, 0))
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "unknown".to_string());

            snapshots.push(VssSnapshot {
                snapshot_id: store_id.clone(),
                store_id: store_id.clone(),
                volume_size: snapshot_entry.volume_size,
                creation_time,
                store_header_offset: store_entry.map(|s| s.store_header_offset).unwrap_or(0),
                block_list_offset: store_entry.map(|s| s.block_list_offset).unwrap_or(0),
                bitmap_offset: store_entry.map(|s| s.bitmap_offset).unwrap_or(0),
                previous_bitmap_offset: store_entry.map(|s| s.previous_bitmap_offset).unwrap_or(0),
                stack_position: snapshot_entry.stack_position,
                attribute_flags: snapshot_entry.attribute_flags,
                has_store_entry: store_entry.is_some(),
            });
        }

        Ok((snapshots, walk))
    }
}

/// How far the catalog chain walk got.
///
/// The catalog is the index of shadow copies on the volume. A walk that stops
/// early lists fewer snapshots than exist, and a missing snapshot reads as "no
/// shadow copy from that date", which is the opposite of what the evidence
/// supports.
#[derive(Default, Clone, Copy)]
struct CatalogWalk {
    /// The chain looped back on itself.
    cycle_detected: bool,
    /// The chain-length bound stopped the walk.
    max_blocks_reached: bool,
}

impl CatalogWalk {
    /// Whether the walk reached the end of the chain.
    ///
    /// Production asks [`CatalogWalk::reason`] instead, because it needs the
    /// reason as well as the fact and `None` already means complete. This is
    /// kept for tests, which assert the fact and the reason separately so that
    /// a walk reporting "incomplete" with no reason, or a reason with no
    /// incompleteness, fails loudly rather than reading as either one.
    #[cfg(test)]
    fn is_complete(&self) -> bool {
        !self.cycle_detected && !self.max_blocks_reached
    }

    /// Stable reason for the standard incompleteness pair. A cap and a corrupt
    /// (cyclic) chain call for different follow-up.
    fn reason(&self) -> Option<&'static str> {
        if self.max_blocks_reached {
            Some(IncompleteReason::CapReached.as_str())
        } else if self.cycle_detected {
            Some(IncompleteReason::UnresolvedStructure.as_str())
        } else {
            None
        }
    }
}

impl ForensicsModule for VssEnumerator {
    fn id(&self) -> &str {
        "plugin.windows.vss_enumerator"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileSystem, ArtifactType::RawEvidence]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let mut produced_artifacts = Vec::new();

        // Only process NTFS filesystems or raw volumes
        if artifact.artifact_type == ArtifactType::FileSystem {
            // Fast path: check subtype first
            if let Some(subtype) = artifact.subtype() {
                if subtype != "ntfs" {
                    return Ok(Vec::new()); // Early exit - not NTFS
                }
            }

            // Fallback: check filesystem_type metadata (case-insensitive; the
            // subtype check above uses lowercase "ntfs" while detectors emit
            // "NTFS").
            let fs_type = artifact
                .metadata
                .get("filesystem_type")
                .and_then(|v| v.as_str());

            if let Some(fs) = fs_type {
                if !fs.eq_ignore_ascii_case("ntfs") {
                    return Ok(produced_artifacts);
                }
            }
        }

        let data_source = match &artifact.data {
            Some(ds) => ds,
            None => return Ok(produced_artifacts),
        };

        // Try to parse VSS volume header
        let volume_header = match self.parse_volume_header(data_source) {
            Ok(header) => {
                if header.record_type != VSS_RECORD_TYPE_VOLUME_HEADER {
                    debug!(
                        "Not a VSS volume (invalid record type: {})",
                        header.record_type
                    );
                    return Ok(produced_artifacts);
                }
                header
            }
            Err(e) => {
                debug!("Failed to parse VSS volume header: {}", e);
                return Ok(produced_artifacts);
            }
        };

        if volume_header.catalog_offset == 0 {
            debug!("VSS volume has no catalog");
            return Ok(produced_artifacts);
        }

        info!(
            "Found VSS volume: version={}, catalog_offset={}",
            volume_header.version, volume_header.catalog_offset
        );

        // Check if the storage volume differs from the source volume.
        // If so, the VSS store data lives on a different disk and we can't
        // reconstruct shadow copies without that volume being ingested too.
        if volume_header.volume_identifier != volume_header.storage_volume_identifier {
            warn!(
                "VSS storage volume {} differs from source volume {}. \
                 Multi-device VSS shadow copies require both volumes to be ingested. \
                 Shadow copies from this volume may have incomplete data.",
                format_guid(&volume_header.storage_volume_identifier),
                format_guid(&volume_header.volume_identifier),
            );
        }

        // Parse catalog and enumerate snapshots
        let (snapshots, catalog_walk) =
            match self.parse_catalog(data_source, volume_header.catalog_offset) {
                Ok(out) => out,
                Err(e) => {
                    // A VSS volume header was found, so this volume carries
                    // shadow copies. Returning nothing here reads as "no shadow
                    // copies on this volume".
                    warn!("Failed to parse VSS catalog: {}", e);
                    produced_artifacts.push(catalog_status_artifact(
                        artifact,
                        IncompleteReason::UnresolvedStructure.as_str(),
                        0,
                        &format!("The VSS catalog could not be read ({e})"),
                    ));
                    return Ok(produced_artifacts);
                }
            };

        info!("Enumerated {} VSS snapshot(s)", snapshots.len());

        // Build one store per stack position and chain them: store N falls
        // through to store N+1, then to the live volume. Build highest stack
        // first so each store's `next` (stack + 1) already exists. Only
        // snapshots with a type-3 store entry can be reconstructed.
        let mut stack_snaps: Vec<&VssSnapshot> =
            snapshots.iter().filter(|s| s.has_store_entry).collect();
        stack_snaps.sort_by_key(|b| std::cmp::Reverse(b.stack_position));

        let mut stores: HashMap<u64, Arc<vss_source::VssStore>> = HashMap::new();
        // Stack positions whose fall-through chain skipped a store: either the
        // stack numbering is not contiguous or an intermediate store failed to
        // build. The bytes that store held are then served from an older store
        // (or the live volume) instead, which silently dates part of the
        // reconstruction to the wrong moment.
        let mut chain_gap: HashSet<u64> = HashSet::new();
        // The nearest higher-numbered store that actually built. Linking to the
        // literal `stack + 1` leaves `next = None` whenever that one is missing,
        // which drops the whole remainder of the chain and falls straight
        // through to the live volume.
        let mut next_store: Option<Arc<vss_source::VssStore>> = None;
        for (i, snap) in stack_snaps.iter().enumerate() {
            let stack = snap.stack_position;
            // Every store already attempted has a higher stack position; any of
            // them missing from `stores` is a hole in this store's chain.
            let higher_missing = stack_snaps[..i]
                .iter()
                .any(|s| !stores.contains_key(&s.stack_position));
            match vss_source::VssStore::build(
                data_source,
                snap.block_list_offset,
                snap.bitmap_offset,
                snap.previous_bitmap_offset,
                snap.volume_size,
                snap.attribute_flags,
                next_store.clone(),
            ) {
                Ok(store) => {
                    if higher_missing {
                        warn!(
                            "VSS store chain for stack position {} skips an unbuilt store; \
                             its reconstruction is flagged incomplete",
                            stack
                        );
                        chain_gap.insert(stack);
                    }
                    let store = Arc::new(store);
                    stores.insert(stack, store.clone());
                    next_store = Some(store);
                }
                Err(e) => {
                    warn!(
                        "Failed to build VSS store for stack position {}: {}",
                        stack, e
                    );
                }
            }
        }

        // The live volume's $MFT, parsed once and compared with each rebuilt
        // snapshot's (HUNT-154, option B). Parsed only when some snapshot has
        // content to compare.
        let live_mft: Option<Result<prior_versions::ParsedMft, String>> = if stores.is_empty() {
            None
        } else {
            Some(prior_versions::read_volume_mft(data_source))
        };

        // Create artifacts for each snapshot
        for snapshot in snapshots {
            // Parse store header for additional metadata if available. An
            // unreadable/short header leaves the version unknown (null) rather
            // than reporting a fabricated version 0 (BUG-242).
            let mut store_version: Option<u32> = None;
            let mut store_header_incomplete: Option<&'static str> = None;
            if snapshot.store_header_offset > 0 {
                let mut store_buf = vec![0u8; VSS_BLOCK_HEADER_SIZE];
                match read_exact_or_fail(
                    data_source.as_ref(),
                    snapshot.store_header_offset,
                    &mut store_buf,
                    "VSS store header",
                ) {
                    Ok(()) => {
                        let mut cursor = std::io::Cursor::new(&store_buf);
                        let _ = cursor.seek(SeekFrom::Start(16)); // skip identifier
                        store_version = cursor.read_u32::<LittleEndian>().ok();
                    }
                    Err(e) => {
                        warn!(
                            "Failed to read VSS store header for snapshot {}: {}",
                            snapshot.snapshot_id, e
                        );
                        store_header_incomplete = Some(IncompleteReason::ShortRead.as_str());
                    }
                }
            }

            let multi_device =
                volume_header.volume_identifier != volume_header.storage_volume_identifier;

            // Count the blocks this snapshot's store preserved (its diff area).
            let mut diff_area_incomplete = false;
            let modified_blocks = if snapshot.block_list_offset > 0 {
                match self.parse_block_list(data_source, snapshot.block_list_offset) {
                    Ok(block_map) => block_map.len(),
                    Err(e) => {
                        warn!(
                            "Failed to parse diff area for snapshot {}: {}",
                            snapshot.snapshot_id, e
                        );
                        // A failed walk must not report "0 preserved blocks" as
                        // if the diff area had been read and found empty.
                        diff_area_incomplete = true;
                        0
                    }
                }
            } else {
                0
            };

            // Attach a per-snapshot content data source that serves the
            // snapshot's point-in-time bytes via the resolved store chain.
            // Only snapshots whose store built successfully get reconstruction;
            // the rest keep the honest "unavailable" flag and no data source.
            let (content_data, content_reconstruction): (Option<Arc<dyn DataSource>>, &str) =
                match stores.get(&snapshot.stack_position) {
                    Some(store) => {
                        let ds: Arc<dyn DataSource> = Arc::new(vss_source::VssDataSource::new(
                            data_source.clone(),
                            store.clone(),
                            snapshot.volume_size,
                        ));
                        (Some(ds), "reconstructed")
                    }
                    None => (None, "unavailable_requires_store_chain"),
                };

            let mut metadata = json!({
                "type": "VssSnapshot",
                "subtype": "vss_snapshot",
                "name": format!("Shadow Copy {}", snapshot.snapshot_id),
                "snapshot_id": snapshot.snapshot_id,
                "store_id": snapshot.store_id,
                "volume_size": snapshot.volume_size,
                "creation_time": snapshot.creation_time,
                "store_header_offset": snapshot.store_header_offset,
                "block_list_offset": snapshot.block_list_offset,
                "bitmap_offset": snapshot.bitmap_offset,
                "stack_position": snapshot.stack_position,
                "store_version": store_version,
                "multi_device": multi_device,
                "modified_blocks": modified_blocks,
                "content_reconstruction": content_reconstruction,
                // False when this snapshot's fall-through chain skipped a store
                // it should have read: the reconstruction mixes in bytes from
                // the wrong point in time.
                "store_chain_complete": !chain_gap.contains(&snapshot.stack_position),
                "source": "VssEnumerator",
            });

            if diff_area_incomplete {
                metadata["diff_area_incomplete"] = json!(true);
                metadata["diff_area_incomplete_reason"] =
                    json!(IncompleteReason::UnresolvedStructure.as_str());
            }
            if let Some(reason) = store_header_incomplete {
                metadata["store_header_incomplete"] = json!(true);
                metadata["store_header_incomplete_reason"] = json!(reason);
            }
            if let Some(reason) = snapshot_content_incompleteness(
                chain_gap.contains(&snapshot.stack_position),
                multi_device,
                diff_area_incomplete,
                content_data.is_some(),
            ) {
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] = json!(reason);
            }

            let mut vss_artifact = Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                content_data.clone(),
                metadata,
            )
            .with_parent(artifact.id);

            // The snapshot's $MFT records that differ from the live volume's,
            // published as prior versions parented to this record.
            let (summary, priors, incomplete_detail) =
                compare_with_live(&vss_artifact, content_data, live_mft.as_ref());
            vss_artifact.metadata["prior_versions"] = summary;
            if let Some(detail) = incomplete_detail {
                if vss_artifact.metadata.get("inventory_incomplete").is_none() {
                    vss_artifact.metadata["inventory_incomplete"] = json!(true);
                    vss_artifact.metadata["inventory_incomplete_reason"] =
                        json!(IncompleteReason::CapReached.as_str());
                }
                vss_artifact.metadata["inventory_incomplete_detail"] = json!(detail);
            }

            produced_artifacts.push(vss_artifact);
            produced_artifacts.extend(priors);
        }

        // The catalog chain did not run to its end: the snapshot list above is a
        // floor. Every snapshot carries that fact, and one record states it even
        // if the truncation left no snapshot at all (B6-020).
        if let Some(reason) = catalog_walk.reason() {
            warn!(
                "VSS catalog walk stopped early (cycle={}, block cap={}); {} snapshot(s) listed",
                catalog_walk.cycle_detected,
                catalog_walk.max_blocks_reached,
                produced_artifacts.len()
            );
            for a in produced_artifacts
                .iter_mut()
                .filter(|a| a.metadata["type"] == "VssSnapshot")
            {
                if let Some(map) = a.metadata.as_object_mut() {
                    map.insert("inventory_incomplete".into(), json!(true));
                    map.insert("inventory_incomplete_reason".into(), json!(reason));
                    map.insert("catalog_walk_complete".into(), json!(false));
                }
            }
            let listed = produced_artifacts
                .iter()
                .filter(|a| a.metadata["type"] == "VssSnapshot")
                .count();
            produced_artifacts.push(catalog_status_artifact(
                artifact,
                reason,
                listed,
                if catalog_walk.cycle_detected {
                    "The VSS catalog chain loops back on itself, so the walk stopped"
                } else {
                    "The VSS catalog chain is longer than this parser walks, so the walk stopped"
                },
            ));
        }

        Ok(produced_artifacts)
    }
}

/// Compare one snapshot's `$MFT` with the live volume's, returning the summary
/// the snapshot record carries, the prior-version records, and the detail of
/// any cap that left the comparison short.
///
/// A snapshot with no rebuilt stream, or a volume whose live `$MFT` could not
/// be located, is not compared, and its summary says so and why: an empty
/// prior-version list must never read as "nothing changed".
fn compare_with_live(
    snapshot: &Artifact,
    stream: Option<Arc<dyn DataSource>>,
    live: Option<&Result<prior_versions::ParsedMft, String>>,
) -> (serde_json::Value, Vec<Artifact>, Option<String>) {
    let not_compared = |why: String| {
        (
            json!({ "status": "not_compared", "reason": why }),
            Vec::new(),
            None,
        )
    };
    let Some(stream) = stream else {
        return not_compared("the snapshot's store chain did not build".to_string());
    };
    let live = match live {
        Some(Ok(live)) => live,
        Some(Err(e)) => return not_compared(format!("the live $MFT could not be read: {e}")),
        None => return not_compared("the live $MFT was not read".to_string()),
    };
    let md = &snapshot.metadata;
    let snap = prior_versions::SnapshotRef {
        artifact: snapshot,
        snapshot_id: md["snapshot_id"].as_str().unwrap_or(""),
        creation_time: md["creation_time"].as_str().unwrap_or("unknown"),
        stack_position: md["stack_position"].as_u64().unwrap_or(0),
        stream,
        content_incomplete_reason: md["content_incomplete_reason"].as_str(),
    };
    match prior_versions::diff_snapshot(live, &snap) {
        Ok(o) => (o.summary, o.prior_versions, o.inventory_incomplete_detail),
        Err(e) => not_compared(format!("the snapshot's $MFT could not be read: {e}")),
    }
}

/// The record that says the shadow-copy catalog was not walked to its end.
///
/// Without it, a truncated or cyclic catalog produces a short snapshot list, or
/// no list at all, that is indistinguishable from a volume that never had a
/// shadow copy.
fn catalog_status_artifact(
    artifact: &Artifact,
    reason: &str,
    snapshots_listed: usize,
    detail: &str,
) -> Artifact {
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "VssCatalogStatus",
            "subtype": "vss_catalog_incomplete",
            "name": "VSS catalog (not fully enumerated)",
            "content_incomplete": true,
            "content_incomplete_reason": reason,
            "inventory_incomplete": true,
            "inventory_incomplete_reason": reason,
            "snapshots_listed": snapshots_listed,
            "content_incomplete_detail": detail,
            "inventory_incomplete_detail": detail,
            "detail": detail,
            "message": "The shadow-copy catalog was not enumerated to its end: shadow copies \
                        past that point are absent from this case, and their absence is not \
                        evidence that they never existed",
            "source": "VssEnumerator",
        }),
    )
    .with_parent(artifact.id)
}

/// Why a reconstructed shadow copy's bytes are not the whole snapshot, if they
/// are not.
///
/// A snapshot with no attached content already says so through
/// `content_reconstruction`; this is about the case that is far more dangerous —
/// a snapshot that DOES serve bytes, and serves the wrong ones:
///
/// * `chain_gap`: the fall-through chain skipped a store it should have read,
///   so part of the image is dated to the wrong moment.
/// * `multi_device`: the diff storage lives on a volume this image is not.
///   Every block the snapshot preserved over there falls through to the LIVE
///   volume, so present-day bytes are mixed into a point-in-time image while it
///   looks fully reconstructed. `multi_device` on its own is a VSS-specific
///   marker; `content_incomplete` is the flag the API, export and
///   integrity-verify paths actually read (B2-153).
/// * `diff_area_incomplete`: the enumerator could not walk this snapshot's diff
///   area, yet a store built and is serving bytes. The two parses disagree about
///   which blocks the snapshot preserved, so any block the walk missed is being
///   served from an older store or the live volume.
///
/// `has_content` gates the last two: with no data source attached
/// `content_reconstruction` already reads "unavailable" and there are no bytes
/// to mislabel.
fn snapshot_content_incompleteness(
    chain_gap: bool,
    multi_device: bool,
    diff_area_incomplete: bool,
    has_content: bool,
) -> Option<&'static str> {
    if chain_gap {
        return Some("vss_store_chain_gap");
    }
    if !has_content {
        return None;
    }
    if multi_device {
        return Some("vss_diff_storage_on_other_volume");
    }
    if diff_area_incomplete {
        return Some("vss_diff_area_unreadable");
    }
    None
}

/// Reconstruct a single shadow copy's point-in-time content on demand.
///
/// The enumerator attaches a live `VssDataSource` to each snapshot at ingest,
/// but that source is *virtual*: its bytes are assembled from scattered
/// diff-area locations across the store chain, so it cannot be expressed as
/// persisted `data_runs` and does not survive the DB round-trip. The API content
/// resolver calls this to rebuild the same store chain from the volume window
/// and re-serve the snapshot's bytes for GUI/TUI viewing and download.
///
/// `volume` is the NTFS volume window the shadow copies live on (the same source
/// the enumerator ran against); `stack_position` selects the snapshot (matches
/// its `stack_position` metadata). Returns `None` if the volume has no VSS
/// catalog or that stack cannot be reconstructed (e.g. no type-3 store entry).
pub fn reconstruct_snapshot_content(
    volume: Arc<dyn DataSource>,
    stack_position: u64,
) -> Option<Arc<dyn DataSource>> {
    let enumerator = VssEnumerator;
    let header = enumerator.parse_volume_header(&volume).ok()?;
    if header.record_type != VSS_RECORD_TYPE_VOLUME_HEADER || header.catalog_offset == 0 {
        return None;
    }
    // The walk state is not needed here: this path re-reads a single snapshot's
    // bytes, and the catalog truncation is reported by the enumerator that
    // produced the snapshot record in the first place.
    let (snapshots, _catalog_walk) = enumerator
        .parse_catalog(&volume, header.catalog_offset)
        .ok()?;

    // Build the store chain highest-stack-first so each store falls through to
    // the nearest higher store that actually built, exactly as `process()` does.
    // Linking to the literal `stack + 1` would drop the rest of the chain
    // whenever that store is missing, quietly serving live-volume bytes in
    // place of the snapshot's own.
    let mut stack_snaps: Vec<&VssSnapshot> =
        snapshots.iter().filter(|s| s.has_store_entry).collect();
    stack_snaps.sort_by_key(|b| std::cmp::Reverse(b.stack_position));

    let mut stores: HashMap<u64, Arc<vss_source::VssStore>> = HashMap::new();
    let mut next_store: Option<Arc<vss_source::VssStore>> = None;
    let mut target_volume_size = None;
    for snap in &stack_snaps {
        if let Ok(store) = vss_source::VssStore::build(
            &volume,
            snap.block_list_offset,
            snap.bitmap_offset,
            snap.previous_bitmap_offset,
            snap.volume_size,
            snap.attribute_flags,
            next_store.clone(),
        ) {
            if snap.stack_position == stack_position {
                target_volume_size = Some(snap.volume_size);
            }
            let store = Arc::new(store);
            stores.insert(snap.stack_position, store.clone());
            next_store = Some(store);
        }
    }

    let store = stores.get(&stack_position)?.clone();
    let volume_size = target_volume_size?;
    Some(Arc::new(vss_source::VssDataSource::new(
        volume,
        store,
        volume_size,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    // The bytes a test built, and no more: a read past the end is short, never
    // padded. The private `MemSource` this replaced zero-filled every read past
    // the end and reported it full (ROADMAP §5.11) — the fabricated-bytes
    // behaviour `seance_core::test_support` exists to forbid. No test here
    // depended on it.
    use seance_core::data_source::ByteSliceDataSource;
    use uuid::Uuid;

    /// A source holding exactly `data` that never reads past its end and only
    /// returns `chunk` bytes per call — a truncated image, or a windowed source
    /// that dribbles bytes at run boundaries.
    #[derive(Debug)]
    struct StrictSource {
        data: Vec<u8>,
        chunk: usize,
    }

    impl DataSource for StrictSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = offset as usize;
            if off >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - off).min(self.chunk);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    /// A valid volume-header buffer with `catalog_offset` written at +48.
    fn volume_header_bytes(catalog_offset: u64) -> Vec<u8> {
        let mut buf = vec![0u8; VSS_VOLUME_HEADER_OFFSET as usize + VSS_VOLUME_HEADER_SIZE];
        let h = VSS_VOLUME_HEADER_OFFSET as usize;
        buf[h + 16..h + 20].copy_from_slice(&1u32.to_le_bytes());
        buf[h + 20..h + 24].copy_from_slice(&VSS_RECORD_TYPE_VOLUME_HEADER.to_le_bytes());
        buf[h + 48..h + 56].copy_from_slice(&catalog_offset.to_le_bytes());
        buf
    }

    #[test]
    fn volume_header_short_read_fails_closed() {
        // BUG-242: a volume that ends inside the header must error rather than
        // parse a zero-padded buffer (which would invent a zero catalog offset
        // and silently report "no shadow copies").
        let mut bytes = volume_header_bytes(16384);
        bytes.truncate(bytes.len() - 100);
        let source: Arc<dyn DataSource> = Arc::new(StrictSource {
            data: bytes,
            chunk: 4096,
        });
        assert!(VssEnumerator.parse_volume_header(&source).is_err());
    }

    #[test]
    fn volume_header_is_reassembled_from_short_reads() {
        // The same header behind a source that returns 64 bytes per call must
        // still parse: the fail-closed read loops before it gives up.
        let source: Arc<dyn DataSource> = Arc::new(StrictSource {
            data: volume_header_bytes(16384),
            chunk: 64,
        });
        let header = VssEnumerator
            .parse_volume_header(&source)
            .expect("short reads must be looped, not treated as EOF");
        assert_eq!(header.record_type, VSS_RECORD_TYPE_VOLUME_HEADER);
        assert_eq!(header.catalog_offset, 16384);
    }

    #[test]
    fn catalog_block_short_read_fails_closed() {
        // A catalog whose block is cut short must not be parsed as a full block
        // of zero entries with a zero next_offset.
        let data = vec![0u8; VSS_BLOCK_SIZE as usize + 100];
        let source: Arc<dyn DataSource> = Arc::new(StrictSource { data, chunk: 4096 });
        assert!(VssEnumerator
            .parse_catalog(&source, VSS_BLOCK_SIZE)
            .is_err());
    }

    // -- FILETIME conversion ------------------------------------------------

    #[test]
    fn filetime_to_unix_returns_none_for_zero_and_pre_epoch() {
        // FILETIME 0 is a timestomping indicator; it must not become a real
        // 1970 date. Pre-epoch values are likewise out of range.
        assert_eq!(seance_core::time::filetime_to_unix_secs(0), None);
        assert_eq!(seance_core::time::filetime_to_unix_secs(1_000_000), None);
    }

    #[test]
    fn filetime_to_unix_converts_known_value() {
        // 2000-01-01 00:00:00 UTC in FILETIME = 125911584000000000.
        // In Unix seconds: 946684800.
        let ft = 125_911_584_000_000_000u64;
        assert_eq!(
            seance_core::time::filetime_to_unix_secs(ft),
            Some(946_684_800)
        );
    }

    // -- GUID formatting ----------------------------------------------------

    #[test]
    fn format_guid_uses_mixed_endian_per_ms_convention() {
        // Microsoft GUIDs flip the first 3 fields (Data1/Data2/Data3) to little-endian.
        // For bytes 00..0f, the first field reverses to 03 02 01 00, etc.
        let bytes: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        assert_eq!(format_guid(&bytes), "03020100-0504-0706-0809-0a0b0c0d0e0f");
    }

    // Chain-aware VssDataSource / VssStore behaviour is covered by unit tests
    // in vss_source.rs (translate_exact_offset, forward-context parsing, and an
    // end-to-end reconstructed read).

    // -- VssEnumerator module gates -----------------------------------------

    fn art(
        art_type: ArtifactType,
        subtype: Option<&str>,
        data: Option<Arc<dyn DataSource>>,
    ) -> Artifact {
        let mut meta = json!({});
        if let Some(s) = subtype {
            meta["subtype"] = json!(s);
        }
        Artifact::new(Uuid::new_v4(), art_type, data, meta)
    }

    #[test]
    fn parse_catalog_terminates_on_self_referential_chain() {
        // A catalog block whose next_offset points back at itself must not
        // hang the worker: the visited-set/iteration guard has to break the
        // cycle. VSS_BLOCK_SIZE = 16384; next_offset lives at block byte 40.
        let block = VSS_BLOCK_SIZE as usize;
        let mut data = vec![0u8; block * 2];
        // Block located at offset `block` points its next_offset back to `block`.
        let next_off = (block as u64).to_le_bytes();
        data[block + 40..block + 48].copy_from_slice(&next_off);

        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let result = VssEnumerator.parse_catalog(&source, block as u64);
        // The important assertion is simply that this call RETURNS.
        assert!(result.is_ok());
        // B6-020: and that the walk says it stopped on a loop. A cycle used to
        // end the walk silently, so a catalog listing more shadow copies past
        // that point looked like a volume that had none.
        let (_snaps, walk) = result.unwrap();
        assert!(!walk.is_complete());
        assert!(walk.cycle_detected);
        assert_eq!(walk.reason(), Some("unresolved_structure"));
    }

    #[test]
    fn module_identity() {
        let m = VssEnumerator;
        assert_eq!(m.id(), "plugin.windows.vss_enumerator");
        let subs = m.subscribes_to();
        assert!(subs.contains(&ArtifactType::FileSystem));
        assert!(subs.contains(&ArtifactType::RawEvidence));
        assert_eq!(m.input_capability(), InputCapability::RandomAccess);
    }

    #[test]
    fn non_ntfs_filesystem_short_circuits() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 16 * 1024]));
        let a = art(ArtifactType::FileSystem, Some("ext4"), Some(src));
        let out = VssEnumerator.process(&a).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn ntfs_filesystem_without_data_source_returns_empty() {
        let a = art(ArtifactType::FileSystem, Some("ntfs"), None);
        let out = VssEnumerator.process(&a).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn ntfs_filesystem_without_vss_volume_header_returns_empty() {
        // A buffer that's NTFS-sized but has zero bytes where the VSS header
        // would be — parse_volume_header succeeds but record_type != 0x01,
        // so the enumerator silently skips.
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 16 * 1024]));
        let a = art(ArtifactType::FileSystem, Some("ntfs"), Some(src));
        let out = VssEnumerator.process(&a).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn filesystem_type_metadata_used_when_subtype_absent() {
        // No subtype, but filesystem_type is set to a non-NTFS value → skip.
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 16 * 1024]));
        let a = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(src),
            json!({ "filesystem_type": "FAT32" }),
        );
        let out = VssEnumerator.process(&a).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn raw_evidence_without_vss_header_returns_empty() {
        // RawEvidence bypasses the NTFS subtype gate but still needs a valid
        // VSS volume header at offset 0x1e00.
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 16 * 1024]));
        let a = art(ArtifactType::RawEvidence, None, Some(src));
        let out = VssEnumerator.process(&a).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn ntfs_filesystem_with_valid_vss_header_but_no_catalog_returns_empty() {
        // Build a buffer big enough to cover the VSS volume header location,
        // and write record_type = 0x01 (volume header) at the right offset
        // with catalog_offset = 0 → enumerator early-exits ("no catalog").
        let mut buf =
            vec![0u8; (VSS_VOLUME_HEADER_OFFSET + VSS_VOLUME_HEADER_SIZE as u64) as usize + 16];
        let hdr_start = VSS_VOLUME_HEADER_OFFSET as usize;
        // 16-byte identifier left at 0.
        // version (u32 LE) at +16
        buf[hdr_start + 16..hdr_start + 20].copy_from_slice(&1u32.to_le_bytes());
        // record_type (u32 LE) at +20 = VSS_RECORD_TYPE_VOLUME_HEADER (0x01)
        buf[hdr_start + 20..hdr_start + 24]
            .copy_from_slice(&VSS_RECORD_TYPE_VOLUME_HEADER.to_le_bytes());
        // current_offset, unknown_offset, then catalog_offset at +48 = 0 (already zero).
        // max_size, volume_id, storage_volume_id all left at 0.

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(buf));
        let a = art(ArtifactType::FileSystem, Some("ntfs"), Some(src));
        let out = VssEnumerator.process(&a).unwrap();
        // catalog_offset == 0 → "VSS volume has no catalog" → empty.
        assert!(out.is_empty());
    }

    /// B2-153: a snapshot whose diff storage lives on another volume still
    /// builds a store chain and still serves bytes — but every block preserved
    /// on the missing volume falls through to the LIVE volume, so present-day
    /// data is served as point-in-time snapshot data. `multi_device: true` is a
    /// VSS-specific marker; the flag the API, export and integrity-verify paths
    /// read is `content_incomplete`, and without it the snapshot looks fully
    /// reconstructed.
    #[test]
    fn a_multi_device_snapshot_that_serves_bytes_is_flagged_incomplete() {
        assert_eq!(
            snapshot_content_incompleteness(false, true, false, true),
            Some("vss_diff_storage_on_other_volume")
        );
        // A chain gap is the more specific defect and keeps its own reason.
        assert_eq!(
            snapshot_content_incompleteness(true, true, false, true),
            Some("vss_store_chain_gap")
        );
        // A store that serves bytes while its diff area would not walk is
        // serving somebody else's blocks for everything the walk missed.
        assert_eq!(
            snapshot_content_incompleteness(false, false, true, true),
            Some("vss_diff_area_unreadable")
        );
        // Nothing served: `content_reconstruction` already says "unavailable",
        // and there are no bytes to mislabel.
        assert_eq!(
            snapshot_content_incompleteness(false, true, true, false),
            None
        );
        // Single-volume, whole chain: complete, so the flag keeps its meaning.
        assert_eq!(
            snapshot_content_incompleteness(false, false, false, true),
            None
        );
    }
}
