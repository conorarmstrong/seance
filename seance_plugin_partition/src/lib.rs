#![forbid(unsafe_code)]
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, SourceCursor, WindowSource},
    io::{read_exact_or_fail, read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct PartitionParser;
pub struct FilesystemDetector;

/// Smallest gap (bytes) worth emitting as an UnallocatedSpace artifact. A one
/// (legacy) sector floor keeps forensically meaningful slack visible (e.g. the
/// classic 63-sector pre-partition gap and inter-partition slack) while dropping
/// zero-length noise.
const MIN_GAP_BYTES: u64 = 512;
/// Gaps smaller than this are additionally flagged `small_gap:true` so the UI can
/// style sub-1MiB slack differently from large unallocated regions.
const SMALL_GAP_BYTES: u64 = 1024 * 1024;

impl ForensicsModule for PartitionParser {
    fn id(&self) -> &str {
        "plugin.disk.partition_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::RawEvidence]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        debug!("PartitionParser processing artifact ID: {}", artifact.id);
        let mut produced_artifacts = Vec::new();

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("Partition parser requires a data source".to_string())
        })?;

        // Read first 512 bytes to determine partition table type. A single
        // `read_at` may return fewer bytes than asked for (E01/AFF4/windowed
        // sources deliver in chunks); parsing the zero tail would fabricate BPB
        // geometry or miss the 0x55AA signature and report a disk as having no
        // partition table at all.
        if data_source.size() < 512 {
            warn!(
                "Artifact {} is smaller than one sector; no partition table to read",
                artifact.id
            );
            return Ok(produced_artifacts);
        }
        let mut header = vec![0u8; 512];
        read_exact_or_fail(data_source.as_ref(), 0, &mut header, "MBR sector")?;

        // Check for GPT first (GPT has a protective MBR in the first sector).
        // The GPT header signature "EFI PART" lives at LBA 1, whose byte offset
        // depends on the logical sector size (512 -> 0x200, 4096 -> 0x1000).
        if let Some(sector_size) = detect_gpt_sector_size(data_source.as_ref())? {
            info!(
                "Detected GPT partition table (sector size {} bytes)",
                sector_size
            );
            produced_artifacts.extend(parse_gpt(artifact, sector_size)?);
            return Ok(produced_artifacts);
        }

        // Check for MBR signature (0x55AA at offset 510-511). MBR is conventionally
        // 512-byte sectored; expose it as a parsed value used consistently below.
        if header.len() >= 512 && header[510] == 0x55 && header[511] == 0xAA {
            let sector_size = 512u64;
            info!("Detected MBR partition table");
            produced_artifacts.extend(parse_mbr(artifact, &header, sector_size)?);
            return Ok(produced_artifacts);
        }

        // No conventional partition table — but a raw RAID/LVM member image has
        // none either: it carries a Linux `md` superblock instead. Detect it and
        // surface that the image is part of an array (and how to reconstruct it),
        // so the examiner learns to run `scan-raid`/`assemble-raid` rather than
        // reading a member as an empty, structureless disk.
        if let Some(rec) = detect_raid_member(artifact, data_source.as_ref(), &header) {
            produced_artifacts.push(rec);
            return Ok(produced_artifacts);
        }

        warn!("No valid partition table found in artifact {}", artifact.id);
        Ok(produced_artifacts)
    }
}

/// If the image carries a Linux `md` software-RAID superblock, emit a
/// `RaidMember` record naming the geometry and pointing at the assembly commands.
/// Returns `None` for anything without a checksum-valid superblock.
///
/// Checks all three placements: v1.1 (offset 0) and v1.2 (4 KiB in) in the head,
/// and v1.0 at the end of the device. The superblock's own checksum is validated
/// ([`seance_container_raid::md::parse_superblock`]), so a coincidental magic in
/// carved or nested data does not produce a false record. `header` is the first
/// sector already read by the caller, reused to avoid re-fetching it from a
/// windowed/encrypted source.
fn detect_raid_member(
    artifact: &Artifact,
    data_source: &dyn seance_core::data_source::DataSource,
    header: &[u8],
) -> Option<Artifact> {
    use seance_container_raid::md;

    // Head: covers v1.1 (@0) and v1.2 (@4096) plus room for the dev_roles the
    // checksum spans. Seed the first sector from the caller's `header` and read
    // only the remainder, so a windowed/encrypted source is not fetched twice.
    let mut head = vec![0u8; 12 * 1024];
    let seed = header.len().min(head.len());
    head[..seed].copy_from_slice(&header[..seed]);
    let more = read_full(data_source, seed as u64, &mut head[seed..]);
    head.truncate(seed + more);

    let found = md::find_superblock(&head).or_else(|| {
        // v1.0 lives at the end of the device. Read a window there and parse it;
        // the checksum guard rejects a miss, so a wrong offset costs nothing.
        let off = md::v10_superblock_offset(data_source.size())?;
        let mut tail = vec![0u8; 12 * 1024];
        let n = read_full(data_source, off, &mut tail);
        tail.truncate(n);
        md::parse_superblock(&tail).map(|g| (g, off as usize))
    })?;
    let (geom, at) = found;

    // Never claim more usable data than the image actually holds: a truncated or
    // partially-imaged member carries a superblock declaring the full original
    // component size. Clamp, and say when the declared size exceeds the capture.
    let image_size = data_source.size();
    let declared = geom.member_size;
    let member_size = declared.min(image_size);
    let truncated = declared > image_size;

    info!(
        "Detected Linux md RAID member ({:?}) in artifact {}",
        geom.level, artifact.id
    );
    let mut meta = serde_json::json!({
        "type": "RaidMember",
        "subtype": "md_superblock",
        "name": "RAID member (Linux md superblock)",
        "raid_level": format!("{:?}", geom.level),
        "raid_disks": geom.raid_disks,
        "chunk_bytes": geom.chunk_bytes,
        "member_size_bytes": member_size,
        "declared_member_size_bytes": declared,
        "superblock_offset": at,
        "reconstruct_with": "seance scan-raid  (or  seance assemble-raid)",
        "evidence_grade": "scanned",
        "note": "This image is a member of a Linux md software-RAID array, not a \
                 standalone disk. Reconstruct the array from all its members with \
                 `seance scan-raid --member <this> --member <other> …` (virtual, \
                 in-ingest) or `seance assemble-raid` (to an image).",
    });
    if truncated {
        if let Some(obj) = meta.as_object_mut() {
            obj.insert("content_incomplete".into(), serde_json::json!(true));
            obj.insert(
                "content_incomplete_reason".into(),
                serde_json::json!(IncompleteReason::ShortRead.as_str()),
            );
            obj.insert(
                "content_incomplete_detail".into(),
                serde_json::json!(
                    "member image is shorter than the superblock's declared component size"
                ),
            );
        }
    }
    Some(
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
            .with_parent(artifact.id),
    )
}

/// Detect a GPT partition table and its logical sector size.
///
/// Returns `Ok(Some(sector_size))` if the GPT header signature "EFI PART" is
/// present at LBA 1 for that sector size. 512-byte sectors place LBA 1 at offset
/// 0x200 and 4Kn (4096-byte) sectors place it at 0x1000; 512 is checked first.
///
/// A read that cannot deliver the 8 signature bytes even though the source is
/// long enough is an I/O failure, and is returned as an error rather than as
/// "not GPT": answering "no partition table" for a disk we simply could not
/// read produces an empty partition map and no filesystem walk, with nothing to
/// distinguish it from a genuinely unpartitioned disk.
fn detect_gpt_sector_size(ds: &dyn DataSource) -> Result<Option<u64>, ModuleError> {
    for &sector_size in &[512u64, 4096u64] {
        if ds.size() < sector_size.saturating_add(8) {
            continue;
        }
        let mut sig = [0u8; 8];
        read_exact_or_fail(ds, sector_size, &mut sig, "GPT header signature")?;
        if &sig == b"EFI PART" {
            return Ok(Some(sector_size));
        }
    }
    Ok(None)
}

/// Compute a GPT partition's `(offset_bytes, size_bytes)` from its inclusive LBA
/// bounds using checked arithmetic. A hostile but CRC-valid table can carry
/// `last_lba < first_lba` or LBAs near `u64::MAX`; the `gpt` crate does not
/// reject these at parse time (it exposes checked size helpers precisely because
/// they can be invalid), so a raw `(last_lba - first_lba + 1) * sector_size`
/// would underflow/overflow and panic in debug builds. Returns `None` for any
/// partition whose geometry does not fit, so the caller can skip it. Preserves
/// the inclusive `+1` sector semantics of the original expression.
fn gpt_partition_extent(first_lba: u64, last_lba: u64, sector_size: u64) -> Option<(u64, u64)> {
    let sectors = last_lba.checked_sub(first_lba)?.checked_add(1)?;
    let size_bytes = sectors.checked_mul(sector_size)?;
    let offset_bytes = first_lba.checked_mul(sector_size)?;
    Some((offset_bytes, size_bytes))
}

/// Byte `(offset, size)` of a free-sector gap described by `(start_lba,
/// length_lba)`. Uses the same checked arithmetic as the partition extents so
/// hostile/corrupt geometry cannot overflow `u64` and produce a wrong window;
/// returns `None` on overflow so the caller can skip the gap.
fn gap_extent(start_lba: u64, length_lba: u64, sector_size: u64) -> Option<(u64, u64)> {
    let offset_bytes = start_lba.checked_mul(sector_size)?;
    let size_bytes = length_lba.checked_mul(sector_size)?;
    Some((offset_bytes, size_bytes))
}

/// CRC-32/ISO-HDLC, the checksum both GPT structures carry.
fn gpt_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = if crc & 1 != 0 { 0xEDB8_8320u32 } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}

/// Decode a GPT whose own integrity check failed, and say so on everything.
///
/// # Why this exists
///
/// The strict parser refuses a table whose CRC does not match, and that turned
/// a readable 2,098,028,544-byte disk into a single artifact — measured, by
/// running NIST CFTT's Forensic String Search methodology (`ROADMAP` §5.2)
/// against `ss-win-07-25-18.dd`, whose header CRC verifies (`0x6e47e4e5`) and
/// whose entry-array CRC does not (declared `0xf87a9ff9`, computed
/// `0x11726dec`). `mmls` reads its four partitions regardless, and so does a
/// by-hand decode.
///
/// A CRC mismatch is what carved, truncated and deliberately damaged evidence
/// looks like. **"Could not verify" is not "not there."** So the entries are
/// decoded from the header's own figures and every partition produced carries
/// `partition_table_verified: false` with the reason, stamped `Unvalidated` —
/// the bytes were read; what could not be established is their integrity.
fn parse_gpt_unverified(
    artifact: &Artifact,
    parent_data: &Arc<dyn DataSource>,
    sector_size: u64,
    strict_error: &str,
) -> Result<Vec<Artifact>, ModuleError> {
    /// GPT's own header size, and the span both CRCs cover.
    const HEADER_BYTES: usize = 92;

    let mut header = vec![0u8; sector_size as usize];
    let read = seance_core::io::read_full(parent_data.as_ref(), sector_size, &mut header);
    if read < HEADER_BYTES || &header[..8] != b"EFI PART" {
        // Not a GPT at all, or its header is unreadable. Refused rather than
        // guessed at: inventing a layout here would invent partitions.
        return Err(ModuleError::ParsingError(format!(
            "Failed to parse GPT: {strict_error}, and its header could not be read directly \
             either ({read} of {HEADER_BYTES} bytes at the GPT header LBA)"
        )));
    }

    let le32 =
        |at: usize| -> u32 { u32::from_le_bytes(header[at..at + 4].try_into().unwrap_or([0; 4])) };
    let le64 =
        |at: usize| -> u64 { u64::from_le_bytes(header[at..at + 8].try_into().unwrap_or([0; 8])) };

    let declared_header_crc = le32(16);
    let mut zeroed = header[..HEADER_BYTES].to_vec();
    zeroed[16..20].copy_from_slice(&[0, 0, 0, 0]);
    let computed_header_crc = gpt_crc32(&zeroed);
    let header_crc_verified = declared_header_crc == computed_header_crc;

    let entries_lba = le64(72);
    let entry_count = le32(80) as usize;
    let entry_size = le32(84) as usize;
    let declared_entries_crc = le32(88);

    // Bounds before any read. An entry count or size the header invented would
    // otherwise be an allocation.
    const MAX_ENTRIES: usize = 4_096;
    const MAX_ENTRY_BYTES: usize = 4_096;
    if entry_count == 0
        || entry_count > MAX_ENTRIES
        || !(128..=MAX_ENTRY_BYTES).contains(&entry_size)
    {
        return Err(ModuleError::ParsingError(format!(
            "Failed to parse GPT: {strict_error}. Its header declares {entry_count} entries of \
             {entry_size} bytes, which this build will not read as a table."
        )));
    }
    let array_bytes = entry_count.saturating_mul(entry_size);
    let array_at = entries_lba.saturating_mul(sector_size);
    let mut entries = vec![0u8; array_bytes];
    let got = seance_core::io::read_full(parent_data.as_ref(), array_at, &mut entries);
    if got < array_bytes {
        return Err(ModuleError::ParsingError(format!(
            "Failed to parse GPT: {strict_error}. Its header puts the entry array at byte \
             {array_at} and {got} of {array_bytes} bytes were readable there, so decoding it \
             would invent partitions."
        )));
    }
    let computed_entries_crc = gpt_crc32(&entries);
    let entries_crc_verified = declared_entries_crc == computed_entries_crc;

    let mut out: Vec<Artifact> = Vec::new();
    for i in 0..entry_count {
        let e = i * entry_size;
        let type_guid = &entries[e..e + 16];
        // An all-zero type GUID is an unused slot, which is not a partition.
        if type_guid.iter().all(|b| *b == 0) {
            continue;
        }
        let first_lba = u64::from_le_bytes(entries[e + 32..e + 40].try_into().unwrap_or([0; 8]));
        let last_lba = u64::from_le_bytes(entries[e + 40..e + 48].try_into().unwrap_or([0; 8]));
        let Some((offset_bytes, size_bytes)) =
            gpt_partition_extent(first_lba, last_lba, sector_size)
        else {
            continue;
        };
        let name = {
            let raw = &entries[e + 56..(e + entry_size).min(entries.len())];
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|u| *u != 0)
                .collect();
            String::from_utf16_lossy(&units)
        };
        let metadata = json!({
            "partition_scheme": "GPT",
            "partition_id": i as u32 + 1,
            "partition_type_guid": gpt_guid_string(type_guid),
            "partition_guid": gpt_guid_string(&entries[e + 16..e + 32]),
            "name": name,
            "first_lba": first_lba,
            "last_lba": last_lba,
            "size_bytes": size_bytes,
            "offset_bytes": offset_bytes,
            "sector_size": sector_size,
            // On every partition, so one exported alone still says its map was
            // not verified.
            "partition_table_verified": false,
            "partition_table_integrity": gpt_integrity_sentence(
                header_crc_verified,
                entries_crc_verified,
            ),
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::Unvalidated.as_str(),
        });
        let window = Arc::new(WindowSource::new(
            Arc::clone(parent_data),
            offset_bytes,
            size_bytes,
        ));
        out.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::Partition,
                Some(window),
                metadata,
            )
            .with_parent(artifact.id),
        );
    }

    let emitted = out.len();
    // The table itself is a record, with both digests so a reader can check
    // the claim rather than take it.
    out.push(
        Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "GptPartitionTableUnverified",
                "subtype": "parse_incomplete",
                "name": "GPT partition table did not verify",
                "header_crc_verified": header_crc_verified,
                "header_crc_declared": format!("0x{declared_header_crc:08x}"),
                "header_crc_computed": format!("0x{computed_header_crc:08x}"),
                "entries_crc_verified": entries_crc_verified,
                "entries_crc_declared": format!("0x{declared_entries_crc:08x}"),
                "entries_crc_computed": format!("0x{computed_entries_crc:08x}"),
                "entries_lba": entries_lba,
                "entry_count": entry_count,
                "entry_size": entry_size,
                "partitions_emitted": emitted,
                "strict_parser_error": strict_error,
                "detail": gpt_integrity_sentence(header_crc_verified, entries_crc_verified),
                "content_incomplete": true,
                "content_incomplete_reason": IncompleteReason::Unvalidated.as_str(),
            }),
        )
        .with_parent(artifact.id),
    );
    Ok(out)
}

/// A GPT GUID in its mixed-endian textual form.
fn gpt_guid_string(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }
    let d1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap_or([0; 4]));
    let d2 = u16::from_le_bytes(bytes[4..6].try_into().unwrap_or([0; 2]));
    let d3 = u16::from_le_bytes(bytes[6..8].try_into().unwrap_or([0; 2]));
    let rest: String = bytes[8..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("{d1:08x}-{d2:04x}-{d3:04x}-{}-{}", &rest[..4], &rest[4..])
}

/// What failed, in the words a record carries.
fn gpt_integrity_sentence(header_ok: bool, entries_ok: bool) -> String {
    match (header_ok, entries_ok) {
        (true, false) => "This GPT's ENTRY-ARRAY CRC did not verify: the table's own checksum \
                          does not match the entries it covers, so the entries may have changed \
                          since the checksum was written. They are decoded and reported anyway, \
                          because a failed integrity check is a fact about the table and not a \
                          reason to report no partitions -- a CRC mismatch is what carved, \
                          truncated and deliberately damaged evidence looks like. The header's \
                          own CRC does verify, so the figures used to find the entry array are \
                          themselves sound."
            .to_string(),
        (false, true) => "This GPT's HEADER CRC did not verify, though the entry array's own \
                          checksum does. That is the louder of the two failures: the header is \
                          where the entry array is, how many entries there are and how big each \
                          one is, and the decode below used those figures because they are the \
                          only ones there are. Treat the partition list as unverified."
            .to_string(),
        (false, false) => "NEITHER of this GPT's CRCs verified. The header is where the entry \
                           array is, how many entries there are and how big each one is, and the \
                           decode below used those figures because they are the only ones there \
                           are; the entry array's own checksum then also failed to match what it \
                           covers. Treat the partition list as unverified in both respects."
            .to_string(),
        (true, true) => "Both of this GPT's CRCs verify. The strict parser refused the table for \
                         another reason, recorded beside this."
            .to_string(),
    }
}

fn parse_gpt(artifact: &Artifact, sector_size: u64) -> Result<Vec<Artifact>, ModuleError> {
    let mut produced_artifacts = Vec::new();

    // Use SourceCursor for streaming access (no memory loading)
    // This supports >2TB images without OOM
    let parent_data = artifact.data.as_ref().ok_or_else(|| {
        ModuleError::InvalidInputFormat(
            "GPT parsing requires artifact with data source".to_string(),
        )
    })?;
    let cursor = SourceCursor::new(Arc::clone(parent_data));

    // Drive the gpt header/LBA math with the detected logical sector size.
    let lb_size = if sector_size == 4096 {
        gpt::disk::LogicalBlockSize::Lb4096
    } else {
        gpt::disk::LogicalBlockSize::Lb512
    };

    let gpt_disk = match gpt::GptConfig::new()
        .writable(false)
        .logical_block_size(lb_size)
        .open_from_device(Box::new(cursor))
    {
        Ok(disk) => disk,
        Err(e) => {
            // A FAILED INTEGRITY CHECK IS A FACT TO REPORT, NOT A REASON TO
            // REPORT NOTHING. The `gpt` crate refuses a table whose CRC does
            // not match, and refusing it here turned a readable 2 GB disk into
            // one artifact: found by running NIST CFTT's Forensic String
            // Search methodology (ROADMAP §5.2) against `ss-win-07-25-18.dd`,
            // whose header CRC verifies and whose entry-array CRC does not.
            // `mmls` reads its four partitions regardless.
            //
            // A CRC mismatch is what carved, truncated and deliberately
            // damaged evidence looks like. "Could not verify" is not "not
            // there", so the entries are decoded from the header's own figures
            // and every partition says the check failed.
            debug!("GPT refused by the strict parser ({e}); decoding the entry array directly");
            return parse_gpt_unverified(artifact, parent_data, sector_size, &e.to_string());
        }
    };

    info!("GPT disk GUID: {:?}", gpt_disk.guid());

    // GPT entries the table names and this parse could not place on the disk.
    // Skipping one drops a whole partition from the map, so the count has to
    // reach the examiner and not only the log — the same defect the MBR
    // extended chain carried (B3-020).
    let mut invalid_geometry_entries: usize = 0;
    let mut first_invalid_geometry: Option<String> = None;

    for (partition_id, partition) in gpt_disk.partitions() {
        let part_type = partition.part_type_guid.guid;
        let part_guid = partition.part_guid;
        let first_lba = partition.first_lba;
        let last_lba = partition.last_lba;
        let name = partition.name.clone();

        let (offset_bytes, size_bytes) =
            match gpt_partition_extent(first_lba, last_lba, sector_size) {
                Some(extent) => extent,
                None => {
                    warn!(
                    "Skipping GPT partition {} with invalid geometry (first_lba {}, last_lba {})",
                    partition_id, first_lba, last_lba
                );
                    invalid_geometry_entries += 1;
                    first_invalid_geometry.get_or_insert(format!(
                        "GPT entry {partition_id} declares first_lba {first_lba} and last_lba \
                         {last_lba}, which describe no readable extent at {sector_size}-byte \
                         sectors"
                    ));
                    continue;
                }
            };

        info!(
            "Found GPT partition {}: {} (Type: {:?}, Size: {} bytes)",
            partition_id, name, part_type, size_bytes
        );

        let metadata = json!({
            "partition_scheme": "GPT",
            "partition_id": partition_id,
            "partition_guid": part_guid.to_string(),
            "partition_type_guid": part_type.to_string(),
            "partition_type_name": gpt_type_name(&part_type),
            "name": name,
            "first_lba": first_lba,
            "last_lba": last_lba,
            "size_bytes": size_bytes,
            "offset_bytes": offset_bytes,
            "sector_size": sector_size,
        });

        // Create a WindowSource for this partition
        // parent_data is already validated above
        let partition_window = Arc::new(WindowSource::new(
            Arc::clone(parent_data),
            offset_bytes,
            size_bytes,
        ));

        let partition_artifact = Artifact::new(
            artifact.case_id,
            ArtifactType::Partition,
            Some(partition_window),
            metadata,
        )
        .with_parent(artifact.id);

        produced_artifacts.push(partition_artifact);
    }

    // An entry the table names and the map does not show is a missing partition,
    // and "this disk has three partitions" is then a false statement about a
    // four-entry table. Record it on the artifacts, not only in the log
    // (B3-020, swept from the MBR extended chain to GPT).
    if invalid_geometry_entries > 0 {
        let emitted = produced_artifacts.len();
        let reason = IncompleteReason::UnresolvedStructure.as_str();
        for part in produced_artifacts.iter_mut() {
            if let Some(map) = part.metadata.as_object_mut() {
                map.insert("inventory_incomplete".into(), json!(true));
                map.insert("inventory_incomplete_reason".into(), json!(reason));
            }
        }
        let why = first_invalid_geometry
            .unwrap_or_else(|| "the entry describes no readable extent".to_string());
        let detail = format!(
            "the GPT table names {invalid_geometry_entries} partition(s) whose geometry could \
             not be resolved, so they are absent from the {emitted} partition(s) listed: {why}"
        );
        produced_artifacts.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "GptPartitionTableIncomplete",
                    "subtype": "parse_incomplete",
                    "status": "PartitionEntriesUnresolved",
                    "partition_scheme": "GPT",
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": reason,
                    "content_incomplete": true,
                    "content_incomplete_reason": reason,
                    "stop_cause": "gpt_entry_invalid_geometry",
                    "invalid_geometry_entries": invalid_geometry_entries,
                    "partitions_emitted": emitted,
                    "content_incomplete_detail": detail,
                    "inventory_incomplete_detail": detail,
                    "detail": detail,
                    "name": format!("GPT partition table: incomplete — {detail}"),
                }),
            )
            .with_parent(artifact.id)
            .with_subtype("parse_incomplete"),
        );
    }

    // Emit UnallocatedSpace artifacts for gaps between/around partitions.
    let free_sectors = gpt_disk.find_free_sectors();
    for (gap_idx, &(start_lba, length_lba)) in free_sectors.iter().enumerate() {
        let (gap_offset, gap_size) = match gap_extent(start_lba, length_lba, sector_size) {
            Some(v) => v,
            None => {
                warn!(
                    "Skipping GPT gap {} with invalid geometry (start_lba {}, length_lba {})",
                    gap_idx, start_lba, length_lba
                );
                continue;
            }
        };
        if gap_size < MIN_GAP_BYTES {
            continue;
        }

        info!(
            "Found unallocated space: offset 0x{:x}, size {} bytes",
            gap_offset, gap_size
        );
        let gap_window = Arc::new(WindowSource::new(
            Arc::clone(parent_data),
            gap_offset,
            gap_size,
        ));
        let mut gap_metadata = json!({
            "partition_scheme": "GPT",
            "gap_index": gap_idx,
            "offset_bytes": gap_offset,
            "size_bytes": gap_size,
            "sector_size": sector_size,
        });
        if gap_size < SMALL_GAP_BYTES {
            gap_metadata
                .as_object_mut()
                .unwrap()
                .insert("small_gap".to_string(), json!(true));
        }
        produced_artifacts.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::UnallocatedSpace,
                Some(gap_window),
                gap_metadata,
            )
            .with_parent(artifact.id),
        );
    }

    Ok(produced_artifacts)
}

/// One 16-byte MBR primary partition-table entry, parsed directly from the first
/// sector. Field semantics match the classic MBR layout: `boot == 0x80` marks the
/// entry active/bootable, and `sys == 0` marks the slot unused.
struct MbrPartition {
    boot: u8,
    sys: u8,
    starting_lba: u32,
    sectors: u32,
}

/// Parse the 4 primary partition entries from the 512-byte first sector. The table
/// starts at byte offset 446, 16 bytes per entry: byte 0 = boot flag, byte 4 =
/// partition type, bytes 8..12 = starting LBA (LE u32), bytes 12..16 = sector count
/// (LE u32). Bounds-checked so a short header yields fewer entries instead of
/// panicking.
fn parse_mbr_entries(header: &[u8]) -> Vec<MbrPartition> {
    const TABLE_OFFSET: usize = 446;
    let mut entries = Vec::with_capacity(4);
    for i in 0..4 {
        let base = TABLE_OFFSET + i * 16;
        if base + 16 > header.len() {
            break;
        }
        let e = &header[base..base + 16];
        entries.push(MbrPartition {
            boot: e[0],
            sys: e[4],
            starting_lba: u32::from_le_bytes([e[8], e[9], e[10], e[11]]),
            sectors: u32::from_le_bytes([e[12], e[13], e[14], e[15]]),
        });
    }
    entries
}

fn parse_mbr(
    artifact: &Artifact,
    header: &[u8],
    sector_size: u64,
) -> Result<Vec<Artifact>, ModuleError> {
    let mut produced_artifacts = Vec::new();

    let parent_data = artifact.data.as_ref().ok_or_else(|| {
        ModuleError::InvalidInputFormat("Parent artifact has no data source".to_string())
    })?;

    // Parse the 4 primary partition-table entries directly from the first sector.
    // This is trivial, bounds-checked, pure-safe Rust, so hostile evidence can't
    // panic here (unlike the previous third-party crate, whose alignment logic
    // unwrapped an empty range and panicked on crafted tables).
    let entries = parse_mbr_entries(header);

    // Logical partitions are conventionally numbered from 5 (after 4 primaries).
    let mut logical_id: u32 = 5;
    // (start_lba, end_lba_exclusive) of each primary — used for gap detection.
    let mut used_ranges: Vec<(u64, u64)> = Vec::new();

    for (idx, partition) in entries.into_iter().enumerate() {
        // Primary entries are numbered 1..=4 (preserving prior numbering).
        let i = idx + 1;
        // A partition is used when its type byte is non-zero.
        if partition.sys == 0 {
            continue;
        }

        let sys = partition.sys;
        let starting_lba = partition.starting_lba as u64;
        let sectors = partition.sectors as u64;

        used_ranges.push((starting_lba, starting_lba + sectors));

        info!(
            "Found MBR partition {}: Type 0x{:02X}, Size: {} bytes",
            i,
            sys,
            sectors * sector_size
        );

        // An extended partition is a container, not a data partition: don't emit
        // it as one, just walk its logical partitions from the EBR chain.
        if is_extended(sys) {
            walk_extended(
                artifact,
                parent_data,
                i,
                starting_lba,
                sectors,
                sector_size,
                &mut logical_id,
                &mut produced_artifacts,
            )?;
        } else {
            produced_artifacts.push(make_mbr_partition(
                artifact,
                parent_data,
                json!(i),
                sys,
                partition.boot == 0x80,
                starting_lba,
                sectors,
                sector_size,
                None,
            ));
        }
    }

    // Emit UnallocatedSpace artifacts for gaps between/around primary partitions.
    let total_sectors = parent_data.size() / sector_size;
    used_ranges.sort_by_key(|r| r.0);

    let mut scan_from: u64 = 1; // first usable sector after the MBR
    let mut gap_idx = 0usize;

    for &(part_start, part_end) in &used_ranges {
        if part_start > scan_from {
            emit_gap(
                artifact,
                parent_data,
                scan_from,
                part_start - scan_from,
                sector_size,
                gap_idx,
                false,
                None,
                &mut produced_artifacts,
            );
            gap_idx += 1;
        }
        scan_from = scan_from.max(part_end);
    }

    // Trailing gap after the last primary partition.
    if total_sectors > scan_from {
        emit_gap(
            artifact,
            parent_data,
            scan_from,
            total_sectors - scan_from,
            sector_size,
            gap_idx,
            true,
            None,
            &mut produced_artifacts,
        );
    }

    Ok(produced_artifacts)
}

/// Extended-container partition type indicators (CHS, LBA, and Linux extended).
fn is_extended(sys: u8) -> bool {
    matches!(sys, 0x05 | 0x0F | 0x85)
}

/// Map an MBR system indicator byte to a human name and optional filesystem subtype.
fn mbr_type_info(sys: u8) -> (&'static str, Option<&'static str>) {
    match sys {
        0x01 => ("FAT12", Some("fat12")),
        0x04 | 0x06 => ("FAT16", Some("fat16")),
        0x07 => ("NTFS/exFAT", Some("ntfs")), // could be exFAT, but NTFS more common
        0x0B | 0x0C => ("FAT32", Some("fat32")),
        0x0E => ("FAT16 LBA", Some("fat16")),
        0x82 => ("Linux Swap", Some("swap")),
        0x83 => ("Linux", Some("linux")), // could be ext4/ext3/xfs/etc.
        0x8E => ("Linux LVM", None),
        0xA5 => ("FreeBSD", None),
        0xA8 => ("Apple UFS", None),
        0xAB => ("Apple Boot", None),
        0xAF => ("Apple HFS+", None),
        0xEE => ("GPT Protective", None),
        0xEF => ("EFI System", None),
        0x05 | 0x0F => ("Extended", None),
        0x85 => ("Linux Extended", None),
        _ => ("Unknown", None),
    }
}

/// Build a Partition artifact from an MBR/EBR entry. When `logical` is
/// `Some(container_index)` the entry is a logical partition and is tagged with
/// `logical:true` plus an `extended_container` back-reference.
#[allow(clippy::too_many_arguments)]
fn make_mbr_partition(
    artifact: &Artifact,
    parent_data: &Arc<dyn DataSource>,
    partition_id: serde_json::Value,
    sys: u8,
    boot: bool,
    starting_lba: u64,
    sectors: u64,
    sector_size: u64,
    logical: Option<usize>,
) -> Artifact {
    let size_bytes = sectors * sector_size;
    let offset_bytes = starting_lba * sector_size;
    let (type_name, subtype) = mbr_type_info(sys);

    let mut metadata = json!({
        "partition_scheme": "MBR",
        "partition_id": partition_id,
        "partition_type": format!("0x{:02X}", sys),
        "partition_type_name": type_name,
        "bootable": boot,
        "starting_lba": starting_lba,
        "sectors": sectors,
        "size_bytes": size_bytes,
        "offset_bytes": offset_bytes,
        "sector_size": sector_size,
    });
    let obj = metadata.as_object_mut().unwrap();
    if let Some(st) = subtype {
        obj.insert("subtype".to_string(), json!(st));
    }
    if let Some(container_idx) = logical {
        obj.insert("logical".to_string(), json!(true));
        obj.insert("extended_container".to_string(), json!(container_idx));
    }

    let window = Arc::new(WindowSource::new(
        Arc::clone(parent_data),
        offset_bytes,
        size_bytes,
    ));
    Artifact::new(
        artifact.case_id,
        ArtifactType::Partition,
        Some(window),
        metadata,
    )
    .with_parent(artifact.id)
}

/// Emit an UnallocatedSpace artifact for a gap, flagging sub-1MiB slack and the
/// trailing gap. Gaps below `MIN_GAP_BYTES` are dropped as noise.
#[allow(clippy::too_many_arguments)]
fn emit_gap(
    artifact: &Artifact,
    parent_data: &Arc<dyn DataSource>,
    start_lba: u64,
    length_lba: u64,
    sector_size: u64,
    gap_idx: usize,
    trailing: bool,
    // Index of the extended container this gap sits inside, when it is
    // inter-logical free space rather than a gap between primaries (B7-013).
    inside_extended: Option<usize>,
    out: &mut Vec<Artifact>,
) {
    let (gap_offset, gap_size) = match gap_extent(start_lba, length_lba, sector_size) {
        Some(v) => v,
        None => {
            warn!(
                "Skipping {}MBR gap {} with invalid geometry (start_lba {}, length_lba {})",
                if trailing { "trailing " } else { "" },
                gap_idx,
                start_lba,
                length_lba
            );
            return;
        }
    };
    if gap_size < MIN_GAP_BYTES {
        return;
    }

    info!(
        "Found {}unallocated space: offset 0x{:x}, size {} bytes",
        if trailing { "trailing " } else { "" },
        gap_offset,
        gap_size
    );
    let window = Arc::new(WindowSource::new(
        Arc::clone(parent_data),
        gap_offset,
        gap_size,
    ));
    let mut metadata = json!({
        "partition_scheme": "MBR",
        "gap_index": gap_idx,
        "offset_bytes": gap_offset,
        "size_bytes": gap_size,
        "sector_size": sector_size,
    });
    let obj = metadata.as_object_mut().unwrap();
    if trailing {
        obj.insert("trailing".to_string(), json!(true));
    }
    if gap_size < SMALL_GAP_BYTES {
        obj.insert("small_gap".to_string(), json!(true));
    }
    if let Some(container) = inside_extended {
        obj.insert("extended_container".to_string(), json!(container));
        obj.insert("inside_extended".to_string(), json!(true));
    }
    out.push(
        Artifact::new(
            artifact.case_id,
            ArtifactType::UnallocatedSpace,
            Some(window),
            metadata,
        )
        .with_parent(artifact.id),
    );
}

/// Walk the Extended Boot Record (EBR) linked list of an extended partition and
/// emit each logical partition as its own Partition artifact.
///
/// EBR relative addressing (standard):
///   * entry[0] describes the logical partition; its starting LBA is relative to
///     the *current* EBR sector.
///   * entry[1] links to the next EBR; its starting LBA is relative to the
///     *extended partition base* (the first EBR).
///
/// Guards against cycles (visited set), runaway chains (iteration cap) and
/// out-of-bounds offsets so a malformed image cannot loop or read past the disk.
///
/// Every one of those guards ends the chain early, and the logical partitions
/// linked after the stop are simply never emitted. That is recorded on the
/// artifacts, not only in the log: a truncated or hostile EBR chain otherwise
/// yields a partition map that presents as the whole disk layout (B3-020).
#[allow(clippy::too_many_arguments)]
fn walk_extended(
    artifact: &Artifact,
    parent_data: &Arc<dyn DataSource>,
    container_idx: usize,
    ext_base_lba: u64,
    ext_sectors: u64,
    sector_size: u64,
    logical_id: &mut u32,
    out: &mut Vec<Artifact>,
) -> Result<(), ModuleError> {
    const MAX_EBRS: usize = 1024;

    let disk_sectors = parent_data.size() / sector_size;
    let ext_end_lba = ext_base_lba.saturating_add(ext_sectors); // exclusive

    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut current_ebr = ext_base_lba;
    // Index of the first artifact this walk contributes, so the honesty flags
    // below land on the logical partitions of THIS container only.
    let first_logical_idx = out.len();
    // Why the chain ended short, if it did: `None` means the walk reached a
    // genuine end-of-chain link and the logical partition list is complete.
    // The tuple is (standard incompleteness reason, specific cause, detail) —
    // the standard reason is what cross-plugin filters read; the cause names
    // which guard fired.
    let mut stop: Option<(IncompleteReason, &'static str, String)> = None;
    // Entries that named a partition outside the container and were skipped.
    let mut out_of_bounds_entries: usize = 0;
    // Set when the walk reached a genuine end-of-chain link. Without it, a chain
    // that happens to be exactly MAX_EBRS links long and ends properly would be
    // reported as capped.
    let mut chain_ended = false;
    // Sectors inside the container that are accounted for: each EBR itself plus
    // every logical partition emitted. Anything left over is free space INSIDE
    // the extended container, which the primary gap scan cannot see because the
    // container occupies one contiguous "used" range there (B7-013).
    let mut inner_used: Vec<(u64, u64)> = Vec::new();

    for _ in 0..MAX_EBRS {
        // Cycle guard.
        if !visited.insert(current_ebr) {
            warn!("EBR chain cycle detected at LBA {}, stopping", current_ebr);
            stop = Some((
                IncompleteReason::UnresolvedStructure,
                "ebr_chain_cycle",
                format!("the EBR chain loops back to LBA {current_ebr}"),
            ));
            break;
        }
        // Bounds guard: each EBR must sit inside the extended container and on disk.
        if current_ebr < ext_base_lba || current_ebr >= ext_end_lba || current_ebr >= disk_sectors {
            warn!("EBR at LBA {} out of bounds, stopping", current_ebr);
            stop = Some((
                IncompleteReason::UnresolvedStructure,
                "ebr_out_of_bounds",
                format!(
                    "the next EBR link points to LBA {current_ebr}, outside the extended \
                     container ({ext_base_lba}..{ext_end_lba}) or past the end of the image \
                     ({disk_sectors} sectors)"
                ),
            ));
            break;
        }

        // Loop over short reads before deciding the chain is truncated: one
        // `read_at` returning 64 bytes is normal for a chunked source, and
        // treating it as the end of the chain drops every logical partition
        // after this point.
        let mut ebr = [0u8; 512];
        let n = read_full(parent_data.as_ref(), current_ebr * sector_size, &mut ebr);
        if n < 512 {
            warn!("Short read for EBR at LBA {}, stopping", current_ebr);
            stop = Some((
                IncompleteReason::ShortRead,
                "short_read",
                format!(
                    "the EBR at LBA {current_ebr} could not be read in full ({n} of 512 bytes)"
                ),
            ));
            break;
        }

        // Scan all four partition-table entries. Conventionally a logical
        // partition sits in entry[0] (relative to this EBR) and a link to the
        // next EBR in entry[1] (relative to the extended base), with the rest
        // zero. But hand-crafted tables (e.g. DFTT #1) put a second data
        // partition in entry[1] and the link in entry[2], so treat every
        // extended-type entry as a link and every other non-empty entry as a
        // logical partition rather than assuming fixed slots.
        // The EBR sector itself is metadata, not free space.
        inner_used.push((current_ebr, current_ebr.saturating_add(1)));

        let mut next_ebr: Option<u64> = None;
        for slot in 0..4 {
            let e = &ebr[446 + slot * 16..446 + slot * 16 + 16];
            let sys = e[4];
            let rel_start = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
            let sectors = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
            if sys == 0 {
                continue;
            }
            if is_extended(sys) {
                // A link entry: its start is relative to the extended base. Link
                // entries commonly carry a zero sector count, so don't require one.
                next_ebr.get_or_insert(ext_base_lba.saturating_add(rel_start));
                continue;
            }
            if sectors == 0 {
                continue; // empty data slot
            }
            // A logical partition: its start is relative to this EBR.
            let abs_start = current_ebr.saturating_add(rel_start);
            let end = abs_start.saturating_add(sectors); // exclusive
            if abs_start >= ext_base_lba && end <= ext_end_lba && end <= disk_sectors {
                info!(
                    "Found logical partition (id {}): Type 0x{:02X}, start LBA {}, {} sectors",
                    *logical_id, sys, abs_start, sectors
                );
                // Emitted as a Partition artifact identical to a primary, so the
                // FilesystemDetector module runs on it via its Partition subscription.
                out.push(make_mbr_partition(
                    artifact,
                    parent_data,
                    json!(*logical_id),
                    sys,
                    e[0] == 0x80,
                    abs_start,
                    sectors,
                    sector_size,
                    Some(container_idx),
                ));
                *logical_id += 1;
                inner_used.push((abs_start, end));
            } else {
                warn!(
                    "Logical partition at LBA {} out of container bounds, skipping",
                    abs_start
                );
                // A named partition dropped from the map. Counted so the map
                // cannot report itself as the complete layout (B3-020).
                out_of_bounds_entries += 1;
            }
        }

        match next_ebr {
            Some(next) if next != ext_base_lba => current_ebr = next,
            _ => {
                chain_ended = true;
                break;
            }
        }
    }

    if !chain_ended && stop.is_none() {
        warn!(
            "EBR chain reached the {} link cap at LBA {}, stopping",
            MAX_EBRS, current_ebr
        );
        stop = Some((
            IncompleteReason::CapReached,
            "ebr_link_cap",
            format!("the EBR chain reached the {MAX_EBRS} link parser cap"),
        ));
    }

    if stop.is_some() || out_of_bounds_entries > 0 {
        let emitted = out.len() - first_logical_idx;
        let (reason, cause, why) = stop.clone().unwrap_or_else(|| {
            (
                IncompleteReason::UnresolvedStructure,
                "logical_partition_out_of_bounds",
                format!(
                    "{out_of_bounds_entries} EBR table entry/entries named a partition outside \
                     the extended container and were not emitted"
                ),
            )
        });
        let reason = reason.as_str();
        // Every logical partition this walk did emit carries the fact, so a
        // partition exported on its own still says the map it came from is
        // short.
        for logical in out.iter_mut().skip(first_logical_idx) {
            if let Some(map) = logical.metadata.as_object_mut() {
                map.insert("inventory_incomplete".into(), json!(true));
                map.insert("inventory_incomplete_reason".into(), json!(reason));
            }
        }
        let detail = format!(
            "the extended partition at LBA {ext_base_lba} yielded {emitted} logical \
             partition(s) before the walk stopped: {why}; logical partitions linked after \
             that point are not in this partition map"
        );
        out.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "MbrExtendedChainIncomplete",
                    "subtype": "parse_incomplete",
                    "status": "ExtendedChainStoppedEarly",
                    "partition_scheme": "MBR",
                    "extended_container": container_idx,
                    "extended_base_lba": ext_base_lba,
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": reason,
                    "content_incomplete": true,
                    "content_incomplete_reason": reason,
                    "stop_cause": cause,
                    "ebrs_followed": visited.len(),
                    "logical_partitions_emitted": emitted,
                    "out_of_bounds_entries": out_of_bounds_entries,
                    "max_ebrs": MAX_EBRS,
                    "content_incomplete_detail": detail,
                    "inventory_incomplete_detail": detail,
                    "detail": detail,
                    "name": format!("MBR extended partition {container_idx}: incomplete — {detail}"),
                }),
            )
            .with_parent(artifact.id)
            .with_subtype("parse_incomplete"),
        );
    }

    // Free space between logical partitions is carvable evidence — deleted
    // logical volumes and hidden data live there — and it was never mapped
    // (B7-013). Only do this when the chain was walked to its genuine end: if
    // the walk stopped short, sectors we never accounted for are UNKNOWN, and
    // publishing them as unallocated space would assert something we did not
    // establish.
    if stop.is_none() {
        let container_end = ext_end_lba.min(disk_sectors);
        inner_used.sort_by_key(|r| r.0);
        let mut scan_from = ext_base_lba;
        let mut inner_gap_idx = 0usize;
        for &(start, end) in &inner_used {
            if start > scan_from {
                emit_gap(
                    artifact,
                    parent_data,
                    scan_from,
                    start - scan_from,
                    sector_size,
                    inner_gap_idx,
                    false,
                    Some(container_idx),
                    out,
                );
                inner_gap_idx += 1;
            }
            scan_from = scan_from.max(end);
        }
        if container_end > scan_from {
            emit_gap(
                artifact,
                parent_data,
                scan_from,
                container_end - scan_from,
                sector_size,
                inner_gap_idx,
                true,
                Some(container_idx),
                out,
            );
        }
    }

    Ok(())
}

/// Map a common GPT partition type GUID to a human-readable name.
fn gpt_type_name(guid: &uuid::Uuid) -> &'static str {
    match guid.to_string().to_uppercase().as_str() {
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft Reserved",
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft Basic Data",
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows Recovery",
        "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3" => "Windows LDM Metadata",
        "AF9B60A0-1431-4F62-BC68-3311714A69AD" => "Windows LDM Data",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux Filesystem",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux Swap",
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => "Linux LVM",
        "A19D880F-05FC-4D3B-A006-743F0F84911E" => "Linux RAID",
        "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" => "Linux Root (x86-64)",
        "933AC7E1-2EB4-4F13-B844-0E14E2AEF915" => "Linux Home",
        "7C3457EF-0000-11AA-AA11-00306543ECAC" => "Apple APFS",
        "48465300-0000-11AA-AA11-00306543ECAC" => "Apple HFS+",
        "55465300-0000-11AA-AA11-00306543ECAC" => "Apple UFS",
        "516E7CB4-6ECF-11D6-8FF8-00022D09712B" => "FreeBSD Data",
        "83BD6B9D-7F41-11DC-BE0B-001560B84F0F" => "FreeBSD Boot",
        "00000000-0000-0000-0000-000000000000" => "Unused",
        _ => "Unknown",
    }
}

// Filesystem Detector - processes Partition artifacts and emits FileSystem artifacts
impl ForensicsModule for FilesystemDetector {
    fn id(&self) -> &str {
        "plugin.disk.filesystem_detector"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Partition, ArtifactType::RawEvidence]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        debug!(
            "FilesystemDetector processing artifact ID: {} (type: {:?})",
            artifact.id, artifact.artifact_type
        );
        let mut produced_artifacts = Vec::new();

        // Get offset/size depending on artifact type
        let (offset_bytes, size_bytes) = match artifact.artifact_type {
            ArtifactType::Partition => {
                let offset = artifact
                    .metadata
                    .get("offset_bytes")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| {
                        ModuleError::InvalidInputFormat("Missing offset_bytes".to_string())
                    })?;
                let size = artifact
                    .metadata
                    .get("size_bytes")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| {
                        ModuleError::InvalidInputFormat("Missing size_bytes".to_string())
                    })?;
                (offset, size)
            }
            ArtifactType::RawEvidence => {
                let ds = artifact.data.as_ref().ok_or_else(|| {
                    ModuleError::InvalidInputFormat("RawEvidence requires data source".to_string())
                })?;
                (0u64, ds.size())
            }
            _ => return Ok(Vec::new()),
        };

        // Get the partition's data source
        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("Partition artifact requires a data source".to_string())
        })?;

        // Read filesystem signature area (first 4KB is usually sufficient).
        // Looped, and truncated to what was actually read: a zero tail from a
        // short read is not evidence of anything, and detecting a signature in
        // it (or failing to, because the bytes never arrived) decides whether
        // the filesystem is walked at all.
        let mut fs_header = vec![0u8; 4096.min(size_bytes as usize)];
        let got = read_full(data_source.as_ref(), 0, &mut fs_header);
        if got < fs_header.len() {
            warn!(
                "Partition {}: signature area read {} of {} bytes; \
                 detection covers only what was readable",
                artifact.id,
                got,
                fs_header.len()
            );
            fs_header.truncate(got);
        }

        // Detect *every* filesystem signature present, not just the first. A
        // partition carrying more than one is a hidden-filesystem (anti-forensic)
        // scenario, so surface all of them and warn — nothing stays invisible.
        let mut detected = detect_all_filesystem_types(&fs_header);

        // ISO9660's "CD001" descriptor (sector 16, 0x8001), the UFS1/UFS2
        // superblocks (8192/65536) and the Btrfs superblock (64 KiB, magic at
        // +0x40) live beyond the 4 KiB signature window.
        {
            // Looped reads: a single short `read_at` here would report "no
            // ISO9660 / no UFS / no Btrfs" for a filesystem that is present.
            let mut vd = [0u8; 8];
            if read_full(data_source.as_ref(), 0x8001, &mut vd) >= 5 && &vd[..5] == b"CD001" {
                detected.push("ISO9660");
            }
            // UFS fs_magic sits at superblock offset 1372.
            let mut m = [0u8; 4];
            if read_full(data_source.as_ref(), 8192 + 1372, &mut m) == 4
                && u32::from_le_bytes(m) == 0x0001_1954
            {
                detected.push("UFS1");
            }
            if read_full(data_source.as_ref(), 65536 + 1372, &mut m) == 4
                && u32::from_le_bytes(m) == 0x1954_0119
            {
                detected.push("UFS2");
            }
            // Btrfs: "_BHRfS_M" at +0x40 in each superblock copy. The primary
            // copy is at 64 KiB; the mirrors at 64 MiB and 256 GiB let a volume
            // whose primary superblock is damaged still be recognised (the
            // parser falls back to the same mirrors). Without this probe a
            // Btrfs volume produces no FileSystem artifact at all and the
            // parser — which gates on `subtype == "btrfs"` — never runs.
            if probe_btrfs(data_source.as_ref(), size_bytes) {
                detected.push("Btrfs");
            }
            // UDF (ECMA-167) announces itself in the Volume Recognition
            // Sequence, which shares sectors 16+ with ISO 9660's descriptors.
            if probe_udf_vrs(data_source.as_ref()) {
                detected.push("UDF");
            }
        }

        // A bare SquashFS image is walked by the SquashFS reader's own
        // `RawEvidence` subscription; handing it on as a FileSystem as well
        // would walk it twice. Inside a partition it is named (HUNT-174).
        if artifact.artifact_type == ArtifactType::RawEvidence {
            detected.retain(|fs| *fs != "SquashFS");
        }

        if detected.is_empty() {
            warn!(
                "Could not detect filesystem type for partition {}",
                artifact.id
            );
            return Ok(produced_artifacts);
        }

        // A UDF bridge disc (ISO 9660 and UDF structures on one volume, as
        // every Windows install ISO and most authored DVDs are) is the format
        // working as designed, not two filesystems hiding one another. The
        // pair is stamped `udf_bridge` and does not count toward overlap;
        // anything else found beside it still does. The two halves need not
        // list the same files (on the Windows 11 ISO the ISO 9660 half holds
        // only README.TXT) and nothing here compares them: a divergence
        // between the halves raises no signal of its own.
        let udf_bridge = detected.contains(&"ISO9660") && detected.contains(&"UDF");
        let overlap = detected.len() > if udf_bridge { 2 } else { 1 };
        if overlap {
            warn!(
                "Overlapping filesystems in partition {}: {} — possible anti-forensic \
                 hiding; surfacing all",
                artifact.id,
                detected.join(", ")
            );
        }

        // Resolve the evidence path once (forwarded to parsers that need it,
        // e.g. btrfs finding sibling device images of a multi-device volume).
        let evidence_path = ["path", "source_path", "container_path"]
            .iter()
            .find_map(|k| artifact.metadata.get(*k).and_then(|v| v.as_str()))
            .map(str::to_string);

        for (idx, detected_fs) in detected.iter().enumerate() {
            let is_primary = idx == 0;
            info!(
                "Detected {} filesystem in partition {}{}",
                detected_fs,
                artifact.id,
                if overlap && !is_primary {
                    " (overlapping/hidden)"
                } else {
                    ""
                }
            );

            let mut metadata = json!({
                "filesystem_type": detected_fs,
                "subtype": detected_fs.to_lowercase(),
                "offset_bytes": offset_bytes,
                "size_bytes": size_bytes,
                "partition_id": artifact.id.to_string(),
            });
            if let Some(ref p) = evidence_path {
                metadata["path"] = json!(p);
            }
            if udf_bridge && matches!(*detected_fs, "ISO9660" | "UDF") {
                metadata["udf_bridge"] = json!(true);
            }
            if overlap {
                // Every artifact in an overlap set names the full set and flags
                // it, so the UI can warn and the examiner sees the hidden
                // filesystem(s) rather than only the advertised one.
                metadata["filesystem_overlap"] = json!(true);
                metadata["overlapping_filesystems"] = json!(detected);
                if is_primary {
                    metadata["overlap_warning"] = json!(format!(
                        "This partition also carries a valid {} signature \
                         (overlapping filesystems — possible anti-forensic hiding).",
                        detected[1..].join(", ")
                    ));
                } else {
                    metadata["hidden"] = json!(true);
                    metadata["overlap_warning"] = json!(format!(
                        "Hidden {} filesystem overlapping the primary {} in this partition.",
                        detected_fs, detected[0]
                    ));
                }
            }

            let filesystem_artifact = Artifact::new(
                artifact.case_id,
                ArtifactType::FileSystem,
                Some(Arc::clone(data_source)),
                metadata,
            )
            .with_parent(artifact.id);
            produced_artifacts.push(filesystem_artifact);
        }

        Ok(produced_artifacts)
    }
}

/// Every filesystem signature present in the header window, in probe order.
///
/// More than one match means overlapping filesystems in the same partition —
/// a classic anti-forensic hiding technique (e.g. an NTFS volume whose bytes
/// also carry a valid ext2 superblock). The caller surfaces *all* of them and
/// warns, rather than returning only the first (which would hide the rest).
/// These signatures live at distinct, non-conflicting offsets, so a normal
/// single-filesystem volume matches exactly one.
fn detect_all_filesystem_types(header: &[u8]) -> Vec<&'static str> {
    let mut found = Vec::new();

    // NTFS / exFAT: OEM name at offset 3 (mutually exclusive content).
    if header.len() >= 11 {
        match &header[3..11] {
            b"NTFS    " => found.push("NTFS"),
            b"EXFAT   " => found.push("exFAT"),
            _ => {}
        }
    }

    // FAT32: "FAT32   " at offset 82
    if header.len() >= 90 && &header[82..90] == b"FAT32   " {
        found.push("FAT32");
    } else if is_fat32_sized_by_totsec64(header) {
        // HUNT-157: the same bytes carry a 64-bit sector count instead.
        found.push("FAT32");
    }
    // FAT16: "FAT16   " at offset 54
    if header.len() >= 62 && &header[54..62] == b"FAT16   " {
        found.push("FAT16");
    }
    // FAT12: "FAT12   " at offset 54
    if header.len() >= 62 && &header[54..62] == b"FAT12   " {
        found.push("FAT12");
    }

    // ext2/ext3/ext4: magic 0xEF53 (LE) at offset 0x438 (1080).
    if header.len() >= 1082 && u16::from_le_bytes([header[1080], header[1081]]) == 0xEF53 {
        found.push("ext4"); // ext2/3/4 share the magic; default to ext4
    }

    // F2FS (modern Android /data): superblock magic 0xF2F52010 (LE) at the
    // fixed superblock offset 1024.
    if header.len() >= 1028
        && u32::from_le_bytes([header[1024], header[1025], header[1026], header[1027]])
            == 0xF2F5_2010
    {
        found.push("F2FS");
    }

    // APFS: "NXSB" container superblock magic at offset 32.
    if header.len() >= 36 && &header[32..36] == b"NXSB" {
        found.push("APFS");
    }

    // HFS+ / HFSX: "H+" (0x482B) / "HX" (0x4858) in the volume header at 1024.
    if header.len() >= 1026 {
        match &header[1024..1026] {
            b"H+" => found.push("HFS+"),
            b"HX" => found.push("HFSX"),
            _ => {}
        }
    }

    // XFS: "XFSB" (big-endian 0x58465342) at offset 0 of the AG0 superblock,
    // which is the first sector of the partition. Without this the XFS parser
    // — which gates on `subtype == "xfs"` — is never handed a FileSystem
    // artifact, and an XFS volume silently yields an empty inventory.
    if header.len() >= 4 && &header[0..4] == b"XFSB" {
        found.push("XFS");
    }

    // SquashFS: "hsqs" at offset 0 of the superblock (HUNT-174). Any version
    // is named, so the reader can say which one it will not read rather than
    // the volume going unmentioned.
    if header.len() >= 4 && &header[0..4] == b"hsqs" {
        found.push("SquashFS");
    }

    found
}

/// A FAT32 boot sector whose sector count is carried in the non-standard
/// 64-bit field at offset 82, where the "FAT32   " type string otherwise sits:
/// the `dfir_ntfs` condition (FAT32-shaped BPB, 0x29 extended boot signature,
/// both standard counts zero) plus a nonzero count and the 0x55AA signature,
/// since without the type string nothing else vouches for the sector.
fn is_fat32_sized_by_totsec64(header: &[u8]) -> bool {
    if header.len() < 512 {
        return false;
    }
    let u16_at = |o: usize| u16::from_le_bytes([header[o], header[o + 1]]);
    let u32_at =
        |o: usize| u32::from_le_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]]);
    let bytes_per_sector = u16_at(11);
    header[510] == 0x55
        && header[511] == 0xAA
        && matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        && header[13].is_power_of_two()
        && u16_at(17) == 0 // root entries
        && u16_at(19) == 0 // 16-bit sector count
        && u16_at(22) == 0 // 16-bit FAT size
        && u32_at(32) == 0 // 32-bit sector count
        && u32_at(36) != 0 // 32-bit FAT size
        && header[66] == 0x29
        && header[82..90].iter().any(|b| *b != 0)
}

/// True when a Btrfs superblock copy is readable and carries the magic.
///
/// Btrfs puts `_BHRfS_M` at +0x40 in a superblock that starts at 64 KiB, well
/// outside the 4 KiB signature window every other in-band probe uses. The
/// 64 MiB and 256 GiB mirrors are probed too, and only when the partition is
/// large enough to contain them: reading past the end would say "not Btrfs"
/// for the same reason a short read would, and the two must not be confused.
fn probe_btrfs(source: &dyn DataSource, size_bytes: u64) -> bool {
    const BTRFS_SUPERBLOCK_OFFSETS: [u64; 3] = [0x1_0000, 0x400_0000, 0x40_0000_0000];
    const MAGIC_OFFSET: u64 = 0x40;
    const MAGIC: &[u8; 8] = b"_BHRfS_M";

    for base in BTRFS_SUPERBLOCK_OFFSETS {
        let at = base + MAGIC_OFFSET;
        if at + MAGIC.len() as u64 > size_bytes {
            continue;
        }
        let mut magic = [0u8; 8];
        if read_full(source, at, &mut magic) == MAGIC.len() && &magic == MAGIC {
            return true;
        }
    }
    false
}

/// True when the Volume Recognition Sequence (ECMA-167 2/8.3) declares a UDF
/// volume: a `BEA01` extended-area descriptor followed by an `NSR02` or `NSR03`
/// descriptor before the `TEA01` that closes the extended area.
///
/// The VRS starts at byte 32768, one descriptor per 2048 bytes (or per
/// sector on 4 KiB-sector media), and may begin with
/// ISO 9660's own `CD001` descriptors (a UDF bridge disc). An `NSR` outside a
/// BEA/TEA pair is not a recognition sequence and is not believed.
fn probe_udf_vrs(source: &dyn DataSource) -> bool {
    // ECMA-167 2/8.3: each descriptor starts a sector when sectors are larger
    // than 2048 bytes, so 4 KiB-sector media is walked in 4096-byte steps.
    // Detecting it lets the UDF reader read it (it finds the anchor at
    // 4096-byte sector 256) instead of the volume reading as "no filesystem".
    //
    // The 4096-byte walk is tried only when the 2048-byte slot after the
    // first descriptor is blank, as it is on 4 KiB-sector media; otherwise a
    // 2048-byte sequence read at every other descriptor could pair a BEA01
    // with an NSR that in fact follows the TEA01.
    if vrs_declares_udf(source, 2048) {
        return true;
    }
    let mut second = [0u8; 6];
    read_full(source, 32768 + 2048, &mut second) == 6
        && second[1..6] == [0u8; 5]
        && vrs_declares_udf(source, 4096)
}

fn vrs_declares_udf(source: &dyn DataSource, step: u64) -> bool {
    const VRS_START: u64 = 32768;
    // ECMA-167 bounds nothing here; 64 descriptors is far past any real VRS
    // (a bridge disc has a handful) and keeps a crafted image from a scan.
    const MAX_DESCRIPTORS: u64 = 64;
    let mut in_extended_area = false;
    for i in 0..MAX_DESCRIPTORS {
        let mut id = [0u8; 6];
        if read_full(source, VRS_START + i * step, &mut id) < 6 {
            return false;
        }
        match &id[1..6] {
            b"BEA01" => in_extended_area = true,
            b"NSR02" | b"NSR03" if in_extended_area => return true,
            b"TEA01" => in_extended_area = false,
            // ISO 9660 / ECMA-168 / boot descriptors may precede the
            // extended area; anything else ends the sequence (8.3.1).
            b"CD001" | b"CDW02" | b"BOOT2" => {}
            b"NSR02" | b"NSR03" => {}
            _ => return false,
        }
    }
    false
}

/// The primary (first) filesystem in the header window, if any. Test-only
/// single-signature helper; the production path uses the plural form so it can
/// surface overlapping/hidden filesystems.
#[cfg(test)]
fn detect_filesystem_type(header: &[u8]) -> Option<&'static str> {
    detect_all_filesystem_types(header).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    use seance_core::data_source::ByteSliceDataSource;

    fn make_raw_artifact(buf: Vec<u8>) -> Artifact {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(buf));
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            Some(src),
            json!({ "name": "disk.raw" }),
        )
    }

    // -- detect_filesystem_type fingerprints --------------------------------

    fn fs_header(magic_at: usize, magic: &[u8], len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        buf[magic_at..magic_at + magic.len()].copy_from_slice(magic);
        buf
    }

    #[test]
    fn detect_ntfs() {
        let h = fs_header(3, b"NTFS    ", 512);
        assert_eq!(detect_filesystem_type(&h), Some("NTFS"));
    }

    #[test]
    fn detect_fat32() {
        let h = fs_header(82, b"FAT32   ", 512);
        assert_eq!(detect_filesystem_type(&h), Some("FAT32"));
    }

    #[test]
    fn detect_fat16_and_fat12() {
        let h16 = fs_header(54, b"FAT16   ", 512);
        assert_eq!(detect_filesystem_type(&h16), Some("FAT16"));
        let h12 = fs_header(54, b"FAT12   ", 512);
        assert_eq!(detect_filesystem_type(&h12), Some("FAT12"));
    }

    #[test]
    fn detect_exfat() {
        let h = fs_header(3, b"EXFAT   ", 512);
        assert_eq!(detect_filesystem_type(&h), Some("exFAT"));
    }

    #[test]
    fn detect_ext_via_magic_at_0x438() {
        // ext superblock magic 0xEF53 (LE) at offset 1080.
        let mut h = vec![0u8; 2048];
        h[1080] = 0x53;
        h[1081] = 0xEF;
        assert_eq!(detect_filesystem_type(&h), Some("ext4"));
    }

    #[test]
    fn detect_apfs() {
        let h = fs_header(32, b"NXSB", 512);
        assert_eq!(detect_filesystem_type(&h), Some("APFS"));
    }

    #[test]
    fn detect_f2fs() {
        let mut h = vec![0u8; 2048];
        h[1024..1028].copy_from_slice(&0xF2F5_2010u32.to_le_bytes());
        assert_eq!(detect_filesystem_type(&h), Some("F2FS"));
    }

    #[test]
    fn detect_all_returns_every_signature_present() {
        // The DFTT #10 hidden-filesystem case: one partition's bytes carry both
        // an NTFS OEM name (offset 3) and a valid ext superblock magic (0x438).
        let mut buf = vec![0u8; 4096];
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[1080] = 0x53;
        buf[1081] = 0xEF;
        assert_eq!(detect_all_filesystem_types(&buf), vec!["NTFS", "ext4"]);
        // Back-compat single detect still returns the primary.
        assert_eq!(detect_filesystem_type(&buf), Some("NTFS"));
    }

    #[test]
    fn process_surfaces_and_flags_overlapping_filesystems() {
        let mut buf = vec![0u8; 4096];
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[1080] = 0x53;
        buf[1081] = 0xEF;
        let out = FilesystemDetector.process(&make_raw_artifact(buf)).unwrap();
        assert_eq!(out.len(), 2, "both filesystems must be surfaced");

        assert_eq!(out[0].metadata["filesystem_type"].as_str(), Some("NTFS"));
        assert_eq!(out[0].metadata["filesystem_overlap"].as_bool(), Some(true));
        assert_eq!(
            out[0].metadata["overlapping_filesystems"],
            json!(["NTFS", "ext4"])
        );
        assert!(out[0].metadata.get("hidden").is_none());

        assert_eq!(out[1].metadata["filesystem_type"].as_str(), Some("ext4"));
        assert_eq!(out[1].metadata["hidden"].as_bool(), Some(true));
        assert!(out[1].metadata["overlap_warning"].as_str().is_some());
    }

    /// A volume whose Volume Recognition Sequence descriptors (2048 bytes
    /// each, from sector 16) carry the given standard identifiers. Descriptor
    /// type 0x01 for CD001 (a primary VD), 0xFF for the terminator, 0 for the
    /// ECMA-167 extended-area descriptors.
    fn vrs_volume(idents: &[(u8, &[u8; 5])]) -> Vec<u8> {
        let mut buf = vec![0u8; 2048 * (16 + idents.len() + 4)];
        for (i, (ty, id)) in idents.iter().enumerate() {
            let at = 2048 * (16 + i);
            buf[at] = *ty;
            buf[at + 1..at + 6].copy_from_slice(*id);
            buf[at + 6] = 1;
        }
        buf
    }

    #[test]
    fn udf_bridge_disc_yields_iso_and_udf_without_hiding_warning() {
        let buf = vrs_volume(&[
            (1, b"CD001"),
            (255, b"CD001"),
            (0, b"BEA01"),
            (0, b"NSR02"),
            (0, b"TEA01"),
        ]);
        let out = FilesystemDetector.process(&make_raw_artifact(buf)).unwrap();
        let subtypes: Vec<&str> = out
            .iter()
            .map(|a| a.metadata["subtype"].as_str().unwrap())
            .collect();
        assert_eq!(subtypes, vec!["iso9660", "udf"]);
        for a in &out {
            assert_eq!(a.metadata["udf_bridge"].as_bool(), Some(true));
            assert!(a.metadata.get("hidden").is_none());
            assert!(a.metadata.get("overlap_warning").is_none());
            assert!(a.metadata.get("filesystem_overlap").is_none());
        }
    }

    #[test]
    fn pure_udf_volume_is_detected() {
        let buf = vrs_volume(&[(0, b"BEA01"), (0, b"NSR03"), (0, b"TEA01")]);
        let out = FilesystemDetector.process(&make_raw_artifact(buf)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["subtype"].as_str(), Some("udf"));
        assert!(out[0].metadata.get("udf_bridge").is_none());
    }

    #[test]
    fn udf_vrs_on_4k_sector_media_is_detected() {
        // ECMA-167 2/8.3: on media whose sectors are larger than 2048 bytes
        // each recognition descriptor starts its own sector. A 4 KiB-sector
        // volume must be named UDF (the reader then reads it at that sector
        // size), not read as "no filesystem".
        let idents: [&[u8; 5]; 3] = [b"BEA01", b"NSR03", b"TEA01"];
        let mut buf = vec![0u8; 32768 + 4096 * 8];
        for (i, id) in idents.iter().enumerate() {
            let at = 32768 + 4096 * i;
            buf[at + 1..at + 6].copy_from_slice(*id);
            buf[at + 6] = 1;
        }
        let out = FilesystemDetector.process(&make_raw_artifact(buf)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["subtype"].as_str(), Some("udf"));
    }

    #[test]
    fn nsr_outside_bea_tea_is_not_udf() {
        let buf = vrs_volume(&[(0, b"NSR02"), (0, b"TEA01")]);
        let out = FilesystemDetector.process(&make_raw_artifact(buf)).unwrap();
        assert!(
            out.is_empty(),
            "a stray NSR02 is not a recognition sequence"
        );
        // And an NSR after the TEA closes the area is not believed either.
        let buf = vrs_volume(&[(0, b"BEA01"), (0, b"TEA01"), (0, b"NSR02")]);
        let out = FilesystemDetector.process(&make_raw_artifact(buf)).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn process_single_filesystem_has_no_overlap_flag() {
        let mut buf = vec![0u8; 4096];
        buf[3..11].copy_from_slice(b"NTFS    ");
        let out = FilesystemDetector.process(&make_raw_artifact(buf)).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].metadata.get("filesystem_overlap").is_none());
    }

    #[test]
    fn detect_hfs_plus() {
        assert_eq!(
            detect_filesystem_type(&fs_header(1024, b"H+", 2048)),
            Some("HFS+")
        );
        assert_eq!(
            detect_filesystem_type(&fs_header(1024, b"HX", 2048)),
            Some("HFSX")
        );
    }

    #[test]
    fn detect_xfs_via_superblock_magic_at_zero() {
        // XFS AG0 superblock starts at the first byte of the partition.
        let h = fs_header(0, b"XFSB", 512);
        assert_eq!(detect_filesystem_type(&h), Some("XFS"));
    }

    #[test]
    fn process_emits_xfs_subtype_the_parser_gates_on() {
        // The XFS parser only runs when it is handed `subtype == "xfs"`, so a
        // detector that never names XFS makes the whole volume invisible.
        let mut buf = vec![0u8; 4096];
        buf[0..4].copy_from_slice(b"XFSB");
        let out = FilesystemDetector.process(&make_raw_artifact(buf)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["filesystem_type"].as_str(), Some("XFS"));
        assert_eq!(out[0].metadata["subtype"].as_str(), Some("xfs"));
    }

    /// Disk image carrying a Btrfs superblock magic at `base + 0x40`.
    fn btrfs_disk(base: u64) -> Vec<u8> {
        let end = (base + 0x40 + 8) as usize;
        let mut buf = vec![0u8; end];
        buf[(base as usize) + 0x40..end].copy_from_slice(b"_BHRfS_M");
        buf
    }

    #[test]
    fn process_emits_btrfs_subtype_from_64kib_superblock() {
        // Btrfs magic lives at 64 KiB + 0x40 — outside the 4 KiB signature
        // window, so only an explicit out-of-window probe can see it.
        let out = FilesystemDetector
            .process(&make_raw_artifact(btrfs_disk(0x1_0000)))
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["filesystem_type"].as_str(), Some("Btrfs"));
        assert_eq!(out[0].metadata["subtype"].as_str(), Some("btrfs"));
    }

    #[test]
    fn btrfs_probe_falls_back_to_64mib_mirror() {
        // Primary superblock wiped, 64 MiB mirror intact: still Btrfs.
        let mut disk = btrfs_disk(0x400_0000);
        disk[0x1_0000 + 0x40..0x1_0000 + 0x48].copy_from_slice(&[0u8; 8]);
        let src = ByteSliceDataSource::new(disk);
        assert!(probe_btrfs(&src, src.size()));
    }

    #[test]
    fn btrfs_probe_rejects_blank_and_short_volumes() {
        let blank = ByteSliceDataSource::new(vec![0u8; 0x2_0000]);
        assert!(!probe_btrfs(&blank, blank.size()));
        // Volume shorter than the primary superblock: absence of the magic is
        // absence of the bytes, and must not be read as "definitely Btrfs".
        let short = ByteSliceDataSource::new(vec![0u8; 4096]);
        assert!(!probe_btrfs(&short, short.size()));
    }

    #[test]
    fn detect_returns_none_on_blank() {
        let h = vec![0u8; 4096];
        assert_eq!(detect_filesystem_type(&h), None);
    }

    #[test]
    fn detect_short_buffer_does_not_panic() {
        assert_eq!(detect_filesystem_type(&[]), None);
        assert_eq!(detect_filesystem_type(&[0x00; 10]), None);
        assert_eq!(detect_filesystem_type(&[0x00; 60]), None);
    }

    // -- PartitionParser module behavior ------------------------------------

    #[test]
    fn module_identity() {
        let p = PartitionParser;
        assert_eq!(p.id(), "plugin.disk.partition_parser");
        assert_eq!(p.subscribes_to(), vec![ArtifactType::RawEvidence]);
        assert_eq!(p.input_capability(), InputCapability::RandomAccess);

        let d = FilesystemDetector;
        assert_eq!(d.id(), "plugin.disk.filesystem_detector");
        assert!(d.subscribes_to().contains(&ArtifactType::Partition));
        assert!(d.subscribes_to().contains(&ArtifactType::RawEvidence));
    }

    #[test]
    fn parser_requires_data_source() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            None,
            json!({ "name": "disk.raw" }),
        );
        match PartitionParser.process(&art) {
            Err(ModuleError::InvalidInputFormat(_)) => {}
            other => panic!("expected InvalidInputFormat, got {:?}", other),
        }
    }

    #[test]
    fn no_partition_table_produces_no_artifacts() {
        // 1MB of zeros — no MBR boot signature, no EFI PART magic.
        let art = make_raw_artifact(vec![0u8; 1024 * 1024]);
        let out = PartitionParser.process(&art).unwrap();
        assert!(out.is_empty());
    }

    /// Build a minimal valid MBR with one used partition entry.
    /// Returns a full disk image of `total_size` bytes.
    fn build_mbr_disk(
        total_size: usize,
        part_type: u8,
        starting_lba: u32,
        sectors: u32,
    ) -> Vec<u8> {
        let mut disk = vec![0u8; total_size];
        // MBR signature at 510/511
        disk[510] = 0x55;
        disk[511] = 0xAA;

        // Partition entry 1 at offset 446..462 (16 bytes per entry).
        let p = 446;
        disk[p] = 0x00; // not bootable
                        // CHS first (3 bytes) — left at 0
        disk[p + 4] = part_type;
        // CHS last (3 bytes) — left at 0
        // Starting LBA at p+8..p+12 (LE)
        disk[p + 8..p + 12].copy_from_slice(&starting_lba.to_le_bytes());
        // Sectors at p+12..p+16 (LE)
        disk[p + 12..p + 16].copy_from_slice(&sectors.to_le_bytes());

        disk
    }

    #[test]
    fn detects_mbr_with_single_partition() {
        // 16 MB disk: 1 partition starting at LBA 2048 (1 MiB offset), 8192 sectors (4 MiB).
        let disk = build_mbr_disk(16 * 1024 * 1024, 0x07, 2048, 8192);
        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();

        // Expect at least one Partition artifact for the entry.
        let partitions: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Partition)
            .collect();
        assert_eq!(partitions.len(), 1, "expected exactly one MBR partition");

        let p = partitions[0];
        assert_eq!(p.parent_id, Some(art.id));
        assert_eq!(
            p.metadata.get("partition_scheme").and_then(|v| v.as_str()),
            Some("MBR")
        );
        assert_eq!(
            p.metadata.get("starting_lba").and_then(|v| v.as_u64()),
            Some(2048)
        );
        assert_eq!(
            p.metadata.get("sectors").and_then(|v| v.as_u64()),
            Some(8192)
        );
        assert_eq!(
            p.metadata.get("offset_bytes").and_then(|v| v.as_u64()),
            Some(2048 * 512)
        );
        assert_eq!(
            p.metadata.get("size_bytes").and_then(|v| v.as_u64()),
            Some(8192 * 512)
        );
        // 0x07 → NTFS/exFAT (assigned subtype "ntfs" by the parser).
        assert_eq!(
            p.metadata
                .get("partition_type_name")
                .and_then(|v| v.as_str()),
            Some("NTFS/exFAT")
        );
        assert_eq!(
            p.metadata.get("subtype").and_then(|v| v.as_str()),
            Some("ntfs")
        );

        // The partition's data source must be sized to the partition window.
        let p_ds = p.data.as_ref().expect("partition needs data source");
        assert_eq!(p_ds.size(), 8192 * 512);
    }

    #[test]
    fn mbr_emits_unallocated_space_before_partition() {
        // Same fixture: partition starts at 1 MiB, so the gap from MBR (sector 1)
        // up to LBA 2048 is 1 MiB - 512 bytes, which is below MIN_UNALLOC_SIZE (1 MiB).
        // Verify: with a larger gap, an UnallocatedSpace artifact is emitted.
        // Place the partition further out: starting LBA 4096 (2 MiB offset).
        let disk = build_mbr_disk(32 * 1024 * 1024, 0x83, 4096, 8192);
        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();

        let gaps: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
            .collect();
        assert!(!gaps.is_empty(), "expected at least one unallocated gap");
        // The leading gap should cover sectors 1..4096 = 2 MiB - 512 bytes.
        let leading = gaps
            .iter()
            .find(|g| g.metadata.get("offset_bytes").and_then(|v| v.as_u64()) == Some(512))
            .expect("missing leading gap at offset 512");
        let size = leading
            .metadata
            .get("size_bytes")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(size, (4096 - 1) * 512);
    }

    #[test]
    fn mbr_skips_empty_partition_entries() {
        // All entries unused (no partition type set). MBR signature present.
        let mut disk = vec![0u8; 1024 * 1024];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        // Entries are all-zero → type byte 0 → treated as unused → no Partition artifacts.

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();
        let parts: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Partition)
            .collect();
        assert!(parts.is_empty(), "empty MBR should yield no partitions");
    }

    #[test]
    fn mbr_partition_type_mapping() {
        // 0x83 → Linux/linux subtype.
        let disk = build_mbr_disk(8 * 1024 * 1024, 0x83, 2048, 4096);
        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();
        let p = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::Partition)
            .expect("partition missing");
        assert_eq!(
            p.metadata
                .get("partition_type_name")
                .and_then(|v| v.as_str()),
            Some("Linux")
        );
        assert_eq!(
            p.metadata.get("subtype").and_then(|v| v.as_str()),
            Some("linux")
        );
        assert_eq!(
            p.metadata.get("partition_type").and_then(|v| v.as_str()),
            Some("0x83")
        );
    }

    #[test]
    fn mbr_two_primary_partitions_parse_to_correct_types() {
        // Two standard primaries via put_entry: bootable NTFS (0x07) then Linux
        // (0x83). The direct parser must yield exactly two partitions with the
        // right type bytes and carry the boot flag through.
        let mut disk = vec![0u8; 4 * 1024 * 1024];
        put_entry(&mut disk, 0, 0, 0x80, 0x07, 2048, 2048); // bootable NTFS
        put_entry(&mut disk, 0, 1, 0x00, 0x83, 4096, 2048); // Linux
        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();

        let parts: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Partition)
            .collect();
        assert_eq!(parts.len(), 2, "expected exactly two primary partitions");

        let types: Vec<&str> = parts
            .iter()
            .filter_map(|p| p.metadata.get("partition_type").and_then(|v| v.as_str()))
            .collect();
        assert!(types.contains(&"0x07"), "NTFS primary missing");
        assert!(types.contains(&"0x83"), "Linux primary missing");

        // The bootable flag comes from boot byte 0x80 (replacing BOOT_ACTIVE).
        let ntfs = parts
            .iter()
            .find(|p| p.metadata.get("partition_type").and_then(|v| v.as_str()) == Some("0x07"))
            .unwrap();
        assert_eq!(
            ntfs.metadata.get("bootable").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    /// HUNT-174: a real SquashFS image (`mksquashfs -comp gzip`, the squashfs
    /// crate's committed fixture) inside a partition window larger than the
    /// image is named, with the subtype the SquashFS reader gates on.
    #[test]
    fn filesystem_detector_names_squashfs_inside_a_partition() {
        let mut window =
            include_bytes!("../../seance_plugin_squashfs/tests/fixtures/tree.sqfs").to_vec();
        window.resize(window.len() + 64 * 1024, 0);
        let part = make_partition_artifact(Uuid::new_v4(), &window);
        let out = FilesystemDetector.process(&part).unwrap();
        assert_eq!(
            out.len(),
            1,
            "{:?}",
            out.iter().map(|a| &a.metadata).collect::<Vec<_>>()
        );
        assert_eq!(out[0].metadata["filesystem_type"], "SquashFS");
        assert_eq!(out[0].metadata["subtype"], "squashfs");
    }

    /// A bare SquashFS image is walked by the reader's own `RawEvidence`
    /// subscription; naming it here as well would walk it twice.
    #[test]
    fn filesystem_detector_leaves_a_bare_squashfs_image_to_its_reader() {
        let image =
            include_bytes!("../../seance_plugin_squashfs/tests/fixtures/tree.sqfs").to_vec();
        let out = FilesystemDetector
            .process(&make_raw_artifact(image))
            .unwrap();
        assert!(out.is_empty());
    }

    /// HUNT-157: a FAT32 volume sized only by the non-standard 64-bit count
    /// at offset 82 has no "FAT32   " string there. The boot sector here is
    /// the one `mkfs.fat -F 32` wrote, with its count moved into that field
    /// (the shape of `dfir_ntfs`'s `fat64.raw`).
    #[test]
    fn filesystem_detector_names_a_fat32_volume_sized_by_the_64_bit_count() {
        let mut bs = vec![0u8; 4096];
        bs[..90].copy_from_slice(&[
            0xeb, 0x58, 0x90, b'm', b'k', b'f', b's', b'.', b'f', b'a', b't', 0x00, 0x02, 0x01,
            0x20, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x29, 0x78, 0x56, 0x34,
            0x12, b'S', b'E', b'A', b'N', b'C', b'E', b'6', b'4', b' ', b' ', b' ', 0x00, 0x10,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        bs[510] = 0x55;
        bs[511] = 0xaa;
        let part = make_partition_artifact(Uuid::new_v4(), &bs);
        let out = FilesystemDetector.process(&part).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["filesystem_type"], "FAT32");
        // Without the 0x29 signature offset 82 is not a count, and the
        // volume is not claimed on its strength.
        bs[66] = 0x28;
        let part = make_partition_artifact(Uuid::new_v4(), &bs);
        assert!(FilesystemDetector.process(&part).unwrap().is_empty());
    }

    // -- FilesystemDetector behavior ----------------------------------------

    fn make_partition_artifact(case_id: Uuid, fs_header_bytes: &[u8]) -> Artifact {
        // Wrap fs_header_bytes in a ByteSliceDataSource exactly that size (so size_bytes lines up).
        let size = fs_header_bytes.len() as u64;
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(fs_header_bytes.to_vec()));
        Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(src),
            json!({
                "partition_scheme": "MBR",
                "offset_bytes": 0u64,
                "size_bytes": size,
            }),
        )
    }

    #[test]
    fn filesystem_detector_emits_filesystem_artifact_for_ntfs_partition() {
        let case_id = Uuid::new_v4();
        let header = fs_header(3, b"NTFS    ", 4096);
        let part = make_partition_artifact(case_id, &header);
        let out = FilesystemDetector.process(&part).unwrap();

        assert_eq!(out.len(), 1);
        let fs = &out[0];
        assert_eq!(fs.artifact_type, ArtifactType::FileSystem);
        assert_eq!(fs.parent_id, Some(part.id));
        assert_eq!(
            fs.metadata.get("filesystem_type").and_then(|v| v.as_str()),
            Some("NTFS")
        );
        assert_eq!(
            fs.metadata.get("subtype").and_then(|v| v.as_str()),
            Some("ntfs")
        );
    }

    #[test]
    fn filesystem_detector_returns_empty_for_unknown_partition() {
        let case_id = Uuid::new_v4();
        let header = vec![0u8; 4096];
        let part = make_partition_artifact(case_id, &header);
        let out = FilesystemDetector.process(&part).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn filesystem_detector_requires_offset_and_size_metadata_for_partition() {
        // Partition artifact missing offset_bytes/size_bytes → InvalidInputFormat.
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 4096]));
        let part = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(src),
            json!({ "partition_scheme": "MBR" }),
        );
        match FilesystemDetector.process(&part) {
            Err(ModuleError::InvalidInputFormat(_)) => {}
            other => panic!("expected InvalidInputFormat, got {:?}", other),
        }
    }

    #[test]
    fn filesystem_detector_accepts_raw_evidence() {
        // FilesystemDetector also accepts RawEvidence (no offset/size metadata required).
        let header = fs_header(82, b"FAT32   ", 4096);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(header));
        let raw = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            Some(src),
            json!({}),
        );
        let out = FilesystemDetector.process(&raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0]
                .metadata
                .get("filesystem_type")
                .and_then(|v| v.as_str()),
            Some("FAT32")
        );
    }

    #[test]
    fn filesystem_detector_ignores_unsupported_artifact_types() {
        // FileEntry artifact → silently returns empty (not in subscribes_to but
        // process() is defensive).
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 64]));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({}),
        );
        let out = FilesystemDetector.process(&art).unwrap();
        assert!(out.is_empty());
    }

    // -- Fixture helpers ----------------------------------------------------

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test_data")
            .join(name)
    }

    /// Write one MBR/EBR partition entry (and the boot signature) into `disk`.
    fn put_entry(
        disk: &mut [u8],
        sector: usize,
        entry_idx: usize,
        boot: u8,
        sys: u8,
        rel_lba: u32,
        sectors: u32,
    ) {
        let base = sector * 512 + 446 + entry_idx * 16;
        disk[base] = boot;
        disk[base + 4] = sys;
        disk[base + 8..base + 12].copy_from_slice(&rel_lba.to_le_bytes());
        disk[base + 12..base + 16].copy_from_slice(&sectors.to_le_bytes());
        disk[sector * 512 + 510] = 0x55;
        disk[sector * 512 + 511] = 0xAA;
    }

    /// Fuzz regression: a used partition with starting LBA 0 once drove the old
    /// third-party MBR crate's alignment calc into an `Option::unwrap()` on an
    /// empty range and panicked. The direct parser can't panic on this input, so
    /// process() returns cleanly. The test passing (no panic) is the assertion.
    #[test]
    fn malformed_mbr_alignment_does_not_panic() {
        let mut disk = vec![0u8; 512];
        put_entry(&mut disk, 0, 0, 0, 0x0C, 0, 1); // used (0x0C), rel_lba=0
        let art = make_raw_artifact(disk);
        let _ = PartitionParser.process(&art); // must not panic
    }

    // -- Extended-partition (EBR) walking -----------------------------------

    #[test]
    fn tsk_extended_partition_yields_logical() {
        // tsk_volume_system.raw: MBR primary 0x83 (LBA 1) + extended 0x05 (LBA 351,
        // 2529 sectors). Its single EBR at LBA 351 holds one logical 0x83 partition
        // at relative LBA 1 (absolute LBA 352), 2528 sectors, containing ext.
        if !fixture("tsk_volume_system.raw").exists() {
            eprintln!("skipping: tsk_volume_system.raw not present (gitignored corpus)");
            return;
        }
        let bytes = std::fs::read(fixture("tsk_volume_system.raw")).unwrap();
        let art = make_raw_artifact(bytes);
        let out = PartitionParser.process(&art).unwrap();

        let logical = out
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::Partition
                    && a.metadata.get("logical").and_then(|v| v.as_bool()) == Some(true)
            })
            .expect("expected a logical partition from the EBR walk");

        assert_eq!(
            logical.parent_id,
            Some(art.id),
            "logical parent is the data source"
        );
        assert_eq!(
            logical
                .metadata
                .get("offset_bytes")
                .and_then(|v| v.as_u64()),
            Some(352 * 512)
        );
        assert_eq!(
            logical.metadata.get("sectors").and_then(|v| v.as_u64()),
            Some(2528)
        );
        assert_eq!(
            logical.metadata.get("size_bytes").and_then(|v| v.as_u64()),
            Some(2528 * 512)
        );
        assert_eq!(
            logical
                .metadata
                .get("partition_type")
                .and_then(|v| v.as_str()),
            Some("0x83")
        );
        assert_eq!(
            logical
                .metadata
                .get("partition_scheme")
                .and_then(|v| v.as_str()),
            Some("MBR")
        );
        assert!(
            logical.metadata.get("extended_container").is_some(),
            "missing extended_container ref"
        );
        assert_eq!(
            logical.metadata.get("sector_size").and_then(|v| v.as_u64()),
            Some(512)
        );

        // FilesystemDetector runs on the logical partition exactly like a primary.
        let fs_out = FilesystemDetector.process(logical).unwrap();
        assert_eq!(
            fs_out.len(),
            1,
            "expected a filesystem inside the logical partition"
        );
        assert_eq!(
            fs_out[0]
                .metadata
                .get("filesystem_type")
                .and_then(|v| v.as_str()),
            Some("ext4")
        );
    }

    #[test]
    fn ebr_walk_emits_logical_with_correct_relative_offsets() {
        // Two logical partitions in a crafted extended container.
        // MBR: extended 0x05 at LBA 100, 200 sectors (ext_end = 300), disk = 400 sectors.
        // EBR@100: logical 0x83 rel 8 -> abs 108, 10 sectors; link -> EBR@150 (rel 50).
        // EBR@150: logical 0x83 rel 4 -> abs 154, 10 sectors; no link.
        let mut disk = vec![0u8; 400 * 512];
        put_entry(&mut disk, 0, 0, 0x00, 0x05, 100, 200); // primary extended container
        put_entry(&mut disk, 100, 0, 0x00, 0x83, 8, 10); // logical 1 (abs 108)
        put_entry(&mut disk, 100, 1, 0x00, 0x05, 50, 0); // link to LBA 150
        put_entry(&mut disk, 150, 0, 0x00, 0x83, 4, 10); // logical 2 (abs 154)
                                                         // EBR@150 entry 1 left empty -> end of chain.

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();

        let logicals: Vec<&Artifact> = out
            .iter()
            .filter(|a| {
                a.artifact_type == ArtifactType::Partition
                    && a.metadata.get("logical").and_then(|v| v.as_bool()) == Some(true)
            })
            .collect();
        assert_eq!(logicals.len(), 2, "expected two logical partitions");

        let offsets: Vec<u64> = logicals
            .iter()
            .map(|p| {
                p.metadata
                    .get("offset_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap()
            })
            .collect();
        assert!(
            offsets.contains(&(108 * 512)),
            "logical 1 abs offset (EBR-relative)"
        );
        assert!(
            offsets.contains(&(154 * 512)),
            "logical 2 abs offset (base-relative link)"
        );
    }

    #[test]
    fn ebr_cycle_is_guarded() {
        // Malformed chain: EBR@150 links to itself. The visited-set guard must stop
        // the walk instead of looping forever, while still emitting reachable logicals.
        let mut disk = vec![0u8; 400 * 512];
        put_entry(&mut disk, 0, 0, 0x00, 0x05, 100, 200); // extended container (ext_end 300)
        put_entry(&mut disk, 100, 0, 0x00, 0x83, 1, 10); // logical (abs 101)
        put_entry(&mut disk, 100, 1, 0x00, 0x05, 50, 0); // link -> LBA 150
        put_entry(&mut disk, 150, 0, 0x00, 0x83, 1, 10); // logical (abs 151)
        put_entry(&mut disk, 150, 1, 0x00, 0x05, 50, 0); // link -> LBA 150 (self-cycle)

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap(); // must terminate

        let logicals = out
            .iter()
            .filter(|a| {
                a.artifact_type == ArtifactType::Partition
                    && a.metadata.get("logical").and_then(|v| v.as_bool()) == Some(true)
            })
            .count();
        assert_eq!(
            logicals, 2,
            "cycle guard should emit each EBR's logical exactly once"
        );
    }

    /// Build a checksum-valid md v1 superblock with the given fields, via the RAID
    /// crate's shared `test-support` builder (enabled as a dev-dependency feature).
    fn md_superblock(
        level: u32,
        layout: u32,
        chunk_sectors: u32,
        disks: u32,
        size_sectors: u64,
    ) -> Vec<u8> {
        seance_container_raid::md::build_superblock(
            level as i32,
            layout,
            chunk_sectors,
            disks,
            size_sectors,
        )
    }

    /// A raw RAID member (Linux md v1.2 superblock, no partition table) must be
    /// surfaced as a RaidMember record pointing at the reconstruction commands,
    /// not silently reported as a structureless disk.
    #[test]
    fn a_raid_member_superblock_is_surfaced() {
        let mut disk = vec![0u8; 8192]; // no MBR/GPT signature (all zero)
        let sb = md_superblock(5, 2, 128, 4, 2048);
        disk[4096..4096 + sb.len()].copy_from_slice(&sb); // v1.2 offset

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();
        let rec = out
            .iter()
            .find(|a| a.metadata["type"] == json!("RaidMember"))
            .expect("a member with an md superblock must surface a RaidMember record");
        assert_eq!(rec.metadata["raid_level"], json!("Raid5"));
        assert_eq!(rec.metadata["raid_disks"], json!(4));
        assert_eq!(rec.metadata["chunk_bytes"], json!(128u64 * 512));
        assert_eq!(rec.metadata["superblock_offset"], json!(4096));
        assert!(rec.metadata["note"]
            .as_str()
            .unwrap()
            .contains("software-RAID"));
        assert!(rec.metadata["reconstruct_with"]
            .as_str()
            .unwrap()
            .contains("scan-raid"));
    }

    /// A v1.0 member keeps its superblock at the END of the device; detection
    /// must find it there, not only in the head.
    #[test]
    fn a_v1_0_end_of_device_member_is_surfaced() {
        let size = 1024 * 1024usize; // 1 MiB → 2048 sectors
        let mut disk = vec![0u8; size];
        let off = seance_container_raid::md::v10_superblock_offset(size as u64).unwrap() as usize;
        let sb = md_superblock(6, 2, 128, 5, 1024);
        disk[off..off + sb.len()].copy_from_slice(&sb);

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();
        let rec = out
            .iter()
            .find(|a| a.metadata["type"] == json!("RaidMember"))
            .expect("a v1.0 end-of-device superblock must be found");
        assert_eq!(rec.metadata["raid_level"], json!("Raid6"));
        assert_eq!(rec.metadata["superblock_offset"], json!(off));
    }

    /// A member whose superblock declares more usable data than the image holds
    /// must report the clamped size and flag the shortfall, never overstate it.
    #[test]
    fn a_truncated_member_reports_clamped_size() {
        let mut disk = vec![0u8; 8192]; // only 8 KiB captured
                                        // Superblock declares 1,000,000 sectors (~512 MB) of component data.
        let sb = md_superblock(5, 2, 128, 4, 1_000_000);
        disk[4096..4096 + sb.len()].copy_from_slice(&sb);
        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();
        let rec = out
            .iter()
            .find(|a| a.metadata["type"] == json!("RaidMember"))
            .unwrap();
        assert_eq!(rec.metadata["member_size_bytes"], json!(8192)); // clamped to image
        assert_eq!(
            rec.metadata["declared_member_size_bytes"],
            json!(1_000_000u64 * 512)
        );
        assert_eq!(rec.metadata["content_incomplete"], json!(true));
        // The reason is the canonical IncompleteReason identifier (round-trippable
        // by from_str), with the human explanation carried in the detail field.
        assert_eq!(
            rec.metadata["content_incomplete_reason"],
            json!(IncompleteReason::ShortRead.as_str())
        );
        assert!(rec.metadata["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("shorter than"));
    }

    /// A plain disk with no partition table and no superblock does not fabricate
    /// a RaidMember record.
    #[test]
    fn a_plain_disk_is_not_a_raid_member() {
        let art = make_raw_artifact(vec![0u8; 8192]);
        let out = PartitionParser.process(&art).unwrap();
        assert!(out
            .iter()
            .all(|a| a.metadata["type"] != json!("RaidMember")));
    }

    /// B3-020: the cycle guard used to stop the chain with a `warn!` and nothing
    /// else, so a hostile or corrupt EBR chain produced a partition map that
    /// presented as the disk's complete layout. What an examiner learns from the
    /// marker: the chain stopped early and partitions linked after it are not
    /// listed. A wrong answer looks like "this disk has two logical partitions"
    /// for a disk the parser never finished walking.
    #[test]
    fn ebr_cycle_records_inventory_incompleteness() {
        let mut disk = vec![0u8; 400 * 512];
        put_entry(&mut disk, 0, 0, 0x00, 0x05, 100, 200);
        put_entry(&mut disk, 100, 0, 0x00, 0x83, 1, 10);
        put_entry(&mut disk, 100, 1, 0x00, 0x05, 50, 0);
        put_entry(&mut disk, 150, 0, 0x00, 0x83, 1, 10);
        put_entry(&mut disk, 150, 1, 0x00, 0x05, 50, 0); // self-cycle

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();

        let marker = out
            .iter()
            .find(|a| a.metadata["type"] == json!("MbrExtendedChainIncomplete"))
            .expect("a chain stopped by the cycle guard must say so");
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(
            marker.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert_eq!(marker.metadata["stop_cause"], json!("ebr_chain_cycle"));
        assert_eq!(marker.metadata["logical_partitions_emitted"], json!(2));

        // The logical partitions that WERE emitted carry the fact too, so one
        // exported on its own still says its map is short.
        for logical in out.iter().filter(|a| {
            a.artifact_type == ArtifactType::Partition
                && a.metadata.get("logical").and_then(|v| v.as_bool()) == Some(true)
        }) {
            assert_eq!(logical.metadata["inventory_incomplete"], json!(true));
        }
    }

    /// B3-020 control: a chain that ends properly must carry no marker, so an
    /// unmarked partition map really does mean the walk saw the whole chain.
    #[test]
    fn complete_ebr_chain_carries_no_incompleteness_marker() {
        let mut disk = vec![0u8; 400 * 512];
        put_entry(&mut disk, 0, 0, 0x00, 0x05, 100, 200);
        put_entry(&mut disk, 100, 0, 0x00, 0x83, 8, 10);
        put_entry(&mut disk, 100, 1, 0x00, 0x05, 50, 0);
        put_entry(&mut disk, 150, 0, 0x00, 0x83, 4, 10);

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();

        assert!(
            !out.iter()
                .any(|a| a.metadata["type"] == json!("MbrExtendedChainIncomplete")),
            "a complete chain must not be reported as incomplete"
        );
        assert!(out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Partition)
            .all(|a| a.metadata.get("inventory_incomplete").is_none()));
    }

    /// B3-020: an EBR link pointing outside the extended container drops every
    /// partition after it. That is a truncated map, not a complete one.
    #[test]
    fn ebr_link_out_of_bounds_records_incompleteness() {
        let mut disk = vec![0u8; 400 * 512];
        put_entry(&mut disk, 0, 0, 0x00, 0x05, 100, 200); // container 100..300
        put_entry(&mut disk, 100, 0, 0x00, 0x83, 8, 10);
        put_entry(&mut disk, 100, 1, 0x00, 0x05, 250, 0); // link -> LBA 350, past ext_end

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();

        let marker = out
            .iter()
            .find(|a| a.metadata["type"] == json!("MbrExtendedChainIncomplete"))
            .expect("an out-of-bounds EBR link must be recorded");
        assert_eq!(marker.metadata["stop_cause"], json!("ebr_out_of_bounds"));
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    }

    // -- GPT entries the map could not place --------------------------------

    /// CRC-32/ISO-HDLC, the checksum both GPT structures carry. Written out
    /// here so the fixture below needs no dependency the crate does not already
    /// have; the `gpt` crate rejects a header or an entry array whose checksum
    /// does not match, so a fixture cannot skip it.
    fn crc32_iso_hdlc(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                let mask = if crc & 1 != 0 { 0xEDB8_8320u32 } else { 0 };
                crc = (crc >> 1) ^ mask;
            }
        }
        !crc
    }

    /// A 64-sector, 512-byte-sector GPT disk whose entry array holds `entries`
    /// as `(first_lba, last_lba)` pairs, with both CRCs correct so the `gpt`
    /// crate parses it.
    fn gpt_image(entries: &[(u64, u64)]) -> Vec<u8> {
        const SECTORS: u64 = 64;
        const NUM_PARTS: usize = 4;
        let mut disk = vec![0u8; SECTORS as usize * 512];
        // Protective MBR signature, as every real GPT disk carries.
        disk[510] = 0x55;
        disk[511] = 0xAA;

        // Entry array at LBA 2 (one sector holds four 128-byte slots).
        let table_off = 2 * 512;
        for (i, &(first, last)) in entries.iter().enumerate() {
            let e = table_off + i * 128;
            // A zeroed slot is "unused"; any non-zero type GUID makes it a
            // partition the table names.
            disk[e..e + 16].copy_from_slice(&[0x0F; 16]);
            disk[e + 16..e + 32].copy_from_slice(&[(i as u8) + 1; 16]);
            disk[e + 32..e + 40].copy_from_slice(&first.to_le_bytes());
            disk[e + 40..e + 48].copy_from_slice(&last.to_le_bytes());
        }
        let table_crc = crc32_iso_hdlc(&disk[table_off..table_off + NUM_PARTS * 128]);

        let h = 512; // LBA 1
        disk[h..h + 8].copy_from_slice(b"EFI PART");
        disk[h + 8..h + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
        disk[h + 12..h + 16].copy_from_slice(&92u32.to_le_bytes()); // header size
                                                                    // header CRC stays zero while it is computed
        disk[h + 24..h + 32].copy_from_slice(&1u64.to_le_bytes()); // current_lba
        disk[h + 32..h + 40].copy_from_slice(&(SECTORS - 1).to_le_bytes()); // backup_lba
        disk[h + 40..h + 48].copy_from_slice(&3u64.to_le_bytes()); // first_usable
        disk[h + 48..h + 56].copy_from_slice(&(SECTORS - 2).to_le_bytes()); // last_usable
        disk[h + 56..h + 72].copy_from_slice(&[0xAB; 16]); // disk GUID
        disk[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes()); // part_start
        disk[h + 80..h + 84].copy_from_slice(&(NUM_PARTS as u32).to_le_bytes());
        disk[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // part_size
        disk[h + 88..h + 92].copy_from_slice(&table_crc.to_le_bytes());
        let header_crc = crc32_iso_hdlc(&disk[h..h + 92]);
        disk[h + 16..h + 20].copy_from_slice(&header_crc.to_le_bytes());

        disk
    }

    /// A GPT disk whose ENTRY-ARRAY CRC is deliberately wrong, with the header
    /// CRC still correct — the shape real evidence takes.
    fn gpt_image_with_bad_entry_crc(entries: &[(u64, u64)]) -> Vec<u8> {
        let mut disk = gpt_image(entries);
        // Corrupt the stored entry-array CRC, then recompute the header CRC so
        // the header itself still verifies. That is what the CFTT image looks
        // like: header CRC good, entry CRC bad.
        let h = 512;
        disk[h + 88..h + 92].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        disk[h + 16..h + 20].copy_from_slice(&[0, 0, 0, 0]);
        let header_crc = crc32_iso_hdlc(&disk[h..h + 92]);
        disk[h + 16..h + 20].copy_from_slice(&header_crc.to_le_bytes());
        disk
    }

    /// **A GPT whose entry-array CRC does not verify must still yield its
    /// partitions**, and every one of them must say the check failed.
    ///
    /// Found by running NIST CFTT's Forensic String Search methodology
    /// (`ROADMAP` §5.2) against `ss-win-07-25-18.dd`: the whole 2,098,028,544-byte
    /// image produced **one** artifact — the evidence root — because the GPT
    /// was refused outright with "partition table CRC mismatch". Measured on
    /// that image: the header CRC matches (`0x6e47e4e5`) and the entry-array
    /// CRC does not (declared `0xf87a9ff9`, computed `0x11726dec`). `mmls`
    /// reads its four partitions regardless, and so does a by-hand decode of
    /// the entry array.
    ///
    /// A failed integrity check is a fact to report, not a reason to report
    /// nothing: a CRC mismatch is what carved, truncated and deliberately
    /// damaged evidence looks like, and refusing the table turns a readable
    /// disk into silence. **"Could not verify" is not "not there"** — the same
    /// invariant this codebase is written around.
    #[test]
    fn a_gpt_whose_entry_crc_fails_still_yields_its_partitions_and_says_so() {
        let art = make_raw_artifact(gpt_image_with_bad_entry_crc(&[(8, 15), (20, 30)]));
        let out = PartitionParser.process(&art).unwrap();

        let partitions: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Partition)
            .collect();
        assert_eq!(
            partitions.len(),
            2,
            "both entries are readable; the CRC says the table may have changed, not that it \
             holds nothing"
        );

        // Every partition carries the failed check, so one exported on its own
        // still says its map was unverified.
        for p in &partitions {
            assert_eq!(
                p.metadata["partition_table_verified"],
                json!(false),
                "got {:?}",
                p.metadata
            );
            let why = p.metadata["partition_table_integrity"]
                .as_str()
                .expect("the reason rides on the partition");
            assert!(
                why.contains("CRC") && why.contains("not verif"),
                "got {why}"
            );
            assert_eq!(
                p.metadata["content_incomplete_reason"],
                json!("unvalidated"),
                "the bytes were read; what could not be established is their integrity"
            );
        }

        // And a record of the table itself, with both digests so a reader can
        // check the claim rather than take it.
        let marker = out
            .iter()
            .find(|a| a.metadata["type"] == json!("GptPartitionTableUnverified"))
            .expect("the failed check is a record of its own");
        assert_eq!(marker.metadata["header_crc_verified"], json!(true));
        assert_eq!(marker.metadata["entries_crc_verified"], json!(false));
        assert_eq!(
            marker.metadata["entries_crc_declared"],
            json!(format!("0x{:08x}", 0xDEAD_BEEFu32))
        );
        assert!(marker.metadata["entries_crc_computed"].is_string());
        assert_eq!(marker.metadata["partitions_emitted"], json!(2));
        assert_eq!(
            marker.metadata["content_incomplete_reason"],
            json!("unvalidated")
        );
    }

    /// The control: a sound table says nothing about an unverified one.
    #[test]
    fn a_sound_gpt_table_is_not_reported_as_unverified() {
        let art = make_raw_artifact(gpt_image(&[(8, 15), (20, 30)]));
        let out = PartitionParser.process(&art).unwrap();
        assert!(
            !out.iter()
                .any(|a| a.metadata["type"] == json!("GptPartitionTableUnverified")),
            "a table that verified must not be reported as unverified"
        );
        assert!(
            out.iter()
                .filter(|a| a.artifact_type == ArtifactType::Partition)
                .all(|a| a.metadata.get("partition_table_verified").is_none()),
            "and its partitions carry no such field at all"
        );
    }

    /// **A header CRC that does not verify is a louder statement**, because the
    /// header is what says where the entry array is and how big it is. The
    /// entries are still decoded — from the header's own figures, which is all
    /// there is — and the record says both checks failed.
    #[test]
    fn a_gpt_whose_header_crc_also_fails_is_decoded_and_says_both_failed() {
        let mut disk = gpt_image(&[(8, 15), (20, 30)]);
        let h = 512;
        // Corrupt the header CRC only, leaving the entry array's own CRC
        // correct.
        disk[h + 16..h + 20].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();

        assert_eq!(
            out.iter()
                .filter(|a| a.artifact_type == ArtifactType::Partition)
                .count(),
            2,
            "the entries are where the header says they are, and they read"
        );
        let marker = out
            .iter()
            .find(|a| a.metadata["type"] == json!("GptPartitionTableUnverified"))
            .expect("recorded");
        assert_eq!(marker.metadata["header_crc_verified"], json!(false));
        let why = marker.metadata["detail"].as_str().unwrap_or("");
        assert!(
            why.contains("header") && why.contains("where the entry array is"),
            "a bad header CRC undermines the figures the decode itself used: {why}"
        );
    }

    /// A file with the signature and an entry array outside the image is
    /// refused, with the reason — decoding past the end would invent
    /// partitions.
    #[test]
    fn a_gpt_whose_entry_array_lies_outside_the_image_is_refused_with_the_reason() {
        let mut disk = gpt_image(&[(8, 15)]);
        let h = 512;
        // Entry array at LBA 1,000,000, far past a 64-sector disk.
        disk[h + 72..h + 80].copy_from_slice(&1_000_000u64.to_le_bytes());
        disk[h + 16..h + 20].copy_from_slice(&[0, 0, 0, 0]);
        let header_crc = crc32_iso_hdlc(&disk[h..h + 92]);
        disk[h + 16..h + 20].copy_from_slice(&header_crc.to_le_bytes());
        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap_or_default();
        assert!(
            !out.iter()
                .any(|a| a.artifact_type == ArtifactType::Partition),
            "decoding past the end of the image would invent partitions"
        );
    }

    /// B3-020 (swept to GPT): a GPT entry whose geometry will not resolve was
    /// skipped on a `warn!`, so a four-entry table rendered as a three-partition
    /// disk with nothing to say a partition was lost. What an examiner learns
    /// from the marker: the table names more partitions than the map shows.
    #[test]
    fn a_gpt_entry_with_unresolvable_geometry_records_incompleteness() {
        // Entry 1 is sound; entry 2 has last_lba < first_lba, which describes no
        // extent, so `gpt_partition_extent` yields None and the entry is skipped.
        let art = make_raw_artifact(gpt_image(&[(8, 15), (40, 20)]));
        let out = PartitionParser.process(&art).unwrap();

        let partitions: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Partition)
            .collect();
        assert_eq!(partitions.len(), 1, "only the sound entry can be placed");

        let marker = out
            .iter()
            .find(|a| a.metadata["type"] == json!("GptPartitionTableIncomplete"))
            .expect("a GPT entry dropped from the map must be recorded");
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(
            marker.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert_eq!(marker.metadata["invalid_geometry_entries"], json!(1));
        assert_eq!(marker.metadata["partitions_emitted"], json!(1));

        // The partition that WAS placed says its map is short, so exporting it
        // alone still carries the fact.
        assert_eq!(partitions[0].metadata["inventory_incomplete"], json!(true));
    }

    /// B3-020 control: every entry resolves, so nothing may claim the GPT map is
    /// short — otherwise the marker means nothing.
    #[test]
    fn a_sound_gpt_table_carries_no_incompleteness_marker() {
        let art = make_raw_artifact(gpt_image(&[(8, 15), (20, 30)]));
        let out = PartitionParser.process(&art).unwrap();

        assert!(
            !out.iter()
                .any(|a| a.metadata["type"] == json!("GptPartitionTableIncomplete")),
            "a sound GPT table must not be reported as incomplete"
        );
        assert!(out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Partition)
            .all(|a| a.metadata.get("inventory_incomplete").is_none()));
    }

    // -- Sector size --------------------------------------------------------

    #[test]
    fn detect_gpt_sector_size_512_and_4096() {
        let mut buf512 = vec![0u8; 4096];
        buf512[512..520].copy_from_slice(b"EFI PART");
        assert_eq!(
            detect_gpt_sector_size(&ByteSliceDataSource::new(buf512)).unwrap(),
            Some(512)
        );

        let mut buf4k = vec![0u8; 8192];
        buf4k[4096..4104].copy_from_slice(b"EFI PART");
        assert_eq!(
            detect_gpt_sector_size(&ByteSliceDataSource::new(buf4k)).unwrap(),
            Some(4096)
        );

        assert_eq!(
            detect_gpt_sector_size(&ByteSliceDataSource::new(vec![0u8; 8192])).unwrap(),
            None
        );
    }

    use seance_core::test_support::DribbleSource;

    #[test]
    fn a_chunked_source_does_not_hide_a_valid_partition_table() {
        // B2-036: one `read_at` can return fewer bytes than requested. Reading
        // the MBR and the GPT signature in a single shot made a perfectly valid
        // disk behind a chunked source look unpartitioned — an empty partition
        // map and no filesystem walk at all.
        let mut disk = vec![0u8; 8192];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        disk[512..520].copy_from_slice(b"EFI PART");
        let ds = DribbleSource::new(disk, 4);
        assert_eq!(
            detect_gpt_sector_size(&ds).unwrap(),
            Some(512),
            "the GPT signature must be found even when reads dribble in"
        );
    }

    #[test]
    fn a_truncated_disk_errors_instead_of_reporting_no_partition_table() {
        // The source claims 8 KiB but delivers 600 bytes: the 4Kn probe cannot
        // be answered. "Could not read" must not render as "no GPT here".
        #[derive(Debug)]
        struct Truncated;
        impl DataSource for Truncated {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
                let off = offset as usize;
                if off >= 600 {
                    return Ok(0);
                }
                let n = buf.len().min(600 - off);
                for b in buf[..n].iter_mut() {
                    *b = 0;
                }
                Ok(n)
            }
            fn size(&self) -> u64 {
                8192
            }
        }
        assert!(
            detect_gpt_sector_size(&Truncated).is_err(),
            "an unreadable signature must fail closed"
        );
    }

    #[test]
    fn gpt_partition_extent_is_panic_safe_on_hostile_geometry() {
        // Valid inclusive range LBA 34..=41 -> 8 sectors; matches the original
        // `(last_lba - first_lba + 1) * sector_size` expression exactly.
        assert_eq!(gpt_partition_extent(34, 41, 512), Some((34 * 512, 8 * 512)));
        // Single-sector partition (first_lba == last_lba) -> 1 sector.
        assert_eq!(gpt_partition_extent(40, 40, 512), Some((40 * 512, 512)));
        // last_lba < first_lba: a raw subtraction would underflow-panic in debug;
        // the checked helper yields None so the caller skips the partition.
        assert_eq!(gpt_partition_extent(100, 50, 512), None);
        // Huge last_lba overflows the size multiply -> None (no panic).
        assert_eq!(gpt_partition_extent(0, u64::MAX, 4096), None);
        // Huge first_lba overflows the offset multiply -> None (no panic).
        assert_eq!(gpt_partition_extent(u64::MAX, u64::MAX, 512), None);
    }

    #[test]
    fn gap_extent_skips_on_overflow() {
        // Normal geometry resolves to byte offset/size.
        assert_eq!(gap_extent(100, 8, 512), Some((100 * 512, 8 * 512)));
        // Huge start_lba overflows the offset multiply -> None (gap skipped).
        assert_eq!(gap_extent(u64::MAX, 1, 512), None);
        // Huge length_lba overflows the size multiply -> None (gap skipped).
        assert_eq!(gap_extent(0, u64::MAX, 4096), None);
    }

    #[test]
    fn gpt_4kn_detects_sector_size_4096() {
        use gpt::disk::LogicalBlockSize;
        use std::io::Cursor;

        // Craft a real 4Kn GPT (valid CRC32s) via the gpt writer over an in-memory device.
        let total = 4096 * 256; // 1 MiB, 256 x 4096-byte sectors
        let cursor = Cursor::new(vec![0u8; total]);
        let mut disk = gpt::GptConfig::new()
            .writable(true)
            .logical_block_size(LogicalBlockSize::Lb4096)
            .create_from_device(cursor, None)
            .unwrap();
        disk.add_partition("linux", 4096 * 16, gpt::partition_types::LINUX_FS, 0, None)
            .unwrap();
        let cursor = disk.write().unwrap();
        let bytes = cursor.into_inner();

        let art = make_raw_artifact(bytes);
        let out = PartitionParser.process(&art).unwrap();

        let part = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::Partition)
            .expect("expected a GPT partition");
        assert_eq!(
            part.metadata
                .get("partition_scheme")
                .and_then(|v| v.as_str()),
            Some("GPT")
        );
        assert_eq!(
            part.metadata.get("sector_size").and_then(|v| v.as_u64()),
            Some(4096)
        );
        assert_eq!(
            part.metadata
                .get("partition_type_name")
                .and_then(|v| v.as_str()),
            Some("Linux Filesystem")
        );
        // Offsets/sizes must use the 4096-byte sector size.
        let off = part
            .metadata
            .get("offset_bytes")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(off % 4096, 0, "offset must be a 4Kn sector multiple");
        assert!(off >= 4096, "partition must start beyond the GPT header");
    }

    #[test]
    fn gpt_single_fixture_detected_as_512_not_4kn() {
        // gpt_single.dd is a 512-byte GPT image ("EFI PART" at 0x200). Detection must
        // report 512, never mistake it for 4Kn. (This TSK fixture has a deliberately
        // malformed header the strict `gpt` crate rejects on full parse, so we assert
        // the sector-size layer only.)
        if !fixture("gpt_single.dd").exists() {
            eprintln!("skipping: gpt_single.dd not present (gitignored corpus)");
            return;
        }
        let bytes = std::fs::read(fixture("gpt_single.dd")).unwrap();
        assert_eq!(
            detect_gpt_sector_size(&ByteSliceDataSource::new(bytes)).unwrap(),
            Some(512)
        );
    }

    // -- Small unallocated gaps ---------------------------------------------

    #[test]
    fn mbr_dual_small_gaps_flagged() {
        // mbr_dual.dd: primary NTFS at LBA 63 (50 sectors) + FAT32 at LBA 120
        // (60 sectors) on a 200-sector disk. The classic sub-1MiB pre-partition gap
        // (sectors 1..63) must now be represented and flagged small_gap.
        if !fixture("mbr_dual.dd").exists() {
            eprintln!("skipping: mbr_dual.dd not present (gitignored corpus)");
            return;
        }
        let bytes = std::fs::read(fixture("mbr_dual.dd")).unwrap();
        let art = make_raw_artifact(bytes);
        let out = PartitionParser.process(&art).unwrap();

        let parts = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Partition)
            .count();
        assert_eq!(parts, 2, "two primary partitions expected");

        let gaps: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
            .collect();

        let leading = gaps
            .iter()
            .find(|g| g.metadata.get("offset_bytes").and_then(|v| v.as_u64()) == Some(512))
            .expect("missing the classic pre-partition gap at offset 512");
        assert_eq!(
            leading.metadata.get("size_bytes").and_then(|v| v.as_u64()),
            Some(62 * 512)
        );
        assert_eq!(
            leading.metadata.get("small_gap").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            leading.metadata.get("sector_size").and_then(|v| v.as_u64()),
            Some(512)
        );

        // The inter-partition slack (sectors 113..120) is also a small gap.
        assert!(
            gaps.iter().any(|g| g.metadata.get("offset_bytes").and_then(|v| v.as_u64()) == Some(113 * 512)),
            "inter-partition slack gap missing"
        );
    }

    #[test]
    fn large_gap_not_flagged_small() {
        // A >1MiB gap must NOT carry small_gap.
        let disk = build_mbr_disk(32 * 1024 * 1024, 0x83, 4096, 8192);
        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();
        let leading = out
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::UnallocatedSpace
                    && a.metadata.get("offset_bytes").and_then(|v| v.as_u64()) == Some(512)
            })
            .expect("leading gap missing");
        assert!(
            leading.metadata.get("small_gap").is_none(),
            "large gap wrongly flagged small_gap"
        );
    }

    #[test]
    fn walks_extended_with_nonstandard_entry_layout() {
        // 1 primary + an extended container. The first EBR has a logical in
        // entry[0], a SECOND logical in entry[1] (not a link), and the link in
        // entry[2] -- the DFTT #1 hand-crafted case. A second EBR holds a third
        // logical. Expect 4 partitions (1 primary + 3 logical), no 0x05 container.
        let mut disk = vec![0u8; 2 * 1024 * 1024];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        put_entry(&mut disk, 0, 0, 0, 0x04, 1, 100); // primary FAT16 @ LBA 1
        put_entry(&mut disk, 0, 1, 0, 0x05, 200, 1000); // extended container, base LBA 200
                                                        // EBR @200 (sector 200); put_entry writes the 0x55AA sig for the sector.
        put_entry(&mut disk, 200, 0, 0, 0x06, 10, 50); // logical @ 210
        put_entry(&mut disk, 200, 1, 0, 0x04, 100, 50); // logical @ 300 (data, not a link)
        put_entry(&mut disk, 200, 2, 0, 0x05, 400, 50); // link -> EBR @ 600 (ext_base+400)
                                                        // EBR @600
        put_entry(&mut disk, 600, 0, 0, 0x06, 10, 50); // logical @ 610

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();
        let parts: Vec<_> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::Partition)
            .collect();
        assert_eq!(parts.len(), 4, "expected 1 primary + 3 logical partitions");
        assert!(
            parts
                .iter()
                .all(|p| p.metadata.get("partition_type").and_then(|v| v.as_str()) != Some("0x05")),
            "the extended container must not be emitted as a partition"
        );
    }

    /// Free space BETWEEN logical partitions inside an extended container is
    /// carvable evidence — deleted logical volumes and hidden data live there.
    /// The primary gap scan cannot see it, because the container occupies one
    /// contiguous "used" range there, so it was never mapped at all (B7-013).
    #[test]
    fn free_space_inside_an_extended_container_is_mapped() {
        let mut disk = vec![0u8; 2 * 1024 * 1024];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        put_entry(&mut disk, 0, 0, 0, 0x04, 1, 100); // primary FAT16 @ LBA 1
        put_entry(&mut disk, 0, 1, 0, 0x05, 200, 1000); // extended container @ 200..1200

        // One logical partition at LBA 210..260. Sectors 260..1200 inside the
        // container are free and must be published as unallocated space.
        put_entry(&mut disk, 200, 0, 0, 0x06, 10, 50);

        let art = make_raw_artifact(disk);
        let out = PartitionParser.process(&art).unwrap();

        let inner: Vec<_> = out
            .iter()
            .filter(|a| {
                a.artifact_type == ArtifactType::UnallocatedSpace
                    && a.metadata.get("inside_extended").and_then(|v| v.as_bool()) == Some(true)
            })
            .collect();
        assert!(
            !inner.is_empty(),
            "inter-logical free space inside the extended container must be mapped"
        );
        let tail = inner
            .iter()
            .find(|a| a.metadata["offset_bytes"] == json!(260u64 * 512))
            .expect("the free tail after the last logical partition must be emitted");
        assert_eq!(tail.metadata["size_bytes"], json!((1200u64 - 260) * 512));
        assert_eq!(tail.metadata["extended_container"], json!(2));
    }
}
