use super::*;
use crate::fat_structs::*;
use seance_core::data_source::DataSource;
use seance_core::test_support::DribbleSource;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Mock data source for testing
#[derive(Debug)]
struct MockFatSource {
    data: Vec<u8>,
}

impl MockFatSource {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for MockFatSource {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }

        let to_read = std::cmp::min(buffer.len(), self.data.len() - offset);
        buffer[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Build a directory entry carrying only the fields creation_datetime reads.
fn dir_entry_with_creation(date: u16, time: u16, tenth: u8) -> DirectoryEntry {
    DirectoryEntry {
        name: [b' '; 11],
        attributes: 0,
        reserved: 0,
        creation_time_tenth: tenth,
        creation_time: time,
        creation_date: date,
        access_date: 0,
        first_cluster_high: 0,
        modification_time: 0,
        modification_date: 0,
        first_cluster_low: 0,
        file_size: 0,
    }
}

/// BUG-066: creation_datetime must apply DIR_CrtTimeTenth (10 ms units), not
/// truncate to the even DOS second.
#[test]
fn test_creation_datetime_applies_tenth_of_second() {
    // DOS date 2021-06-15, DOS time 10:30:20 (second field = 10 => 20 s).
    let date: u16 = (41 << 9) | (6 << 5) | 15;
    let time: u16 = (10 << 11) | (30 << 5) | 10;

    // tenth = 0 => exactly the even second, no sub-second component.
    let base = dir_entry_with_creation(date, time, 0)
        .creation_datetime()
        .unwrap();
    assert_eq!(base.to_rfc3339(), "2021-06-15T10:30:20+00:00");

    // tenth = 150 => +1.5 s (carries one whole second plus 500 ms).
    let refined = dir_entry_with_creation(date, time, 150)
        .creation_datetime()
        .unwrap();
    assert_eq!(refined.to_rfc3339(), "2021-06-15T10:30:21.500+00:00");
}

#[test]
fn test_fat_type_detection() {
    // Create minimal valid BPB
    let mut boot_sector = vec![0u8; 512];

    // Jump instruction
    boot_sector[0] = 0xEB;
    boot_sector[1] = 0x3C;
    boot_sector[2] = 0x90;

    // OEM name
    boot_sector[3..11].copy_from_slice(b"MSWIN4.1");

    // Bytes per sector: 512
    boot_sector[11] = 0x00;
    boot_sector[12] = 0x02;

    // Sectors per cluster: 4
    boot_sector[13] = 0x04;

    // Reserved sectors: 1
    boot_sector[14] = 0x01;
    boot_sector[15] = 0x00;

    // Number of FATs: 2
    boot_sector[16] = 0x02;

    // Root entries: 512
    boot_sector[17] = 0x00;
    boot_sector[18] = 0x02;

    // Total sectors (16-bit): 20480
    boot_sector[19] = 0x00;
    boot_sector[20] = 0x50;

    // Media descriptor: 0xF8
    boot_sector[21] = 0xF8;

    // Sectors per FAT: 20
    boot_sector[22] = 0x14;
    boot_sector[23] = 0x00;

    // Boot signature
    boot_sector[510] = 0x55;
    boot_sector[511] = 0xAA;

    let bpb = BiosParameterBlock::parse(&boot_sector).unwrap();

    assert_eq!(bpb.bytes_per_sector, 512);
    assert_eq!(bpb.sectors_per_cluster, 4);
    assert_eq!(bpb.num_fats, 2);

    let sectors_per_fat = bpb.sectors_per_fat();
    let fat_type = bpb.determine_fat_type(sectors_per_fat);

    // This should be FAT16 based on cluster count
    assert_eq!(fat_type, FatType::Fat16);
}

#[test]
fn test_directory_entry_parsing() {
    let mut entry_data = vec![0u8; 32];

    // Filename: "TEST    TXT"
    // forensic-lint: allow RAGGED-STRING — an 8.3 short name IS space-padded to 11 bytes.
    entry_data[0..11].copy_from_slice(b"TEST    TXT");

    // Attributes: Archive
    entry_data[11] = ATTR_ARCHIVE;

    // Creation time: 12:30:00
    entry_data[14] = 0x30; // Time low byte
    entry_data[15] = 0x62; // Time high byte (12:30)

    // Creation date: 2024-01-15
    entry_data[16] = 0x0F; // Date low byte (day 15)
    entry_data[17] = 0x58; // Date high byte (2024-01)

    // File size: 1024 bytes
    entry_data[28] = 0x00;
    entry_data[29] = 0x04;
    entry_data[30] = 0x00;
    entry_data[31] = 0x00;

    let entry = DirectoryEntry::parse(&entry_data).unwrap();

    assert_eq!(entry.get_short_name(), ("TEST.TXT".to_string(), false));
    assert_eq!(entry.file_size, 1024);
    assert!(!entry.is_directory());
    assert!(!entry.is_deleted());
    assert!(!entry.is_lfn());
}

#[test]
fn test_lfn_entry_parsing() {
    let mut lfn_data = vec![0u8; 32];

    // Sequence: 0x41 (last entry, sequence 1)
    lfn_data[0] = 0x41;

    // Name part 1: "L" "o" "n" "g" " " (UTF-16LE)
    lfn_data[1] = b'L';
    lfn_data[2] = 0x00;
    lfn_data[3] = b'o';
    lfn_data[4] = 0x00;
    lfn_data[5] = b'n';
    lfn_data[6] = 0x00;
    lfn_data[7] = b'g';
    lfn_data[8] = 0x00;
    lfn_data[9] = b' ';
    lfn_data[10] = 0x00;

    // Attributes: 0x0F (LFN)
    lfn_data[11] = ATTR_LONG_NAME;

    let lfn = LfnEntry::parse(&lfn_data).unwrap();

    assert!(lfn.is_last());
    assert_eq!(lfn.sequence_number(), 1);
    assert!(lfn.get_name_part().starts_with("Long"));
}

#[test]
fn lfn_chain_rejects_wrong_and_torn_checksums() {
    use crate::fat_parser::lfn_chain_matches;

    // A live short 8.3 entry "MEMO    TXT".
    let mut short = vec![0u8; 32];
    // forensic-lint: allow RAGGED-STRING — an 8.3 short name IS space-padded to 11 bytes.
    short[0..11].copy_from_slice(b"MEMO    TXT");
    short[11] = 0x20; // archive attribute (not volume label / LFN)
    let dir = DirectoryEntry::parse(&short).unwrap();
    let expected = dir.lfn_checksum();

    // A single LFN slot carrying the correct 8.3 checksum is accepted.
    let mut good_slot = vec![0u8; 32];
    good_slot[0] = 0x41; // last slot, sequence 1
    good_slot[11] = ATTR_LONG_NAME;
    good_slot[13] = expected;
    let good = LfnEntry::parse(&good_slot).unwrap();
    assert!(lfn_chain_matches(&[good], &dir, false));

    // A slot whose checksum belongs to a different file is rejected: it must not
    // be attached as this file's long name (BUG-163).
    let mut wrong_slot = good_slot.clone();
    wrong_slot[13] = expected.wrapping_add(1);
    let wrong = LfnEntry::parse(&wrong_slot).unwrap();
    assert!(!lfn_chain_matches(&[wrong], &dir, false));

    // A torn chain mixing two checksums is rejected even though one matches.
    let good2 = LfnEntry::parse(&good_slot).unwrap();
    let torn = LfnEntry::parse(&wrong_slot).unwrap();
    assert!(!lfn_chain_matches(&[good2, torn], &dir, false));

    // An empty buffer yields no long name.
    assert!(!lfn_chain_matches(&[], &dir, false));
}

#[test]
fn test_cluster_chain_to_runs_coalescing() {
    use crate::fat_parser::cluster_chain_to_runs;

    // Contiguous clusters 2,3,4 then a jump to 10
    let chain = vec![2u32, 3, 4, 10];
    let (runs, complete) = cluster_chain_to_runs(&chain, 512, true, |c| c as u64 * 512);

    assert_eq!(
        runs,
        serde_json::json!([[1024u64, 1536u64], [5120u64, 512u64]])
    );
    assert!(complete);
}

#[test]
fn test_cluster_chain_to_runs_cap() {
    use crate::fat_parser::cluster_chain_to_runs;

    // Non-contiguous clusters past the shared cap -> capped, marked incomplete
    // (CR-047: the shared 4,096, no longer a private 512). SYNTHETIC chain.
    let cap = seance_core::data_source::MAX_METADATA_DATA_RUNS;
    let chain: Vec<u32> = (0..(cap as u32 + 88)).map(|i| i * 2 + 2).collect();
    let (runs, complete) = cluster_chain_to_runs(&chain, 512, true, |c| c as u64 * 512);

    assert_eq!(runs.as_array().unwrap().len(), cap);
    assert!(!complete);
}

/// BUG-210: a chain the walker cut short (safety cap / cycle) must mark the run
/// list incomplete even when the coalesced runs fit well under the run cap.
#[test]
fn test_cluster_chain_to_runs_propagates_truncated_chain() {
    use crate::fat_parser::cluster_chain_to_runs;

    let chain = vec![2u32, 3, 4];
    let (runs, complete) = cluster_chain_to_runs(&chain, 512, false, |c| c as u64 * 512);

    assert_eq!(
        runs.as_array().unwrap().len(),
        1,
        "clusters coalesce to 1 run"
    );
    assert!(
        !complete,
        "an incomplete cluster chain must not yield data_runs_complete = true"
    );
}

#[test]
fn test_build_allocation_buckets_downsampling() {
    use crate::fat_parser::build_allocation_buckets_from_bitmap;

    // 131072 clusters -> 2 clusters per bucket, 65536 buckets; the first 100
    // clusters allocated.
    let mut bitmap = vec![0xFFu8; 12];
    bitmap.push(0x0F);
    bitmap.resize(131072 / 8, 0);
    let (buckets, clusters_per_bucket) = build_allocation_buckets_from_bitmap(131072, &bitmap);
    assert_eq!(clusters_per_bucket, 2);
    assert_eq!(buckets.len(), 65536);
    assert_eq!(buckets[0], 255); // fully allocated bucket
    assert_eq!(buckets[50], 0); // fully free bucket (clusters 100/101)
    assert!(buckets[49] == 255); // clusters 98,99 allocated

    // Partial bucket: half allocated -> 127
    let bitmap = vec![0x55u8; 131072 / 8];
    let (buckets, cpb) = build_allocation_buckets_from_bitmap(131072, &bitmap);
    assert_eq!(cpb, 2);
    assert!(buckets.iter().all(|&b| b == 127));
}

#[test]
fn test_data_sectors_underflow_saturates_to_zero() {
    // Reproduces the fuzz crash: reserved + FAT + root_dir metadata (69088
    // sectors) exceeds the volume's total sectors (6144). data_sectors must
    // saturate to 0 instead of underflow-panicking (debug) / wrapping (release).
    let bpb = BiosParameterBlock {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        reserved_sectors: 64992,
        num_fats: 2,
        root_entries: 0,
        total_sectors_16: 6144,
        media_descriptor: 0xF8,
        sectors_per_fat_16: 0,
        sectors_per_track: 63,
        num_heads: 255,
        hidden_sectors: 0,
        total_sectors_32: 1_048_576,
        total_sectors_64: 0,
    };
    assert_eq!(bpb.data_sectors(2048), 0);
    assert_eq!(bpb.total_clusters(2048), 0);
}

#[test]
fn test_module_metadata() {
    let parser = FatParser;

    assert_eq!(parser.id(), "plugin.filesystem.fat_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileSystem));

    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_process_non_fat_data() {
    let parser = FatParser;
    let case_id = Uuid::new_v4();

    // Create artifact with non-FAT data
    let non_fat_data = vec![0u8; 512];
    let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(non_fat_data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::Partition,
        Some(data_source),
        json!({"name": "test"}),
    );

    // Should return empty vec (not a FAT filesystem)
    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

/// Regression: a deleted, multi-cluster, NON-fragmented file must be recovered
/// in full. On deletion the FAT chain is freed, so following the chain yields
/// only the first cluster. The parser must instead read the file's clusters
/// contiguously from the start cluster (matching TSK `icat`). Validated against
/// the DFTT "FAT Undelete Test #6" known-answer image; this synthetic fixture
/// pins the behavior without a large binary dependency.
#[test]
fn test_undelete_multicluster_contiguous_recovery() {
    use seance_core::hashing::compute_hashes;

    // Geometry: 512 B/sector, 1 sector/cluster, 1 reserved, 1 FAT of 17
    // sectors, 16 root entries (1 sector). data clusters = 4181 -> FAT16.
    const BPS: usize = 512;
    const SPF: usize = 17;
    const RESERVED: usize = 1;
    const ROOT_ENTRIES: usize = 16;
    const TOTAL_SECTORS: usize = 4200;
    let mut img = vec![0u8; TOTAL_SECTORS * BPS];

    // Boot sector / BPB.
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes()); // bytes/sector
    img[13] = 1; // sectors/cluster
    img[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    img[16] = 1; // num FATs
    img[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    img[19..21].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    img[21] = 0xF8; // media descriptor
    img[22..24].copy_from_slice(&(SPF as u16).to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;

    // Root directory begins right after the FAT(s).
    let root_off = (RESERVED + SPF) * BPS; // 18 * 512
                                           // First data cluster (cluster 2) begins after the root directory (1 sector).
    let first_data_sector = RESERVED + SPF + 1; // 19
    let cluster2_off = first_data_sector * BPS;

    // A 900-byte file spans two contiguous clusters (512 + 388).
    const FILE_SIZE: usize = 900;
    let content: Vec<u8> = (0..FILE_SIZE).map(|i| (i * 7 + 3) as u8).collect();
    img[cluster2_off..cluster2_off + FILE_SIZE].copy_from_slice(&content);
    let expected_md5 = compute_hashes(&content).md5;

    // Deleted directory entry for "_ULT.DAT" (was MULT.DAT), start cluster 2.
    // The FAT entries for clusters 2 and 3 are left ZERO (freed on delete).
    let e = root_off;
    img[e] = 0xE5; // deletion marker (first name byte)
    img[e + 1..e + 8].copy_from_slice(b"ULT    ");
    img[e + 8..e + 11].copy_from_slice(b"DAT");
    img[e + 11] = ATTR_ARCHIVE;
    img[e + 26..e + 28].copy_from_slice(&2u16.to_le_bytes()); // first_cluster_low
    img[e + 28..e + 32].copy_from_slice(&(FILE_SIZE as u32).to_le_bytes());
    // Slot 1 stays 0x00 -> end of directory.

    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "synthetic.dd", "subtype": "fat16" }),
    );

    let out = FatParser.process(&fs).expect("parse synthetic fat16");
    let file = out
        .iter()
        .find(|a| a.metadata.get("deleted").and_then(|v| v.as_bool()) == Some(true))
        .expect("recovered deleted file present");

    assert_eq!(
        file.metadata.get("size").and_then(|v| v.as_u64()),
        Some(FILE_SIZE as u64)
    );
    assert_eq!(
        file.metadata
            .get("deleted_recovery_method")
            .and_then(|v| v.as_str()),
        Some("contiguous_assumed"),
        "contiguous recovery must be flagged as an assumption"
    );
    // B2-160: the FAT no longer records where this file's clusters were, so the
    // contiguous span is a GUESS. A fragmented original re-serves another
    // file's bytes under this name. `deleted_recovery_method` is descriptive;
    // the flag the API, export and integrity-verify paths read is
    // `content_incomplete`, and without it the guess is hashed and exported as
    // the file itself.
    assert_eq!(file.metadata["content_incomplete"], json!(true));
    assert_eq!(
        file.metadata["content_incomplete_reason"],
        json!("deleted_contiguous_assumed")
    );
    // But the run list DOES span the recorded 900 bytes, and the content
    // resolver refuses outright to serve any artifact whose `data_runs_complete`
    // is false. Marking a full-length contiguous recovery short would withdraw
    // every recovered deleted file on every FAT volume from the examiner — the
    // opposite defect. "These runs cover the file" and "these runs are certainly
    // this file's clusters" are different claims and get different flags.
    assert_eq!(file.metadata["data_runs_complete"], json!(true));

    // Read the full recovered content: must be all 900 bytes across both
    // clusters (not just the first 512), and hash to the original.
    let src = file
        .data
        .as_ref()
        .expect("recovered file has a data source");
    let mut buf = vec![0u8; FILE_SIZE];
    let mut off = 0usize;
    while off < FILE_SIZE {
        match src.read_at(off as u64, &mut buf[off..]).unwrap() {
            0 => break,
            n => off += n,
        }
    }
    assert_eq!(
        off, FILE_SIZE,
        "recovered {} of {} bytes (chain truncated?)",
        off, FILE_SIZE
    );
    assert_eq!(
        compute_hashes(&buf).md5,
        expected_md5,
        "recovered content mismatch"
    );
}

/// Regression (F2): the BytesPerSectorShift/SectorsPerClusterShift bytes are
/// attacker-controlled; a shift >= 16 makes `1u16 << shift` a shift-amount
/// overflow that panics in debug builds. parse() must reject out-of-range
/// shifts and still accept valid geometry.
#[test]
fn exfat_boot_sector_rejects_out_of_range_shift() {
    use crate::exfat_structs::ExFatBootSector;
    let mut data = vec![0u8; 512];
    data[3..11].copy_from_slice(b"EXFAT   ");
    data[510] = 0x55;
    data[511] = 0xAA;
    data[108] = 20; // bytes_per_sector_shift -> would panic on `1u16 << 20`
    data[109] = 0;
    assert!(ExFatBootSector::parse(&data).is_err());
    data[108] = 9; // 512-byte sectors
    data[109] = 16; // sum 25 but overflows the u16 result -> must still reject
    assert!(ExFatBootSector::parse(&data).is_err());
    data[109] = 3; // 8 sectors/cluster -> valid
    assert!(ExFatBootSector::parse(&data).is_ok());
}

/// Regression (F7): cluster_to_offset must saturate for clusters < 2 rather than
/// underflow-panic on `cluster - 2`.
#[test]
fn exfat_cluster_to_offset_saturates_below_two() {
    use crate::exfat_structs::ExFatBootSector;
    let mut data = vec![0u8; 512];
    data[3..11].copy_from_slice(b"EXFAT   ");
    data[510] = 0x55;
    data[511] = 0xAA;
    data[108] = 9;
    data[109] = 0;
    let bs = ExFatBootSector::parse(&data).unwrap();
    let _ = bs.cluster_to_offset(0);
    let _ = bs.cluster_to_offset(1);
}

/// Regression (F5): non-power-of-two geometry (sectors_per_cluster = 3) must be
/// rejected rather than parsed with bogus cluster math that inflates
/// attacker-controlled cluster counts.
#[test]
fn fat_rejects_non_power_of_two_geometry() {
    let mut img = vec![0u8; 4200 * 512];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&512u16.to_le_bytes());
    img[13] = 3; // sectors/cluster: NOT a power of two
    img[14..16].copy_from_slice(&1u16.to_le_bytes());
    img[16] = 1;
    img[17..19].copy_from_slice(&16u16.to_le_bytes());
    img[19..21].copy_from_slice(&4200u16.to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&17u16.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "bad.dd", "subtype": "fat16" }),
    );
    let out = FatParser.process(&fs).expect("must not panic");
    assert!(out.is_empty(), "non-power-of-two geometry must be rejected");
}

/// Regression (F4): a deleted entry claiming a ~4 GiB file_size on a tiny volume
/// must not build a multi-million-cluster Vec; the contiguous recovery is
/// clamped to the volume length.
#[test]
fn fat_undelete_huge_size_is_bounded() {
    const BPS: usize = 512;
    const SPF: usize = 17;
    const RESERVED: usize = 1;
    const ROOT_ENTRIES: usize = 16;
    const TOTAL_SECTORS: usize = 4200;
    let mut img = vec![0u8; TOTAL_SECTORS * BPS];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = 1;
    img[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    img[16] = 1;
    img[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    img[19..21].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&(SPF as u16).to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    let e = (RESERVED + SPF) * BPS; // root directory
    img[e] = 0xE5;
    img[e + 1..e + 8].copy_from_slice(b"BIG    ");
    img[e + 8..e + 11].copy_from_slice(b"DAT");
    img[e + 11] = ATTR_ARCHIVE;
    img[e + 26..e + 28].copy_from_slice(&2u16.to_le_bytes());
    img[e + 28..e + 32].copy_from_slice(&u32::MAX.to_le_bytes()); // ~4 GiB
    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "big.dd", "subtype": "fat16" }),
    );
    let out = FatParser
        .process(&fs)
        .expect("parse must complete without OOM/panic");
    let file = out
        .iter()
        .find(|a| a.metadata.get("deleted").and_then(|v| v.as_bool()) == Some(true))
        .expect("deleted file present");
    // The coalesced contiguous run must be bounded by the ~2 MiB volume, not the
    // declared ~4 GiB size.
    let runs = file
        .metadata
        .get("data_runs")
        .and_then(|v| v.as_array())
        .expect("data_runs present");
    let total_len: u64 = runs
        .iter()
        .filter_map(|r| r.as_array())
        .filter_map(|r| r.get(1))
        .filter_map(|v| v.as_u64())
        .sum();
    assert!(
        total_len <= (TOTAL_SECTORS * BPS) as u64 + BPS as u64,
        "recovered run coverage ({total_len}) must be bounded by the volume size"
    );
    // BUG-210: the clamp leaves the reconstruction far short of the declared
    // size, so the run list must not be published as complete; otherwise the
    // content resolver zero-fills the missing ~4 GiB as if it were a hole.
    assert_eq!(file.metadata["data_runs_complete"], json!(false));
    assert_eq!(file.metadata["cluster_chain_incomplete"], json!(true));
}

/// BUG-188: a FAT12/16 root-directory slot that the source can only partly
/// return must NOT be zero-padded and parsed. The zero tail would invent a
/// file's cluster and size (or forge the 0x00 end-of-directory marker) from half
/// a record.
#[test]
fn fat_root_short_read_is_not_parsed_as_entry() {
    const BPS: usize = 512;
    const SPF: usize = 17;
    const RESERVED: usize = 1;
    const ROOT_ENTRIES: usize = 16;
    const TOTAL_SECTORS: usize = 4200;

    let root_off = (RESERVED + SPF) * BPS;
    // The image stops 16 bytes into the SECOND root-directory slot.
    let mut img = vec![0u8; root_off + 32 + 16];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = 1; // sectors/cluster
    img[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    img[16] = 1; // num FATs
    img[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    img[19..21].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&(SPF as u16).to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;

    // Slot 0: a complete, ordinary entry.
    img[root_off..root_off + 8].copy_from_slice(b"GOOD    ");
    img[root_off + 8..root_off + 11].copy_from_slice(b"TXT");
    img[root_off + 11] = ATTR_ARCHIVE;

    // Slot 1: only the first 16 bytes exist (name + attributes). The cluster and
    // size fields live in the missing half.
    let slot1 = root_off + 32;
    img[slot1..slot1 + 8].copy_from_slice(b"EVIL    ");
    img[slot1 + 8..slot1 + 11].copy_from_slice(b"TXT");
    img[slot1 + 11] = ATTR_ARCHIVE;

    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "short.dd", "subtype": "fat16" }),
    );

    let out = FatParser.process(&fs).expect("parse must complete");
    let names: Vec<String> = out
        .iter()
        .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect();

    assert!(
        names.iter().any(|n| n == "GOOD.TXT"),
        "the complete entry must still be parsed: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.starts_with("EVIL")),
        "a half-read directory slot must not become a file: {names:?}"
    );
    // The listing stopped on a slot the image could not deliver, which is not
    // the end of the directory: the volume record must say so.
    let map = out
        .iter()
        .find(|a| a.metadata["type"] == json!("allocation_map"))
        .expect("allocation map");
    assert_eq!(map.metadata["directory_parse_incomplete"], json!(true));
    assert_eq!(
        map.metadata["directory_parse_incomplete_reason"],
        json!("fat_root_chain_incomplete")
    );
}

/// ROADMAP 5.12: the root-directory walk must stop at the all-zero
/// end-of-directory marker via `DirectoryEntry::is_end_of_directory`, not a
/// second inline `entry_data[0] == 0x00` check. A slot placed after the
/// marker is on-disk garbage from a shrunk directory; reading past the
/// marker would surface it as a live file.
#[test]
fn fat_root_directory_walk_stops_at_end_of_directory_marker() {
    const BPS: usize = 512;
    const SPF: usize = 17;
    const RESERVED: usize = 1;
    const ROOT_ENTRIES: usize = 16;
    const TOTAL_SECTORS: usize = 4200;
    let mut img = vec![0u8; TOTAL_SECTORS * BPS];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = 1; // sectors/cluster
    img[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    img[16] = 1; // num FATs
    img[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    img[19..21].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&(SPF as u16).to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;

    let root_off = (RESERVED + SPF) * BPS;

    // Slot 0: a complete, ordinary entry.
    img[root_off..root_off + 8].copy_from_slice(b"GOOD    ");
    img[root_off + 8..root_off + 11].copy_from_slice(b"TXT");
    img[root_off + 11] = ATTR_ARCHIVE;

    // Slot 1 stays all-zero: the end-of-directory marker.

    // Slot 2: a well-formed entry that sits past the marker. A directory
    // shrunk in place leaves exactly this shape — a stale record beyond the
    // new end — and it must never be read as live.
    let slot2 = root_off + 64;
    img[slot2..slot2 + 8].copy_from_slice(b"GHOST   ");
    img[slot2 + 8..slot2 + 11].copy_from_slice(b"TXT");
    img[slot2 + 11] = ATTR_ARCHIVE;
    img[slot2 + 26..slot2 + 28].copy_from_slice(&2u16.to_le_bytes());
    img[slot2 + 28..slot2 + 32].copy_from_slice(&512u32.to_le_bytes());

    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "stops_at_marker.dd", "subtype": "fat16" }),
    );

    let out = FatParser.process(&fs).expect("parse must complete");
    let names: Vec<String> = out
        .iter()
        .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect();

    assert!(
        names.iter().any(|n| n == "GOOD.TXT"),
        "the entry before the marker must still be parsed: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.starts_with("GHOST")),
        "a slot past the end-of-directory marker must never surface as a file: {names:?}"
    );
}

/// B2-096: `follow_chain` already reports that a cyclic or capped chain does not
/// cover the whole directory, but the directory parser threw that answer away
/// and emitted whatever prefix it had collected. A directory listing is evidence
/// of absence — an examiner reads "the file is not in this folder" — so a
/// listing that stops early must be marked, exactly as the file-content path
/// already marks a truncated chain.
#[test]
fn a_directory_on_a_cyclic_chain_is_flagged_incomplete() {
    let out = parse_fat16_with_subdir_chain(&[(2u32, 3u16), (3u32, 2u16)]);
    let sub = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("SUB"))
        .expect("the subdirectory entry is emitted");
    assert_eq!(
        sub.metadata["directory_parse_incomplete"],
        json!(true),
        "a cyclic directory chain must not read as a complete listing"
    );
    assert_eq!(
        sub.metadata["directory_parse_incomplete_reason"],
        json!("fat_chain_incomplete")
    );
}

/// The success path of the check above: a directory whose chain ends on a real
/// end-of-chain marker carries no incompleteness flag, so the flag stays
/// meaningful.
#[test]
fn a_directory_on_a_terminated_chain_carries_no_incomplete_flag() {
    let out = parse_fat16_with_subdir_chain(&[(2u32, 0xFFFFu16)]);
    let sub = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("SUB"))
        .expect("the subdirectory entry is emitted");
    assert!(
        sub.metadata.get("directory_parse_incomplete").is_none(),
        "a properly terminated chain is a complete listing"
    );
}

/// B2-154: a sized file whose chain yields no clusters at all — its start
/// cluster is outside the FAT — gets no data source and no runs. Emitted bare it
/// is indistinguishable from a zero-length file, and an examiner reads "this
/// file had no content". It must instead say the content could not be located.
#[test]
fn a_file_whose_start_cluster_is_outside_the_fat_says_so() {
    let mut img = build_fat16_image_with_subdir(&[(2u32, 0xFFFFu16)]);

    // Second root slot: a live 1000-byte file starting at cluster 5000, which
    // is past the end of this volume's 17-sector FAT.
    let root_off = (1 + 17) * 512;
    let slot1 = root_off + 32;
    img[slot1..slot1 + 8].copy_from_slice(b"ORPHAN  ");
    img[slot1 + 8..slot1 + 11].copy_from_slice(b"BIN");
    img[slot1 + 11] = ATTR_ARCHIVE;
    img[slot1 + 26..slot1 + 28].copy_from_slice(&5000u16.to_le_bytes());
    img[slot1 + 28..slot1 + 32].copy_from_slice(&1000u32.to_le_bytes());

    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "orphan.dd", "subtype": "fat16" }),
    );
    let out = FatParser.process(&fs).expect("parse must complete");

    let orphan = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("ORPHAN.BIN"))
        .expect("the entry is still listed — the file exists, its content does not resolve");
    assert!(
        orphan.data.is_none(),
        "no cluster of this file could be located"
    );
    assert_eq!(orphan.metadata["content_incomplete"], json!(true));
    assert_eq!(
        orphan.metadata["content_incomplete_reason"],
        json!("chain_entry_out_of_range")
    );
    assert_eq!(orphan.metadata["data_runs_complete"], json!(false));
}

/// Build a FAT16 volume with a single subdirectory "SUB" starting at cluster 2,
/// writing `fat` as (cluster, entry) pairs into the FAT, and run the parser.
fn parse_fat16_with_subdir_chain(fat: &[(u32, u16)]) -> Vec<Artifact> {
    let img = build_fat16_image_with_subdir(fat);
    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "chain.dd", "subtype": "fat16" }),
    );
    FatParser.process(&fs).expect("parse must complete")
}

/// The bytes of that volume, without running the parser.
fn build_fat16_image_with_subdir(fat: &[(u32, u16)]) -> Vec<u8> {
    const BPS: usize = 512;
    const SPF: usize = 17;
    const RESERVED: usize = 1;
    const ROOT_ENTRIES: usize = 16;
    const TOTAL_SECTORS: usize = 4200;

    let mut img = vec![0u8; TOTAL_SECTORS * BPS];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = 1; // sectors/cluster
    img[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    img[16] = 1; // num FATs
    img[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    img[19..21].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&(SPF as u16).to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT entries (FAT16: two bytes per cluster), starting at the reserved area.
    let fat_off = RESERVED * BPS;
    for &(cluster, entry) in fat {
        let at = fat_off + cluster as usize * 2;
        img[at..at + 2].copy_from_slice(&entry.to_le_bytes());
    }

    // Root directory: one subdirectory entry "SUB" at cluster 2.
    let root_off = (RESERVED + SPF) * BPS;
    img[root_off..root_off + 8].copy_from_slice(b"SUB     ");
    img[root_off + 8..root_off + 11].copy_from_slice(b"   ");
    img[root_off + 11] = ATTR_DIRECTORY;
    img[root_off + 26..root_off + 28].copy_from_slice(&2u16.to_le_bytes());

    // Cluster 2 holds one ordinary file entry so the listing is non-empty.
    let root_dir_sectors = (ROOT_ENTRIES * 32) / BPS;
    let cluster2 = (RESERVED + SPF + root_dir_sectors) * BPS;
    img[cluster2..cluster2 + 8].copy_from_slice(b"CHILD   ");
    img[cluster2 + 8..cluster2 + 11].copy_from_slice(b"TXT");
    img[cluster2 + 11] = ATTR_ARCHIVE;

    img
}

/// B2-008: the boot sector was read with one bare `read_at` into a pre-zeroed
/// buffer, and the length was never checked. On a source that answers in small
/// chunks the tail stayed zero, so the 0x55AA signature read as absent and a
/// perfectly sound FAT volume was skipped entirely — the examiner is told there
/// is no filesystem on the partition. Every byte of this image is present; only
/// the delivery is chunked, and the volume must parse.
#[test]
fn a_chunked_source_still_yields_the_whole_boot_sector_and_the_volume() {
    let img = build_fat16_image_with_subdir(&[(2u32, 0xFFFFu16)]);
    // Holds the whole image but never returns more than 100 bytes from a single
    // `read_at` — exactly how a windowed, E01-backed or network source behaves.
    // Nothing is missing from it.
    let dribble = Arc::new(DribbleSource::new(img, 100));
    let ds: Arc<dyn DataSource> = dribble.clone();
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "chunked.dd", "subtype": "fat16" }),
    );
    let out = FatParser.process(&fs).expect("parse must complete");
    assert!(
        out.iter()
            .any(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("SUB")),
        "a chunked but complete image must parse to the same inventory, got {} artifacts",
        out.len()
    );
    assert!(
        out.iter()
            .any(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("CHILD.TXT")),
        "the subdirectory's contents must be reached too"
    );
    dribble.assert_dribbled();
}

/// The other half of B2-008: when the boot sector genuinely is not all there,
/// the read fails closed, which at the module boundary means "no filesystem
/// here" rather than a volume invented from the pre-zeroed tail.
#[test]
fn a_partial_boot_sector_yields_no_filesystem_instead_of_invented_geometry() {
    // A valid FAT16 boot sector, truncated to 200 bytes.
    let mut img = vec![0u8; 512];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&512u16.to_le_bytes());
    img[13] = 1;
    img[14..16].copy_from_slice(&1u16.to_le_bytes());
    img[16] = 1;
    img[17..19].copy_from_slice(&16u16.to_le_bytes());
    img[19..21].copy_from_slice(&4200u16.to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&17u16.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    img.truncate(200);

    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "partial.dd", "subtype": "fat16" }),
    );
    let out = FatParser.process(&fs).expect("parse must complete");
    assert!(
        out.is_empty(),
        "a partially readable boot sector must not produce artifacts, got {}",
        out.len()
    );
}

/// Build a FAT16 volume carrying one live file and a boot-sector volume label,
/// both written as the raw OEM bytes a DOS/Windows formatter would store.
fn build_fat16_image_with_oem_names(name_8_3: &[u8; 11], volume_label: &[u8; 11]) -> Vec<u8> {
    const BPS: usize = 512;
    const SPF: usize = 17;
    const RESERVED: usize = 1;
    const ROOT_ENTRIES: usize = 16;
    const TOTAL_SECTORS: usize = 4200;

    let mut img = vec![0u8; TOTAL_SECTORS * BPS];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = 1; // sectors/cluster
    img[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    img[16] = 1; // num FATs
    img[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    img[19..21].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&(SPF as u16).to_le_bytes());
    // FAT16 extended BPB: boot signature @38, volume ID @39, label @43, type @54.
    img[38] = 0x29;
    img[43..54].copy_from_slice(volume_label);
    img[54..62].copy_from_slice(b"FAT16   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT: cluster 2 is the file's only cluster and terminates the chain.
    let fat_off = RESERVED * BPS;
    img[fat_off + 4..fat_off + 6].copy_from_slice(&0xFFFFu16.to_le_bytes());

    // Root directory: one live 8.3 entry, no long-name slots -- so the short
    // name is the only name this file has.
    let root_off = (RESERVED + SPF) * BPS;
    img[root_off..root_off + 11].copy_from_slice(name_8_3);
    img[root_off + 11] = ATTR_ARCHIVE;
    img[root_off + 26..root_off + 28].copy_from_slice(&2u16.to_le_bytes());
    img[root_off + 28..root_off + 32].copy_from_slice(&64u32.to_le_bytes());

    img
}

fn parse_oem_image(img: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "oem.dd", "subtype": "fat16" }),
    );
    FatParser.process(&fs).expect("parse must complete")
}

/// What an examiner learns: the name of a file on the volume, and the name of
/// the volume itself. FAT stores both as OEM bytes; decoding them as UTF-8
/// replaced every byte 0x80-0xFF with U+FFFD, so `MÜLLER.DOC` was listed as
/// `M\u{FFFD}LLER.DOC` -- a name that matches no keyword search, no hash-set
/// entry and no witness statement, and on a deleted entry is the only name that
/// survives at all.
#[test]
fn an_oem_8_3_name_and_volume_label_are_decoded_and_stamped_with_their_code_page() {
    // 0x9A is Ü and 0x82 is é in CP437, the OEM set these fields are written in.
    let img = build_fat16_image_with_oem_names(b"M\x9aLLER  DOC", b"CAF\x82       ");
    let out = parse_oem_image(img);

    let file = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .expect("the live file must be listed");
    assert_eq!(file.metadata["name"], "MÜLLER.DOC");
    assert_eq!(file.metadata["short_name"], "MÜLLER.DOC");
    assert!(
        !file.metadata["name"].as_str().unwrap().contains('\u{FFFD}'),
        "an 8.3 name must not be listed with replacement characters"
    );
    assert_eq!(
        file.metadata["path_decode"], "cp437",
        "a name this build interpreted must name the code page it assumed"
    );

    let map = out
        .iter()
        .find(|a| a.metadata["type"] == "allocation_map")
        .expect("the volume record must be emitted");
    assert_eq!(map.metadata["volume_label"], "CAFé");
    assert_eq!(map.metadata["path_decode"], "cp437");
}

/// The code page has to be a parameter: these are OEM bytes, and reading them
/// through the Windows ANSI table gives a different, equally confident name --
/// byte 0x82 is `é` on a FAT volume and a low quotation mark in CP1252.
#[test]
fn an_8_3_name_is_read_as_oem_not_as_windows_ansi() {
    let mut entry_data = vec![0u8; 32];
    // forensic-lint: allow RAGGED-STRING — an 8.3 short name IS space-padded to 11 bytes.
    entry_data[0..11].copy_from_slice(b"CAF\x82    TXT");
    entry_data[11] = ATTR_ARCHIVE;
    let entry = DirectoryEntry::parse(&entry_data).unwrap();
    assert_eq!(entry.get_short_name(), ("CAFé.TXT".to_string(), true));
}

/// Anti-cry-wolf: an all-ASCII name and label read identically under every
/// single-byte code page, so nothing was interpreted and no record may claim a
/// decode it did not perform.
#[test]
fn an_ascii_8_3_name_and_volume_label_carry_no_code_page_stamp() {
    let img = build_fat16_image_with_oem_names(b"REPORT  DOC", b"BACKUP     ");
    let out = parse_oem_image(img);

    let file = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .expect("the live file must be listed");
    assert_eq!(file.metadata["name"], "REPORT.DOC");
    assert!(file.metadata.get("path_decode").is_none());

    let map = out
        .iter()
        .find(|a| a.metadata["type"] == "allocation_map")
        .expect("the volume record must be emitted");
    assert_eq!(map.metadata["volume_label"], "BACKUP");
    assert!(map.metadata.get("path_decode").is_none());
}

// Integration tests with real FAT images

#[cfg(test)]
mod integration_tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    /// FAT geometry now rides on the allocation-map record (the FAT parser no
    /// longer mints its own FileSystem artifact). Pull the detected fat_type
    /// from there.
    fn fat_type_of(artifacts: &[Artifact]) -> Option<&str> {
        artifacts
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("allocation_map"))
            .and_then(|a| a.metadata.get("fat_type").and_then(|v| v.as_str()))
    }

    /// The allocation-map record (holds geometry now that no FileSystem is minted).
    fn alloc_map(artifacts: &[Artifact]) -> Option<&Artifact> {
        artifacts
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("allocation_map"))
    }

    /// True when the geometry record reports an exFAT volume.
    fn is_exfat(artifacts: &[Artifact]) -> bool {
        alloc_map(artifacts).and_then(|a| a.metadata.get("fs_type").and_then(|v| v.as_str()))
            == Some("exFAT")
    }

    /// Neither FAT nor exFAT parsing may mint a FileSystem artifact — the
    /// partition plugin owns it, and a second one cascades without bound.
    fn assert_no_minted_filesystem(artifacts: &[Artifact]) {
        assert!(
            !artifacts
                .iter()
                .any(|a| a.artifact_type == ArtifactType::FileSystem),
            "parser must not create a FileSystem artifact"
        );
    }

    /// Helper to load and decompress a test image. Returns `None` (and logs a
    /// skip) when the gitignored corpus file is absent, e.g. in CI or a fresh
    /// checkout, so callers can `let Some(data) = ... else { return };`.
    /// One image from the gitignored corpus, decompressed.
    ///
    /// Two directories are searched, and the second is why: these fixtures come
    /// from the `dfir_ntfs` project and live under `reference/dfir_ntfs/test_data/`,
    /// while this loader only ever looked in `../test_data`. Every FAT and exFAT
    /// test that called it therefore took the `None` branch and printed
    /// "skipping" on a machine that held the images all along — which is
    /// `test_data/README.md`'s own named failure mode: "a run over an empty
    /// `test_data/` reports `ok` having compared nothing."
    pub(super) fn load_test_image(filename: &str) -> Option<Vec<u8>> {
        let candidates = [
            Path::new("../test_data").join(filename),
            Path::new("../reference/dfir_ntfs/test_data").join(filename),
        ];
        let Some(path) = candidates.iter().find(|p| p.exists()) else {
            eprintln!(
                "skipping: {filename} not present in ../test_data or \
                 ../reference/dfir_ntfs/test_data (gitignored corpus, absent in CI)"
            );
            return None;
        };
        let file =
            File::open(path).unwrap_or_else(|_| panic!("Failed to open test file: {path:?}"));
        let mut decoder = GzDecoder::new(file);
        let mut data = Vec::new();
        decoder
            .read_to_end(&mut data)
            .unwrap_or_else(|_| panic!("Failed to decompress test file: {path:?}"));
        Some(data)
    }

    #[test]
    fn test_fat12_real_image() {
        let Some(data) = load_test_image("fat12.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat12_test"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();
        assert!(!artifacts.is_empty(), "Expected at least one artifact");

        assert_eq!(fat_type_of(&artifacts), Some("Fat12"));
        // Must emit file entries and must NOT mint a FileSystem artifact — the
        // partition plugin owns that; a second one would cascade endlessly.
        assert!(artifacts
            .iter()
            .any(|a| a.artifact_type == ArtifactType::FileEntry));
        assert!(
            !artifacts
                .iter()
                .any(|a| a.artifact_type == ArtifactType::FileSystem),
            "FAT parser must not create a FileSystem artifact"
        );

        println!("FAT12 test produced {} artifacts", artifacts.len());
    }

    #[test]
    fn test_fat16_real_image() {
        let Some(data) = load_test_image("fat16.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat16_test"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        assert!(!artifacts.is_empty());
        assert_eq!(fat_type_of(&artifacts), Some("Fat16"));
        assert!(
            !artifacts
                .iter()
                .any(|a| a.artifact_type == ArtifactType::FileSystem),
            "FAT parser must not create a FileSystem artifact"
        );

        println!("FAT16 test produced {} artifacts", artifacts.len());
    }

    #[test]
    fn test_fat32_real_image() {
        let Some(data) = load_test_image("fat32_loop.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat32_test"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        assert!(!artifacts.is_empty());
        assert_eq!(fat_type_of(&artifacts), Some("Fat32"));
        assert!(
            !artifacts
                .iter()
                .any(|a| a.artifact_type == ArtifactType::FileSystem),
            "FAT parser must not create a FileSystem artifact"
        );

        println!("FAT32 test produced {} artifacts", artifacts.len());
    }

    #[test]
    fn test_fat32_small_is_read_as_fat32() {
        // fat32_small.raw.gz is a FAT32-layout volume with very few clusters.
        // The layout, not the cluster count, decides the width: it is read as
        // FAT32 and the disagreement with the spec's cluster-count rule is
        // recorded on the allocation map, not silently resolved as an empty
        // FAT12 volume.
        let Some(data) = load_test_image("fat32_small.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat32_small_test"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        assert!(!artifacts.is_empty());
        assert_eq!(fat_type_of(&artifacts), Some("Fat32"));
        assert!(alloc_map(&artifacts)
            .expect("allocation map")
            .metadata
            .get("fat_type_note")
            .is_some());
    }

    #[test]
    fn test_file_metadata_extraction() {
        // Use FAT32 loop image which has files with known metadata
        let Some(data) = load_test_image("fat32_loop.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat32_metadata_test"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        // FAT geometry rides on the allocation-map record (the parser no longer
        // mints its own FileSystem artifact).
        assert!(!artifacts.is_empty());
        let map = artifacts
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("allocation_map"))
            .expect("allocation_map record");
        assert_eq!(map.metadata["fat_type"], "Fat32");
        assert!(map.metadata["bytes_per_sector"].is_number());
        assert!(map.metadata["sectors_per_cluster"].is_number());

        // Check file entries exist (artifacts also include the allocation_map ParsedRecord)
        if let Some(file_entry) = artifacts
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
        {
            // Verify file metadata fields exist
            let file_metadata = &file_entry.metadata;
            assert!(file_metadata["name"].is_string());
            assert!(file_metadata["size"].is_number());
            assert!(file_metadata["is_directory"].is_boolean());
            assert!(file_metadata["attributes"].is_object());

            println!(
                "Sample file metadata: {}",
                serde_json::to_string_pretty(&file_metadata).unwrap()
            );
        }
    }

    #[test]
    fn test_subdirectory_parsing() {
        // Use FAT32 full test which has nested directories
        let Some(data) = load_test_image("fat32_loop.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat32_subdir_test"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        // Should have filesystem + files + subdirectories
        assert!(
            artifacts.len() > 4,
            "Expected more than 4 artifacts with subdirectories"
        );

        // Find entries with paths containing subdirectories
        let nested_files: Vec<&Artifact> = artifacts
            .iter()
            .filter(|a| {
                if let Some(path) = a.metadata.get("path") {
                    if let Some(path_str) = path.as_str() {
                        // Count slashes to find nested paths
                        return path_str.matches('/').count() > 1;
                    }
                }
                false
            })
            .collect();

        if !nested_files.is_empty() {
            println!("Found {} nested file entries", nested_files.len());
            println!("Sample nested path: {}", nested_files[0].metadata["path"]);
            assert!(nested_files[0].metadata["path"]
                .as_str()
                .unwrap()
                .contains('/'));
        }

        // Verify all file entries have path metadata
        let file_entries: Vec<&Artifact> = artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();

        for entry in file_entries {
            assert!(
                entry.metadata.get("path").is_some(),
                "File entry missing path metadata"
            );
        }
    }

    #[test]
    fn test_against_expected_output() {
        // Test FAT12 image against its expected output file
        let Some(data) = load_test_image("fat12.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat12_validation"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);
        assert!(result.is_ok());
        let artifacts = result.unwrap();

        // Read expected output, from wherever the corpus is -- the same two
        // directories `load_test_image` searches, for the same reason.
        let expected_content = [
            Path::new("../test_data/fat12_full_test.txt"),
            Path::new("../reference/dfir_ntfs/test_data/fat12_full_test.txt"),
        ]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .expect("the image loaded, so its expected-output listing is beside it");

        // Parse expected paths
        let expected_paths: Vec<&str> = expected_content
            .lines()
            .map(|line| line.split('\t').next().unwrap())
            .collect();

        println!(
            "Expected {} paths from fat12_full_test.txt",
            expected_paths.len()
        );

        // Extract actual paths from artifacts
        let actual_paths: Vec<String> = artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .filter_map(|a| {
                a.metadata
                    .get("path")
                    .and_then(|p| p.as_str())
                    .map(String::from)
            })
            .collect();

        println!("Found {} file entries from FAT12 image", actual_paths.len());

        // Show some sample actual paths
        println!("\nSample actual paths:");
        for path in actual_paths.iter().take(10) {
            println!("  {}", path);
        }

        // Show some expected paths
        println!("\nSample expected paths:");
        for path in expected_paths.iter().take(10) {
            println!("  {}", path);
        }

        // Verify we found a similar number of paths
        // The exact paths may differ due to FAT implementation details,
        // but we should have approximately the same count
        let count_diff_ratio = (actual_paths.len() as f64 - expected_paths.len() as f64).abs()
            / expected_paths.len() as f64;

        println!(
            "\nCount difference: {} ({}%)",
            (actual_paths.len() as i32 - expected_paths.len() as i32),
            count_diff_ratio * 100.0
        );

        // Allow up to 2x the expected paths (could have extra metadata files, etc.)
        assert!(
            actual_paths.len() <= expected_paths.len() * 2,
            "Found {} paths but expected around {}",
            actual_paths.len(),
            expected_paths.len()
        );
        // Lower bound: every expected path must be recovered. A wrong FAT12/16
        // data-area offset (omitting the fixed root-directory region) makes
        // every subdirectory read land in the wrong place, silently dropping
        // their contents — this guards against that regressing.
        assert!(
            actual_paths.len() >= expected_paths.len(),
            "FAT12 recovery regressed: found only {} of {} expected paths (subdirectory recursion broken?)",
            actual_paths.len(),
            expected_paths.len()
        );

        // Verify we have proper subdirectory structure
        let root_entries = actual_paths
            .iter()
            .filter(|p| p.matches('/').count() == 1)
            .count();
        let nested_entries = actual_paths
            .iter()
            .filter(|p| p.matches('/').count() > 1)
            .count();

        println!("\nPath structure:");
        println!("  Root-level entries: {}", root_entries);
        println!("  Nested entries: {}", nested_entries);

        assert!(root_entries > 0, "Should have root-level entries");
        // The image has 513 files nested inside per-digit subdirectories; a
        // healthy recursion recovers them all. > 0 was too weak to catch a
        // recursion that finds only the root level.
        assert!(
            nested_entries >= 500,
            "FAT12 subdirectory recursion regressed: {} nested entries (expected ~513)",
            nested_entries
        );
    }

    #[test]
    fn test_fat_chain_reading() {
        // Test that we can read and parse the FAT table

        use crate::fat_structs::*;

        let Some(data) = load_test_image("fat32_loop.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        // Read boot sector
        let mut boot_sector_data = vec![0u8; 512];
        data_source.read_at(0, &mut boot_sector_data).unwrap();

        // Parse BPB
        let bpb = BiosParameterBlock::parse(&boot_sector_data).unwrap();
        let sectors_per_fat = bpb.sectors_per_fat();
        let fat_type = bpb.determine_fat_type(sectors_per_fat);

        let extended = match fat_type {
            FatType::Fat32 => {
                FatExtendedBpb::Fat32(Fat32ExtendedBpb::parse(&boot_sector_data).unwrap())
            }
            _ => FatExtendedBpb::Fat16(Fat16ExtendedBpb::parse(&boot_sector_data).unwrap()),
        };

        let boot_sector = FatBootSector {
            bpb: bpb.clone(),
            extended,
            fat_type,
        };

        // This test just verifies the FAT table structure is accessible
        // More comprehensive tests will be added when we integrate FAT chain reading
        println!("FAT type: {:?}", boot_sector.fat_type);
        println!("Sectors per FAT: {}", sectors_per_fat);
    }

    #[test]
    fn test_fat16_moved() {
        // Test FAT16 with moved files
        let Some(data) = load_test_image("fat16_moved.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat16_moved_test"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();
        assert!(!artifacts.is_empty());
        assert_eq!(fat_type_of(&artifacts), Some("Fat16"));

        println!("FAT16 moved test produced {} artifacts", artifacts.len());
    }

    #[test]
    fn test_fat_noloop() {
        // Test FAT filesystem without loops (corruption test)
        let Some(data) = load_test_image("fat_noloop.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat_noloop_test"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        if !artifacts.is_empty() {
            println!("FAT noloop test produced {} artifacts", artifacts.len());
            // Should parse without infinite loops
            assert!(artifacts.len() < 100000, "Detected potential infinite loop");
        }
    }

    #[test]
    fn test_exfat_encrypted() {
        let Some(data) = load_test_image("exfat_encrypted.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "exfat_encrypted"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        // Should parse exFAT filesystem
        assert!(!artifacts.is_empty(), "exFAT should return artifacts");

        assert!(is_exfat(&artifacts), "expected exFAT geometry record");
        assert_no_minted_filesystem(&artifacts);

        println!("exFAT encrypted: parsed {} artifacts", artifacts.len());
    }

    #[test]
    fn test_exfat_lin_part() {
        // This image contains a full disk with MBR partition table
        // The exFAT filesystem starts at sector 2048 (1MB offset)
        // We need to skip to the partition start
        let Some(full_disk) = load_test_image("exfat_lin_part.raw.gz") else {
            return;
        };

        // Extract just the exFAT partition (starts at sector 2048)
        let partition_offset = 2048 * 512;
        let partition_data = full_disk[partition_offset..].to_vec();

        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(partition_data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "exfat_lin_part"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        // Should parse exFAT filesystem
        assert!(!artifacts.is_empty(), "exFAT should return artifacts");

        assert!(is_exfat(&artifacts), "expected exFAT geometry record");
        assert_no_minted_filesystem(&artifacts);

        // Count file entries
        let file_count = artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .count();

        println!(
            "exFAT Linux partition: parsed {} total artifacts, {} files",
            artifacts.len(),
            file_count
        );
    }

    #[test]
    fn test_exfat_win() {
        let Some(data) = load_test_image("exfat_win.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "exfat_win"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        // Should parse exFAT filesystem
        assert!(!artifacts.is_empty(), "exFAT should return artifacts");

        assert!(is_exfat(&artifacts), "expected exFAT geometry record");
        assert_no_minted_filesystem(&artifacts);

        // Verify we have file entries
        let file_count = artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .count();

        println!(
            "exFAT Windows: parsed {} total artifacts, {} files",
            artifacts.len(),
            file_count
        );

        // Verify file metadata structure
        if let Some(file_artifact) = artifacts
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
        {
            assert!(file_artifact.metadata.get("name").is_some());
            assert!(file_artifact.metadata.get("path").is_some());
            assert!(file_artifact.metadata.get("size").is_some());
            assert!(file_artifact.metadata.get("attributes").is_some());
        }
    }

    /// Find the allocation_map ParsedRecord and check the contract fields
    fn assert_allocation_map(artifacts: &[Artifact], expected_cluster_size: u64) -> &Artifact {
        // The FAT parser must NOT mint its own FileSystem artifact (the
        // partition plugin owns that); doing so re-triggers this module on its
        // own output and cascades without bound.
        assert!(
            !artifacts
                .iter()
                .any(|a| a.artifact_type == ArtifactType::FileSystem),
            "FAT parser must not create a FileSystem artifact"
        );

        let map = artifacts
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::ParsedRecord
                    && a.metadata["type"] == "allocation_map"
            })
            .expect("allocation_map artifact should be emitted");

        let meta = &map.metadata;
        assert_eq!(meta["allocation_cluster_size"], expected_cluster_size);
        let total = meta["allocation_total_clusters"].as_u64().unwrap();
        assert!(total > 0);
        let cpb = meta["allocation_clusters_per_bucket"].as_u64().unwrap();
        assert!(cpb >= 1);

        use base64::Engine as _;
        let buckets = base64::engine::general_purpose::STANDARD
            .decode(meta["allocation_bitmap_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(buckets.len() as u64, total.div_ceil(cpb));
        assert!(buckets.len() as u64 <= 65536);
        map
    }

    #[test]
    fn test_fat_allocation_map() {
        let Some(data) = load_test_image("fat16.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat16_alloc"}),
        );

        let artifacts = FatParser.process(&artifact).unwrap();
        assert!(artifacts.len() > 1);

        // Geometry now lives on the allocation-map record itself.
        let map0 = artifacts
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("allocation_map"))
            .expect("allocation_map record");
        let fs_clusters = map0.metadata["allocation_total_clusters"].as_u64().unwrap();
        let cluster_size = map0.metadata["bytes_per_sector"].as_u64().unwrap()
            * map0.metadata["sectors_per_cluster"].as_u64().unwrap();

        let map = assert_allocation_map(&artifacts, cluster_size);
        assert_eq!(
            map.metadata["allocation_total_clusters"].as_u64().unwrap(),
            fs_clusters
        );

        // A used filesystem must show at least one allocated bucket
        use base64::Engine as _;
        let buckets = base64::engine::general_purpose::STANDARD
            .decode(map.metadata["allocation_bitmap_b64"].as_str().unwrap())
            .unwrap();
        assert!(
            buckets.iter().any(|&b| b > 0),
            "expected allocated clusters in the map"
        );
    }

    #[test]
    fn test_fat_data_runs_contract() {
        let Some(data) = load_test_image("fat32_loop.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat32_runs"}),
        );

        let artifacts = FatParser.process(&artifact).unwrap();

        let files_with_content: Vec<&Artifact> = artifacts
            .iter()
            .filter(|a| {
                a.artifact_type == ArtifactType::FileEntry
                    && !a.metadata["is_directory"].as_bool().unwrap_or(true)
                    && a.metadata["size"].as_u64().unwrap_or(0) > 0
                    && a.data.is_some()
            })
            .collect();
        assert!(
            !files_with_content.is_empty(),
            "expected files with content"
        );

        for file in &files_with_content {
            let runs = file.metadata["data_runs"]
                .as_array()
                .unwrap_or_else(|| panic!("missing data_runs on {}", file.metadata["name"]));
            assert!(!runs.is_empty());
            assert!(file.metadata["data_runs_complete"].is_boolean());

            // Runs must cover at least the file size
            let covered: u64 = runs.iter().map(|r| r[1].as_u64().unwrap()).sum();
            let size = file.metadata["size"].as_u64().unwrap();
            if file.metadata["data_runs_complete"].as_bool().unwrap() {
                assert!(covered >= size, "runs cover {} < size {}", covered, size);
            }
        }

        // Every FileEntry carries path and parent_path
        for entry in artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        {
            assert!(entry.metadata["path"].as_str().unwrap().starts_with('/'));
            assert!(entry.metadata["parent_path"]
                .as_str()
                .unwrap()
                .starts_with('/'));
        }
    }

    #[test]
    fn test_exfat_allocation_map_and_data_runs() {
        let Some(data) = load_test_image("exfat_win.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "exfat_contract"}),
        );

        let artifacts = FatParser.process(&artifact).unwrap();
        assert!(is_exfat(&artifacts), "expected exFAT geometry record");

        let map0 = alloc_map(&artifacts).expect("allocation_map record");
        let cluster_size = map0.metadata["bytes_per_sector"].as_u64().unwrap()
            * map0.metadata["sectors_per_cluster"].as_u64().unwrap();
        assert_allocation_map(&artifacts, cluster_size);

        // Files with content persist data runs; all entries carry paths
        for entry in artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        {
            assert!(entry.metadata["path"].as_str().unwrap().starts_with('/'));
            assert!(entry.metadata["parent_path"]
                .as_str()
                .unwrap()
                .starts_with('/'));
            if entry.data.is_some() {
                assert!(
                    entry.metadata["data_runs"].is_array(),
                    "missing data_runs on {}",
                    entry.metadata["name"]
                );
                assert!(entry.metadata["data_runs_complete"].is_boolean());
            }
        }
        assert!(
            artifacts
                .iter()
                .any(|a| a.artifact_type == ArtifactType::FileEntry && a.data.is_some()),
            "expected at least one file with content"
        );
    }

    #[test]
    fn test_file_content_reading() {
        // Test that we can read file content from FAT and exFAT filesystems
        let Some(data) = load_test_image("fat32_loop.raw.gz") else {
            return;
        };
        let data_source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));

        let case_id = Uuid::new_v4();
        let artifact = Artifact::new(
            case_id,
            ArtifactType::Partition,
            Some(data_source),
            json!({"name": "fat32_test"}),
        );

        let parser = FatParser;
        let result = parser.process(&artifact);

        assert!(result.is_ok());
        let artifacts = result.unwrap();

        // Find a file entry with content
        let file_with_content = artifacts.iter().find(|a| {
            a.artifact_type == ArtifactType::FileEntry
                && a.data.is_some()
                && a.metadata["size"].as_u64().unwrap_or(0) > 0
                && !a.metadata["is_directory"].as_bool().unwrap_or(true)
        });

        if let Some(file_artifact) = file_with_content {
            let size = file_artifact.metadata["size"].as_u64().unwrap();
            println!(
                "Testing file: {} (size: {} bytes)",
                file_artifact.metadata["name"], size
            );

            // Try to read some content
            if let Some(ref data_source) = file_artifact.data {
                let mut buf = vec![0u8; std::cmp::min(size, 1024) as usize];
                let read_result = data_source.read_at(0, &mut buf);

                assert!(read_result.is_ok());
                let bytes_read = read_result.unwrap();
                assert!(bytes_read > 0, "Should read at least some bytes");
                assert_eq!(
                    data_source.size(),
                    size,
                    "DataSource size should match metadata"
                );

                println!("Successfully read {} bytes from file", bytes_read);
            }
        } else {
            // If no files with content, that's okay for this test image
            println!("No files with content found in test image (may be normal for this image)");
        }
    }
}

/// FAT-001. The extended boot signature (0x29) is what declares that the volume
/// id, label and filesystem-type fields exist. It was read and discarded, so on
/// a volume without an extended BPB -- many FAT12 floppies -- whatever bytes the
/// formatter left at those offsets were read as a volume label anyway.
///
/// Decoding through CP437 made this worse rather than better: the arbitrary
/// bytes stopped rendering as visible U+FFFD garbage and started rendering as
/// plausible text, which an examiner would take for a name somebody chose.
///
/// Against the unfixed code the volume record carries a label built from those
/// bytes.
#[test]
fn a_volume_with_no_extended_bpb_is_not_given_a_label_from_whatever_was_there() {
    let mut img = build_fat16_image_with_oem_names(b"README  TXT", b"REALLABEL  ");
    // No extended BPB: clear the signature and fill its fields with the kind of
    // arbitrary bytes a formatter leaves behind.
    img[38] = 0x00;
    img[43..54].copy_from_slice(&[
        0x80, 0x9C, 0x9D, 0x9F, 0xE1, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    ]);
    let out = parse_oem_image(img);

    let map = out
        .iter()
        .find(|a| a.metadata["type"] == "allocation_map")
        .expect("the volume record must still be emitted");
    let label = map.metadata["volume_label"].as_str().unwrap_or("");
    assert_eq!(
        label, "",
        "with no 0x29 signature those bytes declare nothing; a label must not be \
         invented from them, and it read as {label:?}"
    );
    assert!(
        map.metadata.get("path_decode").is_none(),
        "nothing was decoded, so no code page may be claimed"
    );
}

/// **A FAT volume's free clusters become regions a carver reads**
/// (`ROADMAP` §5.4).
///
/// The FAT *is* this filesystem's allocation map, so the bits are synthesised
/// from it, and three readings matter rather than two: a zero entry is free,
/// any other value is in use — the bad-cluster marker and the reserved value 1
/// included, neither of which may be carved as free — and **no entry at all**,
/// past what the FAT actually holds, is unassessed rather than free.
#[test]
fn the_free_clusters_of_a_fat_volume_become_carvable_regions() {
    // Clusters 2 and 3 allocated into a chain; everything else free.
    let img = build_fat16_image_with_subdir(&[(2, 3), (3, 0xFFFF)]);
    let source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        json!({"name": "fat volume"}),
    );
    let out = FatParser.process(&artifact).unwrap();

    let map = out
        .iter()
        .find(|a| a.metadata["type"] == "allocation_map")
        .expect("the allocation map");
    let regions: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .collect();
    assert!(
        !regions.is_empty(),
        "a volume with two clusters in use has free clusters"
    );
    assert_eq!(
        regions.len(),
        map.metadata["free_regions_emitted"].as_u64().unwrap() as usize
    );
    for region in &regions {
        let first = region.metadata["first_cluster"].as_u64().unwrap();
        assert!(
            first >= 2,
            "clusters 0 and 1 are the FAT's own reserved entries and are not data clusters"
        );
        assert!(
            first > 3,
            "clusters 2 and 3 are the chain in use; a region over them would mean a non-zero \
             FAT entry was read as free"
        );
        assert_eq!(region.metadata["filesystem"], "FAT16");
        assert_eq!(
            region.data.as_ref().map(|d| d.size()),
            region.metadata["size_bytes"].as_u64(),
            "the window is the length the record declares"
        );
        assert!(region.metadata["offset_basis"]
            .as_str()
            .unwrap_or_default()
            .contains("not the start of the evidence"));
    }
}

/// A cluster the FAT marks **bad** is not free space.
///
/// `0xFFF7` on FAT16 is the bad-cluster marker. It is not a zero entry and a
/// region over it would offer an examiner a carve out of media the filesystem
/// itself has written off — and, worse, would be a region the bitmap route
/// claims is free.
#[test]
fn a_cluster_the_fat_marks_bad_is_never_reported_as_free() {
    let img = build_fat16_image_with_subdir(&[(2, 3), (3, 0xFFFF), (4, 0xFFF7)]);
    let source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        json!({"name": "fat volume"}),
    );
    let out = FatParser.process(&artifact).unwrap();
    for region in out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
    {
        let first = region.metadata["first_cluster"].as_u64().unwrap();
        let clusters = region.metadata["clusters"].as_u64().unwrap();
        assert!(
            4 < first || 4 >= first + clusters,
            "cluster 4 is marked bad and a region at {first}+{clusters} covers it"
        );
    }
}

/// **The free clusters of a real exFAT volume become carvable regions**
/// (`ROADMAP` §5.4), on a volume from the `dfir_ntfs` project's own corpus with
/// an `fls`-style listing beside it.
///
/// This is the image that settles what a hand-built fixture cannot. exFAT's
/// first bitmap bit is cluster **2**, and cluster 2 sits at the start of the
/// **cluster heap**, not at the start of the volume — here 0x20000 bytes in —
/// so a base of zero would put every region 128 KiB from where its bytes are,
/// at an offset that is perfectly plausible.
///
/// `exfat_lin_part.raw` carries a second discrimination the offset-zero images
/// cannot: the volume sits at 0x100000 inside a partitioned image, so the
/// regions' offsets must be relative to the **volume** and not to the image.
/// The test hands the parser the volume window, which is what the filesystem
/// detector does in a real ingest, and asserts the offsets fall inside it.
#[test]
fn the_free_clusters_of_a_real_exfat_volume_become_carvable_regions() {
    let Some(image) = integration_tests::load_test_image("exfat_lin_part.raw.gz") else {
        return;
    };
    // The volume, as the partition layer would hand it over.
    const VOLUME_AT: usize = 0x100000;
    assert_eq!(
        &image[VOLUME_AT + 3..VOLUME_AT + 11],
        b"EXFAT   ",
        "the corpus image holds its exFAT volume at 0x100000"
    );
    let volume = image[VOLUME_AT..].to_vec();
    let volume_bytes = volume.len() as u64;
    let source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(volume));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        json!({"name": "exfat volume", "filesystem_type": "exFAT"}),
    );
    let out = FatParser.process(&artifact).unwrap();

    let map = out
        .iter()
        .find(|a| a.metadata["type"] == "allocation_map")
        .expect("a real exFAT volume publishes its allocation map");
    assert_eq!(map.metadata["fs_type"], "exFAT");
    let cluster_size = map.metadata["allocation_cluster_size"].as_u64().unwrap();
    assert_eq!(cluster_size, 4096, "512-byte sectors, 8 per cluster");

    let regions: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .collect();
    eprintln!(
        "  exFAT: {} cluster(s) of {cluster_size} bytes; {} free region(s), {} bytes, \
         {} run(s) dropped, {} cluster(s) unassessed",
        map.metadata["allocation_total_clusters"],
        map.metadata["free_regions_emitted"],
        map.metadata["free_bytes_emitted"],
        map.metadata["free_runs_dropped"],
        map.metadata["free_space_unassessed_clusters"],
    );
    assert!(
        !regions.is_empty(),
        "a 64 MiB exFAT volume holding a handful of files has free clusters"
    );

    // The bitmap is 2,012 bytes -- the listing beside the image says so -- which
    // is 16,096 bits for exactly the 16,096 clusters the boot sector declares.
    // So the whole volume is assessed and nothing is unknown.
    assert_eq!(
        map.metadata["free_space_unassessed_clusters"], 0,
        "$ALLOC_BITMAP is 2,012 bytes = 16,096 bits = the volume's own cluster count, so every \
         cluster is accounted for"
    );

    let heap_base = 0x20000u64;
    let mut previous_end = 0u64;
    for region in &regions {
        let offset = region.metadata["offset_bytes"].as_u64().expect("offset");
        let size = region.metadata["size_bytes"].as_u64().expect("size");
        let first_cluster = region.metadata["first_cluster"].as_u64().expect("cluster");
        assert!(size > 0);
        assert!(
            first_cluster >= 2,
            "exFAT numbers data clusters from 2; cluster {first_cluster} is a reserved entry"
        );
        // The discrimination a fixture at offset zero cannot make.
        assert_eq!(
            offset,
            heap_base + (first_cluster - 2) * cluster_size,
            "a cluster's offset is measured from the CLUSTER HEAP at {heap_base:#x}, not from \
             the start of the volume -- a base of zero would put this region 128 KiB out, at an \
             offset that would look entirely ordinary"
        );
        assert!(
            offset >= heap_base,
            "no region may fall before the cluster heap: the boot region, the FAT and the \
             bitmap itself live there and are not free space"
        );
        assert!(
            offset + size <= volume_bytes,
            "a region at {offset}+{size} reaches past the volume's {volume_bytes} bytes -- the \
             offsets are relative to the volume, not to the image the volume sits inside"
        );
        assert!(
            offset >= previous_end,
            "regions overlap or are out of order"
        );
        assert_eq!(region.metadata["filesystem"], "exFAT");
        assert_eq!(
            region.data.as_ref().map(|d| d.size()),
            Some(size),
            "the window is the length the record declares"
        );
        previous_end = offset + size;
    }
}

/// ROADMAP §5.10: the allocation-map downsample. The reference here is the
/// bit-by-bit walk the tree shipped with, kept verbatim so the byte-oriented
/// builder that replaced it can be held to its output bucket for bucket, and a
/// fingerprint of what each real image produced before the change.
#[cfg(test)]
mod allocation_map_downsample {
    use super::*;
    use crate::fat_parser::{build_allocation_buckets_from_bitmap, MAX_ALLOCATION_BUCKETS};
    use base64::Engine as _;
    use std::time::Instant;

    /// The walk as it was: one closure call per cluster.
    fn reference_bit_by_bit(
        total_clusters: u64,
        mut is_allocated: impl FnMut(u64) -> bool,
    ) -> (Vec<u8>, u64) {
        let clusters_per_bucket = total_clusters.div_ceil(MAX_ALLOCATION_BUCKETS).max(1);
        let bucket_count = total_clusters.div_ceil(clusters_per_bucket);
        let mut buckets = Vec::with_capacity(bucket_count as usize);
        let mut cluster: u64 = 0;
        while cluster < total_clusters {
            let in_bucket = clusters_per_bucket.min(total_clusters - cluster);
            let mut allocated: u64 = 0;
            for i in cluster..cluster + in_bucket {
                if is_allocated(i) {
                    allocated += 1;
                }
            }
            buckets.push(((allocated * 255) / in_bucket) as u8);
            cluster += in_bucket;
        }
        (buckets, clusters_per_bucket)
    }

    fn fnv1a(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
        })
    }

    /// A deterministic bitmap whose bytes are mixed enough that a bucket
    /// boundary falls on every bit position.
    fn synthetic_bitmap(bytes: usize) -> Vec<u8> {
        let mut state = 0x9E3779B97F4A7C15u64;
        (0..bytes)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// `partition_offset` skips a leading partition table: `fat64` and
    /// `exfat_lin_part` are whole-disk images whose volume starts at 1 MiB.
    fn real_image_map(name: &str, partition_offset: usize) -> Option<(Vec<u8>, u64, u64)> {
        let data = super::integration_tests::load_test_image(name)?[partition_offset..].to_vec();
        let source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(source),
            json!({"name": name}),
        );
        let artifacts = FatParser.process(&artifact).unwrap();
        let map = artifacts
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("allocation_map"))
            .expect("allocation_map record");
        let buckets = base64::engine::general_purpose::STANDARD
            .decode(map.metadata["allocation_bitmap_b64"].as_str().unwrap())
            .unwrap();
        Some((
            buckets,
            map.metadata["allocation_clusters_per_bucket"]
                .as_u64()
                .unwrap(),
            map.metadata["allocation_total_clusters"].as_u64().unwrap(),
        ))
    }

    #[test]
    fn bitmap_buckets_match_the_bit_by_bit_walk_at_every_boundary() {
        let bitmap = synthetic_bitmap(70_000);
        // Cluster counts chosen so clusters-per-bucket is 1, 2, 3, 8 and 9,
        // the last bucket is short, and the bit range ends mid-byte.
        for total in [
            1u64, 7, 8, 9, 65_536, 65_537, 131_071, 131_072, 131_073, 196_607, 524_288, 524_289,
            559_997,
        ] {
            let bytes_needed = (total as usize).div_ceil(8);
            let bits = &bitmap[..bytes_needed];
            let expected =
                reference_bit_by_bit(total, |i| bits[(i / 8) as usize] & (1 << (i % 8)) != 0);
            let actual = build_allocation_buckets_from_bitmap(total, bits);
            assert_eq!(actual, expected, "total_clusters = {total}");
        }
    }

    #[test]
    fn clusters_past_the_bitmap_count_as_unallocated_as_they_did_before() {
        let bitmap = synthetic_bitmap(1_000);
        let total = 9_000;
        let expected = reference_bit_by_bit(total, |i| {
            bitmap
                .get((i / 8) as usize)
                .is_some_and(|b| b & (1 << (i % 8)) != 0)
        });
        assert_eq!(
            build_allocation_buckets_from_bitmap(total, &bitmap),
            expected
        );
        assert_eq!(
            build_allocation_buckets_from_bitmap(0, &bitmap),
            (Vec::new(), 1)
        );
    }

    #[test]
    fn real_images_downsample_to_the_map_they_did_before() {
        // Fingerprints of the bucket vectors the per-cluster walk produced on
        // 2026-09-19, before the byte-oriented builder replaced it.
        for (name, offset, buckets_len, cpb, total, fnv) in [
            ("fat12.raw.gz", 0, 2036, 1, 2036, 0x8b0a89867bb54a76u64),
            ("fat16.raw.gz", 0, 6123, 1, 6123, 0xf169baa3861432b4),
            ("fat32_loop.raw.gz", 0, 64511, 2, 129022, 0x2aa6e880540e1024),
            ("exfat_win.raw.gz", 0, 12032, 1, 12032, 0x2a1c7e644cf4fe3d),
            ("win_exfat_7.raw.gz", 0, 1504, 1, 1504, 0x42fceebcff0396ce),
            (
                "exfat_lin_part.raw.gz",
                2048 * 512,
                16096,
                1,
                16096,
                0xc81ea6335be1049b,
            ),
            // Added 2026-09-23 with HUNT-157: before the 64-bit sector count
            // was read this image produced no allocation map at all.
            (
                "fat64.raw.gz",
                2048 * 512,
                63503,
                2,
                127006,
                0xacb92ebb2cd81b3e,
            ),
        ] {
            let Some((buckets, got_cpb, got_total)) = real_image_map(name, offset) else {
                continue;
            };
            assert_eq!(buckets.len(), buckets_len, "{name}: bucket count");
            assert_eq!(got_cpb, cpb, "{name}: clusters per bucket");
            assert_eq!(got_total, total, "{name}: total clusters");
            assert_eq!(fnv1a(&buckets), fnv, "{name}: bucket bytes changed");
        }
    }

    /// Not an assertion, a measurement: a 1 TB exFAT volume at 32 KiB clusters
    /// has a 4 MiB allocation bitmap. Recorded on 2026-09-19 (this host, debug
    /// / release): bit by bit 431 ms / 150 ms; by byte, see the run.
    #[test]
    fn measure_downsample_of_a_terabyte_exfat_bitmap() {
        let bitmap = synthetic_bitmap(4 * 1024 * 1024);
        let total = bitmap.len() as u64 * 8;
        let start = Instant::now();
        let (reference, _) =
            reference_bit_by_bit(total, |i| bitmap[(i / 8) as usize] & (1 << (i % 8)) != 0);
        let bit_by_bit = start.elapsed();
        let start = Instant::now();
        let (buckets, cpb) = build_allocation_buckets_from_bitmap(total, &bitmap);
        let by_byte = start.elapsed();
        assert_eq!(buckets, reference);
        eprintln!(
            "exFAT-shaped bitmap: {} bytes, {total} clusters, cpb {cpb}, {} buckets: \
             bit by bit {bit_by_bit:?}, by byte {by_byte:?}",
            bitmap.len(),
            buckets.len(),
        );
    }
}

/// HUNT-157: a FAT32 volume whose sector count is carried only in the
/// non-standard 64-bit field at boot-sector offset 82 (both standard counts
/// zero, boot signature 0x29). Read as zero sectors, the volume produced no
/// allocation map and no files.
#[cfg(test)]
mod fat32_totsec64 {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    /// `mkfs.fat -F 32 -s 1 -n SEANCE64` on a 34 MiB file, three files and a
    /// directory copied in with `mcopy`/`mmd`, then the 32-bit count at offset
    /// 32 moved into the 64-bit field at offset 82 in both the boot sector
    /// and its backup at sector 6 -- the shape of `dfir_ntfs`'s `fat64.raw`.
    fn fixture() -> Vec<u8> {
        let gz = include_bytes!("../tests/fixtures/fat32_totsec64.raw.gz");
        let mut data = Vec::new();
        GzDecoder::new(&gz[..]).read_to_end(&mut data).unwrap();
        data
    }

    fn parse(data: Vec<u8>) -> Vec<Artifact> {
        let source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(source),
            json!({"name": "fat32_totsec64"}),
        );
        FatParser.process(&artifact).unwrap()
    }

    fn names(artifacts: &[Artifact]) -> Vec<String> {
        artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn the_64_bit_count_is_read_when_both_standard_counts_are_zero() {
        let data = fixture();
        let bpb = BiosParameterBlock::parse(&data[..512]).unwrap();
        assert_eq!((bpb.total_sectors_16, bpb.total_sectors_32), (0, 0));
        assert_eq!(bpb.total_sectors(), 69_632);
    }

    #[test]
    fn a_fat32_volume_sized_by_the_64_bit_field_is_walked() {
        let artifacts = parse(fixture());
        let map = artifacts
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("allocation_map"))
            .expect("an allocation map for the volume");
        assert_eq!(map.metadata["fat_type"], "Fat32");
        assert_eq!(map.metadata["total_sectors"], 69_632);
        assert_eq!(map.metadata["total_sectors_source"], "bs_totsec64");
        let names = names(&artifacts);
        for want in ["note.txt", "LongerFileName.txt", "subdir", "inner.txt"] {
            assert!(
                names.iter().any(|n| n == want),
                "{want} missing from {names:?}"
            );
        }
    }

    /// The field is read only under dfir_ntfs's three-way condition: on a
    /// FAT32 boot sector without the 0x29 signature, offset 82 is the
    /// file-system-type string and is not a count.
    #[test]
    fn the_64_bit_field_is_not_read_without_the_extended_boot_signature() {
        let mut data = fixture();
        data[66] = 0x28;
        let bpb = BiosParameterBlock::parse(&data[..512]).unwrap();
        assert_eq!(bpb.total_sectors(), 0);
        // And a standard count, when present, wins.
        let mut data = fixture();
        data[32..36].copy_from_slice(&1000u32.to_le_bytes());
        let bpb = BiosParameterBlock::parse(&data[..512]).unwrap();
        assert_eq!(bpb.total_sectors(), 1000);
    }

    /// The real `dfir_ntfs` image (gitignored corpus; skips when absent).
    #[test]
    fn dfir_ntfs_fat64_image_is_walked() {
        let Some(data) = super::integration_tests::load_test_image("fat64.raw.gz") else {
            return;
        };
        let artifacts = parse(data[2048 * 512..].to_vec());
        let map = artifacts
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("allocation_map"))
            .expect("an allocation map for fat64.raw");
        assert_eq!(map.metadata["fat_type"], "Fat32");
        assert_eq!(map.metadata["total_sectors"], 129_024);
        assert!(
            artifacts
                .iter()
                .any(|a| a.artifact_type == ArtifactType::FileEntry),
            "fat64.raw produced no files"
        );
    }
}

// --- HUNT-124: per-file slack regions on FAT.

/// A FAT16 volume (512-byte clusters, cluster 2 right after the one-sector
/// root directory) holding one 900-byte file "SLACK.DAT" on clusters 2-3.
/// `live` chains 2 -> 3 -> EOC in the FAT; otherwise the entry is deleted and
/// the FAT entries are left free. `tail` is planted 10 bytes into the slack of
/// cluster 3 (which starts at byte 388 of that cluster).
fn fat16_with_one_file(live: bool, tail: &[u8]) -> (Vec<u8>, u64) {
    const BPS: usize = 512;
    const SPF: usize = 17;
    const RESERVED: usize = 1;
    const TOTAL_SECTORS: usize = 4200;
    let mut img = vec![0u8; TOTAL_SECTORS * BPS];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = 1;
    img[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    img[16] = 1;
    img[17..19].copy_from_slice(&16u16.to_le_bytes());
    img[19..21].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&(SPF as u16).to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    let fat = RESERVED * BPS;
    img[fat..fat + 2].copy_from_slice(&0xFFF8u16.to_le_bytes());
    img[fat + 2..fat + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
    if live {
        img[fat + 4..fat + 6].copy_from_slice(&3u16.to_le_bytes());
        img[fat + 6..fat + 8].copy_from_slice(&0xFFFFu16.to_le_bytes());
    }
    let root = (RESERVED + SPF) * BPS;
    let cluster2 = (RESERVED + SPF + 1) * BPS;
    for i in 0..900 {
        img[cluster2 + i] = b'a' + (i % 26) as u8;
    }
    let slack_start = cluster2 + 900;
    img[slack_start + 10..slack_start + 10 + tail.len()].copy_from_slice(tail);
    img[root] = if live { b'S' } else { 0xE5 };
    img[root + 1..root + 8].copy_from_slice(b"LACK   ");
    img[root + 8..root + 11].copy_from_slice(b"DAT");
    img[root + 11] = ATTR_ARCHIVE;
    img[root + 26..root + 28].copy_from_slice(&2u16.to_le_bytes());
    img[root + 28..root + 32].copy_from_slice(&900u32.to_le_bytes());
    (img, slack_start as u64)
}

fn parse_fat_image(img: Vec<u8>) -> (Artifact, Vec<Artifact>) {
    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "synthetic.dd", "subtype": "fat16" }),
    );
    let out = FatParser.process(&fs).expect("parse synthetic fat16");
    (fs, out)
}

fn fat_slack_regions(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .collect()
}

#[test]
fn fat_slack_region_for_live_file_with_nonzero_tail() {
    let (img, slack_start) = fat16_with_one_file(true, b"3slack3");
    let (fs, out) = parse_fat_image(img);
    let regions = fat_slack_regions(&out);
    assert_eq!(regions.len(), 1);
    let r = regions[0];
    assert_eq!(r.parent_id, Some(fs.id));
    assert_eq!(r.metadata["offset_bytes"], slack_start);
    assert_eq!(r.metadata["size_bytes"], 512 - 388);
    assert_eq!(r.metadata["filesystem"], "FAT16");
    assert_eq!(r.metadata["parent_file"], "SLACK.DAT");
    let file = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry && a.metadata["name"] == "SLACK.DAT")
        .unwrap();
    assert_eq!(r.metadata["owner_artifact_id"], file.id.to_string());
    let mut got = [0u8; 7];
    r.data.as_ref().unwrap().read_at(10, &mut got).unwrap();
    assert_eq!(&got, b"3slack3");
    let summary = out
        .iter()
        .find(|a| a.metadata["subtype"] == "slack_space_summary")
        .expect("summary");
    assert_eq!(summary.metadata["regions_emitted"], 1);
    assert_eq!(summary.metadata["filesystem"], "FAT16");
}

#[test]
fn no_fat_slack_region_for_deleted_entry() {
    let (img, _) = fat16_with_one_file(false, b"3slack3");
    let (_, out) = parse_fat_image(img);
    assert!(
        fat_slack_regions(&out).is_empty(),
        "a deleted entry's guessed chain is not a proven allocation"
    );
    let summary = out
        .iter()
        .find(|a| a.metadata["subtype"] == "slack_space_summary")
        .expect("summary");
    assert_eq!(summary.metadata["files_offered"], 0);
}

#[test]
fn fat_zero_tail_is_counted_not_emitted() {
    let (img, _) = fat16_with_one_file(true, b"");
    let (_, out) = parse_fat_image(img);
    assert!(fat_slack_regions(&out).is_empty());
    let summary = out
        .iter()
        .find(|a| a.metadata["subtype"] == "slack_space_summary")
        .expect("summary");
    assert_eq!(summary.metadata["zero_tails"], 1);
}

/// HUNT-124 wiring on a real exFAT volume (`exfat_win.raw.gz`, from the
/// dfir_ntfs corpus). There is no published slack ground truth for this
/// image, so this checks shape, not content: every region belongs to a live
/// file the same pass emitted, starts exactly at that file's logical end and
/// stays inside the cluster holding its last byte, and the pass is summarised.
#[test]
fn exfat_real_volume_slack_regions_are_each_inside_their_owners_last_cluster() {
    let Some(data) = integration_tests::load_test_image("exfat_win.raw.gz") else {
        return;
    };
    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({"name": "exfat_win"}),
    );
    let out = FatParser.process(&fs).expect("parse exfat_win");
    let summary = out
        .iter()
        .find(|a| a.metadata["subtype"] == "slack_space_summary")
        .expect("the slack pass is summarised on a real volume");
    assert_eq!(summary.metadata["filesystem"], "exFAT");
    eprintln!("exfat_win slack: {}", summary.metadata["statement"]);
    let offered = summary.metadata["files_offered"].as_u64().unwrap();
    let emitted = summary.metadata["regions_emitted"].as_u64().unwrap();
    let zero = summary.metadata["zero_tails"].as_u64().unwrap();
    let unreadable = summary.metadata["unreadable_tails"].as_u64().unwrap();
    assert!(
        offered > 0,
        "a real volume has files with a partial last cluster"
    );
    assert_eq!(offered, emitted + zero + unreadable);
    for r in out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
    {
        let owner_id = r.metadata["owner_artifact_id"].as_str().unwrap();
        let owner = out
            .iter()
            .find(|a| a.id.to_string() == owner_id)
            .expect("owner emitted by the same pass");
        let cluster = r.metadata["cluster_size"].as_u64().unwrap();
        let size = owner.metadata["size"].as_u64().unwrap();
        assert_eq!(
            r.metadata["size_bytes"].as_u64().unwrap(),
            cluster - size % cluster
        );
        let runs = owner.metadata["data_runs"].as_array().unwrap();
        let mut logical = 0u64;
        let mut phys_end = None;
        for run in runs {
            let len = run[1].as_u64().unwrap();
            if size <= logical + len {
                phys_end = Some(run[0].as_u64().unwrap() + (size - logical));
                break;
            }
            logical += len;
        }
        assert_eq!(r.metadata["offset_bytes"].as_u64(), phys_end);
    }
}

/// A live file with a tail whose run list cannot say where the tail is — a
/// chain cut short, a run list truncated at the metadata ceiling, or an exFAT
/// unwritten tail — is counted as not located, not dropped silently: a volume
/// of fragmented files must not read as one with no slack-bearing files.
/// Deleted entries, directories and cluster-aligned sizes are not counted.
#[test]
fn fat_live_file_whose_tail_cannot_be_located_is_counted() {
    let vol: Arc<dyn DataSource> = Arc::new(MockFatSource::new(vec![0u8; 64 * 1024]));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::clone(&vol)),
        json!({"name": "vol"}),
    );
    let entry = |md: serde_json::Value| {
        Artifact::new(fs.case_id, ArtifactType::FileEntry, None, md).with_parent(fs.id)
    };
    let mut slack = crate::fat_parser::fat_slack_collector("FAT16", 512);
    // Counted: the chain is incomplete / the run list does not reach the tail.
    for md in [
        json!({"name": "A", "size": 1000, "data_runs": [[4096, 512]], "data_runs_complete": false}),
        json!({"name": "B", "size": 1000, "data_runs": [[4096, 1024]], "data_runs_complete": true, "cluster_chain_incomplete": true}),
        json!({"name": "C", "size": 1000, "data_runs": [[4096, 512]], "data_runs_complete": true}),
        json!({"name": "D", "size": 1000, "data_runs": [[4096, 512], [null, 512]], "data_runs_complete": true, "has_unwritten_tail": true}),
    ] {
        crate::fat_parser::offer_file_slack(&mut slack, &fs, &vol, &entry(md), 512);
    }
    // Not counted: deleted, directory, whole clusters.
    for md in [
        json!({"name": "E", "size": 1000, "deleted": true, "data_runs_complete": false}),
        json!({"name": "F", "size": 1000, "is_directory": true, "data_runs_complete": false}),
        json!({"name": "G", "size": 1024, "data_runs": [[4096, 512]], "data_runs_complete": false}),
    ] {
        crate::fat_parser::offer_file_slack(&mut slack, &fs, &vol, &entry(md), 512);
    }
    assert_eq!(slack.outcome().files_not_located, 4);
    assert_eq!(slack.outcome().files_offered, 0);
}

/// HUNT-275: a directory whose parent entry is gone is found by its own `.`
/// entry in a free cluster. Its entries are recovered as deleted, the path
/// names the cluster and not a folder, and an ordinary free cluster, or one
/// whose `.` points elsewhere, is not mistaken for a directory.
#[test]
fn a_directory_left_in_a_free_cluster_is_recovered_and_labelled() {
    const CLUSTER_5: usize = (1 + 17 + 1) * 512 + 3 * 512;
    const CLUSTER_6: usize = CLUSTER_5 + 512;

    let mut img = build_fat16_image_with_subdir(&[(2, 0xFFFF)]);
    let put = |img: &mut Vec<u8>, at: usize, name: &[u8; 11], attr: u8, cluster: u16| {
        img[at..at + 11].copy_from_slice(name);
        img[at + 11] = attr;
        img[at + 26..at + 28].copy_from_slice(&cluster.to_le_bytes());
    };
    put(&mut img, CLUSTER_5, b".          ", ATTR_DIRECTORY, 5);
    put(&mut img, CLUSTER_5 + 32, b"..         ", ATTR_DIRECTORY, 0);
    put(&mut img, CLUSTER_5 + 64, b"SECRET  TXT", ATTR_ARCHIVE, 9);
    // A look-alike whose `.` names another cluster is not accepted.
    put(&mut img, CLUSTER_6, b".          ", ATTR_DIRECTORY, 40);
    put(&mut img, CLUSTER_6 + 32, b"..         ", ATTR_DIRECTORY, 0);
    // forensic-lint: allow RAGGED-STRING — an 8.3 directory name, space-padded by the format.
    put(&mut img, CLUSTER_6 + 64, b"DECOY   TXT", ATTR_ARCHIVE, 9);

    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "orphan.dd", "subtype": "fat16" }),
    );
    let out = FatParser.process(&fs).expect("parse must complete");

    let found: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["orphan_directory_cluster"] == json!(5))
        .collect();
    assert_eq!(found.len(), 1, "only SECRET.TXT is under the orphan");
    let secret = found[0];
    assert_eq!(secret.metadata["deleted"], json!(true));
    assert_eq!(secret.metadata["recovered_from_free_space"], json!(true));
    assert_eq!(secret.metadata["orphan_parent_cluster"], json!(0));
    assert_eq!(
        secret.metadata["path"],
        json!("/[orphaned directory, cluster 5]/SECRET.TXT")
    );
    assert!(secret.metadata["path_basis"]
        .as_str()
        .expect("the path says what it is")
        .contains("not a folder"));
    assert!(
        !out.iter().any(|a| a.metadata["name"] == json!("DECOY.TXT")),
        "a '.' that names another cluster is not a directory"
    );

    let map = out
        .iter()
        .find(|a| a.metadata["type"] == json!("allocation_map"))
        .expect("allocation map");
    assert_eq!(
        map.metadata["orphan_directory_scan"]["directories_found"],
        json!(1)
    );
    assert!(
        map.metadata
            .get("orphan_directory_scan_incomplete")
            .is_none(),
        "a small volume is scanned in full"
    );
}

/// HUNT-278: an orphaned directory's `..` names a cluster. When that cluster is
/// a directory the live walk reached, the record says which path that is
/// *now* — a statement about the volume today, not about where the directory
/// sat when it was deleted, since the cluster may have been reused. A `..` that
/// names nothing reached carries no path.
#[test]
fn an_orphan_names_the_live_directory_its_dotdot_resolves_to_without_claiming_it_was_the_parent() {
    const CLUSTER_5: usize = (1 + 17 + 1) * 512 + 3 * 512;
    const CLUSTER_6: usize = CLUSTER_5 + 512;
    const CLUSTER_7: usize = CLUSTER_6 + 512;

    let mut img = build_fat16_image_with_subdir(&[(2, 0xFFFF)]);
    let put = |img: &mut Vec<u8>, at: usize, name: &[u8; 11], attr: u8, cluster: u16| {
        img[at..at + 11].copy_from_slice(name);
        img[at + 11] = attr;
        img[at + 26..at + 28].copy_from_slice(&cluster.to_le_bytes());
    };
    // Under the live directory SUB (cluster 2).
    put(&mut img, CLUSTER_5, b".          ", ATTR_DIRECTORY, 5);
    put(&mut img, CLUSTER_5 + 32, b"..         ", ATTR_DIRECTORY, 2);
    // forensic-lint: allow RAGGED-STRING — an 8.3 directory name, space-padded by the format.
    put(&mut img, CLUSTER_5 + 64, b"A       TXT", ATTR_ARCHIVE, 9);
    // Under the root.
    put(&mut img, CLUSTER_6, b".          ", ATTR_DIRECTORY, 6);
    put(&mut img, CLUSTER_6 + 32, b"..         ", ATTR_DIRECTORY, 0);
    // forensic-lint: allow RAGGED-STRING — an 8.3 directory name, space-padded by the format.
    put(&mut img, CLUSTER_6 + 64, b"B       TXT", ATTR_ARCHIVE, 9);
    // Under a cluster nothing reached.
    put(&mut img, CLUSTER_7, b".          ", ATTR_DIRECTORY, 7);
    put(&mut img, CLUSTER_7 + 32, b"..         ", ATTR_DIRECTORY, 99);
    // forensic-lint: allow RAGGED-STRING — an 8.3 directory name, space-padded by the format.
    put(&mut img, CLUSTER_7 + 64, b"C       TXT", ATTR_ARCHIVE, 9);

    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "orphan.dd", "subtype": "fat16" }),
    );
    let out = FatParser.process(&fs).expect("parse must complete");
    let under = |cluster: u32| -> &Artifact {
        out.iter()
            .find(|a| a.metadata["orphan_directory_cluster"] == json!(cluster))
            .expect("the orphan's entry is recovered")
    };

    let a = under(5);
    assert_eq!(a.metadata["orphan_parent_path_now"], json!("/SUB"));
    assert!(a.metadata["orphan_parent_path_basis"]
        .as_str()
        .expect("the claim is bounded")
        .contains("not where the directory sat"));
    assert_eq!(under(6).metadata["orphan_parent_path_now"], json!("/"));
    assert!(
        under(7).metadata.get("orphan_parent_path_now").is_none(),
        "a '..' that names nothing reached gives no path"
    );
}

/// HUNT-278: a directory whose parent entry is gone but whose clusters the FAT
/// still shows allocated (the chain survived the entry's removal, or a repair
/// left it lost) is found by the same `.`/`..` test. It is **not** called
/// deleted: nothing about it was deleted that the volume shows. Its entries are
/// recovered with the FAT state said, a live file's data cluster that merely
/// is allocated and unreached is not taken for a directory, and the free-cluster
/// finding is unchanged and says it was free.
#[test]
fn an_unreachable_directory_in_allocated_clusters_is_found_and_not_called_deleted() {
    const CLUSTER_5: usize = (1 + 17 + 1) * 512 + 3 * 512;
    const CLUSTER_6: usize = CLUSTER_5 + 512;
    const CLUSTER_7: usize = CLUSTER_6 + 512;
    const CLUSTER_8: usize = CLUSTER_7 + 512;

    // 2: the live directory SUB; 5: an orphan directory, allocated; 6: a free
    // orphan; 7: allocated, '.' naming another cluster; 8: allocated file data
    // that merely begins with dots.
    let mut img =
        build_fat16_image_with_subdir(&[(2, 0xFFFF), (5, 0xFFFF), (7, 0xFFFF), (8, 0xFFFF)]);
    let put = |img: &mut Vec<u8>, at: usize, name: &[u8; 11], attr: u8, cluster: u16| {
        img[at..at + 11].copy_from_slice(name);
        img[at + 11] = attr;
        img[at + 26..at + 28].copy_from_slice(&cluster.to_le_bytes());
    };
    put(&mut img, CLUSTER_5, b".          ", ATTR_DIRECTORY, 5);
    put(&mut img, CLUSTER_5 + 32, b"..         ", ATTR_DIRECTORY, 0);
    // forensic-lint: allow RAGGED-STRING — an 8.3 name, space-padded by the format.
    put(&mut img, CLUSTER_5 + 64, b"LOST    TXT", ATTR_ARCHIVE, 9);
    put(&mut img, CLUSTER_6, b".          ", ATTR_DIRECTORY, 6);
    put(&mut img, CLUSTER_6 + 32, b"..         ", ATTR_DIRECTORY, 0);
    // forensic-lint: allow RAGGED-STRING — an 8.3 name, space-padded by the format.
    put(&mut img, CLUSTER_6 + 64, b"GONE    TXT", ATTR_ARCHIVE, 9);
    put(&mut img, CLUSTER_7, b".          ", ATTR_DIRECTORY, 40);
    put(&mut img, CLUSTER_7 + 32, b"..         ", ATTR_DIRECTORY, 0);
    // forensic-lint: allow RAGGED-STRING — an 8.3 name, space-padded by the format.
    put(&mut img, CLUSTER_7 + 64, b"DECOY   TXT", ATTR_ARCHIVE, 9);
    img[CLUSTER_8..CLUSTER_8 + 64].copy_from_slice(&[b'.'; 64]);

    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "orphan.dd", "subtype": "fat16" }),
    );
    let out = FatParser.process(&fs).expect("parse must complete");
    let under = |cluster: u32| -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["orphan_directory_cluster"] == json!(cluster))
            .collect()
    };

    let lost = under(5);
    assert_eq!(lost.len(), 1, "LOST.TXT only");
    assert_eq!(lost[0].metadata["orphan_fat_state"], json!("allocated"));
    assert_eq!(lost[0].metadata["recovered_from_free_space"], json!(false));
    assert_ne!(
        lost[0].metadata["deleted"],
        json!(true),
        "an allocated, unreachable directory is not a deleted one"
    );
    assert_eq!(
        lost[0].metadata["path"],
        json!("/[orphaned directory, cluster 5]/LOST.TXT")
    );

    let gone = under(6);
    assert_eq!(gone.len(), 1);
    assert_eq!(gone[0].metadata["orphan_fat_state"], json!("free"));
    assert_eq!(gone[0].metadata["deleted"], json!(true));
    assert_eq!(gone[0].metadata["recovered_from_free_space"], json!(true));

    assert!(
        under(7).is_empty(),
        "a '.' naming another cluster is not a directory"
    );
    assert!(
        under(8).is_empty(),
        "file data that begins with dots is not a directory"
    );

    let map = out
        .iter()
        .find(|a| a.metadata["type"] == json!("allocation_map"))
        .expect("allocation map");
    let scan = &map.metadata["orphan_directory_scan"];
    assert_eq!(scan["directories_found"], json!(2));
    assert_eq!(scan["directories_in_allocated_clusters"], json!(1));
    assert!(scan["allocated_clusters_examined"].as_u64().unwrap() >= 3);
}

/// A FAT32-layout volume (`sectors_per_fat_16 == 0`) of `total_sectors` sectors,
/// one sector per cluster, one 33-sector FAT, so well under 65,525 clusters.
/// `fat` is written as (cluster, entry) pairs; `root_entries` is the BPB field
/// FAT32 requires to be zero. Cluster 2 holds a single file entry `ROOT.TXT`.
fn build_fat32_image(
    total_sectors: u32,
    root_cluster: u32,
    root_entries: u16,
    fat: &[(u32, u32)],
) -> Vec<u8> {
    const BPS: usize = 512;
    const RESERVED: usize = 32;
    const SPF: usize = 33;

    let mut img = vec![0u8; (RESERVED + SPF + 40) * BPS];
    img[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    img[3..11].copy_from_slice(b"MSWIN4.1");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = 1; // sectors/cluster
    img[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    img[16] = 1; // num FATs
    img[17..19].copy_from_slice(&root_entries.to_le_bytes());
    img[21] = 0xF8;
    img[32..36].copy_from_slice(&total_sectors.to_le_bytes());
    img[36..40].copy_from_slice(&(SPF as u32).to_le_bytes());
    img[44..48].copy_from_slice(&root_cluster.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;

    let fat_off = RESERVED * BPS;
    for &(cluster, entry) in fat {
        let at = fat_off + cluster as usize * 4;
        img[at..at + 4].copy_from_slice(&entry.to_le_bytes());
    }

    let cluster2 = (RESERVED + SPF) * BPS;
    img[cluster2..cluster2 + 8].copy_from_slice(b"ROOT    ");
    img[cluster2 + 8..cluster2 + 11].copy_from_slice(b"TXT");
    img[cluster2 + 11] = ATTR_ARCHIVE;
    img
}

fn parse_fat_volume(img: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(MockFatSource::new(img));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "volume.dd" }),
    );
    FatParser.process(&fs).expect("parse must complete")
}

fn allocation_map_of(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata["type"] == json!("allocation_map"))
        .expect("allocation map")
}

fn file_names(out: &[Artifact]) -> Vec<String> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect()
}

/// FAT-LAYOUT: the layout decides the FAT size and the root directory, not the
/// cluster count. A FAT32-layout volume with fewer than 65,525 clusters (a small
/// `mkfs.fat -F32` image) used to be sized from the zero 16-bit FAT field and
/// walked as an empty, complete FAT12/16 root.
#[test]
fn a_small_fat32_layout_volume_is_read_as_fat32_and_lists_its_files() {
    let out = parse_fat_volume(build_fat32_image(
        100,
        2,
        0,
        &[(0, 0x0FFF_FFF8), (1, 0x0FFF_FFFF), (2, 0x0FFF_FFFF)],
    ));
    let map = allocation_map_of(&out);
    assert_eq!(map.metadata["fat_type"], json!("Fat32"));
    assert!(
        map.metadata["fat_type_note"]
            .as_str()
            .expect("the disagreement with the cluster count is recorded")
            .contains("Fat12"),
        "{:?}",
        map.metadata["fat_type_note"]
    );
    assert!(file_names(&out).contains(&"ROOT.TXT".to_string()));
    assert!(map.metadata.get("directory_parse_incomplete").is_none());
}

/// A BPB that is half FAT32 and half FAT12/16 does not say where the root
/// directory is; it is flagged, not listed as empty and whole.
#[test]
fn a_bpb_mixing_fat32_and_fat16_root_fields_flags_the_root_listing() {
    let out = parse_fat_volume(build_fat32_image(100, 2, 512, &[(2, 0x0FFF_FFFF)]));
    let map = allocation_map_of(&out);
    assert_eq!(map.metadata["directory_parse_incomplete"], json!(true));
    assert_eq!(
        map.metadata["directory_parse_incomplete_reason"],
        json!("fat_bpb_layout_inconsistent")
    );
    assert!(file_names(&out).is_empty());
}

/// A broken FAT32 root chain flags the allocation map; it is not a complete
/// root listing.
#[test]
fn a_fat32_root_whose_chain_is_broken_flags_the_allocation_map() {
    // FAT[2] is free: the root's chain stops on a freed entry.
    let out = parse_fat_volume(build_fat32_image(100, 2, 0, &[(0, 0x0FFF_FFF8)]));
    let map = allocation_map_of(&out);
    assert_eq!(map.metadata["directory_parse_incomplete"], json!(true));
    assert_eq!(
        map.metadata["directory_parse_incomplete_reason"],
        json!("fat_root_chain_incomplete")
    );
}

/// A root cluster of 0 or 1 is not a data cluster: the root could not be
/// located, which is not an empty root.
#[test]
fn a_fat32_root_cluster_below_two_is_flagged_not_listed_as_empty() {
    for root_cluster in [0u32, 1] {
        let out = parse_fat_volume(build_fat32_image(100, root_cluster, 0, &[(2, 0x0FFF_FFFF)]));
        let map = allocation_map_of(&out);
        assert_eq!(
            map.metadata["directory_parse_incomplete"],
            json!(true),
            "root_cluster {root_cluster}"
        );
        assert_eq!(
            map.metadata["directory_parse_incomplete_reason"],
            json!("fat_root_cluster_invalid")
        );
    }
}

/// A volume reporting zero clusters has no allocation map to carry the flag, so
/// a bare `fat_volume_walk` record carries it.
#[test]
fn a_zero_cluster_volume_with_an_incomplete_root_mints_a_fat_volume_walk_record() {
    // 65 sectors = reserved 32 + FAT 33: no data area at all.
    let out = parse_fat_volume(build_fat32_image(65, 2, 0, &[(2, 0x0FFF_FFFF)]));
    assert!(
        !out.iter()
            .any(|a| a.metadata["type"] == json!("allocation_map")),
        "a zero-cluster volume has no allocation map"
    );
    let walk = out
        .iter()
        .find(|a| a.metadata["type"] == json!("fat_volume_walk"))
        .expect("a fat_volume_walk record carries the flag");
    assert_eq!(walk.metadata["directory_parse_incomplete"], json!(true));
    assert_eq!(
        walk.metadata["directory_parse_incomplete_reason"],
        json!("fat_root_chain_incomplete")
    );
}

/// A hostile boot sector declaring ~4 billion clusters over a small FAT must not
/// size the bitmap or the orphan scan from the header: they are bounded by the
/// entries the FAT holds, and the record says the declared count was not covered.
#[test]
fn a_declared_cluster_count_far_beyond_the_fat_does_not_size_the_scan() {
    let out = parse_fat_volume(build_fat32_image(
        0xFFFF_FFFF,
        2,
        0,
        &[(0, 0x0FFF_FFF8), (2, 0x0FFF_FFFF)],
    ));
    let map = allocation_map_of(&out);
    assert!(map.metadata["allocation_total_clusters"].as_u64().unwrap() > 4_000_000_000);
    // 33 sectors of 4-byte entries, less clusters 0 and 1.
    assert_eq!(
        map.metadata["allocation_fat_covered_clusters"],
        json!(33 * 512 / 4 - 2)
    );
    assert!(file_names(&out).contains(&"ROOT.TXT".to_string()));
}

/// A chain entry the padded FAT holds but that lies past the last data cluster
/// points outside the volume; the directory is flagged, not read from there.
#[test]
fn a_chain_entry_past_the_last_data_cluster_flags_the_directory() {
    // The FAT16 volume has 4,181 data clusters (2..=4182) and a 17-sector FAT
    // that holds 4,352 entries.
    let out = parse_fat16_with_subdir_chain(&[(2, 4300)]);
    let sub = out
        .iter()
        .find(|a| a.metadata["name"] == json!("SUB"))
        .expect("SUB directory");
    assert_eq!(sub.metadata["directory_parse_incomplete"], json!(true));
}

/// A deleted entry whose first cluster is far outside the volume gets no
/// fabricated run at a saturated offset.
#[test]
fn a_deleted_entry_with_a_first_cluster_outside_the_volume_publishes_no_runs() {
    let mut img = build_fat32_image(100, 2, 0, &[(2, 0x0FFF_FFFF)]);
    let slot = (32 + 33) * 512 + 32;
    img[slot..slot + 8].copy_from_slice(b"\xE5ONE    ");
    img[slot + 8..slot + 11].copy_from_slice(b"BIN");
    img[slot + 11] = ATTR_ARCHIVE;
    img[slot + 20..slot + 22].copy_from_slice(&0xFFFFu16.to_le_bytes());
    img[slot + 26..slot + 28].copy_from_slice(&0xFFF0u16.to_le_bytes());
    img[slot + 28..slot + 32].copy_from_slice(&1000u32.to_le_bytes());
    let out = parse_fat_volume(img);
    let gone = out
        .iter()
        .find(|a| a.metadata["deleted"] == json!(true))
        .expect("the deleted entry is listed");
    assert!(
        gone.metadata.get("data_runs").is_none(),
        "{:?}",
        gone.metadata
    );
    assert_eq!(gone.metadata["data_runs_complete"], json!(false));
    assert_eq!(gone.metadata["content_incomplete"], json!(true));
    assert_eq!(
        gone.metadata["content_incomplete_reason"],
        json!("deleted_reconstruction_short")
    );
}

/// A source that fails every read overlapping `bad`.
#[derive(Debug)]
struct FailingRange {
    inner: MockFatSource,
    bad: std::ops::Range<u64>,
}

impl DataSource for FailingRange {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<usize> {
        if offset < self.bad.end && offset + buffer.len() as u64 > self.bad.start {
            return Err(std::io::Error::other("injected read failure"));
        }
        self.inner.read_at(offset, buffer)
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// A free cluster the orphan scan could not read is a cluster where a deleted
/// directory may have sat: the scan is not exhaustive, and says why.
#[test]
fn an_unreadable_free_cluster_makes_the_orphan_scan_incomplete() {
    const CLUSTER_5: u64 = (1 + 17 + 1) * 512 + 3 * 512;
    let img = build_fat16_image_with_subdir(&[(2, 0xFFFF)]);
    let ds: Arc<dyn DataSource> = Arc::new(FailingRange {
        inner: MockFatSource::new(img),
        bad: CLUSTER_5..CLUSTER_5 + 512,
    });
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "name": "unreadable.dd", "subtype": "fat16" }),
    );
    let out = FatParser.process(&fs).expect("parse must complete");
    let map = allocation_map_of(&out);
    assert_eq!(
        map.metadata["orphan_directory_scan_incomplete"],
        json!(true)
    );
    assert_eq!(
        map.metadata["orphan_directory_scan_incomplete_reason"],
        json!("unreadable_clusters")
    );
    let scan = &map.metadata["orphan_directory_scan"];
    assert_eq!(scan["unreadable_clusters"], json!(1));
    assert_eq!(scan["max_clusters_examined"], json!(1u64 << 20));
    assert!(scan.get("max_free_clusters_examined").is_none());
}

/// HUNT-278: directory recovery past one cluster, past a `0x00` marker, and
/// refusal where a deleted directory's first cluster was reused.
///
/// SYNTHETIC. Every volume here was built by `tests/fixtures/make_hunt278_fixtures.sh`
/// with `mkfs.fat -F 16 -s 1` and mtools (plus `plant_hunt278_slack.py` for the
/// slack volume). They grade this parser on a layout the generator knows; they
/// say nothing about what Windows, a camera or any other FAT driver leaves behind
/// on a real volume. See `documentation/VALIDATION.md`.
#[cfg(test)]
mod hunt278 {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn parse_gz(gz: &[u8]) -> Vec<Artifact> {
        let mut data = Vec::new();
        GzDecoder::new(gz).read_to_end(&mut data).unwrap();
        parse_raw(data)
    }

    fn parse_raw(data: Vec<u8>) -> Vec<Artifact> {
        let source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(source),
            json!({"name": "hunt278"}),
        );
        FatParser.process(&artifact).unwrap()
    }

    fn parse_data(data: Vec<u8>) -> Vec<Artifact> {
        let source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(source),
            json!({"name": "hunt278"}),
        );
        FatParser.process(&artifact).unwrap()
    }

    fn files_under<'a>(artifacts: &'a [Artifact], prefix: &str) -> Vec<&'a Artifact> {
        artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .filter(|a| {
                a.metadata["path"]
                    .as_str()
                    .is_some_and(|p| p.starts_with(prefix))
            })
            .collect()
    }

    fn named<'a>(artifacts: &'a [Artifact], path: &str) -> &'a Artifact {
        artifacts
            .iter()
            .find(|a| a.metadata["path"] == json!(path))
            .unwrap_or_else(|| panic!("no record at {path}"))
    }

    fn long_names() -> Vec<String> {
        (1..=40)
            .map(|i| format!("Recovered Long Name {i:02}.txt"))
            .collect()
    }

    #[test]
    fn a_multi_cluster_deleted_directory_is_recovered_whole_and_says_its_chain_was_assumed() {
        let artifacts = parse_gz(include_bytes!("../tests/fixtures/hunt278_fat16_a.raw.gz"));
        let dir = named(&artifacts, "/_");
        assert_eq!(dir.metadata["deleted"], json!(true));
        assert!(dir.metadata.get("directory_parse_incomplete").is_none());
        let inside = files_under(&artifacts, "/_/");
        for want in long_names() {
            let hit = inside
                .iter()
                .find(|a| a.metadata["name"] == json!(want))
                .unwrap_or_else(|| panic!("{want} not recovered; got {} records", inside.len()));
            assert_eq!(hit.metadata["deleted"], json!(true), "{want}");
        }
        assert_eq!(inside.len(), 40);
        // The first cluster's records rest on the entry itself; later ones on
        // the assumption that the directory was laid out contiguously.
        let later = inside
            .iter()
            .filter(|a| a.metadata["directory_chain_basis"] == json!("contiguous_assumed"))
            .count();
        assert!(later >= 30, "records beyond the first cluster: {later}");
        let first = named(&artifacts, "/_/Recovered Long Name 01.txt");
        assert!(first.metadata.get("directory_chain_basis").is_none());
        // The live neighbour is untouched.
        assert_eq!(files_under(&artifacts, "/KEEP").len(), 1);
    }

    #[test]
    fn a_deleted_directory_whose_next_cluster_holds_file_bytes_stops_there_and_says_so() {
        let artifacts = parse_gz(include_bytes!("../tests/fixtures/hunt278_fat16_a2.raw.gz"));
        let dir = named(&artifacts, "/_");
        assert_eq!(dir.metadata["directory_parse_incomplete"], json!(true));
        assert_eq!(
            dir.metadata["directory_parse_incomplete_reason"],
            json!("fat_deleted_chain_unverified")
        );
        let inside = files_under(&artifacts, "/_/");
        // Cluster 2 held four long-named files; the text in cluster 3 is not
        // read as entries, so nothing past them is invented.
        assert_eq!(
            inside.len(),
            4,
            "{:?}",
            inside
                .iter()
                .map(|a| &a.metadata["name"])
                .collect::<Vec<_>>()
        );
        assert!(inside
            .iter()
            .all(|a| a.metadata.get("directory_chain_basis").is_none()));
    }

    /// The byte offset of `cluster` on a FAT12/16 volume, from its boot sector.
    fn fat16_cluster_offset(data: &[u8], cluster: u32) -> usize {
        let bps = u16::from_le_bytes([data[11], data[12]]) as usize;
        let spc = data[13] as usize;
        let reserved = u16::from_le_bytes([data[14], data[15]]) as usize;
        let fats = data[16] as usize;
        let root_entries = u16::from_le_bytes([data[17], data[18]]) as usize;
        let fat_sectors = u16::from_le_bytes([data[22], data[23]]) as usize;
        let data_start = (reserved + fats * fat_sectors) * bps + root_entries * 32;
        data_start + (cluster as usize - 2) * spc * bps
    }

    /// HUNT-278. Windows 11's FAT32 and exFAT drivers were observed to leave a deleted
    /// directory's clusters all zero (`VALIDATION.md` `WIN11-FAT-1`). A deleted directory
    /// whose first cluster is free and all zero has no entry to read: it is flagged as
    /// such, with its own reason, and no name is invented. SYNTHETIC: the multi-cluster
    /// fixture with its first cluster zeroed in memory.
    #[test]
    fn a_deleted_directory_whose_first_cluster_is_all_zero_says_so_and_reads_nothing() {
        let mut data = Vec::new();
        GzDecoder::new(&include_bytes!("../tests/fixtures/hunt278_fat16_a.raw.gz")[..])
            .read_to_end(&mut data)
            .unwrap();
        let first = {
            let before = parse_data(data.clone());
            named(&before, "/_").metadata["first_cluster"]
                .as_u64()
                .unwrap() as u32
        };
        let bps = u16::from_le_bytes([data[11], data[12]]) as usize;
        let spc = data[13] as usize;
        let at = fat16_cluster_offset(&data, first);
        data[at..at + spc * bps].fill(0);
        let artifacts = parse_data(data);
        let dir = named(&artifacts, "/_");
        assert_eq!(dir.metadata["deleted"], json!(true));
        assert_eq!(dir.metadata["directory_content_zero"], json!(true));
        assert_eq!(dir.metadata["directory_parse_incomplete"], json!(true));
        assert_eq!(
            dir.metadata["directory_parse_incomplete_reason"],
            json!("fat_deleted_directory_zeroed")
        );
        assert!(files_under(&artifacts, "/_/").is_empty());
    }

    /// HUNT-278. A freed cluster is the first one a driver gives the next new directory, so a
    /// deleted directory's first cluster can be a live directory's first cluster. The deleted
    /// one used to be skipped without a word (and, read before the live one, would have read its
    /// entries as its own). It is now flagged, and the live directory is read. SYNTHETIC: the
    /// multi-cluster fixture with `/KEEP`'s first cluster pointed at the deleted directory's.
    #[test]
    fn a_deleted_directory_sharing_its_first_cluster_with_a_live_one_is_flagged_not_skipped() {
        let mut data = Vec::new();
        GzDecoder::new(&include_bytes!("../tests/fixtures/hunt278_fat16_a.raw.gz")[..])
            .read_to_end(&mut data)
            .unwrap();
        let bps = u16::from_le_bytes([data[11], data[12]]) as usize;
        let reserved = u16::from_le_bytes([data[14], data[15]]) as usize;
        let fats = data[16] as usize;
        let fat_sectors = u16::from_le_bytes([data[22], data[23]]) as usize;
        let root = (reserved + fats * fat_sectors) * bps;
        let keep = (0..3)
            .map(|i| root + 32 * i)
            .find(|&at| &data[at..at + 11] == b"KEEP       ")
            .expect("the fixture's live directory");
        let deleted_first = {
            let before = parse_data(data.clone());
            named(&before, "/_").metadata["first_cluster"]
                .as_u64()
                .unwrap() as u16
        };
        data[keep + 26..keep + 28].copy_from_slice(&deleted_first.to_le_bytes());
        let artifacts = parse_data(data);
        let dir = named(&artifacts, "/_");
        assert_eq!(dir.metadata["deleted"], json!(true));
        assert_eq!(dir.metadata["directory_content_reallocated"], json!(true));
        assert_eq!(dir.metadata["directory_parse_incomplete"], json!(true));
        assert_eq!(
            dir.metadata["directory_parse_incomplete_reason"],
            json!("fat_deleted_directory_unverified")
        );
        assert!(
            files_under(&artifacts, "/_/").is_empty(),
            "nothing is read as the deleted directory's content"
        );
    }

    /// HUNT-278. Directory entries in a free cluster no directory leads to and no `.` names
    /// are recovered when every slot reads as an entry; a `.` that names a different cluster
    /// is reported as such. SYNTHETIC: the multi-cluster fixture with its parent entry's
    /// cluster zeroed (so nothing leads to the cluster) and its `.` entry pointed elsewhere.
    /// The real-volume grading is `tests/real_rm2_headless_test.rs`.
    #[test]
    fn entries_in_a_free_cluster_nothing_anchors_are_recovered_and_labelled_headless() {
        let mut data = Vec::new();
        GzDecoder::new(&include_bytes!("../tests/fixtures/hunt278_fat16_a.raw.gz")[..])
            .read_to_end(&mut data)
            .unwrap();
        let bps = u16::from_le_bytes([data[11], data[12]]) as usize;
        let reserved = u16::from_le_bytes([data[14], data[15]]) as usize;
        let fats = data[16] as usize;
        let fat_sectors = u16::from_le_bytes([data[22], data[23]]) as usize;
        let root = (reserved + fats * fat_sectors) * bps;
        let first = {
            let before = parse_data(data.clone());
            named(&before, "/_").metadata["first_cluster"]
                .as_u64()
                .unwrap() as u32
        };
        // The deleted directory's parent entry no longer leads anywhere.
        let parent = (0..3)
            .map(|i| root + 32 * i)
            .find(|&at| data[at] == 0xE5)
            .expect("the fixture's deleted directory entry");
        data[parent + 26..parent + 28].copy_from_slice(&[0, 0]);
        // Its `.` entry names another cluster.
        let at = fat16_cluster_offset(&data, first);
        data[at + 26..at + 28].copy_from_slice(&7u16.to_le_bytes());
        let artifacts = parse_data(data);
        let found: Vec<&Artifact> = artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .filter(|a| a.metadata["orphan_directory_headless"] == json!(true))
            .collect();
        assert!(found.len() >= 8, "entries recovered: {}", found.len());
        // The directory's first cluster, whose `.` was pointed at cluster 7, and its later
        // clusters, which have no `.` at all: each is a headless cluster of its own.
        let in_first: Vec<&&Artifact> = found
            .iter()
            .filter(|a| a.metadata["orphan_directory_cluster"] == json!(first))
            .collect();
        assert!(
            in_first.len() >= 4,
            "entries in the first cluster: {}",
            in_first.len()
        );
        for a in &found {
            assert_eq!(a.metadata["deleted"], json!(true));
            let cluster = a.metadata["orphan_directory_cluster"].as_u64().unwrap();
            assert!(a.metadata["path"].as_str().unwrap().starts_with(&format!(
                "/[headless directory entries, cluster {cluster}]/"
            )));
            assert!(a.metadata["path_basis"]
                .as_str()
                .unwrap()
                .contains("not a folder"));
            if cluster == u64::from(first) {
                assert_eq!(a.metadata["orphan_directory_dot_names_cluster"], json!(7));
            } else {
                assert!(a
                    .metadata
                    .get("orphan_directory_dot_names_cluster")
                    .is_none());
            }
        }
    }

    /// File bytes are never read as names: a free cluster of text is not a headless directory.
    #[test]
    fn a_free_cluster_of_file_bytes_is_not_read_as_directory_entries() {
        let slots: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut s = [b'a'; 32];
                s[0] = b'A' + i as u8;
                s
            })
            .collect();
        assert!(!crate::fat_parser::headless_cluster_qualifies(&slots, 1000));
        assert!(!crate::fat_parser::headless_cluster_qualifies(&[], 1000));
        let zero = [[0u8; 32]; 16];
        assert!(!crate::fat_parser::headless_cluster_qualifies(&zero, 1000));
    }

    #[test]
    fn a_deleted_directory_whose_first_cluster_was_reused_reads_no_entries_out_of_file_data() {
        let artifacts = parse_gz(include_bytes!("../tests/fixtures/hunt278_fat16_b.raw.gz"));
        let dir = named(&artifacts, "/_");
        assert_eq!(dir.metadata["deleted"], json!(true));
        assert_eq!(dir.metadata["directory_content_reallocated"], json!(true));
        assert_eq!(dir.metadata["directory_parse_incomplete"], json!(true));
        assert_eq!(
            dir.metadata["directory_parse_incomplete_reason"],
            json!("fat_deleted_directory_unverified")
        );
        let inside = files_under(&artifacts, "/_/");
        assert!(
            inside.is_empty(),
            "entries invented from file bytes: {:?}",
            inside
                .iter()
                .map(|a| &a.metadata["path"])
                .collect::<Vec<_>>()
        );
        // The file that took the cluster is still a live file.
        assert!(named(&artifacts, "/reused.txt")
            .metadata
            .get("deleted")
            .is_none());
    }

    /// `make_hunt278_fixtures.sh` scenario E: the shape Linux's `vfat` leaves. /DirD held 100 files with
    /// 57-character names (five name slots and the short entry, six slots each in 16-slot clusters, so names
    /// straddle a cluster), grown around 50 KB of file data, then deleted whole. The directory's clusters are
    /// not adjacent, so each is read alone and the name cut by a cluster boundary is joined from the
    /// cluster before by the checksum its slots share. SYNTHETIC (mtools), the real-driver counterpart is
    /// `tests/real_linux_fat_test.rs`.
    #[test]
    fn names_cut_by_a_cluster_boundary_of_a_deleted_directory_are_joined_and_nothing_else_is() {
        let artifacts = parse_gz(include_bytes!("../tests/fixtures/hunt278_fat16_e.raw.gz"));
        let want: std::collections::BTreeSet<String> = (1..=100)
            .map(|i| format!("Quarterly-report-DirD-{i:03}-with-a-long-descriptive-name.txt"))
            .collect();
        let got: std::collections::BTreeSet<String> = artifacts
            .iter()
            .filter(|a| {
                a.metadata["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with("Quarterly"))
            })
            .map(|a| a.metadata["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, want);
        let joined = artifacts
            .iter()
            .filter(|a| a.metadata["long_name_basis"] == json!("stitched_across_clusters"))
            .count();
        assert!(
            joined > 0,
            "a name was cut by a cluster boundary and none was joined"
        );
        // Nothing is shown whole that is not.
        assert!(artifacts
            .iter()
            .all(|a| a.metadata.get("long_name_possibly_truncated").is_none()
                || a.metadata["long_name_possibly_truncated"] == serde_json::Value::Null));
    }

    /// The same bytes without the cluster before: the half-name is flagged, not presented as the name.
    #[test]
    fn a_deleted_name_whose_head_is_in_a_cluster_that_is_gone_is_flagged_possibly_truncated() {
        let mut data = Vec::new();
        GzDecoder::new(&include_bytes!("../tests/fixtures/hunt278_fat16_e.raw.gz")[..])
            .read_to_end(&mut data)
            .unwrap();
        // Zero every free cluster that holds only deleted name slots and ends in a name slot.
        let bps = u16::from_le_bytes([data[11], data[12]]) as usize;
        let spc = data[13] as usize;
        let reserved = u16::from_le_bytes([data[14], data[15]]) as usize;
        let nfats = data[16] as usize;
        let root_entries = u16::from_le_bytes([data[17], data[18]]) as usize;
        let fat_sectors = u16::from_le_bytes([data[22], data[23]]) as usize;
        let data_start = (reserved + nfats * fat_sectors) * bps + root_entries * 32;
        let cluster_len = spc * bps;
        let mut zeroed = 0;
        let mut at = data_start;
        while at + cluster_len <= data.len() {
            let last = &data[at + cluster_len - 32..at + cluster_len];
            let first = &data[at..at + 32];
            if last[11] == 0x0F && last[0] == 0xE5 && first[0] == 0xE5 {
                data[at..at + cluster_len].fill(0);
                zeroed += 1;
            }
            at += cluster_len;
        }
        assert!(
            zeroed > 0,
            "the fixture has no cluster ending in a name slot"
        );
        let artifacts = parse_raw(data);
        let flagged = artifacts
            .iter()
            .filter(|a| a.metadata["long_name_possibly_truncated"] == json!(true))
            .count();
        assert!(flagged > 0, "cut names are shown as whole ones");
    }

    /// The shape Haiku's FAT driver leaves (`HUNT-278`): a freed directory whose slots were never marked
    /// `0xE5`, so every name slot keeps its ordinal and every short entry its first byte. The fixture's marked
    /// slots get back what the driver wrote: the text of a name slot says which of its five it is, and every
    /// short entry here is `QUAR~nnn.TXT`.
    fn with_ordinals_kept(mut data: Vec<u8>) -> Vec<u8> {
        let reserved = u16::from_le_bytes([data[14], data[15]]) as usize;
        let bps = u16::from_le_bytes([data[11], data[12]]) as usize;
        let nfats = data[16] as usize;
        let root_entries = u16::from_le_bytes([data[17], data[18]]) as usize;
        let fat_sectors = u16::from_le_bytes([data[22], data[23]]) as usize;
        let mut at = (reserved + nfats * fat_sectors) * bps + root_entries * 32;
        while at + 32 <= data.len() {
            if data[at] == 0xE5 {
                if data[at + 11] == 0x0F {
                    let seq = match (data[at + 1], data[at + 3]) {
                        (b'Q', b'u') => 1,
                        (b'o', b'r') => 2,
                        (b'w', b'i') => 3,
                        (b'e', b's') => 4,
                        (b'm', b'e') => 0x45,
                        _ => 0,
                    };
                    if seq != 0 {
                        data[at] = seq;
                    }
                } else if &data[at + 1..at + 5] == b"UAR~" {
                    data[at] = b'Q';
                }
            }
            at += 32;
        }
        data
    }

    fn quarterly_names(artifacts: &[Artifact]) -> std::collections::BTreeSet<String> {
        artifacts
            .iter()
            .filter_map(|a| a.metadata["name"].as_str())
            .filter(|n| n.starts_with("Quarterly"))
            .map(str::to_string)
            .collect()
    }

    /// The same boundary-cut names as `names_cut_by_a_cluster_boundary_of_a_deleted_directory_are_joined_and_nothing_else_is`,
    /// from slots that kept their ordinals. The ordinals prove the join: the tail's last slot is one more than
    /// the head's first, and the tail opens with the terminator slot. SYNTHETIC (the mtools fixture, markers put
    /// back); the real-driver counterpart is `tests/real_haiku_fat_test.rs`.
    #[test]
    fn names_cut_by_a_cluster_boundary_are_joined_when_the_driver_left_the_ordinals_and_short_names_intact(
    ) {
        let mut data = Vec::new();
        GzDecoder::new(&include_bytes!("../tests/fixtures/hunt278_fat16_e.raw.gz")[..])
            .read_to_end(&mut data)
            .unwrap();
        let artifacts = parse_raw(with_ordinals_kept(data));
        let want: std::collections::BTreeSet<String> = (1..=100)
            .map(|i| format!("Quarterly-report-DirD-{i:03}-with-a-long-descriptive-name.txt"))
            .collect();
        assert_eq!(quarterly_names(&artifacts), want);
        assert!(
            artifacts
                .iter()
                .any(|a| a.metadata["long_name_basis"] == json!("stitched_across_clusters")),
            "a name was cut by a cluster boundary and none was joined"
        );
        assert!(artifacts
            .iter()
            .all(|a| a.metadata["long_name_possibly_truncated"] != json!(true)));
    }

    /// Without the cluster before, a name cut from slots that kept their ordinals is flagged, and the ordinals
    /// make the flag exact: the first slot present lacks the terminator bit. Nothing short of the whole name is
    /// shown unflagged.
    #[test]
    fn a_name_whose_head_is_gone_is_flagged_when_the_ordinals_were_kept() {
        let mut data = Vec::new();
        GzDecoder::new(&include_bytes!("../tests/fixtures/hunt278_fat16_e.raw.gz")[..])
            .read_to_end(&mut data)
            .unwrap();
        let mut data = with_ordinals_kept(data);
        let bps = u16::from_le_bytes([data[11], data[12]]) as usize;
        let spc = data[13] as usize;
        let reserved = u16::from_le_bytes([data[14], data[15]]) as usize;
        let nfats = data[16] as usize;
        let root_entries = u16::from_le_bytes([data[17], data[18]]) as usize;
        let fat_sectors = u16::from_le_bytes([data[22], data[23]]) as usize;
        let data_start = (reserved + nfats * fat_sectors) * bps + root_entries * 32;
        let cluster_len = spc * bps;
        let mut zeroed = 0;
        let mut at = data_start;
        while at + cluster_len <= data.len() {
            let last = &data[at + cluster_len - 32..at + cluster_len];
            let first = &data[at..at + 32];
            if last[11] == 0x0F
                && last[0] != 0xE5
                && last[0] != 0
                && first[0] != 0
                && first[11] == 0x0F
            {
                data[at..at + cluster_len].fill(0);
                zeroed += 1;
            }
            at += cluster_len;
        }
        assert!(
            zeroed > 0,
            "the fixture has no cluster ending in a name slot"
        );
        let artifacts = parse_raw(data);
        let full = |n: &str| n.ends_with("-with-a-long-descriptive-name.txt");
        let cut: Vec<&Artifact> = artifacts
            .iter()
            .filter(|a| {
                a.metadata["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with("Quarterly") && !full(n))
            })
            .collect();
        assert!(!cut.is_empty(), "no name was cut");
        for a in cut {
            assert_eq!(
                a.metadata["long_name_possibly_truncated"],
                json!(true),
                "{} is shown as a name",
                a.metadata["name"]
            );
        }
    }

    fn exfat_image() -> Vec<u8> {
        let mut data = Vec::new();
        GzDecoder::new(&include_bytes!("../tests/fixtures/hunt278_exfat.raw.gz")[..])
            .read_to_end(&mut data)
            .unwrap();
        data
    }

    fn parse_exfat(data: Vec<u8>) -> Vec<Artifact> {
        let source: Arc<dyn DataSource> = Arc::new(MockFatSource::new(data));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(source),
            json!({"name": "hunt278_exfat"}),
        );
        FatParser.process(&artifact).unwrap()
    }

    /// `make_hunt278_exfat.py` deleted /DIR (NoFatChain, two clusters) holding
    /// f1..f6. f2's set is also marked deleted with its checksum as the in-use
    /// set had it; f3's SetChecksum is corrupt. The other four verify.
    #[test]
    fn a_deleted_exfat_directory_gives_up_the_sets_whose_checksum_verifies_and_counts_the_rest() {
        let artifacts = parse_exfat(exfat_image());
        let dir = named(&artifacts, "/DIR");
        assert_eq!(dir.metadata["deleted"], json!(true));
        let inside = files_under(&artifacts, "/DIR/");
        let mut names: Vec<_> = inside
            .iter()
            .map(|a| a.metadata["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        // f6 straddles the two clusters; f3 is refused.
        assert_eq!(
            names,
            ["f1.txt", "f2.txt", "f4.txt", "f5.txt", "f6.txt"],
            "recovered from the deleted directory"
        );
        for a in &inside {
            assert_eq!(a.metadata["deleted"], json!(true));
            assert_eq!(
                a.metadata["directory_content_basis"],
                json!("set_checksum_validated")
            );
        }
        assert_eq!(dir.metadata["directory_entry_sets_refused"], json!(1));
        assert_eq!(
            dir.metadata["directory_parse_incomplete_reason"],
            json!("exfat_deleted_directory_sets_refused")
        );
    }

    #[test]
    fn a_deleted_exfat_directory_whose_cluster_is_in_use_again_is_not_read() {
        let mut data = exfat_image();
        let first = {
            let before = parse_exfat(data.clone());
            named(&before, "/DIR").metadata["first_cluster"]
                .as_u64()
                .unwrap()
        };
        // Bitmap cluster 2 opens the cluster heap on this volume (dump.exfat:
        // "Bitmap start cluster: 2"); bit (c - 2) is cluster c.
        let bytes_per_sector = 1usize << data[108];
        let heap = u32::from_le_bytes(data[88..92].try_into().unwrap()) as usize * bytes_per_sector;
        data[heap + (first as usize - 2) / 8] |= 1 << ((first - 2) % 8);
        let artifacts = parse_exfat(data);
        let dir = named(&artifacts, "/DIR");
        assert_eq!(dir.metadata["directory_content_reallocated"], json!(true));
        assert_eq!(
            dir.metadata["directory_parse_incomplete_reason"],
            json!("exfat_deleted_directory_unverified")
        );
        assert!(files_under(&artifacts, "/DIR/").is_empty());
    }

    /// HUNT-278, exFAT. The same, for a deleted directory whose first cluster is free and all
    /// zero: a reason of its own, and no entry set read. SYNTHETIC (the fixture with the
    /// cluster zeroed in memory).
    #[test]
    fn a_deleted_exfat_directory_whose_first_cluster_is_all_zero_says_so() {
        let mut data = exfat_image();
        let first = {
            let before = parse_exfat(data.clone());
            named(&before, "/DIR").metadata["first_cluster"]
                .as_u64()
                .unwrap() as usize
        };
        let bps = 1usize << data[108];
        let spc = 1usize << data[109];
        let heap = u32::from_le_bytes(data[88..92].try_into().unwrap()) as usize * bps;
        let at = heap + (first - 2) * spc * bps;
        data[at..at + spc * bps].fill(0);
        let artifacts = parse_exfat(data);
        let dir = named(&artifacts, "/DIR");
        assert_eq!(dir.metadata["deleted"], json!(true));
        assert_eq!(dir.metadata["directory_content_zero"], json!(true));
        assert_eq!(dir.metadata["directory_parse_incomplete"], json!(true));
        assert_eq!(
            dir.metadata["directory_parse_incomplete_reason"],
            json!("exfat_deleted_directory_zeroed")
        );
        assert!(files_under(&artifacts, "/DIR/").is_empty());
    }

    /// A deleted directory's stale FAT chain is followed for exactly the clusters its DataLength
    /// needs, and stops, flagged short, at a link that leaves the heap, loops, ends early or
    /// leads into a cluster that is in use again.
    #[test]
    fn a_stale_fat_chain_is_followed_only_as_far_as_it_can_be_trusted() {
        use crate::exfat_parser::{stale_fat_chain, ExFatTable};
        let table = |links: &[(usize, u32)]| {
            let mut t = vec![0u8; 64 * 4];
            for &(c, v) in links {
                t[c * 4..c * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
            ExFatTable { table_data: t }
        };
        let free = |_: u32| true;
        // 6 -> 28 -> 40 -> end: three clusters, as many as the length needs.
        let t = table(&[(6, 28), (28, 40), (40, 0xFFFF_FFFF)]);
        assert_eq!(stale_fat_chain(&t, 6, 3, free), (vec![6, 28, 40], true));
        // A directory needing four but whose chain ends at three is short.
        assert_eq!(stale_fat_chain(&t, 6, 4, free), (vec![6, 28, 40], false));
        // Only as many as the length needs, though the chain goes on.
        assert_eq!(stale_fat_chain(&t, 6, 2, free), (vec![6, 28], true));
        // A cluster in use again ends the walk before it.
        assert_eq!(stale_fat_chain(&t, 6, 3, |c| c != 28), (vec![6], false));
        // A loop is not followed twice.
        let l = table(&[(6, 28), (28, 6)]);
        assert_eq!(stale_fat_chain(&l, 6, 5, free), (vec![6, 28], false));
        // A link past the table ends it.
        let o = table(&[(6, 9999)]);
        assert_eq!(stale_fat_chain(&o, 6, 3, free), (vec![6, 9999], false));
    }

    #[test]
    fn the_exfat_set_checksum_matches_the_specification_vector() {
        // One primary + stream + name set built by the generator for "f1.txt",
        // checksummed by an independent reading of the specification: rotate
        // right then add, skipping bytes 2 and 3 of the primary.
        let mut primary = [0u8; 32];
        primary[0] = 0x85;
        primary[1] = 2;
        let mut stream = [0u8; 32];
        stream[0] = 0xC0;
        stream[3] = 1;
        let mut name = [0u8; 32];
        name[0] = 0xC1;
        name[2] = b'a';
        let want = {
            let mut sum: u32 = 0;
            for (e, entry) in [primary, stream, name].iter().enumerate() {
                for (b, &byte) in entry.iter().enumerate() {
                    if e == 0 && (b == 2 || b == 3) {
                        continue;
                    }
                    sum = ((sum << 15) | (sum >> 1)) & 0xFFFF;
                    sum = (sum + u32::from(byte)) & 0xFFFF;
                }
            }
            sum as u16
        };
        assert_eq!(
            crate::exfat_parser::exfat_set_checksum(&[primary, stream, name]),
            want
        );
    }

    #[test]
    fn entries_left_behind_a_zero_marker_are_published_as_slack_and_garbage_is_not() {
        let artifacts = parse_gz(include_bytes!("../tests/fixtures/hunt278_fat16_c.raw.gz"));
        let live: Vec<_> = ["ONE.TXT", "TWO.TXT", "THREE.TXT"]
            .iter()
            .map(|n| named(&artifacts, &format!("/S/{n}")))
            .collect();
        assert!(live.iter().all(|a| a.metadata.get("deleted").is_none()));
        assert!(live
            .iter()
            .all(|a| a.metadata.get("recovered_from_directory_slack").is_none()));
        // FOUR's first byte became the marker; FIVE and SIX sit behind it; the
        // slot after them holds bytes no directory writes.
        for n in ["FIVE.TXT", "SIX.TXT"] {
            let a = named(&artifacts, &format!("/S/{n}"));
            assert_eq!(a.metadata["deleted"], json!(true), "{n}");
            assert_eq!(
                a.metadata["recovered_from_directory_slack"],
                json!(true),
                "{n}"
            );
            assert!(a.metadata["directory_slack_basis"]
                .as_str()
                .unwrap()
                .contains("after the end-of-directory marker, state unknown"));
        }
        assert_eq!(files_under(&artifacts, "/S/").len(), 5);
        // A directory whose tail is plain zeros publishes nothing from it.
        assert_eq!(files_under(&artifacts, "/Z/").len(), 1);
        let map = artifacts
            .iter()
            .find(|a| a.metadata["type"] == json!("allocation_map"))
            .unwrap();
        assert_eq!(map.metadata["directory_slack_slots_rejected"], json!(1));
    }
}
