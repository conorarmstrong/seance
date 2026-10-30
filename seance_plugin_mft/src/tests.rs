use super::*;
use byteorder::WriteBytesExt;
use seance_core::data_source::DataSource;
use std::io::Write;
use std::sync::Mutex;
use uuid::Uuid;

// --- Mock Data Source ---
// Reusing similar mock structure as in other tests
#[derive(Debug)]
struct MockMftSource {
    data: Arc<Mutex<Vec<u8>>>,
}

impl MockMftSource {
    fn new(size: usize) -> Self {
        Self {
            data: Arc::new(Mutex::new(vec![0u8; size])),
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) {
        let mut data = self.data.lock().unwrap();
        if offset as usize + buf.len() > data.len() {
            data.resize(offset as usize + buf.len(), 0);
        }
        data[offset as usize..offset as usize + buf.len()].copy_from_slice(buf);
    }
}

impl DataSource for MockMftSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let data = self.data.lock().unwrap();
        if offset >= data.len() as u64 {
            return Ok(0);
        }
        let available = data.len() as u64 - offset;
        let to_read = std::cmp::min(available, buf.len() as u64) as usize;
        buf[..to_read].copy_from_slice(&data[offset as usize..offset as usize + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.lock().unwrap().len() as u64
    }
}

// --- Helpers to Construct MFT Records ---

fn create_mft_header(record_num: u32, first_attr_offset: u16) -> Vec<u8> {
    let mut buf = vec![];
    buf.write_all(b"FILE").unwrap();
    buf.write_u16::<LittleEndian>(48).unwrap(); // usa_offset (header blob is 48 bytes)
    buf.write_u16::<LittleEndian>(3).unwrap(); // usa_size (3 words: USN + 2 sectors)
    buf.write_u64::<LittleEndian>(0).unwrap(); // lsn
    buf.write_u16::<LittleEndian>(1).unwrap(); // sequence
    buf.write_u16::<LittleEndian>(1).unwrap(); // hard_links
    buf.write_u16::<LittleEndian>(first_attr_offset).unwrap(); // first_attr
    buf.write_u16::<LittleEndian>(1).unwrap(); // flags (IN_USE)
    buf.write_u32::<LittleEndian>(1024).unwrap(); // real_size
    buf.write_u32::<LittleEndian>(1024).unwrap(); // alloc_size
    buf.write_u64::<LittleEndian>(0).unwrap(); // base_ref
    buf.write_u16::<LittleEndian>(0).unwrap(); // next_attr
    buf.write_u16::<LittleEndian>(0).unwrap(); // padding
    buf.write_u32::<LittleEndian>(record_num).unwrap(); // record_num

    // USA follows the 48-byte header blob: USN (0x1234) + Sector 1 end + Sector 2 end
    buf.write_u16::<LittleEndian>(0x1234).unwrap();
    buf.write_u16::<LittleEndian>(0x0000).unwrap(); // Original bytes at 510
    buf.write_u16::<LittleEndian>(0x0000).unwrap(); // Original bytes at 1022

    buf
}

fn create_si_attribute(creation: u64) -> Vec<u8> {
    create_si_attribute_times(creation, creation, creation, creation)
}

fn create_si_attribute_times(c: u64, m: u64, mft: u64, a: u64) -> Vec<u8> {
    let mut content = vec![];
    content.write_u64::<LittleEndian>(c).unwrap(); // C
    content.write_u64::<LittleEndian>(m).unwrap(); // M
    content.write_u64::<LittleEndian>(mft).unwrap(); // MFT
    content.write_u64::<LittleEndian>(a).unwrap(); // A
                                                   // ... permission flags, etc (ignored by parser for now)
    content.resize(72, 0); // Standard SI size

    let mut attr = vec![];
    attr.write_u32::<LittleEndian>(0x10).unwrap(); // Type
    let len = 24 + content.len() as u32; // Header (24) + Content
    attr.write_u32::<LittleEndian>(len).unwrap();
    attr.write_u8(0).unwrap(); // Resident
    attr.write_u8(0).unwrap(); // Name len
    attr.write_u16::<LittleEndian>(0).unwrap(); // Name offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Flags
    attr.write_u16::<LittleEndian>(0).unwrap(); // ID
    attr.write_u32::<LittleEndian>(content.len() as u32)
        .unwrap(); // Content size
    attr.write_u16::<LittleEndian>(24).unwrap(); // Content offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Padding

    attr.extend_from_slice(&content);
    attr
}

fn create_fn_attribute(name: &str, parent_ref: u64) -> Vec<u8> {
    create_fn_attribute_times(name, parent_ref, 0, 0, 0, 0)
}

/// FILETIME (100ns since 1601) for a given Unix second plus a 100ns fraction.
fn filetime_from_unix(unix_secs: i64, subsec_100ns: u64) -> u64 {
    ((unix_secs + 11_644_473_600) as u64) * 10_000_000 + subsec_100ns
}

fn create_fn_attribute_times(
    name: &str,
    parent_ref: u64,
    c: u64,
    m: u64,
    mft: u64,
    a: u64,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes().to_vec())
        .collect();

    let mut content = vec![];
    content.write_u64::<LittleEndian>(parent_ref).unwrap(); // Parent ref
    content.write_u64::<LittleEndian>(c).unwrap(); // C
    content.write_u64::<LittleEndian>(m).unwrap(); // M
    content.write_u64::<LittleEndian>(mft).unwrap(); // MFT
    content.write_u64::<LittleEndian>(a).unwrap(); // A
    content.write_u64::<LittleEndian>(0).unwrap(); // Alloc size
    content.write_u64::<LittleEndian>(0).unwrap(); // Real size
    content.write_u32::<LittleEndian>(0).unwrap(); // Flags
    content.write_u32::<LittleEndian>(0).unwrap(); // Reparse
    content.write_u8(name.len() as u8).unwrap(); // Name len
    content.write_u8(0).unwrap(); // Namespace
    content.extend_from_slice(&name_bytes);

    // Padding to 8-byte alignment
    while content.len() % 8 != 0 {
        content.push(0);
    }

    let mut attr = vec![];
    attr.write_u32::<LittleEndian>(0x30).unwrap(); // Type
    let len = 24 + content.len() as u32;
    attr.write_u32::<LittleEndian>(len).unwrap();
    attr.write_u8(0).unwrap(); // Resident
    attr.write_u8(0).unwrap(); // Name len
    attr.write_u16::<LittleEndian>(0).unwrap(); // Name offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Flags
    attr.write_u16::<LittleEndian>(1).unwrap(); // ID
    attr.write_u32::<LittleEndian>(content.len() as u32)
        .unwrap(); // Content size
    attr.write_u16::<LittleEndian>(24).unwrap(); // Content offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Padding

    attr.extend_from_slice(&content);
    attr
}

fn create_data_run_list(runs: &[(u64, i64)]) -> Vec<u8> {
    let mut buf = vec![];
    for (len, offset) in runs {
        // Simple encoding: 1 byte len, 1 byte offset
        // TODO: Handle larger values if needed for tests
        let header = 0x11; // 1 byte off, 1 byte len
        buf.write_u8(header).unwrap();
        buf.write_u8(*len as u8).unwrap();
        buf.write_i8(*offset as i8).unwrap();
    }
    buf.write_u8(0).unwrap(); // Terminator
    buf
}

/// Non-resident $DATA whose real/allocated/initialized sizes are all fixed at
/// 40960 — i.e. exactly 10 clusters of 4096. Only use it for a fixture that
/// really is that shape. The parser clips a file's runs to its real_size and
/// zero-fills the never-written tail (`logical_extent_runs`), so a run list
/// with a different total, or a different cluster size, comes back clipped or
/// with a trailing sparse hole. Use `create_non_resident_data_attr_ex` and pass
/// the matching real_size instead.
fn create_non_resident_data_attr(runs: &[(u64, i64)]) -> Vec<u8> {
    create_non_resident_data_attr_ex(runs, 2, 0, 10, 40960)
}

/// Non-resident $DATA with explicit identity/extent fields. $ATTRIBUTE_LIST
/// fixtures need this: extension-record extents carry distinct attribute ids
/// and nonzero start VCNs.
fn create_non_resident_data_attr_ex(
    runs: &[(u64, i64)],
    attribute_id: u16,
    start_vcn: u64,
    last_vcn: u64,
    real_size: u64,
) -> Vec<u8> {
    create_non_resident_data_attr_raw(
        create_data_run_list(runs),
        attribute_id,
        start_vcn,
        last_vcn,
        real_size,
    )
}

/// Non-resident unnamed $DATA over an already-encoded run list.
fn create_non_resident_data_attr_raw(
    run_list: Vec<u8>,
    attribute_id: u16,
    start_vcn: u64,
    last_vcn: u64,
    real_size: u64,
) -> Vec<u8> {
    let mut attr = vec![];
    attr.write_u32::<LittleEndian>(0x80).unwrap(); // Type
    let len = 64 + run_list.len() as u32; // Header (64 for non-resident) + runs
                                          // Align length to 8 bytes
    let aligned_len = (len + 7) & !7;

    attr.write_u32::<LittleEndian>(aligned_len).unwrap();
    attr.write_u8(1).unwrap(); // Non-Resident
    attr.write_u8(0).unwrap(); // Name len
    attr.write_u16::<LittleEndian>(0).unwrap(); // Name offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Flags
    attr.write_u16::<LittleEndian>(attribute_id).unwrap(); // ID

    attr.write_u64::<LittleEndian>(start_vcn).unwrap(); // Start VCN
    attr.write_u64::<LittleEndian>(last_vcn).unwrap(); // Last VCN
    attr.write_u16::<LittleEndian>(64).unwrap(); // Runs offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Compression
    attr.write_u32::<LittleEndian>(0).unwrap(); // Padding
    attr.write_u64::<LittleEndian>(real_size).unwrap(); // Alloc size
    attr.write_u64::<LittleEndian>(real_size).unwrap(); // Real size
    attr.write_u64::<LittleEndian>(real_size).unwrap(); // Init size

    attr.extend_from_slice(&run_list);

    // Pad
    while attr.len() < aligned_len as usize {
        attr.push(0);
    }

    attr
}

/// Named (ADS) non-resident $DATA; the name sits between the 64-byte
/// non-resident header and the run list.
fn create_non_resident_named_data_attr_ex(
    name: &str,
    runs: &[(u64, i64)],
    attribute_id: u16,
    start_vcn: u64,
    last_vcn: u64,
    real_size: u64,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes().to_vec())
        .collect();
    let run_list = create_data_run_list(runs);
    let name_off = 64u16;
    let runs_off = 64 + ((name_bytes.len() as u16 + 7) & !7);

    let mut attr = vec![];
    attr.write_u32::<LittleEndian>(0x80).unwrap(); // Type
    let len = runs_off as u32 + run_list.len() as u32;
    let aligned_len = (len + 7) & !7;
    attr.write_u32::<LittleEndian>(aligned_len).unwrap();
    attr.write_u8(1).unwrap(); // Non-Resident
    attr.write_u8(name.len() as u8).unwrap(); // Name len
    attr.write_u16::<LittleEndian>(name_off).unwrap(); // Name offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Flags
    attr.write_u16::<LittleEndian>(attribute_id).unwrap(); // ID

    attr.write_u64::<LittleEndian>(start_vcn).unwrap();
    attr.write_u64::<LittleEndian>(last_vcn).unwrap();
    attr.write_u16::<LittleEndian>(runs_off).unwrap(); // Runs offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Compression
    attr.write_u32::<LittleEndian>(0).unwrap(); // Padding
    attr.write_u64::<LittleEndian>(real_size).unwrap();
    attr.write_u64::<LittleEndian>(real_size).unwrap();
    attr.write_u64::<LittleEndian>(real_size).unwrap();

    attr.extend_from_slice(&name_bytes);
    while attr.len() < runs_off as usize {
        attr.push(0);
    }
    attr.extend_from_slice(&run_list);
    while attr.len() < aligned_len as usize {
        attr.push(0);
    }

    attr
}

/// Generic resident attribute (used for INDEX_ROOT and resident DATA in tests)
fn create_resident_attr(attr_type: u32, content: &[u8]) -> Vec<u8> {
    let mut attr = vec![];
    attr.write_u32::<LittleEndian>(attr_type).unwrap();
    let len = 24 + content.len() as u32;
    let aligned_len = (len + 7) & !7;
    attr.write_u32::<LittleEndian>(aligned_len).unwrap();
    attr.write_u8(0).unwrap(); // Resident
    attr.write_u8(0).unwrap(); // Name len
    attr.write_u16::<LittleEndian>(0).unwrap(); // Name offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Flags
    attr.write_u16::<LittleEndian>(0).unwrap(); // ID
    attr.write_u32::<LittleEndian>(content.len() as u32)
        .unwrap(); // Content size
    attr.write_u16::<LittleEndian>(24).unwrap(); // Content offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Padding
    attr.extend_from_slice(content);
    while attr.len() < aligned_len as usize {
        attr.push(0);
    }
    attr
}

/// Assemble a full 1024-byte MFT record with fixups applied
fn build_record(record_num: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut record = vec![0u8; 1024];
    {
        let mut cursor = std::io::Cursor::new(&mut record[..]);
        cursor
            .write_all(&create_mft_header(record_num, 56))
            .unwrap();
        cursor.set_position(56);
        for attr in attrs {
            cursor.write_all(attr).unwrap();
        }
        cursor.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();
    }
    // Fixup signature (USN 0x1234) at end of both sectors
    record[510] = 0x34;
    record[511] = 0x12;
    record[1022] = 0x34;
    record[1023] = 0x12;
    record
}

/// Minimal NTFS boot sector for cluster-size and allocation-map tests
fn create_ntfs_boot_sector(
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    total_sectors: u64,
) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    buf[3..11].copy_from_slice(b"NTFS    ");
    buf[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
    buf[13] = sectors_per_cluster;
    buf[40..48].copy_from_slice(&total_sectors.to_le_bytes());
    buf[510] = 0x55;
    buf[511] = 0xAA;
    buf
}

// --- Tests ---

/// Encode one data run (`clusters` at absolute `lcn`) with minimal field
/// widths, as NTFS does.
fn encode_run(clusters: u64, lcn: i64) -> Vec<u8> {
    fn unsigned_len(v: u64) -> usize {
        (1..=8).find(|&n| n == 8 || v < 1u64 << (8 * n)).unwrap()
    }
    fn signed_len(v: i64) -> usize {
        (1..=8)
            .find(|&n| n == 8 || (v >= -(1i64 << (8 * n - 1)) && v < 1i64 << (8 * n - 1)))
            .unwrap()
    }
    let (l, o) = (unsigned_len(clusters), signed_len(lcn));
    let mut out = vec![((o as u8) << 4) | l as u8];
    out.extend_from_slice(&clusters.to_le_bytes()[..l]);
    out.extend_from_slice(&lcn.to_le_bytes()[..o]);
    out
}

/// Byte offset of the `$MFT` that [`write_ntfs_volume`] lays out.
fn mft_byte_offset(cluster_size: u64, mft_lcn: u64) -> u64 {
    cluster_size * mft_lcn
}

/// Lay out a real-shaped NTFS volume in `source`: `boot` (from
/// `create_ntfs_boot_sector`) at offset 0 with its `$MFT` cluster set to
/// `mft_lcn` and 1,024-byte records, a record 0 whose `$DATA` is one run
/// covering the table, and each of `records` at the slot its header names.
/// The table has at least 16 slots. Returns the `$MFT`'s byte offset.
fn write_ntfs_volume(
    source: &MockMftSource,
    boot: Vec<u8>,
    mft_lcn: u64,
    records: &[Vec<u8>],
) -> u64 {
    let slotted: Vec<(u64, Vec<u8>)> = records
        .iter()
        .map(|r| (header_slot(r), r.clone()))
        .collect();
    write_ntfs_volume_slotted(source, boot, mft_lcn, &slotted)
}

/// The slot an NTFS 3.1 record's header names (0x2C).
fn header_slot(r: &[u8]) -> u64 {
    u32::from_le_bytes(r[44..48].try_into().unwrap()) as u64
}

/// `write_ntfs_volume` with each record's slot given, for records whose
/// header carries no number (NTFS 3.0).
fn write_ntfs_volume_slotted(
    source: &MockMftSource,
    mut boot: Vec<u8>,
    mft_lcn: u64,
    records: &[(u64, Vec<u8>)],
) -> u64 {
    let parsed = crate::boot::NtfsBootSector::parse(&boot).expect("an NTFS boot sector");
    let cluster_size = parsed.cluster_size();
    boot[0x30..0x38].copy_from_slice(&(mft_lcn as i64).to_le_bytes());
    boot[0x40] = 0xF6; // 2^10 = 1,024-byte records, whatever the cluster size
    source.write_at(0, &boot);

    let slot_of = |r: &(u64, Vec<u8>)| r.0;
    let slots = records
        .iter()
        .map(slot_of)
        .max()
        .map_or(16, |m| (m + 1).max(16));
    let table_bytes = slots * 1024;
    let clusters = table_bytes.div_ceil(cluster_size);
    let mft_offset = mft_byte_offset(cluster_size, mft_lcn);
    if !records.iter().any(|r| slot_of(r) == 0) {
        let data = create_non_resident_data_attr_raw(
            {
                let mut runs = encode_run(clusters, mft_lcn as i64);
                runs.push(0);
                runs
            },
            2,
            0,
            clusters - 1,
            table_bytes,
        );
        source.write_at(
            mft_offset,
            &build_record(0, &[create_fn_attribute("$MFT", 5), data]),
        );
    }
    for r in records {
        source.write_at(mft_offset + slot_of(r) * 1024, &r.1);
    }
    // The volume reaches at least the end of the table.
    let end = mft_offset + clusters * cluster_size;
    if source.size() < end {
        source.write_at(end - 1, &[0]);
    }
    mft_offset
}

/// Re-lay the records staged in `staged` (at any 1,024-byte slot, as the
/// older fixtures write them) into a real-shaped NTFS volume with 4,096-byte
/// clusters, each at the table slot its header names. The parser reads a
/// volume's `$MFT` through record 0's runs and nothing else (HUNT-251), so a
/// fixture that is to be read as a volume has to be one.
fn as_ntfs_volume(staged: &MockMftSource) -> Arc<dyn DataSource> {
    let bytes = staged.data.lock().unwrap().clone();
    // A 3.1 record goes to the slot its header names; a 3.0 record (USA at
    // 0x2A, no number in its header) stays at the slot it was staged in.
    let records: Vec<(u64, Vec<u8>)> = bytes
        .as_chunks::<1024>()
        .0
        .iter()
        .enumerate()
        .filter(|(_, c)| &c[0..4] == b"FILE")
        .map(|(i, c)| {
            let usa_offset = u16::from_le_bytes([c[4], c[5]]);
            let slot = if usa_offset >= 0x30 {
                header_slot(c)
            } else {
                i as u64
            };
            (slot, c.to_vec())
        })
        .collect();
    let volume = MockMftSource::new(0);
    // Table at LCN 1,000 (byte 4,096,000): clear of every run a fixture names.
    write_ntfs_volume_slotted(
        &volume,
        create_ntfs_boot_sector(512, 8, 1 << 24),
        1000,
        &records,
    );
    Arc::new(volume)
}

/// A volume whose `$MFT` begins at a byte offset that is not a multiple of
/// the record size (512-byte clusters, the DFTT #3 shape) is read through the
/// table's runs, so every record is found. Stepping the volume from offset 0
/// in record-size strides once landed between records and found none.
#[test]
fn a_table_that_is_not_record_aligned_in_the_volume_is_read_through_its_runs() {
    let source = Arc::new(MockMftSource::new(0));
    let mft_offset = write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 1, 20_000),
        5355, // byte 2,741,760: 512 (mod 1024)
        &[build_record(14, &[create_fn_attribute("user.txt", 5)])],
    );
    assert_eq!(mft_offset % 1024, 512);
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    let file = find_entry(&results, "user.txt");
    assert_eq!(file.metadata["record_number"], 14);
    assert_eq!(file.metadata["mft_offset"], mft_offset + 14 * 1024);
}

#[test]
fn test_mft_parsing_basic() {
    let mft_source = Arc::new(MockMftSource::new(1024 * 10));

    // Create Record 0 ($MFT) - Usually has $DATA
    let mut record0 = vec![0u8; 1024];

    // Header
    let _header = create_mft_header(0, 56); // 56 start of attrs? 42 + 6 = 48 -> aligned
                                            // Actually let's just write header then attrs
    let mut cursor = std::io::Cursor::new(&mut record0);
    cursor.write_all(&create_mft_header(0, 56)).unwrap();

    // SI
    cursor.set_position(56);
    let si = create_si_attribute(1234567890123456789);
    cursor.write_all(&si).unwrap();

    // FN
    let fn_attr = create_fn_attribute("$MFT", 5); // Parent 5 (Root)
    cursor.write_all(&fn_attr).unwrap();

    // DATA (Non-resident)
    let runs = vec![(10, 100)]; // 10 clusters at offset 100
    let data_attr = create_non_resident_data_attr(&runs);
    cursor.write_all(&data_attr).unwrap();

    // End
    cursor.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();

    // Apply fixup signature (USN 0x1234) at end of sectors
    record0[510] = 0x34;
    record0[511] = 0x12;
    record0[1022] = 0x34;
    record0[1023] = 0x12;

    mft_source.write_at(0, &record0);

    // Create an artifact wrapper
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        // A volume, not a bare $MFT: the runs address this same buffer, and
        // only a FileSystem input serves them (HUNT-161).
        ArtifactType::FileSystem,
        Some(mft_source.clone()),
        serde_json::json!({
            "name": "analyzed_file.bin", // Generic name, parser detects content
            "cluster_size": 4096
        }),
    );

    let parser = MftParser::new();
    let results = parser.process(&artifact).expect("Parser failed");

    // Should produce:
    // 1. FileEntry for record 0
    // 2. Timeline events for SI and FN

    assert!(results.len() >= 2);

    let file_entry = results
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .unwrap();
    assert_eq!(file_entry.metadata["name"], "$MFT");
    assert_eq!(file_entry.metadata["record_number"], 0);

    // Verify Data Source on File Entry
    assert!(file_entry.data.is_some());
    // Should be able to read from the run list
    // (10, 100) -> 10 clusters at offset 100 * 4096 = 409600
    // Mock source only has 10k bytes, so read will return 0s if out of bounds,
    // but the structure is what we test.
}

#[test]
fn test_fixup_application() {
    let mut record = vec![0u8; 1024];

    // Set USN at offset 42
    record[42] = 0xAD;
    record[43] = 0xDE;

    // Original bytes (replacements)
    record[44] = 0xAA;
    record[45] = 0xBB;
    record[46] = 0xCC;
    record[47] = 0xDD;

    // Sector ends (should match USN)
    record[510] = 0xAD;
    record[511] = 0xDE;
    record[1022] = 0xAD;
    record[1023] = 0xDE;

    apply_fixups(&mut record, 42, 3).expect("Fixup failed");

    // Verify replacements
    assert_eq!(record[510], 0xAA);
    assert_eq!(record[511], 0xBB);
    assert_eq!(record[1022], 0xCC);
    assert_eq!(record[1023], 0xDD);
}

#[test]
fn test_fixup_validation_failure() {
    let mut record = vec![0u8; 1024];

    // Set USN
    record[42] = 0xAD;
    record[43] = 0xDE;

    // Sector end DOES NOT match USN
    record[510] = 0x00;
    record[511] = 0x00;

    let result = apply_fixups(&mut record, 42, 2);
    assert!(result.is_err());
}

#[test]
fn test_run_list_parsing() {
    use mft_structs::parse_data_runs;
    // 0x11: 1 byte offset, 1 byte len
    // 0x01: len=1
    // 0x02: offset=2
    // 0x00: terminator
    let data = vec![0x11, 0x01, 0x02, 0x00];

    let runs = parse_data_runs(&data);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0], (Some(2), 1));
}

#[test]
fn test_sparse_run_list() {
    use mft_structs::parse_data_runs;
    // 0x01: 0 byte offset (sparse), 1 byte len
    // 0x05: len=5
    let data = vec![0x01, 0x05, 0x00];

    let runs = parse_data_runs(&data);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0], (None, 5));
}

#[test]
fn test_negative_offset_run_list() {
    use mft_structs::parse_data_runs;
    // Run 1: Len 1, Offset 10
    // Run 2: Len 1, Offset -5 (Relative) -> Absolute 5
    let data = vec![
        0x11, 0x01, 0x0A, // (1, 10)
        0x11, 0x01, 0xFB, // (1, -5) -> 0xFB is -5 in i8
        0x00,
    ];

    let runs = parse_data_runs(&data);
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0], (Some(10), 1));
    assert_eq!(runs[1], (Some(5), 1));
}

#[test]
fn test_zero_and_out_of_range_filetime_is_none() {
    // FILETIME 0 is a timestomping indicator, not 1970 or 1601
    assert!(seance_core::time::filetime_to_datetime(0).is_none());
    // Below the 1970 epoch offset: out of range for artifact timestamps
    assert!(seance_core::time::filetime_to_datetime(116444735999999999).is_none());
}

#[test]
fn test_known_filetime_converts() {
    // 133484640000000000 = 2023-12-31T02:40:00Z (unix 1703990400)
    let dt = seance_core::time::filetime_to_datetime(133484640000000000).unwrap();
    assert_eq!(dt.timestamp(), 1703990400);
}

#[test]
fn test_zero_timestamps_absent_from_metadata() {
    let mft_source = Arc::new(MockMftSource::new(1024));
    let mut record = vec![0u8; 1024];

    let mut cursor = std::io::Cursor::new(&mut record);
    cursor.write_all(&create_mft_header(1, 56)).unwrap();

    cursor.set_position(56);
    // SI attribute with all-zero FILETIMEs (timestomped)
    cursor.write_all(&create_si_attribute(0)).unwrap();

    let fn_attr = create_fn_attribute("stomped.txt", 5);
    cursor.write_all(&fn_attr).unwrap();

    cursor.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();

    record[510] = 0x34;
    record[511] = 0x12;
    record[1022] = 0x34;
    record[1023] = 0x12;

    mft_source.write_at(0, &record);

    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(mft_source.clone()),
        serde_json::json!({"cluster_size": 4096}),
    );

    let parser = MftParser::new();
    let results = parser.process(&artifact).unwrap();

    let file_entry = results
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .expect("Should produce a FileEntry");
    assert!(
        file_entry.metadata.get("created").is_none(),
        "zero FILETIME must not become a created date"
    );
    assert!(file_entry.metadata.get("modified").is_none());
    assert!(file_entry.metadata.get("accessed").is_none());

    // No timeline events should be emitted for zero timestamps
    let events: Vec<_> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();
    assert!(
        events.is_empty(),
        "zero FILETIMEs must not generate 1970 timeline events"
    );
}

#[test]
fn test_timeline_event_generation() {
    let mft_source = Arc::new(MockMftSource::new(1024));
    let mut record = vec![0u8; 1024];

    // Basic record with SI and FN
    let mut cursor = std::io::Cursor::new(&mut record);
    cursor.write_all(&create_mft_header(1, 56)).unwrap();

    cursor.set_position(56);
    // Use a known timestamp: 2024-01-01 00:00:00 UTC
    // 133484640000000000 (approx)
    let ts = 133484640000000000;
    cursor.write_all(&create_si_attribute(ts)).unwrap();

    let fn_attr = create_fn_attribute("test_file.txt", 5);
    cursor.write_all(&fn_attr).unwrap();

    cursor.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();

    // Fixups
    record[510] = 0x34;
    record[511] = 0x12;
    record[1022] = 0x34;
    record[1023] = 0x12;

    mft_source.write_at(0, &record);

    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(mft_source.clone()),
        serde_json::json!({"cluster_size": 4096}),
    );

    let parser = MftParser::new();
    let results = parser.process(&artifact).unwrap();

    // Should have events for SI (C, M, MFT, A) = 4 events.
    // The FN attribute in this fixture carries a zero FILETIME, which must
    // not fabricate a 1970 "Created (FN)" event.
    let events: Vec<_> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();
    assert_eq!(events.len(), 4);

    let created_event = events
        .iter()
        .find(|e| e.metadata["timestamp_desc"] == "Created")
        .unwrap();
    assert_eq!(created_event.metadata["filename"], "test_file.txt");
    assert_eq!(created_event.metadata["artifact_type"], "FILE");
}
/// HUNT-125: timeline events are 8 of every 9 artifacts this module makes and
/// were held in memory until the whole table had been walked. Streamed, they
/// leave in batches, and nothing else about the output changes.
#[test]
fn streamed_timeline_events_leave_in_batches_and_the_rest_is_unchanged() {
    let records = 6u32;
    let mft_source = Arc::new(MockMftSource::new(1024 * records as usize));
    for n in 0..records {
        let mut record = vec![0u8; 1024];
        let mut cursor = std::io::Cursor::new(&mut record);
        cursor.write_all(&create_mft_header(n, 56)).unwrap();
        cursor.set_position(56);
        cursor
            .write_all(&create_si_attribute(133484640000000000 + n as u64))
            .unwrap();
        cursor
            .write_all(&create_fn_attribute(&format!("file_{n}.txt"), 5))
            .unwrap();
        cursor.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();
        record[510] = 0x34;
        record[511] = 0x12;
        record[1022] = 0x34;
        record[1023] = 0x12;
        mft_source.write_at(n as u64 * 1024, &record);
    }
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(mft_source.clone()),
        serde_json::json!({"cluster_size": 4096}),
    );
    let is_event = |a: &Artifact| a.artifact_type == ArtifactType::TimelineEvent;

    let parser = MftParser::new();
    let whole = parser.process(&artifact).unwrap();
    let whole_events = whole.iter().filter(|a| is_event(a)).count();
    assert!(
        whole_events >= 2 * 4,
        "the fixture must make events: {whole_events}"
    );

    // A flush threshold of 5 events across 6 records is several mid-walk flushes
    // and a part-filled tail.
    let mut batches: Vec<Vec<Artifact>> = Vec::new();
    let kept = parser
        .process_records(&artifact, Some(&mut |b| batches.push(b)), 5, false)
        .unwrap();

    assert!(
        kept.iter().all(|a| !is_event(a)),
        "a streaming run must not also return the events"
    );
    assert!(batches.len() >= 2, "events must leave mid-walk, in batches");
    assert!(batches
        .iter()
        .all(|b| !b.is_empty() && b.iter().all(is_event)));
    let streamed: usize = batches.iter().map(Vec::len).sum();
    assert_eq!(streamed, whole_events, "every event, exactly once");
    assert_eq!(
        kept.len(),
        whole.len() - whole_events,
        "everything that is not an event is returned unchanged"
    );
    // The events are the same events: same descriptions and timestamps.
    let key = |a: &Artifact| {
        format!(
            "{}|{}|{}",
            a.metadata["filename"], a.metadata["timestamp_desc"], a.metadata["timestamp"]
        )
    };
    let mut a: Vec<String> = whole.iter().filter(|x| is_event(x)).map(key).collect();
    let mut b: Vec<String> = batches.iter().flatten().map(key).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
}

/// HUNT-125: a caller that wants each record once (the shadow-copy comparison)
/// gets every file entry through the sink and holds none of them.
#[test]
fn a_full_stream_delivers_every_record_and_returns_nothing() {
    let records = 6u32;
    let mft_source = Arc::new(MockMftSource::new(1024 * records as usize));
    for n in 0..records {
        let mut record = vec![0u8; 1024];
        let mut cursor = std::io::Cursor::new(&mut record);
        cursor.write_all(&create_mft_header(n, 56)).unwrap();
        cursor.set_position(56);
        cursor
            .write_all(&create_si_attribute(133484640000000000 + n as u64))
            .unwrap();
        cursor
            .write_all(&create_fn_attribute(&format!("file_{n}.txt"), 5))
            .unwrap();
        cursor.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();
        record[510] = 0x34;
        record[511] = 0x12;
        record[1022] = 0x34;
        record[1023] = 0x12;
        mft_source.write_at(n as u64 * 1024, &record);
    }
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(mft_source.clone()),
        serde_json::json!({"cluster_size": 4096}),
    );
    let parser = MftParser::new();
    let whole = parser.process(&artifact).unwrap();

    let mut streamed: Vec<Artifact> = Vec::new();
    let kept = parser
        .process_records(&artifact, Some(&mut |b| streamed.extend(b)), 2, true)
        .unwrap();
    assert!(
        kept.len() < whole.len() && streamed.len() + kept.len() == whole.len(),
        "everything is accounted for, and most of it left through the sink"
    );
    let entries = |v: &[Artifact]| {
        v.iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .count()
    };
    assert_eq!(entries(&streamed) + entries(&kept), entries(&whole));

    // The public walk sees each base record once, through the same path.
    let mut names: Vec<String> = Vec::new();
    crate::volume_mft::parse_bare_mft_each(mft_source.clone(), 4096, 1024, &mut |m| {
        names.push(m["name"].as_str().unwrap_or_default().to_string())
    })
    .unwrap();
    let collected = crate::volume_mft::parse_bare_mft(mft_source, 4096, 1024).unwrap();
    assert_eq!(names.len(), collected.len());
    assert!(!names.is_empty());
}

// ==========================================
// ERROR PATH TESTS
// Tests for corrupted/invalid MFT data
// ==========================================

#[test]
fn test_corrupted_mft_signature() {
    // Create MFT with invalid signature
    let source = Arc::new(MockMftSource::new(2048));

    let mut bad_record = vec![0u8; 1024];
    // Set invalid signature (should be "FILE")
    bad_record[0..4].copy_from_slice(b"XXXX");
    bad_record[4..8].copy_from_slice(&[0x30, 0x00, 0x2A, 0x00]); // Fixup offset
    bad_record[20..22].copy_from_slice(&[0x30, 0x00]); // First attr offset
    source.write_at(0, &bad_record);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let parser = MftParser::new();
    let results = parser.process(&artifact).unwrap();

    // Should skip invalid record and return empty
    assert_eq!(results.len(), 0);
}

#[test]
fn test_truncated_mft_record() {
    // Create MFT with truncated record (less than 1024 bytes)
    let source = Arc::new(MockMftSource::new(512)); // Only 512 bytes, not enough for a record

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let parser = MftParser::new();
    let results = parser.process(&artifact).unwrap();

    // Should handle truncation gracefully
    assert_eq!(results.len(), 0);
}

#[test]
fn test_mft_missing_data_source() {
    // Test that parser returns error when artifact has no data source
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        None, // No data source
        serde_json::json!({"cluster_size": 4096}),
    );

    let parser = MftParser::new();
    let result = parser.process(&artifact);

    // Should return InvalidInputFormat error
    assert!(result.is_err());
    if let Err(ModuleError::InvalidInputFormat(msg)) = result {
        assert!(msg.contains("data source"));
    } else {
        panic!("Expected InvalidInputFormat error");
    }
}

#[test]
fn test_mft_corrupt_attribute_header() {
    let source = Arc::new(MockMftSource::new(2048));

    // Create a minimal FILE record with corrupted attribute
    let mut record = create_mft_header(5, 56);

    // Add corrupt attribute header (invalid type, length extends beyond record)
    let mut attr = vec![];
    attr.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap(); // Invalid attribute type
    attr.write_u32::<LittleEndian>(5000).unwrap(); // Length exceeds record size
    attr.write_u8(0).unwrap(); // Non-resident flag
    attr.write_u8(0).unwrap(); // Name length
    attr.write_u16::<LittleEndian>(0).unwrap(); // Name offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Flags
    attr.write_u16::<LittleEndian>(0).unwrap(); // Attribute ID

    record.extend_from_slice(&attr);
    record.resize(1024, 0); // Pad to full record size

    source.write_at(0, &record);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let parser = MftParser::new();
    let results = parser.process(&artifact).unwrap();

    // Should handle corrupt attributes gracefully (skip or minimal output)
    // Parser should not panic
    // Parser should not panic - results may be empty or have entries
    let _ = results.len();
}

#[test]
fn test_mft_zero_length_record() {
    let source = Arc::new(MockMftSource::new(1024));

    // Create record with all zeros (completely empty)
    let zero_record = vec![0u8; 1024];
    source.write_at(0, &zero_record);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let parser = MftParser::new();
    let results = parser.process(&artifact).unwrap();

    // Should skip zero record gracefully
    assert_eq!(results.len(), 0);
}

#[test]
fn test_mft_invalid_cluster_size() {
    let source = Arc::new(MockMftSource::new(2048));

    // Create valid MFT record using existing helper
    let mut record = vec![0u8; 1024];
    let header = create_mft_header(0, 56);
    record[..header.len()].copy_from_slice(&header);
    source.write_at(0, &record);

    // Test with missing cluster_size (should default to 4096)
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source.clone()),
        serde_json::json!({}), // No cluster_size
    );

    let parser = MftParser::new();
    let results = parser.process(&artifact).unwrap();

    // Should use default cluster size and parse successfully (0 results for minimal record)
    // Parser should not panic - results may be empty or have entries
    let _ = results.len();
}

// === Infinite Loop Protection Tests ===

#[test]
fn test_parse_data_runs_zero_length_size() {
    use mft_structs::parse_data_runs;

    // Header byte 0x10 = len_size=0, offset_size=1 (invalid: len_size cannot be 0)
    // This would have caused an infinite loop before the fix
    let malformed_data = vec![0x10, 0x01, 0x00]; // Invalid encoding

    // Should return empty or partial result, NOT hang
    let runs = parse_data_runs(&malformed_data);
    // The function should exit quickly, not loop forever
    assert!(runs.is_empty() || runs.len() < 100);
}

#[test]
fn test_parse_data_runs_zero_length_clusters() {
    use mft_structs::parse_data_runs;

    // Header 0x11 = len_size=1, offset_size=1
    // Length = 0 (zero clusters), Offset = 1
    // Zero-length runs should be skipped
    let data_with_zero_length = vec![
        0x11, 0x00, 0x01, // Zero-length run (should be skipped)
        0x11, 0x05, 0x02, // Valid run: 5 clusters at offset +2
        0x00, // Terminator
    ];

    let runs = parse_data_runs(&data_with_zero_length);

    // Should only have the valid run, zero-length was skipped
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].1, 5); // 5 clusters
}

#[test]
fn test_parse_data_runs_max_iterations() {
    use mft_structs::parse_data_runs;

    // Create data that would loop many times without a limit
    // Each run is: header=0x11 (1 byte len, 1 byte offset), len=1, offset=1
    let mut infinite_pattern = Vec::new();
    for _ in 0..20000 {
        // Way more than MAX_DATA_RUNS
        infinite_pattern.push(0x11); // header
        infinite_pattern.push(0x01); // length = 1
        infinite_pattern.push(0x01); // offset = 1
    }
    // No terminator - would loop "forever" without limit

    let runs = parse_data_runs(&infinite_pattern);

    // Should be capped at MAX_DATA_RUNS (10000)
    assert!(runs.len() <= 10000);
}

#[test]
fn test_parse_data_runs_no_terminator() {
    use mft_structs::parse_data_runs;

    // Valid-looking runs but no 0x00 terminator
    let no_terminator = vec![
        0x11, 0x05, 0x10, // 5 clusters at LCN +16
        0x21, 0x0A, 0x00,
        0x20, // 10 clusters at LCN +32 (2-byte offset)
              // No 0x00 terminator, data ends
    ];

    let runs = parse_data_runs(&no_terminator);

    // Should parse 2 runs and stop at end of data
    assert_eq!(runs.len(), 2);
}

#[test]
fn test_attribute_loop_max_iterations() {
    // Create a record with many attributes to test the loop limit
    let source = MockMftSource::new(4096);

    // Write MFT header
    let mut header = vec![0u8; 48];
    header[0..4].copy_from_slice(b"FILE");
    header[20..22].copy_from_slice(&24u16.to_le_bytes()); // first_attr_offset = 24
    header[22..24].copy_from_slice(&0x0001u16.to_le_bytes()); // flags = in_use

    source.write_at(0, &header);

    // Write many minimal attributes that point to each other (could loop)
    // Each attribute: type=0x10 (STANDARD_INFO), length=24, resident, content_offset=24
    for i in 0..150 {
        let offset = 24 + (i * 24);
        let mut attr = vec![0u8; 24];
        attr[0..4].copy_from_slice(&0x10u32.to_le_bytes()); // type = STANDARD_INFO
        attr[4..8].copy_from_slice(&24u32.to_le_bytes()); // length = 24
        attr[8] = 0; // resident
        attr[20..22].copy_from_slice(&24u16.to_le_bytes()); // content_offset
        source.write_at(offset as u64, &attr);
    }

    // Write END marker after many attributes
    source.write_at(24 + (150 * 24), &0xFFFFFFFFu32.to_le_bytes());

    let source_arc: Arc<dyn DataSource> = Arc::new(source);
    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileSystem,
        Some(source_arc.clone()),
        serde_json::json!({"cluster_size": 4096}),
    );

    let parser = MftParser::new();
    // This should complete quickly, not hang (even with 150 attributes)
    // The limit is 100, so it will stop early
    let results = parser.process(&artifact);
    assert!(results.is_ok());
}

// ==========================================
// PATH RECONSTRUCTION / METADATA CONTRACT TESTS
// ==========================================

fn index_root_attr() -> Vec<u8> {
    create_resident_attr(0x90, &[0u8; 32])
}

fn find_entry<'a>(results: &'a [Artifact], name: &str) -> &'a Artifact {
    results
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry && a.metadata["name"] == name)
        .unwrap_or_else(|| panic!("Missing FileEntry {}", name))
}

#[test]
fn test_path_reconstruction() {
    let source = Arc::new(MockMftSource::new(1024 * 3));
    // Record 5: root directory "."
    source.write_at(
        0,
        &build_record(5, &[create_fn_attribute(".", 5), index_root_attr()]),
    );
    // Record 10: directory "docs" under root
    source.write_at(
        1024,
        &build_record(10, &[create_fn_attribute("docs", 5), index_root_attr()]),
    );
    // Record 11: file "file.txt" under docs
    source.write_at(
        2048,
        &build_record(11, &[create_fn_attribute("file.txt", 10)]),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();

    let root = find_entry(&results, ".");
    assert_eq!(root.metadata["path"], "/");
    assert_eq!(root.metadata["parent_path"], "/");

    let docs = find_entry(&results, "docs");
    assert_eq!(docs.metadata["path"], "/docs");
    assert_eq!(docs.metadata["parent_path"], "/");
    assert_eq!(docs.metadata["is_directory"], true);

    let file = find_entry(&results, "file.txt");
    assert_eq!(file.metadata["path"], "/docs/file.txt");
    assert_eq!(file.metadata["parent_path"], "/docs");
}

#[test]
fn test_orphan_and_cycle_paths() {
    let source = Arc::new(MockMftSource::new(1024 * 3));
    // Record 20: parent 99 does not exist -> orphan
    source.write_at(0, &build_record(20, &[create_fn_attribute("lost.txt", 99)]));
    // Records 30/31: parent cycle -> orphan
    source.write_at(
        1024,
        &build_record(30, &[create_fn_attribute("a", 31), index_root_attr()]),
    );
    source.write_at(
        2048,
        &build_record(31, &[create_fn_attribute("b", 30), index_root_attr()]),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();

    let lost = find_entry(&results, "lost.txt");
    assert_eq!(lost.metadata["path"], "/$OrphanFiles/lost.txt");
    assert_eq!(lost.metadata["parent_path"], "/$OrphanFiles");

    let a = find_entry(&results, "a");
    assert_eq!(a.metadata["path"], "/$OrphanFiles/a");
}

/// HUNT-065. A `$FILE_NAME` parent reference is a record number AND a
/// sequence number, and the sequence is what says whether the record still
/// holds the directory the file was in. The path builder masked the sequence
/// off and followed the record number alone, so a deleted file whose directory
/// was deleted and its record reused was grafted under whatever now lives
/// there. On the NIST Data Leakage image 1,419 entries — an installer's
/// unpacked `.pyd` files — read as
/// `…/Recent/Resignation_Letter_(Iaman_Informant).docx.lnk/win32file.pyd`,
/// a path through two files that were never directories.
#[test]
fn a_parent_whose_record_was_reused_makes_an_orphan_not_a_path_through_the_new_occupant() {
    let source = Arc::new(MockMftSource::new(1024 * 3));
    // Record 10 is a FILE (no $INDEX_ROOT) at sequence 1 under root.
    source.write_at(
        1024,
        &build_record(10, &[create_fn_attribute("note.lnk", 5)]),
    );
    // Record 11 names record 10 as its parent at sequence 3; the record now
    // holds sequence 1. The directory the reference meant is gone and the
    // slot has been reused: the reference is stale.
    let stale_parent = 10u64 | (3u64 << 48);
    source.write_at(
        2048,
        &build_record(11, &[create_fn_attribute("win32file.pyd", stale_parent)]),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(as_ntfs_volume(&source)),
        serde_json::json!({"cluster_size": 4096}),
    );
    let results = MftParser::new().process(&artifact).unwrap();

    let pyd = find_entry(&results, "win32file.pyd");
    assert_eq!(
        pyd.metadata["path"], "/$OrphanFiles/win32file.pyd",
        "a path through note.lnk would name a directory that never existed: {}",
        pyd.metadata["path"]
    );
    assert_eq!(pyd.metadata["orphan_reason"], "parent_record_reused");

    // A live file under a live directory, sequence matching, still resolves:
    // record 12 is a directory at sequence 1, record 13 names it with seq 1.
    let source = Arc::new(MockMftSource::new(1024 * 3));
    source.write_at(
        1024,
        &build_record(12, &[create_fn_attribute("docs", 5), index_root_attr()]),
    );
    let parent_with_seq = 12u64 | (1u64 << 48);
    source.write_at(
        2048,
        &build_record(13, &[create_fn_attribute("file.txt", parent_with_seq)]),
    );
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(as_ntfs_volume(&source)),
        serde_json::json!({"cluster_size": 4096}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    let f = find_entry(&results, "file.txt");
    assert_eq!(f.metadata["path"], "/docs/file.txt");
    assert!(f.metadata.get("orphan_reason").is_none());

    // A parent at the right sequence that is not a directory is not a parent.
    let source = Arc::new(MockMftSource::new(1024 * 3));
    source.write_at(
        1024,
        &build_record(14, &[create_fn_attribute("plain.txt", 5)]),
    );
    source.write_at(
        2048,
        &build_record(
            15,
            &[create_fn_attribute("child.txt", 14u64 | (1u64 << 48))],
        ),
    );
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(as_ntfs_volume(&source)),
        serde_json::json!({"cluster_size": 4096}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    let c = find_entry(&results, "child.txt");
    assert_eq!(c.metadata["path"], "/$OrphanFiles/child.txt");
    assert_eq!(c.metadata["orphan_reason"], "parent_not_a_directory");
}

#[test]
fn test_data_runs_metadata_coalesced() {
    let source = Arc::new(MockMftSource::new(1024));
    // Two contiguous runs: 10 clusters at LCN 100, then 5 clusters at LCN 110.
    // real_size covers all 15 clusters, so the whole allocation is logical file
    // content and nothing is clipped as cluster slack.
    let data_attr = create_non_resident_data_attr_ex(&[(10, 100), (5, 10)], 2, 0, 14, 15 * 4096);
    source.write_at(
        0,
        &build_record(12, &[create_fn_attribute("frag.bin", 5), data_attr]),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let file = find_entry(&results, "frag.bin");

    // Contiguous runs must coalesce: offset 100*4096, length 15*4096
    assert_eq!(
        file.metadata["data_runs"],
        serde_json::json!([[409600u64, 61440u64]])
    );
    assert_eq!(file.metadata["data_runs_complete"], true);
    assert!(file.metadata.get("resident_data_b64").is_none());
}

#[test]
fn test_resident_data_b64() {
    let source = Arc::new(MockMftSource::new(1024));
    let data_attr = create_resident_attr(0x80, b"hello world");
    source.write_at(
        0,
        &build_record(13, &[create_fn_attribute("small.txt", 5), data_attr]),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let file = find_entry(&results, "small.txt");

    assert_eq!(file.metadata["resident_data_b64"], "aGVsbG8gd29ybGQ=");
    assert!(
        file.metadata.get("data_runs").is_none(),
        "resident files carry no data_runs"
    );
    assert_eq!(file.metadata["path"], "/small.txt");

    // Resident content must also be readable through the artifact data source
    let data = file
        .data
        .as_ref()
        .expect("resident file should have a data source");
    let mut buf = vec![0u8; 11];
    assert_eq!(data.read_at(0, &mut buf).unwrap(), 11);
    assert_eq!(&buf, b"hello world");
}

#[test]
fn test_directories_have_no_data_runs() {
    let source = Arc::new(MockMftSource::new(1024));
    source.write_at(
        0,
        &build_record(10, &[create_fn_attribute("docs", 5), index_root_attr()]),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let dir = find_entry(&results, "docs");
    assert!(dir.metadata.get("data_runs").is_none());
    assert!(dir.metadata.get("resident_data_b64").is_none());
}

#[test]
fn test_cluster_size_from_boot_sector() {
    // Boot sector says 512 * 2 = 1024-byte clusters; metadata says 4096.
    // The boot sector must win for FileSystem inputs.
    let source = Arc::new(MockMftSource::new(0));
    // 10 clusters of 1024 bytes, fully written: real_size matches the
    // allocation so no part of it is clipped as slack.
    let data_attr = create_non_resident_data_attr_ex(&[(10, 100)], 2, 0, 9, 10 * 1024);
    write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 2, 2048),
        20,
        &[build_record(
            14,
            &[create_fn_attribute("clus.bin", 5), data_attr],
        )],
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let file = find_entry(&results, "clus.bin");

    // 100 clusters * 1024 = 102400 offset, 10 * 1024 = 10240 length
    assert_eq!(
        file.metadata["data_runs"],
        serde_json::json!([[102400u64, 10240u64]])
    );
}

#[test]
fn test_allocation_map_from_bitmap_record() {
    // Volume: 512-byte sectors, 2 sectors/cluster (1024), 256 sectors -> 128 clusters
    let source = Arc::new(MockMftSource::new(1024 * 16));

    // Record 6: $Bitmap with one 1-cluster run at LCN 10 (byte offset 10240)
    let data_attr = create_non_resident_data_attr(&[(1, 10)]);
    write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 2, 256),
        20,
        &[build_record(
            6,
            &[create_fn_attribute("$Bitmap", 5), data_attr],
        )],
    );

    // Bitmap content: first 64 clusters allocated, rest free
    source.write_at(10240, &[0xFFu8; 8]);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let map = results
        .iter()
        .find(|a| {
            a.artifact_type == ArtifactType::ParsedRecord && a.metadata["type"] == "allocation_map"
        })
        .expect("allocation_map artifact should be emitted");

    assert_eq!(map.parent_id, Some(artifact.id));
    assert_eq!(map.metadata["allocation_total_clusters"], 128);
    assert_eq!(map.metadata["allocation_cluster_size"], 1024);
    assert_eq!(map.metadata["allocation_clusters_per_bucket"], 1);

    use base64::Engine as _;
    let buckets = base64::engine::general_purpose::STANDARD
        .decode(map.metadata["allocation_bitmap_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(buckets.len(), 128);
    assert!(buckets[..64].iter().all(|&b| b == 255));
    assert!(buckets[64..].iter().all(|&b| b == 0));
}

#[test]
fn test_no_allocation_map_for_bare_mft_input() {
    // Bare $MFT (FileEntry input): no volume window, so no allocation map
    let source = Arc::new(MockMftSource::new(1024));
    let data_attr = create_non_resident_data_attr(&[(1, 10)]);
    source.write_at(
        0,
        &build_record(6, &[create_fn_attribute("$Bitmap", 5), data_attr]),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    assert!(
        !results
            .iter()
            .any(|a| a.artifact_type == ArtifactType::ParsedRecord),
        "bare $MFT inputs must not fabricate an allocation map"
    );
}

#[test]
fn test_fixture_mft_paths_smoke() {
    // Real-world MFT fixture: every FileEntry must carry the path contract keys
    let path = std::path::Path::new("../test_data/mft/nist-hacking-case.mft");
    if !path.exists() {
        eprintln!("skipping: nist-hacking-case.mft not present (gitignored corpus, absent in CI)");
        return;
    }
    let data = std::fs::read(path).expect("fixture nist-hacking-case.mft missing");
    let source = Arc::new(MockMftSource::new(0));
    source.write_at(0, &data);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let entries: Vec<_> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect();
    assert!(
        entries.len() > 1000,
        "expected many entries, got {}",
        entries.len()
    );

    for entry in &entries {
        let p = entry.metadata["path"]
            .as_str()
            .unwrap_or_else(|| panic!("missing path on {:?}", entry.metadata["name"]));
        assert!(p.starts_with('/'), "path must be absolute: {}", p);
        assert!(entry.metadata["parent_path"].is_string());
    }

    // Most records on a real volume resolve to real paths, not orphans
    let orphans = entries
        .iter()
        .filter(|e| {
            e.metadata["path"]
                .as_str()
                .unwrap()
                .starts_with("/$OrphanFiles")
        })
        .count();
    assert!(
        orphans * 2 < entries.len(),
        "too many orphans: {}/{}",
        orphans,
        entries.len()
    );

    // Deep nesting must exist
    assert!(entries
        .iter()
        .any(|e| e.metadata["path"].as_str().unwrap().matches('/').count() >= 3));
}

#[test]
fn test_mft_progress_reporter_receives_record_events() {
    use seance_core::orchestrator::{OrchestratorEvent, ProgressReporter};

    let path = std::path::Path::new("../test_data/mft/nist-hacking-case.mft");
    if !path.exists() {
        eprintln!("skipping: nist-hacking-case.mft not present (gitignored corpus, absent in CI)");
        return;
    }
    let data = std::fs::read(path).expect("fixture nist-hacking-case.mft missing");
    let source = Arc::new(MockMftSource::new(0));
    source.write_at(0, &data);

    let (tx, mut rx) = tokio::sync::broadcast::channel(4096);
    let reporter = ProgressReporter::new(tx, "plugin.ntfs.mft_parser");
    let parser = MftParser::new().with_progress(reporter);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );
    let artifact_id = artifact.id;
    parser.process(&artifact).unwrap();

    let mut saw_records = false;
    while let Ok(event) = rx.try_recv() {
        if let OrchestratorEvent::ModuleProgress {
            module_id,
            artifact_id: reported_id,
            units_total,
            unit,
            ..
        } = event
        {
            assert_eq!(module_id, "plugin.ntfs.mft_parser");
            assert_eq!(reported_id, artifact_id);
            assert_eq!(unit, "records");
            assert!(
                units_total.unwrap() > 0,
                "denominator must be a real record count"
            );
            saw_records = true;
        }
    }
    assert!(
        saw_records,
        "expected at least one ModuleProgress event with unit=records"
    );
}

#[test]
fn test_mft_cancellation_returns_early() {
    use seance_core::orchestrator::CancellationHandle;

    let path = std::path::Path::new("../test_data/mft/nist-hacking-case.mft");
    if !path.exists() {
        eprintln!("skipping: nist-hacking-case.mft not present (gitignored corpus, absent in CI)");
        return;
    }
    let data = std::fs::read(path).expect("fixture nist-hacking-case.mft missing");
    let source = Arc::new(MockMftSource::new(0));
    source.write_at(0, &data);

    let handle = CancellationHandle::new();
    handle.cancel_all();
    let parser = MftParser::new().with_cancellation(handle);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );
    let results = parser.process(&artifact).unwrap();

    // A full parse of this fixture yields >1000 FileEntry artifacts; a
    // pre-cancelled run must break the record loop before producing them.
    let entries = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .count();
    assert!(
        entries < 100,
        "cancelled parse should stop early, got {} entries",
        entries
    );
}

// ==========================================
// $FILE_NAME MACB + TIMESTOMP DETECTION TESTS
// ==========================================

/// Build a single-record MFT source with the given SI and FN attributes and run
/// the parser over it as a FileSystem artifact.
fn parse_single_record(record_num: u32, si: Vec<u8>, fn_attr: Vec<u8>) -> Vec<Artifact> {
    let source = Arc::new(MockMftSource::new(1024));
    source.write_at(0, &build_record(record_num, &[si, fn_attr]));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );
    MftParser::new().process(&artifact).unwrap()
}

#[test]
fn test_fn_macb_emits_four_distinct_events() {
    // FN with four distinct, valid MACB timestamps must yield four FN events.
    let base = filetime_from_unix(1_600_000_000, 5_000_000); // 2020-09-13, .5s
    let fn_c = base;
    let fn_m = base + 100 * 10_000_000; // +100s
    let fn_mft = base + 200 * 10_000_000;
    let fn_a = base + 300 * 10_000_000;

    let results = parse_single_record(
        40,
        create_si_attribute(base),
        create_fn_attribute_times("macb.txt", 5, fn_c, fn_m, fn_mft, fn_a),
    );

    let fn_events: Vec<_> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .filter(|a| {
            a.metadata["timestamp_type"]
                .as_str()
                .map(|s| s.starts_with("FN_"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(fn_events.len(), 4, "expected four FN timeline events");

    let by_type = |t: &str| {
        fn_events
            .iter()
            .find(|e| e.metadata["timestamp_type"] == t)
            .unwrap_or_else(|| panic!("missing FN event {}", t))
    };
    assert_eq!(
        by_type("FN_Created").metadata["timestamp_desc"],
        "Created (FN)"
    );
    assert_eq!(
        by_type("FN_Modified").metadata["timestamp_desc"],
        "Modified (FN)"
    );
    assert_eq!(
        by_type("FN_MftModified").metadata["timestamp_desc"],
        "MFT Modified (FN)"
    );
    assert_eq!(
        by_type("FN_Accessed").metadata["timestamp_desc"],
        "Accessed (FN)"
    );

    // FileEntry must carry the four fn_* metadata keys.
    let file = find_entry(&results, "macb.txt");
    assert!(file.metadata["fn_created"].is_string());
    assert!(file.metadata["fn_modified"].is_string());
    assert!(file.metadata["fn_mft_modified"].is_string());
    assert!(file.metadata["fn_accessed"].is_string());
}

/// The indicators a file carries, as `(reason, strength)`.
fn indicators(file: &Artifact) -> Vec<(String, String)> {
    file.metadata
        .get("timestamp_indicators")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|i| {
                    (
                        i["reason"].as_str().unwrap_or_default().to_string(),
                        i["strength"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_copied_file_is_reported_as_an_indicator_and_not_as_tampering() {
    // The single largest false positive HUNT-051 measured: a copy keeps the
    // source's Last-Modified in $SI while $FN Created records when the copy
    // landed, so `SI Modified < FN Created` is what every installed file looks
    // like. 4,026 files on a stock Windows XP install carried exactly this.
    let copied_at = filetime_from_unix(1_672_531_200, 1_234_567);
    let modified_before = filetime_from_unix(1_262_304_000, 7_654_321);
    let si = create_si_attribute_times(
        copied_at,       // created when the copy landed
        modified_before, // modification time carried over from the source
        copied_at,
        copied_at + 10_000_000,
    );
    let fn_attr = create_fn_attribute_times(
        "installed.dll",
        5,
        copied_at,
        copied_at,
        copied_at,
        copied_at,
    );

    let results = parse_single_record(41, si, fn_attr);
    let file = find_entry(&results, "installed.dll");

    assert_eq!(
        file.metadata["timestomp_suspected"], false,
        "an ordinary copy must not be reported as timestomping"
    );
    assert!(
        file.metadata["timestomp_reasons"]
            .as_array()
            .unwrap()
            .is_empty(),
        "the reasons key carries what the verdict rests on, and there is no verdict"
    );
    let seen = indicators(file);
    assert_eq!(
        seen,
        vec![(
            "SI Modified precedes FN Created".to_string(),
            "weak".to_string()
        )],
        "the observation is still reported, as a weak indicator"
    );
    // And the ordinary operation that produces it is named beside it, so the
    // reader is not left to work out why it is weak.
    let benign = file.metadata["timestamp_indicators"][0]["also_produced_by"]
        .as_str()
        .unwrap_or_default();
    assert!(benign.contains("copy"), "{benign}");
}

#[test]
fn a_moved_file_carries_two_weak_indicators_and_still_no_verdict() {
    // What every file in \RECYCLER looks like: the move writes a fresh $FN
    // while $SI keeps both the original creation and modification times. Two
    // weak indicators, one ordinary explanation, no tampering.
    let moved_at = filetime_from_unix(1_672_531_200, 1_234_567);
    let created_before = filetime_from_unix(1_262_304_000, 7_654_321);
    let modified_before = filetime_from_unix(1_262_304_500, 111_111);
    let si = create_si_attribute_times(
        created_before,
        modified_before,
        moved_at,
        moved_at + 10_000_000,
    );
    let fn_attr = create_fn_attribute_times("Dc1.exe", 5, moved_at, moved_at, moved_at, moved_at);

    let results = parse_single_record(44, si, fn_attr);
    let file = find_entry(&results, "Dc1.exe");

    assert_eq!(file.metadata["timestomp_suspected"], false);
    let seen: Vec<String> = indicators(file).into_iter().map(|(r, _)| r).collect();
    assert_eq!(
        seen,
        vec![
            "SI Created precedes FN Created".to_string(),
            "SI Modified precedes FN Created".to_string(),
        ],
        "both observations are reported; neither is a verdict"
    );
}

#[test]
fn bulk_set_timestamps_are_the_one_pattern_that_asserts_tampering() {
    // All four SI values identical to the second, with an FN Created that
    // differs. No copy, move or rename produces this: those four diverge the
    // moment a file is written or read. This is what a stamping tool leaves.
    let stamped = filetime_from_unix(1_262_304_000, 0);
    let real_creation = filetime_from_unix(1_672_531_200, 1_234_567);
    let si = create_si_attribute_times(stamped, stamped, stamped, stamped);
    let fn_attr = create_fn_attribute_times(
        "stomped.exe",
        5,
        real_creation,
        real_creation,
        real_creation,
        real_creation,
    );

    let results = parse_single_record(42, si, fn_attr);
    let file = find_entry(&results, "stomped.exe");

    assert_eq!(
        file.metadata["timestomp_suspected"], true,
        "a strong indicator is what a verdict rests on"
    );
    let reasons = file.metadata["timestomp_reasons"].as_array().unwrap();
    assert!(
        reasons
            .iter()
            .any(|r| r.as_str().unwrap().contains("bulk-set")),
        "the verdict must name what it rests on, got {reasons:?}"
    );
    assert!(
        indicators(file).iter().any(|(_, s)| s == "strong"),
        "and the indicator list must grade it strong"
    );
}

/// HUNT-152: the parser's own output, not a hand-built record, has to reach
/// the timestomp lead. The module is dispatched what it subscribes to, so the
/// entry the parser emits must be of that type and carry the verdict.
#[test]
fn the_parsers_file_entry_raises_the_timestomp_lead() {
    use seance_plugin_findings::TimestompFindings;

    let stomped = filetime_from_unix(1_600_471_735, 0);
    let real_name = filetime_from_unix(1_600_486_096, 9_704_452);
    let results = parse_single_record(
        47,
        create_si_attribute_times(stomped, stomped, stomped, stomped),
        create_fn_attribute_times("stomped.exe", 5, real_name, real_name, real_name, real_name),
    );
    let file = find_entry(&results, "stomped.exe");

    let module = TimestompFindings::new();
    assert!(
        module.subscribes_to().contains(&file.artifact_type),
        "the lead is never dispatched the {:?} the parser writes the verdict on",
        file.artifact_type
    );
    let out = module.process(file).expect("processed");
    assert_eq!(out.len(), 1, "one lead for one stomped file");
    let lead = &out[0].metadata;
    assert_eq!(lead["finding_kind"], "timestomp");
    assert_eq!(lead["subject_artifact_id"], file.id.to_string());
    let evidence = lead["evidence"].to_string();
    assert!(evidence.contains("si_mft_modified"), "{evidence}");
    assert!(evidence.contains("fn_created"), "{evidence}");

    // An ordinary file from the same parser raises nothing.
    let t = filetime_from_unix(1_600_486_096, 9_704_452);
    let plain = parse_single_record(
        48,
        create_si_attribute_times(t, t, t, t),
        create_fn_attribute_times("plain.txt", 5, t, t, t, t),
    );
    let plain = find_entry(&plain, "plain.txt");
    assert!(module.process(plain).expect("processed").is_empty());
}

/// HUNT-073: DFIR Madness Case 001's `Beth_Secret.txt`. Its $SI times were
/// set to the evening before the intrusion, whole seconds, ChangeTime
/// included (2020-09-18T23:35:35); its $FN Created is 2020-09-19T03:34:56.97.
/// The filesystem writes ChangeTime with full precision every time the
/// record changes, and writing the name entry is a record change, so a
/// whole-second ChangeTime older than the record's own name was written by
/// something other than the filesystem. Measured on three Windows images
/// (276,563 file records) this fires on exactly that file. The three weak
/// indicators it also carries left the verdict at "not suspected".
#[test]
fn a_whole_second_change_time_older_than_the_name_entry_asserts_tampering() {
    let stomped_created = filetime_from_unix(1_600_471_634, 0); // 2020-09-18T23:33:54Z
    let stomped_modified = filetime_from_unix(1_600_471_735, 0); // 2020-09-18T23:35:35Z
    let real_name = filetime_from_unix(1_600_486_096, 9_704_452); // 2020-09-19T03:34:56.97Z
    let si = create_si_attribute_times(
        stomped_created,
        stomped_modified,
        stomped_modified,
        stomped_created,
    );
    let fn_attr = create_fn_attribute_times(
        "Beth_Secret.txt",
        5,
        real_name,
        real_name,
        real_name,
        real_name,
    );

    let results = parse_single_record(46, si, fn_attr);
    let file = find_entry(&results, "Beth_Secret.txt");

    assert_eq!(
        file.metadata["timestomp_suspected"], true,
        "a whole-second ChangeTime older than the name entry is not something the \
         filesystem writes"
    );
    let seen = indicators(file);
    assert!(
        seen.iter()
            .any(|(r, s)| r.contains("MFT-changed is whole-second") && s == "strong"),
        "{seen:?}"
    );
    // The three weak observations are still there for the examiner.
    assert_eq!(
        seen.iter().filter(|(_, s)| s == "weak").count(),
        3,
        "{seen:?}"
    );
}

/// The same ChangeTime-before-name pattern with a sub-second ChangeTime is
/// what AppX deployment, WinSxS servicing and the driver store leave (4,231
/// files on Case 001's two Windows images, all under those trees): restore
/// semantics carry the source's full-precision ChangeTime. Not tampering.
#[test]
fn a_sub_second_change_time_older_than_the_name_entry_is_not_a_verdict() {
    let deployed = filetime_from_unix(1_600_471_735, 1_234_567);
    let real_name = filetime_from_unix(1_600_486_096, 9_704_452);
    // The SI values differ from each other so the bulk-set signal stays out
    // of the picture; this test is about the ChangeTime alone.
    let si = create_si_attribute_times(
        deployed,
        deployed + 10_000_000,
        deployed + 20_000_000,
        deployed + 30_000_000,
    );
    let fn_attr =
        create_fn_attribute_times("appx.dll", 5, real_name, real_name, real_name, real_name);
    let results = parse_single_record(47, si, fn_attr);
    let file = find_entry(&results, "appx.dll");
    assert_eq!(file.metadata["timestomp_suspected"], false);
    assert!(
        !indicators(file)
            .iter()
            .any(|(r, _)| r.contains("MFT-changed")),
        "{:?}",
        indicators(file)
    );
}

/// A whole-second ChangeTime that is NOT older than the name entry is what a
/// copy from a FAT volume followed by nothing else looks like only for the
/// other three values; the ChangeTime itself is the copy time. Stated as a
/// guard: equal seconds do not fire.
#[test]
fn a_whole_second_change_time_in_the_same_second_as_the_name_does_not_fire() {
    let name = filetime_from_unix(1_600_486_096, 9_704_452);
    let change = filetime_from_unix(1_600_486_096, 0);
    let si = create_si_attribute_times(change, change, change, change);
    let fn_attr = create_fn_attribute_times("fat.txt", 5, name, name, name, name);
    let results = parse_single_record(48, si, fn_attr);
    let file = find_entry(&results, "fat.txt");
    assert!(
        !indicators(file)
            .iter()
            .any(|(r, _)| r.contains("MFT-changed")),
        "{:?}",
        indicators(file)
    );
}

#[test]
fn a_clean_file_carries_no_indicators_at_all() {
    let base = filetime_from_unix(1_600_000_000, 5_000_000);
    let si = create_si_attribute_times(
        base,
        base + 100 * 10_000_000,
        base + 200 * 10_000_000,
        base + 300 * 10_000_000,
    );
    let fn_attr = create_fn_attribute_times("clean.txt", 5, base, base, base, base);

    let results = parse_single_record(43, si, fn_attr);
    let file = find_entry(&results, "clean.txt");

    assert_eq!(file.metadata["timestomp_suspected"], false);
    assert!(file.metadata["timestomp_reasons"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(
        file.metadata.get("timestamp_indicators").is_none(),
        "nothing observed means the key is absent, not an empty list to read past"
    );
}

#[test]
fn a_whole_second_si_against_a_sub_second_fn_is_weak_and_names_fat() {
    // Classic one-second-granularity stamping — and equally what a copy from a
    // FAT volume leaves, which is why it is weak on its own.
    let fn_c = filetime_from_unix(1_672_531_200, 4_500_000);
    let si_c = filetime_from_unix(1_672_531_200, 0);
    let si = create_si_attribute_times(
        si_c,
        si_c + 10_000_000,
        si_c + 20_000_000,
        si_c + 30_000_000,
    );
    let fn_attr = create_fn_attribute_times("trunc.txt", 5, fn_c, fn_c, fn_c, fn_c);

    let results = parse_single_record(45, si, fn_attr);
    let file = find_entry(&results, "trunc.txt");

    assert_eq!(file.metadata["timestomp_suspected"], false);
    let seen = indicators(file);
    assert!(
        seen.iter()
            .any(|(r, s)| r.contains("whole-second") && s == "weak"),
        "{seen:?}"
    );
    let benign = file.metadata["timestamp_indicators"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| {
            i["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("whole-second")
        })
        .and_then(|i| i["also_produced_by"].as_str())
        .unwrap_or_default();
    assert!(
        benign.contains("FAT"),
        "the coarse-granularity source is named: {benign}"
    );
}

#[test]
fn the_reverse_sub_second_direction_is_not_reported() {
    // FN whole-second against a fractional SI is not something a stamping tool
    // produces, and reporting it was noise for its own sake.
    let fn_c = filetime_from_unix(1_672_531_200, 0);
    let si_c = filetime_from_unix(1_672_531_200, 4_500_000);
    let si = create_si_attribute_times(
        si_c,
        si_c + 10_000_000,
        si_c + 20_000_000,
        si_c + 30_000_000,
    );
    let fn_attr = create_fn_attribute_times("reverse.txt", 5, fn_c, fn_c, fn_c, fn_c);

    let results = parse_single_record(46, si, fn_attr);
    let file = find_entry(&results, "reverse.txt");

    assert_eq!(file.metadata["timestomp_suspected"], false);
    let seen = indicators(file);
    assert!(
        !seen.iter().any(|(r, _)| r.contains("whole-second")),
        "{seen:?}"
    );
}

#[test]
fn test_fixture_fn_macb_events_present() {
    // Real-world MFT: FN attributes carry full MACB, so FN Modified / MFT /
    // Accessed events must appear across the volume, not just FN Created.
    let path = std::path::Path::new("../test_data/mft/nist-hacking-case.mft");
    if !path.exists() {
        eprintln!("skipping: nist-hacking-case.mft not present (gitignored corpus, absent in CI)");
        return;
    }
    let data = std::fs::read(path).expect("fixture nist-hacking-case.mft missing");
    let source = Arc::new(MockMftSource::new(0));
    source.write_at(0, &data);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let count_type = |t: &str| {
        results
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
            .filter(|a| a.metadata["timestamp_type"] == t)
            .count()
    };

    assert!(count_type("FN_Created") > 0, "no FN_Created events");
    assert!(count_type("FN_Modified") > 0, "no FN_Modified events");
    assert!(count_type("FN_MftModified") > 0, "no FN_MftModified events");
    assert!(count_type("FN_Accessed") > 0, "no FN_Accessed events");

    // Every primary file-record entry (not an ADS sub-stream) must carry the
    // timestomp verdict keys.
    let entries: Vec<_> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter(|a| a.metadata.get("is_ads").and_then(|v| v.as_bool()) != Some(true))
        .collect();
    assert!(entries
        .iter()
        .all(|e| e.metadata["timestomp_suspected"].is_boolean()));
    assert!(entries
        .iter()
        .all(|e| e.metadata["timestomp_reasons"].is_array()));
}

// --- Regression: one unreadable region must not truncate enumeration ---

/// Data source that reports a full-size volume but fails the read at exactly one
/// record offset, simulating a single unreadable region in the middle of the MFT.
#[derive(Debug)]
struct HoleyMftSource {
    data: Vec<u8>,
    bad_offset: u64,
}

impl DataSource for HoleyMftSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset == self.bad_offset {
            return Err(std::io::Error::other("simulated bad region"));
        }
        if offset >= self.data.len() as u64 {
            return Ok(0);
        }
        let available = self.data.len() as u64 - offset;
        let to_read = std::cmp::min(available, buf.len() as u64) as usize;
        buf[..to_read].copy_from_slice(&self.data[offset as usize..offset as usize + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Build a complete 1024-byte MFT record with SI + FN attributes, mirroring the
/// construction used by `test_mft_parsing_basic`.
fn build_named_record(record_num: u32, name: &str) -> Vec<u8> {
    let mut record = vec![0u8; 1024];
    let mut cursor = std::io::Cursor::new(&mut record);
    cursor
        .write_all(&create_mft_header(record_num, 56))
        .unwrap();
    cursor.set_position(56);
    cursor
        .write_all(&create_si_attribute(1234567890123456789))
        .unwrap();
    cursor.write_all(&create_fn_attribute(name, 5)).unwrap();
    cursor.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap(); // attribute-list end
                                                           // Fixup signature (USN 0x1234) at the end of each 512-byte sector.
    record[510] = 0x34;
    record[511] = 0x12;
    record[1022] = 0x34;
    record[1023] = 0x12;
    record
}

#[test]
fn test_unreadable_region_does_not_truncate_enumeration() {
    // Four record slots; slot 1 (offset 1024) is an unreadable hole. Records in
    // slots 2 and 3 sit *after* the hole and must still be enumerated.
    let mut data = vec![0u8; 1024 * 4];
    data[0..1024].copy_from_slice(&build_named_record(0, "file0"));
    // slot 1 left as zeros; the source errors on reads there anyway
    data[2048..3072].copy_from_slice(&build_named_record(2, "file2"));
    data[3072..4096].copy_from_slice(&build_named_record(3, "file3"));

    let source = Arc::new(HoleyMftSource {
        data,
        bad_offset: 1024,
    });
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({ "cluster_size": 4096 }),
    );

    let results = MftParser::new().process(&artifact).expect("parser failed");

    let names: Vec<&str> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
        .collect();

    // The pre-fix bug aborted at the first short/failed read, dropping file2/file3.
    assert!(
        names.contains(&"file2"),
        "record after the unreadable region was dropped: {:?}",
        names
    );
    assert!(
        names.contains(&"file3"),
        "record after the unreadable region was dropped: {:?}",
        names
    );

    // The loss must be surfaced, not hidden: a summary artifact reports the count.
    let summary = results
        .iter()
        .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("mft_parse_summary"))
        .expect("expected an mft_parse_summary artifact when records are skipped");
    assert_eq!(summary.metadata["unreadable_records"], 1);
}

/// Regression (I6): the `$MFT` of a large-cluster volume is found at the
/// cluster the boot sector names, with the sectors-per-cluster byte decoded
/// the way the boot-sector parser does it (a byte > 0xF0 means 2^(256 - byte)
/// sectors). Read as the raw byte, the `$MFT` offset is wrong and every record
/// is missed.
#[test]
fn a_large_cluster_volume_finds_its_mft_at_the_decoded_cluster() {
    let source = Arc::new(MockMftSource::new(0));
    // 0xF6 -> 1,024 sectors of 512 bytes: 512 KiB clusters. `$MFT` at LCN 1.
    let mft_offset = write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 0xF6, 1024 * 8),
        1,
        &[build_record(20, &[create_fn_attribute("big.txt", 5)])],
    );
    assert_eq!(
        mft_offset,
        1024 * 512,
        "the decoded spc (1024), not the raw 246"
    );
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    assert_eq!(
        find_entry(&results, "big.txt").metadata["record_number"],
        20
    );
}

#[test]
fn test_decode_sectors_per_cluster() {
    assert_eq!(crate::boot::decode_sectors_per_cluster(8), Some(8));
    assert_eq!(crate::boot::decode_sectors_per_cluster(0x80), Some(0x80));
    assert_eq!(crate::boot::decode_sectors_per_cluster(0xF6), Some(1024)); // 2^(256-246)
    assert_eq!(crate::boot::decode_sectors_per_cluster(0), None);
    assert_eq!(crate::boot::decode_sectors_per_cluster(0x90), None); // reserved range
}

/// A hostile MFT can set the compression-unit exponent to anything a u16 holds.
/// `1u64 << 64` is a panic under overflow-checks, and that panic would unwind
/// the whole MFT parse and lose every file in the table — so a corrupt exponent
/// must yield `None`, not a crash and not a fabricated size. Found by fuzzing
/// (`mft_parser` shift-left overflow at the old `1u64 << compression_unit`).
#[test]
fn compression_unit_bytes_never_overflows_on_a_corrupt_exponent() {
    // Ordinary NTFS: exponent 4 → 16 clusters × 4096 = 65536.
    assert_eq!(compression_unit_bytes(4, 4096), Some(65_536));
    assert_eq!(compression_unit_bytes(0, 4096), Some(4096));
    // A shift of 64 or more would panic on the bare `1u64 << exp`.
    assert_eq!(compression_unit_bytes(64, 4096), None);
    assert_eq!(compression_unit_bytes(255, 4096), None);
    assert_eq!(compression_unit_bytes(u16::MAX, 512), None);
    // In range for the shift but the product overflows u64.
    assert_eq!(compression_unit_bytes(63, 4096), None);
}

// ==========================================
// $ATTRIBUTE_LIST (fragmented attribute) TESTS
// ==========================================

/// Build one $ATTRIBUTE_LIST entry. `base_ref` is the full 64-bit file
/// reference (48-bit record number | 16-bit sequence in the high bits).
fn create_attr_list_entry(
    attribute_type: u32,
    lowest_vcn: u64,
    base_ref: u64,
    attribute_id: u16,
    name: Option<&str>,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = name
        .map(|n| {
            n.encode_utf16()
                .flat_map(|c| c.to_le_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default();
    let mut entry = vec![];
    entry.write_u32::<LittleEndian>(attribute_type).unwrap();
    entry
        .write_u16::<LittleEndian>(0x1A + name_bytes.len() as u16)
        .unwrap(); // entry length
    entry
        .write_u8(name.map(|n| n.len() as u8).unwrap_or(0))
        .unwrap(); // name len (UTF-16 units)
    entry
        .write_u8(if name_bytes.is_empty() { 0 } else { 0x1A })
        .unwrap(); // name offset
    entry.write_i64::<LittleEndian>(lowest_vcn as i64).unwrap();
    entry.write_u64::<LittleEndian>(base_ref).unwrap();
    entry.write_u16::<LittleEndian>(attribute_id).unwrap();
    entry.extend_from_slice(&name_bytes);
    entry
}

/// Resident $ATTRIBUTE_LIST attribute wrapping the given raw entries.
fn create_attribute_list_attr(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut content = vec![];
    for e in entries {
        content.extend_from_slice(e);
    }
    create_resident_attr(0x20, &content)
}

/// Set a record's base file reference (0x20..0x28). An extension record
/// names the base record that owns it here; a base record holds zero.
fn with_base_ref(mut record: Vec<u8>, base_ref: u64) -> Vec<u8> {
    record[0x20..0x28].copy_from_slice(&base_ref.to_le_bytes());
    record
}

/// Assemble a 1024-byte NTFS 3.0 (Windows 2000) record. Its header has no
/// record number: the update sequence array starts at 0x2A and runs to 0x30,
/// where the first attribute begins. `at_2c` is the first fixup replacement
/// word, the bytes a 3.1 reader would misread as the record number.
fn build_record_v30(attrs: &[Vec<u8>], base_ref: u64, at_2c: u16) -> Vec<u8> {
    let mut record = vec![0u8; 1024];
    record[0..4].copy_from_slice(b"FILE");
    record[4..6].copy_from_slice(&0x2Au16.to_le_bytes()); // usa_offset
    record[6..8].copy_from_slice(&3u16.to_le_bytes()); // usa_size
    record[0x10..0x12].copy_from_slice(&1u16.to_le_bytes()); // sequence
    record[0x12..0x14].copy_from_slice(&1u16.to_le_bytes()); // hard links
    record[0x14..0x16].copy_from_slice(&0x30u16.to_le_bytes()); // first attr
    record[0x16..0x18].copy_from_slice(&1u16.to_le_bytes()); // IN_USE
    record[0x18..0x1C].copy_from_slice(&1024u32.to_le_bytes());
    record[0x1C..0x20].copy_from_slice(&1024u32.to_le_bytes());
    record[0x20..0x28].copy_from_slice(&base_ref.to_le_bytes());
    // USA: USN 0x1234, then the two sector-end replacement words.
    record[0x2A..0x2C].copy_from_slice(&0x1234u16.to_le_bytes());
    record[0x2C..0x2E].copy_from_slice(&at_2c.to_le_bytes());
    let mut pos = 0x30;
    for attr in attrs {
        record[pos..pos + attr.len()].copy_from_slice(attr);
        pos += attr.len();
    }
    record[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // Sector 1 ends with `at_2c` after fixup; store the USN placeholder.
    record[510..512].copy_from_slice(&0x1234u16.to_le_bytes());
    record[1022..1024].copy_from_slice(&0x1234u16.to_le_bytes());
    record
}

/// HUNT-256: an NTFS 3.0 extension record has no header record number, so
/// the trust check must not compare 0x2C (USA bytes) against the slot. The
/// base reference is what ties it to the file.
#[test]
fn ntfs30_attribute_list_extension_record_is_merged() {
    let source = Arc::new(MockMftSource::new(1024 * 42));
    let cluster = 4096u64;

    let base_data = create_non_resident_data_attr_ex(&[(2, 100)], 2, 0, 1, 5 * cluster);
    let attr_list = create_attribute_list_attr(&[
        create_attr_list_entry(0x80, 0, 40 | (1 << 48), 2, None),
        create_attr_list_entry(0x80, 2, 41 | (1 << 48), 5, None),
    ]);
    source.write_at(
        40 * 1024,
        &build_record_v30(
            &[create_fn_attribute("w2k.bin", 5), base_data, attr_list],
            0,
            0,
        ),
    );
    let ext_data = create_non_resident_data_attr_ex(&[(3, 50)], 5, 2, 4, 5 * cluster);
    source.write_at(
        41 * 1024,
        &build_record_v30(&[ext_data], 40 | (1 << 48), 0x1147),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(as_ntfs_volume(&source)),
        serde_json::json!({"cluster_size": 4096}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    let file = find_entry(&results, "w2k.bin");
    assert_eq!(
        file.metadata["data_runs"],
        serde_json::json!([[100 * cluster, 2 * cluster], [50 * cluster, 3 * cluster]])
    );
    assert_eq!(file.metadata["data_runs_complete"], true);
}

/// An extension record whose base reference names another file is not this
/// file's extent, on either NTFS version. On 3.0 that reference is the only
/// link; on 3.1 it is checked as well as the header record number.
fn foreign_base_extension_is_untrusted(v30: bool) {
    let source = Arc::new(MockMftSource::new(1024 * 42));
    let cluster = 4096u64;

    let base_data = create_non_resident_data_attr_ex(&[(2, 100)], 2, 0, 1, 5 * cluster);
    let attr_list = create_attribute_list_attr(&[
        create_attr_list_entry(0x80, 0, 40 | (1 << 48), 2, None),
        create_attr_list_entry(0x80, 2, 41 | (1 << 48), 5, None),
    ]);
    let base_attrs = [create_fn_attribute("foreign.bin", 5), base_data, attr_list];
    let ext_data = create_non_resident_data_attr_ex(&[(3, 50)], 5, 2, 4, 5 * cluster);
    let foreign = 7 | (1 << 48);
    if v30 {
        source.write_at(40 * 1024, &build_record_v30(&base_attrs, 0, 0));
        source.write_at(41 * 1024, &build_record_v30(&[ext_data], foreign, 0));
    } else {
        source.write_at(40 * 1024, &build_record(40, &base_attrs));
        source.write_at(
            41 * 1024,
            &with_base_ref(build_record(41, &[ext_data]), foreign),
        );
    }

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(as_ntfs_volume(&source)),
        serde_json::json!({"cluster_size": 4096}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    let file = find_entry(&results, "foreign.bin");
    assert_eq!(file.metadata["data_runs_complete"], false);
    assert_eq!(
        file.metadata["data_runs"],
        serde_json::json!([[100 * cluster, 2 * cluster], [null, 3 * cluster]]),
        "the foreign record's extent must not be merged"
    );
}

#[test]
fn ntfs30_extension_record_with_foreign_base_reference_is_untrusted() {
    foreign_base_extension_is_untrusted(true);
}

#[test]
fn ntfs31_extension_record_with_foreign_base_reference_is_untrusted() {
    foreign_base_extension_is_untrusted(false);
}

/// Non-resident `$INDEX_ALLOCATION:$I30` over `runs` (clusters, LCN delta).
fn create_i30_index_allocation_attr(
    runs: &[(u64, i64)],
    attribute_id: u16,
    start_vcn: u64,
    last_vcn: u64,
    size: u64,
) -> Vec<u8> {
    let mut attr = create_non_resident_named_data_attr_ex(
        "$I30",
        runs,
        attribute_id,
        start_vcn,
        last_vcn,
        size,
    );
    attr[0..4].copy_from_slice(&0xA0u32.to_le_bytes());
    attr
}

/// A directory whose `$I30` index allocation lives in an extension record,
/// laid out as a volume with 4 KiB clusters. The extension record's base
/// reference is `ext_base`; `INDX` markers sit in the index's two clusters.
fn directory_with_extension_index(v30: bool, ext_base: u64) -> Vec<Artifact> {
    let cluster = 4096u64;
    let attr_list = create_attribute_list_attr(&[create_attr_list_entry(
        0xA0,
        0,
        41 | (1 << 48),
        4,
        Some("$I30"),
    )]);
    let base_attrs = [
        create_fn_attribute("bigdir", 5),
        index_root_attr(),
        attr_list,
    ];
    let ext_attrs = [create_i30_index_allocation_attr(
        &[(2, 50)],
        4,
        0,
        1,
        2 * cluster,
    )];
    let root = [create_fn_attribute(".", 5), index_root_attr()];
    let records: Vec<(u64, Vec<u8>)> = if v30 {
        vec![
            (5, build_record_v30(&root, 0, 0x0500)),
            (40, build_record_v30(&base_attrs, 0, 0x2800)),
            (41, build_record_v30(&ext_attrs, ext_base, 0x1147)),
        ]
    } else {
        vec![
            (5, build_record(5, &root)),
            (40, build_record(40, &base_attrs)),
            (41, with_base_ref(build_record(41, &ext_attrs), ext_base)),
        ]
    };
    let volume = MockMftSource::new(0);
    write_ntfs_volume_slotted(
        &volume,
        create_ntfs_boot_sector(512, 8, 1 << 24),
        1000,
        &records,
    );
    volume.write_at(50 * cluster, b"INDX-first");
    volume.write_at(51 * cluster, b"INDX-second");
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(volume)),
        serde_json::json!({"cluster_size": 4096}),
    );
    MftParser::new().process(&artifact).unwrap()
}

fn i30_of<'a>(results: &'a [Artifact], dir: &str) -> Option<&'a Artifact> {
    results
        .iter()
        .find(|a| a.metadata["name"] == "$I30" && a.metadata["parent_file"] == dir)
}

/// HUNT-256 grading found this on the real Windows 2000 volume: the `$I30`
/// index allocation of `/WINNT/system32/dllcache` (record 70) lives wholly in
/// extension record 5,597, and the directory was published with no `$I30`
/// stream at all and nothing saying so. The index's clusters are resolved
/// through the `$ATTRIBUTE_LIST` like a `$DATA` extent, on both versions.
fn extension_index_allocation_is_published(v30: bool) {
    let results = directory_with_extension_index(v30, 40 | (1 << 48));
    let i30 = i30_of(&results, "bigdir").expect("the directory's $I30 stream is published");
    let data = i30
        .data
        .as_ref()
        .expect("the index's clusters are addressable");
    assert_eq!(data.size(), 2 * 4096);
    let mut buf = [0u8; 11];
    data.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf[..10], b"INDX-first");
    data.read_at(4096, &mut buf).unwrap();
    assert_eq!(&buf, b"INDX-second");
    assert!(i30.metadata.get("content_incomplete").is_none());
}

#[test]
fn ntfs30_extension_index_allocation_is_published() {
    extension_index_allocation_is_published(true);
}

#[test]
fn ntfs31_extension_index_allocation_is_published() {
    extension_index_allocation_is_published(false);
}

/// When the extension record that holds a listed `$I30` extent cannot be
/// trusted (here it names another base file), the stream is still published
/// — the list proves it exists — but flagged incomplete, never silently
/// dropped and never filled from the foreign record.
#[test]
fn unresolvable_extension_index_allocation_is_flagged_not_dropped() {
    let results = directory_with_extension_index(true, 7 | (1 << 48));
    let i30 = i30_of(&results, "bigdir").expect("a listed $I30 stream is not dropped");
    assert!(i30.data.is_none(), "no clusters from the foreign record");
    assert_eq!(i30.metadata["content_incomplete"], true);
    assert_eq!(
        i30.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

#[test]
fn test_attribute_list_merges_extension_record_runs() {
    // Record 40 (base): $DATA extent for VCN 0..2 (2 clusters at LCN 100) plus
    // a resident $ATTRIBUTE_LIST naming record 41 for the continuation.
    // Record 41 (extension): $DATA extent for VCN 2..5 (3 clusters at LCN 50).
    // The extension LCN is LOWER than the base LCN on purpose: the merged list
    // must follow lowest_vcn order, not byte order.
    let source = Arc::new(MockMftSource::new(1024 * 42));
    let cluster = 4096u64;

    let base_data = create_non_resident_data_attr_ex(&[(2, 100)], 2, 0, 1, 5 * cluster);
    let attr_list = create_attribute_list_attr(&[
        create_attr_list_entry(0x80, 0, 40 | (1 << 48), 2, None),
        create_attr_list_entry(0x80, 2, 41 | (1 << 48), 5, None),
    ]);
    source.write_at(
        40 * 1024,
        &build_record(
            40,
            &[create_fn_attribute("big.bin", 5), base_data, attr_list],
        ),
    );

    let ext_data = create_non_resident_data_attr_ex(&[(3, 50)], 5, 2, 4, 5 * cluster);
    source.write_at(
        41 * 1024,
        &with_base_ref(build_record(41, &[ext_data]), 40 | (1 << 48)),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(as_ntfs_volume(&source)),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let file = find_entry(&results, "big.bin");

    // Base fragment first (vcn 0), then the extension fragment (vcn 2).
    assert_eq!(
        file.metadata["data_runs"],
        serde_json::json!([[100 * cluster, 2 * cluster], [50 * cluster, 3 * cluster]])
    );
    assert_eq!(file.metadata["data_runs_complete"], true);

    // The extension record has no $FILE_NAME and must not surface as a file
    // (the volume's own `$MFT`, record 0, is the only other entry).
    assert_eq!(
        results
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .filter(|a| a.metadata["name"] != "$MFT")
            .count(),
        1
    );
}

#[test]
fn test_attribute_list_unreadable_extension_flags_incomplete() {
    // Same fragmented layout, but the extension records cannot be recovered:
    // one reference is out of range (record 999), another points at a slot
    // with no FILE signature. The base fragments must still be emitted, with
    // data_runs_complete = false.
    let source = Arc::new(MockMftSource::new(1024 * 42));
    let cluster = 4096u64;

    let base_data = create_non_resident_data_attr_ex(&[(2, 100)], 2, 0, 1, 7 * cluster);
    let attr_list = create_attribute_list_attr(&[
        create_attr_list_entry(0x80, 0, 40 | (1 << 48), 2, None),
        create_attr_list_entry(0x80, 2, 999 | (1 << 48), 5, None), // out of range
        create_attr_list_entry(0x80, 4, 20 | (1 << 48), 6, None),  // zeroed slot
    ]);
    source.write_at(
        40 * 1024,
        &build_record(
            40,
            &[create_fn_attribute("partial.bin", 5), base_data, attr_list],
        ),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(as_ntfs_volume(&source)),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let file = find_entry(&results, "partial.bin");

    // The base extent is emitted at its true offset. The 5 clusters the
    // unreadable extension records would have described are held open as a
    // hole, so the run list still spans the file's declared 7 clusters instead
    // of quietly describing a 2-cluster file. The hole is only honest because
    // the flags below say the list is not the whole file.
    assert_eq!(
        file.metadata["data_runs"],
        serde_json::json!([[100 * cluster, 2 * cluster], [null, 5 * cluster]])
    );
    assert_eq!(file.metadata["data_runs_complete"], false);
    assert_eq!(file.metadata["content_incomplete"], true);
    assert_eq!(
        file.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

#[test]
fn test_attribute_list_bogus_entry_length_does_not_panic() {
    // A corrupt $ATTRIBUTE_LIST: one valid self-referencing entry, then an
    // entry claiming a huge length. The parser must skip the damage safely,
    // keep the base record's runs, and flag them incomplete.
    let source = Arc::new(MockMftSource::new(1024 * 41));
    let cluster = 4096u64;

    let base_data = create_non_resident_data_attr_ex(&[(2, 100)], 2, 0, 1, 2 * cluster);
    let mut bogus = vec![];
    bogus.write_u32::<LittleEndian>(0x80).unwrap(); // type
    bogus.write_u16::<LittleEndian>(0xFFFF).unwrap(); // bogus entry length
    bogus.resize(0x1A, 0); // fixed part present so the parser reaches the length check
    let attr_list = create_attribute_list_attr(&[
        create_attr_list_entry(0x80, 0, 40 | (1 << 48), 2, None),
        bogus,
    ]);
    source.write_at(
        40 * 1024,
        &build_record(
            40,
            &[create_fn_attribute("corrupt.bin", 5), base_data, attr_list],
        ),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(as_ntfs_volume(&source)),
        serde_json::json!({"cluster_size": 4096}),
    );

    // Must not panic.
    let results = MftParser::new().process(&artifact).unwrap();
    let file = find_entry(&results, "corrupt.bin");
    assert_eq!(
        file.metadata["data_runs"],
        serde_json::json!([[100 * cluster, 2 * cluster]])
    );
    assert_eq!(file.metadata["data_runs_complete"], false);
}

#[test]
fn test_attribute_list_merges_named_ads_runs() {
    // A named stream split across records: base record 40 holds the first
    // extent of "secret" (2 clusters at LCN 100), extension record 41 the
    // continuation (3 clusters at LCN 50). Fragments match on
    // type + name + attribute id via the list entries.
    let source = Arc::new(MockMftSource::new(1024 * 42));
    let cluster = 4096u64;

    let base_ads =
        create_non_resident_named_data_attr_ex("secret", &[(2, 100)], 3, 0, 1, 5 * cluster);
    let attr_list = create_attribute_list_attr(&[
        create_attr_list_entry(0x80, 0, 40 | (1 << 48), 3, Some("secret")),
        create_attr_list_entry(0x80, 2, 41 | (1 << 48), 7, Some("secret")),
    ]);
    source.write_at(
        40 * 1024,
        &build_record(
            40,
            &[create_fn_attribute("stream.bin", 5), base_ads, attr_list],
        ),
    );

    let ext_ads =
        create_non_resident_named_data_attr_ex("secret", &[(3, 50)], 7, 2, 4, 5 * cluster);
    source.write_at(
        41 * 1024,
        &with_base_ref(build_record(41, &[ext_ads]), 40 | (1 << 48)),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(as_ntfs_volume(&source)),
        serde_json::json!({"cluster_size": 4096}),
    );

    let results = MftParser::new().process(&artifact).unwrap();
    let ads = find_entry(&results, "stream.bin:secret");
    assert_eq!(
        ads.metadata["data_runs"],
        serde_json::json!([[100 * cluster, 2 * cluster], [50 * cluster, 3 * cluster]])
    );
    assert_eq!(ads.metadata["data_runs_complete"], true);
    assert_eq!(ads.metadata["is_ads"], true);
}

/// The parent entry has to say the streams exist.
///
/// The ADS sub-stream gets its own artifact, but an examiner looking at
/// `stream.bin` in the file tree sees the parent. `ads_count`/`ads_names` were
/// inserted into the metadata map AFTER `Artifact::new` had taken it, so they
/// stayed in the local map: a file carrying hidden streams was indistinguishable
/// on its own record from a file carrying none.
#[test]
fn the_parent_entry_names_the_alternate_data_streams_hanging_off_it() {
    let cluster = 4096u64;
    let ads = create_non_resident_named_data_attr_ex("secret", &[(2, 100)], 3, 0, 1, 2 * cluster);
    let record = build_record(72, &[create_fn_attribute("stream.bin", 5), ads]);
    let entry = parse_record_at_cluster_size(record, cluster);

    assert_eq!(
        entry.metadata["ads_count"],
        serde_json::json!(1),
        "the parent record must carry the count of its hidden streams"
    );
    assert_eq!(entry.metadata["ads_names"], serde_json::json!(["secret"]));
}

#[test]
fn test_parse_attribute_list_bounds() {
    use mft_structs::parse_attribute_list;

    // Two valid entries parse cleanly, with the 48/16-bit reference split.
    let content = [
        create_attr_list_entry(0x80, 0, 40 | (7 << 48), 2, None),
        create_attr_list_entry(0x30, 5, 41 | (1 << 48), 9, Some("ads")),
    ]
    .concat();
    let parsed = parse_attribute_list(&content);
    assert!(!parsed.truncated);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].base_record_number, 40);
    assert_eq!(parsed.entries[0].base_record_sequence, 7);
    assert_eq!(parsed.entries[1].name.as_deref(), Some("ads"));
    assert_eq!(parsed.entries[1].lowest_vcn, 5);

    // Huge entry_length: keep what parsed before, report the loss.
    let mut bad = create_attr_list_entry(0x80, 0, 40, 2, None);
    let mut bogus = vec![];
    bogus.write_u32::<LittleEndian>(0x80).unwrap();
    bogus.write_u16::<LittleEndian>(0xFFFF).unwrap();
    bogus.resize(0x1A, 0);
    bad.extend_from_slice(&bogus);
    let parsed = parse_attribute_list(&bad);
    assert!(parsed.truncated);
    assert_eq!(parsed.entries.len(), 1);

    // Torn tail (fewer bytes than the fixed part) is truncation, not a panic.
    let mut torn = create_attr_list_entry(0x80, 0, 40, 2, None);
    torn.extend_from_slice(&[0x80, 0x00, 0x00]);
    let parsed = parse_attribute_list(&torn);
    assert!(parsed.truncated);
    assert_eq!(parsed.entries.len(), 1);

    // Negative lowest_vcn is invalid.
    let neg = create_attr_list_entry(0x80, u64::MAX, 40, 2, None); // -1 as i64
    let parsed = parse_attribute_list(&neg);
    assert!(parsed.truncated);
    assert!(parsed.entries.is_empty());

    // Entry-count cap: more entries than the limit stops parsing safely.
    let mut flood = Vec::new();
    for _ in 0..2000 {
        flood.extend_from_slice(&create_attr_list_entry(0x80, 0, 40, 2, None));
    }
    let parsed = parse_attribute_list(&flood);
    assert!(parsed.truncated);
    assert_eq!(parsed.entries.len(), 1024);
}

/// Non-resident $DATA with independently chosen allocated/real/initialized
/// sizes: the three are equal on an ordinary written file, and differ exactly
/// where cluster slack and never-written tails live.
fn create_non_resident_data_attr_sizes(
    runs: &[(u64, i64)],
    allocated_size: u64,
    real_size: u64,
    initialized_size: u64,
) -> Vec<u8> {
    let run_list = create_data_run_list(runs);

    let mut attr = vec![];
    attr.write_u32::<LittleEndian>(0x80).unwrap();
    let len = 64 + run_list.len() as u32;
    let aligned_len = (len + 7) & !7;
    attr.write_u32::<LittleEndian>(aligned_len).unwrap();
    attr.write_u8(1).unwrap(); // Non-Resident
    attr.write_u8(0).unwrap(); // Name len
    attr.write_u16::<LittleEndian>(0).unwrap(); // Name offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Flags
    attr.write_u16::<LittleEndian>(0).unwrap(); // ID
    attr.write_u64::<LittleEndian>(0).unwrap(); // Start VCN
    attr.write_u64::<LittleEndian>(runs.len() as u64).unwrap(); // Last VCN
    attr.write_u16::<LittleEndian>(64).unwrap(); // Runs offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Compression unit
    attr.write_u32::<LittleEndian>(0).unwrap(); // Padding
    attr.write_u64::<LittleEndian>(allocated_size).unwrap();
    attr.write_u64::<LittleEndian>(real_size).unwrap();
    attr.write_u64::<LittleEndian>(initialized_size).unwrap();
    attr.extend_from_slice(&run_list);
    while attr.len() < aligned_len as usize {
        attr.push(0);
    }
    attr
}

/// Run a single MFT record through the parser and return the FileEntry it
/// produced for that record.
fn parse_record_at_cluster_size(record: Vec<u8>, cluster_size: u64) -> Artifact {
    let mft_source = Arc::new(MockMftSource::new(1024 * 64));
    mft_source.write_at(0, &record);
    let artifact = Artifact::new(
        Uuid::new_v4(),
        // A volume, not a bare $MFT: the runs address this same buffer, and
        // only a FileSystem input serves them (HUNT-161).
        ArtifactType::FileSystem,
        Some(mft_source),
        serde_json::json!({ "name": "mft.bin", "cluster_size": cluster_size }),
    );
    let results = MftParser::new()
        .process(&artifact)
        .expect("MFT parsing failed");
    results
        .into_iter()
        .find(|a| {
            a.artifact_type == ArtifactType::FileEntry
                && a.metadata.get("is_ads").is_none()
                && a.metadata.get("record_number").is_some()
        })
        .expect("no FileEntry produced")
}

#[test]
fn a_files_content_stops_at_its_logical_size_instead_of_running_into_cluster_slack() {
    // Two 4096-byte clusters allocated, but the file is 5000 bytes long: the
    // last 3192 bytes of the allocation belong to whatever used the cluster
    // before. Hashing them would make every digest wrong.
    let runs = vec![(2u64, 100i64)];
    let attr = create_non_resident_data_attr_sizes(&runs, 8192, 5000, 5000);
    let record = build_record(30, &[create_fn_attribute("slack.bin", 5), attr]);
    let entry = parse_record_at_cluster_size(record, 4096);

    assert_eq!(entry.metadata["size"], 5000);
    let persisted = entry.metadata["data_runs"].as_array().unwrap();
    let total: u64 = persisted
        .iter()
        .map(|r| r[1].as_u64().unwrap())
        .sum::<u64>();
    assert_eq!(total, 5000, "persisted runs must cover exactly the file");
    assert_eq!(
        entry.data.as_ref().unwrap().size(),
        5000,
        "the ingest content source is the file, not its clusters"
    );
}

#[test]
fn the_never_written_tail_of_an_extended_file_reads_as_zeros_not_as_the_previous_tenant() {
    // 8192 bytes allocated and 8192 bytes long, but only the first 100 bytes
    // were ever written. NTFS returns zeros past initialized_size; the clusters
    // behind it still hold a deleted file.
    let runs = vec![(2u64, 100i64)];
    let attr = create_non_resident_data_attr_sizes(&runs, 8192, 8192, 100);
    let record = build_record(31, &[create_fn_attribute("extended.bin", 5), attr]);
    let entry = parse_record_at_cluster_size(record, 4096);

    let persisted = entry.metadata["data_runs"].as_array().unwrap();
    assert_eq!(persisted.len(), 2);
    assert_eq!(persisted[0][0].as_u64(), Some(100 * 4096));
    assert_eq!(persisted[0][1].as_u64(), Some(100));
    assert!(
        persisted[1][0].is_null(),
        "the uninitialized tail must be a sparse hole, not a disk offset"
    );
    assert_eq!(persisted[1][1].as_u64(), Some(8192 - 100));
    assert_eq!(entry.data.as_ref().unwrap().size(), 8192);
}

#[test]
fn logical_extent_runs_drops_slack_and_zeroes_the_uninitialized_tail() {
    // Fully written file: only the trailing slack is dropped.
    let runs = vec![(Some(4096), 8192)];
    assert_eq!(
        logical_extent_runs(&runs, 5000, 5000),
        vec![(Some(4096), 5000)]
    );

    // Partially initialized: prefix kept, remainder sparse.
    assert_eq!(
        logical_extent_runs(&runs, 100, 5000),
        vec![(Some(4096), 100), (None, 4900)]
    );

    // Never written at all: the whole file reads as zeros.
    assert_eq!(logical_extent_runs(&runs, 0, 5000), vec![(None, 5000)]);

    // initialized_size > real_size is a corrupt header; the file still stops at
    // its own length.
    assert_eq!(
        logical_extent_runs(&runs, u64::MAX, 5000),
        vec![(Some(4096), 5000)]
    );

    // Run list shorter than the file: the undescribed range is zeros, never
    // borrowed from the next run.
    let short = vec![(Some(4096), 512)];
    assert_eq!(
        logical_extent_runs(&short, 5000, 5000),
        vec![(Some(4096), 512), (None, 4488)]
    );

    // A non-resident attribute claiming size 0 cannot be trusted to mean "empty",
    // so its allocated runs survive untouched.
    assert_eq!(logical_extent_runs(&runs, 0, 0), runs);

    // Multiple runs: the cut lands inside the second one.
    let two = vec![(Some(4096), 4096), (Some(65536), 4096)];
    assert_eq!(
        logical_extent_runs(&two, 6000, 6000),
        vec![(Some(4096), 4096), (Some(65536), 1904)]
    );
}

#[test]
fn a_missing_attribute_extent_leaves_a_hole_instead_of_shifting_later_extents_leftward() {
    let cluster = 4096u64;
    // Extents at VCN 0 and VCN 2; the VCN-1 extent was lost.
    let frags = vec![
        (0u64, vec![(Some(cluster), cluster)]),
        (2u64, vec![(Some(9 * cluster), cluster)]),
    ];
    let (runs, gapped) = merge_vcn_fragments(frags, cluster);
    assert!(gapped, "a VCN gap must be reported to the caller");
    assert_eq!(
        runs,
        vec![
            (Some(cluster), cluster),
            (None, cluster),
            (Some(9 * cluster), cluster)
        ],
        "the surviving extent must stay at its true logical offset"
    );

    // A first extent that does not start at VCN 0 is the same defect.
    let (runs, gapped) = merge_vcn_fragments(vec![(3u64, vec![(Some(cluster), cluster)])], cluster);
    assert!(gapped);
    assert_eq!(runs, vec![(None, 3 * cluster), (Some(cluster), cluster)]);

    // Contiguous extents merge with no hole and no flag.
    let (runs, gapped) = merge_vcn_fragments(
        vec![
            (1u64, vec![(Some(2 * cluster), cluster)]),
            (0u64, vec![(Some(cluster), cluster)]),
        ],
        cluster,
    );
    assert!(!gapped);
    assert_eq!(
        runs,
        vec![(Some(cluster), cluster), (Some(2 * cluster), cluster)]
    );

    // Overlapping extents disagree with each other: drop the overlap and say so
    // rather than pushing everything after it out of place.
    let (_, gapped) = merge_vcn_fragments(
        vec![
            (0u64, vec![(Some(cluster), 2 * cluster)]),
            (1u64, vec![(Some(5 * cluster), cluster)]),
        ],
        cluster,
    );
    assert!(gapped);
}

#[test]
fn an_efs_encrypted_file_is_marked_as_ciphertext_so_its_hash_is_not_read_as_plaintext() {
    // $LOGGED_UTILITY_STREAM named $EFS marks the file encrypted; the $DATA runs
    // still address ciphertext.
    let name_bytes: Vec<u8> = "$EFS"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes().to_vec())
        .collect();
    let mut efs = vec![];
    efs.write_u32::<LittleEndian>(0x100).unwrap();
    let content_off = 24u16 + name_bytes.len() as u16;
    let aligned_len = ((content_off as u32 + 8) + 7) & !7;
    efs.write_u32::<LittleEndian>(aligned_len).unwrap();
    efs.write_u8(0).unwrap(); // Resident
    efs.write_u8(4).unwrap(); // Name len (chars)
    efs.write_u16::<LittleEndian>(24).unwrap(); // Name offset
    efs.write_u16::<LittleEndian>(0).unwrap(); // Flags
    efs.write_u16::<LittleEndian>(0).unwrap(); // ID
    efs.write_u32::<LittleEndian>(8).unwrap(); // Content size
    efs.write_u16::<LittleEndian>(content_off).unwrap(); // Content offset
    efs.write_u16::<LittleEndian>(0).unwrap(); // Padding
    efs.extend_from_slice(&name_bytes);
    while efs.len() < aligned_len as usize {
        efs.push(0);
    }

    let attr = create_non_resident_data_attr_sizes(&[(2u64, 100i64)], 8192, 8192, 8192);
    let record = build_record(32, &[create_fn_attribute("secret.docx", 5), attr, efs]);
    let entry = parse_record_at_cluster_size(record, 4096);

    assert_eq!(entry.metadata["efs_encrypted"], true);
    assert_eq!(entry.metadata["content_ciphertext"], "ntfs_efs");
}

// --- Regression tests: torn records, attribute-bounded run lists, compressed
// --- ADS, directory flags and the $Bitmap allocation map.

/// Non-resident $DATA whose declared length ends EXACTLY after the run list,
/// with no 0x00 terminator. Used to prove the run-list decoder stops at the
/// attribute boundary instead of eating the next attribute's bytes.
fn create_data_attr_unterminated_runs(runs_bytes: &[u8], real_size: u64) -> Vec<u8> {
    let mut attr = vec![];
    attr.write_u32::<LittleEndian>(0x80).unwrap(); // Type $DATA
    attr.write_u32::<LittleEndian>(64 + runs_bytes.len() as u32)
        .unwrap(); // Length: header + runs, nothing more
    attr.write_u8(1).unwrap(); // Non-resident
    attr.write_u8(0).unwrap(); // Name len
    attr.write_u16::<LittleEndian>(0).unwrap(); // Name offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Flags
    attr.write_u16::<LittleEndian>(0).unwrap(); // ID
    attr.write_u64::<LittleEndian>(0).unwrap(); // Start VCN
    attr.write_u64::<LittleEndian>(0).unwrap(); // Last VCN
    attr.write_u16::<LittleEndian>(64).unwrap(); // Runs offset
    attr.write_u16::<LittleEndian>(0).unwrap(); // Compression unit
    attr.write_u32::<LittleEndian>(0).unwrap(); // Padding
    attr.write_u64::<LittleEndian>(real_size).unwrap(); // Allocated
    attr.write_u64::<LittleEndian>(real_size).unwrap(); // Real
    attr.write_u64::<LittleEndian>(real_size).unwrap(); // Initialized
    attr.extend_from_slice(runs_bytes);
    attr
}

/// A run list that runs off the end of its attribute without a terminator must
/// NOT keep decoding the following attribute's header bytes as extents. The
/// next attribute here starts with type 0x00001011, whose first three bytes
/// decode as a perfectly plausible 16-cluster run at the previous LCN
/// (B6-003).
#[test]
fn data_runs_stop_at_the_attribute_boundary() {
    // 0x11 = 1 length byte, 1 offset byte: 4 clusters at LCN 10.
    let data = create_data_attr_unterminated_runs(&[0x11, 0x04, 0x0A], 20480);
    let record = build_record(
        70,
        &[
            create_fn_attribute("bounded.bin", 5),
            data,
            create_resident_attr(0x0000_1011, &[]),
        ],
    );
    let entry = parse_record_at_cluster_size(record, 1024);

    // Only the real extent survives; the rest of the logical size becomes a
    // sparse hole, never a second run pointing back into LCN 10.
    assert_eq!(
        entry.metadata["data_runs"],
        serde_json::json!([[10240u64, 4096u64], [serde_json::Value::Null, 16384u64]]),
        "bytes past the attribute must not be decoded as data runs"
    );
}

/// A record whose Update Sequence Array fixup fails is torn: every sector's
/// last two bytes still hold the USA placeholder. Parsing on published
/// plausible names, MACB times and cluster runs for a corrupt record
/// (B6-002). It must be skipped and counted.
#[test]
fn torn_record_with_failed_fixup_is_skipped_and_counted() {
    let mut record = build_record(71, &[create_fn_attribute("torn.bin", 5)]);
    // Sector 1 no longer ends with the update sequence number (0x1234).
    record[510] = 0x00;
    record[511] = 0x00;

    let source = Arc::new(MockMftSource::new(1024 * 4));
    source.write_at(0, &record);
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        serde_json::json!({ "name": "mft.bin", "cluster_size": 1024 }),
    );
    let results = MftParser::new().process(&artifact).unwrap();

    assert!(
        !results
            .iter()
            .any(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("torn.bin")),
        "a record that failed its USA fixup must not be published as a file"
    );

    let summary = results
        .iter()
        .find(|a| a.metadata["type"] == "mft_parse_summary")
        .expect("skipped records must be reported, never silently dropped");
    assert_eq!(summary.metadata["fixup_failed_records"], 1);
    assert_eq!(summary.metadata["content_incomplete"], true);
    assert_eq!(summary.metadata["inventory_incomplete"], true);
}

/// Named non-resident $DATA carrying an LZNT1 compression unit.
fn create_compressed_named_data_attr(
    name: &str,
    runs: &[(u64, i64)],
    compression_unit: u16,
    real_size: u64,
) -> Vec<u8> {
    let mut attr = create_non_resident_named_data_attr_ex(name, runs, 3, 0, 3, real_size);
    // compression_unit sits at offset 34 of the non-resident attribute header.
    attr[34..36].copy_from_slice(&compression_unit.to_le_bytes());
    attr
}

/// A compressed alternate data stream must be published as compressed. Before
/// this, the ADS branch never looked at `compression_unit`, so the on-disk
/// LZNT1 cluster image was trimmed to the logical size and served, indexed and
/// hashed as the stream's plaintext (B6-004).
#[test]
fn compressed_ads_is_published_as_compressed_not_raw_clusters() {
    // Larger than NTFS_DECOMPRESS_CAP, so no reconstruction is attempted and
    // the stream must be reported as content we did not resolve.
    let oversize = 512 * 1024 * 1024u64;
    let ads = create_compressed_named_data_attr("zip", &[(4, 10)], 4, oversize);
    let record = build_record(72, &[create_fn_attribute("packed.bin", 5), ads]);

    let source = Arc::new(MockMftSource::new(1024 * 4));
    source.write_at(0, &record);
    let artifact = Artifact::new(
        Uuid::new_v4(),
        // A volume, not a bare $MFT: the runs address this same buffer, and
        // only a FileSystem input serves them (HUNT-161).
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({ "name": "mft.bin", "cluster_size": 1024 }),
    );
    let results = MftParser::new().process(&artifact).unwrap();

    let stream = results
        .iter()
        .find(|a| a.metadata.get("is_ads").and_then(|v| v.as_bool()) == Some(true))
        .expect("ADS artifact should be emitted");

    assert_eq!(stream.metadata["compression"], "ntfs_lznt1");
    assert_eq!(
        stream.metadata["compression_unit_bytes"],
        (1u64 << 4) * 1024
    );
    assert_eq!(stream.metadata["content_incomplete"], true);
    assert_eq!(stream.metadata["content_incomplete_reason"], "compressed");
    assert!(
        stream.data.is_none(),
        "compressed clusters must never be attached as the stream's own bytes"
    );
    // The runs describe the compressed image, so they are published as-is and
    // not trimmed to the (much larger) logical size.
    assert_eq!(
        stream.metadata["data_runs"],
        serde_json::json!([[10240u64, 4096u64]])
    );
}

/// The primary `$DATA` path makes the same four-way split the ADS path does
/// (CR-033 #6).
///
/// It had kept the old two-way shape after the ADS path was fixed: a corrupt
/// compression exponent on a stream that was also empty or over the cap was
/// stamped `ntfs_lznt1_oversize` on a record already carrying
/// `compression_unit_invalid`, and a zero-length compressed file was marked
/// `content_incomplete` with no content to be missing.
#[test]
fn a_compressed_primary_data_stream_names_the_reason_it_could_not_be_resolved() {
    fn primary_meta(compression_unit: u16, real_size: u64) -> serde_json::Value {
        let mut data = create_non_resident_data_attr_ex(&[(4, 10)], 2, 0, 3, real_size);
        // compression_unit sits at offset 34 of the non-resident attribute header.
        data[34..36].copy_from_slice(&compression_unit.to_le_bytes());
        let record = build_record(73, &[create_fn_attribute("packed.bin", 5), data]);
        let source = Arc::new(MockMftSource::new(1024 * 4));
        source.write_at(0, &record);
        let artifact = Artifact::new(
            Uuid::new_v4(),
            // A volume, not a bare $MFT: the runs address this same buffer, and
            // only a FileSystem input serves them (HUNT-161).
            ArtifactType::FileSystem,
            Some(source),
            serde_json::json!({ "name": "mft.bin", "cluster_size": 1024 }),
        );
        let results = MftParser::new().process(&artifact).unwrap();
        results
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("packed.bin"))
            .expect("the file should be emitted")
            .metadata
            .clone()
    }

    // 1. Genuinely too large to reconstruct at ingest.
    let oversize = primary_meta(4, 512 * 1024 * 1024);
    assert_eq!(oversize["compression_unsupported"], "ntfs_lznt1_oversize");
    assert_eq!(oversize["content_incomplete"], true);

    // 2. A corrupt exponent on an oversize stream: the record used to say
    //    both "the descriptor is invalid" and "the data is merely too large".
    let corrupt = primary_meta(64, 512 * 1024 * 1024);
    assert_eq!(
        corrupt["compression_unsupported"], "ntfs_lznt1_invalid_compression_unit",
        "a corrupt descriptor is not an oversize stream: {corrupt}"
    );
    assert_eq!(corrupt["compression_unit_invalid"], true);
    assert_eq!(corrupt["content_incomplete"], true);

    // 3. A corrupt exponent on a stream within the cap says the same thing,
    //    rather than "decompression failed" for a decompression never tried.
    let corrupt_small = primary_meta(64, 4096);
    assert_eq!(
        corrupt_small["compression_unsupported"],
        "ntfs_lznt1_invalid_compression_unit"
    );

    // 4. A zero-length compressed file has no content to be missing.
    let empty = primary_meta(4, 0);
    assert_eq!(empty["compression_unsupported"], "ntfs_lznt1_zero_length");
    assert!(
        empty.get("content_incomplete").is_none(),
        "a file with no content is not content-incomplete: {empty}"
    );
}

/// Each way a compressed ADS can fail to resolve gets its OWN reason code.
///
/// Everything undecompressible used to fall through one arm stamped
/// `ntfs_lznt1_oversize`, which is a claim about the stream's SIZE: it tells the
/// examiner the data is there and merely too large — and on this path that also
/// implies the resolver will decompress it on demand. For a corrupt compression
/// descriptor that is false twice over. The stream is not oversize, nothing will
/// ever recover it, and the record already carried `compression_unit_invalid`
/// two fields away, so it contradicted itself. `content_incomplete_reason` is
/// what an examiner reads to decide whether to pursue the data another way, and
/// a wrong reason there costs real work chasing something that is not there.
#[test]
fn a_compressed_ads_names_the_reason_it_could_not_be_resolved() {
    /// The ADS metadata for one record, built from a single compressed stream.
    fn ads_meta(compression_unit: u16, real_size: u64) -> serde_json::Value {
        let ads = create_compressed_named_data_attr("zip", &[(4, 10)], compression_unit, real_size);
        let record = build_record(72, &[create_fn_attribute("packed.bin", 5), ads]);
        let source = Arc::new(MockMftSource::new(1024 * 4));
        source.write_at(0, &record);
        let artifact = Artifact::new(
            Uuid::new_v4(),
            // A volume, not a bare $MFT: the runs address this same buffer, and
            // only a FileSystem input serves them (HUNT-161).
            ArtifactType::FileSystem,
            Some(source),
            serde_json::json!({ "name": "mft.bin", "cluster_size": 1024 }),
        );
        let results = MftParser::new().process(&artifact).unwrap();
        results
            .iter()
            .find(|a| a.metadata.get("is_ads").and_then(|v| v.as_bool()) == Some(true))
            .expect("ADS artifact should be emitted")
            .metadata
            .clone()
    }

    // 1. Genuinely too large to reconstruct at ingest. The one case the old
    //    label described, and it keeps it.
    let oversize = ads_meta(4, 512 * 1024 * 1024);
    assert_eq!(oversize["compression_unsupported"], "ntfs_lznt1_oversize");
    assert_eq!(oversize["content_incomplete"], true);

    // 2. A corrupt compression exponent. `compression_unit_bytes` refuses any
    //    exponent from 63 up, so there is no unit size to walk the runs with.
    let corrupt = ads_meta(64, 4096);
    assert_eq!(
        corrupt["compression_unsupported"], "ntfs_lznt1_invalid_compression_unit",
        "a corrupt descriptor is not an oversize stream: {corrupt}"
    );
    assert_eq!(
        corrupt["compression_unit_invalid"], true,
        "and the record must not contradict itself: {corrupt}"
    );
    assert_eq!(corrupt["compression_unit_exponent"], 64);
    assert_eq!(corrupt["content_incomplete"], true);

    // 3. A zero-length compressed stream. There is no content to be missing, so
    //    it must NOT be counted as content that could not be read — that would
    //    inflate every incompleteness figure the report states.
    let empty = ads_meta(4, 0);
    assert_eq!(empty["compression_unsupported"], "ntfs_lznt1_zero_length");
    assert!(
        empty.get("content_incomplete").is_none(),
        "a stream with no content is not content-incomplete: {empty}"
    );
}

/// Directory-ness has two signals; reading only $INDEX_ROOT published a
/// directory whose index attribute was lost as an ordinary file (B6-033).
#[test]
fn directory_flag_is_read_from_the_record_header_too() {
    let mut record = build_record(73, &[create_fn_attribute("Documents", 5)]);
    // Record header flags: bit 0 IN_USE, bit 1 DIRECTORY.
    record[22..24].copy_from_slice(&0x0003u16.to_le_bytes());
    let entry = parse_record_at_cluster_size(record, 1024);

    assert_eq!(entry.metadata["is_directory"], true);
    assert_eq!(entry.metadata["is_directory_source"], "mft_record_flag");
}

/// A `$Bitmap` shorter than the volume must never redefine the volume as
/// smaller. The clusters it does not cover render as free space, and free
/// space reads as "nothing was ever written here" (B5-004).
#[test]
fn short_bitmap_keeps_the_volume_size_and_is_flagged_incomplete() {
    // 512-byte sectors, 2 sectors/cluster, 2,000,000 sectors -> 1,000,000
    // clusters, which needs 125,000 bitmap bytes.
    let source = Arc::new(MockMftSource::new(1024 * 16));

    // $Bitmap declares 40960 bytes but only one 1024-byte cluster is addressed.
    let data_attr = create_non_resident_data_attr(&[(1, 10)]);
    write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 2, 2_000_000),
        20,
        &[build_record(
            6,
            &[create_fn_attribute("$Bitmap", 5), data_attr],
        )],
    );
    source.write_at(10240, &[0xFFu8; 8]);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    let map = results
        .iter()
        .find(|a| a.metadata["type"] == "allocation_map")
        .expect("allocation_map artifact should be emitted");

    assert_eq!(
        map.metadata["allocation_total_clusters"], 1_000_000u64,
        "the boot sector's cluster count is the volume's extent; a short \
         bitmap must not shrink it"
    );
    assert_eq!(map.metadata["allocation_map_incomplete"], true);
    assert_eq!(map.metadata["allocation_clusters_covered"], 8192u64);
    assert_eq!(map.metadata["content_incomplete"], true);
    assert_eq!(map.metadata["content_incomplete_reason"], "short_read");

    // And the same rule applied to the free REGIONS this now emits (§5.4):
    // not one of them may fall in the 991,808 clusters the held bitmap could
    // not speak for. Carving that tail would report unallocated space nobody
    // assessed, which is B5-004 with a carver attached.
    let regions: Vec<&Artifact> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .collect();
    let covered_bytes = 8192u64 * 1024;
    for region in &regions {
        let offset = region.metadata["offset_bytes"].as_u64().expect("offset");
        let size = region.metadata["size_bytes"].as_u64().expect("size");
        assert!(
            offset + size <= covered_bytes,
            "a region at {offset}+{size} reaches past the {covered_bytes} bytes the bitmap \
             covers, so it claims free space nothing established"
        );
    }
    // 991,808 clusters lie past the bitmap. The mock source is 16 KiB, so the free run the
    // bitmap does cover (clusters 64..8,192, 8,128 clusters) lies past the end of the data
    // source too, and the emitter counts it as unassessed instead of carving it.
    assert_eq!(
        map.metadata["free_space_unassessed_clusters"],
        991_808u64 + 8_128,
        "1,000,000 clusters less the 64 allocated ones the 16 KiB source can hold"
    );
    assert_eq!(map.metadata["free_space_complete"], false);
    assert!(map.metadata["free_space_incomplete_detail"]
        .as_str()
        .unwrap_or_default()
        .contains("NOT free space"));
}

/// The free clusters of a volume become regions the automatic carver is
/// pointed at (`ROADMAP` §5.4).
///
/// Before this, the only producer of `UnallocatedSpace` in the tree was the
/// partition parser's gaps *between* partitions, so the free space inside a
/// filesystem — where nearly everything an examiner carves for is — was never
/// carved automatically.
#[test]
fn the_free_clusters_of_a_volume_become_regions_a_carver_can_be_pointed_at() {
    // 512-byte sectors, 2 per cluster -> 1 KiB clusters; 64 sectors -> 32
    // clusters, so one bitmap byte covers eight of them and four bytes cover
    // the volume.
    let source = Arc::new(MockMftSource::new(1024 * 64));
    let data_attr = create_non_resident_data_attr(&[(1, 10)]);
    write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 2, 64),
        12,
        &[build_record(
            6,
            &[create_fn_attribute("$Bitmap", 4), data_attr],
        )],
    );
    // Clusters 0,1,2 allocated; 3..8 free; 8,9 allocated; 10..32 free.
    source.write_at(10240, &[0b0000_0111u8, 0b0000_0011u8, 0x00, 0x00]);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    let regions: Vec<&Artifact> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .collect();
    assert_eq!(
        regions
            .iter()
            .map(|r| (
                r.metadata["first_cluster"].as_u64().unwrap(),
                r.metadata["clusters"].as_u64().unwrap(),
                r.metadata["offset_bytes"].as_u64().unwrap(),
            ))
            .collect::<Vec<_>>(),
        vec![(3, 5, 3 * 1024), (10, 22, 10 * 1024)],
        "two runs, at the byte offsets their clusters occupy in the volume"
    );
    for region in &regions {
        assert_eq!(region.metadata["filesystem"], "NTFS");
        // The one field the carver reads, and the one the content resolver
        // requires beside it.
        assert!(region.metadata["offset_bytes"].is_u64());
        assert_eq!(
            region.data.as_ref().map(|d| d.size()),
            region.metadata["size_bytes"].as_u64(),
            "the window is the length the record declares"
        );
        // Which coordinate space those offsets are in, since the carver adds
        // this one to a candidate's position and calls the sum absolute.
        assert!(region.metadata["offset_basis"]
            .as_str()
            .unwrap_or_default()
            .contains("not the start of the evidence"));
    }
    let map = results
        .iter()
        .find(|a| a.metadata["type"] == "allocation_map")
        .expect("the allocation map");
    assert_eq!(map.metadata["free_regions_emitted"], 2);
    assert_eq!(map.metadata["free_bytes_emitted"], 27u64 * 1024);
    assert_eq!(map.metadata["free_space_complete"], true);
    assert!(
        map.metadata.get("free_space_incomplete").is_none(),
        "a complete pass carries no shortfall marker"
    );
}

/// An extent whose byte span is not a whole number of clusters still occupies
/// the cluster it partially fills. Truncating division under-counted the VCNs
/// covered, inventing a hole ahead of the next extent and pushing it off its
/// true logical offset (B5-027).
#[test]
fn merge_vcn_fragments_rounds_partial_cluster_spans_up() {
    let frags = vec![
        (0u64, vec![(Some(0u64), 1536u64)]),
        (2u64, vec![(Some(8192u64), 1024u64)]),
    ];
    let (runs, gapped) = merge_vcn_fragments(frags, 1024);
    assert_eq!(runs, vec![(Some(0), 1536), (Some(8192), 1024)]);
    assert!(
        !gapped,
        "a 1536-byte span covers VCNs 0 and 1, so VCN 2 follows with no gap"
    );
}

/// A compression-unit exponent past what NTFS emits is a corrupt descriptor,
/// not a size.
///
/// The old bound was "does not overflow a u64". An exponent of 30 does not, and
/// names a 4 TiB unit that flowed into the decompressor's allocation, which the
/// allocator refused — a process ABORT, not a panic, so nothing caught it and
/// one crafted record ended the ingest.
#[test]
fn a_compression_unit_exponent_past_the_format_is_a_corrupt_descriptor() {
    assert_eq!(compression_unit_bytes(4, 4096), Some(16 * 4096));
    assert_eq!(compression_unit_bytes(0, 4096), Some(4096));
    assert_eq!(compression_unit_bytes(6, 4096), Some(64 * 4096));
    for exp in [7u16, 10, 30, 40, 63] {
        assert_eq!(
            compression_unit_bytes(exp, 4096),
            None,
            "exponent {exp} must be refused before it becomes an allocation"
        );
    }
    assert_eq!(compression_unit_bytes(64, 4096), None);
}

/// Run lengths come from evidence, and a list whose lengths reach the top of
/// `u64` overflowed the coalescing arithmetic (HUNT-049).
#[test]
fn run_lists_whose_lengths_overflow_are_coalesced_without_panicking() {
    let runs = vec![
        (Some(u64::MAX - 8), 8u64),
        (Some(0u64), u64::MAX),
        (None, u64::MAX),
        (None, 16u64),
    ];
    let (json, _complete) = seance_core::data_source::byte_runs_to_metadata(&runs);
    let arr = json.as_array().expect("an array of runs");
    assert!(!arr.is_empty());
    // CR-047: the two sparse runs are NOT merged. A merged length that would
    // overflow stays as two runs (as `seance_core` does for every other
    // filesystem) rather than saturate to a length that was never recorded.
    // SYNTHETIC run list.
    assert_eq!(arr.last().unwrap()[1], 16);
    assert_eq!(arr[arr.len() - 2][1], u64::MAX);
}

/// A file reference is a record number *and* a sequence number, and NTFS
/// increments the sequence when it recycles a freed record. The reader
/// published only the record number, so nothing downstream could tell "this is
/// still that file" from "that record now holds a different one" — which is
/// what every structure pointing at a file by reference needs, the USN journal
/// first among them (§2.2 detection 6).
#[test]
fn a_file_entry_carries_both_halves_of_its_file_reference() {
    let mft_source = Arc::new(MockMftSource::new(1024 * 10));
    let mut record0 = vec![0u8; 1024];
    let mut cursor = std::io::Cursor::new(&mut record0);
    cursor.write_all(&create_mft_header(0, 56)).unwrap();
    cursor.set_position(56);
    cursor
        .write_all(&create_si_attribute(1234567890123456789))
        .unwrap();
    cursor
        .write_all(&create_fn_attribute("notes.txt", 5))
        .unwrap();
    cursor.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();
    record0[510] = 0x34;
    record0[511] = 0x12;
    record0[1022] = 0x34;
    record0[1023] = 0x12;
    mft_source.write_at(0, &record0);

    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(mft_source.clone()),
        serde_json::json!({ "name": "mft.bin", "cluster_size": 4096 }),
    );
    let out = MftParser::new().process(&artifact).expect("Parser failed");
    let entry = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .expect("a file entry");
    assert_eq!(entry.metadata["record_number"], 0);
    assert_eq!(
        entry.metadata["sequence_number"], 1,
        "the sequence number is what says whether this is still that file"
    );
}

// --- HUNT-161: a bare $MFT has no volume to read a run from -----------------

/// `reference/hackshaw/test_data/HD001_MFT.dat`: a real 37 MB `$MFT` with no
/// volume beneath it. `$Secure:$SDS` is non-resident at 29,237,248 + 272,848 —
/// inside this file's own byte range, so a run list applied against the file
/// "reads" 272,848 bytes of other MFT records and serves them as the security
/// descriptor stream. Gitignored, so absent in CI.
#[test]
fn a_bare_mft_serves_no_non_resident_stream_from_its_own_bytes() {
    use seance_core::data_source::FileDataSource;
    let path = std::path::Path::new("../reference/hackshaw/test_data/HD001_MFT.dat");
    if !path.exists() {
        eprintln!("skipping: {path:?} not present (gitignored corpus, absent in CI)");
        return;
    }
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(
            FileDataSource::new(path.to_path_buf()).expect("open"),
        )),
        serde_json::json!({ "name": "HD001_MFT.dat", "path": path.to_string_lossy() }),
    );
    let out = MftParser::new()
        .process(&artifact)
        .expect("the $MFT parses");

    let sds = out
        .iter()
        .find(|a| a.metadata["name"] == "$Secure:$SDS")
        .expect("$Secure:$SDS is in this $MFT");
    assert!(
        sds.data.is_none(),
        "the $SDS runs address a volume that is not in evidence; the $MFT's own \
         bytes at those offsets are not the stream"
    );
    assert_eq!(sds.metadata["content_incomplete"], true);
    assert_eq!(
        sds.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(sds.metadata["volume_not_in_evidence"], true);
    assert!(sds.metadata["content_incomplete_detail"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    // The run list is still published: where the stream lived is evidence.
    assert!(sds.metadata["data_runs"]
        .as_array()
        .is_some_and(|r| !r.is_empty()));

    // And the same for every other non-resident stream and index: no artifact
    // from a bare $MFT carries a data source built from a run list.
    for a in &out {
        let non_resident =
            a.metadata.get("data_runs").is_some() || a.metadata["type"] == "IndexAllocation";
        if non_resident {
            assert!(
                a.data.is_none(),
                "{} is served from the $MFT's own bytes",
                a.metadata["name"]
            );
        }
    }
    // A resident stream is the record's own bytes and is still served.
    assert!(out.iter().any(|a| a.metadata["is_ads"] == true
        && a.metadata.get("resident_data_b64").is_some()
        && a.data.is_some()));
}

/// HUNT-178: NTFS 3.x keeps a file's security descriptor in `$Secure:$SDS` and
/// puts only its key — `security_id`, at 0x34 of the 72-byte
/// `$STANDARD_INFORMATION` — in the record. Without it on the FileEntry, the
/// descriptors the `$SDS` reader publishes are keyed by an id nothing else in
/// the case carries.
#[test]
fn the_standard_information_security_id_is_published() {
    let mut si = create_si_attribute(1234567890123456789);
    // Resident content starts after the 24-byte header; owner_id at 0x30,
    // security_id at 0x34.
    si[24 + 0x30..24 + 0x34].copy_from_slice(&0u32.to_le_bytes());
    si[24 + 0x34..24 + 0x38].copy_from_slice(&0x0105u32.to_le_bytes());
    let entry = parse_single_record(40, si, create_fn_attribute("owned.txt", 5))
        .into_iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .expect("a file entry");
    assert_eq!(entry.metadata["security_id"], 0x0105);

    // A 48-byte NTFS 1.2 $STANDARD_INFORMATION has no security_id; none is
    // invented.
    let mut short_si = create_si_attribute(1234567890123456789);
    short_si.truncate(24 + 48);
    short_si[4..8].copy_from_slice(&(24u32 + 48).to_le_bytes());
    short_si[16..20].copy_from_slice(&48u32.to_le_bytes());
    let entry = parse_single_record(41, short_si, create_fn_attribute("old.txt", 5))
        .into_iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .expect("a file entry");
    assert!(entry.metadata.get("security_id").is_none());
}

// --- HUNT-230: an exported `$MFT` ingested under its own name -----------------

/// The recursion guard declined any artifact *named* `$MFT`, so an examiner's
/// exported `$MFT` — ingested as the `SystemArtifact` content detection makes
/// it, under that name — produced nothing and said nothing. The parser's own
/// `$MFT` entry is told apart by what it carries (its `record_number`), not by
/// its name. Graded on `reference/hackshaw/test_data/HD001_MFT.dat`, a real
/// 37 MB `$MFT` (gitignored, absent in CI).
#[test]
fn an_exported_mft_ingested_as_dollar_mft_is_parsed() {
    use seance_core::data_source::FileDataSource;
    let path = std::path::Path::new("../reference/hackshaw/test_data/HD001_MFT.dat");
    if !path.exists() {
        eprintln!("skipping: {path:?} not present (gitignored corpus, absent in CI)");
        return;
    }
    let exported = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(Arc::new(
            FileDataSource::new(path.to_path_buf()).expect("open"),
        )),
        serde_json::json!({ "name": "$MFT", "source_path": "/export/$MFT" }),
    );
    let out = MftParser::new()
        .process(&exported)
        .expect("the $MFT parses");
    assert!(
        out.iter()
            .any(|a| a.artifact_type == ArtifactType::FileEntry
                && a.metadata["name"] == "$Secure:$SDS"),
        "an exported $MFT named $MFT must be parsed, not declined ({} artifacts)",
        out.len()
    );
}

/// The guard's real job still holds: the `$MFT` entry the parser publishes
/// from a volume is not parsed again.
#[test]
fn the_parsers_own_mft_entry_is_not_parsed_again() {
    let source = Arc::new(MockMftSource::new(1024 * 4));
    source.write_at(
        0,
        &build_record(
            0,
            &[
                create_fn_attribute("$MFT", 5),
                create_non_resident_data_attr(&[(1, 0)]),
            ],
        ),
    );
    let volume = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({ "cluster_size": 4096 }),
    );
    let out = MftParser::new().process(&volume).unwrap();
    let own = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry && a.metadata["name"] == "$MFT")
        .expect("the parser publishes its $MFT entry");
    assert!(own.metadata.get("record_number").is_some());
    assert!(
        MftParser::new().process(own).unwrap().is_empty(),
        "the parser's own $MFT entry must not be re-parsed"
    );
}

// --- HUNT-251: a volume's records come from its own table, and only it ---

fn fs_artifact(volume: Arc<dyn DataSource>) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(volume),
        serde_json::json!({ "filesystem_type": "NTFS" }),
    )
}

fn file_entries(results: &[Artifact], record: u64) -> Vec<&Artifact> {
    results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter(|a| a.metadata.get("is_ads").and_then(|v| v.as_bool()) != Some(true))
        .filter(|a| a.metadata["record_number"] == record)
        .collect()
}

fn summary(results: &[Artifact]) -> Option<&Artifact> {
    results
        .iter()
        .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("mft_parse_summary"))
}

/// A `FILE` record outside the `$MFT` — an older copy in free space or a
/// shadow-copy diff area, or `$MFTMirr`'s copies of records 0-3 — is not a
/// live record. The whole-volume scan published each as an in-use file under
/// the record number in its header, and let it name a directory in the path
/// map. On dfir_ntfs's Server 2003 VSS volume that made deleted record 77 a
/// live file a second time (HUNT-251).
#[test]
fn a_stray_file_record_in_free_space_is_not_a_live_entry_and_names_no_path() {
    let source = MockMftSource::new(0);
    // The real record 14: deleted (not in use), sequence 2.
    let mut gone = build_record(14, &[create_fn_attribute("gone.txt", 5)]);
    gone[16..18].copy_from_slice(&2u16.to_le_bytes());
    gone[22..24].copy_from_slice(&0u16.to_le_bytes());
    // Record 15 names record 14 at sequence 1 as its parent: the directory
    // the reference meant is gone.
    let child = build_record(15, &[create_fn_attribute("child.txt", 14 | (1 << 48))]);
    let mft_offset = write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 8, 1 << 24),
        1000,
        &[gone, child],
    );

    // An older copy of record 14 — in use, sequence 1, a directory named
    // `straydir` — BEFORE the table in the volume, where a front-to-back scan
    // reads it first.
    let mut stray = build_record(14, &[create_fn_attribute("straydir", 5), index_root_attr()]);
    stray[22..24].copy_from_slice(&3u16.to_le_bytes());
    source.write_at(2_208_768, &stray);

    // `$MFTMirr` at LCN 500: copies of records 0-3.
    let mut table_head = vec![0u8; 4 * 1024];
    source.read_at(mft_offset, &mut table_head).unwrap();
    source.write_at(500 * 4096, &table_head);
    let mut boot = vec![0u8; 512];
    source.read_at(0, &mut boot).unwrap();
    boot[0x38..0x40].copy_from_slice(&500i64.to_le_bytes());
    source.write_at(0, &boot);

    let results = MftParser::new()
        .process(&fs_artifact(Arc::new(source)))
        .unwrap();

    let r14 = file_entries(&results, 14);
    assert_eq!(r14.len(), 1, "record 14 is one slot of one table");
    assert_eq!(r14[0].metadata["name"], "gone.txt");
    assert_eq!(r14[0].metadata["sequence_number"], 2);
    assert_eq!(r14[0].metadata["deleted"], true);
    assert_eq!(r14[0].metadata["mft_offset"], mft_offset + 14 * 1024);
    assert!(
        !results.iter().any(|a| a.metadata["name"] == "straydir"),
        "the stray copy is published as nothing"
    );
    assert_eq!(
        file_entries(&results, 0).len(),
        1,
        "$MFTMirr's copy is not a second $MFT"
    );

    let child = &file_entries(&results, 15)[0];
    assert_eq!(
        child.metadata["path"], "/$OrphanFiles/child.txt",
        "the stray's name must not enter path reconstruction"
    );
    assert!(
        summary(&results).is_none(),
        "a whole table located from record 0 is not remarked on"
    );
}

/// A torn `$MFT` record 0 leaves the table's runs unknown; `$MFTMirr`'s copy
/// of it is read instead, and the summary says which copy the runs came from.
#[test]
fn a_torn_record_zero_is_read_from_the_mirror_and_labelled() {
    let source = MockMftSource::new(0);
    let mft_offset = write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 8, 1 << 24),
        1000,
        &[build_record(20, &[create_fn_attribute("kept.txt", 5)])],
    );
    let mut head = vec![0u8; 4 * 1024];
    source.read_at(mft_offset, &mut head).unwrap();
    source.write_at(500 * 4096, &head);
    let mut boot = vec![0u8; 512];
    source.read_at(0, &mut boot).unwrap();
    boot[0x38..0x40].copy_from_slice(&500i64.to_le_bytes());
    source.write_at(0, &boot);
    // Tear the table's record 0: its first sector's USA check value no longer
    // matches.
    source.write_at(mft_offset + 510, &[0xEE, 0xEE]);

    let results = MftParser::new()
        .process(&fs_artifact(Arc::new(source)))
        .unwrap();
    assert_eq!(file_entries(&results, 20)[0].metadata["name"], "kept.txt");
    let s = summary(&results).expect("the fallback is stated");
    assert_eq!(s.metadata["mft_record0_source"], "mftmirr_record_0");
    assert_eq!(s.metadata["mft_located"], true);
}

/// With neither record 0 nor its mirror copy readable the table cannot be
/// found. Nothing is scanned for; the refusal is published.
#[test]
fn a_volume_whose_mft_cannot_be_located_publishes_the_refusal_not_a_scan() {
    let source = MockMftSource::new(0);
    let mft_offset = write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 8, 1 << 24),
        1000,
        &[build_record(20, &[create_fn_attribute("unseen.txt", 5)])],
    );
    source.write_at(mft_offset + 510, &[0xEE, 0xEE]);

    let results = MftParser::new()
        .process(&fs_artifact(Arc::new(source)))
        .unwrap();
    assert!(
        !results
            .iter()
            .any(|a| a.artifact_type == ArtifactType::FileEntry),
        "no record is published from a table that was not found"
    );
    let s = summary(&results).expect("the refusal is stated");
    assert_eq!(s.metadata["mft_located"], false);
    assert_eq!(s.metadata["inventory_incomplete"], true);
    assert!(s.metadata["mft_not_located_detail"]
        .as_str()
        .unwrap()
        .contains("$MFTMirr"));
}

/// A `$MFT` whose own run list is short — record 0's `$ATTRIBUTE_LIST` names
/// an extension record that cannot be read — is read as far as its runs
/// reach, and the summary says the table is incomplete.
#[test]
fn a_table_whose_run_list_is_short_is_stated_incomplete() {
    let source = MockMftSource::new(0);
    // 16 slots of 1 KiB at LCN 1000 in 4 KiB clusters: 4 clusters. Record 0
    // says the table continues in extension record 40, which does not exist.
    let mut runs = encode_run(4, 1000);
    runs.push(0);
    let data = create_non_resident_data_attr_raw(runs, 2, 0, 3, 32 * 1024);
    let attr_list = create_attribute_list_attr(&[
        create_attr_list_entry(0x80, 0, 1 << 48, 2, None),
        create_attr_list_entry(0x80, 4, 40 | (1 << 48), 5, None),
    ]);
    let record0 = build_record(0, &[create_fn_attribute("$MFT", 5), data, attr_list]);
    write_ntfs_volume(
        &source,
        create_ntfs_boot_sector(512, 8, 1 << 24),
        1000,
        &[
            record0,
            build_record(9, &[create_fn_attribute("early.txt", 5)]),
        ],
    );

    let results = MftParser::new()
        .process(&fs_artifact(Arc::new(source)))
        .unwrap();
    assert_eq!(file_entries(&results, 9)[0].metadata["name"], "early.txt");
    let s = summary(&results).expect("the short table is stated");
    assert_eq!(s.metadata["mft_runs_complete"], false);
    assert_eq!(s.metadata["inventory_incomplete"], true);
    assert_eq!(
        s.metadata["mft_record_slots_unreached"], 16,
        "32 KiB of table, 16 KiB located"
    );
}

/// HUNT-256 S2 on real evidence: the base-reference check added to the
/// extension-record trust test must not reject a genuine NTFS 3.1 extension
/// record. Every extension record in the NIST CFReDS Hacking Case `$MFT`
/// (Windows XP; 132 `$ATTRIBUTE_LIST` references) names its base record and
/// is accepted. This is the gitignored reference corpus: the test skips where
/// it is absent. It is a regression check on 3.1, not a grading on 3.0.
#[test]
fn every_real_xp_extension_record_passes_the_base_reference_check() {
    let path = std::path::Path::new("../reference/dfir_ntfs/test_data/nist-hacking-case.mft");
    if !path.exists() {
        eprintln!("skipping: nist-hacking-case.mft not present (gitignored corpus)");
        return;
    }
    let data = std::fs::read(path).unwrap();
    let source = MockMftSource::new(0);
    source.write_at(0, &data);
    let mut extensions = 0;
    for (slot, chunk) in data.as_chunks::<1024>().0.iter().enumerate() {
        if &chunk[0..4] != b"FILE" {
            continue;
        }
        let base = u64::from_le_bytes(chunk[0x20..0x28].try_into().unwrap()) & 0xFFFF_FFFF_FFFF;
        if base == 0 {
            continue;
        }
        extensions += 1;
        assert!(
            read_extension_record(&source, 1024, slot as u64, base).is_some(),
            "extension record {slot} (base {base}) was rejected"
        );
        assert!(
            read_extension_record(&source, 1024, slot as u64, base + 1).is_none(),
            "extension record {slot} accepted for a file that is not its base"
        );
    }
    assert!(extensions > 0, "the corpus holds extension records");
}

/// HUNT-256 S3: a bare `$MFT` of NTFS 3.0 records. Their headers carry no
/// record number (0x2C is a fixup word), so each record is numbered by its
/// slot and says so; the fixup bytes are never published as a number, and
/// parent references resolve through the slot numbers.
#[test]
fn bare_ntfs30_mft_numbers_records_by_slot() {
    let source = Arc::new(MockMftSource::new(1024 * 8));
    // Slot 0 is `$MFT`, as in a real table (and a bare table is recognised by
    // the FILE signature at its start).
    source.write_at(
        0,
        &build_record_v30(&[create_fn_attribute("$MFT", 5)], 0, 0x0300),
    );
    source.write_at(
        5 * 1024,
        &build_record_v30(&[create_fn_attribute(".", 5), index_root_attr()], 0, 0x1147),
    );
    source.write_at(
        6 * 1024,
        &build_record_v30(
            &[create_fn_attribute("docs", 5), index_root_attr()],
            0,
            0x2B00,
        ),
    );
    source.write_at(
        7 * 1024,
        &build_record_v30(&[create_fn_attribute("file.txt", 6)], 0, 0x0C00),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );
    let results = MftParser::new().process(&artifact).unwrap();

    let root = find_entry(&results, ".");
    assert_eq!(root.metadata["record_number"], 5);
    assert_eq!(root.metadata["record_number_source"], "slot");
    assert!(
        root.metadata.get("header_record_number").is_none(),
        "a 3.0 header has no number to set beside the slot"
    );
    assert!(
        !results
            .iter()
            .any(|a| a.metadata.get("record_number") == Some(&serde_json::json!(0x1147))),
        "fixup bytes must never be published as a record number"
    );
    let file = find_entry(&results, "file.txt");
    assert_eq!(file.metadata["record_number"], 7);
    assert_eq!(file.metadata["record_number_source"], "slot");
}

#[test]
fn bare_ntfs30_parent_path_resolves_via_slot() {
    let source = Arc::new(MockMftSource::new(1024 * 8));
    // Slot 0 is `$MFT`, as in a real table (and a bare table is recognised by
    // the FILE signature at its start).
    source.write_at(
        0,
        &build_record_v30(&[create_fn_attribute("$MFT", 5)], 0, 0x0300),
    );
    source.write_at(
        5 * 1024,
        &build_record_v30(&[create_fn_attribute(".", 5), index_root_attr()], 0, 0x1147),
    );
    source.write_at(
        6 * 1024,
        &build_record_v30(
            &[create_fn_attribute("docs", 5), index_root_attr()],
            0,
            0x2B00,
        ),
    );
    source.write_at(
        7 * 1024,
        &build_record_v30(&[create_fn_attribute("file.txt", 6)], 0, 0x0C00),
    );
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    assert_eq!(find_entry(&results, "docs").metadata["path"], "/docs");
    assert_eq!(
        find_entry(&results, "file.txt").metadata["path"],
        "/docs/file.txt"
    );
}

/// A bare 3.1 `$MFT` is numbered by its headers, as before: no source key.
#[test]
fn bare_ntfs31_mft_keeps_header_numbers() {
    let source = Arc::new(MockMftSource::new(1024));
    source.write_at(0, &build_record(11, &[create_fn_attribute("f.txt", 5)]));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        serde_json::json!({"cluster_size": 4096}),
    );
    let results = MftParser::new().process(&artifact).unwrap();
    let f = find_entry(&results, "f.txt");
    assert_eq!(f.metadata["record_number"], 11);
    assert!(f.metadata.get("record_number_source").is_none());
}

// --- HUNT-124: a per-file slack region for every live, fully described,
// --- non-resident file whose tail holds anything.

/// Run one record through the parser as a FileSystem input, with `plant`
/// written into the volume, and return everything it produced plus the input.
fn parse_volume_with(record: Vec<u8>, plant: &[(u64, &[u8])]) -> (Artifact, Vec<Artifact>) {
    let src = Arc::new(MockMftSource::new(1024 * 1024));
    src.write_at(0, &record);
    for (at, bytes) in plant {
        src.write_at(*at, bytes);
    }
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(src),
        serde_json::json!({ "name": "vol", "cluster_size": 4096 }),
    );
    let out = MftParser::new().process(&fs).expect("MFT parsing failed");
    (fs, out)
}

fn slack_regions(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .collect()
}

/// A 1000-byte file in one 4096-byte cluster at LCN 100 (byte 409600).
fn thousand_byte_file_attr() -> Vec<u8> {
    create_non_resident_data_attr_sizes(&[(1u64, 100i64)], 4096, 1000, 1000)
}

#[test]
fn slack_region_emitted_for_nonresident_file_with_nonzero_slack() {
    let record = build_record(
        40,
        &[
            create_fn_attribute("slack.bin", 5),
            thousand_byte_file_attr(),
        ],
    );
    let (fs, out) = parse_volume_with(record, &[(409_600 + 1024, b"MZ")]);
    let regions = slack_regions(&out);
    assert_eq!(regions.len(), 1, "one slack region for the one file");
    let r = regions[0];
    assert_eq!(r.parent_id, Some(fs.id), "parented to the FileSystem");
    assert_eq!(r.metadata["offset_bytes"], 409_600 + 1000);
    assert_eq!(r.metadata["size_bytes"], 3096);
    assert_eq!(r.metadata["source"], "file_slack");
    assert_eq!(r.metadata["parent_file"], "slack.bin");
    assert_eq!(r.metadata["filesystem"], "NTFS");
    let file = out
        .iter()
        .find(|a| {
            a.artifact_type == ArtifactType::FileEntry
                && a.metadata["record_number"] == 40
                && a.metadata.get("is_ads").is_none()
        })
        .unwrap();
    assert_eq!(r.metadata["owner_artifact_id"], file.id.to_string());
    // The file's own content still stops at its logical size.
    assert_eq!(file.data.as_ref().unwrap().size(), 1000);
    let mut two = [0u8; 2];
    r.data.as_ref().unwrap().read_at(24, &mut two).unwrap();
    assert_eq!(&two, b"MZ");
    let summary = out
        .iter()
        .find(|a| a.metadata["subtype"] == "slack_space_summary")
        .expect("the volume's slack pass is summarised");
    assert_eq!(summary.metadata["regions_emitted"], 1);
    assert_eq!(summary.parent_id, Some(fs.id));
}

#[test]
fn no_slack_region_when_tail_is_zero() {
    let record = build_record(
        41,
        &[
            create_fn_attribute("clean.bin", 5),
            thousand_byte_file_attr(),
        ],
    );
    let (_, out) = parse_volume_with(record, &[]);
    assert!(slack_regions(&out).is_empty());
    let summary = out
        .iter()
        .find(|a| a.metadata["subtype"] == "slack_space_summary")
        .expect("examined-and-empty is still recorded");
    assert_eq!(summary.metadata["zero_tails"], 1);
}

#[test]
fn no_slack_region_for_resident_file() {
    let record = build_record(
        42,
        &[
            create_fn_attribute("tiny.txt", 5),
            create_resident_attr(0x80, b"hello"),
        ],
    );
    let (_, out) = parse_volume_with(record, &[(409_600 + 1024, b"MZ")]);
    assert!(slack_regions(&out).is_empty());
}

#[test]
fn no_slack_region_for_deleted_file() {
    let mut record = build_record(
        43,
        &[
            create_fn_attribute("gone.bin", 5),
            thousand_byte_file_attr(),
        ],
    );
    record[22] = 0; // header flags: not IN_USE
    let (_, out) = parse_volume_with(record, &[(409_600 + 1024, b"MZ")]);
    assert!(
        slack_regions(&out).is_empty(),
        "a deleted file's clusters are not proven to be its own"
    );
}

#[test]
fn no_slack_region_for_compressed_or_incomplete_runs() {
    let mut compressed = thousand_byte_file_attr();
    compressed[12] = 0x01; // attribute flags: compressed
    compressed[34] = 4; // compression unit exponent
    let record = build_record(44, &[create_fn_attribute("packed.bin", 5), compressed]);
    let (_, out) = parse_volume_with(record, &[(409_600 + 1024, b"MZ")]);
    assert!(
        slack_regions(&out).is_empty(),
        "compressed: runs are not the file"
    );
    assert_eq!(
        slack_summary(&out)["files_not_located"],
        1,
        "a live compressed file has a tail that was not looked at: counted, not dropped"
    );

    // A run list that runs off the end of its attribute: truncated.
    let torn = create_data_attr_unterminated_runs(&[0x21, 0x01, 0x64], 1000);
    let record = build_record(45, &[create_fn_attribute("torn.bin", 5), torn]);
    let (_, out) = parse_volume_with(record, &[(409_600 + 1024, b"MZ")]);
    assert!(
        slack_regions(&out).is_empty(),
        "incomplete runs are not offered"
    );
    assert_eq!(
        slack_summary(&out)["files_not_located"],
        1,
        "a live file whose run list is torn has a tail nobody could locate: counted"
    );
    assert_eq!(slack_summary(&out)["content_incomplete"], true);
}

fn slack_summary(out: &[Artifact]) -> serde_json::Value {
    out.iter()
        .find(|a| a.metadata["subtype"] == "slack_space_summary")
        .expect("the slack pass is summarised")
        .metadata
        .clone()
}

/// A resident file has no clusters, so no slack: it is not counted as a tail
/// that could not be located.
#[test]
fn resident_file_is_not_counted_as_not_located() {
    let record = build_record(
        46,
        &[
            create_fn_attribute("tiny.txt", 5),
            create_resident_attr(0x80, b"hello"),
        ],
    );
    let (_, out) = parse_volume_with(record, &[]);
    assert_eq!(slack_summary(&out)["files_not_located"], 0);
}

/// A minimal PE32 image goblin parses: one `.text` section, 1024 bytes.
fn tiny_pe32() -> Vec<u8> {
    let mut pe = vec![0u8; 0x400];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    pe[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // sections
    pe[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes()); // opt hdr
    pe[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // exec, 32-bit
    let opt = coff + 20;
    let put32 = |pe: &mut Vec<u8>, at: usize, v: u32| {
        pe[at..at + 4].copy_from_slice(&v.to_le_bytes());
    };
    pe[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    put32(&mut pe, opt + 16, 0x1000); // entry point
    put32(&mut pe, opt + 20, 0x1000); // base of code
    put32(&mut pe, opt + 24, 0x1000); // base of data
    put32(&mut pe, opt + 28, 0x0040_0000); // image base
    put32(&mut pe, opt + 32, 0x1000); // section alignment
    put32(&mut pe, opt + 36, 0x200); // file alignment
    pe[opt + 40..opt + 42].copy_from_slice(&4u16.to_le_bytes()); // OS major
    pe[opt + 48..opt + 50].copy_from_slice(&4u16.to_le_bytes()); // subsystem major
    put32(&mut pe, opt + 56, 0x2000); // size of image
    put32(&mut pe, opt + 60, 0x200); // size of headers
    pe[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // GUI
    put32(&mut pe, opt + 72, 0x10_0000);
    put32(&mut pe, opt + 76, 0x1000);
    put32(&mut pe, opt + 80, 0x10_0000);
    put32(&mut pe, opt + 84, 0x1000);
    put32(&mut pe, opt + 92, 16); // data directories
    let sec = opt + 0xE0;
    pe[sec..sec + 5].copy_from_slice(b".text");
    put32(&mut pe, sec + 8, 0x100); // virtual size
    put32(&mut pe, sec + 12, 0x1000); // virtual address
    put32(&mut pe, sec + 16, 0x200); // raw size
    put32(&mut pe, sec + 20, 0x200); // raw pointer
    put32(&mut pe, sec + 36, 0x6000_0020);
    pe[0x200] = 0xC3; // ret
    pe
}

/// HUNT-124, end to end, from the record shape the enumerator produces: a live
/// NTFS file whose last cluster's slack holds a PE image. The $MFT parser
/// emits the slack region, the automatic carver carves it, the PE plugin
/// analyses the carve and `plugin.findings.pe` raises exactly one
/// `carved_executable_in_slack` lead naming the host file. Nothing below hands
/// a `carving_source` to anything; every provenance key is produced by the
/// stage before it.
///
/// Synthetic: this pins the mechanism (the detection is reachable), not the
/// detection's performance on real evidence — no held image carries a PE in
/// file slack.
#[test]
fn carved_executable_in_slack_fires_on_enumerator_produced_shape() {
    use seance_plugin_carver::UnallocatedCarver;
    use seance_plugin_findings::PeFindings;
    use seance_plugin_pe::PeSignatureParser;

    // A 1000-byte file in one 4096-byte cluster at LCN 100 (byte 409600).
    // Slack runs 410600..413696; its first sector boundary is 410624.
    let record = build_record(
        50,
        &[
            create_fn_attribute("report.docx", 5),
            thousand_byte_file_attr(),
        ],
    );
    let (fs, out) = parse_volume_with(record, &[(409_600 + 1024, &tiny_pe32())]);
    let regions = slack_regions(&out);
    assert_eq!(regions.len(), 1);
    assert!(fs.id != regions[0].id);

    let carved = UnallocatedCarver::new().process(regions[0]).unwrap();
    let exe = carved
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .expect("the PE in slack is carved");
    assert_eq!(exe.metadata["carving_offset_absolute"], 409_600 + 1024);

    let pe_records = PeSignatureParser.process(exe).unwrap();
    let findings: Vec<Artifact> = pe_records
        .iter()
        .flat_map(|r| PeFindings::new().process(r).unwrap())
        .collect();
    let slack: Vec<_> = findings
        .iter()
        .filter(|f| f.metadata["finding_kind"] == "carved_executable_in_slack")
        .collect();
    assert_eq!(slack.len(), 1, "{findings:?}");
    let observation = slack[0].metadata["observation"].as_str().unwrap();
    assert!(observation.contains("report.docx"), "{observation}");
}

/// CR-047. SYNTHETIC: a source whose every read fails. An unreadable header
/// is "could not look", never "not this format": `process` must return the
/// error, not an empty success a report would read as "no such artefact".
#[test]
fn an_unreadable_header_is_could_not_look_not_not_this_format() {
    use seance_core::test_support::UnreadableSource;
    let ds: std::sync::Arc<dyn seance_core::data_source::DataSource> =
        std::sync::Arc::new(UnreadableSource::new(4096));
    let art = seance_core::artifact::Artifact::new(
        uuid::Uuid::new_v4(),
        seance_core::artifact::ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": "$MFT" }),
    );
    let out = MftParser::new().process(&art);
    assert!(
        matches!(out, Err(seance_core::module::ModuleError::IoError(_))),
        "an unreadable header must be an error, got {out:?}"
    );
}
