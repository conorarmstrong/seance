use super::*;
use byteorder::WriteBytesExt;
use seance_core::data_source::DataSource;
use std::io::{self, Cursor, Write};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[allow(dead_code)] // Helper function
fn init_logging() {
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;
    let _ = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG) // Set to DEBUG level
        .try_init();
}

// --- Mock Data Source ---
#[derive(Debug)]
struct MockI30Source {
    data: Arc<Mutex<Vec<u8>>>,
}

impl MockI30Source {
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

impl DataSource for MockI30Source {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
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

// --- Helper Functions to Construct INDX Structures ---

// Helper to create a FILE_NAME attribute structure
fn create_file_name_attribute(
    parent_ref: u64,
    created: u64,
    modified: u64,
    name: &str,
    flags: u32,
    namespace: u8,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes().to_vec())
        .collect();

    let mut buf = vec![];
    buf.write_u64::<LittleEndian>(parent_ref).unwrap();
    buf.write_u64::<LittleEndian>(created).unwrap();
    buf.write_u64::<LittleEndian>(modified).unwrap();
    buf.write_u64::<LittleEndian>(modified).unwrap(); // mft_changed
    buf.write_u64::<LittleEndian>(created).unwrap(); // accessed
    buf.write_u64::<LittleEndian>(0).unwrap(); // allocated_size
    buf.write_u64::<LittleEndian>(0).unwrap(); // real_size
    buf.write_u32::<LittleEndian>(flags).unwrap(); // file_attributes
    buf.write_u32::<LittleEndian>(0).unwrap(); // reparse_point_tag (padding)
    buf.write_u8(name.len() as u8).unwrap(); // name_length
    buf.write_u8(namespace).unwrap(); // namespace
    buf.extend_from_slice(&name_bytes);

    // Pad to a multiple of 8 bytes for clean structure within the INDX entry if needed
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    buf
}

// Helper to create an INDX buffer header part (first 0x30 bytes)
fn create_indx_header_part(
    index_entry_offset: u32, // Offset to first real index entry from 0x18
    total_size: u32,         // Total size of index entries + $ATTR_END
) -> Vec<u8> {
    let mut buf = vec![0u8; 0x30]; // Fixed size for the initial header
    let mut cursor = Cursor::new(&mut buf);

    cursor.write_all(b"INDX").unwrap(); // 0x00: Magic
    cursor.write_u16::<LittleEndian>(0x30).unwrap(); // 0x04: update_seq_offset (points to USN after this header part)
    cursor.write_u16::<LittleEndian>(0).unwrap(); // 0x06: update_seq_size (placeholder)
    cursor.write_u64::<LittleEndian>(0).unwrap(); // 0x08: LSN
    cursor.write_u64::<LittleEndian>(0).unwrap(); // 0x10: VCN
    cursor
        .write_u32::<LittleEndian>(index_entry_offset)
        .unwrap(); // 0x18: Offset to first index entry (relative to 0x18 itself)
    cursor.write_u32::<LittleEndian>(total_size).unwrap(); // 0x1C: Total size of index entries + $ATTR_END (actual total size)
    cursor.write_u32::<LittleEndian>(total_size).unwrap(); // 0x20: Allocated size (same as total_size for simplicity in mock)
    cursor.write_u32::<LittleEndian>(0).unwrap(); // 0x24: Reserved
    buf
}

// Helper to create an INDX Entry structure
fn create_indx_entry(file_ref: u64, file_name_attr: &[u8], flags: u16) -> Vec<u8> {
    let mut buf = vec![];
    buf.write_u64::<LittleEndian>(file_ref).unwrap(); // File Reference
    let entry_len = 16 + file_name_attr.len() + 8; // Size of index entry header (16) + attr + padding (8) minimum
    let attr_len = file_name_attr.len();

    buf.write_u16::<LittleEndian>(entry_len as u16).unwrap(); // Length of entry
    buf.write_u16::<LittleEndian>(attr_len as u16).unwrap(); // Length of attribute
    buf.write_u16::<LittleEndian>(flags).unwrap(); // Flags
    buf.write_u16::<LittleEndian>(0).unwrap(); // Padding

    buf.extend_from_slice(file_name_attr);

    // Pad to 8-byte alignment, as INDX entries are typically 8-byte aligned
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    buf
}

// --- Tests ---

#[test]
fn test_parse_index_entry_valid() {
    init_logging();

    let file_name_attr_data = create_file_name_attribute(
        5,
        133484640000000000, // 2024-01-01 00:00:00 UTC
        133484640000000000,
        "test.txt",
        0x20, // ARCHIVE attribute
        0x1,  // Win32 namespace
    );

    let indx_entry_flags = 0x0; // No special flags

    let entry = create_indx_entry(10, &file_name_attr_data, indx_entry_flags);

    let parsed_entry = parse_index_entry(
        &entry,
        file_name_attr_data.len(),
        indx_entry_flags,
        0,
        0,
        false,
    )
    .expect("Failed to parse valid index entry");

    assert_eq!(parsed_entry.file_name, "test.txt");
    assert_eq!(parsed_entry.parent_reference, "5-0");
    assert_eq!(parsed_entry.file_reference, "10-0");
    assert!(!parsed_entry.is_directory);
    assert_eq!(parsed_entry.namespace_string(), "win32");
    assert_eq!(parsed_entry.file_attributes, 0x20);
}

#[test]
fn test_parse_index_entry_directory() {
    init_logging();

    let file_name_attr_data = create_file_name_attribute(
        5,
        133484640000000000,
        133484640000000000,
        "test_dir",
        0x10, // DIRECTORY attribute
        0x1,  // Win32 namespace
    );

    let indx_entry_flags = 0x1; // Has subnode

    let entry = create_indx_entry(12, &file_name_attr_data, indx_entry_flags);

    let parsed_entry = parse_index_entry(
        &entry,
        file_name_attr_data.len(),
        indx_entry_flags,
        0,
        0,
        false,
    )
    .expect("Failed to parse directory index entry");

    assert_eq!(parsed_entry.file_name, "test_dir");
    assert!(parsed_entry.is_directory);
    assert!(parsed_entry.flag_strings().contains(&"has_subnode"));
}

#[test]
fn test_parse_index_buffer_single_entry() {
    init_logging();

    let indx_buffer_size = 4096;
    let mut full_buffer = vec![0u8; indx_buffer_size];

    let file_name_attr = create_file_name_attribute(
        5,
        133484640000000000,
        133484640000000000,
        "single.doc",
        0x20,
        0x1,
    );
    let indx_entry_data = create_indx_entry(15, &file_name_attr, 0x02); // Last entry flag

    debug!("indx_entry_data len: {}", indx_entry_data.len());
    debug!(
        "indx_entry_data content (first 20 bytes): {:02X?}",
        &indx_entry_data[..20]
    );

    let entry_offset_in_buffer_relative_to_0x18 = 0x28; // header[0x18]: EntriesOffset
                                                        // header[0x1C] IndexLength is measured from the node header (0x18) and
                                                        // INCLUDES the header, so it is EntriesOffset + entries + $ATTR_END.
    let entries_total_size =
        entry_offset_in_buffer_relative_to_0x18 + (indx_entry_data.len() + 8) as u32;

    let header_part =
        create_indx_header_part(entry_offset_in_buffer_relative_to_0x18, entries_total_size);
    full_buffer[0..header_part.len()].copy_from_slice(&header_part);

    // Fixup Array placement and values (DISABLED FOR NOW)
    let _fixup_offset_in_buffer = 0x30; // Points to where USN starts (after 0x30 bytes of header)
    let _num_sectors = indx_buffer_size / 512;
    let fixup_size = 0; // Temporarily set to 0 to disable fixup logic
    let _fixup_value: u16 = 0xABCD; // The USN

    // Write the actual fixup_size into the header_part in full_buffer
    LittleEndian::write_u16(&mut full_buffer[6..8], fixup_size); // Set fixup_size to 0

    // Place the INDX entry data in the buffer
    let entries_start_absolute_offset = 0x18 + entry_offset_in_buffer_relative_to_0x18 as usize;
    full_buffer
        [entries_start_absolute_offset..entries_start_absolute_offset + indx_entry_data.len()]
        .copy_from_slice(&indx_entry_data);

    debug!(
        "full_buffer entries_start_absolute_offset: {}",
        entries_start_absolute_offset
    );
    debug!(
        "full_buffer content around entries_start_absolute_offset (first 20 bytes): {:02X?}",
        &full_buffer[entries_start_absolute_offset..entries_start_absolute_offset + 20]
    );

    // Add $ATTR_END marker after the last entry
    let attr_end_offset = entries_start_absolute_offset + indx_entry_data.len();
    full_buffer[attr_end_offset..attr_end_offset + 8].copy_from_slice(&[0xFF; 8]); // $ATTR_END is 8 bytes of 0xFF

    let source = MockI30Source::new(indx_buffer_size);
    source.write_at(0, &full_buffer);

    let entries = parse_i30_buffers(&source)
        .expect("Failed to parse INDX buffers")
        .entries;

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name, "single.doc");
    assert!(entries[0].flag_strings().contains(&"last_entry"));
}

/// Regression (I1): IndexLength (0x1C) is measured from the node header (0x18)
/// and includes it. For a nearly-full block the old `entries_start + IndexLength`
/// over-counted by EntriesOffset and pushed entries_end past the buffer, so the
/// bounds check dropped EVERY entry. This block's index length spans the whole
/// 4096-byte record; the old code returned 0 entries (or an error) here.
#[test]
fn test_full_index_block_entries_not_dropped() {
    init_logging();
    let indx_buffer_size = 4096usize;
    let mut full_buffer = vec![0u8; indx_buffer_size];
    let file_name_attr = create_file_name_attribute(
        5,
        133484640000000000,
        133484640000000000,
        "full.doc",
        0x20,
        0x1,
    );
    let indx_entry = create_indx_entry(11, &file_name_attr, 0x02); // last entry
    let entry_offset = 0x28u32;
    // IndexLength spans the whole node: from the header at 0x18 to end of record.
    let total_size = (indx_buffer_size as u32) - 0x18;
    let header = create_indx_header_part(entry_offset, total_size);
    full_buffer[..header.len()].copy_from_slice(&header);
    LittleEndian::write_u16(&mut full_buffer[6..8], 0); // no fixup
    let entry_start = 0x18 + entry_offset as usize;
    full_buffer[entry_start..entry_start + indx_entry.len()].copy_from_slice(&indx_entry);
    let attr_end = entry_start + indx_entry.len();
    full_buffer[attr_end..attr_end + 8].copy_from_slice(&[0xFF; 8]);
    let source = MockI30Source::new(indx_buffer_size);
    source.write_at(0, &full_buffer);
    let entries = parse_i30_buffers(&source)
        .expect("full block must parse")
        .entries;
    assert_eq!(
        entries.len(),
        1,
        "entries in a full block must not be dropped"
    );
    assert_eq!(entries[0].file_name, "full.doc");
}

/// Regression (I2): a crafted INDX entry with entry_len < 16 and attr_len >= 0x42
/// must not panic. The old `attr_len <= entry_len - 16` underflowed the usize
/// subtraction (debug/fuzz panic) before the range check could reject it.
#[test]
fn test_short_entry_len_does_not_underflow() {
    init_logging();
    let indx_buffer_size = 4096usize;
    let mut full_buffer = vec![0u8; indx_buffer_size];
    let entry_offset = 0x28u32;
    let entries_len = 32u32;
    let header = create_indx_header_part(entry_offset, entry_offset + entries_len);
    full_buffer[..header.len()].copy_from_slice(&header);
    LittleEndian::write_u16(&mut full_buffer[6..8], 0); // no fixup
    let entry_start = 0x18 + entry_offset as usize;
    full_buffer[entry_start + 8] = 1; // entry_len = 1 (< 16)
    full_buffer[entry_start + 10] = 0x42; // attr_len = 0x42
    let source = MockI30Source::new(indx_buffer_size);
    source.write_at(0, &full_buffer);
    // Must return without panicking.
    let _ = parse_i30_buffers(&source);
}

#[test]
fn test_parse_slack_space() {
    init_logging();

    let mut slack_data_buffer = vec![0u8; 512];

    // Create a deleted file name attribute in slack
    let deleted_file_name_attr = create_file_name_attribute(
        8,
        133484640000000000,
        133484640000000000,
        "DELETED.TXT",
        0x20, // ARCHIVE
        0x1,
    );

    // Place it at the beginning of the slack buffer
    slack_data_buffer[0..deleted_file_name_attr.len()].copy_from_slice(&deleted_file_name_attr);

    let entries = parse_slack_space(&slack_data_buffer, 0, 0);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name, "DELETED.TXT");
    assert!(entries[0].from_slack);
    assert_eq!(entries[0].parent_reference, "8-0");
}

#[test]
fn test_i30_parser_process_method() {
    init_logging();

    let source = Arc::new(MockI30Source::new(4096 * 2));
    let indx_buffer_size = 4096;
    let mut full_buffer = vec![0u8; indx_buffer_size];

    // Valid INDX entry
    let file_name_attr = create_file_name_attribute(
        5,
        133484640000000000,
        133484640000000000,
        "processed.txt",
        0x20,
        0x1,
    );
    let indx_entry = create_indx_entry(10, &file_name_attr, 0x02); // Last entry flag

    let entry_offset_in_buffer = 0x28;
    let header_data = create_indx_header_part(
        0x28,
        // IndexLength (0x1C) is measured from the node header (0x18) and includes
        // the header, so it is EntriesOffset + entries + $ATTR_END.
        0x28 + (indx_entry.len() + 8) as u32,
    );
    full_buffer[0..header_data.len()].copy_from_slice(&header_data);

    let _fixup_value: u16 = 0xABCD;
    let fixup_size = 0; // Temporarily set to 0
    LittleEndian::write_u16(&mut full_buffer[6..8], fixup_size);

    // Removed fixup array writing
    // LittleEndian::write_u16(&mut full_buffer[header_data.len()..header_data.len() + 2], fixup_value);
    // for i in 1..(indx_buffer_size / 512) {
    //     full_buffer[i * 512 - 2] = (fixup_value & 0xFF) as u8;
    //     full_buffer[i * 512 - 1] = (fixup_value >> 8) as u8;
    //     LittleEndian::write_u16(&mut full_buffer[header_data.len() + (i * 2)..header_data.len() + (i * 2) + 2], i as u16);
    // }

    let entry_start_offset = 0x18 + entry_offset_in_buffer;
    full_buffer[entry_start_offset..entry_start_offset + indx_entry.len()]
        .copy_from_slice(&indx_entry);

    // Add $ATTR_END marker after the last entry
    let attr_end_offset = entry_start_offset + indx_entry.len();
    full_buffer[attr_end_offset..attr_end_offset + 8].copy_from_slice(&[0xFF; 8]); // $ATTR_END is 8 bytes of 0xFF

    source.write_at(0, &full_buffer);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact, // MftParser emits this for IndexAllocation streams
        Some(source.clone()),
        serde_json::json!({
            "name": "$I30",
            "type": "IndexAllocation",
            "parent_file": "some_directory"
        }),
    );

    let parser = I30Parser;
    let results = parser.process(&artifact).expect("Parser failed");

    // The synthetic block declares no update-sequence array, so it is also
    // reported as unverified; the index entry itself must still come through.
    let entries: Vec<_> = results
        .iter()
        .filter(|a| a.metadata.get("file_name").is_some())
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].artifact_type, ArtifactType::ParsedRecord);
    // HUNT-077: with no `type` these records grouped as "Unknown" in the
    // Parsed Records index — 225,745 of them on Case 001, the largest type in
    // the case and the one type with no name.
    assert_eq!(entries[0].metadata["type"], "NtfsIndexEntry");
    assert_eq!(entries[0].metadata["file_name"], "processed.txt");
    assert_eq!(entries[0].metadata["from_slack"], false);
}

#[test]
fn test_i30_parser_empty_source() {
    init_logging();

    let source = Arc::new(MockI30Source::new(0));

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(source.clone()),
        serde_json::json!({
            "name": "$I30",
            "type": "IndexAllocation",
        }),
    );

    let parser = I30Parser;
    let results = parser
        .process(&artifact)
        .expect("Parser should handle empty source");
    assert_eq!(results.len(), 0);
}

/// Build a 4096-byte INDX buffer whose USA protects all 8 sectors with USN
/// `usn`. Each sector-end holds the USN placeholder; the USA replacement slots
/// hold `replacement + i` so a successful fixup is observable.
fn indx_with_usa(usn: u16, replacement: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let usa_offset = 0x30usize;
    let usa_size = 9u16; // 1 USN + 8 sector entries (8 * 512 = 4096)
    LittleEndian::write_u16(&mut buf[4..6], usa_offset as u16);
    LittleEndian::write_u16(&mut buf[6..8], usa_size);
    LittleEndian::write_u16(&mut buf[usa_offset..usa_offset + 2], usn);
    for i in 1..usa_size as usize {
        // USA replacement slot i.
        let slot = usa_offset + i * 2;
        LittleEndian::write_u16(&mut buf[slot..slot + 2], replacement.wrapping_add(i as u16));
        // Sector-end placeholder = USN.
        let sector_end = i * 512 - 2;
        LittleEndian::write_u16(&mut buf[sector_end..sector_end + 2], usn);
    }
    buf
}

/// A well-formed USA must be applied: every sector-end placeholder is replaced
/// by its USA slot value, and the call succeeds.
#[test]
fn test_apply_fixup_replaces_sector_ends() {
    let mut buf = indx_with_usa(0xABCD, 0x1000);
    apply_fixup(&mut buf).expect("valid fixup must succeed");
    for i in 1..9usize {
        let sector_end = i * 512 - 2;
        let got = LittleEndian::read_u16(&buf[sector_end..sector_end + 2]);
        assert_eq!(
            got,
            0x1000u16.wrapping_add(i as u16),
            "sector {} end not restored from USA",
            i
        );
    }
}

/// BUG-060: a per-sector USN mismatch (torn/overwritten block) must surface as
/// an error, not silently return Ok with the placeholder left in place.
#[test]
fn test_apply_fixup_mismatch_surfaces_error() {
    let mut buf = indx_with_usa(0xABCD, 0x1000);
    // Corrupt sector 3's trailing bytes so they no longer match the USN.
    let sector_end = 3 * 512 - 2;
    LittleEndian::write_u16(&mut buf[sector_end..sector_end + 2], 0xDEAD);
    let err = apply_fixup(&mut buf).expect_err("torn block must error");
    match err {
        ModuleError::ParsingError(msg) => assert!(
            msg.contains("mismatch"),
            "expected a fixup mismatch error, got: {msg}"
        ),
        other => panic!("expected ParsingError, got {other:?}"),
    }
    // Sectors verified before the mismatch (1, 2) were still corrected in place.
    assert_eq!(
        LittleEndian::read_u16(&buf[510..512]),
        0x1001,
        "sector 1 should have been fixed before the mismatch"
    );
    // The mismatched sector keeps its (corrupt) bytes; it is not overwritten.
    assert_eq!(
        LittleEndian::read_u16(&buf[sector_end..sector_end + 2]),
        0xDEAD
    );
}

#[test]
fn test_corrupt_huge_filetime_does_not_panic() {
    // A corrupt FILETIME near u64::MAX must not overflow the conversion
    // (naive `intervals * 100` would panic in debug builds).
    let entry = IndexEntry {
        file_reference: "1-1".to_string(),
        parent_reference: "5-1".to_string(),
        file_name: "corrupt.txt".to_string(),
        created: u64::MAX,
        modified: u64::MAX - 1,
        mft_changed: 0,
        accessed: 133484640000000000, // 2023-12-31T02:40:00Z
        allocated_size: 0,
        real_size: 0,
        file_attributes: 0,
        namespace: 1,
        flags: 0,
        is_directory: false,
        from_slack: false,
        buffer_index: 0,
        entry_offset: 0,
    };

    // Must not panic; value may be far-future or None but never bogus-small.
    let _ = entry.created_time();
    let _ = entry.modified_time();
    // Zero FILETIME stays absent
    assert!(entry.mft_changed_time().is_none());
    // Valid value still converts
    assert_eq!(
        entry.accessed_time().as_deref(),
        Some("2023-12-31T02:40:00+00:00")
    );
}

/// Build a 4096-byte INDX buffer carrying one entry, with a real
/// update-sequence array. When `tear` is set, one protected sector's trailing
/// placeholder is wrong, which is what a half-written index block looks like.
fn indx_buffer_with_usa(name: &str, tear: bool) -> Vec<u8> {
    const SIZE: usize = 4096;
    const USN: u16 = 0x1234;
    let mut buf = vec![0u8; SIZE];

    let file_name_attr =
        create_file_name_attribute(5, 133484640000000000, 133484640000000000, name, 0x20, 0x1);
    let entry = create_indx_entry(15, &file_name_attr, 0x02); // last entry
    let entry_offset = 0x28u32;
    let header = create_indx_header_part(entry_offset, entry_offset + entry.len() as u32 + 8);
    buf[..header.len()].copy_from_slice(&header);

    // USA: one USN plus one replacement per 512-byte sector, parked at 0x30.
    let usa_offset = 0x30usize;
    let sectors = SIZE / 512;
    LittleEndian::write_u16(&mut buf[4..6], usa_offset as u16);
    LittleEndian::write_u16(&mut buf[6..8], (sectors + 1) as u16);
    LittleEndian::write_u16(&mut buf[usa_offset..usa_offset + 2], USN);
    for i in 1..=sectors {
        let slot = usa_offset + i * 2;
        LittleEndian::write_u16(&mut buf[slot..slot + 2], 0);
        let sector_end = i * 512 - 2;
        LittleEndian::write_u16(&mut buf[sector_end..sector_end + 2], USN);
    }
    if tear {
        // Sector 2's tail no longer carries the USN: the block was not written
        // as one unit.
        LittleEndian::write_u16(&mut buf[2 * 512 - 2..2 * 512], 0xDEAD);
    }

    let entry_start = 0x18 + entry_offset as usize;
    buf[entry_start..entry_start + entry.len()].copy_from_slice(&entry);
    let attr_end = entry_start + entry.len();
    buf[attr_end..attr_end + 8].copy_from_slice(&[0xFF; 8]);
    buf
}

#[test]
fn an_indx_block_that_passes_its_update_sequence_check_is_reported_as_verified() {
    init_logging();
    let block = indx_buffer_with_usa("clean.doc", false);
    let source = MockI30Source::new(block.len());
    source.write_at(0, &block);

    let scan = parse_i30_buffers(&source).expect("clean block must parse");
    assert!(
        scan.torn_buffers.is_empty(),
        "a block whose fixup verifies is not torn"
    );
    assert!(scan.stopped.is_none());
}

#[test]
fn entries_recovered_from_a_torn_indx_block_are_never_presented_as_verified() {
    init_logging();
    let block = indx_buffer_with_usa("torn.doc", true);
    let source = MockI30Source::new(block.len());
    source.write_at(0, &block);

    let scan = parse_i30_buffers(&source).expect("a torn block still parses best-effort");
    assert_eq!(
        scan.torn_buffers,
        vec![0],
        "the torn buffer must be identified, not merely logged"
    );

    // And it must reach the examiner on the emitted records.
    let ds = MockI30Source::new(block.len());
    ds.write_at(0, &block);
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(Arc::new(ds)),
        json!({ "type": "IndexAllocation", "name": "$I30" }),
    );
    let out = I30Parser.process(&artifact).expect("process failed");
    assert!(
        out.iter().any(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("I30ScanStatus")
                && a.metadata["content_incomplete_reason"] == "indx_fixup_failed"
        }),
        "a torn index must emit a scan-status record"
    );
    for a in &out {
        if a.metadata.get("source").and_then(|v| v.as_str()) == Some("$I30")
            && a.metadata.get("file_name").is_some()
        {
            assert_eq!(a.metadata["fixup_verified"], false);
            assert_eq!(a.metadata["content_incomplete"], true);
        }
    }
}

/// Build an INDX record of `size` bytes carrying one entry and a real
/// update-sequence array sized for that record. NTFS index records are
/// whatever `$INDEX_ROOT` declared — commonly the cluster size — so 8 KiB and
/// 16 KiB records are ordinary, not exotic.
fn indx_record_of_size(size: usize, name: &str) -> Vec<u8> {
    const USN: u16 = 0x1234;
    let mut buf = vec![0u8; size];

    let file_name_attr =
        create_file_name_attribute(5, 133484640000000000, 133484640000000000, name, 0x20, 0x1);
    let entry = create_indx_entry(15, &file_name_attr, 0x02); // last entry
    let entry_offset = 0x28u32;
    let header = create_indx_header_part(entry_offset, entry_offset + entry.len() as u32 + 8);
    buf[..header.len()].copy_from_slice(&header);

    let usa_offset = 0x30usize;
    let sectors = size / 512;
    LittleEndian::write_u16(&mut buf[4..6], usa_offset as u16);
    LittleEndian::write_u16(&mut buf[6..8], (sectors + 1) as u16);
    LittleEndian::write_u16(&mut buf[usa_offset..usa_offset + 2], USN);
    for i in 1..=sectors {
        let slot = usa_offset + i * 2;
        LittleEndian::write_u16(&mut buf[slot..slot + 2], 0);
        let sector_end = i * 512 - 2;
        LittleEndian::write_u16(&mut buf[sector_end..sector_end + 2], USN);
    }

    let entry_start = 0x18 + entry_offset as usize;
    buf[entry_start..entry_start + entry.len()].copy_from_slice(&entry);
    let attr_end = entry_start + entry.len();
    buf[attr_end..attr_end + 8].copy_from_slice(&[0xFF; 8]);
    buf
}

/// The record size is read from the record, never assumed. Before this the
/// scanner hardcoded 4096, so on an 8 KiB-index volume it read half of record
/// 0, then resumed at the 4 KiB mark inside it — the second record's name and
/// timestamps were never decoded.
#[test]
fn index_record_size_is_taken_from_the_record_not_assumed_to_be_4k() {
    init_logging();
    for size in [512usize, 1024, 4096, 8192, 16384] {
        let block = indx_record_of_size(size, "sized.doc");
        assert_eq!(
            indx_record_size(&block[..0x24]),
            Some(size),
            "record size for a {}-byte INDX record",
            size
        );
    }
}

#[test]
fn every_record_of_an_8k_index_is_walked() {
    init_logging();
    let a = indx_record_of_size(8192, "first.doc");
    let b = indx_record_of_size(8192, "second.doc");
    let source = MockI30Source::new(a.len() + b.len());
    source.write_at(0, &a);
    source.write_at(a.len() as u64, &b);

    let scan = parse_i30_buffers(&source).expect("8 KiB index must parse");
    assert!(scan.stopped.is_none(), "the whole stream must be covered");
    assert!(scan.torn_buffers.is_empty());
    let names: Vec<&str> = scan.entries.iter().map(|e| e.file_name.as_str()).collect();
    assert_eq!(
        names,
        vec!["first.doc", "second.doc"],
        "both 8 KiB records must be decoded at their own alignment"
    );
}

/// A record whose size cannot be determined must STOP the scan and say why.
/// Guessing 4 KiB would decode every following buffer at the wrong offset and
/// publish the resulting garbage as directory entries.
#[test]
fn an_indeterminate_record_size_stops_the_scan_and_is_reported() {
    init_logging();
    let mut block = indx_record_of_size(4096, "unreadable.doc");
    // USA count and allocated size both implausible: nothing states the size.
    LittleEndian::write_u16(&mut block[6..8], 0);
    LittleEndian::write_u32(&mut block[0x20..0x24], 0xFFFF_FFFF);
    let source = MockI30Source::new(block.len());
    source.write_at(0, &block);

    let scan = parse_i30_buffers(&source).expect("scan returns what it could read");
    assert_eq!(scan.stopped, Some("indx_record_size_unresolved"));
    assert!(scan.entries.is_empty());

    // And the stop reaches the examiner as a record, not just a log line.
    let ds = MockI30Source::new(block.len());
    ds.write_at(0, &block);
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(Arc::new(ds)),
        json!({ "type": "IndexAllocation", "name": "$I30" }),
    );
    let out = I30Parser.process(&artifact).expect("process failed");
    assert!(
        out.iter().any(|a| {
            a.metadata.get("record_type").and_then(|v| v.as_str()) == Some("i30_scan_status")
                && a.metadata["content_incomplete_reason"] == "indx_record_size_unresolved"
        }),
        "an unresolved record size must be published, not swallowed"
    );
}

/// The MFT parser names FileEntry artifacts with `name`, not `file_name`, so
/// the FileEntry branch of the gate matched nothing the pipeline emits
/// (B6-035). Only the SystemArtifact branch was live.
#[test]
fn a_file_entry_named_i30_is_recognised_by_its_name_key() {
    init_logging();

    let indx_buffer_size = 4096;
    let mut full_buffer = vec![0u8; indx_buffer_size];
    let file_name_attr = create_file_name_attribute(
        5,
        133484640000000000,
        133484640000000000,
        "recovered.txt",
        0x20,
        0x1,
    );
    let indx_entry = create_indx_entry(10, &file_name_attr, 0x02);
    let header_data = create_indx_header_part(0x28, 0x28 + (indx_entry.len() + 8) as u32);
    full_buffer[0..header_data.len()].copy_from_slice(&header_data);
    LittleEndian::write_u16(&mut full_buffer[6..8], 0); // no update-sequence array
    let entry_start_offset = 0x18 + 0x28;
    full_buffer[entry_start_offset..entry_start_offset + indx_entry.len()]
        .copy_from_slice(&indx_entry);
    let attr_end_offset = entry_start_offset + indx_entry.len();
    full_buffer[attr_end_offset..attr_end_offset + 8].copy_from_slice(&[0xFF; 8]);

    let source = Arc::new(MockI30Source::new(indx_buffer_size));
    source.write_at(0, &full_buffer);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        serde_json::json!({ "name": "$I30", "path": "/Users/Bob:$I30" }),
    );
    let results = I30Parser.process(&artifact).expect("parse failed");
    assert!(
        results
            .iter()
            .any(|a| a.metadata.get("file_name").and_then(|v| v.as_str()) == Some("recovered.txt")),
        "a FileEntry keyed by `name` must be recognised as an $I30 stream"
    );
}

// --- Graded on a real volume --------------------------------------------------

/// `reference/dfir_ntfs/test_data/ntfs_index.raw.gz`: a 32 MiB NTFS volume at
/// sector 128, from the `dfir_ntfs` project. Its `test_dir` held
/// `BBBBBBBBBBBBB-del.txt`, which was deleted; the name survives only in the
/// slack of `test_dir`'s index buffer (dfir_ntfs's
/// `test_file_system_index_allocation` carves it from there). Gitignored, so
/// absent in CI: the test says so and returns.
fn load_ntfs_index_volume() -> Option<Vec<u8>> {
    use std::io::Read;
    let path = std::path::Path::new("../reference/dfir_ntfs/test_data/ntfs_index.raw.gz");
    if !path.exists() {
        eprintln!("skipping: {path:?} not present (gitignored corpus, absent in CI)");
        return None;
    }
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).expect("open ntfs_index.raw.gz"))
        .read_to_end(&mut data)
        .expect("decompress ntfs_index.raw.gz");
    Some(data)
}

/// Every `$I30` record the pipeline produces for this volume: the MFT parser
/// walks the volume and emits one `IndexAllocation` stream per directory, and
/// each is handed to this module exactly as the orchestrator hands it.
fn i30_records_from_real_volume(image: Vec<u8>) -> Vec<Artifact> {
    use seance_core::data_source::ByteSliceDataSource;
    const VOLUME_OFFSET: usize = 128 * 512;
    let volume = image[VOLUME_OFFSET..].to_vec();
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(ByteSliceDataSource::new(volume))),
        json!({ "filesystem_type": "NTFS" }),
    );
    let mft_out = seance_plugin_mft::MftParser::new()
        .process(&fs)
        .expect("the MFT parser reads the real volume");
    let streams: Vec<&Artifact> = mft_out
        .iter()
        .filter(|a| {
            a.artifact_type == ArtifactType::SystemArtifact
                && a.metadata.get("type").and_then(|v| v.as_str()) == Some("IndexAllocation")
        })
        .collect();
    assert!(
        !streams.is_empty(),
        "the MFT parser must emit the volume's $I30 streams"
    );
    streams
        .into_iter()
        .flat_map(|s| I30Parser.process(s).expect("the $I30 stream parses"))
        .collect()
}

/// HUNT-153: the slack pass was bounded at `IndexLength`, so it received an
/// empty slice after the last entry and recovered nothing on any real volume.
/// The deleted file's name is in the slack of a real index buffer; it must come
/// back, marked as recovered from slack, with its real file reference.
#[test]
fn a_deleted_name_in_real_index_slack_is_recovered_through_the_pipeline() {
    let Some(image) = load_ntfs_index_volume() else {
        return;
    };
    let records = i30_records_from_real_volume(image);
    let slack: Vec<&Artifact> = records
        .iter()
        .filter(|a| a.metadata.get("from_slack") == Some(&json!(true)))
        .collect();
    let deleted = slack
        .iter()
        .find(|a| a.metadata["file_name"] == "BBBBBBBBBBBBB-del.txt")
        .unwrap_or_else(|| {
            panic!(
                "the deleted name in test_dir's index slack must be recovered; \
                 slack records: {:?}",
                slack
                    .iter()
                    .map(|a| a.metadata["file_name"].clone())
                    .collect::<Vec<_>>()
            )
        });
    // Its parent is test_dir, record 39 sequence 1 (dfir_ntfs asserts the
    // live entries' parent as 281474976710695 = 39 | 1 << 48).
    assert_eq!(deleted.metadata["parent_reference"], "39-1");
    // On this volume the 16 bytes in front of the stale $FILE_NAME are the
    // directory's new end-of-index marker (reference 0, length 16, flags
    // `last_entry`), written over the deleted entry's header when the entries
    // were shifted down. The deleted file's reference is gone, so it is
    // published as unknown — never as the placeholder "0-0", which reads as
    // MFT record 0.
    assert_eq!(deleted.metadata["file_reference"], "");

    // The whole of test_dir's slack, against dfir_ntfs's own expectation for
    // the same buffer (`file_names_slack_dir`): the deleted name plus two stale
    // copies of the surviving `AAAAAAAAAAA.txt` left when entries shifted.
    let mut dir_slack: Vec<&str> = slack
        .iter()
        .filter(|a| a.metadata["parent_reference"] == "39-1")
        .map(|a| a.metadata["file_name"].as_str().unwrap())
        .collect();
    dir_slack.sort_unstable();
    assert_eq!(
        dir_slack,
        vec![
            "AAAAAAAAAAA.txt",
            "AAAAAAAAAAA.txt",
            "BBBBBBBBBBBBB-del.txt"
        ]
    );

    // The root's slack holds `test_dir` (dfir_ntfs asserts it too). Its stale
    // entry header survived, so its reference is read — and it is test_dir's
    // real MFT reference, the same 39-1 its children name as their parent.
    let test_dir = slack
        .iter()
        .find(|a| a.metadata["file_name"] == "test_dir")
        .expect("the root's slack holds test_dir");
    assert_eq!(test_dir.metadata["file_reference"], "39-1");
    assert_eq!(test_dir.metadata["parent_reference"], "5-5");

    // A byte-offset scan with only a shape test also reads fragments as names.
    // Every slack record must be a name dfir_ntfs's carve recognises on this
    // volume: a `test_dir` child or root entry, never a stray fragment.
    for a in &slack {
        let parent = a.metadata["parent_reference"].as_str().unwrap();
        assert!(
            parent == "39-1" || parent == "5-5",
            "slack record {} names parent {parent}, which is no directory on this volume",
            a.metadata["file_name"]
        );
    }
}

// --- HUNT-153: the scan's own honesty ------------------------------------------

/// NTFS protects every multi-sector structure at a fixed 512-byte stride,
/// whatever the disk's sector size: `4k-large.mft` in the dfir_ntfs corpus
/// holds 4,096-byte records with an update-sequence count of 9 (8 x 512), and
/// dfir_ntfs's `UPDATE_SEQUENCE_STRIDE_INDEX` is 512. A 4,096-byte "sector"
/// stride is not a thing a record can carry, so a USA count of 9 names exactly
/// one record size — 4,096 — and must not be read as "4,096 or 32,768,
/// undecidable" when the allocated size is damaged.
#[test]
fn the_update_sequence_stride_is_always_512_bytes() {
    let mut block = indx_record_of_size(4096, "stride.doc");
    // allocated_size damaged: only the USA can state the size.
    LittleEndian::write_u32(&mut block[0x20..0x24], 0xFFFF_FFFF);
    assert_eq!(indx_record_size(&block[..0x24]), Some(4096));
}

/// A data source whose reads fail from `fail_from` onward.
#[derive(Debug)]
struct FailingSource {
    data: Vec<u8>,
    fail_from: u64,
}

impl DataSource for FailingSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.fail_from {
            return Err(io::Error::other("injected read failure"));
        }
        let end = (offset as usize + buf.len())
            .min(self.data.len())
            .min(self.fail_from as usize);
        let n = end.saturating_sub(offset as usize);
        buf[..n].copy_from_slice(&self.data[offset as usize..offset as usize + n]);
        Ok(n)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// A read that fails part-way through the stream ended the scan with
/// `stopped` still `None`, so a stream cut off by an I/O error reported
/// itself complete. It must stop with a reason and publish the status record.
#[test]
fn a_read_that_fails_mid_stream_is_a_stop_not_the_end() {
    let a = indx_record_of_size(4096, "first.doc");
    let mut data = a.clone();
    data.extend(indx_record_of_size(4096, "second.doc"));
    let source = FailingSource {
        data,
        fail_from: 4096,
    };
    let scan = parse_i30_buffers(&source).expect("scan returns what it read");
    assert_eq!(scan.entries.len(), 1, "the first record was read whole");
    assert_eq!(scan.stopped, Some("indx_read_failed"));
}

/// A buffer that read whole but could not be parsed was `warn!`ed and
/// otherwise forgotten: no torn count, no stop, no status record. Its names are
/// missing from the listing, so the listing must say it is short.
#[test]
fn an_unparsable_buffer_is_counted_and_published() {
    let mut block = indx_record_of_size(4096, "lost.doc");
    // EntriesOffset beyond IndexLength: the node header cannot be walked.
    LittleEndian::write_u32(&mut block[0x18..0x1C], 0x0FFF);
    let ds = MockI30Source::new(block.len());
    ds.write_at(0, &block);
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(Arc::new(ds)),
        json!({ "type": "IndexAllocation", "name": "$I30" }),
    );
    let out = I30Parser.process(&artifact).expect("process failed");
    let status = out
        .iter()
        .find(|a| a.metadata["record_type"] == "i30_scan_status")
        .expect("an unparsable buffer must produce the scan-status record");
    assert_eq!(status.metadata["buffers_unparsed"], 1);
}

/// The status record wrote its sentence under `message`, which the frontend's
/// incompleteness reader never looks at. It must carry the shared vocabulary:
/// the listing pair (names are missing from it) with a `_detail`, and a
/// `content_incomplete_detail` beside the content pair it already had.
#[test]
fn the_scan_status_speaks_the_shared_incompleteness_vocabulary() {
    let block = indx_buffer_with_usa("torn.doc", true);
    let ds = MockI30Source::new(block.len());
    ds.write_at(0, &block);
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(Arc::new(ds)),
        json!({ "type": "IndexAllocation", "name": "$I30" }),
    );
    let out = I30Parser.process(&artifact).expect("process failed");
    let status = out
        .iter()
        .find(|a| a.metadata["record_type"] == "i30_scan_status")
        .expect("status record");
    let m = &status.metadata;
    assert_eq!(m["inventory_incomplete"], true);
    assert_eq!(m["inventory_incomplete_reason"], "indx_fixup_failed");
    assert!(m["inventory_incomplete_detail"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert!(m["content_incomplete_detail"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

// --- HUNT-222: a stale copy of a live entry is not a deleted name -------------

/// The slack of a real index holds stale copies of entries that still exist as
/// well as the names of deleted files. On dfir_ntfs's `ntfs_index.raw`, two of
/// the three names in `test_dir`'s slack are copies of the live
/// `AAAAAAAAAAA.txt` (53-1), and the third, `BBBBBBBBBBBBB-del.txt`, has no
/// live entry. They were published alike, so an examiner reading "recovered
/// from slack" as "deleted" counted a live file as deleted (HUNT-222).
#[test]
fn slack_copies_of_live_entries_are_labelled_as_copies_on_a_real_volume() {
    let Some(image) = load_ntfs_index_volume() else {
        return;
    };
    let records = i30_records_from_real_volume(image);
    let slack_in = |parent: &str, name: &str| -> Vec<serde_json::Value> {
        records
            .iter()
            .filter(|a| {
                a.metadata["from_slack"] == json!(true)
                    && a.metadata["parent_reference"] == parent
                    && a.metadata["file_name"] == name
            })
            .map(|a| a.metadata.clone())
            .collect()
    };

    // test_dir (39-1): two copies of the live AAAAAAAAAAA.txt, one deleted name.
    let copies = slack_in("39-1", "AAAAAAAAAAA.txt");
    assert_eq!(copies.len(), 2);
    for c in &copies {
        assert_eq!(c["file_reference"], "53-1");
        assert_eq!(
            c["slack_status"], "copy_of_live_entry",
            "a stale copy of a live entry must say so: {c}"
        );
        assert_eq!(c["stale_copy_of_live_entry"], true);
    }
    let deleted = slack_in("39-1", "BBBBBBBBBBBBB-del.txt");
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0]["slack_status"], "no_live_entry");
    assert_eq!(deleted[0]["stale_copy_of_live_entry"], false);

    // The root (5-5): `test_dir` itself survives in slack with its reference,
    // and is live — a copy, not a deleted directory.
    let test_dir = slack_in("5-5", "test_dir");
    assert_eq!(test_dir.len(), 1);
    assert_eq!(test_dir[0]["slack_status"], "copy_of_live_entry");

    // A slack entry whose reference was overwritten but whose name is live in
    // the same index cannot be proven a copy — the name could have been
    // reused by a new file — and cannot be called deleted either.
    let lost_ref = records
        .iter()
        .find(|a| {
            a.metadata["from_slack"] == json!(true)
                && a.metadata["parent_reference"] == "5-5"
                && a.metadata["file_reference"] == ""
        })
        .expect("the root's slack holds one entry whose reference is gone");
    assert_eq!(
        lost_ref.metadata["slack_status"],
        "live_name_reference_unknown"
    );
    assert_eq!(lost_ref.metadata["stale_copy_of_live_entry"], json!(null));

    // Every live entry says nothing about slack.
    for a in records
        .iter()
        .filter(|a| a.metadata["from_slack"] == json!(false))
    {
        assert!(a.metadata.get("slack_status").is_none());
    }
}

// --- HUNT-221: a stream with no data source is unread, not skipped ------------

/// The `$MFT` of the real volume, cut out on its own as a bare `$MFT` (the
/// first 128 records, which on this volume are contiguous at cluster 4,949).
fn bare_mft_from_real_volume(image: &[u8]) -> Artifact {
    use seance_core::data_source::ByteSliceDataSource;
    const VOLUME_OFFSET: usize = 128 * 512;
    const MFT_OFFSET: usize = VOLUME_OFFSET + 4949 * 2048;
    let mft = image[MFT_OFFSET..MFT_OFFSET + 128 * 1024].to_vec();
    assert_eq!(&mft[..4], b"FILE");
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(Arc::new(ByteSliceDataSource::new(mft))),
        // Named as an examiner's export is: an artifact named exactly `$MFT`
        // is the MFT parser's own output and is not re-parsed.
        json!({ "source_path": "/evidence/MFT.bin", "cluster_size": 2048 }),
    )
}

/// From a bare `$MFT` the MFT parser emits each directory's `$I30` stream
/// with no data source and `volume_not_in_evidence: true`. This module
/// refused it with `InvalidInputFormat`, which the processing log files as
/// "skipped" beside artifacts it was never for, and no record said the
/// directory's index was never read (HUNT-221).
#[test]
fn an_i30_stream_from_a_bare_mft_is_published_as_unread_on_a_real_volume() {
    let Some(image) = load_ntfs_index_volume() else {
        return;
    };
    let mft_out = seance_plugin_mft::MftParser::new()
        .process(&bare_mft_from_real_volume(&image))
        .expect("the MFT parser reads the bare $MFT");
    let streams: Vec<&Artifact> = mft_out
        .iter()
        .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("IndexAllocation"))
        .collect();
    assert!(
        !streams.is_empty(),
        "a bare $MFT still names its $I30 streams"
    );
    for stream in streams {
        assert!(stream.data.is_none());
        assert_eq!(stream.metadata["volume_not_in_evidence"], true);
        let out = I30Parser.process(stream).unwrap_or_else(|e| {
            panic!("a stream with no volume must be published as unread, not refused: {e:?}")
        });
        assert_eq!(out.len(), 1, "one status record, no entries: {out:?}");
        let m = &out[0].metadata;
        assert_eq!(m["type"], "I30ScanStatus");
        assert_eq!(m["inventory_incomplete"], true);
        assert_eq!(m["inventory_incomplete_reason"], "unresolved_structure");
        assert_eq!(m["content_incomplete"], true);
        assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
        assert_eq!(m["read_incomplete"], "volume_not_in_evidence");
        assert_eq!(m["entries_recovered"], 0);
        assert_eq!(m["parent_file"], stream.metadata["parent_file"]);
    }
}

/// The same with no producer's reason: a hand-built stream with no data
/// source says only that it had none.
#[test]
fn an_i30_stream_with_no_data_source_and_no_reason_is_published_as_unread() {
    let stream = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        None,
        json!({ "name": "$I30", "type": "IndexAllocation", "parent_file": "Users" }),
    );
    let out = I30Parser
        .process(&stream)
        .expect("no data source is an unread index, not a refused input");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["read_incomplete"], "no_data_source");
    assert_eq!(
        out[0].metadata["inventory_incomplete_reason"],
        "unresolved_structure"
    );
}

/// A slack entry whose file reference is live under another name is an old
/// name of a file that still exists — renamed — not a deleted file; one whose
/// record was reused at a later sequence is a candidate deleted name.
#[test]
fn a_slack_name_whose_file_is_live_under_another_name_is_not_called_deleted() {
    fn entry(name: &str, reference: &str, from_slack: bool) -> IndexEntry {
        IndexEntry {
            file_reference: reference.to_string(),
            parent_reference: "5-5".to_string(),
            file_name: name.to_string(),
            created: 0,
            modified: 0,
            mft_changed: 0,
            accessed: 0,
            allocated_size: 0,
            real_size: 0,
            file_attributes: 0x20,
            namespace: 1,
            flags: 0,
            is_directory: false,
            from_slack,
            buffer_index: 0,
            entry_offset: 0,
        }
    }
    let live = [entry("report-final.docx", "70-3", false)];
    let refs = live
        .iter()
        .map(|e| (e.file_reference.as_str(), e.file_name.as_str()))
        .collect();
    let names = live.iter().map(|e| e.file_name.as_str()).collect();
    assert_eq!(
        slack_status(&entry("report-draft.docx", "70-3", true), &refs, &names),
        ("reference_live_under_other_name", Some(false))
    );
    // Record 70 reused at a later sequence: the old file is gone.
    assert_eq!(
        slack_status(&entry("report-final.docx", "70-2", true), &refs, &names),
        ("no_live_entry", Some(false))
    );
}

/// HUNT-229. The FileEntry and RawEvidence gates took any name or path that
/// merely contained "i30" as an index stream, so `vti30.dll` or a case note
/// called `i30_notes.txt` was parsed as `$I30` — and, with no data behind
/// it, reported as an index that "was not read". Only the stream itself is
/// taken: a last path component of `$I30`, `…:$I30` or
/// `…:$I30:$INDEX_ALLOCATION`, compared without case.
#[test]
fn a_name_that_merely_contains_i30_is_not_taken_for_an_index_stream() {
    let file_entry = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        serde_json::json!({ "name": "vti30.dll", "path": "/Windows/System32/vti30.dll" }),
    );
    assert!(
        I30Parser.process(&file_entry).unwrap().is_empty(),
        "a DLL whose name contains i30 is not an index stream"
    );
    let raw: Arc<dyn DataSource> = Arc::new(MockI30Source::new(64));
    let raw = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(raw),
        serde_json::json!({ "source_path": "/cases/2026/i30_notes.txt" }),
    );
    assert!(
        I30Parser.process(&raw).unwrap().is_empty(),
        "a raw file whose path contains i30 is not an index stream"
    );
}

#[test]
fn the_index_stream_is_matched_exactly_and_without_case() {
    for name in [
        "$I30",
        "$i30",
        "/Users/Bob:$I30",
        "C:\\Users\\Bob:$i30:$INDEX_ALLOCATION",
    ] {
        assert!(is_i30_stream(name), "{name}");
    }
    for name in [
        "vti30.dll",
        "/cases/i30_notes.txt",
        "/$I30/readme.txt",
        "$I30.bak",
        "Bob:$I300",
    ] {
        assert!(!is_i30_stream(name), "{name}");
    }
    // An unread stream still names itself (the HUNT-221 record).
    let unread = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        serde_json::json!({ "name": "Bob:$i30", "path": "/Users/Bob:$i30" }),
    );
    assert_eq!(I30Parser.process(&unread).unwrap().len(), 1);
}
