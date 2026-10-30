use super::{
    create_artifact_from_record, decode_reason_flags, format_file_reference, parse_usn_journal,
    parse_usn_journal_capped, parse_usn_record, primary_operation, reason_flags, UsnJrnlParser,
};
use byteorder::{LittleEndian, WriteBytesExt};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::ForensicsModule;
use seance_core::test_support::DribbleSource;
use std::io::{self, Cursor, Write};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// --- Mock Data Source ---
#[derive(Debug)]
struct MockUsnJrnlSource {
    data: Arc<Mutex<Vec<u8>>>,
}

impl MockUsnJrnlSource {
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

impl DataSource for MockUsnJrnlSource {
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

// --- Helper Functions to Construct USN Records ---

// FILETIME for 2024-01-01 00:00:00 UTC
const TEST_FILETIME: u64 = 133484640000000000;

// Helper to create a USN_RECORD_V2
fn create_usn_record_v2(
    usn: u64,
    file_ref: u64,
    parent_ref: u64,
    reason_flags: u32,
    file_name: &str,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = file_name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes().to_vec())
        .collect();
    let file_name_length = name_bytes.len() as u16;
    let file_name_offset = 60u16; // V2: filename starts at offset 60

    // Record length includes: 56 byte header + 2 byte file_name_length + 2 byte file_name_offset + filename
    // Must be 8-byte aligned
    let raw_length = 60 + file_name_length as u32;
    let record_length = (raw_length + 7) & !7; // Align to 8 bytes

    let mut buf = vec![0u8; record_length as usize];
    let mut cursor = Cursor::new(&mut buf);

    cursor.write_u32::<LittleEndian>(record_length).unwrap(); // 0x00 record_length
    cursor.write_u16::<LittleEndian>(2).unwrap(); // 0x04 major_version
    cursor.write_u16::<LittleEndian>(0).unwrap(); // 0x06 minor_version
    cursor.write_u64::<LittleEndian>(file_ref).unwrap(); // 0x08 file_reference_number
    cursor.write_u64::<LittleEndian>(parent_ref).unwrap(); // 0x10 parent_reference_number
    cursor.write_u64::<LittleEndian>(usn).unwrap(); // 0x18 usn
    cursor.write_u64::<LittleEndian>(TEST_FILETIME).unwrap(); // 0x20 timestamp
    cursor.write_u32::<LittleEndian>(reason_flags).unwrap(); // 0x28 reason_flags
    cursor.write_u32::<LittleEndian>(0).unwrap(); // 0x2C source_info
    cursor.write_u32::<LittleEndian>(0).unwrap(); // 0x30 security_id
    cursor.write_u32::<LittleEndian>(0).unwrap(); // 0x34 file_attributes
    cursor.write_u16::<LittleEndian>(file_name_length).unwrap(); // 0x38 file_name_length
    cursor.write_u16::<LittleEndian>(file_name_offset).unwrap(); // 0x3A file_name_offset
    cursor.write_all(&name_bytes).unwrap(); // 0x3C filename
    buf
}

// Helper to create a USN_RECORD_V3 or V4
#[allow(clippy::too_many_arguments)]
fn create_usn_record_v3_v4(
    usn: u64,
    major_version: u16,
    file_ref_lo: u64,
    file_ref_hi: u64,
    parent_ref_lo: u64,
    parent_ref_hi: u64,
    reason_flags: u32,
    file_name: &str,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = file_name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes().to_vec())
        .collect();
    let file_name_length = name_bytes.len() as u16;

    let base_record_size = 60 + 16; // V2 base (60) + extra 16 for ref hi fields
    let raw_length = base_record_size + file_name_length as u32;
    let record_length = (raw_length + 7) & !7; // Align to 8 bytes

    let mut buf = vec![0u8; record_length as usize];
    let mut cursor = Cursor::new(&mut buf);

    cursor.write_u32::<LittleEndian>(record_length).unwrap(); // 0x00 record_length
    cursor.write_u16::<LittleEndian>(major_version).unwrap(); // 0x04 major_version
    cursor.write_u16::<LittleEndian>(0).unwrap(); // 0x06 minor_version
    cursor.write_u64::<LittleEndian>(file_ref_lo).unwrap(); // 0x08 file_reference_number (low)
    cursor.write_u64::<LittleEndian>(file_ref_hi).unwrap(); // 0x10 file_reference_number (high)
    cursor.write_u64::<LittleEndian>(parent_ref_lo).unwrap(); // 0x18 parent_reference_number (low)
    cursor.write_u64::<LittleEndian>(parent_ref_hi).unwrap(); // 0x20 parent_reference_number (high)
    cursor.write_u64::<LittleEndian>(usn).unwrap(); // 0x28 usn
    cursor.write_u64::<LittleEndian>(TEST_FILETIME).unwrap(); // 0x30 timestamp
    cursor.write_u32::<LittleEndian>(reason_flags).unwrap(); // 0x38 reason_flags
    cursor.write_u32::<LittleEndian>(0).unwrap(); // 0x3C source_info
    cursor.write_u32::<LittleEndian>(0).unwrap(); // 0x40 security_id
    cursor.write_u32::<LittleEndian>(0).unwrap(); // 0x44 file_attributes
    cursor.write_u16::<LittleEndian>(file_name_length).unwrap(); // 0x48 file_name_length
    cursor
        .write_u16::<LittleEndian>(base_record_size as u16)
        .unwrap(); // 0x4A file_name_offset

    cursor.write_all(&name_bytes).unwrap();
    buf
}

// --- Tests ---

#[test]
fn test_parse_usn_record_v2() {
    let record_data = create_usn_record_v2(
        1001,
        0x1000000000005,
        0x2000000000003,
        reason_flags::FILE_CREATE,
        "testfile.txt",
    );

    let record = parse_usn_record(&record_data).expect("Failed to parse V2 record");

    assert_eq!(record.major_version, 2);
    assert_eq!(record.usn, 1001);
    assert_eq!(record.file_name, "testfile.txt");
    assert_eq!(record.file_reference_number, 0x1000000000005);
    assert_eq!(record.parent_reference_number, 0x2000000000003);
    assert!(record.reason_flags & reason_flags::FILE_CREATE != 0);
}

#[test]
fn test_parse_usn_record_v3() {
    let record_data = create_usn_record_v3_v4(
        2002,
        3,
        0x1234567890ABCDEF,
        0xFEDCBA9876543210,
        0x1122334455667788,
        0x99AABBCCDDEEFF00,
        reason_flags::RENAME_NEW_NAME | reason_flags::RENAME_OLD_NAME,
        "newname.txt",
    );

    let record = parse_usn_record(&record_data).expect("Failed to parse V3 record");

    assert_eq!(record.major_version, 3);
    assert_eq!(record.usn, 2002);
    assert_eq!(record.file_name, "newname.txt");
    assert_eq!(record.file_reference_number, 0x1234567890ABCDEF);
    assert_eq!(record.file_reference_number_hi, 0xFEDCBA9876543210);
    assert_eq!(record.parent_reference_number, 0x1122334455667788);
    assert_eq!(record.parent_reference_number_hi, 0x99AABBCCDDEEFF00);
    assert!(record.reason_flags & reason_flags::RENAME_NEW_NAME != 0);
    assert!(record.reason_flags & reason_flags::RENAME_OLD_NAME != 0);
}

#[test]
fn test_usn_journal_handles_short_reads() {
    // Regression (BUG-063): a source returning only a few bytes per read_at must
    // not truncate or zero-fill. The read loop reassembles the full journal and
    // every record parses.
    let mut data = Vec::new();
    data.extend_from_slice(&create_usn_record_v2(
        1,
        0x100,
        0x200,
        reason_flags::FILE_CREATE,
        "a.txt",
    ));
    data.extend_from_slice(&create_usn_record_v2(
        2,
        0x101,
        0x201,
        reason_flags::FILE_DELETE,
        "b.txt",
    ));
    // Returns at most 7 bytes per `read_at`, simulating a windowed/streaming
    // source that never fills the whole buffer in one call. 7 is well under the
    // 60-byte USN_RECORD_V2 header, so every structural read is split.
    let src = DribbleSource::new(data, 7);

    let (records, window) =
        parse_usn_journal(&src).expect("short reads must be looped, not truncated");
    src.assert_dribbled();
    assert_eq!(records.len(), 2);
    assert!(
        !window.truncated(),
        "a journal under the cap is parsed whole"
    );
    assert_eq!(records[0].usn, 1);
    assert_eq!(records[1].usn, 2);
}

#[test]
fn test_usn_journal_reads_tail_when_over_cap() {
    // Regression (BUG-063): when the journal exceeds the cap, read the live tail
    // (recent records) rather than the sparse, purged head. The record sits at
    // an 8-aligned offset so the zero-record skip lands exactly on it.
    let source = MockUsnJrnlSource::new(0);
    source.write_at(0, &vec![0u8; 800]); // sparse/purged head
    let record = create_usn_record_v2(7777, 0x100, 0x200, reason_flags::FILE_CREATE, "tail.txt");
    source.write_at(800, &record);

    let total = source.size();
    let cap = total - 400; // start = 400, dropping part of the zero head
    let (records, window) = parse_usn_journal_capped(&source, cap).expect("tail parse");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].usn, 7777);
    assert_eq!(records[0].file_name, "tail.txt");
    // BUG-283: reading only the tail must be reported, not left to look like
    // the whole journal.
    assert!(window.truncated());
    assert_eq!(window.window_start, 400);
    assert_eq!(window.journal_size, total);
}

#[test]
fn test_parse_usn_journal_multiple_records() {
    let source = MockUsnJrnlSource::new(4096);
    let _case_id = Uuid::new_v4();

    let record_v2_data =
        create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "file1.txt");
    let record_v3_data = create_usn_record_v3_v4(
        2002,
        3,
        0x101,
        0,
        0x201,
        0,
        reason_flags::DATA_OVERWRITE,
        "file2.txt",
    );

    // Pad records to 8-byte alignment if needed
    let padded_v2_len = (record_v2_data.len() + 7) & !7; // Align to 8 bytes
    let _padded_v3_len = (record_v3_data.len() + 7) & !7;

    source.write_at(0, &record_v2_data);
    source.write_at(padded_v2_len as u64, &record_v3_data);

    let (records, _window) = parse_usn_journal(&source).expect("Failed to parse USN journal");

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].major_version, 2);
    assert_eq!(records[0].usn, 1001);
    assert_eq!(records[1].major_version, 3);
    assert_eq!(records[1].usn, 2002);
}

#[test]
fn test_usnjrnl_parser_process_method() {
    let source = Arc::new(MockUsnJrnlSource::new(1024));
    let case_id = Uuid::new_v4();

    let record_data =
        create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "file1.txt");
    source.write_at(0, &record_data);

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry, // Simulate detection
        Some(source.clone()),
        serde_json::json!({ "file_name": "$UsnJrnl:$J", "source_path": "C:\\$Extend\\$UsnJrnl" }),
    );

    let parser = UsnJrnlParser;
    let results = parser.process(&artifact).expect("Parser failed");

    assert_eq!(results.len(), 2); // One ParsedRecord + One TimelineEvent
    let parsed_record = results
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .unwrap();
    let timeline_event = results
        .iter()
        .find(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .unwrap();

    assert_eq!(parsed_record.metadata["file_name"], "file1.txt");
    // Timeline event has short_desc like "USN: FILE_CREATE on file1.txt"
    let short_desc = timeline_event.metadata["short_desc"].as_str().unwrap();
    assert!(
        short_desc.contains("FILE_CREATE"),
        "Expected short_desc to contain FILE_CREATE, got: {}",
        short_desc
    );
    assert!(
        short_desc.contains("file1.txt"),
        "Expected short_desc to contain file1.txt, got: {}",
        short_desc
    );
    assert_eq!(timeline_event.parent_id, Some(parsed_record.id));
}

#[test]
fn test_zero_filetime_record_has_no_timestamp() {
    let mut record_data =
        create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "stomped.txt");
    // Zero out the FILETIME at offset 0x20 (timestomping indicator)
    record_data[0x20..0x28].copy_from_slice(&[0u8; 8]);

    let record = parse_usn_record(&record_data).expect("Failed to parse record");
    assert!(
        record.timestamp.is_none(),
        "FILETIME 0 must not become a 1970 date"
    );
}

#[test]
fn test_corrupt_huge_filetime_does_not_panic() {
    let mut record_data =
        create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "corrupt.txt");
    // u64::MAX would overflow a naive `intervals * 100` conversion
    record_data[0x20..0x28].copy_from_slice(&u64::MAX.to_le_bytes());

    let record = parse_usn_record(&record_data).expect("Failed to parse record");
    // Either a far-future value or None is acceptable; panicking is not.
    let _ = record.timestamp;
}

#[test]
fn test_zero_timestamp_omitted_from_artifacts() {
    let source = Arc::new(MockUsnJrnlSource::new(1024));
    let case_id = Uuid::new_v4();

    let mut record_data =
        create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "stomped.txt");
    record_data[0x20..0x28].copy_from_slice(&[0u8; 8]);
    source.write_at(0, &record_data);

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(source.clone()),
        serde_json::json!({ "file_name": "$UsnJrnl:$J", "source_path": "C:\\$Extend\\$UsnJrnl" }),
    );

    let parser = UsnJrnlParser;
    let results = parser.process(&artifact).expect("Parser failed");

    let parsed_record = results
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .unwrap();
    assert!(
        parsed_record.metadata.get("timestamp").is_none(),
        "zero FILETIME must not appear as an epoch timestamp"
    );

    // No timeline event should be fabricated for an absent timestamp
    assert!(
        results
            .iter()
            .all(|a| a.artifact_type != ArtifactType::TimelineEvent),
        "zero FILETIME must not generate a 1970 timeline event"
    );
}

#[test]
fn test_decode_reason_flags() {
    let flags =
        reason_flags::FILE_CREATE | reason_flags::DATA_EXTEND | reason_flags::SECURITY_CHANGE;
    let reasons = decode_reason_flags(flags);
    assert!(reasons.contains(&"FILE_CREATE".to_string()));
    assert!(reasons.contains(&"DATA_EXTEND".to_string()));
    assert!(reasons.contains(&"SECURITY_CHANGE".to_string()));
    assert_eq!(reasons.len(), 3);
}

#[test]
fn test_primary_operation() {
    assert_eq!(primary_operation(reason_flags::FILE_CREATE), "FILE_CREATE");
    assert_eq!(primary_operation(reason_flags::FILE_DELETE), "FILE_DELETE");
    assert_eq!(
        primary_operation(reason_flags::RENAME_OLD_NAME | reason_flags::RENAME_NEW_NAME),
        "RENAME"
    );
    assert_eq!(
        primary_operation(reason_flags::DATA_OVERWRITE),
        "DATA_MODIFY"
    );
    assert_eq!(
        primary_operation(reason_flags::SECURITY_CHANGE),
        "SECURITY_CHANGE"
    );
    assert_eq!(primary_operation(reason_flags::CLOSE), "CLOSE");
    assert_eq!(primary_operation(0), "UNKNOWN");
}

#[test]
fn test_format_file_reference() {
    // V2 style (hi part is 0)
    assert_eq!(format_file_reference(0x0001000000000005, 0), "5-1");
    // V3+ style (hi part is non-zero)
    assert_eq!(
        format_file_reference(0x1234567890ABCDEF, 0xFEDCBA9876543210),
        "1234567890ABCDEF-FEDCBA9876543210"
    );
}

// --- USN_RECORD_V4 (range-tracking) ---

// Helper to create a real USN_RECORD_V4: no timestamp, no filename, just
// changed byte ranges. `extents` are (offset, length) pairs.
#[allow(clippy::too_many_arguments)]
fn create_usn_record_v4(
    usn: u64,
    file_ref_lo: u64,
    file_ref_hi: u64,
    parent_ref_lo: u64,
    parent_ref_hi: u64,
    reason_flags: u32,
    remaining_extents: u32,
    extents: &[(i64, i64)],
) -> Vec<u8> {
    let record_length = (0x40 + extents.len() * 16) as u32; // already 8-aligned
    let mut buf = vec![0u8; record_length as usize];
    let mut cursor = Cursor::new(&mut buf);

    cursor.write_u32::<LittleEndian>(record_length).unwrap(); // 0x00 record_length
    cursor.write_u16::<LittleEndian>(4).unwrap(); // 0x04 major_version
    cursor.write_u16::<LittleEndian>(2).unwrap(); // 0x06 minor_version
    cursor.write_u64::<LittleEndian>(file_ref_lo).unwrap(); // 0x08 file_reference_number (low)
    cursor.write_u64::<LittleEndian>(file_ref_hi).unwrap(); // 0x10 file_reference_number (high)
    cursor.write_u64::<LittleEndian>(parent_ref_lo).unwrap(); // 0x18 parent (low)
    cursor.write_u64::<LittleEndian>(parent_ref_hi).unwrap(); // 0x20 parent (high)
    cursor.write_u64::<LittleEndian>(usn).unwrap(); // 0x28 usn
    cursor.write_u32::<LittleEndian>(reason_flags).unwrap(); // 0x30 reason
    cursor.write_u32::<LittleEndian>(0).unwrap(); // 0x34 source_info
    cursor.write_u32::<LittleEndian>(remaining_extents).unwrap(); // 0x38 remaining_extents
    cursor
        .write_u16::<LittleEndian>(extents.len() as u16)
        .unwrap(); // 0x3C number_of_extents
    cursor.write_u16::<LittleEndian>(16).unwrap(); // 0x3E extent_size
    for (offset, length) in extents {
        cursor.write_i64::<LittleEndian>(*offset).unwrap();
        cursor.write_i64::<LittleEndian>(*length).unwrap();
    }
    buf
}

#[test]
fn test_parse_usn_record_v4() {
    let record_data = create_usn_record_v4(
        9001,
        0xAAAA000000000001,
        0xBBBB000000000002,
        0xCCCC000000000003,
        0xDDDD000000000004,
        reason_flags::DATA_OVERWRITE | reason_flags::DATA_EXTEND,
        7,
        &[(0x1000, 0x200), (0x4000, 0x1000)],
    );

    let record = parse_usn_record(&record_data).expect("Failed to parse V4 record");

    assert_eq!(record.major_version, 4);
    assert_eq!(record.minor_version, 2);
    assert_eq!(record.usn, 9001);
    assert_eq!(record.file_reference_number, 0xAAAA000000000001);
    assert_eq!(record.file_reference_number_hi, 0xBBBB000000000002);
    assert_eq!(record.parent_reference_number, 0xCCCC000000000003);
    assert_eq!(record.parent_reference_number_hi, 0xDDDD000000000004);
    assert!(record.reason_flags & reason_flags::DATA_OVERWRITE != 0);
    assert_eq!(record.remaining_extents, 7);
    assert_eq!(record.extents.len(), 2);
    assert_eq!(record.extents[0].offset, 0x1000);
    assert_eq!(record.extents[0].length, 0x200);
    assert_eq!(record.extents[1].offset, 0x4000);
    assert_eq!(record.extents[1].length, 0x1000);

    // V4 carries no timestamp or filename; both must stay empty, never
    // fabricated out of extent bytes.
    assert!(record.timestamp.is_none());
    assert!(record.file_name.is_empty());
}

#[test]
fn test_parse_usn_record_v4_zero_extents() {
    let record_data = create_usn_record_v4(1, 0x100, 0, 0x200, 0, reason_flags::CLOSE, 0, &[]);

    let record = parse_usn_record(&record_data).expect("Failed to parse empty V4 record");
    assert_eq!(record.major_version, 4);
    assert!(record.extents.is_empty());
    assert_eq!(record.remaining_extents, 0);
}

#[test]
fn test_parse_usn_record_v4_truncated_extents() {
    // Declares 3 extents but carries only 1.
    let mut record_data = create_usn_record_v4(1, 0x100, 0, 0x200, 0, 0, 0, &[(0x1000, 0x200)]);
    record_data[0x3C..0x3E].copy_from_slice(&3u16.to_le_bytes());

    let result = parse_usn_record(&record_data);
    assert!(
        result.is_err(),
        "truncated extent array must error, not guess"
    );
}

#[test]
fn test_parse_usn_record_v4_bad_extent_size() {
    // ExtentSize too small to hold offset+length.
    let mut record_data = create_usn_record_v4(1, 0x100, 0, 0x200, 0, 0, 0, &[(0x1000, 0x200)]);
    record_data[0x3E..0x40].copy_from_slice(&8u16.to_le_bytes());

    let result = parse_usn_record(&record_data);
    assert!(result.is_err(), "undersized extent entries must error");
}

#[test]
fn test_v4_record_emits_no_timeline_event_and_reports_extents() {
    let source = Arc::new(MockUsnJrnlSource::new(1024));
    let case_id = Uuid::new_v4();

    let record_data = create_usn_record_v4(
        42,
        0x100,
        0,
        0x200,
        0,
        reason_flags::DATA_OVERWRITE,
        0,
        &[(0x8000, 0x1000)],
    );
    source.write_at(0, &record_data);

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(source.clone()),
        serde_json::json!({ "file_name": "$UsnJrnl:$J", "source_path": "C:\\$Extend\\$UsnJrnl" }),
    );

    let parser = UsnJrnlParser;
    let results = parser.process(&artifact).expect("Parser failed");

    let parsed_record = results
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .expect("V4 record must still produce a ParsedRecord");

    // The record reports its extents and carries no timestamp...
    let extents = parsed_record.metadata["extents"].as_array().unwrap();
    assert_eq!(extents.len(), 1);
    assert_eq!(extents[0]["offset"], 0x8000);
    assert_eq!(extents[0]["length"], 0x1000);
    assert!(parsed_record.metadata.get("timestamp").is_none());
    assert!(parsed_record.metadata.get("security_id").is_none());
    assert!(parsed_record.metadata.get("file_attributes").is_none());

    // ...and no 1970 timeline event is fabricated from a missing timestamp.
    assert!(
        results
            .iter()
            .all(|a| a.artifact_type != ArtifactType::TimelineEvent),
        "V4 record has no timestamp and must not generate a timeline event"
    );
}

#[test]
fn test_over_cap_parse_emits_a_window_marker() {
    // BUG-283: a journal larger than the parse cap yields only its recent tail.
    // Nothing in the produced artifacts used to say so, so the timeline looked
    // like the complete rename/delete history of the volume.
    let source = Arc::new(MockUsnJrnlSource::new(0));
    source.write_at(0, &vec![0u8; 800]); // purged/sparse head
    let record = create_usn_record_v2(7777, 0x100, 0x200, reason_flags::FILE_CREATE, "tail.txt");
    source.write_at(800, &record);
    let total = source.size();

    let (records, window) =
        parse_usn_journal_capped(source.as_ref(), total - 400).expect("tail parse");
    assert_eq!(records.len(), 1);
    assert!(window.truncated());
    assert_eq!(window.window_start, 400);
    assert_eq!(window.bytes_read, total - 400);
    assert_eq!(window.journal_size, total);
}

#[test]
fn test_journal_under_the_cap_emits_no_window_marker() {
    let source = Arc::new(MockUsnJrnlSource::new(1024));
    let record_data =
        create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "file1.txt");
    source.write_at(0, &record_data);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source.clone()),
        serde_json::json!({ "file_name": "$UsnJrnl:$J" }),
    );
    let results = UsnJrnlParser.process(&artifact).expect("Parser failed");
    assert!(
        results
            .iter()
            .all(|a| a.metadata["type"] != "UsnJournalWindow"),
        "a fully parsed journal must not claim to be partial"
    );
}

#[test]
fn a_v4_record_with_more_extents_elsewhere_does_not_present_its_list_as_the_whole_change() {
    let record_data = create_usn_record_v4(
        9001,
        0x1,
        0,
        0x2,
        0,
        reason_flags::DATA_OVERWRITE,
        7, // seven further extents live in other records
        &[(0x1000, 0x200)],
    );
    let record = parse_usn_record(&record_data).expect("Failed to parse V4 record");
    let art = create_artifact_from_record(Uuid::new_v4(), &record, Uuid::new_v4());

    assert_eq!(art.metadata["remaining_extents"], 7);
    assert_eq!(art.metadata["extents_complete"], false);
    assert_eq!(art.metadata["content_incomplete"], true);
    assert_eq!(
        art.metadata["content_incomplete_reason"],
        "v4_extents_continue_in_later_records"
    );
}

#[test]
fn a_v4_record_holding_every_extent_is_marked_complete() {
    let record_data = create_usn_record_v4(
        9002,
        0x1,
        0,
        0x2,
        0,
        reason_flags::DATA_OVERWRITE,
        0,
        &[(0x1000, 0x200)],
    );
    let record = parse_usn_record(&record_data).expect("Failed to parse V4 record");
    let art = create_artifact_from_record(Uuid::new_v4(), &record, Uuid::new_v4());

    assert_eq!(art.metadata["extents_complete"], true);
    assert!(art.metadata.get("content_incomplete").is_none());
}

/// B2-156: only the byte cap used to make the parse honest. A journal whose
/// stream ends early, or that holds a record length the walker cannot use,
/// silently loses history and reported itself whole — so a rename or delete
/// missing from the timeline read as a rename or delete that never happened.
#[test]
fn a_journal_with_an_unusable_record_length_reports_itself_incomplete() {
    let source = Arc::new(MockUsnJrnlSource::new(0));
    let good = create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "file1.txt");
    source.write_at(0, &good);
    // A record claiming a length that is neither 8-aligned nor >= 60: the
    // walker resyncs 8 bytes on, skipping an unknown span of the journal.
    let bad_off = good.len() as u64;
    source.write_at(bad_off, &7u32.to_le_bytes());
    source.write_at(bad_off + 4, &[0u8; 4]);
    // Pad out so the walk continues past it.
    source.write_at(bad_off + 8, &[0u8; 64]);

    let (records, window) = parse_usn_journal(source.as_ref()).expect("parse");
    assert_eq!(records.len(), 1, "the good record still comes through");
    assert!(!window.truncated(), "the byte cap did not apply here");
    assert_eq!(
        window.invalid_lengths, 1,
        "the skipped span must be counted, not only logged"
    );
    assert_eq!(
        window.incomplete_reason(),
        Some("unresolved_structure"),
        "a journal with a skipped span is not a complete journal"
    );

    // And it must reach the examiner as a record.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source.clone()),
        serde_json::json!({ "file_name": "$UsnJrnl:$J" }),
    );
    let results = UsnJrnlParser.process(&artifact).expect("Parser failed");
    let status = results
        .iter()
        .find(|a| a.metadata["type"] == "UsnJournalWindow")
        .expect("a partly parsed journal must publish a status record");
    assert_eq!(
        status.metadata["content_incomplete"],
        serde_json::json!(true)
    );
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        serde_json::json!("unresolved_structure")
    );
    assert_eq!(
        status.metadata["invalid_record_lengths"],
        serde_json::json!(1)
    );
}

/// A window ending part-way through a record means the rest of that record —
/// and everything after it — was never read.
#[test]
fn a_window_ending_mid_record_is_reported_incomplete() {
    let source = Arc::new(MockUsnJrnlSource::new(0));
    let good = create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "file1.txt");
    source.write_at(0, &good);
    // A second record header declaring 200 bytes with only 8 present.
    let off = good.len() as u64;
    source.write_at(off, &200u32.to_le_bytes());
    source.write_at(off + 4, &[0u8; 4]);

    let (records, window) = parse_usn_journal(source.as_ref()).expect("parse");
    assert_eq!(records.len(), 1);
    assert!(window.trailing_partial_record);
    assert_eq!(window.incomplete_reason(), Some("short_read"));
}

/// The MFT parser publishes `$UsnJrnl:$J` as a FileEntry keyed by `name` and
/// `stream_name`; it never writes `file_name`. Gating on `file_name` alone
/// meant a normal NTFS ingest produced NO USN history at all, while these
/// tests passed because they hand-set `file_name` (B6-001).
#[test]
fn the_mft_spelling_of_the_j_stream_is_recognised() {
    let source = Arc::new(MockUsnJrnlSource::new(1024));
    source.write_at(
        0,
        &create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "file1.txt"),
    );

    // Exactly the metadata shape seance_plugin_mft emits for an ADS.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        serde_json::json!({
            "name": "$UsnJrnl:$J",
            "stream_name": "$J",
            "is_ads": true,
            "parent_file": "$UsnJrnl",
            "path": "/$Extend/$UsnJrnl:$J",
        }),
    );
    let results = UsnJrnlParser.process(&artifact).expect("Parser failed");
    let parsed = results
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .expect("the MFT-emitted $J stream must be parsed");
    assert_eq!(parsed.metadata["file_name"], "file1.txt");
}

/// `$UsnJrnl` also carries a `$Max` control stream and a base record with no
/// change records at all. Widening the gate must not make either of them decode
/// as journal history.
/// The fuzz target's artifact shape must reach the record walk.
///
/// `fuzz/fuzz_targets/usnjrnl_parser.rs` used to build a `SystemArtifact`
/// named `$UsnJrnl` with no stream — which the test below pins as
/// must-not-decode, correctly, because that is the base record and not the
/// `$J` change stream. So the target returned `Ok(vec![])` for every input,
/// the record-length walk it exists to exercise was never reached, and it was
/// counted among the live fuzz coverage. A fuzz target
/// that selects nothing is worse than no target, because it is reported as
/// coverage.
#[test]
fn a_fuzz_targets_artifact_shape_reaches_the_record_walk() {
    let source = Arc::new(MockUsnJrnlSource::new(1024));
    source.write_at(
        0,
        &create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "file1.txt"),
    );
    // Kept byte-for-byte in step with the fuzz target.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(source),
        serde_json::json!({"name": "$UsnJrnl:$J", "stream_name": "$J"}),
    );
    let results = UsnJrnlParser.process(&artifact).expect("Parser failed");
    assert!(
        results
            .iter()
            .any(|a| a.metadata["type"] == "UsnJournalEntry"),
        "the fuzz target's metadata must be accepted, or the target fuzzes nothing"
    );
}

#[test]
fn the_max_stream_and_the_base_record_are_not_parsed_as_journal() {
    let source = Arc::new(MockUsnJrnlSource::new(1024));
    source.write_at(
        0,
        &create_usn_record_v2(1001, 0x100, 0x200, reason_flags::FILE_CREATE, "file1.txt"),
    );

    for metadata in [
        serde_json::json!({ "name": "$UsnJrnl:$Max", "stream_name": "$Max", "is_ads": true }),
        serde_json::json!({ "name": "$UsnJrnl", "path": "/$Extend/$UsnJrnl" }),
    ] {
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(source.clone()),
            metadata.clone(),
        );
        let results = UsnJrnlParser.process(&artifact).expect("Parser failed");
        assert!(
            results.is_empty(),
            "{} must not be decoded as USN records",
            metadata
        );
    }
}
