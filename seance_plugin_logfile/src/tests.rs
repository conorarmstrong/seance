use super::*;
use seance_core::data_source::DataSource;
use std::io;
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
struct MockLogFileSource {
    data: Arc<Mutex<Vec<u8>>>,
}

impl MockLogFileSource {
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

impl DataSource for MockLogFileSource {
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

// --- Fixture builders: real LFS pages with update sequence array protection ---
//
// Every page is 8 sectors of 512 bytes. The USA holds one sequence number plus
// the true last-two-bytes of every sector; on disk each sector tail carries a
// copy of the sequence number instead. Fixtures are built as plain content and
// then "protected" so the parser's fixup has something real to verify and
// restore — exactly like an on-disk $LogFile.

const PAGE: usize = 4096;
const SECTORS: usize = PAGE / 512;
const USA_COUNT: u16 = (SECTORS + 1) as u16; // 9
const RESTART_USA_OFFSET: usize = 0x30;
const RESTART_AREA_OFFSET: usize = 0x48;
const RECORD_USA_OFFSET: usize = 0x28;
const RECORD_DATA_OFFSET: usize = 0x40;
const LFS_HEADER_LEN: usize = 0x30;
const SEQ: u16 = 0xBEEF;

fn put16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}
fn put32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}
fn put64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

/// Stash every sector's true tail bytes into the USA and write the sequence
/// number placeholders, mirroring what NTFS writes to disk.
fn usa_protect(page: &mut [u8], usa_offset: usize) {
    let count = page.len() / 512 + 1;
    page[usa_offset..usa_offset + 2].copy_from_slice(&SEQ.to_le_bytes());
    for i in 1..count {
        let tail = i * 512 - 2;
        let saved = [page[tail], page[tail + 1]];
        page[usa_offset + i * 2..usa_offset + i * 2 + 2].copy_from_slice(&saved);
        page[tail..tail + 2].copy_from_slice(&SEQ.to_le_bytes());
    }
}

/// Build a valid restart (`RSTR`) page: 4096-byte system/log pages, restart
/// area at 0x48, no client records.
fn create_restart_page(current_lsn: u64, file_size: u64) -> Vec<u8> {
    let mut p = vec![0u8; PAGE];
    p[0..4].copy_from_slice(b"RSTR");
    put16(&mut p, 4, RESTART_USA_OFFSET as u16);
    put16(&mut p, 6, USA_COUNT);
    // chkdsk_lsn @8 left as 0
    put32(&mut p, 16, PAGE as u32); // system_page_size
    put32(&mut p, 20, PAGE as u32); // log_page_size
    put16(&mut p, 24, RESTART_AREA_OFFSET as u16);
    put16(&mut p, 26, 0); // minor version
    put16(&mut p, 28, 1); // major version

    let ra = RESTART_AREA_OFFSET;
    put64(&mut p, ra, current_lsn);
    put16(&mut p, ra + 8, 0); // log_clients = 0 (client array skipped)
    put16(&mut p, ra + 14, 0); // flags
    put32(&mut p, ra + 16, 0); // seq_number_bits
    put16(&mut p, ra + 20, 512); // restart_area_length
    put16(&mut p, ra + 22, 0); // client_array_offset
    put64(&mut p, ra + 24, file_size);
    put16(&mut p, ra + 36, LFS_HEADER_LEN as u16); // record_header_length
    put16(&mut p, ra + 38, RECORD_DATA_OFFSET as u16); // log_page_data_offset

    usa_protect(&mut p, RESTART_USA_OFFSET);
    p
}

/// Build one NTFS client log record: 48-byte LFS header + 32-byte NTFS op
/// header (client_data_length = 32, a multiple of 8 as the format requires).
#[allow(clippy::too_many_arguments)]
fn create_log_record(
    lsn: u64,
    redo_op: u16,
    undo_op: u16,
    redo_len: u16,
    undo_len: u16,
    target_attr: u16,
    target_vcn: i64,
) -> Vec<u8> {
    let mut r = vec![0u8; LFS_HEADER_LEN + 32];
    put64(&mut r, 0, lsn);
    // client_previous_lsn @8, client_undo_next_lsn @16 left as 0
    put32(&mut r, 24, 32); // client_data_length
    put32(&mut r, 28, 0); // client_id
    put32(&mut r, 32, LFS_CLIENT_RECORD);
    put32(&mut r, 36, 1); // transaction_id
    put16(&mut r, 40, 0); // flags

    let d = LFS_HEADER_LEN;
    put16(&mut r, d, redo_op);
    put16(&mut r, d + 2, undo_op);
    put16(&mut r, d + 4, 0); // redo_offset
    put16(&mut r, d + 6, redo_len);
    put16(&mut r, d + 8, 0); // undo_offset
    put16(&mut r, d + 10, undo_len);
    put16(&mut r, d + 12, target_attr);
    put16(&mut r, d + 14, 0); // lcns_to_follow
    r[d + 24..d + 32].copy_from_slice(&target_vcn.to_le_bytes());
    r
}

/// Build a valid `RCRD` record page holding `records` back-to-back starting at
/// the data offset, with next_record_offset set just past the last one.
fn create_record_page(records: &[Vec<u8>]) -> Vec<u8> {
    let mut p = vec![0u8; PAGE];
    p[0..4].copy_from_slice(b"RCRD");
    put16(&mut p, 4, RECORD_USA_OFFSET as u16);
    put16(&mut p, 6, USA_COUNT);

    let mut off = RECORD_DATA_OFFSET;
    for r in records {
        p[off..off + r.len()].copy_from_slice(r);
        off += r.len();
    }
    put16(&mut p, 24, off as u16); // next_record_offset

    usa_protect(&mut p, RECORD_USA_OFFSET);
    p
}

// --- Tests ---

#[test]
fn test_parse_restart_page_success() {
    init_logging();
    let page = create_restart_page(0x1234567890ABCDEF, PAGE as u64 * 10);

    let restart = parse_restart_page(&page).expect("Failed to parse restart page");

    assert_eq!(&restart.signature, b"RSTR");
    assert_eq!(restart.current_lsn, 0x1234567890ABCDEF);
    assert_eq!(restart.file_size, PAGE as i64 * 10);
    assert_eq!(restart.restart_area_length, 512);
    assert_eq!(restart.system_page_size, PAGE as u32);
    assert_eq!(restart.log_page_size, PAGE as u32);
    assert_eq!(restart.record_header_length, LFS_HEADER_LEN as u16);
    assert_eq!(restart.log_page_data_offset, RECORD_DATA_OFFSET as u16);
}

#[test]
fn test_parse_restart_page_invalid_magic() {
    init_logging();
    let mut page = create_restart_page(0, 0);
    page[0..4].copy_from_slice(b"BAD!"); // not at a sector tail, fixup still passes

    let result = parse_restart_page(&page);
    assert!(result.is_err());
    assert!(format!("{:?}", result.unwrap_err()).contains("bad signature"));
}

#[test]
fn test_torn_restart_page_detected() {
    init_logging();
    let mut page = create_restart_page(0x1000, PAGE as u64 * 2);
    page[511] ^= 0xFF; // break the sector-0 tail placeholder => torn write

    let result = parse_restart_page(&page);
    assert!(result.is_err());
    assert!(format!("{:?}", result.unwrap_err()).contains("torn"));
}

#[test]
fn test_parse_logfile_records() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 3);
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 3));

    let records = vec![
        create_log_record(0x1001, 0x05, 0x00, 16, 0, 0x80, 0), // CreateAttribute
        create_log_record(0x1002, 0x07, 0x00, 32, 0, 0x10, 0), // UpdateResidentValue
        create_log_record(0x1003, 0x00, 0x06, 0, 0, 0x30, 0),  // undo DeleteAttribute
        create_log_record(0x1004, 0x13, 0x00, 0, 0, 0x30, 0),  // UpdateFileNameRoot
        create_log_record(0x1005, 0x00, 0x00, 0, 0, 0x00, 0),  // Noop
    ];
    source.write_at(PAGE as u64 * 2, &create_record_page(&records));

    let parsed = parse_logfile(&source).expect("Failed to parse $LogFile");

    assert_eq!(parsed.restart_page_used, 1);
    assert_eq!(parsed.records.len(), 5);
    assert_eq!(parsed.torn_pages, 0);
    assert_eq!(parsed.pages_scanned, 1);

    let op0 = parsed.records[0].op.as_ref().unwrap();
    assert_eq!(parsed.records[0].lsn, 0x1001);
    assert_eq!(op0.redo_operation, 0x05);
    assert_eq!(ntfs_operation_name(op0.redo_operation), "CreateAttribute");
    assert_eq!(op0.redo_length, 16);
    assert_eq!(op0.target_attribute, 0x80);

    let op2 = parsed.records[2].op.as_ref().unwrap();
    assert_eq!(op2.redo_operation, 0x00);
    assert_eq!(op2.undo_operation, 0x06);
    assert_eq!(ntfs_operation_name(op2.undo_operation), "DeleteAttribute");

    // Significance: anything with a non-Noop redo or undo op.
    assert!(is_significant(&parsed.records[0]));
    assert!(is_significant(&parsed.records[2]));
    assert!(!is_significant(&parsed.records[4]));
}

#[test]
fn test_parse_logfile_uses_backup_restart_page() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 2);

    let mut torn_primary = create_restart_page(0x1000, PAGE as u64 * 2);
    torn_primary[1023] ^= 0xFF; // torn sector tail => primary fails fixup
    source.write_at(0, &torn_primary);
    source.write_at(PAGE as u64, &create_restart_page(0x2000, PAGE as u64 * 2));

    let parsed = parse_logfile(&source).expect("Should fall back to backup restart page");

    assert_eq!(parsed.restart_page_used, 2);
    assert_eq!(parsed.restart.current_lsn, 0x2000);
    assert!(parsed.records.is_empty());
}

#[test]
fn test_parse_logfile_no_restart_page() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 2); // all zeros

    assert!(parse_logfile(&source).is_err());
}

#[test]
fn test_multi_page_record_flagged_and_walk_stops() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 3);
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 3));

    // A record whose client data spills past the end of the page.
    let mut rec = create_log_record(0x1001, 0x08, 0x00, 0, 0, 0x80, 0);
    put32(&mut rec, 24, (PAGE * 2) as u32); // client_data_length far past page end
    source.write_at(PAGE as u64 * 2, &create_record_page(&[rec]));

    let parsed = parse_logfile(&source).expect("Failed to parse $LogFile");

    assert_eq!(parsed.records.len(), 1);
    assert!(
        parsed.records[0].multi_page,
        "record spilling past the page must be flagged multi_page"
    );
}

#[test]
fn test_logfile_parser_process_method() {
    init_logging();
    let source = Arc::new(MockLogFileSource::new(PAGE * 3));
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 3));
    source.write_at(
        PAGE as u64 * 2,
        &create_record_page(&[create_log_record(0x1001, 0x05, 0x00, 16, 0, 0x80, 0)]),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source.clone()),
        serde_json::json!({
            "name": "$LogFile",
            "file_size": PAGE * 3
        }),
    );

    let parser = LogFileParser;
    let results = parser.process(&artifact).expect("Parser failed");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(results[0].metadata["operation"], "CreateAttribute");
    assert_eq!(results[0].metadata["lsn"], "0x0000000000001001");
    assert_eq!(results[0].metadata["source"], "$LogFile");
    assert_eq!(results[0].metadata["multi_page"], false);

    // The record carries a categorical TYPE that names the kind of record, and
    // does NOT carry a bare numeric `record_type` — the analysis grouping keys
    // on `type` first and would otherwise file every $LogFile record under a
    // card titled by that number ("1"), which is the largest class in an NTFS
    // case. The number is still present under a name that says what it is.
    assert_eq!(
        results[0].metadata["type"], "NtfsLogFileRecord",
        "a $LogFile record must group by a real type name, not fall through to a number"
    );
    assert!(
        results[0].metadata.get("record_type").is_none(),
        "the bare numeric `record_type` key must be gone; the analysis grouping treats that key \
         as a category name and a number there reads as a record type called \"1\""
    );
    assert_eq!(
        results[0].metadata["ntfs_record_type"], 1,
        "the NTFS log record-type number is kept, under a name that says what it is"
    );
}

#[test]
fn test_logfile_parser_skip_insignificant() {
    init_logging();
    let source = Arc::new(MockLogFileSource::new(PAGE * 3));
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 3));
    source.write_at(
        PAGE as u64 * 2,
        &create_record_page(&[create_log_record(0x1001, 0x00, 0x00, 0, 0, 0x00, 0)]),
    );

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source.clone()),
        serde_json::json!({
            "name": "$LogFile",
            "file_size": PAGE * 3
        }),
    );

    let parser = LogFileParser;
    let results = parser.process(&artifact).expect("Parser failed");

    assert_eq!(results.len(), 0);
}

#[test]
fn a_torn_record_page_makes_the_parse_report_itself_incomplete() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 4);
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 4));

    // Page 1 of the logging area is intact; page 2 has a broken sector-tail
    // placeholder, so its USA fixup fails and the page is skipped.
    let records = vec![create_log_record(0x1001, 0x05, 0x00, 16, 0, 0x80, 0)];
    source.write_at(PAGE as u64 * 2, &create_record_page(&records));
    let mut torn = create_record_page(&records);
    torn[511] ^= 0xFF;
    source.write_at(PAGE as u64 * 3, &torn);

    let parsed = parse_logfile(&source).expect("Failed to parse $LogFile");
    assert_eq!(parsed.torn_pages, 1);
    assert!(
        !parsed.complete(),
        "a skipped page means the log was not fully read"
    );
    assert_eq!(parsed.incomplete_reasons(), vec!["torn_pages_skipped"]);
}

#[test]
fn a_fully_read_logfile_reports_itself_complete() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 3);
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 3));
    let records = vec![create_log_record(0x1001, 0x05, 0x00, 16, 0, 0x80, 0)];
    source.write_at(PAGE as u64 * 2, &create_record_page(&records));

    let parsed = parse_logfile(&source).expect("Failed to parse $LogFile");
    assert!(parsed.complete());
    assert!(parsed.incomplete_reasons().is_empty());
}

#[test]
fn a_logfile_larger_than_the_evidence_holds_is_not_reported_as_fully_walked() {
    init_logging();
    // The restart area declares a 16-page $LogFile; the source holds 3 pages,
    // as a truncated acquisition or an incomplete extraction leaves it. Ending
    // the walk at the end of the evidence must not read as ending at the end of
    // the log: the renames and deletes on the missing pages are simply unread.
    let source = MockLogFileSource::new(PAGE * 3);
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 16));
    let records = vec![create_log_record(0x1001, 0x05, 0x00, 16, 0, 0x80, 0)];
    source.write_at(PAGE as u64 * 2, &create_record_page(&records));

    let parsed = parse_logfile(&source).expect("a short $LogFile still parses what it has");
    assert!(!parsed.records.is_empty(), "recovered records are kept");
    assert!(parsed.declared_beyond_source);
    assert!(
        !parsed.complete(),
        "the walk stopped at the end of the evidence, not the end of the log"
    );
    assert_eq!(
        parsed.incomplete_reasons(),
        vec!["source_shorter_than_declared_log"]
    );
}

#[test]
fn an_incomplete_logfile_parse_emits_a_status_record_an_examiner_can_see() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 4);
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 4));
    let records = vec![create_log_record(0x1001, 0x05, 0x00, 16, 0, 0x80, 0)];
    source.write_at(PAGE as u64 * 2, &create_record_page(&records));
    let mut torn = create_record_page(&records);
    torn[511] ^= 0xFF;
    source.write_at(PAGE as u64 * 3, &torn);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(Arc::new(source)),
        serde_json::json!({ "name": "$LogFile" }),
    );
    let out = LogFileParser.process(&artifact).expect("process failed");

    let status = out
        .iter()
        .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("LogFileParseStatus"))
        .expect("no incomplete-parse status record emitted");
    assert_eq!(status.metadata["content_incomplete"], true);
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        "torn_pages_skipped"
    );
    assert_eq!(status.metadata["torn_pages"], 1);
}

/// B2-157: a record whose client data spills past the end of its page ends the
/// in-page walk — the LSN chain would be needed to find the next one. Every
/// record recorded AFTER it in the same page is then never emitted. Before
/// this, only the multi-page record itself was marked, and the whole parse
/// still reported itself complete: the dropped operations looked like
/// operations that never happened.
#[test]
fn a_page_abandoned_at_a_multi_page_record_is_reported_as_part_walked() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 3);
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 3));

    // First record declares far more client data than the page can hold; the
    // second sits right behind it and is lost when the walk stops.
    let mut spilling = create_log_record(0x1001, 0x05, 0x00, 16, 0, 0x80, 0);
    put32(&mut spilling, 24, PAGE as u32); // client_data_length: past page end
    let following = create_log_record(0x1002, 0x07, 0x00, 32, 0, 0x10, 0);
    source.write_at(PAGE as u64 * 2, &create_record_page(&[spilling, following]));

    let parsed = parse_logfile(&source).expect("Failed to parse $LogFile");
    assert_eq!(
        parsed.records.len(),
        1,
        "the walk stops at the multi-page record"
    );
    assert!(parsed.records[0].multi_page);
    assert_eq!(
        parsed.pages_part_walked, 1,
        "the abandoned remainder of the page must be counted"
    );
    assert!(
        !parsed.complete(),
        "records dropped from a page mean the log was not fully read"
    );
    assert!(parsed
        .incomplete_reasons()
        .contains(&"page_records_not_fully_walked"));
}

/// The same page walked to its end reports nothing part-walked, so the count
/// keeps its meaning.
#[test]
fn a_page_walked_to_its_end_is_not_reported_as_part_walked() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 3);
    source.write_at(0, &create_restart_page(0x1000, PAGE as u64 * 3));
    let records = vec![
        create_log_record(0x1001, 0x05, 0x00, 16, 0, 0x80, 0),
        create_log_record(0x1002, 0x07, 0x00, 32, 0, 0x10, 0),
    ];
    source.write_at(PAGE as u64 * 2, &create_record_page(&records));

    let parsed = parse_logfile(&source).expect("Failed to parse $LogFile");
    assert_eq!(parsed.records.len(), 2);
    assert_eq!(parsed.pages_part_walked, 0);
    assert!(parsed.complete());
}

/// A file whose bytes ARE an NTFS transaction log ("RSTR" at offset 0) but whose
/// restart area is unusable used to produce nothing at all: the parse error went
/// to a log line and the case got an empty batch. An examiner reading the case
/// then cannot tell "this journal recorded no renames or deletes" from "this
/// journal was never read", and the first of those is a statement about the
/// suspect's conduct.
#[test]
fn a_confirmed_logfile_that_cannot_be_parsed_is_reported_not_passed_over() {
    init_logging();
    // Detection keys off the "RSTR" magic; everything behind it is garbage, so
    // no restart page parses and `parse_logfile` returns Err.
    let source = MockLogFileSource::new(PAGE * 2);
    source.write_at(0, b"RSTR");

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(Arc::new(source)),
        serde_json::json!({ "name": "$LogFile" }),
    );
    let out = LogFileParser.process(&artifact).expect("must not error");

    assert_eq!(out.len(), 1, "the failure is stated exactly once");
    let status = &out[0];
    assert_eq!(status.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(status.parent_id, Some(artifact.id));
    assert_eq!(status.metadata["type"], "LogFileParseStatus");
    assert_eq!(status.metadata["record_type"], "logfile_parse_status");
    assert_eq!(status.metadata["content_incomplete"], true);
    // The shared vocabulary, so the API, the export and the report can all
    // classify it rather than showing the examiner a raw string.
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        IncompleteReason::UnresolvedStructure.as_str()
    );
    // Nothing from this journal is in the case, which is an inventory shortfall
    // as well as a content one; the census and the report's "not recovered"
    // section read the inventory pair.
    assert_eq!(status.metadata["inventory_incomplete"], true);
    assert_eq!(
        status.metadata["inventory_incomplete_reason"],
        IncompleteReason::UnresolvedStructure.as_str()
    );
    // And the sentence lands where the examiner-facing reader shows it.
    for key in ["content_incomplete_detail", "inventory_incomplete_detail"] {
        assert!(
            status.metadata[key]
                .as_str()
                .is_some_and(|s| s.contains("could not be parsed")),
            "`{key}` must carry the sentence explaining the reason code"
        );
    }
    // Counted as zero because zero was walked, never omitted: an absent count
    // would leave a reader guessing between "none" and "unknown".
    for key in [
        "torn_pages",
        "pages_part_walked",
        "pages_scanned",
        "records_parsed",
    ] {
        assert_eq!(status.metadata[key], 0, "`{key}` must be stated");
    }
    assert!(status.metadata["parse_error"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

/// The counterpart: a FileSystem artifact is handed to this module for every
/// NTFS volume in every case, and the volume's own bytes are not a $LogFile. A
/// failed parse there is not a shortfall this module can attest to, and marking
/// one on every volume would drown the disclosures that mean something.
#[test]
fn an_ntfs_volume_that_is_not_a_logfile_is_passed_over_silently() {
    init_logging();
    let source = MockLogFileSource::new(PAGE * 2);
    source.write_at(0, b"NTFS    ");

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(source)),
        serde_json::json!({ "filesystem_type": "NTFS", "volume_name": "C" }),
    );
    let out = LogFileParser.process(&artifact).expect("must not error");
    assert!(
        out.is_empty(),
        "a volume was never established to be a transaction log"
    );
}
