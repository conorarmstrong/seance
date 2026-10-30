use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

const CREATED: u32 = 0x0100_0000;
const FILE_EVENT: u32 = 0x0000_8000;
const FOLDER_EVENT: u32 = 0x0000_0001;

fn dls1_record(path: &str, event_id: u64, flags: u32) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(path.as_bytes());
    r.push(0);
    r.extend_from_slice(&event_id.to_le_bytes());
    r.extend_from_slice(&flags.to_le_bytes());
    r
}

fn dls2_record(path: &str, event_id: u64, flags: u32, node_id: u64) -> Vec<u8> {
    let mut r = dls1_record(path, event_id, flags);
    r.extend_from_slice(&node_id.to_le_bytes());
    r
}

/// Wrap packed records in a page: `magic` + u32 unknown + u32 page_size + body.
fn page(magic: &[u8; 4], records: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = records.iter().flatten().copied().collect();
    let page_size = (12 + body.len()) as u32;
    let mut p = Vec::new();
    p.extend_from_slice(magic);
    p.extend_from_slice(&0u32.to_le_bytes());
    p.extend_from_slice(&page_size.to_le_bytes());
    p.extend_from_slice(&body);
    p
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn run(module: &dyn ForensicsModule, name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    module.process(&art).unwrap()
}

#[test]
fn parses_gzipped_dls1_page() {
    let raw = page(
        b"1SLD",
        &[
            dls1_record("/Users/x/secret.txt", 0xabc, CREATED | FILE_EVENT),
            dls1_record("/Users/x/dir", 0x1234, FOLDER_EVENT | CREATED),
        ],
    );
    let arts = run(&FsEventsParser, "0000000000000abc", gzip(&raw));
    assert_eq!(arts.len(), 2);

    let a = &arts[0].metadata;
    assert_eq!(a["type"], "FSEventsRecord");
    assert_eq!(a["subtype"], "fsevents");
    assert_eq!(a["path"], "/Users/x/secret.txt");
    assert_eq!(a["name"], "secret.txt");
    assert_eq!(a["event_id"].as_u64(), Some(0xabc));
    assert_eq!(a["flags"].as_u64(), Some((CREATED | FILE_EVENT) as u64));
    let names = a["flag_names"].as_array().unwrap();
    assert!(names.iter().any(|v| v.as_str() == Some("Created")));
    assert!(names.iter().any(|v| v.as_str() == Some("FileEvent")));
    // DLS1 has no node_id.
    assert_eq!(a.get("node_id"), None);

    let b = &arts[1].metadata;
    assert_eq!(b["path"], "/Users/x/dir");
    assert_eq!(b["name"], "dir");
    assert_eq!(b["event_id"].as_u64(), Some(0x1234));
}

#[test]
fn parses_raw_uncompressed_dls1() {
    // A buffer that already starts with the DLS magic (not gzipped).
    let raw = page(b"1SLD", &[dls1_record("/a/b", 7, CREATED)]);
    let arts = run(&FsEventsParser, "raw", raw);
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].metadata["path"], "/a/b");
    assert_eq!(arts[0].metadata["event_id"].as_u64(), Some(7));
}

#[test]
fn parses_dls2_with_node_id() {
    let raw = page(
        b"2SLD",
        &[dls2_record("/private/tmp/f", 99, CREATED, 0xdead_beef)],
    );
    let arts = run(&FsEventsParser, "0000000000abcdef", gzip(&raw));
    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    assert_eq!(m["path"], "/private/tmp/f");
    assert_eq!(m["node_id"].as_u64(), Some(0xdead_beef));
    assert_eq!(m["event_id"].as_u64(), Some(99));
}

#[test]
fn non_gzip_non_dls_yields_nothing() {
    let arts = run(
        &FsEventsParser,
        "random.bin",
        b"not a real fsevents file".to_vec(),
    );
    assert!(arts.is_empty());
}

#[test]
fn gzip_of_non_dls_yields_nothing() {
    // Valid gzip, but the decompressed payload is not a DLS page.
    let arts = run(
        &FsEventsParser,
        "0000000000000abc",
        gzip(b"hello world not dls"),
    );
    assert!(arts.is_empty());
}

/// Assert that a walk produced no event record, and said why.
///
/// A chopped page is a log whose remaining events were never read. Emitting
/// nothing at all would present that as a volume on which nothing happened, so
/// the walk owes the examiner a status record instead of silence (B4-016).
fn assert_no_events_but_a_stated_gap(arts: &[Artifact], what: &str) {
    assert!(
        !arts.iter().any(|a| a.metadata["type"] == "FSEventsRecord"),
        "{what}: no event may be decoded from bytes that were never there"
    );
    assert_eq!(arts.len(), 1, "{what}: {arts:?}");
    let m = &arts[0].metadata;
    assert_eq!(m["type"], "FSEventsParseStatus");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
    assert_eq!(m["page_structure_stopped_early"], json!(true));
    assert_eq!(m["record_cap_reached"], json!(false));
    assert_eq!(m["records_emitted"], json!(0));
}

#[test]
fn truncated_record_does_not_panic() {
    // A raw DLS1 page whose final record is chopped mid-fixed-fields.
    let mut raw = page(b"1SLD", &[dls1_record("/a", 1, CREATED)]);
    raw.truncate(raw.len() - 3);
    let arts = run(&FsEventsParser, "raw", raw);
    assert_no_events_but_a_stated_gap(&arts, "record chopped mid-fixed-fields");
}

#[test]
fn record_without_null_terminator_does_not_panic() {
    // Page body is a path with no null terminator before the page ends.
    let mut raw = Vec::new();
    raw.extend_from_slice(b"1SLD");
    raw.extend_from_slice(&0u32.to_le_bytes());
    let body = b"/no/terminator/here";
    raw.extend_from_slice(&((12 + body.len()) as u32).to_le_bytes());
    raw.extend_from_slice(body);
    let arts = run(&FsEventsParser, "raw", raw);
    assert_no_events_but_a_stated_gap(&arts, "path with no terminator");
}

#[test]
fn empty_data_source_yields_nothing() {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "name": "0000000000000abc" }),
    );
    assert!(FsEventsParser.process(&art).unwrap().is_empty());
}

#[test]
fn module_id_stable() {
    assert_eq!(FsEventsParser.id(), "plugin.macos.fsevents");
    assert_eq!(FsEventsParser.version(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn flag_decode_covers_known_bits() {
    let names = flag_names(0xffff_ffff);
    // Every table entry should be present when all bits are set.
    assert_eq!(names.len(), FLAG_TABLE.len());
    assert!(names.contains(&"FolderCreated"));
    assert!(names.contains(&"Mount"));
    // No bits set -> no names.
    assert!(flag_names(0).is_empty());
}

#[test]
fn gzip_truncated_at_the_cap_is_reported_not_silently_short() {
    // BUG-268: `take(cap)` ends cleanly at the limit, so an over-cap log used to
    // parse as a complete (short) history. The decode must say it was cut.
    let raw = page(
        b"1SLD",
        &[
            dls1_record("/a/one", 1, CREATED),
            dls1_record("/a/two", 2, CREATED),
        ],
    );
    let compressed = gzip(&raw);

    // Cap below the real decompressed length: truncated, and reported as such.
    let cap = (raw.len() - 4) as u64;
    let (out, truncated) = decompress_capped(&compressed, cap).expect("DLS magic present");
    assert!(truncated, "an over-cap stream must report truncation");
    assert_eq!(out.len() as u64, cap, "output is clamped to the cap");

    // A cap at or above the real length is NOT truncation.
    let (whole, truncated) =
        decompress_capped(&compressed, raw.len() as u64).expect("DLS magic present");
    assert!(!truncated, "a stream that fits is complete, not truncated");
    assert_eq!(whole, raw);
}

#[test]
fn record_cap_is_reported_as_incomplete() {
    // Two records, cap of one: the walk stopped early and must say so.
    let raw = page(
        b"1SLD",
        &[
            dls1_record("/a/one", 1, CREATED),
            dls1_record("/a/two", 2, CREATED),
        ],
    );
    let (records, walk) = parse_dls_capped(&raw, Uuid::new_v4(), Uuid::new_v4(), 1);
    assert_eq!(records.len(), 1);
    assert!(
        walk.capped,
        "hitting the record cap must be visible to the caller"
    );

    let (all, walk) = parse_dls_capped(&raw, Uuid::new_v4(), Uuid::new_v4(), 100);
    assert_eq!(all.len(), 2);
    assert!(!walk.capped);
    assert!(!walk.structure_stopped, "a whole log stops at its own end");
}

use seance_core::test_support::TruncatedSource;

/// B3-021: the marker's standard reason was hard-coded to `cap_reached`, so a
/// log cut short by the evidence source itself was reported as a parser cap.
/// What an examiner learns: raising the cap will not recover these events —
/// the image does not hold them.
#[test]
fn a_source_that_delivers_less_than_it_declares_reports_short_read() {
    let raw = page(b"1SLD", &[dls1_record("/a/b", 7, CREATED)]);
    let declared = raw.len() as u64 + 4096;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(raw, declared));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "0000000000000abc" }),
    );
    let arts = FsEventsParser.process(&art).unwrap();

    let marker = arts
        .iter()
        .find(|a| a.metadata["type"] == "FSEventsParseStatus")
        .expect("a short source must be reported");
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(
        marker.metadata["content_incomplete_reason"],
        json!("short_read"),
        "a shortfall below the byte cap is the source failing, not a parser cap"
    );
    assert_eq!(marker.metadata["compressed_input_truncated"], json!(true));
    assert_eq!(marker.metadata["record_cap_reached"], json!(false));
}

/// B3-021 control: a genuine parser cap still reports `cap_reached`.
#[test]
fn a_record_cap_still_reports_cap_reached() {
    let raw = page(b"1SLD", &[dls1_record("/a/b", 7, CREATED)]);
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(raw));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "0000000000000abc" }),
    );
    // Reach the marker builder directly: the production cap is 500_000 records.
    // `capped` is the assertion under test: the record cap stopped the walk, so
    // the reason must be `cap_reached` and not a structural stop, which would
    // send an examiner to recover the file rather than raise the limit.
    let marker = incomplete_marker(
        &art,
        1,
        false,
        false,
        DlsWalk {
            capped: true,
            structure_stopped: false,
        },
        false,
    );
    assert_eq!(
        marker.metadata["content_incomplete_reason"],
        json!("cap_reached")
    );
}

#[test]
fn a_fully_parsed_log_emits_no_incomplete_marker() {
    let raw = page(b"1SLD", &[dls1_record("/a/b", 7, CREATED)]);
    let arts = run(&FsEventsParser, "raw", raw);
    assert_eq!(arts.len(), 1);
    assert!(arts
        .iter()
        .all(|a| a.metadata["type"] != "FSEventsParseStatus"));
}

/// B4-016: a log whose page stream ends on garbage after valid pages used to
/// return the decoded prefix with no marker, so a damaged FSEvents log read as
/// the machine's whole file-activity history.
#[test]
fn a_page_stream_that_stops_on_garbage_is_reported() {
    let mut raw = page(
        b"1SLD",
        &[
            dls1_record("/a/one", 1, CREATED),
            dls1_record("/a/two", 2, CREATED),
        ],
    );
    // Where the next page header belongs: not padding, not a DLS magic.
    raw.extend_from_slice(&[0x5A; 32]);

    let (records, walk) = parse_dls_capped(&raw, Uuid::new_v4(), Uuid::new_v4(), 100);
    assert_eq!(records.len(), 2, "the readable pages still parse");
    assert!(
        walk.structure_stopped,
        "a stream that ends on non-padding bytes left events unread"
    );
    assert!(!walk.capped, "no cap was involved");

    let arts = run(&FsEventsParser, "0000000000000abc", gzip(&raw));
    let marker = arts
        .iter()
        .find(|a| a.metadata["type"] == "FSEventsParseStatus")
        .expect("a structural stop must produce a status record");
    assert_eq!(marker.metadata["content_incomplete"], true);
    assert_eq!(
        marker.metadata["content_incomplete_reason"], "unresolved_structure",
        "a damaged log is not a cap: the follow-up differs"
    );
    assert_eq!(marker.metadata["page_structure_stopped_early"], true);
}

/// The counterpart: zero padding after the last page is the normal end of a
/// log, and must not raise a false incompleteness.
#[test]
fn zero_padding_after_the_last_page_is_not_a_stop() {
    let mut raw = page(b"1SLD", &[dls1_record("/a/one", 1, CREATED)]);
    raw.extend_from_slice(&[0u8; 64]);

    let arts = run(&FsEventsParser, "0000000000000abc", gzip(&raw));
    assert!(
        arts.iter()
            .all(|a| a.metadata["type"] != "FSEventsParseStatus"),
        "padding is not a truncated log"
    );
}

/// **A gzip stream cut short must not read as "not an FSEvents log".**
///
/// `read_capped` stops at `MAX_COMPRESSED`, and any source can short-read, so a
/// real macOS event history can arrive with its last gzip member incomplete.
/// `read_to_end` then errors — and the pages it had already decoded were being
/// thrown away with it, so `decompress` answered `None` and the whole log
/// vanished from the case with nothing recorded. An examiner saw a Mac with no
/// filesystem event history.
///
/// What decoded must survive, and must say it is partial.
#[test]
fn a_truncated_gzip_stream_yields_its_decoded_pages_marked_incomplete() {
    // Many records, so the cut lands after some have decoded. One record in a
    // small stream is compressed into so few bytes that any cut loses it, which
    // would test only that the log is not dropped — true, and weaker than what
    // this needs to show.
    let records: Vec<Vec<u8>> = (0..400)
        .map(|i| dls1_record(&format!("/recovered/before/the/cut/{i}"), 40 + i, CREATED))
        .collect();
    let raw = page(b"1SLD", &records);
    let whole = gzip(&raw);
    // Cut the tail off: the deflate stream now ends mid-member, which is
    // exactly what an over-cap or short-read input looks like.
    let cut = whole.len() * 3 / 4;
    let truncated = whole[..cut].to_vec();

    let arts = run(&FsEventsParser, "0000000000000abc", truncated);

    assert!(
        !arts.is_empty(),
        "a truncated FSEvents log produced nothing at all, which reads as a Mac with no \
         filesystem event history"
    );
    assert!(
        arts.iter().any(|a| {
            a.metadata["path"]
                .as_str()
                .is_some_and(|p| p.starts_with("/recovered/before/the/cut/"))
        }),
        "the events that decoded before the cut must reach the examiner; only a status \
         record came back: {:?}",
        arts.iter()
            .map(|a| a.metadata["name"].clone())
            .collect::<Vec<_>>()
    );
    assert!(
        arts.iter().any(|a| {
            a.metadata["decompressed_output_truncated"] == serde_json::json!(true)
                || a.metadata["content_incomplete"] == serde_json::json!(true)
        }),
        "the recovery must be marked partial, or it reads as the whole history"
    );
}
