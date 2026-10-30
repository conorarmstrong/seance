use super::*;
use seance_core::data_source::DataSource;
use seance_core::test_support::TruncatedSource;
use std::sync::Arc;
use uuid::Uuid;

/// Mock data source for testing
#[derive(Debug)]
struct MockDataSource {
    data: Vec<u8>,
}

impl MockDataSource {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for MockDataSource {
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

#[test]
fn test_prefetch_parser_module_metadata() {
    let parser = PrefetchParser;

    assert_eq!(parser.id(), "plugin.windows.prefetch_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));
    assert!(subscriptions.contains(&ArtifactType::SystemArtifact));

    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_prefetch_parser_requires_data_source() {
    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None, // No data source
        json!({"name": "TEST.EXE-12345678.pf"}),
    );

    // With no data source, module returns Ok(empty) instead of Err (expected for carved files)
    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_prefetch_parser_skips_non_prefetch_file() {
    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();

    // Random data that isn't a prefetch file
    let data = vec![0u8; 100];
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "random_file.bin"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0); // Should skip non-prefetch files
}

#[test]
fn test_prefetch_parser_handles_truncated_header() {
    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();

    // Valid MAM signature but truncated - MAM\x04 is the Win8+ prefetch magic
    let mut data = vec![0u8; 10];
    data[0] = b'M';
    data[1] = b'A';
    data[2] = b'M';
    data[3] = 0x04;

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "TRUNCATED.EXE-12345678.pf"}),
    );

    // Should either skip (not detected as prefetch) or return empty (failed parse)
    let result = parser.process(&artifact);
    assert!(result.is_ok());
}

#[test]
fn test_prefetch_parser_handles_corrupted_data() {
    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();

    // MAM\x04 header but corrupted content
    let mut data = vec![0xFFu8; 1000];
    data[0] = b'M';
    data[1] = b'A';
    data[2] = b'M';
    data[3] = 0x04;

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "CORRUPTED.EXE-ABCDEF01.pf"}),
    );

    // Should handle gracefully
    let result = parser.process(&artifact);
    assert!(result.is_ok());
}

#[test]
fn test_prefetch_parser_empty_data() {
    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();

    let data = Vec::new();
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "EMPTY.EXE-00000000.pf"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0); // Empty file shouldn't be detected as prefetch
}

#[test]
fn test_prefetch_parser_rejects_oversized_metric_count() {
    // Regression: a prefetch file declaring a metric count near u32::MAX once
    // drove an unbounded Vec::with_capacity(n) to hundreds of GB (OOM). The
    // native parser validates the count against the file length and returns an
    // error. Completing here (no OOM) is the assertion; the file is still
    // reported, as a parse-status record rather than silence (B2-165).
    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();

    let mut data = vec![0u8; 0x100];
    data[0..4].copy_from_slice(&17u32.to_le_bytes()); // version 0x11 (Win XP)
    data[4..8].copy_from_slice(b"SCCA"); // signature (so it is detected as prefetch)
                                         // metric-section offset @ 0x54, metric count @ 0x58.
    data[0x54..0x58].copy_from_slice(&0x60u32.to_le_bytes());
    data[0x58..0x5c].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::SystemArtifact,
        Some(data_source),
        json!({"name": "OOM.EXE-DEADBEEF.pf"}),
    );

    let produced = parser.process(&artifact).expect("must not error");
    assert_eq!(
        produced.len(),
        1,
        "the unreadable file must still be reported"
    );
    assert_eq!(produced[0].metadata["type"], "PrefetchParseStatus");
    assert_eq!(produced[0].metadata["content_incomplete"], json!(true));
    assert_eq!(produced[0].metadata["failure"], "parse_failed");
    assert_eq!(
        produced[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

#[test]
fn test_prefetch_parser_rejects_oversized_input() {
    // A prefetch-signatured buffer larger than the input cap is refused before
    // being read into the parser -- and the refusal is recorded, so the file is
    // not silently absent from the case (B2-165).
    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();

    let mut data = vec![0u8; super::MAX_PREFETCH_SIZE + 1];
    data[0..4].copy_from_slice(&17u32.to_le_bytes());
    data[4..8].copy_from_slice(b"SCCA");

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::SystemArtifact,
        Some(data_source),
        json!({"name": "HUGE.EXE-DEADBEEF.pf"}),
    );

    let produced = parser.process(&artifact).expect("must not error");
    assert_eq!(produced.len(), 1, "the unread file must still be reported");
    assert_eq!(produced[0].metadata["type"], "PrefetchParseStatus");
    assert_eq!(produced[0].metadata["failure"], "size_cap_exceeded");
    assert_eq!(
        produced[0].metadata["content_incomplete_reason"],
        "cap_reached"
    );
    assert!(
        produced[0].metadata["name"]
            .as_str()
            .unwrap()
            .contains("HUGE.EXE"),
        "the status record must name the file it stands for"
    );
}

// ---------------------------------------------------------------------------
// Native parser tests (replacing the removed third-party crate)
// ---------------------------------------------------------------------------

fn put_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

/// Write `s` as UTF-16LE (ASCII assumed) at `off`.
fn put_utf16(buf: &mut [u8], off: usize, s: &str) {
    let mut i = off;
    for c in s.chars() {
        buf[i] = c as u8;
        buf[i + 1] = 0;
        i += 2;
    }
}

/// Build a well-formed Windows Vista/7 (v23) SCCA file with one metric and one
/// volume so every section is exercised.
fn build_v23_file() -> Vec<u8> {
    let mut data = vec![0u8; 0x200];
    put_u32(&mut data, 0x0, 23); // version
    data[0x4..0x8].copy_from_slice(b"SCCA"); // signature
    put_utf16(&mut data, 0x10, "NOTEPAD.EXE"); // executable name

    // File information section.
    put_u32(&mut data, 0x54, 0x100); // metrics array offset
    put_u32(&mut data, 0x58, 1); // metrics count
    put_u32(&mut data, 0x64, 0x140); // filename strings offset
    put_u32(&mut data, 0x68, 0x20); // filename strings size
    put_u32(&mut data, 0x6c, 0x160); // volumes info offset
    put_u32(&mut data, 0x70, 1); // volumes count
    put_u64(&mut data, 0x80, 0x01D5_A1B2_C3D4_E5F6); // last run FILETIME
    put_u32(&mut data, 0x98, 7); // run count

    // Metric entry (32 bytes) at 0x100. Filename offset/length fields for v23
    // live at entry+0xc and entry+0x10.
    put_u32(&mut data, 0x100 + 0xc, 0); // filename offset within name section
    put_u32(&mut data, 0x100 + 0x10, 12); // filename length in chars

    // Filename strings section at 0x140.
    put_utf16(&mut data, 0x140, "KERNEL32.DLL");

    // Volume entry (104 bytes for v23) at 0x160.
    put_u32(&mut data, 0x160, 0x20); // device path offset (rel. to section)
    put_u32(&mut data, 0x160 + 0x4, 23); // device path chars
    put_u64(&mut data, 0x160 + 0x8, 0x0111_2233_4455_6677); // creation time
    put_u32(&mut data, 0x160 + 0x10, 0xDEAD_BEEF); // serial number
    put_utf16(&mut data, 0x160 + 0x20, "\\DEVICE\\HARDDISKVOLUME1");

    data
}

#[test]
fn test_native_parser_v23_header_extracts_name_and_run_count() {
    let data = build_v23_file();

    // Direct parser check.
    let pf = super::parse_prefetch(&data).expect("valid v23 file should parse");
    assert_eq!(pf.executable_name, "NOTEPAD.EXE");
    assert_eq!(pf.run_count, 7);
    assert_eq!(pf.last_execution_time, 0x01D5_A1B2_C3D4_E5F6);
    assert_eq!(pf.version_label, "WindowsVista7");
    assert_eq!(pf.loaded_files, vec!["KERNEL32.DLL".to_string()]);
    assert_eq!(pf.volumes.len(), 1);
    assert_eq!(pf.volumes[0].device_path, "\\DEVICE\\HARDDISKVOLUME1");
    assert_eq!(pf.volumes[0].serial_number, 0xDEAD_BEEF);
    assert_eq!(pf.volumes[0].creation_time, 0x0111_2233_4455_6677);

    // End-to-end through the module: detection + artifact shape.
    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "NOTEPAD.EXE-12345678.pf"}),
    );

    let artifacts = parser.process(&artifact).expect("process should succeed");
    // One ParsedRecord plus one TimelineEvent for the single last-run time.
    let parsed: Vec<_> = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    assert_eq!(parsed.len(), 1);
    let md = &parsed[0].metadata;
    assert_eq!(md["type"], "PrefetchEntry");
    assert_eq!(md["executable_name"], "NOTEPAD.EXE");
    assert_eq!(md["run_count"], 7);
    assert_eq!(md["version"], "WindowsVista7");
    assert_eq!(md["loaded_files_count"], 1);
    assert_eq!(md["loaded_files"][0], "KERNEL32.DLL");
    assert_eq!(md["short_desc"], "NOTEPAD.EXE (executed 7 times)");
}

/// Build a minimal but well-formed Windows 10 (v30) file with zero metrics and
/// zero volumes, and the supplied last-run FILETIMEs written into the 8-slot
/// array at 0x80.
fn build_v30_file_with_runtimes(times: &[u64]) -> Vec<u8> {
    let mut data = vec![0u8; 0x200];
    put_u32(&mut data, 0x0, 30); // version
    data[0x4..0x8].copy_from_slice(b"SCCA");
    put_utf16(&mut data, 0x10, "CHROME.EXE");

    // Empty metrics/name/volume sections (counts zero -> trivially valid).
    put_u32(&mut data, 0x54, 0x100); // metrics offset
    put_u32(&mut data, 0x58, 0); // metrics count
    put_u32(&mut data, 0x64, 0x100); // name section offset
    put_u32(&mut data, 0x68, 0); // name section size
    put_u32(&mut data, 0x6c, 0x100); // volumes offset
    put_u32(&mut data, 0x70, 0); // volumes count

    // Up to 8 last-run FILETIMEs at 0x80.
    for (i, &t) in times.iter().enumerate().take(8) {
        put_u64(&mut data, 0x80 + i * 8, t);
    }
    put_u32(&mut data, 0xd0, times.len() as u32); // run count
    data
}

#[test]
fn test_v23_module_emits_single_timeline_event() {
    let data = build_v23_file();
    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "NOTEPAD.EXE-12345678.pf"}),
    );

    let artifacts = parser.process(&artifact).expect("process should succeed");
    let events: Vec<_> = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();
    assert_eq!(events.len(), 1, "v23 exposes one last-run time");

    let ev = events[0];
    assert_eq!(
        ev.metadata["source_module"],
        "plugin.windows.prefetch_parser"
    );
    let expected = seance_core::time::filetime_to_unix_secs(0x01D5_A1B2_C3D4_E5F6).unwrap();
    assert_eq!(ev.metadata["timestamp"].as_i64().unwrap(), expected);
    let short = ev.metadata["short_desc"].as_str().unwrap();
    assert!(!short.is_empty());
    assert!(short.contains("NOTEPAD.EXE"));
}

#[test]
fn test_v30_parser_collects_multiple_run_times() {
    // Three non-zero run times plus two zero (unused) slots.
    let t1 = 0x01D5_A1B2_C3D4_E5F6;
    let t2 = 0x01D5_A1B2_0000_0000;
    let t3 = 0x01D4_0000_0000_0000;
    let data = build_v30_file_with_runtimes(&[t1, t2, t3, 0, 0]);

    let pf = super::parse_prefetch(&data).expect("valid v30 file should parse");
    assert_eq!(pf.run_times, vec![t1, t2, t3]);
    assert_eq!(pf.last_execution_time, t1);

    // End-to-end: three non-zero times -> three timeline events.
    let parser = PrefetchParser;
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "CHROME.EXE-ABCDEF01.pf"}),
    );
    let artifacts = parser.process(&artifact).expect("process should succeed");
    let events: Vec<_> = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();
    assert_eq!(events.len(), 3);
    assert!(events
        .iter()
        .all(|e| e.metadata["source_module"] == "plugin.windows.prefetch_parser"));
}

#[test]
fn test_v30_run_count_1607_layout_at_0xc8() {
    // Regression (BUG-056): Windows 10 build 1607+ places RunCount at 0xC8, not
    // 0xD0, under the same version number. Build a v30 file whose 0xD0 field is
    // an unrelated zero and whose real count lives at 0xC8; the parser must
    // recover the 0xC8 value instead of reporting 0.
    let t1 = 0x01D5_A1B2_C3D4_E5F6;
    let mut data = build_v30_file_with_runtimes(&[t1]);
    put_u32(&mut data, 0xd0, 0); // canonical offset holds an unrelated field
    put_u32(&mut data, 0xc8, 9); // real 1607+ run count

    let pf = super::parse_prefetch(&data).expect("valid v30 file should parse");
    assert_eq!(
        pf.run_count, 9,
        "must read RunCount from the 0xC8 (1607+) layout"
    );
}

#[test]
fn test_v30_run_count_canonical_0xd0_still_wins() {
    // The classic v30 layout (valid count at 0xD0) must keep using 0xD0 even
    // when the 0xC8 alternate holds noise -- the heuristic never worsens a
    // correctly laid-out file.
    let t1 = 0x01D5_A1B2_C3D4_E5F6;
    let mut data = build_v30_file_with_runtimes(&[t1]);
    put_u32(&mut data, 0xd0, 4); // valid canonical count
    put_u32(&mut data, 0xc8, 0xDEAD); // noise at the alternate offset

    let pf = super::parse_prefetch(&data).expect("valid v30 file should parse");
    assert_eq!(
        pf.run_count, 4,
        "canonical 0xD0 count must win when plausible"
    );
}

#[test]
fn test_parsed_record_converts_filetimes_to_rfc3339() {
    // Regression (BUG-057): last_execution_time and volume creation_time must be
    // emitted as converted timestamps, not raw Windows FILETIME integers that
    // downstream would misread as Unix seconds.
    let mut data = build_v23_file();
    // Give the volume a valid (post-1970) creation FILETIME so it converts.
    let vol_ct = 0x01D5_A1B2_0000_0000u64;
    put_u64(&mut data, 0x160 + 0x8, vol_ct);

    let parser = PrefetchParser;
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "NOTEPAD.EXE-12345678.pf"}),
    );
    let artifacts = parser.process(&artifact).expect("process should succeed");
    let parsed = artifacts
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .unwrap();

    // last_execution_time is an RFC 3339 string, never a bare FILETIME integer.
    let let_str = parsed.metadata["last_execution_time"].as_str().unwrap();
    let expected = seance_core::time::filetime_to_rfc3339(0x01D5_A1B2_C3D4_E5F6).unwrap();
    assert_eq!(let_str, expected);
    assert!(parsed.metadata["last_execution_time"].as_u64().is_none());

    // Volume creation_time is likewise converted.
    let vol_str = parsed.metadata["volumes"][0]["creation_time"]
        .as_str()
        .unwrap();
    assert_eq!(
        vol_str,
        seance_core::time::filetime_to_rfc3339(vol_ct).unwrap()
    );
    assert!(parsed.metadata["volumes"][0]["creation_time"]
        .as_u64()
        .is_none());
}

#[test]
fn test_native_parser_rejects_absurd_metric_count() {
    // A metric count near u32::MAX must be refused (Err) without allocating,
    // not drive an unbounded Vec::with_capacity.
    let mut data = build_v23_file();
    put_u32(&mut data, 0x58, 0xFFFF_FFFF);
    assert!(super::parse_prefetch(&data).is_err());
}

#[test]
fn test_native_parser_rejects_absurd_volume_count() {
    let mut data = build_v23_file();
    put_u32(&mut data, 0x70, 0xFFFF_FFFF);
    assert!(super::parse_prefetch(&data).is_err());
}

#[test]
fn test_native_parser_truncated_file_does_not_panic() {
    // A valid header whose declared sections/fields run past a truncated file
    // must return Err, never panic. Try every truncation length.
    let full = build_v23_file();
    for len in 0..full.len() {
        let slice = &full[..len];
        let _ = super::parse_prefetch(slice); // must not panic
    }
    // Truncated right after the version+signature is still safe.
    assert!(super::parse_prefetch(&full[..8]).is_err());
}

#[test]
fn test_native_parser_unknown_version_is_error() {
    let mut data = build_v23_file();
    put_u32(&mut data, 0x0, 99); // not a known prefetch version
    assert!(super::parse_prefetch(&data).is_err());
}

#[test]
fn test_native_parser_mam_garbage_does_not_panic() {
    // A MAM\x04 wrapper with a sane declared size but garbage compressed body
    // must return Err (decompression failure), never panic or OOM.
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&[b'M', b'A', b'M', 0x04]);
    put_u32(&mut data, 4, 4096); // plausible uncompressed size
                                 // bytes 8.. are zero: an empty/garbage Huffman table.
    let _ = super::parse_prefetch(&data); // must not panic

    // An absurd declared uncompressed size is refused before decompressing.
    put_u32(&mut data, 4, 0xFFFF_FFFF);
    assert!(super::parse_prefetch(&data).is_err());
}

// Integration test with real prefetch file
#[test]
fn test_parse_real_prefetch_file() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("../test_data/sample.pf");
    if !test_file.exists() {
        eprintln!("Skipping integration test: sample.pf not found");
        return;
    }

    let parser = PrefetchParser;
    let case_id = Uuid::new_v4();

    let data = fs::read(test_file).expect("Failed to read sample.pf");
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "sample.pf"}),
    );

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Failed to parse sample.pf: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    assert!(
        !artifacts.is_empty(),
        "No artifacts produced from sample.pf"
    );

    // Verify the artifact structure
    let pf_artifact = &artifacts[0];
    assert_eq!(pf_artifact.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(pf_artifact.metadata["type"], "PrefetchEntry");
    assert!(pf_artifact.metadata.get("executable_name").is_some());
    assert!(pf_artifact.metadata.get("run_count").is_some());
}

/// A Windows 10 file cut short inside its eight-slot last-run array must fail
/// closed and be reported, never yield a short but complete-looking execution
/// history.
///
/// What an examiner learns: how many times, and when, a program ran. A wrong
/// answer here is a PrefetchEntry naming two executions for a program that ran
/// eight, presented with no sign that six slots were never read. The run counter
/// sits past the array in every supported layout, so a buffer too short for a
/// slot is also too short for the counter and the whole parse is rejected
/// (B2-166); the module then records the file as unparsed (B2-165).
#[test]
fn test_v30_truncated_run_time_array_fails_closed_and_is_reported() {
    // Full file, then cut inside the last-run array (slots run 0x80..0xc0).
    let mut data = build_v30_file_with_runtimes(&[
        0x01D5_0000_0000_0001,
        0x01D5_0000_0000_0002,
        0x01D5_0000_0000_0003,
    ]);
    data.truncate(0x94);

    assert!(
        super::parse_prefetch(&data).is_err(),
        "a file truncated inside the last-run array must not parse as complete"
    );

    let parser = PrefetchParser;
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "CHOPPED.EXE-11112222.pf"}),
    );

    let produced = parser.process(&artifact).expect("must not error");
    assert_eq!(produced.len(), 1);
    assert_eq!(produced[0].metadata["type"], "PrefetchParseStatus");
    assert_eq!(produced[0].metadata["content_incomplete"], json!(true));
    assert!(
        produced
            .iter()
            .all(|a| a.metadata["type"] != "PrefetchEntry"),
        "no execution record may be published from a file that did not parse"
    );
}

/// B6-016: a `.pf` the source could not deliver in full still parses (the SCCA
/// header is at the front), and used to publish its run count and loaded-file
/// list as if they were the whole record.
#[test]
fn test_short_read_prefetch_record_is_stamped_incomplete() {
    // Hands back fewer bytes than it declares, so the short-read path can be
    // reached without a real damaged image.
    let data = build_v23_file();
    let declared = data.len() as u64 + 4096;
    let source: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(data, declared));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        json!({"name": "NOTEPAD.EXE-11112222.pf"}),
    );

    let produced = PrefetchParser.process(&artifact).expect("must not error");
    let entry = produced
        .iter()
        .find(|a| a.metadata["type"] == "PrefetchEntry")
        .expect("the readable prefix still parses");
    assert_eq!(entry.metadata["content_incomplete"], json!(true));
    assert_eq!(
        entry.metadata["content_incomplete_reason"],
        json!("short_read")
    );
    assert_eq!(entry.metadata["inventory_incomplete"], json!(true));
    assert_eq!(entry.metadata["declared_size"], json!(declared));
    // The timeline events built from the same buffer carry it too.
    for a in produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
    {
        assert_eq!(a.metadata["content_incomplete"], json!(true));
    }
}

/// B6-034: the read cap is a UTF-16 code-unit count, not a byte count. Capping
/// it with the section's byte length truncated names whenever the section was
/// shorter than the declared unit count.
#[test]
fn test_read_utf16_string_cap_is_in_code_units() {
    // 8 code units, 16 bytes, no NUL terminator.
    let mut section = Vec::new();
    for ch in "ABCDEFGH".encode_utf16() {
        section.extend_from_slice(&ch.to_le_bytes());
    }
    // A declared length of 8 units fits exactly: all 8 characters must decode.
    assert_eq!(super::parser::read_utf16_string(&section, 0, 8), "ABCDEFGH");
    // Reading from a byte offset leaves fewer units available; never past the end.
    assert_eq!(super::parser::read_utf16_string(&section, 8, 8), "EFGH");
}

/// HUNT-277: a prefetch file inside a shadow copy is parsed and what it yields says
/// so; a `ParsedRecord` that is not a prior version is not read.
#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    let src: Arc<dyn DataSource> = Arc::new(MockDataSource::new(build_v23_file()));
    let prior = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src.clone()),
        serde_json::json!({
            "type": "VssPriorVersion",
            "name": "A.EXE-12345678.pf [shadow copy]",
            "is_snapshot_version": true,
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
        }),
    );
    let out = PrefetchParser.process(&prior).unwrap();
    assert!(!out.is_empty(), "the prior version is parsed");
    assert!(out
        .iter()
        .all(|a| a.metadata["vss_snapshot_id"] == serde_json::json!("snap-1")));

    let other = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src),
        serde_json::json!({ "type": "SomethingElse" }),
    );
    assert!(PrefetchParser.process(&other).unwrap().is_empty());
}
