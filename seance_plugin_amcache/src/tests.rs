use super::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::TruncatedSource;
use std::path::PathBuf;
use std::sync::Arc;

fn make_artifact_from_path(path: &str, name: &str) -> Artifact {
    let ds = Arc::new(FileDataSource::new(PathBuf::from(path)).unwrap());
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    )
}

#[test]
fn test_amcache_hive_parsing() {
    // This test data file is a live-captured hive with inconsistent sequence numbers.
    // the hive reader may reject it. The parser should handle this gracefully (not panic).
    let path = "test_data/winreg/Amcache.hve";
    if !std::path::Path::new(path).exists() {
        eprintln!("Skipping test: Amcache.hve not found");
        return;
    }
    let artifact = make_artifact_from_path(path, "Amcache.hve");
    let parser = AmcacheParser;
    // Should not panic, even on a corrupted hive
    let results = parser.process(&artifact).unwrap();
    // May or may not produce results depending on hive integrity
    eprintln!("Amcache.hve produced {} artifacts", results.len());
}

#[test]
fn test_win10_amcache_hive() {
    let path = "test_data/winreg/win10-Amcache.hve";
    if !std::path::Path::new(path).exists() {
        let path = "../test_data/winreg/win10-Amcache.hve";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping test: win10-Amcache.hve not found");
            return;
        }
        let artifact = make_artifact_from_path(path, "win10-Amcache.hve");
        let parser = AmcacheParser;
        let results = parser.process(&artifact).unwrap();
        assert!(
            !results.is_empty(),
            "Should produce artifacts from win10-Amcache.hve"
        );
        return;
    }
    let artifact = make_artifact_from_path(path, "win10-Amcache.hve");
    let parser = AmcacheParser;
    let results = parser.process(&artifact).unwrap();
    assert!(
        !results.is_empty(),
        "Should produce artifacts from win10-Amcache.hve"
    );
}

#[test]
fn test_link_date_to_rfc3339() {
    // BUG-100: real hives store LinkDate as "MM/DD/YYYY HH:MM:SS" (UTC). The DB
    // timeline insert requires unix seconds or RFC 3339, so it must be converted.
    let ts = amcache_link_date_to_rfc3339("02/21/2019 17:00:00").unwrap();
    assert!(
        ts.starts_with("2019-02-21T17:00:00"),
        "unexpected RFC3339: {}",
        ts
    );
    // Empty / unparseable values yield None so no timeline event is emitted.
    assert!(amcache_link_date_to_rfc3339("").is_none());
    assert!(amcache_link_date_to_rfc3339("not a date").is_none());
}

#[test]
fn test_decode_amcache_size_qword() {
    // BUG-106: Size is REG_QWORD. A value >= 4 GiB must not be truncated to its
    // low 32 bits.
    let big: u64 = 5_000_000_000; // 5 GB, exceeds u32::MAX
    assert_eq!(decode_amcache_size(&big.to_le_bytes()), Some(big));
    // A rare 4-byte DWORD value still decodes.
    assert_eq!(decode_amcache_size(&1234u32.to_le_bytes()), Some(1234));
    // Too short -> unknown, never a fabricated zero-byte size.
    assert_eq!(decode_amcache_size(&[1, 2]), None);
}

/// Attach an in-memory source without touching the filesystem.
///
/// `ByteSliceDataSource` is the honest source (declared size == bytes held);
/// `TruncatedSource` is the one whose declared size exceeds what it will hand
/// back, which is how the short-read path is reached here.
fn mem_artifact<S: DataSource + 'static>(source: S, name: &str) -> Artifact {
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(source)),
        json!({ "name": name }),
    )
}

#[test]
fn test_non_amcache_hive_skipped() {
    // A registry hive that is NOT amcache should be skipped
    // Create a fake artifact with "SYSTEM" name
    let parser = AmcacheParser;

    // Use a minimal regf header to pass detection but non-amcache name
    let data = {
        let mut buf = vec![0u8; 4096];
        buf[0..4].copy_from_slice(b"regf");
        buf
    };

    let artifact = mem_artifact(ByteSliceDataSource::new(data), "SYSTEM");

    let results = parser.process(&artifact).unwrap();
    assert!(results.is_empty(), "Non-Amcache hive should be skipped");
}

/// A `.bcf` record that fails the length sanity check ends the walk. The prefix
/// that was decoded must not present as the whole recent-file history.
#[test]
fn bcf_mid_stream_stop_is_stamped_incomplete() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 16]); // rest of the 20-byte header

    let path: Vec<u16> = "C:\\evidence\\ran.exe\0".encode_utf16().collect();
    let mut path_bytes = Vec::new();
    for u in &path {
        path_bytes.extend_from_slice(&u.to_le_bytes());
    }
    buf.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&path_bytes);

    // Second record declares a length the file cannot satisfy: the walk stops
    // here and every record after it is unreachable.
    buf.extend_from_slice(&9999u32.to_le_bytes());
    buf.extend_from_slice(&[0x41; 8]);

    let parser = AmcacheParser;
    let artifact = mem_artifact(ByteSliceDataSource::new(buf), "RecentFileCache.bcf");
    let results = parser.process(&artifact).unwrap();

    assert!(!results.is_empty(), "the decoded prefix must be reported");
    let entry = results
        .iter()
        .find(|a| a.metadata["type"] == "AmcacheEntry")
        .expect("the one good record should still be emitted");
    assert_eq!(entry.metadata["content_incomplete"], json!(true));
    assert_eq!(
        entry.metadata["content_incomplete_reason"],
        json!("unresolved_structure"),
    );
    assert_eq!(entry.metadata["walk_record_errors"], json!(1));
}

/// A `.bcf` the source could not hand over in full is a truncated cache, not a
/// machine on which no file was ever opened.
#[test]
fn bcf_short_read_emits_status_record() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 16]);

    let parser = AmcacheParser;
    // Declares 4 KiB, hands back 20 bytes.
    let artifact = mem_artifact(TruncatedSource::new(buf, 4096), "RecentFileCache.bcf");
    let results = parser.process(&artifact).unwrap();

    assert_eq!(results.len(), 1, "a short cache must not return nothing");
    let m = &results[0].metadata;
    assert_eq!(m["record_type"], "amcache_parse_status");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], json!("short_read"));
    assert_eq!(m["inventory_incomplete"], json!(true));
    assert_eq!(m["declared_bytes"], json!(4096));
}

/// A file recognised as an Amcache hive that the hive parser rejects must say so.
/// Returning nothing reads as "this machine ran no programs".
#[test]
fn unparseable_amcache_hive_emits_status_record() {
    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(b"regf");

    let parser = AmcacheParser;
    let artifact = mem_artifact(ByteSliceDataSource::new(buf), "Amcache.hve");
    let results = parser.process(&artifact).unwrap();

    assert_eq!(results.len(), 1, "a rejected hive must not return nothing");
    let m = &results[0].metadata;
    assert_eq!(m["record_type"], "registry_hive_parse_status");
    assert_eq!(m["parse_failed"], json!(true));
    assert_eq!(m["content_incomplete"], json!(true));
    assert!(m["content_incomplete_reason"]
        .as_str()
        .unwrap()
        .contains("unresolved_structure"));
}

/// Two stages can each find the record incomplete; the second must not erase
/// what the first said.
#[test]
fn incomplete_reasons_accumulate() {
    let mut meta = json!({});
    let map = meta.as_object_mut().unwrap();
    add_incomplete_reason(map, "short_read");
    add_incomplete_reason(map, "cap_reached");
    add_incomplete_reason(map, "short_read");
    assert_eq!(map["content_incomplete"], json!(true));
    assert_eq!(
        map["content_incomplete_reason"],
        json!("short_read+cap_reached"),
    );
}

/// The production order in `process`: the hive's recovery state is stamped on
/// every entry first, then the walk tally. A capped walk over a hive that was
/// not loaded in full has two separate limits and an examiner needs both — the
/// entries beyond the cap and the keys beyond the loaded prefix are different
/// missing evidence with different follow-up. Neither stamp may erase the other.
#[test]
fn the_walk_tally_and_the_hive_state_both_reach_the_record() {
    let recovery = hive_state::HiveRecoveryState {
        dirty: false,
        logs_found: Vec::new(),
        bytes_read: 1024,
        declared_bytes: 4096,
    };
    let tally = WalkTally {
        cap_reached: true,
        ..Default::default()
    };

    let mut metadata = json!({ "type": "AmcacheEntry" });
    hive_state::stamp(&mut metadata, &recovery);
    stamp_walk_tally(&mut metadata, &tally);

    let reason = metadata["content_incomplete_reason"].as_str().unwrap();
    assert!(
        reason.split('+').any(|r| r == "hive_not_read_in_full"),
        "the hive's reason must survive the walk tally: {reason}"
    );
    assert!(
        reason.split('+').any(|r| r == "cap_reached"),
        "the walk's reason must be recorded too: {reason}"
    );
    assert_eq!(metadata["content_incomplete"], json!(true));
    assert_eq!(metadata["hive_truncated"], json!(true));
}

/// HUNT-076: DFIR Madness Case 001's timeline opened with `Amcache LinkDate`
/// events dated 2090-11-05, 2077-10-24 and 2049-11-10 — the reproducible-build
/// hash Windows 10+ Microsoft binaries carry in the PE link-time field,
/// rendered as points in time. A LinkDate later than the write of the key that
/// records it is not a time: kept on the record with the reason, off the
/// timeline.
#[test]
fn a_link_date_after_the_keys_own_write_is_not_a_point_in_time() {
    // 2020-09-18T22:00:00Z as a FILETIME.
    let key_written = FILETIME_UNIX_EPOCH + 1_600_466_400 * 10_000_000;
    let note = link_date_after_key_write("2090-11-05T17:44:17+00:00", key_written)
        .expect("a link date seventy years after the key was written is not a time");
    assert!(note.contains("2090-11-05T17:44:17"), "{note}");
    assert!(note.contains("2020-09-18T22:00:00"), "{note}");
    assert!(note.contains("reproducible-build hash"), "{note}");

    // Earlier than the key write: a time, plausibly the link time.
    assert_eq!(
        link_date_after_key_write("2019-02-21T17:00:00+00:00", key_written),
        None
    );
    // Equal to the key write: not later, not refused.
    assert_eq!(
        link_date_after_key_write("2020-09-18T22:00:00+00:00", key_written),
        None
    );
    // A key with no recorded write time cannot refute anything.
    assert_eq!(
        link_date_after_key_write("2090-11-05T17:44:17+00:00", 0),
        None
    );
}

/// The real Windows 10 hive: no LinkDate later than its key's write reaches
/// the timeline, every entry says which way it was judged, and the entries
/// judged implausible carry the reason.
#[test]
fn no_link_date_later_than_its_key_reaches_the_timeline_on_the_real_hive() {
    let path = [
        "test_data/winreg/win10-Amcache.hve",
        "../test_data/winreg/win10-Amcache.hve",
        "../reference/plaso/test_data/winreg/win10-Amcache.hve",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists());
    let Some(path) = path else {
        eprintln!("Skipping test: win10-Amcache.hve not found");
        return;
    };
    let results = AmcacheParser
        .process(&make_artifact_from_path(path, "win10-Amcache.hve"))
        .unwrap();
    let entries: Vec<&Artifact> = results
        .iter()
        .filter(|a| a.metadata["type"] == "AmcacheEntry" && a.metadata["link_date"] != "")
        .collect();
    assert!(!entries.is_empty(), "the hive has LinkDate-bearing entries");
    for e in &entries {
        let m = &e.metadata;
        assert!(
            m.get("link_date_plausible").is_some(),
            "every LinkDate is judged: {m}"
        );
        if m["link_date_plausible"] == false {
            assert!(m["link_date_note"].as_str().unwrap().contains("later than"));
        }
    }
    let implausible = entries
        .iter()
        .filter(|e| e.metadata["link_date_plausible"] == false)
        .count();
    let events = results
        .iter()
        .filter(|a| {
            a.artifact_type == ArtifactType::TimelineEvent
                && a.metadata["timestamp_desc"] == "Amcache LinkDate (PE link time)"
        })
        .count();
    assert_eq!(
        events + implausible,
        entries.len(),
        "each LinkDate is either on the timeline or refused with a reason"
    );
    for a in &results {
        if a.artifact_type == ArtifactType::TimelineEvent {
            let ts = a.metadata["timestamp"].as_str().unwrap();
            let year: i32 = ts[..4].parse().unwrap();
            assert!(
                year <= 2026,
                "a future link date reached the timeline: {ts}"
            );
        }
    }
    eprintln!(
        "win10-Amcache.hve: {} LinkDates, {} refused as later than their key",
        entries.len(),
        implausible
    );
}

/// HUNT-277. A shadow-copy prior version of `Amcache.hve` is opened under its
/// original name (its `name` carries the `[shadow copy ...]` label), everything
/// it yields repeats the snapshot identity, and a `ParsedRecord` that is not a
/// prior version is not read at all. SYNTHETIC: a `regf` header with nothing
/// behind it, so the record read is the parse-status record a rejected hive
/// produces; no real evidence is graded.
#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(b"regf");
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(buf));
    assert!(AmcacheParser
        .subscribes_to()
        .contains(&ArtifactType::ParsedRecord));

    let prior = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source.clone()),
        json!({
            "type": "VssPriorVersion",
            "name": "Amcache.hve [shadow copy 2015-03-23T00:00:00Z]",
            "file_name": "Amcache.hve",
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 0,
        }),
    );
    let out = AmcacheParser.process(&prior).unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].metadata["record_type"], "registry_hive_parse_status");
    assert_eq!(out[0].metadata["is_snapshot_version"], json!(true));
    assert_eq!(out[0].metadata["vss_snapshot_id"], json!("snap-1"));

    let plain = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source.clone()),
        json!({ "type": "SomethingElse", "name": "Amcache.hve" }),
    );
    assert!(AmcacheParser.process(&plain).unwrap().is_empty());

    // The same bytes as a live FileEntry are read, but not stamped.
    let live = AmcacheParser
        .process(&mem_artifact(
            ByteSliceDataSource::new({
                let mut b = vec![0u8; 4096];
                b[0..4].copy_from_slice(b"regf");
                b
            }),
            "Amcache.hve",
        ))
        .unwrap();
    assert_eq!(live.len(), 1);
    assert!(live[0].metadata.get("is_snapshot_version").is_none());
}
