//! The two real `automaticDestinations-ms` files in plaso's test corpus, one
//! written by Windows 7 (DestList format version 1) and one by Windows 10
//! (format version 3). The expected values are the ones plaso's own test
//! suite pins for the same files
//! (`tests/parsers/olecf_plugins/automatic_destinations.py`), so the reading
//! here is checked against an independent implementation, not against itself.
//!
//! `reference/` is not checked in: when the files are absent the tests skip
//! and say so.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::ByteSliceDataSource;
use seance_core::module::ForensicsModule;
use seance_plugin_jumplists::JumpListParser;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

const WIN7_LIST: &str = "1b4dd67f29cb1962.automaticDestinations-ms";
const WIN10_LIST: &str = "9d1f905ce5044aee.automaticDestinations-ms";

fn fixture(name: &str) -> Option<Vec<u8>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("reference/plaso/test_data/automatic_destinations")
        .join(name);
    match std::fs::read(&root) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: fixture absent (reference/ is not checked in): {}",
                root.display()
            );
            None
        }
    }
}

fn run(name: &str, bytes: Vec<u8>) -> (Artifact, Vec<Artifact>) {
    let parent = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ByteSliceDataSource::new(bytes))),
        json!({ "name": name }),
    );
    let out = JumpListParser
        .process(&parent)
        .expect("the parser does not error");
    (parent, out)
}

fn records<'a>(out: &'a [Artifact], record_type: &str) -> Vec<&'a Artifact> {
    out.iter()
        .filter(|a| a.metadata["record_type"] == record_type)
        .collect()
}

fn shortcuts(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect()
}

#[test]
fn a_windows_7_jump_list_yields_every_dest_list_entry_plaso_reads_from_it() {
    let Some(bytes) = fixture(WIN7_LIST) else {
        return;
    };
    let (parent, out) = run(WIN7_LIST, bytes);

    let entries = records(&out, "jumplist_destlist_entry");
    assert_eq!(
        entries.len(),
        11,
        "plaso reads 11 DestList entries from this file"
    );
    for e in &entries {
        assert_eq!(e.parent_id, Some(parent.id));
        assert_eq!(e.metadata["dest_list_format_version"], 1);
        assert_eq!(e.metadata["dest_list_layout"], "windows_7");
    }

    // plaso's pinned entry: the fifth event_data container, which is the
    // first DestList entry in stream order (offset 32).
    let first = entries[0];
    assert_eq!(first.metadata["mru_position"], 0);
    assert_eq!(first.metadata["entry_number"], 11);
    assert_eq!(first.metadata["stream_name"], "b");
    assert_eq!(first.metadata["offset_in_dest_list"], 32);
    assert_eq!(
        first.metadata["path"],
        "C:\\Users\\nfury\\Pictures\\The SHIELD"
    );
    assert_eq!(first.metadata["hostname"], "wks-win764bitb");
    assert_eq!(
        first.metadata["droid_file_identifier"],
        "63eea867-7b85-11e1-8950-005056a50b40"
    );
    assert_eq!(
        first.metadata["droid_volume_identifier"],
        "cf6619c2-66a8-44a6-8849-1582fcd3a338"
    );
    assert_eq!(
        first.metadata["birth_droid_file_identifier"],
        "63eea867-7b85-11e1-8950-005056a50b40"
    );
    assert_eq!(
        first.metadata["birth_droid_volume_identifier"],
        "cf6619c2-66a8-44a6-8849-1582fcd3a338"
    );
    assert_eq!(
        first.metadata["last_recorded_time"],
        "2012-04-01T13:52:38.997538200+00:00"
    );
    assert_eq!(first.metadata["pin_status"], -1);
    assert_eq!(first.metadata["pinned"], false);
    // A version 1 entry has no field at offset 116, and the record says so
    // rather than carrying a number from nowhere.
    assert!(first
        .metadata
        .get("offset_116_unknown_possibly_access_count")
        .is_none());
    assert!(first.metadata["offset_116_unavailable"]
        .as_str()
        .is_some_and(|s| s.contains("version 1")));

    // The stream order is the most-recently-used order: every entry's
    // recorded time is no later than the one before it.
    let times: Vec<&str> = entries
        .iter()
        .map(|e| e.metadata["last_recorded_time"].as_str().expect("a time"))
        .collect();
    for w in times.windows(2) {
        assert!(w[0] >= w[1], "MRU order: {} then {}", w[0], w[1]);
    }
    let positions: Vec<u64> = entries
        .iter()
        .map(|e| e.metadata["mru_position"].as_u64().unwrap())
        .collect();
    assert_eq!(positions, (0..11).collect::<Vec<u64>>());
}

#[test]
fn a_windows_7_jump_list_reads_its_shortcuts_from_the_directory_and_ties_each_to_its_entry() {
    let Some(bytes) = fixture(WIN7_LIST) else {
        return;
    };
    let (parent, out) = run(WIN7_LIST, bytes);

    let lnks = shortcuts(&out);
    assert_eq!(lnks.len(), 11, "streams 1..9, a, b");
    let mut names: Vec<&str> = lnks
        .iter()
        .map(|a| a.metadata["stream_name"].as_str().expect("a stream name"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b"]
    );
    for l in &lnks {
        assert_eq!(l.parent_id, Some(parent.id));
        assert_eq!(l.metadata["type"], "JumpListStream");
        assert_eq!(l.metadata["recovery_method"], "ole_directory");
        assert_eq!(l.metadata["dest_list_correlation"], "matched");
        let stream = l.metadata["stream_name"].as_str().unwrap();
        assert_eq!(
            l.metadata["name"],
            format!("{WIN7_LIST}_stream_{stream}.lnk")
        );
        let data = l
            .data
            .as_ref()
            .expect("the stream bytes travel with the artifact");
        let mut sig = [0u8; 8];
        data.read_at(0, &mut sig).unwrap();
        assert_eq!(
            sig,
            [0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0],
            "each stream is a shortcut"
        );
        assert_eq!(l.metadata["stream_declared_len"], data.size());
        assert_eq!(l.metadata["app_id"], "1b4dd67f29cb1962");
    }
    let b = lnks
        .iter()
        .find(|l| l.metadata["stream_name"] == "b")
        .expect("stream b");
    assert_eq!(b.metadata["dest_list_entry_number"], 11);
    assert_eq!(b.metadata["dest_list_mru_position"], 0);
    assert_eq!(
        b.metadata["dest_list_path"],
        "C:\\Users\\nfury\\Pictures\\The SHIELD"
    );
    assert_eq!(
        b.data.as_ref().unwrap().size(),
        1496,
        "the directory's declared length for stream b"
    );
}

#[test]
fn a_windows_7_explorer_jump_list_is_attributed_to_explorer_by_a_hash_this_build_computes() {
    let Some(bytes) = fixture(WIN7_LIST) else {
        return;
    };
    let (_, out) = run(WIN7_LIST, bytes);
    let summary = records(&out, "jumplist_destlist");
    assert_eq!(summary.len(), 1, "one DestList record per jump list");
    let s = summary[0];
    assert_eq!(s.metadata["app_id"], "1b4dd67f29cb1962");
    assert_eq!(
        s.metadata["application"],
        "Windows Explorer (explorer.exe, Windows 7)"
    );
    assert!(s.metadata["application_basis"]
        .as_str()
        .is_some_and(|b| b.contains("CRC-64") && b.contains("cross-checked")));
    assert_eq!(s.metadata["ole_directory_read"], true);
    assert_eq!(s.metadata["dest_list_present"], true);
    assert_eq!(s.metadata["dest_list_format_version"], 1);
    assert_eq!(s.metadata["entries_declared"], 11);
    assert_eq!(s.metadata["entries_read"], 11);
    assert_eq!(s.metadata["pinned_entries_declared"], 0);
    assert_eq!(s.metadata["last_entry_number"], 11);
    assert_eq!(s.metadata["lnk_streams_in_directory"], 11);
    assert_eq!(s.metadata["lnk_streams_read"], 11);
    assert_eq!(s.metadata["content_incomplete"], false);
    assert!(s.metadata["entries_without_stream"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(s.metadata["streams_without_entry"]
        .as_array()
        .unwrap()
        .is_empty());
    // The DestList record is the last artifact, so a reader taking the head
    // of the listing cannot mistake it for a shortcut.
    assert_eq!(
        out.last().unwrap().metadata["record_type"],
        "jumplist_destlist"
    );
    // Nothing was carved: every shortcut came out of the directory.
    assert!(records(&out, "jumplist_carve_status").is_empty());
}

#[test]
fn a_windows_10_jump_list_is_decoded_with_the_version_3_layout_and_carries_offset_116() {
    let Some(bytes) = fixture(WIN10_LIST) else {
        return;
    };
    let (_, out) = run(WIN10_LIST, bytes);

    let entries = records(&out, "jumplist_destlist_entry");
    assert_eq!(entries.len(), 2);
    let e = entries[0];
    assert_eq!(e.metadata["dest_list_format_version"], 3);
    assert_eq!(e.metadata["dest_list_layout"], "windows_10");
    assert_eq!(e.metadata["entry_number"], 2);
    assert_eq!(e.metadata["stream_name"], "2");
    assert_eq!(e.metadata["mru_position"], 0);
    assert_eq!(
        e.metadata["path"],
        "http://support.microsoft.com/kb/3124263"
    );
    assert_eq!(
        e.metadata["last_recorded_time"],
        "2016-01-17T13:08:08.247504500+00:00"
    );
    // plaso reads this entry's unknown5 as 1; the record carries the value
    // under a name that says the sources do not establish what it is.
    assert!(e.metadata.get("access_count").is_none());
    assert_eq!(e.metadata["offset_116_unknown_possibly_access_count"], 1);
    assert!(e.metadata["offset_116_note"]
        .as_str()
        .is_some_and(|n| n.contains("unknown5") && n.contains("access count?")));
    assert_eq!(e.metadata["pinned"], false);
    // An empty host name is absent, not "".
    assert!(e.metadata.get("hostname").is_none());
    assert_eq!(
        e.metadata["droid_file_identifier"],
        "00000000-0000-0000-0000-000000000000"
    );
    let second = entries[1];
    assert_eq!(second.metadata["entry_number"], 1);
    assert_eq!(second.metadata["mru_position"], 1);
    assert_eq!(
        second.metadata["path"],
        "http://go.microsoft.com/fwlink/?linkid=624682&clcid=0x409&campaign=ct!!31DAEFFBA6804D2599B337798559C7F4"
    );

    let summary = records(&out, "jumplist_destlist")[0];
    assert_eq!(summary.metadata["app_id"], "9d1f905ce5044aee");
    assert_eq!(summary.metadata["application"], "Microsoft Edge (EdgeHTML)");
    assert_eq!(summary.metadata["dest_list_layout"], "windows_10");
    assert_eq!(summary.metadata["last_revision_number"], 4);

    let lnks = shortcuts(&out);
    assert_eq!(lnks.len(), 2);
    assert!(lnks
        .iter()
        .all(|l| l.metadata["recovery_method"] == "ole_directory"));
}

#[test]
fn each_dest_list_entry_puts_its_recorded_time_on_the_timeline() {
    let Some(bytes) = fixture(WIN7_LIST) else {
        return;
    };
    let (_, out) = run(WIN7_LIST, bytes);
    let events: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();
    assert_eq!(events.len(), 11);
    let first = events
        .iter()
        .find(|e| e.metadata["timestamp"] == "2012-04-01T13:52:38.997538200+00:00")
        .expect("the newest entry's time");
    assert_eq!(
        first.metadata["timestamp_desc"],
        "Jump list entry last recorded"
    );
    assert_eq!(
        first.metadata["source_module"],
        "plugin.windows.jumplist_parser"
    );
    assert!(first.metadata["short_desc"]
        .as_str()
        .unwrap()
        .contains("The SHIELD"));
    assert!(first.metadata["description"]
        .as_str()
        .unwrap()
        .contains("Windows Explorer"));
}

#[test]
fn a_jump_list_whose_directory_cannot_be_read_falls_back_to_the_carve_and_says_so() {
    let Some(mut bytes) = fixture(WIN7_LIST) else {
        return;
    };
    // Wreck the sector-allocation table pointers in the header: the
    // signature is intact, so the file is still a jump list by name and by
    // magic, but the directory cannot be followed.
    for b in &mut bytes[0x30..0x4C] {
        *b = 0xFF;
    }
    let (_, out) = run(WIN7_LIST, bytes);

    let lnks = shortcuts(&out);
    assert!(!lnks.is_empty(), "the carve still finds the shortcuts");
    for l in &lnks {
        assert_eq!(l.metadata["type"], "JumpListCarvedShortcut");
        assert_eq!(l.metadata["recovery_method"], "signature_carve");
        assert!(l.metadata["source_offset"].is_u64());
        assert_eq!(l.metadata["dest_list_correlation"], "dest_list_unavailable");
        assert_eq!(l.metadata["app_id"], "1b4dd67f29cb1962");
    }
    let summary = records(&out, "jumplist_destlist");
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].metadata["ole_directory_read"], false);
    // The directory was not read, so the list's presence is not established.
    assert!(summary[0].metadata["dest_list_present"].is_null());
    assert!(summary[0].metadata["dest_list_present_note"].is_string());
    assert_eq!(summary[0].metadata["content_incomplete"], true);
    assert_eq!(
        summary[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(summary[0].metadata["content_incomplete_detail"]
        .as_str()
        .is_some_and(|s| s.contains("directory") && s.contains("carve")));
    assert!(records(&out, "jumplist_destlist_entry").is_empty());
}

#[test]
fn every_stream_the_directory_hands_on_is_a_shortcut_the_lnk_reader_parses() {
    let Some(bytes) = fixture(WIN7_LIST) else {
        return;
    };
    let (_, out) = run(WIN7_LIST, bytes);
    let lnks = shortcuts(&out);
    assert_eq!(lnks.len(), 11);
    for l in lnks {
        let parsed = seance_plugin_lnk::LnkParser
            .process(l)
            .expect("the LNK reader accepts the stream");
        let records: Vec<&Artifact> = parsed
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .collect();
        assert!(
            records
                .iter()
                .any(|r| r.metadata["record_type"] != "lnk_parse_status"),
            "stream {} yields a shortcut record, not a parse-status record: {:?}",
            l.metadata["stream_name"],
            records.iter().map(|r| &r.metadata).collect::<Vec<_>>()
        );
    }
}

/// Real negative known answer for the unreferenced-sector carve: neither of
/// plaso's jump lists holds a shortcut in a free sector or mini-sector (an
/// independent olefile walk of both, 2026-09-26, found the LNK signature count
/// equal to the directory's stream count and no signature in free space).
#[test]
fn plasos_jump_lists_carve_nothing_from_free_sectors() {
    for name in [WIN7_LIST, WIN10_LIST] {
        let Some(bytes) = fixture(name) else {
            return;
        };
        let (_, out) = run(name, bytes);
        let carved: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["recovery_method"] == "unreferenced_sector_carve")
            .collect();
        assert!(carved.is_empty(), "{name}: {carved:#?}");
        let summary = records(&out, "jumplist_destlist");
        assert_eq!(
            summary[0].metadata["shortcuts_carved_from_unreferenced_sectors"], 0,
            "{name}"
        );
        assert!(
            summary[0].metadata["unreferenced_sector_scan"]
                .as_str()
                .unwrap()
                .contains("scanned"),
            "{name}: the scan ran and says what it covered"
        );
    }
}
