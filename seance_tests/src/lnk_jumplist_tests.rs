/// Integration tests for LNK Parser and Jump Lists with Timeline Integration
///
/// Tests the LnkParser module with timeline event generation and validates
/// Jump List parsing with automatic/custom destinations files.
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_jumplists::JumpListParser;
use seance_plugin_lnk::LnkParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper function to create a FileEntry artifact from a path.
///
/// Returns `None` (with a skip message naming both places looked) when the
/// fixture is absent from `test_data/` and from the plaso corpus, e.g. on a
/// fresh checkout or CI where neither gitignored corpus is present.
fn create_file_artifact(path: &str, case_id: Uuid) -> Option<Artifact> {
    let file_path = crate::fixtures::resolve(path)?;

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let data_source = Arc::new(
        FileDataSource::new(file_path.clone())
            .unwrap_or_else(|e| panic!("Failed to open {}: {}", file_path.display(), e)),
    );

    let metadata = json!({
        "name": file_name,
        "path": path,
        "size": data_source.size(),
        "artifact_source": "test"
    });

    Some(Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        metadata,
    ))
}

/// The record types a jump list reading can produce, partitioned.
struct JumpListOutput<'a> {
    /// The shortcuts, however they were found.
    shortcuts: Vec<&'a Artifact>,
    /// One `jumplist_destlist_entry` per DestList entry decoded.
    entries: Vec<&'a Artifact>,
    /// The `jumplist_destlist` summary: at most one per jump list.
    summaries: Vec<&'a Artifact>,
    /// The `JumpListCarveStatus` record: at most one, and only on a scan.
    carve_status: Vec<&'a Artifact>,
    /// One per DestList entry that carries a recorded time.
    events: Vec<&'a Artifact>,
}

fn partition_jumplist_output(artifacts: &[Artifact]) -> JumpListOutput<'_> {
    let mut out = JumpListOutput {
        shortcuts: Vec::new(),
        entries: Vec::new(),
        summaries: Vec::new(),
        carve_status: Vec::new(),
        events: Vec::new(),
    };
    for a in artifacts {
        let record_type = a.metadata.get("record_type").and_then(|v| v.as_str());
        match (&a.artifact_type, record_type) {
            (ArtifactType::FileEntry, _) => out.shortcuts.push(a),
            (ArtifactType::TimelineEvent, _) => out.events.push(a),
            (ArtifactType::ParsedRecord, Some("jumplist_destlist_entry")) => out.entries.push(a),
            (ArtifactType::ParsedRecord, Some("jumplist_destlist")) => out.summaries.push(a),
            (ArtifactType::ParsedRecord, Some("jumplist_carve_status")) => out.carve_status.push(a),
            (kind, rt) => panic!(
                "a jump list reading produces shortcut FileEntries, DestList entry and summary \
                 ParsedRecords, carve-status ParsedRecords and TimelineEvents, nothing else: \
                 got {kind:?} with record_type {rt:?}: {}",
                a.metadata
            ),
        }
    }
    out
}

/// Check a jump list reading against the contract the parser holds to.
///
/// An automaticDestinations file is an OLE compound file, and when its
/// directory can be followed the reading is the directory's: every numbered
/// stream is a `JumpListStream` FileEntry (`recovery_method: ole_directory`),
/// every DestList entry decoded is a `jumplist_destlist_entry` ParsedRecord
/// with a TimelineEvent for its recorded time, and exactly one trailing
/// `jumplist_destlist` summary accounts for all of them and states every
/// shortfall. No `JumpListCarveStatus` is produced on that path: nothing was
/// carved.
///
/// When the directory cannot be followed — and always for a
/// customDestinations file, which has no directory — the bytes are scanned for
/// the shortcut signature. Each hit is a `JumpListCarvedShortcut` FileEntry
/// (`recovery_method: signature_carve`) with the offset it was found at; no
/// DestList entry or TimelineEvent can come from a scan. B5-040 then holds:
/// a scan that did not cover the file, or covered it and found nothing, ends
/// with exactly one `JumpListCarveStatus` saying which, so a jump list that
/// yielded nothing and one that was never examined are not both silence. An
/// empty result is only permitted for a file this parser does not claim.
fn assert_jumplist_carve_contract(artifacts: &[Artifact], case_id: Uuid, parent_id: Uuid) {
    let out = partition_jumplist_output(artifacts);

    for a in artifacts {
        assert_eq!(a.case_id, case_id);
        assert_eq!(a.parent_id, Some(parent_id));
    }

    // -- the shortcuts, whichever way they were found --------------------
    for lnk in &out.shortcuts {
        let name = lnk
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            name.ends_with(".lnk"),
            "Extracted artifacts should be LNK files: {}",
            name
        );
        assert!(lnk.data.is_some(), "a shortcut must carry its bytes");
        let method = lnk
            .metadata
            .get("recovery_method")
            .and_then(|v| v.as_str())
            .expect("a shortcut says how it was found");
        let kind = lnk.metadata.get("type").and_then(|v| v.as_str());
        match method {
            "ole_directory" => {
                assert_eq!(kind, Some("JumpListStream"));
                assert!(
                    lnk.metadata.get("stream_name").is_some(),
                    "a stream read through the directory is named by its directory entry"
                );
                // A stream's bytes lie whole at one offset or they do not; the
                // record says which, and never invents an offset.
                assert!(
                    lnk.metadata.get("source_offset").is_some()
                        != lnk.metadata.get("source_offset_unavailable").is_some(),
                    "exactly one of source_offset / source_offset_unavailable: {}",
                    lnk.metadata
                );
                assert!(
                    matches!(
                        lnk.metadata
                            .get("dest_list_correlation")
                            .and_then(|v| v.as_str()),
                        Some("matched" | "no_dest_list_entry" | "dest_list_unavailable")
                    ),
                    "a directory stream states how it relates to the DestList: {}",
                    lnk.metadata
                );
            }
            "signature_carve" => {
                assert_eq!(kind, Some("JumpListCarvedShortcut"));
                assert!(
                    lnk.metadata.get("source_offset").is_some(),
                    "a carved shortcut must say where in the JumpList it was found"
                );
            }
            other => panic!("unknown recovery_method {other:?}: {}", lnk.metadata),
        }
    }

    // -- one summary at most, one carve status at most --------------------
    assert!(
        out.summaries.len() <= 1,
        "one jump list, one DestList summary: got {}",
        out.summaries.len()
    );
    assert!(
        out.carve_status.len() <= 1,
        "one carve, one status record: got {}",
        out.carve_status.len()
    );

    let directory_read = out
        .summaries
        .first()
        .and_then(|s| s.metadata.get("ole_directory_read"))
        .and_then(|v| v.as_bool())
        == Some(true);

    if directory_read {
        assert_directory_reading(&out, artifacts);
    } else {
        assert_signature_scan(&out, artifacts);
    }
}

/// The directory was followed: the streams, the entries and the summary must
/// agree with one another, and nothing may claim to have been carved.
fn assert_directory_reading(out: &JumpListOutput<'_>, artifacts: &[Artifact]) {
    let summary = out.summaries[0];
    assert!(
        out.carve_status.is_empty(),
        "a jump list read through its directory was not carved, so it carries no \
         JumpListCarveStatus"
    );
    assert!(
        out.shortcuts
            .iter()
            .all(|l| l.metadata["recovery_method"] == json!("ole_directory")),
        "every shortcut of a directory reading came from the directory"
    );
    // The summary is emitted after everything it accounts for, so a reader
    // taking the head of the listing does not mistake it for a shortcut.
    assert!(
        std::ptr::eq(artifacts.last().expect("a summary exists"), summary),
        "the DestList summary is emitted after the streams and entries it accounts for"
    );
    assert_eq!(summary.metadata["type"], json!("JumpListDestList"));
    assert_eq!(
        summary.metadata["lnk_streams_read"].as_u64(),
        Some(out.shortcuts.len() as u64),
        "the summary counts the streams that came with it"
    );

    // The DestList entries: each names its stream and whether that stream
    // was read, and the summary counts them.
    match summary
        .metadata
        .get("entries_read")
        .and_then(|v| v.as_u64())
    {
        Some(n) => assert_eq!(
            n,
            out.entries.len() as u64,
            "the summary counts the DestList entries that came with it"
        ),
        None => assert!(
            out.entries.is_empty(),
            "no DestList was decoded, so no entry record can exist"
        ),
    }
    for e in &out.entries {
        assert_eq!(e.metadata["type"], json!("JumpListDestListEntry"));
        for key in [
            "entry_number",
            "stream_name",
            "path",
            "mru_position",
            "pin_status",
        ] {
            assert!(
                e.metadata.get(key).is_some(),
                "a DestList entry carries `{key}`: {}",
                e.metadata
            );
        }
        // Pinned is true, false, or null with a note — never a guess.
        let pinned = &e.metadata["pinned"];
        assert!(
            pinned.is_boolean()
                || (pinned.is_null() && e.metadata.get("pin_status_note").is_some()),
            "pinned is stated or its absence explained: {}",
            e.metadata
        );
        // A recorded time reaches the record or its absence is explained.
        assert!(
            e.metadata.get("last_recorded_time").is_some()
                != e.metadata.get("last_recorded_time_unavailable").is_some(),
            "exactly one of last_recorded_time / last_recorded_time_unavailable: {}",
            e.metadata
        );
        let present = e.metadata["lnk_stream_present"]
            .as_bool()
            .expect("an entry says whether its shortcut stream exists");
        let stream_exists = out
            .shortcuts
            .iter()
            .any(|l| l.metadata["stream_name"] == e.metadata["stream_name"]);
        assert_eq!(
            present, stream_exists,
            "lnk_stream_present must agree with the streams actually read: {}",
            e.metadata
        );
    }
    // A stream that says it matched an entry must have one to match.
    for l in &out.shortcuts {
        if l.metadata["dest_list_correlation"] == json!("matched") {
            assert!(
                out.entries
                    .iter()
                    .any(|e| e.metadata["entry_number"] == l.metadata["dest_list_entry_number"]),
                "a matched stream names a DestList entry that was decoded: {}",
                l.metadata
            );
        }
    }

    // One timeline event per entry with a recorded time, no more.
    let timed = out
        .entries
        .iter()
        .filter(|e| e.metadata.get("last_recorded_time").is_some())
        .count();
    assert_eq!(
        out.events.len(),
        timed,
        "one TimelineEvent per DestList entry that carries a recorded time"
    );
    for ev in &out.events {
        assert!(ev.metadata["timestamp"].is_string());
        assert_eq!(
            ev.metadata["source_module"],
            json!("plugin.windows.jumplist_parser")
        );
        assert!(ev.metadata.get("entry_number").is_some());
    }

    // The summary states whether the reading fell short, and a shortfall
    // reaches the examiner as the standard pair, never as a bare flag.
    let incomplete = summary.metadata["content_incomplete"]
        .as_bool()
        .expect("the summary states whether the reading was complete");
    if incomplete {
        assert_incompleteness_pair(summary, "a DestList summary that fell short");
    } else {
        assert!(
            summary.metadata.get("content_incomplete_reason").is_none(),
            "a reading that fell short of nothing names no shortfall"
        );
        assert!(
            summary.metadata.get("inventory_incomplete").is_none(),
            "a complete reading claims no missing inventory"
        );
    }
}

/// The bytes were scanned (a customDestinations file, or an
/// automaticDestinations file whose directory could not be followed).
fn assert_signature_scan(out: &JumpListOutput<'_>, artifacts: &[Artifact]) {
    assert!(
        out.shortcuts
            .iter()
            .all(|l| l.metadata["recovery_method"] == json!("signature_carve")),
        "every shortcut of a scan was carved by signature"
    );
    assert!(
        out.entries.is_empty() && out.events.is_empty(),
        "a scan reads no DestList, so it can produce neither entries nor events"
    );

    // An automaticDestinations file whose directory failed still owes the
    // summary, saying the directory was not read and the DestList not looked
    // for — a reading that fell short, never a file with no DestList.
    if let Some(summary) = out.summaries.first() {
        assert_eq!(summary.metadata["ole_directory_read"], json!(false));
        assert!(
            summary.metadata["dest_list_present"].is_null(),
            "a directory that was never read cannot say whether a DestList exists"
        );
        assert_eq!(summary.metadata["content_incomplete"], json!(true));
        assert_incompleteness_pair(summary, "a DestList summary whose directory failed");
        assert_eq!(
            summary.metadata["shortcuts_carved"].as_u64(),
            Some(out.shortcuts.len() as u64)
        );
    }

    let Some(status) = out.carve_status.first() else {
        assert!(
            !out.shortcuts.is_empty(),
            "a JumpList that produced nothing must say whether it was scanned (B5-040)"
        );
        return;
    };

    // The status record must be last, so a reader taking the head of the
    // listing does not mistake it for a shortcut.
    assert!(
        std::ptr::eq(artifacts.last().expect("a status exists"), *status),
        "the carve-status record is emitted after the shortcuts it accounts for"
    );
    assert_eq!(
        status.metadata.get("type").and_then(|v| v.as_str()),
        Some("JumpListCarveStatus")
    );
    assert_eq!(
        status.metadata.get("links_carved").and_then(|v| v.as_u64()),
        Some(out.shortcuts.len() as u64),
        "the status record must count the shortcuts that came with it"
    );

    let complete = status
        .metadata
        .get("carve_complete")
        .and_then(|v| v.as_bool())
        .expect("the status record must state whether the carve covered the file");
    let incomplete = status
        .metadata
        .get("content_incomplete")
        .and_then(|v| v.as_bool())
        .expect("the status record must carry the incompleteness flag");
    assert_eq!(
        complete, !incomplete,
        "carve_complete and content_incomplete must not disagree"
    );

    if complete {
        assert_eq!(
            out.shortcuts.len(),
            0,
            "a complete carve only reports itself when it found nothing"
        );
        assert!(
            status.metadata.get("content_incomplete_reason").is_none(),
            "a carve that covered the file must name no shortfall"
        );
    } else {
        assert_incompleteness_pair(status, "a short carve");
    }
}

/// The reason and the sentence both have to reach the examiner: the frontend
/// keys its prose off `<flag>_detail`, so a bare `message` would show the
/// reason code with nothing explaining it. Shortcuts or entries past the
/// stopping point are missing from the case, not merely truncated, so the
/// inventory pair travels with the content pair.
fn assert_incompleteness_pair(record: &Artifact, what: &str) {
    for key in [
        "content_incomplete_reason",
        "content_incomplete_detail",
        "inventory_incomplete_reason",
        "inventory_incomplete_detail",
    ] {
        let v = record
            .metadata
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{what} must carry `{key}`: {}", record.metadata));
        assert!(!v.is_empty(), "`{key}` must not be blank");
    }
    assert_eq!(
        record
            .metadata
            .get("inventory_incomplete")
            .and_then(|v| v.as_bool()),
        Some(true),
        "{what}: what lies past the stopping point is missing from the case"
    );
}

#[test]
fn test_lnk_parser_module_metadata() {
    let parser = LnkParser;

    assert_eq!(parser.id(), "plugin.windows.lnk_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));

    use seance_core::module::InputCapability;
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_lnk_basic_parsing() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/example.lnk", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "LNK parsing should succeed");

    let artifacts = result.unwrap();
    println!("example.lnk produced {} artifacts", artifacts.len());

    // Should produce at least 1 ParsedRecord
    assert!(
        !artifacts.is_empty(),
        "Should produce at least one artifact"
    );

    // First artifact should be ParsedRecord
    let parsed_record = artifacts
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord);

    assert!(parsed_record.is_some(), "Should have ParsedRecord artifact");

    if let Some(record) = parsed_record {
        let metadata = &record.metadata;
        assert_eq!(
            metadata.get("type").and_then(|v| v.as_str()),
            Some("LnkFile")
        );
        assert!(
            metadata.get("target_local_path").is_some(),
            "Should have target_local_path"
        );
        assert!(metadata.get("flags").is_some(), "Should have flags");
    }
}

#[test]
fn test_lnk_timeline_event_generation() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/NeroInfoTool.lnk", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "LNK parsing should succeed");

    let artifacts = result.unwrap();
    println!(
        "NeroInfoTool.lnk produced {} artifacts total",
        artifacts.len()
    );

    // Count ParsedRecords and TimelineEvents
    let parsed_records: Vec<_> = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    let timeline_events: Vec<_> = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();

    println!("  - {} ParsedRecord(s)", parsed_records.len());
    println!("  - {} TimelineEvent(s)", timeline_events.len());

    assert_eq!(
        parsed_records.len(),
        1,
        "Should have exactly 1 ParsedRecord"
    );
    assert!(
        !timeline_events.is_empty(),
        "Should have at least one TimelineEvent"
    );
    assert!(
        timeline_events.len() <= 3,
        "Should have at most 3 TimelineEvents (created, accessed, modified)"
    );

    // Verify TimelineEvent structure
    for event in &timeline_events {
        assert_eq!(
            event.parent_id,
            Some(parent_id),
            "Timeline event should reference parent"
        );
        assert_eq!(
            event.case_id, case_id,
            "Timeline event should have same case_id"
        );

        let metadata = &event.metadata;
        assert!(metadata.get("timestamp").is_some(), "Should have timestamp");
        // The LnkParser emits the timeline-contract keys `timestamp_desc` and
        // `source_module` (not the legacy `event_type`/`source`).
        assert!(
            metadata.get("timestamp_desc").is_some(),
            "Should have timestamp_desc"
        );
        assert!(
            metadata.get("short_desc").is_some(),
            "Should have short_desc"
        );
        assert!(
            metadata.get("description").is_some(),
            "Should have description"
        );
        assert_eq!(
            metadata.get("source_module").and_then(|v| v.as_str()),
            Some("plugin.windows.lnk_parser")
        );
        assert!(
            metadata.get("target_path").is_some(),
            "Should have target_path"
        );

        // Verify timestamp is ISO format
        let timestamp = metadata.get("timestamp").and_then(|v| v.as_str()).unwrap();
        assert!(!timestamp.is_empty(), "Timestamp should not be empty");

        println!(
            "Timeline Event: {} - {}",
            metadata.get("timestamp").unwrap(),
            metadata.get("short_desc").unwrap()
        );
    }
}

#[test]
fn test_non_lnk_file_ignored() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    // Use a non-LNK file
    let Some(artifact) = create_file_artifact("test_data/SAM", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Processing non-LNK file should not error");

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-LNK files"
    );
}

#[test]
fn test_jumplist_parser_module_metadata() {
    let parser = JumpListParser;

    assert_eq!(parser.id(), "plugin.windows.jumplist_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));

    use seance_core::module::InputCapability;
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_automatic_destinations_parsing() {
    let parser = JumpListParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact(
        "test_data/automatic_destinations/1b4dd67f29cb1962.automaticDestinations-ms",
        case_id,
    ) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Automatic destinations parsing should succeed"
    );

    let artifacts = result.unwrap();
    println!(
        "Automatic destinations produced {} artifacts",
        artifacts.len()
    );

    assert_jumplist_carve_contract(&artifacts, case_id, parent_id);
    let out = partition_jumplist_output(&artifacts);

    // Anti-vacuity. The contract above admits a reading that found nothing,
    // because "the directory lists no stream" is a legal finding the parser
    // has to be able to state. This fixture DOES hold shortcuts, so a zero
    // here would be the parser failing, not the file being empty -- and an
    // automaticDestinations JumpList read as empty is reported as an
    // application from which the user opened no documents.
    //
    // The streams are pinned by directory name, and their offsets by what the
    // file holds: seven lie whole at their shortcut signature, four (3, 7, 8
    // and b) are scattered across the OLE mini-sector chain and have no single
    // offset. A byte-scan carve of this file finds eleven signatures too, but
    // at 3456, 6528, 10688 and 17856 the bytes match streams 3, 7, 8 and b
    // for only 128, 128, 576 and 64 bytes before running into the next
    // mini-sector of another stream — so the offset is stated only where the
    // bytes really are (the fallback test below is the scan's side of this).
    let mut by_stream: Vec<(&str, Option<u64>)> = out
        .shortcuts
        .iter()
        .map(|a| {
            (
                a.metadata["stream_name"].as_str().expect("a stream name"),
                a.metadata.get("source_offset").and_then(|v| v.as_u64()),
            )
        })
        .collect();
    by_stream.sort();
    assert_eq!(
        by_stream,
        vec![
            ("1", Some(2048)),
            ("2", Some(2816)),
            ("3", None),
            ("4", Some(4672)),
            ("5", Some(5312)),
            ("6", Some(5824)),
            ("7", None),
            ("8", None),
            ("9", Some(13632)),
            ("a", Some(15360)),
            ("b", None),
        ]
    );
    assert!(out
        .shortcuts
        .iter()
        .all(|a| a.metadata["dest_list_correlation"] == json!("matched")));

    // The DestList: eleven entries in stream order, which is most recently
    // used first (plaso reads the same eleven from this file).
    let entry_numbers: Vec<u64> = out
        .entries
        .iter()
        .map(|e| e.metadata["entry_number"].as_u64().unwrap())
        .collect();
    assert_eq!(entry_numbers, vec![11, 9, 8, 10, 7, 1, 2, 6, 5, 4, 3]);
    let positions: Vec<u64> = out
        .entries
        .iter()
        .map(|e| e.metadata["mru_position"].as_u64().unwrap())
        .collect();
    assert_eq!(positions, (0..11).collect::<Vec<u64>>());
    let times: Vec<&str> = out
        .entries
        .iter()
        .map(|e| e.metadata["last_recorded_time"].as_str().unwrap())
        .collect();
    assert!(
        times.windows(2).all(|w| w[0] >= w[1]),
        "recorded times descend in stream order: {times:?}"
    );
    assert_eq!(
        out.entries[0].metadata["path"],
        json!("C:\\Users\\nfury\\Pictures\\The SHIELD")
    );
    assert_eq!(out.events.len(), 11, "one timeline event per recorded time");

    // The file was read whole: the directory, the DestList and every stream.
    // An unqualified reading must not carry a caveat it has not earned, and
    // nothing was carved, so nothing may say it was.
    let summary = out.summaries[0];
    assert_eq!(summary.metadata["content_incomplete"], json!(false));
    assert_eq!(summary.metadata["entries_read"], json!(11));
    assert_eq!(summary.metadata["lnk_streams_read"], json!(11));
    assert_eq!(summary.metadata["dest_list_layout"], json!("windows_7"));
    assert_eq!(
        summary.metadata["application"],
        json!("Windows Explorer (explorer.exe, Windows 7)")
    );
    assert!(
        out.carve_status.is_empty(),
        "a jump list read through its directory emits no carve-status record"
    );
}

#[test]
fn test_custom_destinations_parsing() {
    let parser = JumpListParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact(
        "test_data/custom_destinations/c98dce577f884ef8.customDestinations-ms",
        case_id,
    ) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Custom destinations parsing should succeed");

    let artifacts = result.unwrap();
    println!("Custom destinations produced {} artifacts", artifacts.len());

    assert_jumplist_carve_contract(&artifacts, case_id, parent_id);

    // This fixture is 12 bytes and holds no shortcut structure, so the whole of
    // it is scanned and the only thing produced is the record saying so. Pinned
    // exactly: if the carve ever returns an empty batch here, "nothing was in
    // this JumpList" becomes indistinguishable from "this JumpList was never
    // read" (B5-040).
    assert_eq!(artifacts.len(), 1, "12-byte fixture holds no shortcut");
    assert_eq!(
        artifacts[0].metadata.get("carve_complete"),
        Some(&json!(true)),
        "a file scanned end to end says so positively"
    );
    assert_eq!(artifacts[0].metadata.get("links_carved"), Some(&json!(0)));
}

/// The same contract on a customDestinations file that really does hold
/// shortcuts: the fixture above proves the empty case and would pass even if
/// carving were broken, because nothing to carve is exactly what it contains.
#[test]
fn test_custom_destinations_carves_the_shortcuts_it_contains() {
    let parser = JumpListParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact(
        "test_data/custom_destinations/368d807282ccde9d.customDestinations-ms",
        case_id,
    ) else {
        return;
    };
    let parent_id = artifact.id;

    let artifacts = parser
        .process(&artifact)
        .expect("Custom destinations parsing should succeed");
    assert_jumplist_carve_contract(&artifacts, case_id, parent_id);

    // Three MS-SHLLINK structures, at the offsets they occupy in this fixture.
    // The offsets are asserted, not just the count: a carve that found the right
    // number of shortcuts at the wrong places has attributed bytes to the wrong
    // entries, and the offset is the only thing tying a carved shortcut back to
    // its position in the evidence.
    let offsets: Vec<u64> = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .map(|a| {
            a.metadata
                .get("source_offset")
                .and_then(|v| v.as_u64())
                .expect("a carved shortcut records where it was found")
        })
        .collect();
    assert_eq!(offsets, vec![64, 637, 1226]);

    // The file was read whole, so there is nothing to disclose and no status
    // record: an unqualified carve must not carry a caveat it has not earned.
    assert!(
        artifacts
            .iter()
            .all(|a| a.artifact_type != ArtifactType::ParsedRecord),
        "a complete carve of a readable file emits no status record"
    );
}

#[test]
fn test_non_jumplist_file_ignored() {
    let parser = JumpListParser;
    let case_id = Uuid::new_v4();

    // Use a non-Jump List file
    let Some(artifact) = create_file_artifact("test_data/SAM", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Processing non-Jump List file should not error"
    );

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-Jump List files"
    );
}

#[test]
fn test_parent_relationship() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/example.lnk", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact).unwrap();

    // All artifacts (ParsedRecord and TimelineEvents) should reference the parent
    for child in &result {
        assert_eq!(
            child.parent_id,
            Some(parent_id),
            "Artifact should reference parent LNK file"
        );
        assert_eq!(child.case_id, case_id, "Artifact should have same case_id");
    }
}

#[test]
fn test_timeline_event_timestamps_valid() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/example.lnk", case_id) else {
        return;
    };

    let result = parser.process(&artifact).unwrap();

    let timeline_events: Vec<_> = result
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();

    // B5-032: the three target MAC events used to share the `timestamp_desc`
    // "LNK Target MAC Time", so a timeline filter could not separate "the
    // target was created" from "the target was opened" -- only the prose
    // differed, and prose is not filterable. Each event now names its own MAC
    // time, and each name must be the one that matches its prose: a created
    // event labelled as an access would be worse than the collapsed label.
    let mut seen_descs: Vec<&str> = Vec::new();

    for event in timeline_events {
        let timestamp = event
            .metadata
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap();

        // The parser emits an event only when the FILETIME converted, so a
        // present event always carries a real RFC 3339 instant. Check the
        // layout rather than merely "contains a separator", which a bare
        // "-" would have satisfied.
        let bytes = timestamp.as_bytes();
        assert!(
            bytes.len() >= 20
                && bytes[..4].iter().all(u8::is_ascii_digit)
                && bytes[4] == b'-'
                && bytes[7] == b'-'
                && bytes[10] == b'T'
                && bytes[13] == b':'
                && bytes[16] == b':',
            "Timestamp should be RFC 3339: {}",
            timestamp
        );

        let timestamp_desc = event
            .metadata
            .get("timestamp_desc")
            .and_then(|v| v.as_str())
            .unwrap();

        // The verb that goes with this MAC time, and nothing else.
        let verb = match timestamp_desc {
            "LNK Target Created" => "created",
            "LNK Target Accessed" => "accessed",
            "LNK Target Modified" => "modified",
            other => panic!(
                "timestamp_desc must name which target MAC time this is, got {:?}",
                other
            ),
        };
        assert!(
            !seen_descs.contains(&timestamp_desc),
            "each target MAC time is emitted once, saw {} twice",
            timestamp_desc
        );
        seen_descs.push(timestamp_desc);

        // The prose must agree with the label: a filter selecting "created"
        // and a reader reading the sentence have to reach the same event.
        let short_desc = event
            .metadata
            .get("short_desc")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(
            short_desc.starts_with(&format!("File {}: ", verb)),
            "short_desc {:?} does not match timestamp_desc {:?}",
            short_desc,
            timestamp_desc
        );

        let description = event
            .metadata
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(
            description.contains(&format!("target was {}: ", verb)),
            "description {:?} does not match timestamp_desc {:?}",
            description,
            timestamp_desc
        );
    }

    // This fixture carries all three target MAC times, so all three events are
    // expected. Without this the loop above passes vacuously on a parser that
    // stopped emitting timeline events altogether -- and a shortcut whose target
    // times never reach the timeline is a file access that never happened as far
    // as the case is concerned.
    assert_eq!(
        seen_descs.len(),
        3,
        "example.lnk carries created, accessed and modified target times: {:?}",
        seen_descs
    );
}

#[test]
fn test_jumplist_integration_with_lnk_parser() {
    let jumplist_parser = JumpListParser;
    let lnk_parser = LnkParser;
    let case_id = Uuid::new_v4();

    // Step 1: Parse Jump List to extract LNK files
    let Some(jumplist_artifact) = create_file_artifact(
        "test_data/automatic_destinations/9d1f905ce5044aee.automaticDestinations-ms",
        case_id,
    ) else {
        return;
    };

    let produced = jumplist_parser.process(&jumplist_artifact).unwrap();
    assert_jumplist_carve_contract(&produced, case_id, jumplist_artifact.id);
    let out = partition_jumplist_output(&produced);
    // Only the shortcut streams feed the next stage. The DestList entries,
    // their timeline events and the summary are statements about the jump
    // list, not shortcuts, and must not be counted as such (B5-040).
    let lnk_artifacts: Vec<&Artifact> = out.shortcuts.clone();
    println!("Jump List extracted {} LNK files", lnk_artifacts.len());

    // The jump list's own record of its two entries: read through the
    // directory (Windows 10, DestList version 3), each with a recorded time
    // that goes on the timeline from the JumpListParser itself.
    assert_eq!(
        out.entries.len(),
        2,
        "plaso reads two DestList entries here"
    );
    assert_eq!(out.events.len(), 2, "one timeline event per recorded time");
    assert_eq!(
        out.summaries[0].metadata["dest_list_layout"],
        json!("windows_10")
    );
    assert!(lnk_artifacts
        .iter()
        .all(|l| l.metadata["recovery_method"] == json!("ole_directory")));

    // Step 2: Process each extracted LNK file through LnkParser.
    //
    // The chained LnkParser emits one ParsedRecord per valid LNK header, plus
    // a TimelineEvent for each NON-ZERO target MAC time. The two timeline
    // events above are the DestList's recorded times, not the shortcuts';
    // whether the shortcut streams carry MAC times is the LnkParser's finding
    // and is not assumed here. Assert on the ParsedRecords to prove the
    // JumpListParser -> LnkParser round-trip works.
    let mut total_parsed_records = 0;
    let mut total_timeline_events = 0;

    for lnk_artifact in &lnk_artifacts {
        let result = lnk_parser.process(lnk_artifact);
        if let Ok(artifacts) = result {
            total_parsed_records += artifacts
                .iter()
                .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
                .count();
            total_timeline_events += artifacts
                .iter()
                .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
                .count();
        }
    }

    println!(
        "Generated {} ParsedRecord(s) and {} TimelineEvent(s) from Jump List",
        total_parsed_records, total_timeline_events
    );

    // This fixture's directory holds two shortcut streams. Pinned, because the
    // guard below is a no-op on an empty reading: an integration test that
    // reports a working round-trip when neither stage ran is worse than no
    // test at all.
    assert_eq!(
        lnk_artifacts.len(),
        2,
        "9d1f905ce5044aee.automaticDestinations-ms holds two shortcut streams"
    );

    // The LnkParser must parse each shortcut stream into a ParsedRecord.
    assert_eq!(
        total_parsed_records, 2,
        "each shortcut stream parses as a shortcut"
    );
}

/// An in-memory data source for a fixture altered in place.
#[derive(Debug)]
struct BytesSource(Vec<u8>);

impl DataSource for BytesSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        if off >= self.0.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

/// The fallback path of the same contract, on the same real file: when the
/// OLE directory cannot be followed the shortcuts are found by scanning, and
/// every record says so. The tests above never reach this branch, because
/// the plaso fixtures are intact; a jump list recovered from unallocated
/// space with its header overwritten is the file this test stands in for.
#[test]
fn test_automatic_destinations_with_unreadable_directory_is_carved_and_says_so() {
    let parser = JumpListParser;
    let case_id = Uuid::new_v4();

    let Some(intact) = create_file_artifact(
        "test_data/automatic_destinations/1b4dd67f29cb1962.automaticDestinations-ms",
        case_id,
    ) else {
        return;
    };
    let source = intact.data.as_ref().expect("the fixture carries its bytes");
    let mut bytes = vec![0u8; source.size() as usize];
    let read = source.read_at(0, &mut bytes).expect("fixture readable");
    assert_eq!(read as u64, source.size(), "the whole fixture was read");

    // The sector-shift field at 0x1E is the one value every reader of the
    // container depends on; a version-3 file declares 9 (512-byte sectors).
    // Zero there, and the FAT, the directory and every stream are past
    // reach while every shortcut's bytes are exactly where they were.
    assert_eq!(&bytes[0x1E..0x20], &[0x09, 0x00]);
    bytes[0x1E] = 0;

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(Arc::new(BytesSource(bytes))),
        json!({
            "name": "1b4dd67f29cb1962.automaticDestinations-ms",
            "artifact_source": "test",
        }),
    );
    let parent_id = artifact.id;

    let artifacts = parser
        .process(&artifact)
        .expect("a jump list whose directory is unreadable is still processed");
    assert_jumplist_carve_contract(&artifacts, case_id, parent_id);
    let out = partition_jumplist_output(&artifacts);

    // The directory route was not taken, and the summary is the record of
    // that: it neither claims a DestList nor denies one, and the shortfall
    // reaches the examiner as the standard pair.
    let summary = out.summaries.first().expect(
        "an automaticDestinations file whose directory failed still owes its \
         DestList summary",
    );
    assert_eq!(summary.metadata["ole_directory_read"], json!(false));
    assert!(summary.metadata["ole_directory_error"].is_string());
    assert!(summary.metadata["dest_list_present"].is_null());
    assert_eq!(summary.metadata["content_incomplete"], json!(true));
    assert_eq!(
        summary.metadata["content_incomplete_reason"],
        json!("unresolved_structure")
    );
    assert_eq!(summary.metadata["lnk_streams_read"], json!(0));
    assert!(summary.metadata["lnk_streams_in_directory"].is_null());
    assert!(
        out.entries.is_empty() && out.events.is_empty(),
        "no DestList was read, so no entry and no recorded time may be claimed"
    );

    // Every shortcut is typed as carved, tied to no DestList entry, and
    // placed at the offset its signature was found at. The scan finds the
    // eleven signatures the directory reading knows of -- but for the four
    // streams the directory reading declines to place (3, 7, 8 and b, whose
    // bytes are scattered across mini-sectors; their signatures sit at 3456,
    // 6528, 10688 and 17856) the scan can only report the signature's
    // offset, which is why a carved shortcut is typed apart from a directory
    // stream: its bytes past the first mini-sector may belong to another
    // stream.
    let mut offsets: Vec<u64> = out
        .shortcuts
        .iter()
        .map(|a| a.metadata["source_offset"].as_u64().expect("carved offset"))
        .collect();
    offsets.sort_unstable();
    assert_eq!(
        offsets,
        vec![2048, 2816, 3456, 4672, 5312, 5824, 6528, 10688, 13632, 15360, 17856]
    );
    for a in &out.shortcuts {
        assert_eq!(a.metadata["type"], json!("JumpListCarvedShortcut"));
        assert_eq!(
            a.metadata["dest_list_correlation"],
            json!("dest_list_unavailable")
        );
    }
    assert_eq!(
        summary.metadata["shortcuts_carved"],
        json!(out.shortcuts.len())
    );

    // The scan covered the whole file and found shortcuts, so there is no
    // carve-status record: that record exists to say a scan stopped short or
    // found nothing, and neither is true here.
    assert!(
        out.carve_status.is_empty(),
        "a complete scan that found shortcuts has nothing to disclose beyond the summary"
    );
}
