/// Integration tests for Registry Parser
///
/// Tests the RegistryParser module against real Windows registry hive files
/// from the test_data directory.
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_registry::RegistryParser;
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

/// The registry-resident record types a hive reading can produce beside the
/// hive record itself, partitioned by what they are evidence of.
struct HiveOutput<'a> {
    /// The one `RegistryHive` record: the walk of the live tree and its
    /// disclosures.
    hive: &'a Artifact,
    /// Keys and values decoded out of unallocated cells. Typed apart from the
    /// live tree because a freed cell is evidence a key or value existed, not
    /// that it does.
    recovered: Vec<&'a Artifact>,
    /// Every other ParsedRecord: the typed readings of the live tree
    /// (accounts, devices, programs, MRU lists, coverage records).
    live: Vec<&'a Artifact>,
    /// The timeline events, key-write and otherwise.
    events: Vec<&'a Artifact>,
}

/// Check a hive reading against the contract the registry parser holds to.
///
/// Detection is by content (the `regf` signature), so the reading exists for
/// any hive whatever its name; `hive_type` on the hive record is the
/// artifact's name upper-cased and nothing more -- the parser does not
/// classify hives. The walk of the live tree is summarised on the one
/// `RegistryHive` record, which states whether the key-write scan and the
/// unallocated-cell scan ran to completion and, when either did not, names
/// the cap or the damage. Recovered keys and values are typed
/// `RecoveredRegistryKey` / `RecoveredRegistryValue`, each saying it came
/// from an unallocated cell, and the hive record's `recovered_cells` summary
/// counts exactly the records that came with it.
fn assert_registry_hive_contract<'a>(
    artifacts: &'a [Artifact],
    case_id: Uuid,
    parent_id: Uuid,
    expected_hive_type: &str,
) -> HiveOutput<'a> {
    // Every record hangs off the hive it was read from -- directly, or
    // through another record of this same reading (an InstallDate event
    // hangs off its InstalledProgram record). A parent outside the reading
    // would be a record attributed to evidence it was not read from.
    let produced: std::collections::HashSet<Uuid> = artifacts.iter().map(|a| a.id).collect();
    for a in artifacts {
        assert_eq!(a.case_id, case_id);
        let parent = a.parent_id.expect("every record names its parent");
        assert!(
            parent == parent_id || produced.contains(&parent),
            "a record's parent is the hive or a record read from it: {}",
            a.metadata
        );
    }

    let mut hives = Vec::new();
    let mut recovered = Vec::new();
    let mut live = Vec::new();
    let mut events = Vec::new();
    for a in artifacts {
        let ty = a.metadata.get("type").and_then(|v| v.as_str());
        match (&a.artifact_type, ty) {
            (ArtifactType::TimelineEvent, _) => events.push(a),
            (ArtifactType::ParsedRecord, Some("RegistryHive")) => hives.push(a),
            (
                ArtifactType::ParsedRecord,
                Some("RecoveredRegistryKey" | "RecoveredRegistryValue"),
            ) => recovered.push(a),
            (ArtifactType::ParsedRecord, Some(_)) => live.push(a),
            (kind, ty) => panic!(
                "a hive reading produces one RegistryHive record, typed ParsedRecords and \
                 TimelineEvents, nothing else: got {kind:?} typed {ty:?}: {}",
                a.metadata
            ),
        }
    }
    assert_eq!(
        hives.len(),
        1,
        "one hive, one RegistryHive record: got {}",
        hives.len()
    );
    let hive = hives[0];
    assert!(
        std::ptr::eq(&artifacts[0], hive),
        "the hive record leads the reading, so a consumer taking the head gets the summary"
    );
    assert_eq!(
        hive.metadata["hive_type"],
        json!(expected_hive_type),
        "hive_type is the artifact's name upper-cased, not a classification"
    );
    assert!(
        hive.metadata["root_key_name"].is_string(),
        "the root key is named"
    );
    assert!(
        hive.metadata["total_keys"].as_u64().is_some()
            && hive.metadata["total_values"].as_u64().is_some(),
        "the live walk is counted"
    );

    // The key-write scan says whether it covered the hive, and a scan that
    // stopped short names why. Silence here would let "no key was written
    // after X" be read off a scan that merely stopped counting.
    let key_writes = events
        .iter()
        .filter(|e| e.metadata["timestamp_desc"] == json!("Registry Key Last Written"))
        .count();
    let key_timeline_complete = hive.metadata["key_timeline_complete"]
        .as_bool()
        .expect("the hive record states whether the key-write scan was complete");
    let cap_reason = hive.metadata.get("key_timeline_cap_reason");
    if key_timeline_complete {
        assert!(
            cap_reason.is_none_or(|v| v.is_null()),
            "a complete scan names no cap: {}",
            hive.metadata["key_timeline_cap_reason"]
        );
    } else {
        assert!(
            cap_reason.and_then(|v| v.as_str()).is_some(),
            "a scan that stopped short names the cap or the damage"
        );
    }
    assert!(
        key_writes <= 50_000,
        "the key-write event cap is 50 000 per hive, got {key_writes}"
    );
    assert!(
        hive.metadata["key_inventory_complete"].is_boolean(),
        "the hive record states whether the walk reached every key"
    );

    // Recovered cells: typed apart from the live tree, each saying where it
    // came from, and counted on the hive record exactly.
    let summary = &hive.metadata["recovered_cells"];
    assert!(
        summary["complete"].is_boolean(),
        "the recovered-cell scan states whether it was complete"
    );
    if summary["complete"] == json!(false) {
        assert!(
            summary["incomplete_reason"].is_string(),
            "a recovered-cell scan that stopped short says why"
        );
    }
    let (rec_keys, rec_values): (Vec<&Artifact>, Vec<&Artifact>) = recovered
        .iter()
        .copied()
        .partition(|a| a.metadata["type"] == json!("RecoveredRegistryKey"));
    assert_eq!(
        summary["keys"].as_u64(),
        Some(rec_keys.len() as u64),
        "the hive record counts the recovered keys that came with it"
    );
    assert_eq!(
        summary["values"].as_u64(),
        Some(rec_values.len() as u64),
        "the hive record counts the recovered values that came with it"
    );
    for r in &recovered {
        assert_eq!(
            r.metadata["recovered_from"],
            json!("unallocated hive cell"),
            "a recovered record says it came from unallocated space: {}",
            r.metadata
        );
        assert_eq!(
            r.metadata["evidence_state"],
            json!("recovered"),
            "a recovered record is never presented as live: {}",
            r.metadata
        );
    }
    for l in &live {
        assert_ne!(
            l.metadata["evidence_state"],
            json!("recovered"),
            "a live-tree record does not claim to be recovered: {}",
            l.metadata
        );
    }

    // Every event is placed at an instant and says which module placed it
    // there.
    for e in &events {
        assert!(
            e.metadata["timestamp"].is_string(),
            "a timeline event carries its instant: {}",
            e.metadata
        );
        assert!(
            e.metadata["timestamp_desc"].is_string(),
            "a timeline event says which time this is: {}",
            e.metadata
        );
    }

    HiveOutput {
        hive,
        recovered,
        live,
        events,
    }
}

fn typed<'a>(records: &[&'a Artifact], ty: &str) -> Vec<&'a Artifact> {
    records
        .iter()
        .copied()
        .filter(|a| a.metadata["type"] == json!(ty))
        .collect()
}

#[test]
fn test_sam_hive_reading() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/SAM", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let artifacts = parser
        .process(&artifact)
        .expect("SAM hive processing should succeed");
    let out = assert_registry_hive_contract(&artifacts, case_id, parent_id, "SAM");

    // A small hive, read whole: both scans complete, nothing capped.
    assert_eq!(out.hive.metadata["key_timeline_complete"], json!(true));
    assert_eq!(
        out.hive.metadata["recovered_cells"]["complete"],
        json!(true)
    );

    // The three local accounts this SAM holds, each with its RID from the
    // key it hangs off. Pinned, because the contract above would pass on a
    // SAM read as a bare key tree with no account decoded from it.
    let accounts = typed(&out.live, "LocalAccount");
    assert_eq!(accounts.len(), 3, "this SAM holds three local accounts");
    for a in &accounts {
        assert!(a.metadata["username"].is_string(), "{}", a.metadata);
        assert!(a.metadata["rid"].is_number(), "{}", a.metadata);
    }

    // Unallocated space in this hive holds three freed keys and three freed
    // values that still decode. Pinned so the recovery does not quietly stop
    // finding them; typed apart so they are never read as the live tree.
    assert_eq!(typed(&out.recovered, "RecoveredRegistryKey").len(), 3);
    assert_eq!(typed(&out.recovered, "RecoveredRegistryValue").len(), 3);
}

#[test]
fn test_software_hive_reading() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/SOFTWARE", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let artifacts = parser
        .process(&artifact)
        .expect("SOFTWARE hive processing should succeed");
    let out = assert_registry_hive_contract(&artifacts, case_id, parent_id, "SOFTWARE");

    // This hive holds more keys than the parser will place on the timeline:
    // the key-write scan stops at its 50 000-event cap and the hive record
    // says so by name. The keys past the cap were parsed (the cell cap of
    // 200 000 was not reached) but their write times are not on the
    // timeline, and an examiner has to be told that rather than read the
    // last event shown as the last write.
    let key_writes = out
        .events
        .iter()
        .filter(|e| e.metadata["timestamp_desc"] == json!("Registry Key Last Written"))
        .count();
    assert_eq!(key_writes, 50_000, "the cap, exactly");
    assert_eq!(out.hive.metadata["key_timeline_complete"], json!(false));
    assert_eq!(
        out.hive.metadata["key_timeline_cap_reason"],
        json!("timeline_event_cap")
    );
    assert!(
        out.hive.metadata["total_keys"].as_u64().unwrap() > 50_000,
        "the walk itself reached past the timeline cap"
    );

    // Installed programs from the Uninstall keys: a typed reading of the
    // live tree, one record per program.
    let programs = typed(&out.live, "InstalledProgram");
    assert_eq!(programs.len(), 67, "this hive lists 67 installed programs");
    assert!(programs
        .iter()
        .all(|p| p.metadata["subtype"] == json!("installed_program")));
}

#[test]
fn test_system_hive_reading() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/SYSTEM", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let artifacts = parser
        .process(&artifact)
        .expect("SYSTEM hive processing should succeed");
    let out = assert_registry_hive_contract(&artifacts, case_id, parent_id, "SYSTEM");

    // The SYSTEM hive carries USBSTOR, MountedDevices and the network
    // interfaces; each is a typed record of the live tree. Counts are what
    // this fixture holds, pinned so a reading that stopped decoding them
    // fails rather than passing on the hive record alone.
    assert_eq!(typed(&out.live, "UsbDevice").len(), 2);
    assert_eq!(typed(&out.live, "MountedDevice").len(), 11);
    assert_eq!(typed(&out.live, "NetworkInterface").len(), 4);
}

#[test]
fn test_amcache_hive_is_read_as_the_hive_it_is() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    // Amcache.hve is a regf hive and is detected by content, not by name:
    // the registry parser walks it as it walks any hive. What the hive
    // MEANS -- the application inventory -- is seance_plugin_amcache's
    // subject and is not claimed here; this parser only reports the tree.
    let Some(artifact) = create_file_artifact("test_data/winreg/Amcache.hve", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let artifacts = parser
        .process(&artifact)
        .expect("Amcache processing should not error");
    let out = assert_registry_hive_contract(&artifacts, case_id, parent_id, "AMCACHE.HVE");
    assert_eq!(out.hive.metadata["key_timeline_complete"], json!(true));
    assert_eq!(
        out.hive.metadata["recovered_cells"]["complete"],
        json!(true)
    );
    assert!(
        out.live.is_empty(),
        "no typed reading of the live tree is claimed for an Amcache hive: {:?}",
        out.live
            .iter()
            .map(|a| &a.metadata["type"])
            .collect::<Vec<_>>()
    );
    assert!(
        !out.events.is_empty(),
        "the key-write times of the inventory keys are on the timeline"
    );
}

/// The shell MRU reading earns one "MRU key last written" timeline event
/// per MRU key (seance_plugin_registry/src/mru.rs, `MruCoverage::timeline_event`).
/// It is built as an event -- `type: TimelineEvent`, a `timestamp` and a
/// `timestamp_desc` -- but it travels through `mru::emit` into the
/// registry-resident record list, and every record on that list is wrapped as
/// a `ParsedRecord` (lib.rs, the `for mut record in resident_records` loop),
/// which only makes a TimelineEvent for records carrying `last_executed`.
/// So the MRU event never reaches the timeline, and what does reach the case
/// is a ParsedRecord whose type says it is a timeline event. This test fails
/// until the plugin emits it as the TimelineEvent it is.
#[test]
fn mru_key_last_written_event_reaches_the_timeline() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/SOFTWARE", case_id) else {
        return;
    };
    let artifacts = parser
        .process(&artifact)
        .expect("SOFTWARE hive processing should succeed");

    // This hive holds one shell MRU key with a last-written time, so exactly
    // one such event is owed.
    let mru_keys = artifacts
        .iter()
        .filter(|a| a.metadata["type"] == json!("MruCoverage"))
        .filter(|a| a.metadata["key_last_written"].is_string())
        .count();
    assert_eq!(mru_keys, 1, "this fixture holds one dated shell MRU key");

    let mistyped: Vec<&Artifact> = artifacts
        .iter()
        .filter(|a| {
            a.artifact_type == ArtifactType::ParsedRecord
                && a.metadata["type"] == json!("TimelineEvent")
        })
        .collect();
    assert!(
        mistyped.is_empty(),
        "a record built as a timeline event must be emitted as one, not as a ParsedRecord \
         that the timeline never sees: {:?}",
        mistyped
            .iter()
            .map(|a| &a.metadata["timestamp_desc"])
            .collect::<Vec<_>>()
    );
    let on_timeline = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .filter(|a| a.metadata["timestamp_desc"] == json!("MRU key last written"))
        .count();
    assert_eq!(
        on_timeline, mru_keys,
        "one MRU key last-written event per dated MRU key, on the timeline"
    );
}

#[test]
fn test_regf_test_hives() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    let test_files = vec![
        "test_data/regf/100_sub_keys.hiv",
        // corrupt_sub_key_list.hiv panicked the GPL reader this replaced; our
        // catch_unwind wrapper now handles this gracefully
        "test_data/regf/corrupt_sub_key_list.hiv",
    ];

    for file_path in test_files {
        let Some(artifact) = create_file_artifact(file_path, case_id) else {
            return;
        };
        let result = parser.process(&artifact);

        // Processing should succeed without error (panics are caught)
        assert!(result.is_ok(), "Processing {} should not error", file_path);

        let artifacts = result.unwrap();
        let parsed_records: Vec<&Artifact> = artifacts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .collect();

        // Valid hives should be detected and parsed
        if file_path.contains("100_sub_keys") {
            assert_eq!(
                parsed_records.len(),
                1,
                ".hiv files should be detected via content analysis: {}",
                file_path
            );
            let parsed = parsed_records[0];
            let artifact_type = parsed.metadata.get("type").and_then(|v| v.as_str());
            assert_eq!(
                artifact_type,
                Some("RegistryHive"),
                "Should be detected as RegistryHive"
            );
        } else if file_path.contains("corrupt") {
            // A corrupt hive must not panic a parser; catch_unwind backs that up
            // Parser returns empty results for corrupted hives (graceful degradation)
            assert!(
                parsed_records.len() <= 1,
                "Corrupt hive should either be skipped or partially parsed: {}",
                file_path
            );
        }
    }
}

#[test]
fn test_non_registry_file_ignored() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    // Create artifact with non-registry filename
    let artifact = {
        let metadata = json!({
            "name": "random_file.txt",
            "path": "/tmp/random_file.txt"
        });

        Artifact::new(case_id, ArtifactType::FileEntry, None, metadata)
    };

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Processing non-registry file should not error"
    );

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-registry files"
    );
}

#[test]
fn test_parent_relationship() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/SAM", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact).unwrap();
    let parsed = &result[0];

    // Verify parent-child relationship
    assert_eq!(
        parsed.parent_id,
        Some(parent_id),
        "Parsed artifact should reference parent"
    );
    assert_eq!(
        parsed.case_id, case_id,
        "Parsed artifact should have same case_id"
    );
}

#[test]
fn test_missing_data_source() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    // Create artifact without data source
    let artifact = {
        let metadata = json!({
            "name": "SAM",
            "path": "/fake/path/SAM"
        });

        Artifact::new(case_id, ArtifactType::FileEntry, None, metadata)
    };

    let result = parser.process(&artifact);
    // Parser should gracefully skip artifacts without data sources
    assert!(
        result.is_ok(),
        "Should gracefully skip when data source is missing"
    );
    assert_eq!(
        result.unwrap().len(),
        0,
        "Should produce no artifacts without data source"
    );
}

#[test]
fn test_module_metadata() {
    let parser = RegistryParser;

    assert_eq!(parser.id(), "plugin.windows.registry_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));
    assert!(subscriptions.contains(&ArtifactType::RawEvidence));
}

#[test]
fn test_case_insensitive_name_matching() {
    let parser = RegistryParser;
    let case_id = Uuid::new_v4();

    // Detection is by content, so the name's case cannot stop the reading;
    // the name only reaches the record as the upper-cased `hive_type`.
    let Some(sam_path) = crate::fixtures::resolve("test_data/SAM") else {
        return;
    };
    let artifact = {
        let data_source = Arc::new(FileDataSource::new(sam_path).unwrap());

        let metadata = json!({
            "name": "sam",  // lowercase
            "path": "test_data/sam",
            "size": data_source.size()
        });

        Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            Some(data_source),
            metadata,
        )
    };
    let parent_id = artifact.id;

    let artifacts = parser
        .process(&artifact)
        .expect("Should handle lowercase hive names");
    let out = assert_registry_hive_contract(&artifacts, case_id, parent_id, "SAM");
    assert_eq!(
        typed(&out.live, "LocalAccount").len(),
        3,
        "the same reading as under the upper-case name"
    );
}
