use super::*;
use seance_core::data_source::DataSource;
use serde_json::json;
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
fn test_shellbags_plugin_module_metadata() {
    let parser = ShellBagsPlugin;

    assert_eq!(parser.id(), "plugin.windows.shellbags");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));

    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_shellbags_plugin_skips_non_hive_files() {
    let parser = ShellBagsPlugin;
    let case_id = Uuid::new_v4();

    let data = vec![0u8; 100];
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "random.txt"}), // Not a registry hive
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_shellbags_plugin_skips_wrong_hive_name() {
    let parser = ShellBagsPlugin;
    let case_id = Uuid::new_v4();

    let data = vec![0u8; 100];
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    // SYSTEM hive doesn't contain shellbags
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "SYSTEM"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_shellbags_plugin_requires_data_source() {
    let parser = ShellBagsPlugin;
    let case_id = Uuid::new_v4();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None, // No data source
        json!({"name": "USRCLASS.DAT"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ModuleError::InvalidInputFormat(_)
    ));
}

#[test]
fn test_shellbags_plugin_handles_invalid_hive() {
    let parser = ShellBagsPlugin;
    let case_id = Uuid::new_v4();

    // Random data that isn't a valid registry hive
    let data = vec![0u8; 1000];
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "USRCLASS.DAT"}),
    );

    // A file named as a hive that is not one is not parsed — and now says so.
    // Returning nothing was indistinguishable from a user who opened no
    // folders, and the reason reached a debug log the case never sees
    // (`HUNT-130`).
    let out = parser.process(&artifact).expect("must not error");
    assert_eq!(out.len(), 1, "the refusal must reach the case");
    let status = &out[0].metadata;
    assert_eq!(status["type"], "RegistryHiveParseStatus");
    assert_eq!(status["looked_for"], "shellbags");
    let message = status["message"].as_str().expect("a message");
    assert!(
        message.contains("shellbags were never looked for"),
        "{message}"
    );
    assert!(
        message.contains("NOT evidence that there were none"),
        "{message}"
    );
}

#[test]
fn test_shellbags_plugin_handles_corrupt_hive() {
    let parser = ShellBagsPlugin;
    let case_id = Uuid::new_v4();

    // Registry hive signature but corrupt content
    let mut data = vec![0xFFu8; 4096];
    // regf signature
    data[0] = b'r';
    data[1] = b'e';
    data[2] = b'g';
    data[3] = b'f';

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "NTUSER.DAT"}),
    );

    // Should handle gracefully
    let result = parser.process(&artifact);
    assert!(result.is_ok());
}

#[test]
fn test_shellbags_plugin_empty_data() {
    let parser = ShellBagsPlugin;
    let case_id = Uuid::new_v4();

    let data = Vec::new();
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "USRCLASS.DAT"}),
    );

    // An empty file named as a hive is the same answer as any other file that
    // is not one: not read, and said so.
    let out = parser.process(&artifact).expect("must not error");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "RegistryHiveParseStatus");
}

#[test]
fn test_shellbags_plugin_recognizes_usrclass() {
    let parser = ShellBagsPlugin;
    let case_id = Uuid::new_v4();

    // Test that USRCLASS.DAT is recognized (even if parsing fails)
    let data = vec![0u8; 100];
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "USRCLASS.DAT"}),
    );

    // Parser should attempt to process (won't error on recognition)
    let result = parser.process(&artifact);
    assert!(result.is_ok());
}

#[test]
fn test_shellbags_plugin_recognizes_ntuser_case_insensitive() {
    let parser = ShellBagsPlugin;
    let case_id = Uuid::new_v4();

    let data = vec![0u8; 100];
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    // Test case insensitivity
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "NtUsEr.DaT"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
}

#[test]
fn test_shellbag_timeline_event_from_file_entry_item() {
    use crate::shellbag_structs::shellbag_timeline_event;

    // Craft a minimal file-entry shell item (type 0x31) with a DOS date/time of
    // 2021-06-15 12:30:00. Layout: [0..2]=size [2]=type [3]=unk [4..8]=filesize
    // [8..10]=dos_date [10..12]=dos_time.
    let dos_date: u16 = (41 << 9) | (6 << 5) | 15; // year 2021 (1980+41), month 6, day 15
    let dos_time: u16 = (12 << 11) | (30 << 5); // hour 12, minute 30, second 0
    let mut item = vec![0u8; 20];
    item[0..2].copy_from_slice(&20u16.to_le_bytes());
    item[2] = 0x31; // file-entry shell item
    item[8..10].copy_from_slice(&dos_date.to_le_bytes());
    item[10..12].copy_from_slice(&dos_time.to_le_bytes());

    let case_id = Uuid::new_v4();
    let parent_id = Uuid::new_v4();
    let event = shellbag_timeline_event(case_id, parent_id, "ROOT:BagMRU\\Downloads", &item)
        .expect("file-entry shell item should yield a timeline event");

    assert_eq!(event.artifact_type, ArtifactType::TimelineEvent);
    assert_eq!(event.parent_id, Some(parent_id));
    assert_eq!(event.metadata["source_module"], "plugin.windows.shellbags");
    let ts = event.metadata["timestamp"].as_str().unwrap();
    assert!(
        ts.starts_with("2021-06-15T12:30:00"),
        "unexpected timestamp: {}",
        ts
    );
    let short = event.metadata["short_desc"].as_str().unwrap();
    assert!(!short.is_empty());
    assert!(short.starts_with("ShellBag: "));
}

#[test]
fn test_shellbag_timeline_event_skips_items_without_timestamp() {
    use crate::shellbag_structs::shellbag_timeline_event;

    // A GUID folder item (type 0x1F) carries no DOS date/time.
    let mut item = vec![0u8; 20];
    item[2] = 0x1F;
    let event = shellbag_timeline_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "ROOT:BagMRU\\MyComputer",
        &item,
    );
    assert!(event.is_none());
}

// Integration test with real hive file
#[test]
fn test_parse_real_usrclass_hive() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("../test_data/UsrClass.dat");
    if !test_file.exists() {
        eprintln!("Skipping integration test: UsrClass.dat not found");
        return;
    }

    let parser = ShellBagsPlugin;
    let case_id = Uuid::new_v4();

    let data = fs::read(test_file).expect("Failed to read UsrClass.dat");
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "UsrClass.dat"}),
    );

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Failed to parse UsrClass.dat: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    println!(
        "Parsed {} shellbag artifacts from UsrClass.dat",
        artifacts.len()
    );
}

/// A source that declares more bytes than it will hand over: a truncated
/// acquisition, or a hive larger than the plugin's load cap.
#[derive(Debug)]
struct ShortHiveSource {
    data: Vec<u8>,
    declared: u64,
}

impl DataSource for ShortHiveSource {
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
        self.declared
    }
}

#[test]
fn a_hive_that_could_not_be_loaded_in_full_never_reports_an_empty_shellbag_result() {
    // The source declares a 4 KiB hive and hands over 100 bytes: whatever bags
    // it held are unreachable. Returning nothing at all would put "this user
    // browsed no folders" in the case.
    let mut data = vec![0u8; 100];
    data[0..4].copy_from_slice(b"regf");
    let data_source: Arc<dyn DataSource> = Arc::new(ShortHiveSource {
        data,
        declared: 4096,
    });

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "NTUSER.DAT"}),
    );

    let out = ShellBagsPlugin.process(&artifact).expect("process failed");
    let status = out
        .iter()
        .find(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("RegistryHiveParseStatus")
        })
        .expect("a partially loaded hive must leave a visible record");
    assert_eq!(status.metadata["hive_truncated"], true);
    assert_eq!(status.metadata["content_incomplete"], true);
    assert_eq!(status.metadata["hive_bytes_read"], 100);
    assert_eq!(status.metadata["hive_declared_bytes"], 4096);
}

#[test]
fn a_file_named_as_a_hive_that_is_not_one_says_so_even_when_it_was_read_in_full() {
    // This test was called `a_hive_read_in_full_that_holds_no_bags_stays_silent`
    // and asserted `out.is_empty()`. Its fixture is a thousand zero bytes,
    // which is not a hive at all — so what it actually pinned was the defect
    // in `HUNT-130`: a file named `NTUSER.DAT` that could not be opened left
    // the case with no records and no reason. Reading every byte of something
    // that is not a hive is not the same as reading a hive that held nothing.
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(vec![0u8; 1000]));

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "NTUSER.DAT"}),
    );

    let out = ShellBagsPlugin.process(&artifact).expect("process failed");
    assert_eq!(out.len(), 1);
    let status = &out[0].metadata;
    assert_eq!(status["type"], "RegistryHiveParseStatus");
    // The parser lower-cases the name it works with; the record carries that.
    assert_eq!(status["hive_name"], "ntuser.dat");
    // And it must not claim the file was short: every byte was read.
    assert!(
        status.get("content_incomplete").is_none()
            || status["content_incomplete"] == serde_json::Value::Bool(false),
        "a fully-read file must not be reported as a short read: {status:?}"
    );
}

/// The BagMRU recursion cap must publish the point where the walk stopped, not
/// return an empty subtree.
///
/// What an examiner learns: which folders a user opened. A wrong answer here is
/// a bag list that ends mid-tree with nothing marking the cut, which reads as
/// "the user browsed no further" for folders the tool simply refused to walk
/// (B2-167).
#[test]
fn bagmru_depth_cap_publishes_where_the_walk_stopped() {
    use crate::shellbag_structs::MAX_BAGMRU_DEPTH;

    let case_id = Uuid::new_v4();
    let parent_id = Uuid::new_v4();
    let parser = ShellBagParser::new(case_id, parent_id);

    // Inside the cap: the walk carries on and the guard contributes nothing.
    assert!(parser.depth_guard("ROOT:BagMRU\\0", 0).is_none());
    assert!(parser
        .depth_guard("ROOT:BagMRU\\0", MAX_BAGMRU_DEPTH)
        .is_none());

    // Past the cap: a record, never silence.
    let stop = parser
        .depth_guard("ROOT:BagMRU\\deep\\path", MAX_BAGMRU_DEPTH + 1)
        .expect("past the cap the walk must report itself");
    assert_eq!(stop.len(), 1, "the untraversed subtree must not vanish");
    let md = &stop[0].metadata;
    assert_eq!(md["type"], "ShellBagWalkTruncated");
    assert_eq!(md["content_incomplete"], json!(true));
    assert_eq!(md["content_incomplete_reason"], "bagmru_depth_limit");
    assert_eq!(md["path"], "ROOT:BagMRU\\deep\\path");
    assert_eq!(stop[0].parent_id, Some(parent_id));
    assert_eq!(stop[0].case_id, case_id);
}

// --- the record the walk builds, from a shell item the shared crate makes ----

#[cfg(test)]
mod record {
    use crate::shellbag_structs::shellbag_entry_metadata;
    use seance_shell_item::fixture::file_entry_with_times;

    /// The record an examiner reads. It used to carry the path, the folder
    /// name and the slot — and no time whatever.
    #[test]
    fn the_record_carries_every_time_and_says_they_are_local() {
        let item = file_entry_with_times(8, "Quarterly.xlsx");
        let meta = shellbag_entry_metadata(
            "ROOT:BagMRU\\Desktop\\Quarterly.xlsx",
            "Quarterly.xlsx",
            "0",
            &item,
        );
        assert_eq!(meta["folder_modified"], "2021-06-15T14:30:44+00:00");
        assert_eq!(meta["folder_created"], "2019-01-02T03:04:06+00:00");
        assert_eq!(meta["folder_accessed"], "2021-12-31T23:59:58+00:00");
        // The one thing that must travel with them: they are local wall-clock
        // with no zone, so a consumer must not shift them by a zero offset.
        assert_eq!(meta["timezone"], "local");
        let note = meta["timestamp_note"].as_str().expect("a note");
        assert!(note.contains("NO recorded zone"), "{note}");
        assert!(note.contains("they are NOT UTC"), "{note}");
        assert!(note.contains("two-second resolution"), "{note}");
    }

    #[test]
    fn a_record_with_no_times_carries_no_timezone_claim() {
        // A GUID folder item carries no FAT time at all. Stamping it `local`
        // would assert something about a record that has no date in it.
        let mut item = vec![0u8; 20];
        item[2] = 0x1F; // GUID folder
        let meta = shellbag_entry_metadata("ROOT:BagMRU", "This PC", "0", &item);
        assert!(meta.get("folder_modified").is_none());
        assert!(meta.get("timezone").is_none());
        assert!(meta.get("timestamp_note").is_none());
        // And the record is still emitted: the folder was browsed.
        assert_eq!(meta["folder_name"], "This PC");
    }
}

/// The BagMRU key's last-write time reaches the bag as UTC, and a zero
/// FILETIME adds nothing (Data Leakage key questions 25 and 27).
#[test]
fn a_bag_carries_the_last_write_time_of_its_bagmru_key() {
    use crate::shellbag_structs::with_key_last_written;
    // 2015-03-24 14:00:19 UTC, as a FILETIME.
    let ft: u64 = (1_427_205_619u64 + 11_644_473_600) * 10_000_000;
    let m = with_key_last_written(serde_json::json!({"type": "ShellBagEntry"}), ft);
    assert_eq!(m["key_last_written"], "2015-03-24T14:00:19+00:00");
    assert!(m["key_last_written_basis"]
        .as_str()
        .unwrap()
        .contains("BagMRU key"));

    let none = with_key_last_written(serde_json::json!({"type": "ShellBagEntry"}), 0);
    assert!(none.get("key_last_written").is_none());
}

/// HUNT-277. A shadow-copy prior version of `NTUSER.DAT` is opened under its
/// original name, everything it yields repeats the snapshot identity, and a
/// `ParsedRecord` that is not a prior version is not read. SYNTHETIC: a `regf`
/// header with nothing behind it, so the record is the status a rejected hive
/// produces; no real evidence is graded.
#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    let hive = || {
        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(b"regf");
        Arc::new(MockDataSource::new(data))
    };
    assert!(ShellBagsPlugin
        .subscribes_to()
        .contains(&ArtifactType::ParsedRecord));

    let prior = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(hive()),
        json!({
            "type": "VssPriorVersion",
            "name": "NTUSER.DAT [shadow copy 2015-03-23T00:00:00Z]",
            "file_name": "NTUSER.DAT",
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 0,
        }),
    );
    let out = ShellBagsPlugin.process(&prior).unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].metadata["is_snapshot_version"], json!(true));
    assert_eq!(out[0].metadata["vss_snapshot_id"], json!("snap-1"));

    let plain = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(hive()),
        json!({ "type": "SomethingElse", "name": "NTUSER.DAT" }),
    );
    assert!(ShellBagsPlugin.process(&plain).unwrap().is_empty());

    let live = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(hive()),
        json!({ "name": "NTUSER.DAT" }),
    );
    let live = ShellBagsPlugin.process(&live).unwrap();
    assert_eq!(live.len(), 1);
    assert!(live[0].metadata.get("is_snapshot_version").is_none());
}
