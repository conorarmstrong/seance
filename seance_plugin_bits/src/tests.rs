//! Unit tests. The synthetic inputs here pin refusal and bounds handling only;
//! what a real queue decodes to is pinned in `tests/real_queues.rs`.

use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

/// The first 8 KiB of the Data Leakage PC's `qmgr1.dat` (see the fixture README).
const QMGR1: &[u8] = include_bytes!("../tests/fixtures/qmgr/data_leakage_qmgr1.dat.head8k");

fn file(name: &str, content: Vec<u8>) -> Artifact {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(content));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    )
}

fn types(out: &[Artifact]) -> Vec<String> {
    out.iter()
        .map(|a| a.metadata["type"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn a_file_that_is_neither_named_nor_shaped_like_a_queue_is_left_alone() {
    let out = BitsParser::new()
        .process(&file("notes.txt", b"nothing to see".to_vec()))
        .unwrap();
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn a_queue_named_file_without_the_queue_guids_is_refused_not_read_as_empty() {
    // Named qmgr0.dat, but the bytes do not open with the header GUIDs.
    let mut bytes = QMGR1.to_vec();
    bytes[16..32].copy_from_slice(&[0x11; 16]);
    let out = BitsParser::new()
        .process(&file("qmgr0.dat", bytes))
        .unwrap();
    assert_eq!(types(&out), vec!["BitsQueueIncomplete"], "{out:?}");
    assert_eq!(out[0].metadata["status"], "NotDecoded");
    assert!(!types(&out).contains(&"BitsQueueFile".to_string()));
}

#[test]
fn an_all_zero_queue_file_is_refused() {
    let out = BitsParser::new()
        .process(&file("QMGR1.DAT", vec![0u8; 4096]))
        .unwrap();
    assert_eq!(types(&out), vec!["BitsQueueIncomplete"]);
}

#[test]
fn a_truncated_queue_is_reported_incomplete_not_as_zero_jobs() {
    // Cut inside the one live job, before its closing delimiter.
    let out = BitsParser::new()
        .process(&file("qmgr1.dat", QMGR1[..0x300].to_vec()))
        .unwrap();
    let summary = out
        .iter()
        .find(|a| a.metadata["type"] == "BitsQueueFile")
        .expect("a summary for a file that opened like a queue");
    assert_eq!(summary.metadata["content_incomplete"], true, "{summary:?}");
    assert!(summary.metadata["status"]
        .as_str()
        .unwrap()
        .starts_with("queue partly read"));
    assert!(
        types(&out).contains(&"BitsQueueIncomplete".to_string()),
        "a standalone marker must say the walk fell short: {out:?}"
    );
}

#[test]
fn a_declared_job_count_larger_than_the_file_is_incomplete() {
    let mut bytes = QMGR1[..0xc00].to_vec();
    // The first queue's job count sits after the queue GUID at 0x20.
    bytes[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes());
    let q = qmgr_dat::parse(&bytes).expect("still opens like a queue");
    assert!(q.incomplete.is_some(), "{q:?}");
}

#[test]
fn filetimes_zero_and_all_ones_are_unavailable() {
    assert_eq!(filetime_rfc3339(0), None);
    assert_eq!(filetime_rfc3339(u64::MAX), None);
    assert_eq!(
        filetime_rfc3339(0x01d0_670b_1912_e447).as_deref(),
        Some("2015-03-25T14:50:55.671405500+00:00")
    );
}

#[cfg(feature = "esedb")]
#[test]
fn process_routes_a_real_qmgr_db_to_the_database_reader() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/qmgr_db/lonewolf_qmgr.db"
    ))
    .unwrap();
    let out = BitsParser::new().process(&file("qmgr.db", bytes)).unwrap();
    assert!(
        types(&out).contains(&"BitsQueueDatabase".to_string()),
        "{:?}",
        types(&out)
    );
}

#[test]
fn the_summary_names_the_guid_the_file_opens_with_as_the_file_guid() {
    // bytes[..16] is the file GUID; the header GUID {C82BF713-…} is a
    // different one, so the key must not call the first by the second's name.
    let out = BitsParser::records_for(Uuid::new_v4(), Uuid::new_v4(), "qmgr1.dat", QMGR1);
    let s = out
        .iter()
        .find(|a| a.metadata["type"] == "BitsQueueFile")
        .expect("summary");
    let want = qmgr_dat::guid_string(&QMGR1[..16].try_into().unwrap());
    assert_eq!(s.metadata["file_guid"], want.as_str(), "{:?}", s.metadata);
    assert!(s.metadata.get("header_guid").is_none(), "{:?}", s.metadata);
    assert_eq!(s.metadata["header_guid_offset"], 16);
}

#[test]
fn a_file_named_qmgr_db_that_is_not_an_ese_database_is_refused_not_ignored() {
    // A zero-filled extraction: the name says queue, the bytes say nothing.
    let out = BitsParser::new()
        .process(&file("qmgr.db", vec![0u8; 8192]))
        .unwrap();
    assert_eq!(types(&out), vec!["BitsQueueIncomplete"], "{out:?}");
    assert_eq!(out[0].metadata["status"], "NotDecoded");
    assert!(out[0].metadata["detail"]
        .as_str()
        .unwrap()
        .contains("not an ESE database"));
}

/// No real `qmgr.db` held has returned a `Jobs` row, so the job header from
/// LoneWolf's transaction log (a real `Jobs` record image) is run through the
/// same path a walked row takes. The decoder reads the header only: files and
/// times are not read, and the record must say so rather than show a job that
/// queued nothing.
#[cfg(feature = "esedb")]
#[test]
fn a_job_from_a_qmgr_db_row_says_its_files_and_times_were_not_read() {
    let blob = include_bytes!("../tests/fixtures/qmgr_db/lonewolf_edb00001_log_job_blob.bin");
    let job = qmgr_db::decode_job_blob(blob).expect("the job header decodes");
    let q = qmgr_db::QueueDb {
        db_state: Some(3),
        jobs_rows: 1,
        jobs: vec![(Some("{ROW}".into()), job)],
        ..Default::default()
    };
    let out = BitsParser::records_from_queue_db(Uuid::new_v4(), Uuid::new_v4(), "qmgr.db", &q);
    let job = out
        .iter()
        .find(|a| a.metadata["type"] == "BitsJob")
        .expect("a job record")
        .metadata
        .clone();
    assert_eq!(job["content_incomplete"], true, "{job:#?}");
    let why = job["content_incomplete_reason"].as_str().unwrap();
    assert!(why.contains("file") && why.contains("time"), "{why}");
    assert_eq!(job["files_read"], false);
    assert_eq!(job["times_read"], false);
    assert!(
        job.get("file_count").is_none(),
        "no count was read: {job:#?}"
    );
    assert!(job.get("remote_urls").is_none(), "{job:#?}");
    assert_eq!(job["creation_time"], "not_read");
    let name = job["name"].as_str().unwrap();
    assert!(!name.contains("(no file)"), "{name}");
    assert!(name.contains("UpdateBinary"), "{name}");

    // The summary says the Files rows are not tied to their jobs.
    let s = out
        .iter()
        .find(|a| a.metadata["type"] == "BitsQueueDatabase")
        .unwrap();
    assert_eq!(s.metadata["file_rows_linked_to_jobs"], false);
}

/// A real ESE database that is not the queue, staged through `process`: left
/// alone under its own name, refused (never read as an empty queue) under the
/// queue's.
#[cfg(feature = "esedb")]
#[test]
fn an_ese_database_without_the_queue_tables_is_refused_only_when_named_like_the_queue() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../seance_plugin_winsearch_edb/tests/fixtures/ese_other/lonewolf_settingsync_meta.edb"
    ))
    .unwrap();
    let out = BitsParser::new()
        .process(&file("meta.edb", bytes.clone()))
        .unwrap();
    assert!(out.is_empty(), "{out:?}");
    let out = BitsParser::new().process(&file("qmgr.db", bytes)).unwrap();
    assert_eq!(types(&out), vec!["BitsQueueIncomplete"], "{out:?}");
    assert!(out[0].metadata["detail"]
        .as_str()
        .unwrap()
        .contains("Jobs and Files tables"));
}

/// HUNT-277. A shadow-copy prior version of a queue is read under its own file
/// name and what it yields repeats the snapshot identity; a `ParsedRecord` that
/// is not a prior version is not read. SYNTHETIC: a file named like the
/// Windows 10 queue that is not an ESE database, so the record is the
/// not-decoded marker; no real evidence is graded.
#[test]
fn a_shadow_copy_prior_version_is_read_and_stamped() {
    assert!(BitsParser::new()
        .subscribes_to()
        .contains(&ArtifactType::ParsedRecord));
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 256]));
    let prior = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(ds.clone()),
        json!({
            "type": "VssPriorVersion",
            "name": "qmgr.db [shadow copy 2015-03-23T00:00:00Z]",
            "file_name": "qmgr.db",
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 0,
        }),
    );
    let out = BitsParser::new().process(&prior).unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].metadata["is_snapshot_version"], json!(true));
    assert_eq!(out[0].metadata["vss_snapshot_id"], json!("snap-1"));

    let plain = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(ds),
        json!({ "type": "SomethingElse", "name": "qmgr.db" }),
    );
    assert!(BitsParser::new().process(&plain).unwrap().is_empty());
}
