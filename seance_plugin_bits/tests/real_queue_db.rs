//! Known answers from LoneWolf's real Windows 10 `qmgr.db` (ESE).
//!
//! The database is committed whole and unedited
//! (`tests/fixtures/qmgr_db/README.md`). It was imaged from a running machine:
//! its header says dirty shutdown, its `Jobs` and `Files` tables hold no rows,
//! and the queue's recent state lives in the `edb*.log` transaction logs beside
//! it, which libesedb does not replay. So what this file pins is honesty about
//! that — the tables open, read empty, and the emptiness is not published as an
//! empty queue — plus the byte scan that finds file records in pages the table
//! walk does not reach, and the blob decoders on real blob bytes.
#![cfg(feature = "esedb")]

use seance_plugin_bits::qmgr_db;
use seance_plugin_bits::BitsParser;
use serde_json::Value;
use std::path::PathBuf;
use uuid::Uuid;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/qmgr_db")
        .join(name)
}

fn db_records(path: &std::path::Path) -> Vec<Value> {
    let bytes = std::fs::read(path).expect("read database");
    BitsParser::records_for_db(Uuid::new_v4(), Uuid::new_v4(), "qmgr.db", path, &bytes)
        .into_iter()
        .map(|a| a.metadata)
        .collect()
}

fn of_type<'a>(recs: &'a [Value], t: &str) -> Vec<&'a Value> {
    recs.iter().filter(|r| r["type"] == t).collect()
}

#[test]
fn a_jobs_blob_from_lone_wolfs_transaction_log_decodes_with_the_dat_header_reader() {
    // Bytes 0x11066.. of edb00001.log: a Jobs record image in a log page.
    let blob = std::fs::read(fixture("lonewolf_edb00001_log_job_blob.bin")).unwrap();
    let job = qmgr_db::decode_job_blob(&blob).expect("the job header decodes");
    assert_eq!(job.name, "UpdateBinary");
    assert_eq!(
        job.owner_sid,
        "S-1-5-21-2734969515-1644526556-1039763013-1001"
    );
    assert_eq!(job.job_id, "{BFA381AB-B068-4C96-BFBB-B3A93E5FEE21}");
    assert_eq!((job.job_type, job.priority, job.state), (0, 2, 3));
}

#[test]
fn a_files_blob_in_a_page_the_walk_does_not_reach_decodes() {
    let db = std::fs::read(fixture("lonewolf_qmgr.db")).unwrap();
    let f = qmgr_db::decode_file_blob(&db[0x84089..0x84089 + 0x400]).expect("decodes");
    assert!(f.remote_url.starts_with(
        "http://storage.googleapis.com/update-delta/ojjgnpkioondelmggbekfhllhdaimnho/712/711/"
    ));
    assert!(f
        .local_path
        .starts_with(r"C:\Users\jcloudy\AppData\Local\Temp\chrome_BITS_8696_28470\"));
    assert!(f.temp_path.ends_with(r"\BIT8F8E.tmp"));
}

#[test]
fn the_lone_wolf_qmgr_db_reads_as_dirty_and_empty_not_as_an_empty_queue() {
    let recs = db_records(&fixture("lonewolf_qmgr.db"));
    let summary = of_type(&recs, "BitsQueueDatabase");
    assert_eq!(summary.len(), 1, "{recs:#?}");
    let s = summary[0];
    assert_eq!(s["jobs_rows"], 0);
    assert_eq!(s["files_rows"], 0);
    assert_eq!(s["database_state"], "dirty_shutdown");
    assert_eq!(s["content_incomplete"], true);
    assert!(s["content_incomplete_reason"]
        .as_str()
        .unwrap()
        .contains("transaction logs"));
    assert!(
        of_type(&recs, "BitsJob").is_empty(),
        "no row was returned, so no job may be published"
    );
    assert!(!of_type(&recs, "BitsQueueIncomplete").is_empty());

    // What the byte scan finds in pages no table row points at: labelled, never a job.
    let carved = of_type(&recs, "BitsCarvedFileTransfer");
    let urls: Vec<&str> = carved
        .iter()
        .map(|c| c["remote_url"].as_str().unwrap())
        .collect();
    assert!(
        urls.iter()
            .any(|u| u.starts_with("http://storage.googleapis.com/update-delta/")),
        "{urls:?}"
    );
    assert!(
        urls.iter()
            .any(|u| u.contains("gvt1.com/edgedl/release2/chrome")),
        "{urls:?}"
    );
    assert!(
        urls.iter().any(|u| u.starts_with("https://g.live.com/")),
        "{urls:?}"
    );
    for c in &carved {
        assert_eq!(c["recovery_method"], "database_byte_scan");
        assert!(c["page"].as_u64().is_some(), "{c:#?}");
    }
}

/// Every other ESE database reaches this module too and must produce nothing.
/// This one is committed (LoneWolf's SettingSync `meta.edb`, kept beside the
/// Search-index tests), so the guard runs on every clone and in CI.
#[test]
fn a_committed_non_bits_ese_database_produces_nothing() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("seance_plugin_winsearch_edb/tests/fixtures/ese_other/lonewolf_settingsync_meta.edb");
    let bytes = std::fs::read(&path).expect("the committed collision fixture");
    // It is a real ESE database libesedb opens, or the guard proves nothing.
    assert!(libesedb::EseDb::open(&path).is_ok());
    let recs: Vec<Value> =
        BitsParser::records_for_db(Uuid::new_v4(), Uuid::new_v4(), "meta.edb", &path, &bytes)
            .into_iter()
            .map(|a| a.metadata)
            .collect();
    assert!(recs.is_empty(), "meta.edb produced BITS records: {recs:#?}");
}

/// The same guard over the plaso reference copies, where a workstation has
/// them (`reference/` is not checked in; this skips elsewhere).
#[test]
fn srum_webcache_sum_and_search_databases_produce_nothing() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("reference/plaso/test_data");
    let mut ran = 0;
    for name in [
        "SRUDB.dat",
        "WebCacheV01.dat",
        "SystemIdentity.mdb",
        "Windows.edb",
    ] {
        let path = root.join(name);
        if !path.exists() {
            eprintln!("skipping {name}: reference/ is not checked in");
            continue;
        }
        ran += 1;
        let recs = db_records(&path);
        assert!(recs.is_empty(), "{name} produced BITS records: {recs:#?}");
    }
    eprintln!("{ran} collision database(s) checked");
}
