//! Known answers from real BITS queue files.
//!
//! The committed fixtures are the first 8 KiB of the NIST CFReDS Data Leakage
//! PC's `qmgr0.dat` and `qmgr1.dat` (Windows 7); every byte past the cut is zero
//! on the image (`tests/fixtures/qmgr/README.md`). The whole files, and DFIR
//! Madness DC01's Server 2012 R2 queue (not redistributable, so not committed),
//! are reached through environment variables; the tests that need them skip
//! and say so when they are unset.

use seance_plugin_bits::qmgr_dat;
use seance_plugin_bits::BitsParser;
use serde_json::Value;
use uuid::Uuid;

const QMGR0: &[u8] = include_bytes!("fixtures/qmgr/data_leakage_qmgr0.dat.head8k");
const QMGR1: &[u8] = include_bytes!("fixtures/qmgr/data_leakage_qmgr1.dat.head8k");

const OWNER: &str = "S-1-5-21-2425377081-3129163575-2985601102-1000";
const DOTNET_URL: &str = "http://go.microsoft.com/fwlink/?LinkId=164181&clcid=0x409";

fn records(name: &str, bytes: &[u8]) -> Vec<Value> {
    BitsParser::records_for(Uuid::new_v4(), Uuid::new_v4(), name, bytes)
        .into_iter()
        .map(|a| a.metadata)
        .collect()
}

fn of_type<'a>(recs: &'a [Value], t: &str) -> Vec<&'a Value> {
    recs.iter().filter(|r| r["type"] == t).collect()
}

/// A carved record's source must be a transfer source, never the volume field
/// (`\\?\Volume{...}\`) that sits later in every file record.
fn assert_no_volume_path_taken_as_a_source(recs: &[Value]) {
    for c in of_type(recs, "BitsCarvedFileTransfer") {
        let url = c["remote_url"].as_str().unwrap();
        assert!(
            !url.starts_with(r"\\?\"),
            "volume path carved as a source: {c:#?}"
        );
        assert!(c["temp_path"].as_str().unwrap().contains('\\'), "{c:#?}");
    }
}

fn assert_qmgr1(recs: &[Value]) {
    assert_no_volume_path_taken_as_a_source(recs);
    let jobs = of_type(recs, "BitsJob");
    assert_eq!(
        jobs.len(),
        1,
        "qmgr1.dat's live queue holds one job: {recs:#?}"
    );
    let job = jobs[0];
    assert_eq!(job["job_name"], "Setup Installer");
    assert_eq!(job["job_id"], "{7B403240-D166-4C09-958A-23774DF1F57A}");
    assert_eq!(job["owner_sid"], OWNER);
    assert_eq!(job["job_type_name"], "download");
    assert_eq!(job["state_name"], "transferred");
    assert_eq!(job["file_count"], 1);
    let f = &job["files"][0];
    assert_eq!(f["remote_url"], DOTNET_URL);
    assert!(f["local_path"]
        .as_str()
        .unwrap()
        .ends_with(r"Microsoft .NET Framework 4 Setup_4.0.30319\TMP72E4.tmp"));
    assert!(f["temp_path"].as_str().unwrap().ends_with(r"\BIT7308.tmp"));
    assert_eq!(f["bytes_transferred"], 872_448);
    assert_eq!(f["bytes_total"], 872_448);
    assert_eq!(job["creation_time"], "2015-03-25T14:50:55.671405500+00:00");
    assert_eq!(
        job["modification_time"],
        "2015-03-25T14:50:56.357805500+00:00"
    );
    assert!(
        job.get("transfer_completion_time").is_none(),
        "not a name this reader can defend"
    );
    // Credentials are DPAPI blobs: present, never decrypted.
    assert_eq!(job["credentials_present"], true);
    assert_eq!(job["secrets_decrypted"], false);
    for blob in job["dpapi_blobs"].as_array().unwrap() {
        assert_eq!(blob["description"], "BITS job credentials");
    }

    // The Outlook offline-address-book transfers survive only past the live
    // structure: carved, labelled, never a job.
    let carved = of_type(recs, "BitsCarvedFileTransfer");
    assert_eq!(carved.len(), 2, "diff1867 and diff1868 only: {carved:#?}");
    let oab: Vec<&&Value> = carved
        .iter()
        .filter(|c| {
            c["remote_url"]
                .as_str()
                .unwrap()
                .starts_with("https://outlook.office365.com/OAB/")
        })
        .collect();
    assert!(!oab.is_empty(), "{carved:#?}");
    for c in &oab {
        assert_eq!(c["recovery_method"], "stale_region_carve");
        assert!(c["local_path"]
            .as_str()
            .unwrap()
            .contains(r"\Offline Address Books\"));
    }
    let targets: Vec<&str> = oab
        .iter()
        .map(|c| {
            c["local_path"]
                .as_str()
                .unwrap()
                .rsplit('\\')
                .next()
                .unwrap()
        })
        .collect();
    assert!(targets.contains(&"diff1868.tm_"), "{targets:?}");

    let summary = of_type(recs, "BitsQueueFile");
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["status"], "queue read, 1 job(s)");
    assert!(summary[0].get("content_incomplete").is_none());
}

fn assert_qmgr0(recs: &[Value]) {
    assert_no_volume_path_taken_as_a_source(recs);
    assert!(
        of_type(recs, "BitsJob").is_empty(),
        "qmgr0.dat's live queue is empty"
    );
    let summary = of_type(recs, "BitsQueueFile");
    assert_eq!(summary[0]["status"], "queue read, 0 job(s)");
    let carved = of_type(recs, "BitsCarvedFileTransfer");
    assert_eq!(
        carved.len(),
        3,
        ".NET, diff1867 and diff1868 only: {carved:#?}"
    );
    let urls: Vec<&str> = carved
        .iter()
        .map(|c| c["remote_url"].as_str().unwrap())
        .collect();
    assert!(urls.contains(&DOTNET_URL), "{urls:?}");
    let targets: Vec<&str> = carved
        .iter()
        .map(|c| {
            c["local_path"]
                .as_str()
                .unwrap()
                .rsplit('\\')
                .next()
                .unwrap()
        })
        .collect();
    assert!(targets.contains(&"diff1867.tm_"), "{targets:?}");
    assert!(targets.contains(&"diff1868.tm_"), "{targets:?}");
}

#[test]
fn the_data_leakage_queue_yields_the_dotnet_and_outlook_oab_jobs() {
    assert_qmgr1(&records("qmgr1.dat", QMGR1));
    assert_qmgr0(&records("qmgr0.dat", QMGR0));
}

#[test]
fn the_fixture_cut_loses_nothing_the_whole_file_holds() {
    let Ok(dir) = std::env::var("SEANCE_CFREDS_QMGR_DIR") else {
        eprintln!("SEANCE_CFREDS_QMGR_DIR unset; the whole-file check did not run");
        return;
    };
    let dir = std::path::Path::new(&dir);
    let q1 = std::fs::read(dir.join("qmgr1.dat")).expect("qmgr1.dat");
    let q0 = std::fs::read(dir.join("qmgr0.dat")).expect("qmgr0.dat");
    assert_eq!(q1.len(), 4_194_304);
    assert_qmgr1(&records("qmgr1.dat", &q1));
    assert_qmgr0(&records("qmgr0.dat", &q0));
    assert_eq!(qmgr_dat::parse(&q1), qmgr_dat::parse(QMGR1));
}

#[test]
fn the_dc01_server_2012_r2_queue_reads_as_empty_not_unparsed() {
    let Ok(path) = std::env::var("SEANCE_DC01_QMGR") else {
        eprintln!("SEANCE_DC01_QMGR unset; the Server 2012 R2 check did not run");
        return;
    };
    let bytes = std::fs::read(path).expect("DC01 qmgr0.dat");
    let recs = records("qmgr0.dat", &bytes);
    assert!(
        of_type(&recs, "BitsQueueIncomplete").is_empty(),
        "{recs:#?}"
    );
    let summary = of_type(&recs, "BitsQueueFile");
    assert_eq!(summary.len(), 1, "{recs:#?}");
    assert_eq!(summary[0]["status"], "queue read, 0 job(s)");
    assert_eq!(
        summary[0]["file_guid"],
        "{09ED3228-C7A6-45E9-8F6D-36D946C27C3E}"
    );
    assert_eq!(summary[0]["carved_file_transfers"], 0);
}
