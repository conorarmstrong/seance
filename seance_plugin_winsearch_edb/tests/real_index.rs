//! Known answers from real Search indexes. The indexes are large and are
//! not committed; each test reads one through an environment variable and
//! skips, saying so, when it is unset. The collision guard runs on committed
//! non-index ESE databases and always runs.

use seance_plugin_winsearch_edb::WinSearchParser;
use serde_json::Value;
use std::path::{Path, PathBuf};
use uuid::Uuid;

fn records(path: &Path) -> Vec<Value> {
    records_named(path, "Windows.edb")
}

/// Under the file's own name: a database named like the index but lacking
/// its table is refused by name, so the collision guard uses real names.
fn records_named(path: &Path, name: &str) -> Vec<Value> {
    let bytes = std::fs::read(path).expect("read database");
    WinSearchParser::records_for_db(Uuid::new_v4(), Uuid::new_v4(), name, path, &bytes)
        .into_iter()
        .map(|a| a.metadata)
        .collect()
}

fn items(recs: &[Value]) -> Vec<&Value> {
    recs.iter()
        .filter(|r| r["type"] == "WindowsSearchItem")
        .collect()
}

fn by_path<'a>(recs: &'a [Value], path: &str) -> &'a Value {
    recs.iter()
        .find(|r| r["type"] == "WindowsSearchItem" && r["path"] == path)
        .unwrap_or_else(|| panic!("no item {path}"))
}

#[test]
fn the_data_leakage_index_names_indexed_files_with_paths_and_times() {
    let Ok(p) = std::env::var("SEANCE_CFREDS_WINDOWS_EDB") else {
        eprintln!("SEANCE_CFREDS_WINDOWS_EDB unset; the Windows 7 index check did not run");
        return;
    };
    let recs = records(Path::new(&p));
    assert_eq!(items(&recs).len(), 464);

    // Cross-checked against the file on the image (istat, MFT entry 62436):
    // $DATA size 55,915,216; $SI created 15:11:04.0873339, modified 15:11:04.8517352.
    let ie = by_path(
        &recs,
        r"C:\Users\informant\Desktop\Download\IE11-Windows6.1-x64-en-us.exe",
    );
    let p = &ie["properties"];
    assert_eq!(p["System_Size"], 55_915_216);
    assert_eq!(p["System_DateCreated"], "2015-03-22T15:11:04.087333900Z");
    assert_eq!(p["System_DateModified"], "2015-03-22T15:11:04.851735200Z");
    assert_eq!(ie["schema_variant"], "windows7_systemindex_0a");

    // A mail item from the spy, with its summary decoded from the encoded form.
    let mail = by_path(
        &recs,
        "/iaman.informant@nist.gov/Inbox/RE: Good job, buddy.",
    );
    let m = &mail["properties"];
    assert_eq!(m["System_Message_FromName"], "spy");
    assert_eq!(m["System_Message_ToAddress"], "iaman.informant@nist.gov");
    assert!(m["System_Search_AutoSummary"]
        .as_str()
        .unwrap()
        .starts_with("Okay, I got it. I\u{2019}ll be in touch."));

    // The exchange NIST's answer key quotes ("Umm... I need time to think." in
    // reply to "I confirmed it. But, I need a more data. Do your best.").
    let reply = by_path(
        &recs,
        "/iaman.informant@nist.gov/Sent Items/RE: Important request",
    );
    let s = reply["properties"]["System_Search_AutoSummary"]
        .as_str()
        .unwrap();
    assert!(s.starts_with("Umm\u{2026}.. I need time to think."), "{s}");
    assert!(s.contains("I need time to think."), "{s}");
    assert!(
        s.contains("I confirmed it.  But, I need a more data.  Do your best."),
        "{s}"
    );
    assert_eq!(reply["properties"]["System_Message_FromName"], "iaman");

    // The compressed summaries are named, never rendered.
    let undecoded: Vec<&Value> = items(&recs)
        .into_iter()
        .flat_map(|i| i["properties_not_decoded"].as_array().unwrap().iter())
        .filter(|n| n["property"] == "System_Search_AutoSummary")
        .collect();
    assert_eq!(undecoded.len(), 10, "types 2 and 3");
    assert!(undecoded
        .iter()
        .all(|n| n["reason"].as_str().unwrap().contains("not decode")));

    // A folder's size is not set, never 0x2A2A2A2A2A2A2A2A.
    let users = by_path(&recs, r"C:\Users");
    assert!(users["properties"].get("System_Size").is_none());

    let summary: Vec<&Value> = recs
        .iter()
        .filter(|r| r["type"] == "WindowsSearchIndex")
        .collect();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["items"], 464);
    assert_eq!(summary[0]["database_state"], "dirty_shutdown");
    assert_eq!(summary[0]["content_incomplete"], true);
}

#[test]
fn the_lone_wolf_index_reads_the_property_store_table() {
    let Ok(p) = std::env::var("SEANCE_LONEWOLF_WINDOWS_EDB") else {
        eprintln!("SEANCE_LONEWOLF_WINDOWS_EDB unset; the Windows 10 index check did not run");
        return;
    };
    let recs = records(Path::new(&p));
    assert_eq!(items(&recs).len(), 822);
    let nt = by_path(&recs, r"C:\Users\Default\NTUSER.DAT");
    assert_eq!(nt["schema_variant"], "windows10_propertystore");
    assert_eq!(nt["properties"]["System_Size"], 262_144);
    assert!(nt["properties"]["System_DateModified"]
        .as_str()
        .unwrap()
        .starts_with("2018-"));
}

/// Other ESE databases reach this module and must yield nothing. These two
/// are committed — LoneWolf's SettingSync `meta.edb` and its BITS `qmgr.db` —
/// so the guard runs on every clone and in CI.
#[test]
fn committed_non_index_ese_databases_produce_nothing() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for path in [
        root.join("tests/fixtures/ese_other/lonewolf_settingsync_meta.edb"),
        root.parent()
            .unwrap()
            .join("seance_plugin_bits/tests/fixtures/qmgr_db/lonewolf_qmgr.db"),
    ] {
        assert!(
            path.exists(),
            "committed fixture missing: {}",
            path.display()
        );
        // A real ESE database libesedb opens, or the guard proves nothing.
        assert!(libesedb::EseDb::open(&path).is_ok(), "{}", path.display());
        let name = path.file_name().unwrap().to_string_lossy();
        let recs = records_named(&path, &name);
        assert!(
            recs.is_empty(),
            "{} produced Search records",
            path.display()
        );
    }
}

/// The same guard over the plaso reference copies, where a workstation has
/// them (`reference/` is not checked in; this skips elsewhere).
#[test]
fn srum_webcache_and_ual_databases_produce_nothing() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("reference/plaso/test_data");
    let mut ran = 0;
    for name in ["SRUDB.dat", "WebCacheV01.dat", "SystemIdentity.mdb"] {
        let path = root.join(name);
        if !path.exists() {
            eprintln!("skipping {name}: reference/ is not checked in");
            continue;
        }
        ran += 1;
        assert!(
            records_named(&path, name).is_empty(),
            "{name} produced Search records"
        );
    }
    eprintln!("{ran} collision database(s) checked");
}

#[test]
fn the_lone_wolf_count_is_stated_as_a_floor() {
    let Ok(p) = std::env::var("SEANCE_LONEWOLF_WINDOWS_EDB") else {
        eprintln!("SEANCE_LONEWOLF_WINDOWS_EDB unset; the Windows 10 index check did not run");
        return;
    };
    let recs = records(Path::new(&p));
    let s: Vec<&Value> = recs
        .iter()
        .filter(|r| r["type"] == "WindowsSearchIndex")
        .collect();
    let why = s[0]["content_incomplete_reason"].as_str().unwrap();
    assert!(why.contains("a floor"), "{why}");
    assert!(why.contains("dirty shutdown"), "{why}");
}

/// The same index through `process`, which stages the database in chunks and
/// keeps only its header in memory: the reading must not change.
#[test]
fn the_data_leakage_index_reads_the_same_through_chunked_staging() {
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::module::ForensicsModule;
    let Ok(p) = std::env::var("SEANCE_CFREDS_WINDOWS_EDB") else {
        eprintln!("SEANCE_CFREDS_WINDOWS_EDB unset; the chunked-staging check did not run");
        return;
    };
    let ds: std::sync::Arc<dyn DataSource> =
        std::sync::Arc::new(ByteSliceDataSource::new(std::fs::read(&p).unwrap()));
    let a = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": "Windows.edb" }),
    );
    let recs: Vec<Value> = WinSearchParser::new()
        .process(&a)
        .unwrap()
        .into_iter()
        .map(|a| a.metadata)
        .collect();
    assert_eq!(
        items(&recs).len(),
        464,
        "{:#?}",
        recs.iter()
            .filter(|r| r["type"] != "WindowsSearchItem")
            .collect::<Vec<_>>()
    );
    let s: Vec<&Value> = recs
        .iter()
        .filter(|r| r["type"] == "WindowsSearchIndex")
        .collect();
    assert_eq!(s[0]["database_state"], "dirty_shutdown");
}
