//! HUNT-188: every source in this crate must say when it could not look, and
//! must not make a claim about a file from a read that came back short.
//!
//! The doubles are the shared ones: a [`DribbleSource`] holds every byte and
//! hands them over a few at a time (a windowed image source does exactly this),
//! and a [`TruncatedSource`] declares more bytes than it can deliver.

use super::accounts::AndroidAccountsParser;
use super::bluetooth::AndroidBluetoothParser;
use super::telephony::AndroidTelephonyParser;
use super::AndroidPropertiesParser;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    module::ForensicsModule,
    test_support::{DribbleSource, TruncatedSource},
};
use serde_json::json;
use std::sync::Arc;

fn artifact_over(name: &str, data: Arc<dyn DataSource>) -> Artifact {
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": name, "path": format!("/data/test/{name}")}),
    )
}

fn sqlite_bytes(schema: &[&str]) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("seance-mobile-sr-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("db.sqlite");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for statement in schema {
            conn.execute_batch(statement).unwrap();
        }
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

fn accounts_db() -> Vec<u8> {
    sqlite_bytes(&[
        "PRAGMA user_version = 3;",
        "CREATE TABLE accounts (_id INTEGER PRIMARY KEY, name TEXT, type TEXT);",
        "INSERT INTO accounts (name, type) VALUES ('ada@gmail.com', 'com.google');",
    ])
}

// --- accounts ---------------------------------------------------------------

/// The SQLite-header probe was one unlooped `read_at`: a source that answers a
/// few bytes at a time filed a real accounts store as "does not begin with the
/// SQLite header".
#[test]
fn an_accounts_store_read_a_few_bytes_at_a_time_is_still_read() {
    let data: Arc<dyn DataSource> = Arc::new(DribbleSource::new(accounts_db(), 7));
    let out = AndroidAccountsParser::new()
        .process(&artifact_over("accounts_de.db", data))
        .expect("parsed");
    let record = out
        .iter()
        .find(|a| a.metadata["type"] == "MobileDeviceInfo")
        .expect("a record");
    assert_ne!(
        record.metadata["subtype"], "accounts_unreadable",
        "{:?}",
        record.metadata
    );
    assert_eq!(
        record.metadata["facts"]["google_account"][0],
        "ada@gmail.com"
    );
}

/// And a source that genuinely holds fewer than 16 bytes has not shown the file
/// is not SQLite: it has shown nothing. The record says the read was short.
#[test]
fn an_accounts_store_shorter_than_the_header_is_a_short_read_not_a_claim_about_the_file() {
    let data: Arc<dyn DataSource> =
        Arc::new(TruncatedSource::new(accounts_db()[..10].to_vec(), 4096));
    let out = AndroidAccountsParser::new()
        .process(&artifact_over("accounts_de.db", data))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["subtype"], "accounts_unreadable");
    assert_eq!(m["content_incomplete_reason"], "short_read", "{m:?}");
    let detail = m["content_incomplete_detail"].as_str().unwrap();
    assert!(
        !detail.contains("does not begin with the SQLite header"),
        "a short read is not evidence about the file's header: {detail}"
    );
}

// --- properties -------------------------------------------------------------

const BUILD_PROP: &str = "# begin build properties
ro.product.model=Pixel 3
ro.product.manufacturer=Google
ro.build.id=SP1A.210812.016
ro.serialno=8BGX1ABCD
";

/// One unlooped `read_at` took the first chunk only and stamped the rest as a
/// short read — on a source that held the whole file.
#[test]
fn a_property_file_read_a_few_bytes_at_a_time_is_read_whole() {
    let data: Arc<dyn DataSource> = Arc::new(DribbleSource::new(BUILD_PROP.as_bytes().to_vec(), 9));
    let out = AndroidPropertiesParser::new()
        .process(&artifact_over("build.prop", data))
        .expect("parsed");
    assert_eq!(out.len(), 1, "{out:?}");
    let m = &out[0].metadata;
    assert_eq!(m["facts"]["serial_number"], "8BGX1ABCD", "{m:?}");
    assert!(m.get("content_incomplete").is_none(), "{m:?}");
}

/// A file over the byte ceiling was stopped by this parser, not by the
/// source: `cap_reached`, never `short_read`.
#[test]
fn a_property_file_over_the_byte_ceiling_is_cap_reached_not_short_read() {
    let mut text = BUILD_PROP.to_string();
    // Comment padding: under the property-count cap, over the byte cap.
    while text.len() <= 1024 * 1024 {
        text.push_str("# padding padding padding padding padding padding padding padding\n");
    }
    text.push_str("ro.bootloader=b1c1-0.4-7617406\n");
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(text.into_bytes()));
    let out = AndroidPropertiesParser::new()
        .process(&artifact_over("build.prop", data))
        .expect("parsed");
    let m = &out[0].metadata;
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "cap_reached", "{m:?}");
    assert!(m["facts"].get("bootloader").is_none());
}

// --- Bluetooth --------------------------------------------------------------

const BT_CONFIG: &str = "[Adapter]
Address = 3c:28:6d:00:8e:c8

[d0:5f:b8:33:df:00]
Name = Moto 360 DF00
LinkKey = 38a5fb3db4e433040818f0fdaad037e2

[50:18:09:17:74:22]
Timestamp = 1644731632
Name = Mpow Flame
";

fn pairings(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == "BluetoothPairing")
        .collect()
}

/// One unlooped `read_at`: a source answering 16 bytes a time gave the parser
/// `[Adapter]\nAddress` and nothing else, and it reported no pairings at all.
#[test]
fn a_bt_config_read_a_few_bytes_at_a_time_is_read_whole() {
    let data: Arc<dyn DataSource> = Arc::new(DribbleSource::new(BT_CONFIG.as_bytes().to_vec(), 16));
    let out = AndroidBluetoothParser::new()
        .process(&artifact_over("bt_config.conf", data))
        .expect("parsed");
    assert_eq!(pairings(&out).len(), 2, "{out:?}");
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}

/// A truncated pairing list must not read as the whole list: every record says
/// the file was not read in full, and why.
#[test]
fn a_short_bt_config_says_so_on_every_record() {
    let bytes = BT_CONFIG.as_bytes();
    let cut = BT_CONFIG.find("[50:18").unwrap();
    let data: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(
        bytes[..cut].to_vec(),
        bytes.len() as u64,
    ));
    let out = AndroidBluetoothParser::new()
        .process(&artifact_over("bt_config.conf", data))
        .expect("parsed");
    assert_eq!(pairings(&out).len(), 1);
    assert!(!out.is_empty());
    for a in &out {
        assert_eq!(
            a.metadata["content_incomplete"],
            json!(true),
            "{:?}",
            a.metadata
        );
        assert_eq!(a.metadata["content_incomplete_reason"], "short_read");
    }
}

/// Over the 4 MiB ceiling the parser stopped, and says so.
#[test]
fn a_bt_config_over_the_byte_ceiling_says_cap_reached() {
    let mut text = BT_CONFIG.to_string();
    while text.len() <= 4 * 1024 * 1024 {
        text.push_str("# padding padding padding padding padding padding padding padding\n");
    }
    text.push_str("[11:22:33:44:55:66]\nName = Past the cap\n");
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(text.into_bytes()));
    let out = AndroidBluetoothParser::new()
        .process(&artifact_over("bt_config.conf", data))
        .expect("parsed");
    assert_eq!(pairings(&out).len(), 2);
    for a in &out {
        assert_eq!(a.metadata["content_incomplete_reason"], "cap_reached");
    }
}

// --- telephony --------------------------------------------------------------

fn telephony_marker(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata["subtype"] == "telephony_unreadable")
        .unwrap_or_else(|| panic!("the unread store must be declared: {out:?}"))
}

/// A `siminfo` whose column list will not read — here a view over a table
/// that has since gone — returned nothing, indistinguishable from a device
/// with no telephony store.
#[test]
fn a_telephony_store_whose_siminfo_cannot_be_listed_is_declared() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE s (_id INTEGER PRIMARY KEY, icc_id TEXT, number TEXT);",
        "CREATE VIEW siminfo AS SELECT _id, icc_id, number FROM s;",
        "DROP TABLE s;",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact_over(
            "telephony.db",
            Arc::new(ByteSliceDataSource::new(bytes)),
        ))
        .expect("parsed");
    let m = &telephony_marker(&out).metadata;
    assert_eq!(m["content_incomplete"], json!(true));
    assert!(m["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("siminfo"));
    assert!(!out
        .iter()
        .any(|a| a.metadata["subtype"] == "no_sim_recorded"));
}

/// A file named `telephony.db` that is not SQLite is still the name matched and
/// the store unread: declared, never silent.
#[test]
fn a_telephony_db_that_is_not_a_database_is_declared_unread() {
    let out = AndroidTelephonyParser::new()
        .process(&artifact_over(
            "telephony.db",
            Arc::new(ByteSliceDataSource::new(b"not a database".to_vec())),
        ))
        .expect("parsed");
    let _ = telephony_marker(&out);
}

/// A row the walk could not decode was dropped by `rows.flatten()` uncounted,
/// so one SIM out of three read as the device's whole SIM history. The view
/// raises an integer overflow on its second row — the step error a damaged page
/// gives — and rusqlite ends the walk there.
#[test]
fn a_sim_row_that_will_not_decode_is_counted_not_dropped() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE s (_id INTEGER PRIMARY KEY, icc_id TEXT, number TEXT);",
        "INSERT INTO s VALUES (1, '8944000000000000001', '+15551234567'), \
         (2, '8944000000000000002', '+15557654321'), \
         (3, '8944000000000000003', '+15550001111');",
        "CREATE VIEW siminfo AS SELECT _id, icc_id, \
         CASE WHEN _id = 2 THEN abs(-9223372036854775807 - 1) ELSE number END AS number FROM s;",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact_over(
            "telephony.db",
            Arc::new(ByteSliceDataSource::new(bytes)),
        ))
        .expect("parsed");
    let record = out
        .iter()
        .find(|a| a.metadata["source_kind"] == "android_telephony")
        .expect("the SIM that did decode is still reported");
    let m = &record.metadata;
    assert_eq!(m["sims_read"], 1, "{m:?}");
    assert!(m["rows_undecodable"].as_u64().unwrap() >= 1, "{m:?}");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
}

/// A WAL-mode store whose `-wal` could not be looked for is missing its newest
/// rows; `temp.wal_incomplete_reason()` was never consulted, so the SIM record
/// read as complete.
#[test]
fn a_telephony_store_whose_wal_could_not_be_reached_says_so() {
    let bytes = sqlite_bytes(&[
        "PRAGMA journal_mode = WAL;",
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE siminfo (_id INTEGER PRIMARY KEY, icc_id TEXT, number TEXT);",
        "INSERT INTO siminfo (icc_id, number) VALUES ('8944000000000000001', '+15551234567');",
    ]);
    assert_eq!(bytes[18], 2, "fixture is in WAL mode");
    let out = AndroidTelephonyParser::new()
        .process(&artifact_over(
            "telephony.db",
            Arc::new(ByteSliceDataSource::new(bytes)),
        ))
        .expect("parsed");
    let record = out
        .iter()
        .find(|a| a.metadata["source_kind"] == "android_telephony")
        .expect("a record");
    let m = &record.metadata;
    assert_eq!(m["content_incomplete"], json!(true), "{m:?}");
    assert!(m["wal_incomplete_reason"].is_string(), "{m:?}");
}
