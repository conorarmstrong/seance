//! The sources that answer "whose phone is this?" for the *owner* rather than
//! the handset: the settings the device holds about itself, the accounts signed
//! in to it, and the SIMs that carried its number.

use super::accounts::{is_accounts_db, AndroidAccountsParser};
use super::settings::{is_settings_file, AndroidSettingsParser};
use super::telephony::{is_telephony_db, AndroidTelephonyParser};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    module::ForensicsModule,
};
use serde_json::json;
use std::sync::Arc;

fn artifact(name: &str, bytes: Vec<u8>) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": name, "path": format!("/data/system/users/0/{name}")}),
    )
}

/// A settings document as the framework writes it.
const SETTINGS: &[u8] = br#"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<settings version="222">
  <setting id="2" name="device_name" value="Ada's Pixel" package="android" />
  <setting id="9" name="adb_enabled" value="1" package="android" />
  <setting id="14" name="auto_time" value="0" package="android" />
  <setting id="15" name="auto_time_zone" value="1" package="android" />
  <setting id="31" name="ringtone" value="content://media/1" package="android" />
</settings>
"#;

#[test]
fn the_settings_say_what_the_device_calls_itself() {
    let out = AndroidSettingsParser::new()
        .process(&artifact("settings_global.xml", SETTINGS.to_vec()))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "MobileDeviceInfo");
    assert_eq!(m["encoding"], "text");
    assert_eq!(m["facts"]["device_name"], "Ada's Pixel");
    assert_eq!(m["fact_sources"]["device_name"], "device_name");
    // A setting this build has no fact for is not invented into one.
    assert!(m["facts"].get("ringtone").is_none());
}

/// `auto_time = 0` means the clock was set by hand, which makes every timestamp
/// on the device an assertion by whoever set it. It belongs on the device
/// summary rather than in a file nobody opens.
#[test]
fn whether_the_clock_was_its_own_is_a_device_fact() {
    let out = AndroidSettingsParser::new()
        .process(&artifact("settings_global.xml", SETTINGS.to_vec()))
        .expect("parsed");
    let m = &out[0].metadata;
    assert_eq!(m["facts"]["clock_set_automatically"], "0");
    assert_eq!(m["facts"]["time_zone_set_automatically"], "1");
    assert_eq!(m["facts"]["adb_enabled"], "1");
}

#[test]
fn a_settings_shaped_name_holding_something_else_is_not_claimed() {
    let out = AndroidSettingsParser::new()
        .process(&artifact(
            "settings_global.xml",
            b"<?xml version='1.0'?><preferences><pref name='x' value='1'/></preferences>".to_vec(),
        ))
        .expect("parsed");
    assert!(
        out.is_empty(),
        "no <setting> elements: not the framework's file"
    );
}

#[test]
fn the_settings_files_the_framework_writes_are_recognised() {
    for name in [
        "settings_global.xml",
        "settings_secure.xml",
        "settings_system.xml",
        "SETTINGS_GLOBAL.XML",
    ] {
        assert!(is_settings_file(name), "{name}");
    }
    assert!(!is_settings_file("settings.xml"));
    assert!(is_accounts_db("accounts_de.db"));
    assert!(is_accounts_db("accounts_ce.db"));
    assert!(!is_accounts_db("accounts.db"));
    assert!(is_telephony_db("telephony.db"));
    assert!(!is_telephony_db("telephony.db-wal"));
}

/// Build a SQLite file in memory and hand its bytes to the parser, the way the
/// filesystem readers hand a file's content over.
fn sqlite_bytes(schema: &[&str]) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("seance-mobile-{}", uuid::Uuid::new_v4()));
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

#[test]
fn the_accounts_store_names_the_person_the_phone_belongs_to() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 3;",
        "CREATE TABLE accounts (_id INTEGER PRIMARY KEY, name TEXT, type TEXT);",
        "INSERT INTO accounts (name, type) VALUES \
         ('ada@gmail.com', 'com.google'), \
         ('ada.work@gmail.com', 'com.google'), \
         ('+15551234567', 'com.whatsapp');",
    ]);
    let out = AndroidAccountsParser::new()
        .process(&artifact("accounts_de.db", bytes))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;

    // Both Google accounts, in order, as a multi-valued fact.
    assert_eq!(
        m["facts"]["google_account"],
        json!(["ada@gmail.com", "ada.work@gmail.com"])
    );
    // And every account, with the authenticator that owns it: an app account
    // can be the identity a case turns on.
    assert_eq!(m["facts"]["account"][2], "+15551234567 (com.whatsapp)");
    assert_eq!(m["accounts_read"], 3);
}

/// "Nobody was signed in" and "we could not read who was" are different answers
/// to the only question this file exists to answer.
#[test]
fn an_accounts_store_that_will_not_open_says_so() {
    let out = AndroidAccountsParser::new()
        .process(&artifact(
            "accounts_de.db",
            b"not a database at all".to_vec(),
        ))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["subtype"], "accounts_unreadable");
    assert_eq!(out[0].metadata["content_incomplete"], json!(true));
    assert!(out[0].metadata["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("SQLite header"));
}

/// A real SQLite database that simply is not this store is NOT claimed — and is
/// not reported as an unreadable accounts store either, which would put a
/// shortfall on a case that has none.
#[test]
fn a_sqlite_file_that_is_not_the_accounts_store_is_left_alone() {
    let bytes = sqlite_bytes(&["CREATE TABLE something_else (a TEXT);"]);
    let out = AndroidAccountsParser::new()
        .process(&artifact("accounts_de.db", bytes))
        .expect("parsed");
    assert!(out.is_empty());
}

#[test]
fn the_sim_records_carry_the_phones_own_number() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE siminfo (_id INTEGER PRIMARY KEY, icc_id TEXT, number TEXT, \
         display_name TEXT, carrier_name TEXT);",
        "INSERT INTO siminfo (icc_id, number, display_name, carrier_name) VALUES \
         ('8944000000000000001', '+15551234567', 'Personal', 'Carrier A'), \
         ('8944000000000000002', '+15557654321', 'Work', 'Carrier B');",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact("telephony.db", bytes))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["sims_read"], 2);
    assert_eq!(
        m["facts"]["phone_number"],
        json!(["+15551234567", "+15557654321"])
    );
    assert_eq!(m["facts"]["iccid"][0], "8944000000000000001");
    assert_eq!(m["fact_sources"]["phone_number"], "siminfo.number");
}

/// The column set has changed across Android versions. A `SELECT` naming a
/// column this device does not have fails whole — and the phone's number would
/// then read as absent because an unrelated column was renamed. Optional
/// columns (`imsi`, absent from the real validated store) go without comment;
/// a required one going is declared, in
/// `a_siminfo_table_without_the_number_column_declares_the_field_unresolved`.
#[test]
fn a_table_missing_some_columns_still_yields_the_ones_it_has() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE siminfo (_id INTEGER PRIMARY KEY, icc_id TEXT, number TEXT);",
        "INSERT INTO siminfo (icc_id, number) VALUES ('8944000000000000003', '+15550001111');",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact("telephony.db", bytes))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["facts"]["iccid"][0], "8944000000000000003");
    assert!(out[0].metadata["facts"].get("carrier").is_none());
    assert!(out[0].metadata["facts"].get("imsi").is_none());
}

/// A device that never had a SIM is a finding. Emitting nothing would read as
/// "not examined", which is a different statement.
#[test]
fn a_device_with_no_sim_record_says_so() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE siminfo (_id INTEGER PRIMARY KEY, icc_id TEXT, number TEXT);",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact("telephony.db", bytes))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["subtype"], "no_sim_recorded");
    assert_eq!(out[0].metadata["sims_read"], 0);
}

// --- Schema-drift defence (ROADMAP §1.4a) -------------------------------------

/// The stale-warning marker a parse emitted, if any.
fn stale_marker(out: &[Artifact]) -> Option<&Artifact> {
    out.iter()
        .find(|a| a.metadata["type"] == "ParserStaleWarning")
}

/// `accounts_de.db` was validated against one real store, `PRAGMA
/// user_version` 3 (android2022, Android 12). A store carrying a version this
/// parser never saw is still parsed, and the parse says the version is outside
/// what was validated rather than presenting the account list as checked.
#[test]
fn an_accounts_store_with_a_newer_schema_version_is_parsed_and_declared_stale() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 9;",
        "CREATE TABLE accounts (_id INTEGER PRIMARY KEY, name TEXT, type TEXT);",
        "INSERT INTO accounts (name, type) VALUES ('ada@gmail.com', 'com.google');",
    ]);
    let out = AndroidAccountsParser::new()
        .process(&artifact("accounts_de.db", bytes))
        .expect("parsed");
    let record = out
        .iter()
        .find(|a| a.metadata["source_kind"] == "android_accounts")
        .expect("the accounts are still read");
    assert_eq!(
        record.metadata["facts"]["google_account"][0],
        "ada@gmail.com"
    );
    let stale = stale_marker(&out).expect("a version outside the validated range is declared");
    assert_eq!(stale.metadata["seen_schema_version"], 9);
    assert_eq!(stale.metadata["supported_range"], "3..=3");
    // §1.4a (decided 2026-09-26): outside the range is a disclosure.
    assert_eq!(stale.metadata["status"], "SchemaOutsideValidated");
    assert!(stale.metadata.get("content_incomplete").is_none());
    assert!(stale.metadata.get("content_incomplete_reason").is_none());
    assert!(stale.metadata["message"]
        .as_str()
        .unwrap()
        .contains("NEWER"));
}

/// The two AccountManager stores carry different versions (3 for the
/// device-encrypted store, 10 for the credential-encrypted one, both measured on
/// the same real device), so the range is declared per file, not per parser.
#[test]
fn each_accounts_store_is_checked_against_its_own_validated_version() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 10;",
        "CREATE TABLE accounts (_id INTEGER PRIMARY KEY, name TEXT, type TEXT, password TEXT);",
        "INSERT INTO accounts (name, type) VALUES ('ada@gmail.com', 'com.google');",
    ]);
    let out = AndroidAccountsParser::new()
        .process(&artifact("accounts_ce.db", bytes))
        .expect("parsed");
    assert!(
        stale_marker(&out).is_none(),
        "version 10 is the validated version of accounts_ce.db"
    );
}

/// The framework always stamps `user_version` on this store; a 0 is SQLite's
/// unset default and is not a version. It is never compared against the range
/// as if it were older than 3 — that would be a finding manufactured from an
/// absence — but the absence itself is stated.
#[test]
fn an_accounts_store_with_no_recorded_version_is_not_called_older() {
    let bytes = sqlite_bytes(&[
        "CREATE TABLE accounts (_id INTEGER PRIMARY KEY, name TEXT, type TEXT);",
        "INSERT INTO accounts (name, type) VALUES ('ada@gmail.com', 'com.google');",
    ]);
    let out = AndroidAccountsParser::new()
        .process(&artifact("accounts_de.db", bytes))
        .expect("parsed");
    let stale = stale_marker(&out).expect("the missing version is stated");
    assert_eq!(stale.metadata["status"], "SchemaVersionNotRecorded");
    assert!(stale.metadata.get("seen_schema_version").is_none());
    assert!(
        !stale.metadata["message"]
            .as_str()
            .unwrap()
            .contains("OLDER"),
        "0 is not a version and must not be ranked against the range"
    );
}

/// A renamed column is the drift this defence exists for. The `name` column
/// carries the account itself; when no candidate resolves it, the parse says
/// which logical field is unresolved rather than listing every account as
/// undecodable.
#[test]
fn a_renamed_accounts_column_is_named_on_the_stale_marker() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 3;",
        "CREATE TABLE accounts (_id INTEGER PRIMARY KEY, account_name TEXT, type TEXT);",
        "INSERT INTO accounts (account_name, type) VALUES ('ada@gmail.com', 'com.google');",
    ]);
    let out = AndroidAccountsParser::new()
        .process(&artifact("accounts_de.db", bytes))
        .expect("parsed");
    let stale = stale_marker(&out).expect("an unresolved required field is declared");
    assert_eq!(stale.metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(stale.metadata["unresolved_fields"], json!(["name"]));
    assert_eq!(stale.metadata["store"], "accounts_de.db");
    assert_eq!(stale.metadata["content_incomplete"], json!(true));
    assert_eq!(stale.metadata["content_incomplete_reason"], "unvalidated");
    assert!(stale.metadata["present_columns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "account_name"));

    // The device record beside the marker must attribute the loss to the
    // column, not the rows: the row decoded, the field did not resolve.
    // "Could not be decoded" over an intact row sends an examiner looking for
    // corruption that is not there.
    let record = out
        .iter()
        .find(|a| a.metadata["source_kind"] == "android_accounts")
        .expect("the device record is still emitted");
    let m = &record.metadata;
    assert_eq!(m["accounts_read"], json!(0));
    assert_eq!(m["rows_undecodable"], json!(0), "{m}");
    assert_eq!(m["rows_field_unresolved"], json!(1), "{m}");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "unvalidated", "{m}");
    let detail = m["content_incomplete_detail"].as_str().unwrap();
    assert!(detail.contains("name"), "{detail}");
    assert!(detail.contains("no column"), "{detail}");
    assert!(!detail.contains("could not be decoded"), "{detail}");
}

/// A row whose `name` is NULL or empty on a store whose columns DID resolve is
/// a row this parser cannot list, and that is still "could not be decoded"
/// under `unresolved_structure` — the two counts are kept apart.
#[test]
fn a_null_name_on_a_resolved_column_is_an_undecodable_row_not_an_unresolved_field() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 3;",
        "CREATE TABLE accounts (_id INTEGER PRIMARY KEY, name TEXT, type TEXT);",
        "INSERT INTO accounts (name, type) VALUES ('ada@gmail.com', 'com.google');",
        "INSERT INTO accounts (name, type) VALUES (NULL, 'com.google');",
    ]);
    let out = AndroidAccountsParser::new()
        .process(&artifact("accounts_de.db", bytes))
        .expect("parsed");
    assert!(stale_marker(&out).is_none(), "{out:?}");
    let record = out
        .iter()
        .find(|a| a.metadata["source_kind"] == "android_accounts")
        .expect("the device record is emitted");
    let m = &record.metadata;
    assert_eq!(m["accounts_read"], json!(1));
    assert_eq!(m["rows_undecodable"], json!(1));
    assert_eq!(m["rows_field_unresolved"], json!(0));
    assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
    assert!(m["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("could not be decoded"));
}

/// `telephony.db` was validated against one real store (`user_version`
/// 1703944, android2022). `imsi` is absent from that store and is optional; the
/// number and the ICCID are what a SIM record is, and losing either is declared.
#[test]
fn a_siminfo_table_without_the_number_column_declares_the_field_unresolved() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE siminfo (_id INTEGER PRIMARY KEY, icc_id TEXT);",
        "INSERT INTO siminfo (icc_id) VALUES ('8944000000000000003');",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact("telephony.db", bytes))
        .expect("parsed");
    let record = out
        .iter()
        .find(|a| a.metadata["source_kind"] == "android_telephony")
        .expect("the SIM is still read");
    assert_eq!(record.metadata["facts"]["iccid"][0], "8944000000000000003");
    let stale = stale_marker(&out).expect("the missing number column is declared");
    assert_eq!(stale.metadata["status"], "SchemaFieldsUnresolved");
    assert_eq!(stale.metadata["unresolved_fields"], json!(["number"]));
}

#[test]
fn a_telephony_store_outside_the_validated_version_is_parsed_and_declared_stale() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1900000;",
        "CREATE TABLE siminfo (_id INTEGER PRIMARY KEY, icc_id TEXT, number TEXT);",
        "INSERT INTO siminfo (icc_id, number) VALUES ('8944000000000000001', '+15551234567');",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact("telephony.db", bytes))
        .expect("parsed");
    assert!(out
        .iter()
        .any(|a| a.metadata["facts"]["phone_number"][0] == "+15551234567"));
    let stale = stale_marker(&out).expect("declared");
    assert_eq!(stale.metadata["seen_schema_version"], 1900000);
    assert_eq!(stale.metadata["supported_range"], "1703944..=1703944");
}

/// A store at the validated version with every column present owes nothing.
#[test]
fn a_telephony_store_at_the_validated_version_carries_no_stale_marker() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE siminfo (_id INTEGER PRIMARY KEY, icc_id TEXT, number TEXT, \
         display_name TEXT, carrier_name TEXT);",
        "INSERT INTO siminfo (icc_id, number) VALUES ('8944000000000000001', '+15551234567');",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact("telephony.db", bytes))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    assert!(stale_marker(&out).is_none());
}

/// HUNT-212: a SIM `number` held as an INTEGER failed the string read and was
/// published as absent, without comment. The real Pixel store declares
/// `number TEXT` (whose affinity turns a number into text on insert), so this
/// arises on a `siminfo` whose `number` column carries no declared type.
#[test]
fn a_sim_number_stored_as_an_integer_is_rendered_not_absent() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE siminfo (_id INTEGER PRIMARY KEY, icc_id TEXT NOT NULL, number, \
         display_name TEXT, carrier_name TEXT);",
        "INSERT INTO siminfo (icc_id, number) VALUES ('8944000000000000004', 15551234567);",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact("telephony.db", bytes))
        .expect("parsed");
    assert_eq!(out.len(), 1, "{out:?}");
    let m = &out[0].metadata;
    assert_eq!(m["facts"]["phone_number"], json!(["15551234567"]), "{m}");
    assert!(m.get("content_incomplete").is_none(), "{m}");
}

/// HUNT-212, the value that cannot be rendered as text: a BLOB `number` is a
/// value the device held and this reader will not guess an encoding for. It
/// is stated on the record, never published as absent.
#[test]
fn a_sim_number_stored_as_a_blob_is_stated_not_absent() {
    let bytes = sqlite_bytes(&[
        "PRAGMA user_version = 1703944;",
        "CREATE TABLE siminfo (_id INTEGER PRIMARY KEY, icc_id TEXT NOT NULL, number, \
         display_name TEXT, carrier_name TEXT);",
        "INSERT INTO siminfo (icc_id, number) VALUES ('8944000000000000005', X'FF00FF');",
    ]);
    let out = AndroidTelephonyParser::new()
        .process(&artifact("telephony.db", bytes))
        .expect("parsed");
    let m = &out[0].metadata;
    assert!(m["facts"].get("phone_number").is_none(), "{m}");
    assert_eq!(m["values_not_rendered"]["siminfo.number"], 1, "{m}");
    assert_eq!(m["content_incomplete"], true, "{m}");
}
