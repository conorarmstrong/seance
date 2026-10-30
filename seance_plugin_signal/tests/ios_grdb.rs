//! HUNT-227: the Signal for iOS store opens with a key spec an examiner
//! supplies for that one file, and Signal-iOS's GRDB schema is read.
//!
//! Two layers, because the one real store held has no messages:
//!
//! - **Synthetic, always run.** A GRDB-shaped database — the table and column
//!   names are those of the real store (`model_TSInteraction`, `model_TSThread`,
//!   `model_SignalRecipient`, `model_OWSUserProfile`, `grdb_migrations`) —
//!   with rows in it, written by SQLite with Signal's 80 reserved bytes per page
//!   and encrypted by this project's SQLCipher 4 test encryptor. It proves the
//!   reader turns rows into records; it proves nothing about Signal's own row
//!   contents.
//! - **Real, gated on `SEANCE_IOS_SIGNAL_DIR`** (see
//!   `seance_sqlcipher/tests/signal_ios_real_store.rs` for provisioning). The
//!   Magnet 2022 iPhone 8 store, keyed by the spec from its own keychain export.
//!   It holds no messages, so what it grades is structural: every page and WAL
//!   frame authenticates, the GRDB tables and the columns this reader resolves
//!   are there, and the counts match an independent reading.

use rusqlite::{ffi, Connection};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
use seance_core::data_source::{ByteSliceDataSource, DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_signal::SignalParser;
use seance_sqlcipher::{encrypt_v4_raw_key_for_test, SqlCipher4Config};
use serde_json::{json, Value};
use std::sync::Arc;

const KEY: [u8; 32] = [0x42; 32];
const SALT: [u8; 16] = [0x17; 16];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn key_spec_literal() -> String {
    format!("x'{}{}'", hex(&KEY), hex(&SALT))
}

/// A GRDB-shaped Signal store with 80 reserved bytes per page, as plaintext.
fn grdb_plaintext() -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("seance-grdb-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("plain.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA page_size=4096;").unwrap();
    let mut reserve: std::os::raw::c_int = 80;
    // SAFETY: a valid open handle, the "main" schema, and a pointer to an int
    // that outlives the call — the contract of SQLITE_FCNTL_RESERVE_BYTES.
    let rc = unsafe {
        ffi::sqlite3_file_control(
            conn.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_RESERVE_BYTES,
            &mut reserve as *mut _ as *mut std::os::raw::c_void,
        )
    };
    assert_eq!(rc, ffi::SQLITE_OK);
    conn.execute_batch(
        "CREATE TABLE grdb_migrations (identifier TEXT NOT NULL PRIMARY KEY);
         INSERT INTO grdb_migrations VALUES ('createInitialSchema'), ('uploadTimestamp');
         CREATE TABLE model_TSThread (id INTEGER PRIMARY KEY, recordType INTEGER,
            uniqueId TEXT, creationDate DOUBLE, isArchived INTEGER,
            contactPhoneNumber TEXT, contactUUID TEXT, groupModel BLOB);
         INSERT INTO model_TSThread VALUES (1, 72, 'thread-A', 664416000.0, 0,
            '+15550100', 'uuid-bob', NULL);
         CREATE TABLE model_TSInteraction (id INTEGER PRIMARY KEY, recordType INTEGER,
            uniqueId TEXT, receivedAtTimestamp INTEGER, timestamp INTEGER,
            uniqueThreadId TEXT, authorPhoneNumber TEXT, authorUUID TEXT, body TEXT,
            read INTEGER);
         INSERT INTO model_TSInteraction VALUES
            (1, 19, 'msg-1', 1642723200123, 1642723200000, 'thread-A', '+15550100',
             'uuid-bob', 'meet at the harbour', 1),
            (2, 21, 'msg-2', 1642723260000, 1642723260000, 'thread-A', NULL, NULL,
             'on my way', 1);
         CREATE TABLE model_SignalRecipient (id INTEGER PRIMARY KEY, recordType INTEGER,
            uniqueId TEXT, devices BLOB, recipientPhoneNumber TEXT, recipientUUID TEXT);
         INSERT INTO model_SignalRecipient VALUES (1, 31, 'r-1', NULL, '+15550100', 'uuid-bob');
         CREATE TABLE model_OWSUserProfile (id INTEGER PRIMARY KEY, recordType INTEGER,
            uniqueId TEXT, profileKey BLOB, profileName TEXT, familyName TEXT,
            recipientPhoneNumber TEXT, recipientUUID TEXT, username TEXT);
         INSERT INTO model_OWSUserProfile VALUES (1, 41, 'p-1', X'00112233', 'Bob',
            'Harbour', '+15550100', 'uuid-bob', NULL);",
    )
    .unwrap();
    drop(conn);
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        bytes[20], 80,
        "the plaintext reserves Signal's 80 bytes per page"
    );
    bytes
}

fn store_artifact() -> Artifact {
    let encrypted = encrypt_v4_raw_key_for_test(
        &grdb_plaintext(),
        &KEY,
        &SALT,
        &SqlCipher4Config::signal_ios(),
    );
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ByteSliceDataSource::new(encrypted)) as Arc<dyn DataSource>),
        json!({ "name": "signal.sqlite" }),
    )
}

fn run(artifact: &Artifact, spec: Option<&str>) -> (Vec<Artifact>, Option<CredentialOutcome>) {
    let cred = spec.map(|s| {
        Arc::new(RunCredential::new(
            artifact.id,
            CredentialKind::SignalIosKeySpec,
            s.to_string(),
            "erin",
        ))
    });
    let out = credential::scoped(cred.clone(), || SignalParser.process(artifact).unwrap());
    (out, cred.and_then(|c| c.outcome()))
}

fn of_type<'a>(out: &'a [Artifact], t: &str) -> Vec<&'a Value> {
    out.iter()
        .map(|a| &a.metadata)
        .filter(|m| m["type"] == json!(t))
        .collect()
}

#[test]
fn without_the_key_the_store_is_reported_encrypted() {
    let (out, _) = run(&store_artifact(), None);
    let locked = of_type(&out, "SignalIncomplete");
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0]["status"], json!("StoreEncrypted"));
    assert_eq!(
        locked[0]["scheme"],
        json!("sqlcipher4_raw_key_plaintext_header")
    );
}

#[test]
fn a_key_spec_supplied_for_this_run_opens_the_store_and_reads_the_grdb_schema() {
    let artifact = store_artifact();
    let (out, outcome) = run(&artifact, Some(&key_spec_literal()));
    assert_eq!(outcome, Some(CredentialOutcome::Accepted));

    let messages = of_type(&out, "Signal");
    assert_eq!(messages.len(), 2, "{out:#?}");
    let first = messages
        .iter()
        .find(|m| m["unique_id"] == json!("msg-1"))
        .unwrap();
    assert_eq!(first["text"], json!("meet at the harbour"));
    assert_eq!(first["platform"], json!("ios"));
    assert_eq!(first["thread_unique_id"], json!("thread-A"));
    assert_eq!(first["author"], json!("+15550100"));
    assert_eq!(first["date"], json!(1642723200));
    assert_eq!(first["store"], json!("model_TSInteraction"));
    // Direction lives in the record's class code, which no real row has
    // graded: it is not claimed.
    assert!(first.get("direction").is_none());
    assert!(first.get("is_from_me").is_none());

    let threads = of_type(&out, "SignalThread");
    assert_eq!(threads.len(), 1);
    assert_eq!(threads[0]["contact_phone_number"], json!("+15550100"));

    let contacts = of_type(&out, "SignalContact");
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0]["profile_name"], json!("Bob Harbour"));
    // The profile key is key material: it is not a field of any record.
    for a in &out {
        assert!(a.metadata.get("profile_key").is_none());
    }

    let summary = of_type(&out, "SignalSummary");
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["platform"], json!("ios"));
    assert_eq!(summary[0]["message_count"], json!(2));
    assert_eq!(summary[0]["integrity_verified"], json!(true));
    assert_eq!(summary[0]["grdb_migrations"], json!(2));
    assert_eq!(summary[0]["credential_kind"], json!("signal_ios_key_spec"));

    // The schema statement replaces the "encrypted" one: same record type,
    // same parent, so a re-run supersedes the locked record (HUNT-107).
    let schema = of_type(&out, "SignalIncomplete");
    assert_eq!(schema.len(), 1);
    assert_eq!(schema[0]["warning_class"], json!("ParserStaleWarning"));
    assert_eq!(schema[0]["app"], json!("signal-ios"));
    assert!(
        schema[0].get("content_incomplete").is_none(),
        "{:#}",
        schema[0]
    );

    let secret_hex = hex(&KEY);
    for a in &out {
        assert!(!a.metadata.to_string().contains(&secret_hex));
    }
}

#[test]
fn a_wrong_key_spec_is_rejected() {
    let artifact = store_artifact();
    let wrong = format!("x'{}{}'", hex(&[0x43; 32]), hex(&SALT));
    let (out, outcome) = run(&artifact, Some(&wrong));
    match outcome {
        Some(CredentialOutcome::Rejected { reason }) => {
            assert!(!reason.contains(&hex(&[0x43; 32])), "{reason}");
        }
        other => panic!("a wrong key spec must be rejected, got {other:?}"),
    }
    assert_eq!(
        of_type(&out, "SignalIncomplete")[0]["status"],
        json!("StoreEncrypted")
    );
}

#[test]
fn a_key_spec_that_is_not_hex_is_rejected_without_echoing_it() {
    let (_, outcome) = run(&store_artifact(), Some("correct horse battery staple"));
    match outcome {
        Some(CredentialOutcome::Rejected { reason }) => {
            assert!(!reason.contains("horse"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
}

// ── the real store ──────────────────────────────────────────────────────────

fn corpus(name: &str) -> Option<std::path::PathBuf> {
    seance_core::test_support::corpus::file("SEANCE_IOS_SIGNAL_DIR", name)
}

/// The spec from the keychain export, as the hex literal an examiner would
/// type. Never printed.
fn real_key_spec(keychain: &std::path::Path) -> String {
    let root: plist::Value = plist::from_file(keychain).expect("the keychain export parses");
    let genp = root
        .as_dictionary()
        .and_then(|d| d.get("genp"))
        .and_then(plist::Value::as_array)
        .expect("generic-password items");
    let item = genp
        .iter()
        .filter_map(plist::Value::as_dictionary)
        .find(|d| {
            let is = |k: &str, v: &[u8]| {
                d.get(k).and_then(plist::Value::as_data) == Some(v)
                    || d.get(k)
                        .and_then(plist::Value::as_string)
                        .map(str::as_bytes)
                        == Some(v)
            };
            is("acct", b"GRDBDatabaseCipherKeySpec")
                && is("agrp", b"U68MSDN6DR.org.whispersystems.signal")
        })
        .expect("Signal's key spec item");
    let data = item
        .get("v_Data")
        .and_then(plist::Value::as_data)
        .expect("v_Data");
    format!("x'{}'", hex(data))
}

#[test]
fn the_real_ios_store_opens_with_its_key_spec_and_its_grdb_schema_is_read() {
    let (Some(db), Some(keychain)) = (corpus("signal.sqlite"), corpus("keychain.plist")) else {
        eprintln!("skipping: set SEANCE_IOS_SIGNAL_DIR to the provisioned Signal-iOS directory");
        return;
    };
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(db).unwrap());
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        json!({ "name": "signal.sqlite" }),
    );
    let spec = real_key_spec(&keychain);
    let (out, outcome) = run(&artifact, Some(&spec));
    assert_eq!(outcome, Some(CredentialOutcome::Accepted));

    let summary = of_type(&out, "SignalSummary");
    assert_eq!(summary.len(), 1, "{out:#?}");
    let s = summary[0];
    // Every one of the 305 pages and the 38 committed WAL frames authenticated.
    assert_eq!(s["pages"], json!(305));
    assert_eq!(s["integrity_verified"], json!(true));
    assert_eq!(s["wal_frames_committed"], json!(38));
    assert_eq!(s["wal_integrity_verified"], json!(true));
    // No messages on this device: a finding about the device, and the reason
    // the message mapping is graded structurally only.
    assert_eq!(s["message_count"], json!(0));
    assert_eq!(of_type(&out, "Signal").len(), 0);
    assert_eq!(s["grdb_migrations"], json!(84));
    assert_eq!(s["schema_grading"], json!("structural"));
    // The columns the reader resolves are all present on the real schema.
    let schema = of_type(&out, "SignalIncomplete");
    assert_eq!(schema.len(), 1);
    assert!(
        schema[0].get("schema_unresolved_fields").is_none(),
        "{:#}",
        schema[0]
    );
    assert!(schema[0].get("content_incomplete").is_none());
    assert_eq!(of_type(&out, "SignalThread").len(), 1);
    assert_eq!(of_type(&out, "SignalContact").len(), 1);

    let secret = spec
        .trim_start_matches("x'")
        .trim_end_matches('\'')
        .to_string();
    for a in &out {
        assert!(!a.metadata.to_string().contains(&secret[..32]));
    }

    // A wrong spec on the same store: rejected, and the locked record returned.
    let mut wrong = secret.clone().into_bytes();
    wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
    let wrong = format!("x'{}'", String::from_utf8(wrong).unwrap());
    let (out, outcome) = run(&artifact, Some(&wrong));
    assert!(matches!(outcome, Some(CredentialOutcome::Rejected { .. })));
    assert_eq!(
        of_type(&out, "SignalIncomplete")[0]["status"],
        json!("StoreEncrypted")
    );
}
