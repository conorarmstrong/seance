//! SQLCipher 4 raw-key decryption graded on a store Signal for iOS wrote
//! (HUNT-183).
//!
//! # Why this file exists
//!
//! The unit tests in `src/tests.rs` encrypt with an encryptor written in this
//! project, so they prove only that two readings of SQLCipher 4 agree. This
//! test reads a database this project did not write: `grdb/signal.sqlite` and
//! `grdb/signal.sqlite-wal` from the Magnet 2022 CTF iPhone 8 full-file-system
//! extraction, keyed by the raw key spec Signal keeps in the keychain
//! (`genp` item, `acct` `GRDBDatabaseCipherKeySpec`, access group
//! `U68MSDN6DR.org.whispersystems.signal`, 48 bytes of `v_Data`). Every one of
//! its 305 pages and 38 WAL frames carries an HMAC-SHA512 tag computed by
//! Signal's SQLCipher; all of them verifying is what establishes the framing.
//!
//! # Provisioning
//!
//! Neither the store nor the key is in the repository — the key is evidence,
//! and it is read from the keychain export at run time, never copied, printed or
//! logged. Point `SEANCE_IOS_SIGNAL_DIR` at a directory holding:
//!
//! - `signal.sqlite` and `signal.sqlite-wal`, extracted from
//!   `~/ctf-evidence/ios2022ffs/Jess_CTF_iPhone8/*_files_full.zip` at
//!   `/private/var/mobile/Containers/Shared/AppGroup/92EFD8F4-8BF3-42D7-8DF7-E2F512630E22/grdb/`
//!   (`unzip -j <zip> '<that path>/*' -d "$SEANCE_IOS_SIGNAL_DIR"`);
//!   SHA-256 `0f3bf89b…d1712d23` and `24fc4402…6d72093c`;
//! - `keychain.plist`, a symlink to (or copy of) the same export's
//!   `*_keychain.plist`.
//!
//! Unset, the test skips and says so; set but incomplete, it fails; and
//! `SEANCE_REQUIRE_CORPUS=1` turns the skip into a failure.
//!
//! # The expected values
//!
//! The table counts were measured independently of this crate: a separate
//! Python decryption (the `cryptography` package's AES-CBC, `hashlib`'s
//! HMAC-SHA512 and PBKDF2) whose output the system `sqlite3` opened, with the
//! committed WAL frames applied by hand. Main file alone: `keyvalue` 1980 rows,
//! `MessageSendLog_Payload` 6, `model_SSKJobRecord` 1. With the WAL: 1981, 8
//! and 0 — the WAL is not a formality on this device, 16 of the 21 pages it
//! carries differ from the main file's copy. `model_TSInteraction` holds no
//! rows in either: this store has no messages, which is a finding about the
//! device, not a failure to read.

use std::path::PathBuf;

use seance_sqlcipher::{
    decrypt_v4_raw_key, decrypt_v4_raw_key_wal, RawKeySpec, SqlCipher4Config,
    INTEGRITY_VERIFIED_SHA512,
};

fn corpus(name: &str) -> Option<PathBuf> {
    seance_core::test_support::corpus::file("SEANCE_IOS_SIGNAL_DIR", name)
}

/// The key spec, read from the keychain export. Never printed: `RawKeySpec`'s
/// `Debug` is redacted, and nothing here formats the bytes.
fn signal_key_spec(keychain: &PathBuf) -> RawKeySpec {
    let root: plist::Value = plist::from_file(keychain).expect("the keychain export parses");
    let genp = root
        .as_dictionary()
        .and_then(|d| d.get("genp"))
        .and_then(plist::Value::as_array)
        .expect("the export carries generic-password items");
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
        .expect("Signal's GRDBDatabaseCipherKeySpec item is in the export");
    let data = item
        .get("v_Data")
        .and_then(plist::Value::as_data)
        .expect("the item carries its value");
    assert_eq!(
        data.len(),
        48,
        "a SQLCipher raw key spec: 32-byte key + 16-byte salt"
    );
    RawKeySpec::from_bytes(data).expect("48 bytes is a raw key spec")
}

fn count(conn: &rusqlite::Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |r| {
        r.get(0)
    })
    .unwrap_or_else(|e| panic!("{table}: {e}"))
}

#[test]
fn the_real_signal_ios_store_decrypts_and_every_page_and_frame_authenticates() {
    let Some(store_path) = corpus("signal.sqlite") else {
        return;
    };
    let wal_path = corpus("signal.sqlite-wal").expect("gated above");
    let keychain = corpus("keychain.plist").expect("gated above");

    let store = std::fs::read(&store_path).unwrap();
    let wal = std::fs::read(&wal_path).unwrap();
    assert_eq!(store.len(), 1_249_280, "the held store, not another file");
    // A cheap identity check without a hashing dependency: the length above
    // and the plaintext header's page count agree with the measured file.
    assert_eq!(&store[28..32], &305u32.to_be_bytes());

    let key = signal_key_spec(&keychain);
    let cfg = SqlCipher4Config::signal_ios();

    // --- the main file ---------------------------------------------------
    let d = decrypt_v4_raw_key(&store, &key, &cfg)
        .expect("Signal's own key spec decrypts Signal's own store");
    assert_eq!(d.pages, 305);
    assert!(
        d.failed_pages.is_empty(),
        "failed pages: {:?}",
        d.failed_pages
    );
    assert!(d.integrity_verified);
    assert_eq!(d.integrity_statement, INTEGRITY_VERIFIED_SHA512);

    // --- the write-ahead log ---------------------------------------------
    let w = decrypt_v4_raw_key_wal(&wal, &key, &cfg).expect("the WAL decrypts under the same key");
    assert_eq!(w.frames_in_file, 38);
    assert_eq!(w.frames_committed, 38);
    assert_eq!(w.frames_not_committed, 0);
    assert!(
        w.failed_frames.is_empty(),
        "failed frames: {:?}",
        w.failed_frames
    );
    assert!(w.integrity_verified, "{}", w.integrity_statement);

    // --- SQLite opens both, and they differ as measured ---------------------
    let dir = tempfile::tempdir().unwrap();
    let main_only = dir.path().join("main_only.sqlite");
    std::fs::write(&main_only, &d.plaintext).unwrap();
    {
        let conn = rusqlite::Connection::open_with_flags(
            &main_only,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .unwrap();
        let ok: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ok, "ok");
        assert_eq!(count(&conn, "grdb_migrations"), 84);
        assert_eq!(count(&conn, "keyvalue"), 1980);
        assert_eq!(count(&conn, "MessageSendLog_Payload"), 6);
        assert_eq!(count(&conn, "model_SSKJobRecord"), 1);
        assert_eq!(count(&conn, "model_TSInteraction"), 0);
    }

    let with_wal = dir.path().join("with_wal.sqlite");
    std::fs::write(&with_wal, &d.plaintext).unwrap();
    std::fs::write(dir.path().join("with_wal.sqlite-wal"), &w.plaintext_wal).unwrap();
    let conn = rusqlite::Connection::open(&with_wal).unwrap();
    let ok: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ok, "ok");
    assert_eq!(
        count(&conn, "keyvalue"),
        1981,
        "the WAL's committed frames were replayed"
    );
    assert_eq!(count(&conn, "MessageSendLog_Payload"), 8);
    assert_eq!(count(&conn, "model_SSKJobRecord"), 0);
    assert_eq!(count(&conn, "model_TSInteraction"), 0);
    let threads = count(&conn, "model_TSThread");
    assert_eq!(threads, 1);
}

/// A key spec for another database is refused on the real file, behind its
/// genuine plaintext header — not returned as noise.
#[test]
fn the_real_signal_ios_store_refuses_a_wrong_key() {
    let Some(store_path) = corpus("signal.sqlite") else {
        return;
    };
    let store = std::fs::read(store_path).unwrap();
    let wrong = RawKeySpec::from_bytes(&[0x42u8; 48]).unwrap();
    assert!(decrypt_v4_raw_key(&store, &wrong, &SqlCipher4Config::signal_ios()).is_none());
}
