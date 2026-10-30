//! `crypt14` decryption graded on the real Pixel 7a backups of Josh Hickman's
//! Android 14 public image (`VALIDATION.md` `WHATSAPP-CRYPT14-1`).
//!
//! The files were streamed, stored and CRC-checked, out of the image's
//! `EXTRACTION_FFS.zip`; `test_data/README.md` lists them with their SHA-256.
//! Absent, these tests skip. The grade is cryptographic and external: the GCM
//! tag must verify, the file's own trailing MD5 must match, and every message
//! the backup holds must also be in the live `msgstore.db` (with its `-wal`)
//! that the same extraction took from the phone two days later.

use seance_plugin_whatsapp::crypt14::{decrypt, parse_key, Crypt14Error};
use std::collections::HashSet;
use std::path::PathBuf;

fn dir() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/whatsapp_android14");
    if root.join("key").is_file() && root.join("msgstore.db.crypt14").is_file() {
        Some(root)
    } else {
        println!(
            "Skipping: the Android 14 WhatsApp files are not staged at {}",
            root.display()
        );
        None
    }
}

type Row = (Option<String>, Option<i64>, Option<String>);

fn messages(db: &std::path::Path) -> HashSet<Row> {
    let conn = rusqlite::Connection::open(db).expect("open");
    let mut stmt = conn
        .prepare(
            "SELECT CAST(key_id AS TEXT), timestamp, CAST(text_data AS TEXT) FROM message \
             WHERE key_id IS NOT NULL",
        )
        .expect("message table");
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    rows
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("seance-crypt14-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn real_pixel7a_crypt14_decrypts_to_sqlite_matching_live_msgstore() {
    let Some(dir) = dir() else { return };
    let key = parse_key(&std::fs::read(dir.join("key")).unwrap()).expect("the key file");
    let file = std::fs::read(dir.join("msgstore.db.crypt14")).unwrap();
    let d = decrypt(&file, &key).expect("the backup decrypts under the device's key");
    assert!(d.checksum_ok, "the file's trailing MD5 matches");
    assert!(d.header.has_feature_flag);
    assert_eq!(d.header.app_version.as_deref(), Some("2.24.14.81"));
    assert!(d.database.starts_with(b"SQLite format 3\0"));
    assert_eq!(d.database.len(), 1_662_976);

    let work = scratch("msgstore");
    let backup = work.join("backup.db");
    std::fs::write(&backup, &d.database).unwrap();
    for f in ["msgstore.db", "msgstore.db-wal"] {
        std::fs::copy(dir.join(f), work.join(f)).unwrap();
    }
    let in_backup = messages(&backup);
    let live = messages(&work.join("msgstore.db"));
    let _ = std::fs::remove_dir_all(&work);

    // The backup is older than the extraction: a subset, every row present.
    assert_eq!(in_backup.len(), 197);
    assert_eq!(live.len(), 230);
    let missing: Vec<&Row> = in_backup.difference(&live).collect();
    assert!(
        missing.is_empty(),
        "backup rows not in the live store: {missing:?}"
    );
}

#[test]
fn real_wa_db_backup_without_a_feature_list_decrypts() {
    let Some(dir) = dir() else { return };
    let path = dir.join("wa.db.crypt14");
    if !path.is_file() {
        return;
    }
    let key = parse_key(&std::fs::read(dir.join("key")).unwrap()).unwrap();
    let d = decrypt(&std::fs::read(path).unwrap(), &key).expect("decrypts");
    assert!(
        !d.header.has_feature_flag,
        "wa.db's header has no 0x01 byte"
    );
    assert!(d.checksum_ok);
    assert_eq!(d.database.len(), 409_600);
}

#[test]
fn a_real_backup_made_under_an_earlier_key_is_refused_by_its_salt() {
    let Some(dir) = dir() else { return };
    let path = dir.join("msgstore-2024-07-26.1.db.crypt14");
    if !path.is_file() {
        return;
    }
    // Its header names a server salt (859be502...) that is not the key
    // file's (89542c15...), and a WhatsApp build (2.24.1.78) older than the
    // key file's backups: it was made under another key.
    let key = parse_key(&std::fs::read(dir.join("key")).unwrap()).unwrap();
    let file = std::fs::read(path).unwrap();
    assert_eq!(decrypt(&file, &key).unwrap_err(), Crypt14Error::KeyMismatch);
    // With the salt check skipped, the tag refuses it too.
    let mut bare = key.clone();
    bare.server_salt = None;
    assert_eq!(
        decrypt(&file, &bare).unwrap_err(),
        Crypt14Error::TagMismatch
    );
}

#[test]
fn a_flipped_byte_in_the_real_backup_is_refused() {
    let Some(dir) = dir() else { return };
    let key = parse_key(&std::fs::read(dir.join("key")).unwrap()).unwrap();
    let mut file = std::fs::read(dir.join("msgstore.db.crypt14")).unwrap();
    file[100_000] ^= 0x01;
    assert_eq!(decrypt(&file, &key).unwrap_err(), Crypt14Error::TagMismatch);
}

/// Ingest-shaped: the three backups and the key reach the module as file
/// entries, in the order the extraction's zip holds them (the backups under
/// `/data/media` come before `/data/data`), and are paired by the module
/// itself. Graded on the live store: every message filed from the backup is
/// a row of the live `msgstore.db` (with its `-wal`) the same extraction took.
#[test]
fn real_backups_and_key_ingested_in_zip_order_are_paired() {
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::data_source::{DataSource, FileDataSource};
    use seance_core::module::ForensicsModule;
    use seance_plugin_whatsapp::WhatsAppParser;
    use std::sync::Arc;

    let Some(dir) = dir() else { return };
    let case = uuid::Uuid::new_v4();
    let media = "Dump/data/media/0/Android/media/com.whatsapp/WhatsApp";
    let entry = |file: &str, path: String| {
        let src = FileDataSource::new(dir.join(file)).expect("staged file");
        Artifact::new(
            case,
            ArtifactType::FileEntry,
            Some(Arc::new(src) as Arc<dyn DataSource>),
            serde_json::json!({"name": file, "path": path}),
        )
    };
    let current = entry(
        "msgstore.db.crypt14",
        format!("{media}/Databases/msgstore.db.crypt14"),
    );
    let dated = entry(
        "msgstore-2024-07-26.1.db.crypt14",
        format!("{media}/Databases/msgstore-2024-07-26.1.db.crypt14"),
    );
    let wa = entry("wa.db.crypt14", format!("{media}/Backups/wa.db.crypt14"));
    let key = entry("key", "Dump/data/data/com.whatsapp/files/key".to_string());

    let p = WhatsAppParser;
    let mut out = Vec::new();
    for a in [&current, &dated, &wa] {
        let recs = p.process(a).expect("process");
        let statuses: Vec<_> = recs.iter().map(|r| r.metadata["status"].clone()).collect();
        assert_eq!(
            statuses,
            vec![serde_json::json!("AwaitingKey")],
            "{} awaits the key read after it",
            a.metadata["name"]
        );
        out.extend(recs);
    }
    let from_key = p.process(&key).expect("process key");
    let status_under = |parent: uuid::Uuid, status: &str| {
        from_key
            .iter()
            .filter(|r| {
                r.parent_id == Some(parent)
                    && r.metadata["type"] == "WhatsAppBackup"
                    && r.metadata["status"] == status
            })
            .count()
    };
    assert_eq!(status_under(key.id, "KeyFound"), 1);
    assert_eq!(status_under(current.id, "Decrypted"), 1);
    assert_eq!(status_under(wa.id, "Decrypted"), 1);
    assert_eq!(status_under(dated.id, "Decrypted"), 0);
    assert_eq!(
        status_under(dated.id, "KeyRefused"),
        1,
        "the earlier install's backup is refused by its salt"
    );

    // The messages filed from the current backup, against the live store.
    let msgs: Vec<&Artifact> = from_key
        .iter()
        .filter(|r| r.parent_id == Some(current.id) && r.metadata["type"] == "WhatsApp")
        .collect();
    let work = scratch("paired");
    for f in ["msgstore.db", "msgstore.db-wal"] {
        std::fs::copy(dir.join(f), work.join(f)).unwrap();
    }
    let live: HashSet<String> = messages(&work.join("msgstore.db"))
        .into_iter()
        .filter_map(|(k, _, _)| k)
        .collect();
    let _ = std::fs::remove_dir_all(&work);
    let filed: HashSet<String> = msgs
        .iter()
        .filter_map(|m| m.metadata["key_id"].as_str().map(str::to_string))
        .collect();
    println!(
        "paired: {} message records, {} distinct key_ids, records under wa.db: {}",
        msgs.len(),
        filed.len(),
        from_key
            .iter()
            .filter(|r| r.parent_id == Some(wa.id))
            .count()
    );
    let foreign: Vec<&String> = filed.difference(&live).collect();
    assert!(
        foreign.is_empty(),
        "filed from the backup, not in the live store: {foreign:?}"
    );
    for m in &msgs {
        assert_eq!(m.metadata["provenance"], "decrypted_backup");
        assert_eq!(
            m.metadata["decrypted_backup"]["key_sha256"],
            "eb2f85a4d4c59021d4b3843382f84a1dcc084892b58cb0d63eafdd949a6ab374"
        );
    }
    // Every row of the backup's `message` table is filed (the count the
    // decryption test above reads straight from the decrypted SQLite).
    assert_eq!(msgs.len(), 197);
    assert_eq!(filed.len(), 197);
    // A backup is one file: there is no `-wal` of it to miss. wa.db's
    // header is in WAL mode, and it once drew a "write-ahead log refused"
    // record that claimed rows were missing.
    let wal_claims: Vec<_> = from_key
        .iter()
        .filter(|r| r.metadata.get("wal_incomplete_reason").is_some())
        .map(|r| r.metadata.clone())
        .collect();
    assert!(wal_claims.is_empty(), "{wal_claims:#?}");
}

/// ROADMAP §5.7, owner decision (c) part b: a backup seized without the phone
/// that holds its key file, opened with the key supplied for it as the
/// `whatsapp_key` credential — the key file's bytes as hex, or the bare AES
/// key as 64 hex digits. Graded as above: the tag, and all 197 messages of the
/// backup (the count the decryption test reads) filed.
#[test]
fn a_real_backup_opens_with_its_key_supplied_as_a_credential() {
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
    use seance_core::data_source::{DataSource, FileDataSource};
    use seance_core::module::ForensicsModule;
    use seance_plugin_whatsapp::WhatsAppParser;
    use std::sync::Arc;

    let Some(dir) = dir() else { return };
    let key_file = std::fs::read(dir.join("key")).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let run = |file: &str, secret: String| {
        // A case with no key file in it: the backup alone.
        let src = FileDataSource::new(dir.join(file)).expect("staged file");
        let backup = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(src) as Arc<dyn DataSource>),
            serde_json::json!({"name": file, "path": format!("/sdcard/WhatsApp/Databases/{file}")}),
        );
        let cred = Arc::new(RunCredential::new(
            backup.id,
            CredentialKind::WhatsappKey,
            secret,
            "examiner",
        ));
        let out = credential::scoped(Some(cred.clone()), || {
            WhatsAppParser.process(&backup).expect("process")
        });
        (out, cred.outcome())
    };
    let filed = |out: &[Artifact]| {
        out.iter()
            .filter(|r| r.metadata["type"] == "WhatsApp")
            .count()
    };

    let (out, outcome) = run("msgstore.db.crypt14", hex(&key_file));
    assert_eq!(outcome, Some(CredentialOutcome::Accepted));
    assert_eq!(filed(&out), 197);
    let decrypted: Vec<_> = out
        .iter()
        .filter(|r| r.metadata["status"] == "Decrypted")
        .collect();
    assert_eq!(decrypted.len(), 1);
    assert_eq!(decrypted[0].metadata["key_source"], "credential");
    assert_eq!(
        decrypted[0].metadata["key_sha256"],
        "eb2f85a4d4c59021d4b3843382f84a1dcc084892b58cb0d63eafdd949a6ab374",
        "the SHA-256 of the key file the examiner supplied"
    );
    assert_eq!(decrypted[0].metadata["checksum_ok"], true);

    // The bare AES key, the last 32 bytes of the key file, opens it too.
    let (out, outcome) = run("msgstore.db.crypt14", hex(&key_file[key_file.len() - 32..]));
    assert_eq!(outcome, Some(CredentialOutcome::Accepted));
    assert_eq!(filed(&out), 197);

    // The earlier install's backup refuses this key: by its salt with the
    // key file, and by the GCM tag with the bare key (which has no salt).
    for secret in [hex(&key_file), hex(&key_file[key_file.len() - 32..])] {
        let (out, outcome) = run("msgstore-2024-07-26.1.db.crypt14", secret);
        assert!(
            matches!(outcome, Some(CredentialOutcome::Rejected { .. })),
            "{outcome:?}"
        );
        assert_eq!(filed(&out), 0);
    }
}
