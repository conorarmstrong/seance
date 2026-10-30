//! `crypt15` decryption graded on real backups with their published root key
//! (`VALIDATION.md` `WHATSAPP-CRYPT15-1`).
//!
//! The files are the `tests/res/` backups of the public `wa-crypt-tools`
//! project at commit e2c0282b (2026-09-24), held outside this tree at
//! `~/forensic_corpora/wa_crypt15_2_26` (its `PROVENANCE.md` gives the SHA-256
//! of each) and linked as `test_data/whatsapp_crypt15`. Absent, these tests
//! skip. That project is GPL; only its evidence files are used here, never its
//! code.
//!
//! Which file grades what, read from the bytes:
//! - `msgstore.db.crypt15` (WhatsApp 2.22.5.13, a random IV) is the one that
//!   plausibly came off a phone. It is the known answer: the GCM tag must
//!   verify under the published root key, the file's own trailing MD5 must
//!   match, and the plaintext must be a WhatsApp message store that opens.
//! - The `*-2.26*` and `stickers` files carry the IV `00 01 .. 0f`, the mark
//!   of a file written by that project's own encryptor rather than by
//!   WhatsApp. They pin the format's variants (no feature byte, a ZIP payload,
//!   no MD5 trailer) and are not evidence that WhatsApp writes them so.

use seance_plugin_whatsapp::crypt14::{
    decrypt, decrypt_backup, parse_key, Crypt14Error, KeyKind, Payload,
};
use std::path::PathBuf;

fn dir() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/whatsapp_crypt15");
    if root.join("encrypted_backup.key").is_file() && root.join("msgstore.db.crypt15").is_file() {
        Some(root)
    } else {
        println!(
            "Skipping: the crypt15 backups are not staged at {}",
            root.display()
        );
        None
    }
}

fn read(dir: &std::path::Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap()
}

/// The root key as the phone shows it: 64 hex digits.
const ROOT_HEX: &str = "6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017";

fn root_bytes() -> Vec<u8> {
    (0..32)
        .map(|i| u8::from_str_radix(&ROOT_HEX[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn real_crypt15_msgstore_decrypts_under_its_published_root_key() {
    let Some(dir) = dir() else { return };
    let key = parse_key(&read(&dir, "encrypted_backup.key"))
        .expect("encrypted_backup.key is a Java byte[32] root key");
    let file = read(&dir, "msgstore.db.crypt15");
    let d = decrypt(&file, &key).expect("the backup decrypts under its root key");
    assert_eq!(d.header.generation, 15);
    assert!(d.header.has_feature_flag);
    assert_eq!(d.header.app_version.as_deref(), Some("2.22.5.13"));
    assert!(d.checksum_ok, "the file's own trailing MD5 matches");
    assert_eq!(d.database.len(), 1_273_856);
    assert!(d.database.starts_with(b"SQLite format 3\0"));

    // The plaintext is a WhatsApp message store, not merely SQLite-shaped.
    let path = std::env::temp_dir().join(format!("seance-crypt15-{}.db", std::process::id()));
    std::fs::write(&path, &d.database).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('message','chat','jid')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 3, "message, chat and jid tables");
    drop(conn);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_root_key_as_64_bare_hex_digits_opens_it_too() {
    let Some(dir) = dir() else { return };
    let key = parse_key(&root_bytes()).expect("32 bare bytes");
    let d = decrypt(&read(&dir, "msgstore.db.crypt15"), &key).expect("decrypts");
    assert!(d.database.starts_with(b"SQLite format 3\0"));
}

#[test]
fn a_wrong_root_key_or_a_flipped_byte_is_refused_by_the_gcm_tag() {
    let Some(dir) = dir() else { return };
    let file = read(&dir, "msgstore.db.crypt15");
    let mut wrong = root_bytes();
    wrong[31] ^= 1;
    assert_eq!(
        decrypt(&file, &parse_key(&wrong).unwrap()).unwrap_err(),
        Crypt14Error::TagMismatch
    );
    let key = parse_key(&root_bytes()).unwrap();
    let mut bad = file.clone();
    bad[400] ^= 0x04;
    assert_eq!(decrypt(&bad, &key).unwrap_err(), Crypt14Error::TagMismatch);
}

#[test]
fn a_crypt14_key_file_is_refused_on_a_crypt15_backup_by_name() {
    let Some(dir) = dir() else { return };
    let c14 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic.key");
    let key = parse_key(&std::fs::read(c14).unwrap()).unwrap();
    assert_eq!(
        decrypt(&read(&dir, "msgstore.db.crypt15"), &key).unwrap_err(),
        Crypt14Error::Crypt14KeyOnCrypt15
    );
}

#[test]
fn format_variants_written_by_the_upstream_encryptor_are_read() {
    let Some(dir) = dir() else { return };
    let key = parse_key(&root_bytes()).unwrap();
    // No feature byte after the length byte.
    let wa = decrypt(&read(&dir, "wa-2.26.db.crypt15"), &key).expect("wa.db decrypts");
    assert!(!wa.header.has_feature_flag);
    assert_eq!(wa.database.len(), 888_832);
    let ms = decrypt(&read(&dir, "msgstore-2.26.db.crypt15"), &key).expect("decrypts");
    assert_eq!(ms.database.len(), 1_425_408);
    // A ZIP payload (an incremental backup; a raw ZIP with no MD5 trailer) is
    // authenticated and then refused by name, not passed off as a store.
    for name in ["msgstore-increment-2.26.crypt15", "stickers.backup.crypt15"] {
        assert_eq!(
            decrypt(&read(&dir, name), &key).unwrap_err(),
            Crypt14Error::ZipPayload,
            "{name}"
        );
    }
}

fn sha256(b: &[u8]) -> String {
    seance_core::hashing::compute_hashes(b).sha256
}

/// The known answers the upstream project publishes beside the backups:
/// `tests/res/msgstore.db` is the plaintext of `msgstore.db.crypt15`, and
/// `tests/res/test9.zip` that of `stickers.backup.crypt15`
/// (`~/forensic_corpora/wa_crypt_tools_vectors/SOURCE.md`).
const MSGSTORE_DB_SHA256: &str = "1425b944a2e3885fc936a7bb82f6548c5cc09523a2f61f02aa836c4ed8bbd16e";
const TEST9_ZIP_SHA256: &str = "70b6b1718c499277138a686828165fdf5f07fb532500363366d641e0362d35ea";

#[test]
fn real_crypt15_decrypts_to_the_published_plaintexts_byte_for_byte() {
    let Some(dir) = dir() else { return };
    let key = parse_key(&read(&dir, "encrypted_backup.key")).unwrap();
    assert_eq!(key.kind, KeyKind::Crypt15Root);

    let store = decrypt_backup(&read(&dir, "msgstore.db.crypt15"), &key).expect("decrypts");
    assert!(store.inflated && store.checksum_present && store.checksum_ok);
    match &store.payload {
        Payload::Database(db) => assert_eq!(sha256(db), MSGSTORE_DB_SHA256),
        other => panic!("expected the message store, got {other:?}"),
    }

    let stickers = decrypt_backup(&read(&dir, "stickers.backup.crypt15"), &key).expect("decrypts");
    assert!(!stickers.inflated, "stored raw");
    assert!(
        !stickers.checksum_present,
        "a multi-file backup has no MD5 trailer"
    );
    match &stickers.payload {
        Payload::Archive(zip) => assert_eq!(sha256(zip), TEST9_ZIP_SHA256),
        other => panic!("expected test9.zip, got {other:?}"),
    }
}

#[test]
fn the_three_real_2_26_header_variants_decrypt() {
    let Some(dir) = dir() else { return };
    let key = parse_key(&read(&dir, "encrypted_backup.key")).unwrap();
    // A message store: feature byte, MD5 trailer, zlib -> SQLite.
    let ms = decrypt_backup(&read(&dir, "msgstore-2.26.db.crypt15"), &key).unwrap();
    assert!(ms.header.has_feature_flag && ms.checksum_ok);
    assert_eq!(ms.header.app_version.as_deref(), Some("2.26.34.7"));
    assert!(matches!(&ms.payload, Payload::Database(d) if d.len() == 1_425_408));
    // A non-msgstore backup with no feature byte.
    let wa = decrypt_backup(&read(&dir, "wa-2.26.db.crypt15"), &key).unwrap();
    assert!(!wa.header.has_feature_flag && wa.checksum_ok);
    assert!(matches!(&wa.payload, Payload::Database(d) if d.len() == 888_832));
    // An incremental backup: zlib -> ZIP, with an MD5 trailer.
    let inc = decrypt_backup(&read(&dir, "msgstore-increment-2.26.crypt15"), &key).unwrap();
    assert!(inc.inflated && inc.checksum_ok);
    assert!(matches!(&inc.payload, Payload::Archive(z) if z.len() == 5_359));
}

/// Ingest, in the order a phone's extraction may deliver it: the backups
/// first, then `files/encrypted_backup.key`, paired across the case. The
/// Decrypted statements carry the SHA-256 of the published plaintexts.
#[test]
fn real_crypt15_backups_and_their_key_are_paired_in_ingest() {
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::module::ForensicsModule;
    use seance_plugin_whatsapp::WhatsAppParser;
    use std::sync::Arc;

    let Some(dir) = dir() else { return };
    let case = uuid::Uuid::new_v4();
    let entry = |file: &str, path: String| {
        Artifact::new(
            case,
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(read(&dir, file))) as Arc<dyn DataSource>),
            serde_json::json!({"name": file, "path": path}),
        )
    };
    let media = "Dump/data/media/0/Android/media/com.whatsapp/WhatsApp";
    let store = entry(
        "msgstore.db.crypt15",
        format!("{media}/Databases/msgstore.db.crypt15"),
    );
    let stickers = entry(
        "stickers.backup.crypt15",
        format!("{media}/Backups/stickers.backup.crypt15"),
    );
    let key = entry(
        "encrypted_backup.key",
        "Dump/data/data/com.whatsapp/files/encrypted_backup.key".to_string(),
    );
    let p = WhatsAppParser;
    for a in [&store, &stickers] {
        let recs = p.process(a).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].metadata["status"], "AwaitingKey");
        assert_eq!(recs[0].metadata["scheme"], "crypt15");
    }
    let out = p.process(&key).unwrap();
    let decrypted_under = |parent: uuid::Uuid| {
        out.iter()
            .find(|r| {
                r.parent_id == Some(parent)
                    && r.metadata["type"] == "WhatsAppBackup"
                    && r.metadata["status"] == "Decrypted"
            })
            .unwrap_or_else(|| panic!("no Decrypted record: {out:#?}"))
            .metadata
            .clone()
    };
    let s = decrypted_under(store.id);
    assert_eq!(s["payload"], "sqlite");
    assert_eq!(s["decrypted_sha256"], MSGSTORE_DB_SHA256);
    assert_eq!(s["checksum_ok"], true);
    assert_eq!(s["supersedes_status"], "AwaitingKey");
    let z = decrypted_under(stickers.id);
    assert_eq!(z["payload"], "zip");
    assert_eq!(z["decrypted_sha256"], TEST9_ZIP_SHA256);
    assert!(z["checksum_ok"].is_null());
    let zip = out
        .iter()
        .find(|r| r.parent_id == Some(stickers.id) && r.artifact_type == ArtifactType::FileEntry)
        .expect("the archive filed beneath the backup");
    assert_eq!(zip.metadata["sha256"], TEST9_ZIP_SHA256);
    let found = out
        .iter()
        .find(|r| r.metadata["status"] == "KeyFound")
        .unwrap();
    assert_eq!(found.metadata["backups_decrypted"], 2);
    assert_eq!(found.metadata["key_scheme"], "crypt15");
    // The root key is on no record.
    let all =
        serde_json::to_string(&out.iter().map(|a| a.metadata.clone()).collect::<Vec<_>>()).unwrap();
    assert!(!all.contains(ROOT_HEX));
}
