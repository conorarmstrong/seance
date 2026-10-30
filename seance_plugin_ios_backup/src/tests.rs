use super::*;
use crate::test_support::*;
use seance_core::module::ForensicsModule;
use std::path::PathBuf;
use uuid::Uuid;

fn fixture_dir() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .unwrap()
        .join("test_data")
        .join("ios_backup_fixtures")
}

fn real_backup_dir() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .unwrap()
        .join("test_data")
        .join("ios_backup")
}

// --- Module metadata ---

#[test]
fn test_module_metadata() {
    let parser = IosBackupParser::new();
    assert_eq!(parser.id(), "plugin.mobile.ios_backup");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    assert!(parser.subscribes_to().contains(&ArtifactType::FileEntry));
    assert!(parser.subscribes_to().contains(&ArtifactType::RawEvidence));
    assert_eq!(parser.input_capability(), InputCapability::FilePath);
}

#[test]
fn test_default_no_password() {
    let parser = IosBackupParser::default();
    assert!(parser.password.is_none());
}

#[test]
fn test_with_password() {
    let parser = IosBackupParser::with_password("secret123".to_string());
    assert_eq!(parser.password.as_deref(), Some("secret123"));
}

// --- is_ios_backup detection ---

#[test]
fn test_is_ios_backup_sqlite_fixture() {
    let parser = IosBackupParser::new();
    let sqlite_dir = fixture_dir().join("sqlite_basic");
    assert!(
        parser.is_ios_backup(&sqlite_dir),
        "sqlite_basic fixture should be detected as iOS backup"
    );
}

#[test]
fn test_is_ios_backup_mbdb_fixture() {
    let parser = IosBackupParser::new();
    let mbdb_dir = fixture_dir().join("mbdb_basic");
    assert!(
        parser.is_ios_backup(&mbdb_dir),
        "mbdb_basic fixture should be detected as iOS backup"
    );
}

#[test]
fn test_is_ios_backup_rejects_empty_dir() {
    let parser = IosBackupParser::new();
    let temp_dir = std::env::temp_dir().join(format!("seance_test_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    assert!(
        !parser.is_ios_backup(&temp_dir),
        "Empty directory should not be detected as iOS backup"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_is_ios_backup_rejects_plist_only() {
    let parser = IosBackupParser::new();
    let temp_dir = std::env::temp_dir().join(format!("seance_test_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // Create Manifest.plist but no Manifest.db or Manifest.mbdb
    std::fs::write(temp_dir.join("Manifest.plist"), b"<plist></plist>").unwrap();

    assert!(
        !parser.is_ios_backup(&temp_dir),
        "Directory with only Manifest.plist should not be detected as backup"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// --- resolve_backup_file_path ---

#[test]
fn test_resolve_backup_file_path_two_level() {
    let sqlite_dir = fixture_dir().join("sqlite_basic");
    let file_id = "bb1cc2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9";
    let path = IosBackupParser::resolve_backup_file_path(&sqlite_dir, file_id).unwrap();
    assert!(
        path.exists(),
        "Two-level path should resolve for fixture file"
    );
    assert!(path.to_string_lossy().contains("/bb/bb1cc2d3"));
}

#[test]
fn test_resolve_backup_file_path_flat_fallback() {
    let mbdb_dir = fixture_dir().join("mbdb_basic");
    let file_id = "0000000000000000000000000000000000000002";
    let path = IosBackupParser::resolve_backup_file_path(&mbdb_dir, file_id).unwrap();
    // mbdb_basic uses flat layout
    assert!(
        path.exists(),
        "Flat fallback should resolve for mbdb fixture file"
    );
}

#[test]
fn test_resolve_backup_file_path_missing() {
    let sqlite_dir = fixture_dir().join("sqlite_basic");
    let path = IosBackupParser::resolve_backup_file_path(&sqlite_dir, "nonexistent").unwrap();
    assert!(!path.exists(), "Non-existent file should not resolve");
}

// --- parse_manifest_files (SQLite) ---

#[test]
fn test_parse_sqlite_fixture() {
    let parser = IosBackupParser::new();
    let sqlite_dir = fixture_dir().join("sqlite_basic");
    let case_id = Uuid::new_v4();
    let parent_id = Uuid::new_v4();

    let artifacts = parser
        .parse_manifest_files(&sqlite_dir, None, case_id, parent_id)
        .expect("Should parse sqlite_basic fixture successfully");

    assert_eq!(
        artifacts.len(),
        2,
        "SQLite fixture should produce 2 artifacts"
    );

    // First artifact is a directory
    let dir = &artifacts[0];
    assert_eq!(dir.metadata["domain"], "AppDomain-com.example.notes");
    assert_eq!(dir.metadata["is_directory"], true);
    assert_eq!(dir.artifact_type, ArtifactType::ParsedRecord);

    // Second artifact is a file
    let file = &artifacts[1];
    assert_eq!(file.metadata["domain"], "AppDomain-com.example.notes");
    assert_eq!(file.metadata["relative_path"], "Documents/note.txt");
    assert_eq!(file.metadata["is_directory"], false);
    assert_eq!(file.artifact_type, ArtifactType::FileEntry);

    // Parent chain
    for a in &artifacts {
        assert_eq!(a.parent_id, Some(parent_id));
        assert_eq!(a.case_id, case_id);
    }
}

// --- parse_manifest_files (MBDB) ---

#[test]
fn test_parse_mbdb_fixture() {
    let parser = IosBackupParser::new();
    let mbdb_dir = fixture_dir().join("mbdb_basic");
    let case_id = Uuid::new_v4();
    let parent_id = Uuid::new_v4();

    let artifacts = parser
        .parse_manifest_files(&mbdb_dir, None, case_id, parent_id)
        .expect("Should parse mbdb_basic fixture successfully");

    assert_eq!(
        artifacts.len(),
        2,
        "MBDB fixture should produce 2 artifacts"
    );

    // Verify legacy format metadata
    let dir = &artifacts[0];
    assert_eq!(dir.metadata["format"], "mbdb_legacy");
    assert_eq!(dir.metadata["domain"], "AppDomain-com.example.legacy");
    assert_eq!(dir.metadata["is_directory"], true);

    let file = &artifacts[1];
    assert_eq!(file.metadata["domain"], "AppDomain-com.example.legacy");
    assert_eq!(file.metadata["relative_path"], "Documents/item.dat");
}

// --- process() trait method ---

#[test]
fn test_process_rejects_non_directory() {
    let parser = IosBackupParser::new();
    let case_id = Uuid::new_v4();

    // Point at a file, not a directory
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"path": "/tmp/nonexistent_file.txt"}),
    );

    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 0, "Non-directory should return empty");
}

#[test]
fn test_process_rejects_non_backup_directory() {
    let parser = IosBackupParser::new();
    let case_id = Uuid::new_v4();

    // Use an isolated temp directory that definitely doesn't have iOS backup files
    let temp_dir = std::env::temp_dir().join(format!("seance_not_backup_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"path": temp_dir.to_string_lossy().to_string()}),
    );

    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 0, "Non-backup directory should return empty");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_process_requires_path() {
    let parser = IosBackupParser::new();
    let case_id = Uuid::new_v4();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "something"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_err(), "Missing path should produce an error");
}

#[test]
fn test_process_sqlite_fixture_end_to_end() {
    let parser = IosBackupParser::new();
    let case_id = Uuid::new_v4();
    let sqlite_dir = fixture_dir().join("sqlite_basic");

    let artifact = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"path": sqlite_dir.to_string_lossy().to_string()}),
    );

    let result = parser.process(&artifact).unwrap();
    assert_eq!(
        result.len(),
        2,
        "End-to-end SQLite fixture should produce 2 artifacts"
    );
}

// --- Encrypted backup error path ---

#[test]
fn test_encrypted_backup_no_password_produces_info_artifact() {
    let parser = IosBackupParser::new(); // No password
    let real_dir = real_backup_dir();

    if !real_dir.exists() {
        eprintln!("Skipping encrypted backup test: {:?} not found", real_dir);
        return;
    }

    // Check if the real backup is encrypted
    let plist_path = real_dir.join("Manifest.plist");
    let manifest = ManifestPlist::from_file(&plist_path).unwrap();

    if !manifest.is_encrypted {
        // Unencrypted backup: should succeed normally
        let case_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let artifacts = parser
            .parse_backup(&real_dir, parser.password.as_deref(), case_id, parent_id)
            .unwrap();
        assert!(
            !artifacts.is_empty(),
            "Unencrypted backup should produce artifacts"
        );
        return;
    }

    // Encrypted backup without password: should produce info artifact
    let case_id = Uuid::new_v4();
    let parent_id = Uuid::new_v4();
    let artifacts = parser
        .parse_backup(&real_dir, parser.password.as_deref(), case_id, parent_id)
        .unwrap();

    assert_eq!(
        artifacts.len(),
        1,
        "Encrypted backup without password should produce 1 info artifact"
    );
    assert_eq!(artifacts[0].metadata["status"], "encrypted_no_password");
    assert_eq!(artifacts[0].metadata["is_encrypted"], true);
}

// --- Real backup integration test ---

#[test]
fn test_real_backup_parse() {
    let real_dir = real_backup_dir();
    if !real_dir.exists() {
        eprintln!("Skipping test_real_backup_parse: {:?} not found", real_dir);
        return;
    }

    let parser = IosBackupParser::new();

    // Check basic detection
    assert!(
        parser.is_ios_backup(&real_dir),
        "Real backup should be detected as iOS backup"
    );

    // Check Manifest.plist parsing
    let plist_path = real_dir.join("Manifest.plist");
    let manifest = ManifestPlist::from_file(&plist_path).unwrap();
    assert!(!manifest.version.is_empty());

    // Check manifest file parsing (if unencrypted)
    if !manifest.is_encrypted {
        let case_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let artifacts = parser
            .parse_manifest_files(&real_dir, None, case_id, parent_id)
            .unwrap();
        assert!(artifacts.len() > 100, "Real backup should have many files");

        // Verify domains are present
        let domains: std::collections::HashSet<&str> = artifacts
            .iter()
            .filter_map(|a| a.metadata.get("domain").and_then(|v| v.as_str()))
            .collect();
        assert!(
            domains.len() > 5,
            "Expected multiple domains, got {:?}",
            domains
        );

        eprintln!(
            "Real backup: {} artifacts, {} unique domains",
            artifacts.len(),
            domains.len()
        );
    }
}

// --- Chaining fix: name + DataSource on emitted FileEntry ---

/// Mirror of `identify_imessage_db` in `seance_plugin_imessage`. The real
/// function is private to that crate; this reproduces its predicate so the
/// test can assert the emitted `name` would be accepted downstream.
fn identify_imessage_db(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("chat.db")
        || n.ends_with("sms.db")
        || n.ends_with("chat.db-wal")
        || n.contains("imessage")
        || n.contains("mobilesms")
}

/// Self-contained end-to-end proof (no external fixture required): a synthetic
/// unencrypted iOS backup whose Manifest.db lists an extracted `sms.db` yields a
/// FileEntry that (1) carries `metadata["name"] == "sms.db"`, (2) has a
/// file-backed DataSource with the on-disk bytes, and (3) is recognized by the
/// downstream iMessage identifier.
#[test]
fn test_extracted_sms_db_chains_to_downstream_identifier() {
    let tmp = std::env::temp_dir().join(format!("seance_ios_chain_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();

    // Unencrypted-backup marker.
    std::fs::write(tmp.join("Manifest.plist"), b"<plist></plist>").unwrap();

    // On-disk backup file for sms.db (modern two-level layout).
    let file_id = "abcdef0123456789abcdef0123456789abcdef01";
    let sub = tmp.join(&file_id[..2]);
    std::fs::create_dir_all(&sub).unwrap();
    let sms_bytes: &[u8] = b"SQLite format 3\x00 synthetic imessage payload";
    std::fs::write(sub.join(file_id), sms_bytes).unwrap();

    // Manifest.db (SQLite) with one Files row pointing at Library/SMS/sms.db.
    {
        let conn = rusqlite::Connection::open(tmp.join("Manifest.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, \
             relativePath TEXT, flags INTEGER, file BLOB);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO Files (fileID, domain, relativePath, flags, file) \
             VALUES (?1, ?2, ?3, ?4, NULL)",
            rusqlite::params![file_id, "HomeDomain", "Library/SMS/sms.db", 1_i64],
        )
        .unwrap();
    }

    let parser = IosBackupParser::new();
    let case_id = Uuid::new_v4();
    let parent_id = Uuid::new_v4();
    let artifacts = parser
        .parse_manifest_files(&tmp, None, case_id, parent_id)
        .expect("synthetic unencrypted backup should parse");

    let file_entry = artifacts
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .expect("should emit a FileEntry for sms.db");

    // (1) name is the basename; existing metadata keys preserved.
    assert_eq!(file_entry.metadata["name"], "sms.db");
    assert_eq!(file_entry.metadata["relative_path"], "Library/SMS/sms.db");
    assert_eq!(file_entry.metadata["domain"], "HomeDomain");
    assert_eq!(file_entry.metadata["file_id"], file_id);

    // (2) DataSource attached over the on-disk backup file.
    let ds = file_entry
        .data
        .as_ref()
        .expect("FileEntry must carry a DataSource");
    assert_eq!(ds.size(), sms_bytes.len() as u64);
    let mut buf = vec![0u8; sms_bytes.len()];
    ds.read_at(0, &mut buf).unwrap();
    assert_eq!(
        &buf, sms_bytes,
        "DataSource must expose the backup file bytes"
    );

    // (3) downstream identifier accepts the emitted name.
    let name = file_entry.metadata["name"].as_str().unwrap();
    assert!(
        identify_imessage_db(name),
        "emitted name '{}' must be recognized by the iMessage identifier",
        name
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

// --- Undecryptable files must leave a trace (B2-084) -------------------------

fn sample_manifest_record() -> manifest_db::ManifestRecord {
    manifest_db::ManifestRecord {
        file_id: "3d0d7e5fb2ce288813306e4d4636395e047a3d28".into(),
        domain: "HomeDomain".into(),
        relative_path: "Library/SMS/sms.db".into(),
        flags: 1,
        size: Some(4_194_304),
        mode: Some(0o100644),
        last_modified: Some("2024-01-15T10:30:00+00:00".into()),
        birth: Some("2023-06-01T09:00:00+00:00".into()),
        inode_number: Some(12345),
        user_id: Some(501),
        group_id: Some(501),
        protection_class: Some(3),
        encryption_key: Some(vec![0u8; 40]),
        key_class: Some(3),
        encryption_key_error: None,
        metadata_error: None,
    }
}

/// A file whose bytes could not be decrypted must still appear in the case,
/// carrying its manifest identity and an explicit "content absent" marker —
/// otherwise a missing chat database is indistinguishable from a device that
/// never had one.
#[test]
fn a_file_that_could_not_be_decrypted_still_appears_with_an_incomplete_marker() {
    let record = sample_manifest_record();
    let art = IosBackupParser::undecrypted_file_record(
        std::path::Path::new("/evidence/backup"),
        &record,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "DecryptFailed",
        IncompleteReason::Encrypted,
        "Decryption failed: bad key",
    );
    let md = &art.metadata;
    assert_eq!(md["type"], "IosBackupFile");
    assert_eq!(md["status"], "DecryptFailed");
    assert_eq!(md["relative_path"], "Library/SMS/sms.db");
    assert_eq!(md["domain"], "HomeDomain");
    assert_eq!(md["size"], serde_json::json!(4_194_304));
    assert_eq!(md["decrypted"], serde_json::json!(false));
    assert_eq!(md["content_incomplete"], serde_json::json!(true));
    assert_eq!(md["content_incomplete_reason"], "encrypted");
    assert!(art.data.is_none(), "no content may be attached");
}

/// The backup-level summary states how many manifest entries never produced
/// content, so a partial extraction cannot present itself as the whole backup.
#[test]
fn a_partially_decrypted_backup_reports_how_many_files_are_missing() {
    let art = IosBackupParser::decrypt_gap_summary(
        std::path::Path::new("/evidence/backup"),
        Uuid::new_v4(),
        Uuid::new_v4(),
        1000,
        17,
    );
    let md = &art.metadata;
    assert_eq!(md["status"], "PartialDecryption");
    assert_eq!(md["content_incomplete"], serde_json::json!(true));
    assert_eq!(md["manifest_entries"], serde_json::json!(1000));
    assert_eq!(md["files_not_recovered"], serde_json::json!(17));
}

// --- Unencrypted backups: missing blobs and undecodable metadata (B6-006/036) -

/// Build a synthetic unencrypted backup directory holding a `Manifest.db` with
/// the given rows. `on_disk` names the file IDs whose stored blob is written.
fn synthetic_backup(rows: &[(&str, &str, i64, Option<&[u8]>)], on_disk: &[&str]) -> PathBuf {
    let tmp = std::env::temp_dir().join(format!("seance_ios_gap_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("Manifest.plist"), b"<plist></plist>").unwrap();

    let conn = rusqlite::Connection::open(tmp.join("Manifest.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, \
         relativePath TEXT, flags INTEGER, file BLOB);",
    )
    .unwrap();
    for (file_id, rel, flags, blob) in rows {
        conn.execute(
            "INSERT INTO Files (fileID, domain, relativePath, flags, file) \
             VALUES (?1, 'HomeDomain', ?2, ?3, ?4)",
            rusqlite::params![file_id, rel, flags, blob],
        )
        .unwrap();
    }
    drop(conn);

    for file_id in on_disk {
        let sub = tmp.join(&file_id[..2]);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(file_id), b"SQLite format 3\x00payload").unwrap();
    }
    tmp
}

/// B6-006: the manifest lists a file whose stored blob is not on disk. The entry
/// used to go out as an ordinary FileEntry with the manifest's size and no
/// bytes — which opens as an empty file of that size, and makes a partial backup
/// look fully inventoried.
#[test]
fn a_manifest_entry_whose_blob_is_missing_is_flagged_not_silently_empty() {
    let present = "aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa";
    let absent = "bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb";
    let dir = synthetic_backup(
        &[
            (present, "Library/SMS/sms.db", 1, None),
            (absent, "Library/Notes/notes.sqlite", 1, None),
        ],
        &[present],
    );

    let parser = IosBackupParser::new();
    let artifacts = parser
        .parse_manifest_files(&dir, None, Uuid::new_v4(), Uuid::new_v4())
        .expect("synthetic backup parses");

    let missing = artifacts
        .iter()
        .find(|a| a.metadata["file_id"] == serde_json::json!(absent))
        .expect("the entry is still emitted: the manifest proves it was on the device");
    assert!(missing.data.is_none());
    assert_eq!(
        missing.metadata["content_incomplete"],
        serde_json::json!(true),
        "an entry with no bytes must not present as an empty file"
    );
    assert_eq!(
        missing.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(
        missing.metadata["content_omitted"],
        "backup_blob_unreadable"
    );

    // The file that IS on disk stays clean.
    let ok = artifacts
        .iter()
        .find(|a| a.metadata["file_id"] == serde_json::json!(present))
        .unwrap();
    assert!(ok.data.is_some());
    assert!(ok.metadata.get("content_incomplete").is_none());

    // And the backup itself says its file set has holes.
    let summary = artifacts
        .iter()
        .find(|a| a.metadata["status"] == serde_json::json!("PartialExtraction"))
        .expect("a backup-level gap summary must be emitted");
    assert_eq!(
        summary.metadata["files_without_content"],
        serde_json::json!(1)
    );
    assert_eq!(
        summary.metadata["content_incomplete"],
        serde_json::json!(true)
    );
    assert_eq!(
        summary.metadata["inventory_incomplete"],
        serde_json::json!(true)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A symbolic link stores no file in the backup — its content is the target
/// path the manifest carries. Counting it as a missing blob would raise the
/// "partially extracted" banner on ordinary, complete backups, and a warning
/// that fires on every case is a warning an examiner learns to skip.
#[test]
fn a_symlink_without_a_stored_blob_is_not_counted_as_a_gap() {
    let file = "eeeeeeee55555555eeeeeeee55555555eeeeeeee";
    let link = "ffffffff66666666ffffffff66666666ffffffff";
    let dir = synthetic_backup(
        &[
            (file, "Library/SMS/sms.db", 1, None),
            (link, "Media/DCIM/link", 4, None),
        ],
        &[file],
    );

    let parser = IosBackupParser::new();
    let artifacts = parser
        .parse_manifest_files(&dir, None, Uuid::new_v4(), Uuid::new_v4())
        .unwrap();

    let sym = artifacts
        .iter()
        .find(|a| a.metadata["file_id"] == serde_json::json!(link))
        .expect("the symlink entry is still emitted");
    assert_eq!(sym.metadata["is_symlink"], serde_json::json!(true));
    assert!(
        sym.metadata.get("content_incomplete").is_none(),
        "a symlink with no stored blob is complete, not incomplete"
    );
    assert!(
        artifacts
            .iter()
            .all(|a| a.metadata["status"] != serde_json::json!("PartialExtraction")),
        "a backup whose only blob-less entry is a symlink must raise no gap summary"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A backup with every blob present must NOT raise the summary: the marker only
/// carries meaning if the healthy path does not set it.
#[test]
fn a_complete_backup_raises_no_gap_summary() {
    let id = "cccccccc33333333cccccccc33333333cccccccc";
    let dir = synthetic_backup(&[(id, "Library/SMS/sms.db", 1, None)], &[id]);
    let parser = IosBackupParser::new();
    let artifacts = parser
        .parse_manifest_files(&dir, None, Uuid::new_v4(), Uuid::new_v4())
        .unwrap();
    assert_eq!(artifacts.len(), 1);
    assert!(artifacts[0].metadata.get("content_incomplete").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// B6-036: an entry whose metadata blob will not decode has null size and null
/// MACB times. Unflagged that is identical to an entry the backup stored no
/// metadata for, so the examiner reads "undated" as a fact about the device.
#[test]
fn an_undecodable_metadata_blob_is_declared_on_the_entry() {
    let id = "dddddddd44444444dddddddd44444444dddddddd";
    let dir = synthetic_backup(
        &[(id, "Library/SMS/sms.db", 1, Some(b"not-a-plist"))],
        &[id],
    );
    let parser = IosBackupParser::new();
    let artifacts = parser
        .parse_manifest_files(&dir, None, Uuid::new_v4(), Uuid::new_v4())
        .unwrap();

    let entry = artifacts
        .iter()
        .find(|a| a.metadata["file_id"] == serde_json::json!(id))
        .unwrap();
    assert!(entry.metadata["size"].is_null());
    assert_eq!(
        entry.metadata["inventory_incomplete"],
        serde_json::json!(true),
        "unknown size/times must not render as absent size/times"
    );
    assert_eq!(
        entry.metadata["inventory_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(entry.metadata.get("metadata_parse_error").is_some());

    let summary = artifacts
        .iter()
        .find(|a| a.metadata["status"] == serde_json::json!("PartialExtraction"))
        .expect("the backup-level summary counts undecodable metadata too");
    assert_eq!(
        summary.metadata["entries_without_metadata"],
        serde_json::json!(1)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// B6-019: a legacy `Manifest.mbdb` that desyncs mid-record yields a prefix of
/// the file list. The backup must carry a record saying so.
#[test]
fn a_truncated_legacy_manifest_emits_an_inventory_incomplete_record() {
    let src = fixture_dir().join("mbdb_basic").join("Manifest.mbdb");
    let whole = std::fs::read(&src).expect("fixture readable");

    let dir = std::env::temp_dir().join(format!("seance_ios_mbdbtrunc_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Manifest.plist"), b"<plist></plist>").unwrap();
    std::fs::write(dir.join("Manifest.mbdb"), &whole[..whole.len() - 8]).unwrap();

    let parser = IosBackupParser::new();
    let artifacts = parser
        .parse_manifest_files(&dir, None, Uuid::new_v4(), Uuid::new_v4())
        .expect("a truncated manifest still yields what it could read");

    let marker = artifacts
        .iter()
        .find(|a| a.metadata["status"] == serde_json::json!("ManifestTruncated"))
        .expect("a short file list must not present as the whole backup");
    assert_eq!(
        marker.metadata["content_incomplete"],
        serde_json::json!(true)
    );
    assert_eq!(
        marker.metadata["inventory_incomplete"],
        serde_json::json!(true)
    );
    assert_eq!(
        marker.metadata["inventory_incomplete_reason"],
        "unresolved_structure"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// --- Encrypted backups must never hand out ciphertext as content (B8-026) ----

fn record_for<'a>(
    records: &'a [manifest_db::ManifestRecord],
    file_id: &str,
) -> &'a manifest_db::ManifestRecord {
    records
        .iter()
        .find(|r| r.file_id == file_id)
        .unwrap_or_else(|| panic!("no manifest record for {file_id}"))
}

fn entry<'a>(artifacts: &'a [Artifact], rel: &str) -> &'a Artifact {
    artifacts
        .iter()
        .find(|a| a.metadata["relative_path"] == json!(rel))
        .unwrap_or_else(|| panic!("no artifact emitted for {rel}"))
}

/// B8-026: inside an encrypted backup **every** stored blob is ciphertext, so a
/// file may only be attached as content once it has actually been decrypted.
///
/// Three entries previously escaped that rule and went out with the raw
/// encrypted bytes attached and `"decrypted": true` stamped on the record: a
/// missing `ProtectionClass` field (defaulted to 0, read as "not protected"), an
/// `EncryptionKey` blob too short to survive stripping its class prefix, and an
/// entry with no `EncryptionKey` at all. An examiner would then hash and exhibit
/// ciphertext as recovered plaintext.
#[test]
fn an_encrypted_backup_never_attaches_ciphertext_as_recovered_content() {
    let plain_a: &[u8] = b"class field and key present: fully recoverable plaintext";
    let plain_b: &[u8] = b"no ProtectionClass field: the class lives on the wrapped key";
    let plain_c: &[u8] = b"truncated key blob: nothing here can unwrap this file";
    let plain_d: &[u8] = b"no EncryptionKey at all in this manifest entry";
    // A symlink stores nothing: the fixture writes no blob for it.
    let plain_e: &[u8] = b"";

    let (dir, password) = build_encrypted_backup(&[
        (
            "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "Library/SMS/sms.db",
            1,
            plain_a,
            KeyShape::ClassFieldAndKey,
        ),
        (
            "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
            "Library/Notes/notes.sqlite",
            1,
            plain_b,
            KeyShape::KeyOnlyNoClassField,
        ),
        (
            "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
            "Library/Mail/Envelope Index",
            1,
            plain_c,
            KeyShape::TruncatedKeyBlob,
        ),
        (
            "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
            "Media/DCIM/IMG_0001.JPG",
            1,
            plain_d,
            KeyShape::NoKey,
        ),
        // A symlink: no stored blob, no per-file key, nothing to decrypt. The
        // ordinary case, and it must not be counted as a file that could not be
        // recovered.
        (
            "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
            "Media/DCIM/link",
            4,
            plain_e,
            KeyShape::NoKey,
        ),
    ]);

    let parser = IosBackupParser::with_password(password);
    let artifacts = parser
        .parse_backup(
            &dir,
            parser.password.as_deref(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .expect("a synthetic encrypted backup with the right password parses");

    // (1) Both class carriers present: decrypts, and the content is plaintext.
    let a = entry(&artifacts, "Library/SMS/sms.db");
    assert_eq!(a.metadata["decrypted"], json!(true));
    assert_eq!(
        a.metadata["protection_class_source"],
        "manifest_protection_class_field"
    );
    let ds = a.data.as_ref().expect("a decrypted file carries its bytes");
    assert_eq!(ds.size(), plain_a.len() as u64);
    let mut buf = vec![0u8; plain_a.len()];
    ds.read_at(0, &mut buf).unwrap();
    assert_eq!(buf, plain_a);

    // (2) No `ProtectionClass` field. The 4-byte prefix on the wrapped key is
    // the only carrier left, and it used to be stripped and discarded — the
    // class defaulted to 0 and the ciphertext went out as "decrypted".
    let b = entry(&artifacts, "Library/Notes/notes.sqlite");
    assert_eq!(b.metadata["decrypted"], json!(true));
    assert!(
        b.metadata["protection_class"].is_null(),
        "the manifest field really is absent for this entry"
    );
    assert_eq!(b.metadata["protection_class_used"], json!(FIXTURE_CLASS));
    assert_eq!(
        b.metadata["protection_class_source"],
        "encryption_key_class_prefix"
    );
    let ds = b.data.as_ref().expect("a decrypted file carries its bytes");
    let mut buf = vec![0u8; plain_b.len()];
    ds.read_at(0, &mut buf).unwrap();
    assert_eq!(
        buf, plain_b,
        "content must be the decrypted plaintext, never the stored ciphertext"
    );

    // (3) A 4-byte EncryptionKey blob leaves nothing to unwrap with.
    let c = entry(&artifacts, "Library/Mail/Envelope Index");
    assert!(
        c.data.is_none(),
        "ciphertext must never be attached as file content"
    );
    assert_eq!(c.metadata["status"], "NoFileKey");
    assert_eq!(c.metadata["decrypted"], json!(false));
    assert_eq!(c.metadata["content_incomplete"], json!(true));
    assert_eq!(c.metadata["content_incomplete_reason"], "encrypted");
    assert!(
        c.metadata["message"]
            .as_str()
            .unwrap()
            .contains("too short"),
        "the record must say why, got {:?}",
        c.metadata["message"]
    );

    // (4) No EncryptionKey at all.
    let d = entry(&artifacts, "Media/DCIM/IMG_0001.JPG");
    assert!(d.data.is_none());
    assert_eq!(d.metadata["status"], "NoFileKey");
    assert_eq!(d.metadata["decrypted"], json!(false));
    assert_eq!(d.metadata["content_incomplete"], json!(true));

    // (5) A symlink stores no file and carries no key. That is the ordinary,
    // complete case — not a decryption failure — so it must neither be flagged
    // on the entry nor counted in the backup's "not recovered" total, which the
    // unencrypted path already says (a warning that fires on every backup is one
    // an examiner learns to skip).
    let link = entry(&artifacts, "Media/DCIM/link");
    assert!(link.data.is_none());
    assert_eq!(link.metadata["is_symlink"], json!(true));
    assert_eq!(
        link.metadata["content_omitted"],
        "symlink_has_no_stored_content"
    );
    assert!(
        link.metadata.get("status").is_none(),
        "a symlink is not a failed decryption, got {:?}",
        link.metadata.get("status")
    );
    assert!(link.metadata.get("content_incomplete").is_none());

    // The backup itself states that two of its files were not recovered — the
    // two with unusable keys, and not the symlink.
    let summary = artifacts
        .iter()
        .find(|a| a.metadata["status"] == json!("PartialDecryption"))
        .expect("a partially decrypted backup must say so at backup level");
    assert_eq!(summary.metadata["files_not_recovered"], json!(2));

    // The invariant behind all four: nothing claims decryption without having
    // produced bytes to back the claim.
    for art in &artifacts {
        if art.metadata["decrypted"] == json!(true) {
            assert!(
                art.data.is_some(),
                "'decrypted: true' on an entry with no content is a claim about \
                 bytes that were never produced: {:?}",
                art.metadata["relative_path"]
            );
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The same class as B8-026, on the path the product actually runs.
///
/// `IosBackupParser::new()` is what both binaries register, so every backup goes
/// down the unencrypted path. A `Manifest.plist` that does not declare the
/// backup encrypted, holding manifest entries that each carry a per-file
/// `EncryptionKey`, used to have those entries' stored blobs attached verbatim
/// as their content — wrapped ciphertext, exhibited as the recovered file, with
/// nothing on the record to say so.
#[test]
fn an_entry_with_a_per_file_key_never_has_its_ciphertext_attached() {
    let clear = "1111222233334444555566667777888899990000";
    let wrapped = "aaaabbbbccccddddeeeeffff1111222233334444";
    let blob = metadata_blob(24, &KeyShape::ClassFieldAndKey, &[0xE1u8; 40]);

    let dir = synthetic_backup(
        &[
            (clear, "Library/SMS/sms.db", 1, None),
            (
                wrapped,
                "Library/Notes/notes.sqlite",
                1,
                Some(blob.as_slice()),
            ),
        ],
        &[clear, wrapped],
    );

    let parser = IosBackupParser::new();
    let artifacts = parser
        .parse_manifest_files(&dir, None, Uuid::new_v4(), Uuid::new_v4())
        .expect("synthetic backup parses");

    let enc = artifacts
        .iter()
        .find(|a| a.metadata["file_id"] == json!(wrapped))
        .expect("the entry is still listed: the manifest proves it was on the device");
    assert!(
        enc.data.is_none(),
        "a wrapped blob must never be attached as the file's recovered content"
    );
    assert_eq!(enc.metadata["content_incomplete"], json!(true));
    assert_eq!(enc.metadata["content_incomplete_reason"], "encrypted");
    assert_eq!(enc.metadata["content_omitted"], "stored_blob_is_ciphertext");

    // An entry with no per-file key is ordinary content and stays untouched.
    let ok = artifacts
        .iter()
        .find(|a| a.metadata["file_id"] == json!(clear))
        .unwrap();
    assert!(ok.data.is_some());
    assert!(ok.metadata.get("content_incomplete").is_none());

    // And the backup says at its own level that a file's content is absent.
    let summary = artifacts
        .iter()
        .find(|a| a.metadata["status"] == json!("PartialDecryption"))
        .expect("a backup holding unreadable ciphertext must say so at backup level");
    assert_eq!(summary.metadata["files_not_recovered"], json!(1));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Write a `Manifest.db` holding one row per `(file_id, relative_path, shape)`
/// and return its path, with the directory it lives in.
fn manifest_db_with_shapes(rows: Vec<(&str, &str, KeyShape)>, wrapped_key: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("seance_ios_keyshape_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("Manifest.db");

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, \
         relativePath TEXT, flags INTEGER, file BLOB);",
    )
    .unwrap();
    for (file_id, rel, shape) in rows {
        let blob = metadata_blob(1024, &shape, wrapped_key);
        conn.execute(
            "INSERT INTO Files (fileID, domain, relativePath, flags, file) \
             VALUES (?1, 'HomeDomain', ?2, 1, ?3)",
            rusqlite::params![file_id, rel, blob],
        )
        .unwrap();
    }
    drop(conn);
    db_path
}

/// The 4-byte prefix on the wrapped `EncryptionKey` is the manifest's second
/// statement of a file's protection class. It used to be stripped and thrown
/// away, so an entry whose `ProtectionClass` field was absent carried no class
/// at all — and an unknown class was then read as "not protected" (B8-026).
///
/// A key blob too short to survive the strip must also be recorded: an absent
/// key reads downstream as a file that needed no decryption.
#[test]
fn the_protection_class_prefix_on_the_key_is_kept_and_a_short_key_blob_is_recorded() {
    let wrapped = vec![0xC7u8; 40];
    let db_path = manifest_db_with_shapes(
        vec![
            (
                "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11",
                "Library/Notes/notes.sqlite",
                KeyShape::KeyOnlyNoClassField,
            ),
            (
                "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22",
                "Library/Mail/Envelope Index",
                KeyShape::TruncatedKeyBlob,
            ),
            (
                "cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33",
                "Media/DCIM/IMG_0002.JPG",
                KeyShape::NoKey,
            ),
        ],
        &wrapped,
    );

    let records = manifest_db::ManifestDb::parse(&db_path).unwrap();

    // The metadata blob states no ProtectionClass; the key prefix does.
    let no_field = record_for(&records, "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11");
    assert!(no_field.protection_class.is_none());
    assert_eq!(
        no_field.key_class,
        Some(FIXTURE_CLASS),
        "the class prefix on the wrapped key must be kept, not discarded"
    );
    assert_eq!(no_field.encryption_key.as_deref(), Some(wrapped.as_slice()));
    assert!(no_field.encryption_key_error.is_none());

    // Four bytes of NS.data: the prefix and nothing else.
    let short = record_for(&records, "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22");
    assert!(short.encryption_key.is_none());
    assert!(short.key_class.is_none());
    assert!(
        short
            .encryption_key_error
            .as_deref()
            .is_some_and(|e| e.contains("too short")),
        "a key that was present but unusable must not look like a key that was \
         never there, got {:?}",
        short.encryption_key_error
    );

    // No EncryptionKey entry at all: nothing to report beyond its absence.
    let none = record_for(&records, "cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33");
    assert!(none.encryption_key.is_none());
    assert!(none.encryption_key_error.is_none());
    assert_eq!(none.protection_class, Some(FIXTURE_CLASS as i64));

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

/// An NSKeyedArchiver blob that yields no root dictionary yielded *nothing* —
/// every field null, with no error — which is the same shape as an entry the
/// backup stored no metadata for (B6-036, same class as B8-026).
#[test]
fn an_archiver_blob_with_no_root_object_is_recorded_as_unreadable() {
    let mut top = plist::Dictionary::new();
    top.insert("root".into(), plist::Value::Uid(plist::Uid::new(1)));
    let mut archive = plist::Dictionary::new();
    archive.insert(
        "$archiver".into(),
        plist::Value::String("NSKeyedArchiver".into()),
    );
    archive.insert("$top".into(), plist::Value::Dictionary(top));
    // $objects holds only "$null": object 1 does not exist.
    archive.insert(
        "$objects".into(),
        plist::Value::Array(vec![plist::Value::String("$null".into())]),
    );
    let mut blob = Vec::new();
    plist::Value::Dictionary(archive)
        .to_writer_binary(&mut blob)
        .unwrap();

    let dir = std::env::temp_dir().join(format!("seance_ios_norootobj_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("Manifest.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, \
             relativePath TEXT, flags INTEGER, file BLOB);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO Files VALUES ('ab', 'HomeDomain', 'Library/SMS/sms.db', 1, ?1)",
            rusqlite::params![blob],
        )
        .unwrap();
    }

    let records = manifest_db::ManifestDb::parse(&db_path).unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].size.is_none());
    assert!(
        records[0].metadata_error.is_some(),
        "a blob that decoded to nothing must not present as 'the backup stored \
         no metadata for this file'"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// B6-018: an encrypted backup with no password contributes nothing to the
/// case. A status string alone is invisible to every consumer keyed on the
/// standard incompleteness pair.
#[test]
fn an_encrypted_backup_without_a_password_carries_the_standard_pair() {
    let dir = std::env::temp_dir().join(format!("seance_ios_enc_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Manifest.plist"),
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
          <plist version=\"1.0\"><dict>\
          <key>IsEncrypted</key><true/>\
          <key>Version</key><string>10.0</string>\
          </dict></plist>",
    )
    .unwrap();
    // A Manifest.db must exist for the directory to be recognised as a backup.
    std::fs::write(dir.join("Manifest.db"), b"SQLite format 3\x00").unwrap();

    let parser = IosBackupParser::new(); // no password
    let artifacts = parser
        .parse_backup(
            &dir,
            parser.password.as_deref(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .expect("an encrypted backup without a password is not an error");
    assert_eq!(artifacts.len(), 1);
    let md = &artifacts[0].metadata;
    assert_eq!(md["status"], "encrypted_no_password");
    assert_eq!(md["content_incomplete"], serde_json::json!(true));
    assert_eq!(md["content_incomplete_reason"], "encrypted");
    assert_eq!(md["inventory_incomplete"], serde_json::json!(true));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A manifest `fileID` is evidence, not a path (HUNT-042). One that names a
/// path — relative, absolute, or not even ASCII — must never be joined onto the
/// backup directory: joined, `../outside.txt` read a file beside the backup
/// into the case as backup content, `/etc/hostname` replaced the backup path,
/// and a non-ASCII first character panicked the parser.
#[test]
fn a_manifest_file_id_that_names_a_path_is_refused_not_joined() {
    let root = std::env::temp_dir().join(format!("seance_ios_hostile_{}", Uuid::new_v4()));
    let backup = root.join("backup");
    std::fs::create_dir_all(&backup).unwrap();
    let secret: &[u8] = b"NOT PART OF THE BACKUP";
    std::fs::write(root.join("outside.txt"), secret).unwrap();

    let hostile = ["../outside.txt", "/etc/hostname", "\u{e9}bad", ""];
    {
        let conn = rusqlite::Connection::open(backup.join("Manifest.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, \
             relativePath TEXT, flags INTEGER, file BLOB);",
        )
        .unwrap();
        for (i, id) in hostile.iter().enumerate() {
            conn.execute(
                "INSERT INTO Files (fileID, domain, relativePath, flags, file) \
                 VALUES (?1, ?2, ?3, ?4, NULL)",
                rusqlite::params![id, "HomeDomain", format!("Library/f{i}.db"), 1_i64],
            )
            .unwrap();
        }
    }

    let artifacts = IosBackupParser::new()
        .parse_manifest_files(&backup, None, Uuid::new_v4(), Uuid::new_v4())
        .expect("a hostile manifest is parsed, not panicked on");

    for a in &artifacts {
        if let Some(ds) = &a.data {
            let mut buf = vec![0u8; secret.len()];
            let n = ds.read_at(0, &mut buf).unwrap_or(0);
            assert_ne!(
                &buf[..n],
                secret,
                "bytes from outside the backup reached the case: {}",
                a.metadata
            );
        }
    }
    // Direct check of the resolver, including the layout fallback it keeps.
    for id in hostile {
        assert!(
            IosBackupParser::resolve_backup_file_path(&backup, id).is_err(),
            "{id:?} must be refused"
        );
    }
    assert!(IosBackupParser::resolve_backup_file_path(&backup, "abcdef0123").is_ok());
    let _ = std::fs::remove_dir_all(&root);
}

/// HUNT-085, as amended by SEC-204. The process-level password (the startup
/// route) still opens a backup when no credential is supplied for the run, so
/// adding the interactive route did not break the startup one.
#[test]
fn the_process_level_password_still_opens_a_backup_without_a_credential() {
    let (dir, password) = one_file_encrypted_backup();
    let artifact = backup_artifact_for(&dir);
    let out = IosBackupParser::with_password(password)
        .process(&artifact)
        .expect("the process-level password opens the backup");
    assert_eq!(
        entry(&out, "Library/SMS/sms.db").metadata["decrypted"],
        json!(true)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A supplied credential beats the process-level password: the one the
/// examiner just typed is the more specific answer.
#[test]
fn a_supplied_credential_beats_the_process_level_password() {
    use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
    let (dir, password) = one_file_encrypted_backup();
    let artifact = backup_artifact_for(&dir);
    let cred = std::sync::Arc::new(RunCredential::new(
        artifact.id,
        CredentialKind::IosBackupPassword,
        "not-the-password".to_string(),
        "erin",
    ));
    let parser = IosBackupParser::with_password(password);
    credential::scoped(Some(cred.clone()), || parser.process(&artifact)).unwrap();
    assert!(
        matches!(cred.outcome(), Some(CredentialOutcome::Rejected { .. })),
        "the credential, not the process secret, is the password tried"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// HUNT-090. An encrypted backup ingested without a password records that no
/// files from it are in this case — true when written, false the moment the
/// password opens it, and nothing retracts it. The run that decrypts must
/// therefore say what it did, in the case, and name the statement it answers.
#[test]
fn a_decrypted_backup_says_so_and_names_the_statement_it_supersedes() {
    let record = IosBackupParser::decrypted_summary(
        std::path::Path::new("/evidence/ios17/Backup/00008030-001259123E50802E"),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        9_212,
        3,
        &[],
    );

    assert_eq!(record.metadata["type"], "IosBackupInfo");
    assert_eq!(record.metadata["status"], "decrypted");
    assert_eq!(
        record.metadata["supersedes_status"], "encrypted_no_password",
        "the record must name the statement it answers"
    );
    assert_eq!(record.metadata["files_recovered"], 9_209);
    assert_eq!(record.metadata["files_not_recovered"], 3);
    assert!(record.metadata["message"]
        .as_str()
        .unwrap()
        .contains("before the password was given"));

    // It is a statement that the data IS here. Carrying the incompleteness pair
    // would put a decrypted backup in the census of what was not recovered,
    // which is the opposite of what happened.
    assert!(record.metadata.get("content_incomplete").is_none());
    assert!(record.metadata.get("inventory_incomplete").is_none());
}

/// §1.5 slice A. The decrypted-backup record states which keybag classes the
/// password opened and which are device-bound (WRAP & 1: wrapped under the
/// device's hardware key too), so "decrypted" is never read as "every class
/// is open". It names classes only — never a key byte.
#[test]
fn a_decrypted_backup_states_its_keybag_class_states() {
    use crate::crypto::ClassKeyState::{DeviceBound, Usable};
    let record = IosBackupParser::decrypted_summary(
        std::path::Path::new("/evidence/b"),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        10,
        0,
        &[(1, Usable), (5, DeviceBound), (7, Usable), (9, DeviceBound)],
    );
    let classes = &record.metadata["keybag_classes"];
    assert_eq!(classes["total"], 4);
    assert_eq!(classes["usable"], serde_json::json!([1, 7]));
    assert_eq!(classes["device_bound"], serde_json::json!([5, 9]));
    assert_eq!(classes["not_unwrapped"], serde_json::json!([]));
    assert!(classes["statement"]
        .as_str()
        .unwrap()
        .contains("device's hardware key"));
}

/// SEC-204. The password for an encrypted backup reaches this parser through
/// the credential route — a zeroed, redacted `RunCredential` scoped to the one
/// run — and the parser reports what the password did, so the orchestrator can
/// audit the outcome and decide whether the run's records are kept.
fn backup_artifact_for(dir: &std::path::Path) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "path": dir.to_string_lossy() }),
    )
}

fn one_file_encrypted_backup() -> (PathBuf, String) {
    build_encrypted_backup(&[(
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "Library/SMS/sms.db",
        1,
        b"the plaintext of the only file in this backup",
        KeyShape::ClassFieldAndKey,
    )])
}

#[test]
fn a_supplied_backup_credential_opens_the_backup_and_is_reported_accepted() {
    use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
    let (dir, password) = one_file_encrypted_backup();
    let artifact = backup_artifact_for(&dir);
    let cred = std::sync::Arc::new(RunCredential::new(
        artifact.id,
        CredentialKind::IosBackupPassword,
        password,
        "erin",
    ));

    // No process-level secret and nothing in the artifact's metadata: the
    // credential is the only way the password can arrive.
    let parser = IosBackupParser::new();
    let out = credential::scoped(Some(cred.clone()), || parser.process(&artifact))
        .expect("the right password opens the backup");

    assert_eq!(cred.outcome(), Some(CredentialOutcome::Accepted));
    let sms = entry(&out, "Library/SMS/sms.db");
    assert_eq!(sms.metadata["decrypted"], json!(true));
    assert!(
        out.iter().any(|a| a.metadata["status"] == "decrypted"),
        "the decrypted summary names the statement it supersedes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wrong_backup_credential_is_reported_rejected_and_the_reason_does_not_contain_it() {
    use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
    const WRONG: &str = "Tr0ub4dor&3-not-the-password";
    let (dir, _password) = one_file_encrypted_backup();
    let artifact = backup_artifact_for(&dir);
    let cred = std::sync::Arc::new(RunCredential::new(
        artifact.id,
        CredentialKind::IosBackupPassword,
        WRONG.to_string(),
        "erin",
    ));

    let parser = IosBackupParser::new();
    // A refused secret is a verdict, not a module fault: the run returns and
    // the orchestrator keeps none of its records.
    let out = credential::scoped(Some(cred.clone()), || parser.process(&artifact))
        .expect("a wrong password is a verdict on the secret, not a module error");
    assert!(
        out.iter().all(|a| a.metadata["decrypted"] != json!(true)),
        "nothing may be decrypted with a refused password"
    );

    match cred.outcome() {
        Some(CredentialOutcome::Rejected { reason }) => {
            assert!(!reason.contains(WRONG), "{reason}");
            assert!(reason.contains("class key"), "{reason}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_backup_password_in_artifact_metadata_is_no_longer_read() {
    // SEC-204: the metadata channel (run_module's `secrets` merge) is retired.
    // A password left in metadata must not open the backup.
    let (dir, password) = one_file_encrypted_backup();
    let mut artifact = backup_artifact_for(&dir);
    artifact
        .metadata
        .as_object_mut()
        .unwrap()
        .insert("ios_backup_password".into(), json!(password));
    let out = IosBackupParser::new().process(&artifact).unwrap();
    assert!(
        out.iter()
            .any(|a| a.metadata["status"] == "encrypted_no_password"),
        "without a credential or a process-level password the backup stays locked"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rewrite the synthetic backup's keybag. The fixture's keybag ends with its
/// one class key's `WRAP` and `WPKY` entries; `f` receives the bytes up to
/// (not including) `WRAP`, and returns the replacement tail.
fn rewrite_keybag_tail(dir: &std::path::Path, tail: &[u8]) {
    let path = dir.join("Manifest.plist");
    let mut dict = plist::Value::from_file(&path)
        .unwrap()
        .into_dictionary()
        .unwrap();
    let keybag = dict
        .get("BackupKeyBag")
        .and_then(|v| v.as_data())
        .unwrap()
        .to_vec();
    let at = keybag
        .windows(4)
        .position(|w| w == b"WRAP")
        .expect("fixture keybag has a WRAP entry");
    let mut rewritten = keybag[..at].to_vec();
    rewritten.extend_from_slice(tail);
    dict.insert("BackupKeyBag".into(), plist::Value::Data(rewritten));
    plist::Value::Dictionary(dict).to_file_xml(&path).unwrap();
}

fn ios_credential(artifact: &Artifact, secret: String) -> std::sync::Arc<RunCredential> {
    std::sync::Arc::new(RunCredential::new(
        artifact.id,
        seance_core::credential::CredentialKind::IosBackupPassword,
        secret,
        "erin",
    ))
}

/// SEC-204 review. A keybag whose class keys are none of them wrapped with the
/// passcode (WRAP bit 2 clear) never tries the password — so the password
/// must not be reported **accepted**: nothing tested it.
#[test]
fn a_keybag_with_no_passcode_wrapped_key_does_not_report_the_password_accepted() {
    use seance_core::credential;
    let (dir, password) = one_file_encrypted_backup();
    // WRAP = 1 (device-UID wrapped only), key bytes unchanged.
    let mut tail = tlv(b"WRAP", &1u32.to_be_bytes());
    tail.extend(tlv(b"WPKY", &[0x33u8; 40]));
    rewrite_keybag_tail(&dir, &tail);
    let artifact = backup_artifact_for(&dir);
    let cred = ios_credential(&artifact, password);

    let _ = credential::scoped(Some(cred.clone()), || {
        IosBackupParser::new().process(&artifact)
    });
    assert_eq!(
        cred.outcome(),
        None,
        "a password nothing tested is neither accepted nor rejected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// SEC-204 review. A wrapped class key that is not a valid RFC 3394 length is
/// a malformed keybag, whatever the password: a module error, not a verdict
/// on the password.
#[test]
fn a_malformed_wrapped_class_key_is_a_module_error_not_a_rejected_password() {
    use seance_core::credential;
    let (dir, password) = one_file_encrypted_backup();
    let mut tail = tlv(b"WRAP", &2u32.to_be_bytes());
    tail.extend(tlv(b"WPKY", &[0x33u8; 12])); // not a multiple of 8
    rewrite_keybag_tail(&dir, &tail);
    let artifact = backup_artifact_for(&dir);
    let cred = ios_credential(&artifact, password);

    let out = credential::scoped(Some(cred.clone()), || {
        IosBackupParser::new().process(&artifact)
    });
    assert!(
        out.is_err(),
        "a malformed keybag is a module error: {out:?}"
    );
    assert_eq!(cred.outcome(), None, "no verdict on the password");
    let _ = std::fs::remove_dir_all(&dir);
}

/// SEC-204 review. An integrity failure cannot tell a wrong password from a
/// corrupted wrapped key, so the rejection says both.
#[test]
fn a_rejected_backup_password_says_the_keybag_may_be_corrupt_instead() {
    use seance_core::credential::{self, CredentialOutcome};
    let (dir, _password) = one_file_encrypted_backup();
    let artifact = backup_artifact_for(&dir);
    let cred = ios_credential(&artifact, "not-it".to_string());
    credential::scoped(Some(cred.clone()), || {
        IosBackupParser::new().process(&artifact)
    })
    .unwrap();
    match cred.outcome() {
        Some(CredentialOutcome::Rejected { reason }) => {
            assert!(reason.contains("corrupt"), "{reason}");
            assert!(reason.contains("wrong"), "{reason}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// --- BUG-026: re-reading an encrypted backup's files after ingest ---
//
// The synthetic backup pins the mechanism (the same keybag, key-wrap and AES
// code the ingest path uses); it is not validation against a real device's
// backup.

const REREAD_FILE_ID: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const REREAD_PLAIN: &[u8] = b"the plaintext of the only file in this backup";

fn read_all(ds: &dyn seance_core::data_source::DataSource) -> Vec<u8> {
    let mut buf = vec![0u8; ds.size() as usize];
    let n = ds.read_at(0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

#[test]
fn a_backup_file_reopens_to_its_plaintext_with_the_password() {
    use sha2::{Digest, Sha256};
    let (dir, password) = one_file_encrypted_backup();

    // What ingest attaches for this file, and its digest.
    let parser = IosBackupParser::with_password(password.clone());
    let artifacts = parser
        .parse_backup(&dir, Some(&password), Uuid::new_v4(), Uuid::new_v4())
        .unwrap();
    let ingested = read_all(
        entry(&artifacts, "Library/SMS/sms.db")
            .data
            .as_deref()
            .unwrap(),
    );

    let ds = open_backup_file_plaintext(&dir, REREAD_FILE_ID, &password)
        .expect("the right password reopens the file");
    let reread = read_all(ds.as_ref());
    assert_eq!(reread, REREAD_PLAIN);
    assert_eq!(Sha256::digest(&reread), Sha256::digest(&ingested));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wrong_password_does_not_reopen_a_backup_file() {
    let (dir, _password) = one_file_encrypted_backup();
    match unlock_backup(&dir, "Tr0ub4dor&3-not-the-password") {
        Err(UnlockError::WrongPassword(reason)) => {
            assert!(
                !reason.contains("Tr0ub4dor"),
                "the reason never names the secret"
            );
        }
        Err(other) => panic!("expected WrongPassword, got {other:?}"),
        Ok(_) => panic!("a wrong password must not unlock the backup"),
    }
    assert!(open_backup_file_plaintext(&dir, REREAD_FILE_ID, "nope").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_file_id_absent_from_the_manifest_is_an_error_not_empty_content() {
    let (dir, password) = one_file_encrypted_backup();
    let unlocked = unlock_backup(&dir, &password).expect("the right password unlocks");
    let err = unlocked
        .open_file("ffffffffffffffffffffffffffffffffffffffff")
        .expect_err("an unknown file_id is an error");
    assert!(err.to_string().contains("not in"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unlocked_backup_does_not_print_its_keys() {
    let (dir, password) = one_file_encrypted_backup();
    let unlocked = unlock_backup(&dir, &password).expect("the right password unlocks");
    let dbg = format!("{unlocked:?}");
    // The synthetic class key is 32 bytes of 0x5A.
    assert!(!dbg.to_lowercase().contains("5a5a5a5a"), "{dbg}");
    assert!(!dbg.contains("90, 90, 90"), "{dbg}");
    assert!(dbg.contains("redacted"), "{dbg}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unencrypted_backup_is_not_unlocked() {
    match unlock_backup(&fixture_dir().join("sqlite_basic"), "x") {
        Err(UnlockError::NotEncrypted) => {}
        other => panic!("expected NotEncrypted, got {:?}", other.err()),
    }
}

// --- HUNT-111: the keychain inside an encrypted backup ---
//
// A synthetic backup pins the hook — that `KeychainDomain/keychain-backup.plist`
// is read while the keybag is in scope, parented to its file, and that the
// secret reaches no record. The real-evidence known answer is
// `tests/hickman_ios17_keychain.rs`.

const KC_FILE_ID: &str = KEYCHAIN_FILE_ID;
const KC_SECRET: &[u8] = b"s3cret-wifi-passphrase";

fn keychain_backup_fixture() -> (PathBuf, String) {
    build_keychain_backup(KC_SECRET)
}

#[test]
fn an_encrypted_backup_s_keychain_is_listed_under_its_file_and_its_secret_withheld() {
    const SECRET: &[u8] = KC_SECRET;
    let (dir, password) = keychain_backup_fixture();
    let parser = IosBackupParser::with_password(password.clone());
    let out = parser
        .parse_backup(&dir, Some(&password), Uuid::new_v4(), Uuid::new_v4())
        .unwrap();

    let file = entry(&out, "keychain-backup.plist");
    let items: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "IosKeychainItem")
        .collect();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|a| a.parent_id == Some(file.id)));
    assert_eq!(items[0].metadata["state"], "read");
    assert_eq!(items[0].metadata["account"], "HomeNetwork");
    assert_eq!(items[0].metadata["secret_state"], "withheld");
    assert_eq!(items[1].metadata["state"], "device_bound");
    assert_eq!(
        out.iter()
            .filter(|a| a.metadata["type"] == "IosKeychainSummary")
            .count(),
        1
    );
    let every_record: String = out
        .iter()
        .map(|a| a.metadata.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!every_record.contains("s3cret-wifi-passphrase"));
    assert!(!every_record.contains(&hex::encode(SECRET)));

    // The wrong password opens nothing, so no keychain record exists.
    let wrong = parser.parse_backup(&dir, Some("not-it"), Uuid::new_v4(), Uuid::new_v4());
    assert!(wrong
        .map(|v| v.iter().all(|a| a.metadata["type"] != "IosKeychainItem"))
        .unwrap_or(true));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unlocked_backup_re_derives_a_keychain_secret_only_for_the_item_named() {
    let (dir, password) = keychain_backup_fixture();
    let unlocked = unlock_backup(&dir, &password).expect("the password unlocks");
    // The fixture's persistent refs are 20 bytes of the item's index.
    let ref0 = hex::encode([0u8; 20]);

    let secret = unlocked
        .keychain_secret(KC_FILE_ID, "genp", 0, Some(&ref0))
        .expect("the class-7 item's secret re-derives");
    assert_eq!(secret.expose(), KC_SECRET);
    assert!(!format!("{secret:?}").contains("s3cret"));

    // Another item's reference is refused: a changed file never answers for
    // a different item.
    let wrong_ref = hex::encode([9u8; 20]);
    let e = unlocked
        .keychain_secret(KC_FILE_ID, "genp", 0, Some(&wrong_ref))
        .unwrap_err()
        .to_string();
    assert!(e.contains("persistent reference"), "{e}");
    // The device-bound item has no secret this backup can give.
    let e = unlocked
        .keychain_secret(KC_FILE_ID, "genp", 1, None)
        .unwrap_err()
        .to_string();
    assert!(e.contains("device"), "{e}");
    assert!(unlocked
        .keychain_secret(KC_FILE_ID, "genp", 2, None)
        .is_err());
    assert!(unlocked
        .keychain_secret(KC_FILE_ID, "inet", 0, None)
        .is_err());
    for e in [
        unlocked
            .keychain_secret(KC_FILE_ID, "genp", 1, None)
            .unwrap_err(),
        unlocked
            .keychain_secret(KC_FILE_ID, "genp", 0, Some(&wrong_ref))
            .unwrap_err(),
    ] {
        assert!(!e.to_string().contains("s3cret"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
