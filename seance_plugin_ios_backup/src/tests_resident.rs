use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

const BACKUP_DIR: &str =
    "/eliflatt/Library/Application Support/MobileSync/Backup/518e8d766f9b3e76db216f35fdb6b0604e50f61b";

fn plist_bytes(entries: Vec<(&str, plist::Value)>) -> Vec<u8> {
    let mut dict = plist::Dictionary::new();
    for (k, v) in entries {
        dict.insert(k.to_string(), v);
    }
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &plist::Value::Dictionary(dict)).expect("written");
    out
}

fn artifact_at(path: &str, bytes: Vec<u8>) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let name = path.rsplit('/').next().unwrap_or(path);
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": name, "path": path}),
    )
}

fn lockdown_manifest() -> Vec<u8> {
    let mut lockdown = plist::Dictionary::new();
    for (k, v) in [
        ("DeviceName", "Eli's iPhone"),
        ("ProductType", "iPhone10,6"),
        ("ProductVersion", "14.3"),
        ("BuildVersion", "18C66"),
        ("SerialNumber", "F17WQ1J1JCLK"),
        ("UniqueDeviceID", "b2f0a7e0e3a3"),
    ] {
        lockdown.insert(k.into(), plist::Value::String(v.into()));
    }
    plist_bytes(vec![
        ("IsEncrypted", plist::Value::Boolean(false)),
        ("Version", plist::Value::String("10.0".into())),
        ("Lockdown", plist::Value::Dictionary(lockdown)),
    ])
}

#[test]
fn a_backup_inside_an_image_names_the_phone_it_came_from() {
    let out = IosBackupManifestParser::new()
        .process(&artifact_at(
            &format!("{BACKUP_DIR}/Manifest.plist"),
            lockdown_manifest(),
        ))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "IosBackupInfo");
    assert_eq!(m["device_name"], "Eli's iPhone");
    assert_eq!(m["product_type"], "iPhone10,6");
    assert_eq!(m["serial_number"], "F17WQ1J1JCLK");
    assert_eq!(m["backup_path"], BACKUP_DIR);
    // What this record does NOT hold has to be said: the property list names
    // the device and carries no file inventory — that is the Manifest.db
    // record's job (HUNT-109), and this one points at it.
    assert_eq!(m["inventory_incomplete"], true);
    assert!(m["inventory_incomplete_detail"]
        .as_str()
        .expect("detail")
        .contains("manifest_db_in_evidence"));
}

#[test]
fn an_info_plist_gives_the_imei_the_manifest_does_not() {
    let out = IosBackupManifestParser::new()
        .process(&artifact_at(
            &format!("{BACKUP_DIR}/Info.plist"),
            plist_bytes(vec![
                ("Device Name", plist::Value::String("Eli's iPhone".into())),
                ("Product Type", plist::Value::String("iPhone10,6".into())),
                ("IMEI", plist::Value::String("356759080486567".into())),
            ]),
        ))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["imei"], "356759080486567");
    assert_eq!(out[0].metadata["source_kind"], "Info.plist");
}

#[test]
fn a_plist_outside_a_backup_folder_is_not_a_backup() {
    // Every application bundle on a Mac ships an Info.plist.
    let out = IosBackupManifestParser::new()
        .process(&artifact_at(
            "/Applications/Safari.app/Contents/Info.plist",
            plist_bytes(vec![(
                "Device Name",
                plist::Value::String("not a phone".into()),
            )]),
        ))
        .expect("parsed");
    assert!(out.is_empty());
}

#[test]
fn a_plist_in_a_backup_folder_that_names_no_device_is_not_claimed() {
    let out = IosBackupManifestParser::new()
        .process(&artifact_at(
            &format!("{BACKUP_DIR}/Status.plist"),
            plist_bytes(vec![("BackupState", plist::Value::String("new".into()))]),
        ))
        .expect("parsed");
    assert!(out.is_empty(), "only the two manifests are read");

    let out = IosBackupManifestParser::new()
        .process(&artifact_at(
            &format!("{BACKUP_DIR}/Info.plist"),
            plist_bytes(vec![(
                "Target Identifier",
                plist::Value::String("x".into()),
            )]),
        ))
        .expect("parsed");
    assert!(
        out.is_empty(),
        "a manifest that names no device states nothing"
    );
}

#[test]
fn an_encrypted_backup_still_names_its_device() {
    // The point of reading the manifest: this is the one file that answers
    // "whose phone" without the password.
    let mut lockdown = plist::Dictionary::new();
    lockdown.insert(
        "DeviceName".into(),
        plist::Value::String("Locked iPhone".into()),
    );
    let bytes = plist_bytes(vec![
        ("IsEncrypted", plist::Value::Boolean(true)),
        ("Lockdown", plist::Value::Dictionary(lockdown)),
    ]);
    let out = IosBackupManifestParser::new()
        .process(&artifact_at(&format!("{BACKUP_DIR}/Manifest.plist"), bytes))
        .expect("parsed");
    assert_eq!(out[0].metadata["device_name"], "Locked iPhone");
    assert_eq!(out[0].metadata["encrypted"], true);
}

#[test]
fn a_udid_named_backup_folder_is_recognised() {
    assert!(in_backup_directory(
        "/Users/eli/Library/Application Support/MobileSync/Backup/\
         00008030-001259123E50802E/Manifest.plist"
    ));
    assert!(!in_backup_directory("/Users/eli/Documents/Manifest.plist"));
}

// ── Manifest.db in the evidence (HUNT-109) ──────────────────────────────

/// The in-repo `sqlite_basic` fixture — a `Manifest.db` naming one directory
/// and one file, and that file's stored blob under its two-hex shard — copied
/// into a folder named like a real backup, so `FileDataSource` can open the
/// blob beside the manifest.
fn staged_backup_dir() -> tempfile::TempDir {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data/ios_backup_fixtures/sqlite_basic");
    let dir = tempfile::tempdir().unwrap();
    let backup = dir
        .path()
        .join("MobileSync/Backup/518e8d766f9b3e76db216f35fdb6b0604e50f61b");
    std::fs::create_dir_all(backup.join("bb")).unwrap();
    std::fs::copy(fixture.join("Manifest.db"), backup.join("Manifest.db")).unwrap();
    std::fs::copy(
        fixture.join("bb/bb1cc2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9"),
        backup.join("bb/bb1cc2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9"),
    )
    .unwrap();
    dir
}

fn file_artifact(path: &std::path::Path) -> Artifact {
    let data: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path.to_path_buf()).unwrap());
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": "Manifest.db", "path": path.to_string_lossy()}),
    )
}

/// A backup's stored files were in the case under their hashed names and
/// nothing put them back at their device paths, so `sms.db` was findable only
/// as forty hex digits (HUNT-109). With the manifest read from the evidence and
/// a source that can open its neighbours, each blob is re-emitted under the
/// path it had on the phone, with its bytes attached.
#[test]
fn a_manifest_db_in_the_evidence_puts_the_stored_files_back_at_their_device_paths() {
    let dir = staged_backup_dir();
    let manifest = dir
        .path()
        .join("MobileSync/Backup/518e8d766f9b3e76db216f35fdb6b0604e50f61b/Manifest.db");
    let out = IosBackupManifestParser::new()
        .process(&file_artifact(&manifest))
        .expect("parsed");

    let note = out
        .iter()
        .find(|a| a.metadata["name"] == "note.txt")
        .expect("the file the manifest names is emitted under its device name");
    assert_eq!(note.artifact_type, ArtifactType::FileEntry);
    assert_eq!(note.metadata["domain"], "AppDomain-com.example.notes");
    assert_eq!(note.metadata["relative_path"], "Documents/note.txt");
    assert!(note.metadata["path"]
        .as_str()
        .unwrap()
        .ends_with("/AppDomain-com.example.notes/Documents/note.txt"));
    assert!(note.metadata["stored_path"]
        .as_str()
        .unwrap()
        .ends_with("/bb/bb1cc2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9"));
    let data = note
        .data
        .as_ref()
        .expect("the stored blob is attached as this file's bytes");
    let mut buf = vec![0u8; data.size() as usize];
    data.read_at(0, &mut buf).unwrap();
    let on_disk = std::fs::read(
        dir.path()
            .join("MobileSync/Backup/518e8d766f9b3e76db216f35fdb6b0604e50f61b/bb/bb1cc2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9"),
    )
    .unwrap();
    assert_eq!(buf, on_disk);
    assert!(note.metadata.get("content_incomplete").is_none());

    let dir_entry = out
        .iter()
        .find(|a| a.metadata["is_directory"] == true)
        .expect("the directory row is a record, not a file");
    assert_eq!(dir_entry.artifact_type, ArtifactType::ParsedRecord);

    let summary = out
        .iter()
        .find(|a| a.metadata["subtype"] == "manifest_db_in_evidence")
        .expect("summary");
    assert_eq!(summary.metadata["manifest_entries"], 2);
    assert_eq!(summary.metadata["files_reparented"], 1);
    assert_eq!(summary.metadata["files_missing_from_evidence"], 0);
    assert_eq!(summary.metadata["directories"], 1);
    assert!(summary.metadata.get("inventory_incomplete").is_none());
}

/// A manifest whose stored blob is not beside it: the entry is emitted under
/// its device path with no content and says the content is absent, and the
/// summary counts it. Absence from the case is not evidence the file was empty.
#[test]
fn a_manifest_row_whose_blob_is_not_in_the_evidence_is_marked_absent_not_empty() {
    let dir = staged_backup_dir();
    let backup = dir
        .path()
        .join("MobileSync/Backup/518e8d766f9b3e76db216f35fdb6b0604e50f61b");
    std::fs::remove_file(backup.join("bb/bb1cc2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9")).unwrap();
    let out = IosBackupManifestParser::new()
        .process(&file_artifact(&backup.join("Manifest.db")))
        .expect("parsed");
    let note = out
        .iter()
        .find(|a| a.metadata["name"] == "note.txt")
        .unwrap();
    assert!(note.data.is_none());
    assert_eq!(note.metadata["content_incomplete"], true);
    assert_eq!(note.metadata["content_omitted"], "backup_blob_unreadable");
    let summary = out
        .iter()
        .find(|a| a.metadata["subtype"] == "manifest_db_in_evidence")
        .unwrap();
    assert_eq!(summary.metadata["files_missing_from_evidence"], 1);
    assert_eq!(summary.metadata["inventory_incomplete"], true);
    assert!(summary.metadata["inventory_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("not evidence they were empty"));
}

/// The same manifest read from a source that cannot look for neighbours (a
/// bare byte buffer, as a file inside a disk-image filesystem is today): no
/// file is put back, and the record says that is why — not that every file
/// is missing.
#[test]
fn a_source_that_cannot_open_neighbours_says_so_instead_of_reporting_every_file_missing() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data/ios_backup_fixtures/sqlite_basic/Manifest.db");
    let out = IosBackupManifestParser::new()
        .process(&artifact_at(
            &format!("{BACKUP_DIR}/Manifest.db"),
            std::fs::read(fixture).unwrap(),
        ))
        .expect("parsed");
    let note = out
        .iter()
        .find(|a| a.metadata["name"] == "note.txt")
        .unwrap();
    assert!(note.data.is_none());
    assert_eq!(
        note.metadata["content_omitted"],
        "source_cannot_open_neighbours"
    );
    let summary = out
        .iter()
        .find(|a| a.metadata["subtype"] == "manifest_db_in_evidence")
        .unwrap();
    assert_eq!(summary.metadata["files_reparented"], 0);
    assert_eq!(summary.metadata["files_missing_from_evidence"], 0);
    assert_eq!(summary.metadata["inventory_incomplete"], true);
    assert!(summary.metadata["inventory_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("cannot open files beside it"));
}

/// `Manifest.db` is not a name unique to iTunes. One that is not a backup
/// manifest, in a folder that happens to look like one, produces nothing.
#[test]
fn a_manifest_db_that_is_not_a_backup_manifest_produces_nothing() {
    let out = IosBackupManifestParser::new()
        .process(&artifact_at(
            &format!("{BACKUP_DIR}/Manifest.db"),
            b"not a database".to_vec(),
        ))
        .expect("parsed");
    assert!(out.is_empty());
}

#[test]
fn stored_blob_candidates_shard_first_then_flat_and_refuse_a_non_hex_id() {
    assert_eq!(
        stored_blob_candidates("bb1cc2d3"),
        vec!["bb/bb1cc2d3".to_string(), "bb1cc2d3".to_string()]
    );
    assert!(stored_blob_candidates("../etc/passwd").is_empty());
    assert!(stored_blob_candidates("").is_empty());
}
