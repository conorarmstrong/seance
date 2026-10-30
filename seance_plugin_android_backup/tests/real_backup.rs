//! The success-path summary graded on a real backup payload (ROADMAP §1.4).
//!
//! `SEANCE_MAGNET2019_ADB_TAR` is the path to `adb-data.tar` from the Magnet
//! 2019 Android CTF (75,673,600 bytes, SHA-256 `c3ecaef3…8883d1`): the tar
//! payload of a real `adb backup`, as it was published — without its
//! `ANDROID BACKUP` header. The test puts the documented five-line header back
//! in front of it (version 5, uncompressed, no encryption), so the **wrapper is
//! synthetic and the payload is real**. Ground truth is Python's `tarfile`
//! over the same file: 258 regular files, 62 distinct `apps/<package>`
//! directories among them.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    module::ForensicsModule,
    test_support::corpus,
};
use seance_plugin_android_backup::AndroidBackupModule;
use std::sync::Arc;

#[test]
fn the_magnet_2019_backup_payload_unpacks_whole_and_says_so() {
    let Some(path) = corpus::path("SEANCE_MAGNET2019_ADB_TAR") else {
        return;
    };
    let mut bytes = b"ANDROID BACKUP\n5\n0\nnone\n".to_vec();
    bytes.extend(std::fs::read(&path).unwrap());
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": "adb-data.ab" }),
    );
    let out = AndroidBackupModule.process(&art).unwrap();
    let files = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .count();
    assert_eq!(files, 258);
    let summary: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "AndroidBackupSummary")
        .collect();
    assert_eq!(summary.len(), 1);
    let m = &summary[0].metadata;
    assert_eq!(m["entries_extracted"], 258);
    assert_eq!(m["app_packages"], 62);
    assert_eq!(m["format_version"], "5");
    // Every entry is under the per-entry cap and read whole, so this walk
    // may say it unpacked whole.
    assert_eq!(m["entries_content_incomplete"], 0);
    assert_eq!(m["status"], "Extracted");
    assert!(out
        .iter()
        .all(|a| a.metadata["type"] != "AndroidBackupWarning"));
}
