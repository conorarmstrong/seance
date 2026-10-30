use seance_container_zip::ZipContainerModule;
/// Integration tests for ZIP Container Module
///
/// Tests the ZipContainerModule against real ZIP archive files
/// from the test_data directory.
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper function to create a FileEntry artifact from a ZIP file path.
///
/// Returns `None` (with a skip message naming both places looked) when the
/// fixture is absent from `test_data/` and from the plaso corpus, e.g. on a
/// fresh checkout or CI where neither gitignored corpus is present.
fn create_zip_artifact(path: &str, case_id: Uuid) -> Option<Artifact> {
    let file_path = crate::fixtures::resolve(path)?;

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let data_source = Arc::new(
        FileDataSource::new(file_path.clone())
            .unwrap_or_else(|e| panic!("Failed to open {}: {}", file_path.display(), e)),
    );

    let metadata = json!({
        "name": file_name,
        "path": path,
        "size": data_source.size(),
        "artifact_source": "test"
    });

    Some(Artifact::new(
        case_id,
        ArtifactType::Container,
        Some(data_source),
        metadata,
    ))
}

#[test]
fn test_syslog_zip_extraction() {
    let module = ZipContainerModule;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_zip_artifact("test_data/syslog.zip", case_id) else {
        return;
    };

    let result = module.process(&artifact);
    assert!(result.is_ok(), "ZIP processing should succeed");

    let artifacts = result.unwrap();
    // syslog.zip contains 2 files
    assert_eq!(artifacts.len(), 2, "Should extract 2 files from syslog.zip");

    // Verify all entries are FileEntry type
    for entry in &artifacts {
        assert_eq!(entry.artifact_type, ArtifactType::FileEntry);
        assert_eq!(entry.case_id, case_id);
    }

    // Find the syslog file
    let syslog_entry = artifacts
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("syslog"));

    assert!(syslog_entry.is_some(), "Should find syslog file in archive");

    if let Some(entry) = syslog_entry {
        // Verify metadata
        assert_eq!(
            entry.metadata.get("name").and_then(|v| v.as_str()),
            Some("syslog")
        );
        assert!(entry.metadata.get("size").is_some(), "Should have size");
        assert!(
            entry.metadata.get("compressed_size").is_some(),
            "Should have compressed_size"
        );

        let is_dir = entry.metadata.get("is_directory").and_then(|v| v.as_bool());
        assert_eq!(is_dir, Some(false), "syslog should not be a directory");

        let container = entry.metadata.get("container").and_then(|v| v.as_str());
        assert_eq!(container, Some("zip"), "Should mark container as zip");

        let container_path = entry
            .metadata
            .get("container_path")
            .and_then(|v| v.as_str());
        assert_eq!(
            container_path,
            Some("syslog.zip"),
            "Should record container path"
        );
    }
}

#[test]
fn a_file_named_zip_whose_bytes_are_not_a_zip_is_declared_incomplete_not_empty() {
    // Renamed from `test_recycler_zip_extraction`, which promised extraction
    // and (after the fixture was understood) asserts the opposite. Nothing is
    // extracted here and nothing can be: see below. Real extraction coverage
    // lives in `test_syslog_zip_extraction`.
    //
    // The fixture is not an archive. `$II3DF3L.zip` is a Windows Vista+ Recycle
    // Bin *metadata* file ($I record: version, deleted size, FILETIME, then the
    // original UTF-16 path) that happens to end in `.zip` because the file it
    // describes was one. Its first four bytes are `01 00 00 00`, not `PK\x03\x04`.
    //
    // So the forensic requirement this fixture exercises is the name/content
    // mismatch: a file the case already calls an archive, whose bytes are not an
    // archive, must not be reported as an archive that held no files. An
    // examiner reads an empty listing as "there was nothing inside", and for a
    // truncated `.zip` or `.ufdr` that conclusion is wrong.
    let module = ZipContainerModule;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_zip_artifact("test_data/recycler/$II3DF3L.zip", case_id) else {
        return;
    };

    let result = module.process(&artifact);
    assert!(result.is_ok(), "Recycler ZIP processing should succeed");

    let artifacts = result.unwrap();

    // No content is claimed: nothing was extracted, so nothing may be presented
    // as an extracted file.
    assert!(
        artifacts
            .iter()
            .all(|a| a.artifact_type != ArtifactType::FileEntry),
        "no file entry can come out of a file that is not an archive"
    );

    // And the mismatch is stated rather than swallowed.
    let status = artifacts
        .iter()
        .find(|a| {
            a.metadata.get("record_type").and_then(|v| v.as_str()) == Some("archive_scan_status")
        })
        .expect("a file named .zip whose bytes are not a ZIP must say so, not report zero files");
    assert_eq!(status.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(status.metadata["content_incomplete"], json!(true));
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        json!("zip_magic_unreadable")
    );
    assert_eq!(status.metadata["entries_recovered"], json!(0));
    assert_eq!(status.parent_id, Some(artifact.id));
}

#[test]
fn test_non_zip_file_ignored() {
    let module = ZipContainerModule;
    let case_id = Uuid::new_v4();

    // Create artifact with non-ZIP filename
    let artifact = {
        let metadata = json!({
            "name": "random_file.txt",
            "path": "/tmp/random_file.txt"
        });

        Artifact::new(case_id, ArtifactType::Container, None, metadata)
    };

    let result = module.process(&artifact);
    assert!(result.is_ok(), "Processing non-ZIP should not error");

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-ZIP files"
    );
}

#[test]
fn test_parent_relationship() {
    let module = ZipContainerModule;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_zip_artifact("test_data/syslog.zip", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = module.process(&artifact).unwrap();

    // All extracted files should reference the ZIP as parent
    for entry in &result {
        assert_eq!(
            entry.parent_id,
            Some(parent_id),
            "Extracted file should reference ZIP as parent"
        );
        assert_eq!(
            entry.case_id, case_id,
            "Extracted file should have same case_id"
        );
    }
}

#[test]
fn test_missing_data_source() {
    let module = ZipContainerModule;
    let case_id = Uuid::new_v4();

    // Create artifact without data source
    let artifact = {
        let metadata = json!({
            "name": "test.zip",
            "path": "/fake/path/test.zip"
        });

        Artifact::new(case_id, ArtifactType::Container, None, metadata)
    };

    let result = module.process(&artifact);
    assert!(result.is_err(), "Should error when data source is missing");
}

#[test]
fn test_module_metadata() {
    let module = ZipContainerModule;

    assert_eq!(module.id(), "container.zip_extractor");
    assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = module.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::Container));

    use seance_core::module::InputCapability;
    assert_eq!(module.input_capability(), InputCapability::Stream);
}

#[test]
fn test_file_metadata_fields() {
    let module = ZipContainerModule;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_zip_artifact("test_data/syslog.zip", case_id) else {
        return;
    };

    let result = module.process(&artifact).unwrap();

    for entry in &result {
        let metadata = &entry.metadata;

        // Verify all expected fields are present
        assert!(metadata.get("name").is_some(), "Should have name");
        assert!(metadata.get("size").is_some(), "Should have size");
        assert!(
            metadata.get("compressed_size").is_some(),
            "Should have compressed_size"
        );
        assert!(
            metadata.get("is_directory").is_some(),
            "Should have is_directory"
        );
        assert!(metadata.get("container").is_some(), "Should have container");
        assert!(
            metadata.get("container_path").is_some(),
            "Should have container_path"
        );

        // Verify types
        assert!(
            metadata.get("size").and_then(|v| v.as_u64()).is_some(),
            "size should be number"
        );
        assert!(
            metadata
                .get("compressed_size")
                .and_then(|v| v.as_u64())
                .is_some(),
            "compressed_size should be number"
        );
        assert!(
            metadata
                .get("is_directory")
                .and_then(|v| v.as_bool())
                .is_some(),
            "is_directory should be boolean"
        );
    }
}

#[test]
fn test_case_insensitive_zip_extension() {
    let module = ZipContainerModule;
    let case_id = Uuid::new_v4();

    // Test with uppercase .ZIP extension
    let Some(zip_path) = crate::fixtures::resolve("test_data/syslog.zip") else {
        return;
    };
    let artifact = {
        let data_source = Arc::new(FileDataSource::new(zip_path).unwrap());

        let metadata = json!({
            "name": "ARCHIVE.ZIP",  // uppercase
            "path": "test_data/ARCHIVE.ZIP",
            "size": data_source.size()
        });

        Artifact::new(
            case_id,
            ArtifactType::Container,
            Some(data_source),
            metadata,
        )
    };

    let result = module.process(&artifact);
    assert!(result.is_ok(), "Should handle uppercase .ZIP extension");

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        2,
        "Should extract files regardless of extension case"
    );
}

#[test]
fn test_empty_or_corrupt_zip_handling() {
    let module = ZipContainerModule;
    let case_id = Uuid::new_v4();

    // Create a fake ZIP artifact pointing to a non-ZIP file
    let Some(mut artifact) = create_zip_artifact("test_data/SAM", case_id) else {
        return;
    };

    // Manually override name to make it look like a ZIP. The bytes are a real
    // registry hive (`regf`), so this is the same shape as a truncated or
    // damaged archive: the case calls it a `.zip` and the content disagrees.
    artifact.metadata["name"] = json!("SAM.zip");

    let result = module.process(&artifact);
    // Handled gracefully: the pipeline must not error on one bad file.
    assert!(result.is_ok(), "Should handle invalid ZIP gracefully");

    let artifacts = result.unwrap();

    // Graceful is not the same as silent. Producing nothing here would make a
    // corrupt archive indistinguishable from an archive that genuinely held no
    // files, which is a conclusion an examiner would draw and would be wrong.
    // Exactly one record, and it carries no content of its own.
    assert_eq!(
        artifacts.len(),
        1,
        "a corrupt ZIP must yield its status record and nothing else"
    );
    let status = &artifacts[0];
    assert_eq!(status.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(status.metadata["content_incomplete"], json!(true));
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        json!("zip_magic_unreadable")
    );
    assert_eq!(status.metadata["entries_recovered"], json!(0));
}
