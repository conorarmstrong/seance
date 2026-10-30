/// Integration tests for macOS Plist Parser
///
/// Tests the PlistParser module against real plist files (binary and XML)
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_plist::PlistParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper function to create a FileEntry artifact from a plist file path.
///
/// Returns `None` (with a skip message naming both places looked) when the
/// fixture is absent from `test_data/` and from the plaso corpus, e.g. on a
/// fresh checkout or CI where neither gitignored corpus is present.
fn create_plist_artifact(path: &str, case_id: Uuid) -> Option<Artifact> {
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
        ArtifactType::FileEntry,
        Some(data_source),
        metadata,
    ))
}

#[test]
fn test_plist_module_metadata() {
    let parser = PlistParser;

    assert_eq!(parser.id(), "plugin.macos.plist_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));
    assert!(subscriptions.contains(&ArtifactType::SystemArtifact));

    use seance_core::module::InputCapability;
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_plist_parsing() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_plist_artifact("test_data/Downloads.plist", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Plist parsing should succeed");

    let artifacts = result.unwrap();
    println!("Plist parser produced {} artifacts", artifacts.len());

    // Should have exactly one artifact (parsed plist)
    assert_eq!(
        artifacts.len(),
        1,
        "Should produce one artifact for plist file"
    );

    let parsed = &artifacts[0];
    assert_eq!(parsed.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(parsed.parent_id, Some(parent_id));
    assert_eq!(parsed.case_id, case_id);

    // Verify metadata
    let metadata = &parsed.metadata;
    assert_eq!(
        metadata.get("type").and_then(|v| v.as_str()),
        Some("PlistFile")
    );
    assert_eq!(
        metadata.get("source").and_then(|v| v.as_str()),
        Some("PlistParser")
    );
    assert!(metadata.get("filename").is_some());
}

#[test]
fn test_plist_content_extraction() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_plist_artifact("test_data/com.apple.SoftwareUpdate.plist", case_id)
    else {
        return;
    };

    let result = parser.process(&artifact).unwrap();
    assert_eq!(result.len(), 1);

    let parsed = &result[0];
    let metadata = &parsed.metadata;

    // Should have content or content_size
    assert!(
        metadata.get("content").is_some() || metadata.get("content_size").is_some(),
        "Should have content or content_size field"
    );

    // If content is present, verify it's valid JSON
    if let Some(content) = metadata.get("content") {
        assert!(
            content.is_object() || content.is_array(),
            "Content should be object or array"
        );
        println!("Plist content keys: {:?}", metadata.get("sample_keys"));
    }
}

#[test]
fn test_multiple_plist_files() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    let test_files = vec![
        "test_data/Downloads.plist",
        "test_data/com.apple.SoftwareUpdate.plist",
        "test_data/com.apple.networkextension.uuidcache.plist",
    ];

    for file_path in test_files {
        let Some(artifact) = create_plist_artifact(file_path, case_id) else {
            return;
        };

        let result = parser.process(&artifact);
        assert!(result.is_ok(), "Processing {} should not error", file_path);

        let artifacts = result.unwrap();
        if artifacts.is_empty() {
            println!(
                "Note: {} produced no artifacts (may be unsupported format)",
                file_path
            );
        } else {
            assert_eq!(
                artifacts.len(),
                1,
                "Should produce exactly one artifact for {}",
                file_path
            );

            let parsed = &artifacts[0];
            assert_eq!(parsed.artifact_type, ArtifactType::ParsedRecord);

            println!("Successfully parsed: {}", file_path);
        }
    }
}

#[test]
fn test_non_plist_file_ignored() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    // Use a non-plist file (SAM registry hive)
    let Some(artifact) = create_plist_artifact("test_data/SAM", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Processing non-plist file should not error");

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-plist files"
    );
}

#[test]
fn test_missing_data_source() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    // Create artifact without data source
    let artifact = {
        let metadata = json!({
            "name": "test.plist",
            "path": "/fake/path/test.plist"
        });

        Artifact::new(case_id, ArtifactType::FileEntry, None, metadata)
    };

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Should handle missing data source gracefully"
    );

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts without data source"
    );
}

#[test]
fn test_parent_relationship() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_plist_artifact("test_data/Downloads.plist", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact).unwrap();

    for parsed in &result {
        assert_eq!(
            parsed.parent_id,
            Some(parent_id),
            "Artifact should reference parent"
        );
        assert_eq!(parsed.case_id, case_id, "Artifact should have same case_id");
    }
}

#[test]
fn test_plist_type_detection() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_plist_artifact("test_data/Downloads.plist", case_id) else {
        return;
    };

    let result = parser.process(&artifact).unwrap();
    if !result.is_empty() {
        let parsed = &result[0];
        let metadata = &parsed.metadata;

        // Should have plist_type classification
        assert!(
            metadata.get("plist_type").is_some(),
            "Should have plist_type field"
        );

        let plist_type = metadata
            .get("plist_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        println!("Detected plist type: {}", plist_type);
    }
}
