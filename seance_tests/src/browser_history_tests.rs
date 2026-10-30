/// Integration tests for Browser History Parser
///
/// Tests the BrowserHistoryParser module against real browser history files
/// from the test_data directory.
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_browser_history::BrowserHistoryParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper function to create a FileEntry artifact from a path.
///
/// Returns `None` (with a skip message naming both places looked) when the
/// fixture is absent from `test_data/` and from the plaso corpus, e.g. on a
/// fresh checkout or CI where neither gitignored corpus is present.
fn create_file_artifact(path: &str, case_id: Uuid) -> Option<Artifact> {
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
fn test_chrome_history_detection() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();

    // Test with Chrome History file
    let Some(artifact) = create_file_artifact("test_data/chrome_history/History", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Chrome history processing should succeed");

    let artifacts = result.unwrap();
    assert!(
        !artifacts.is_empty(),
        "Should produce at least 1 artifact, got {}",
        artifacts.len()
    );

    // At least one ParsedRecord (visits/downloads/bookmarks) is produced
    // alongside per-visit TimelineEvents.
    assert!(
        artifacts
            .iter()
            .any(|a| a.artifact_type == ArtifactType::ParsedRecord),
        "Should produce at least one ParsedRecord"
    );

    // Check that some artifacts are browser history entries
    let has_browser = artifacts
        .iter()
        .any(|a| a.metadata.get("browser").and_then(|v| v.as_str()).is_some());
    assert!(has_browser, "Should have artifacts with browser metadata");
}

#[test]
fn test_chrome_history_versions_not_detected() {
    // NOTE: Current parser implementation only matches exact filename "History"
    // Versioned backup files like "History-57.0.2987.133" are not detected
    // This test documents this limitation - in future, parser could be enhanced
    // to match files starting with "History"

    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();

    let test_files = vec![
        "test_data/chrome_history/History-57.0.2987.133",
        "test_data/chrome_history/History-58.0.3029.96",
        "test_data/chrome_history/History-59.0.3071.86",
    ];

    for file_path in test_files {
        let Some(artifact) = create_file_artifact(file_path, case_id) else {
            return;
        };
        let result = parser.process(&artifact);

        assert!(result.is_ok(), "Processing {} should not error", file_path);

        let artifacts = result.unwrap();
        // Current implementation doesn't detect versioned files
        assert_eq!(
            artifacts.len(),
            0,
            "Versioned files not currently detected: {}",
            file_path
        );
    }
}

#[test]
fn test_firefox_history_detection() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();

    // Test with Firefox places.sqlite
    let Some(artifact) = create_file_artifact("test_data/firefox_history/places.sqlite", case_id)
    else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Firefox history processing should succeed");

    let artifacts = result.unwrap();
    assert!(
        !artifacts.is_empty(),
        "Should produce at least 1 artifact, got {}",
        artifacts.len()
    );

    assert!(
        artifacts
            .iter()
            .any(|a| a.artifact_type == ArtifactType::ParsedRecord),
        "Should produce at least one ParsedRecord"
    );

    // Check that some artifacts reference Firefox browser
    let has_firefox = artifacts
        .iter()
        .any(|a| a.metadata.get("browser").and_then(|v| v.as_str()) == Some("Firefox"));
    assert!(
        has_firefox,
        "Should have artifacts with Firefox browser metadata"
    );
}

#[test]
fn test_non_history_file_ignored() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();

    // Create artifact with non-history filename
    let artifact = {
        let metadata = json!({
            "name": "random_file.txt",
            "path": "/tmp/random_file.txt"
        });

        Artifact::new(case_id, ArtifactType::FileEntry, None, metadata)
    };

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Processing non-history file should not error"
    );

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-history files"
    );
}

#[test]
fn test_parent_relationship() {
    let parser = BrowserHistoryParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_file_artifact("test_data/chrome_history/History", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact).unwrap();
    let parsed = &result[0];

    // Verify parent-child relationship
    assert_eq!(
        parsed.parent_id,
        Some(parent_id),
        "Parsed artifact should reference parent"
    );
    assert_eq!(
        parsed.case_id, case_id,
        "Parsed artifact should have same case_id"
    );
}

#[test]
fn test_module_metadata() {
    let parser = BrowserHistoryParser;

    assert_eq!(parser.id(), "plugin.browsers.history_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    assert_eq!(
        parser.subscribes_to(),
        // A `ParsedRecord` is read only when it is a shadow-copy prior version (HUNT-277).
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
            ArtifactType::ParsedRecord
        ]
    );
}
