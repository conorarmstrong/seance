/// Integration tests for the forensic SQLite parser
///
/// The parser was rewritten from a driver-based 5-row sampler into a raw
/// b-tree forensic parser. It now emits a `SqliteDatabaseForensics` summary
/// plus one `SqliteRow` artifact per recovered row (live, deleted, or carved).
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_sqlite::SqliteParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper function to create a FileEntry artifact from a SQLite database path.
///
/// Returns `None` (with a skip message naming both places looked) when the
/// fixture is absent from `test_data/` and from the plaso corpus, e.g. on a
/// fresh checkout or CI where neither gitignored corpus is present.
fn create_sqlite_artifact(path: &str, case_id: Uuid) -> Option<Artifact> {
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
fn test_sqlite_module_metadata() {
    let parser = SqliteParser;

    assert_eq!(parser.id(), "plugin.generic.sqlite_parser");

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));
    assert!(subscriptions.contains(&ArtifactType::SystemArtifact));

    use seance_core::module::InputCapability;
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_sqlite_database_parsing() {
    let parser = SqliteParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_sqlite_artifact("test_data/activity.sqlite", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "SQLite parsing should succeed");

    let artifacts = result.unwrap();
    println!("SQLite parser produced {} artifacts", artifacts.len());
    assert!(
        !artifacts.is_empty(),
        "Should produce at least one artifact"
    );

    // Find the forensic database summary artifact
    let summary = artifacts.iter().find(|a| {
        a.metadata.get("type").and_then(|v| v.as_str()) == Some("SqliteDatabaseForensics")
    });

    assert!(
        summary.is_some(),
        "Should have a SqliteDatabaseForensics summary artifact"
    );

    if let Some(summary) = summary {
        assert_eq!(summary.parent_id, Some(parent_id));
        assert_eq!(summary.case_id, case_id);
        assert!(
            summary.metadata.get("page_size").is_some(),
            "summary should record page_size"
        );
        assert!(
            summary.metadata.get("tables").is_some(),
            "summary should list tables"
        );
        assert!(
            summary.metadata.get("live_rows").is_some(),
            "summary should count live_rows"
        );
    }
}

#[test]
fn test_sqlite_row_extraction() {
    let parser = SqliteParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_sqlite_artifact("test_data/activity.sqlite", case_id) else {
        return;
    };

    let result = parser.process(&artifact).unwrap();

    // Rows are emitted individually as SqliteRow records.
    let rows: Vec<_> = result
        .iter()
        .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("SqliteRow"))
        .collect();

    assert!(!rows.is_empty(), "Should recover at least one row");

    for row in rows.iter().take(20) {
        let m = &row.metadata;
        assert!(m.get("table").is_some(), "row should name its table");
        assert!(
            m.get("columns").is_some(),
            "row should carry decoded columns"
        );
        // `deleted` and `recovery_source` classify live vs recovered rows.
        assert!(
            m.get("deleted").is_some(),
            "row should carry a deleted flag"
        );
    }
}

#[test]
fn test_non_sqlite_file_ignored() {
    let parser = SqliteParser;
    let case_id = Uuid::new_v4();

    // Use a non-SQLite file (SAM registry hive)
    let Some(artifact) = create_sqlite_artifact("test_data/SAM", case_id) else {
        return;
    };

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Processing non-SQLite file should not error"
    );

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-SQLite files"
    );
}

#[test]
fn test_missing_data_source() {
    let parser = SqliteParser;
    let case_id = Uuid::new_v4();

    // Create artifact without data source
    let artifact = {
        let metadata = json!({
            "name": "test.db",
            "path": "/fake/path/test.db"
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
    let parser = SqliteParser;
    let case_id = Uuid::new_v4();

    let Some(artifact) = create_sqlite_artifact("test_data/activity.sqlite", case_id) else {
        return;
    };
    let parent_id = artifact.id;

    let result = parser.process(&artifact).unwrap();

    // All emitted artifacts should reference the database file as parent.
    for parsed in &result {
        assert_eq!(
            parsed.parent_id,
            Some(parent_id),
            "Artifact should reference parent"
        );
        assert_eq!(parsed.case_id, case_id, "Artifact should have same case_id");
    }
}
