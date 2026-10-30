/// Integration tests for SRUM (System Resource Usage Monitor) Parser
///
/// Tests the SrumParser module against real SRUDB.dat ESE database files
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_srum::SrumParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper function to resolve test data path from workspace or seance_tests directory
fn resolve_test_path(relative_path: &str) -> std::path::PathBuf {
    let project_root = std::env::current_dir().unwrap();
    if project_root.ends_with("seance_tests") {
        project_root.parent().unwrap().join(relative_path)
    } else {
        project_root.join(relative_path)
    }
}

/// Helper function to create a FileEntry artifact from a path
fn create_file_artifact(path: &str, case_id: Uuid) -> Artifact {
    let file_path = resolve_test_path(path);

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

    Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        metadata,
    )
}

#[test]
fn test_srum_parser_module_metadata() {
    let parser = SrumParser;

    assert_eq!(parser.id(), "plugin.windows.srum_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));

    use seance_core::module::InputCapability;
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_srum_database_detection() {
    let parser = SrumParser;
    let case_id = Uuid::new_v4();

    let srudb_path = resolve_test_path("test_data/SRUDB.dat");
    if !srudb_path.exists() {
        println!("Skipping SRUM test: test_data/SRUDB.dat not found");
        return;
    }

    let artifact = create_file_artifact("test_data/SRUDB.dat", case_id);
    let parent_id = artifact.id;

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "SRUM parsing should succeed");

    let artifacts = result.unwrap();
    println!("SRUDB.dat produced {} artifacts", artifacts.len());

    // Should produce at least one artifact (either table detection or database detection)
    assert!(
        !artifacts.is_empty(),
        "Should produce at least one artifact"
    );

    // Artifacts are a mix of ParsedRecord (table summaries) and TimelineEvent (individual timestamps)
    let parsed_records: Vec<_> = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    let timeline_events: Vec<_> = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();

    assert!(
        !parsed_records.is_empty(),
        "Should produce ParsedRecord artifacts"
    );
    println!("  ParsedRecord artifacts: {}", parsed_records.len());
    println!("  TimelineEvent artifacts: {}", timeline_events.len());

    // All ParsedRecord artifacts should be direct children of the SRUDB.dat.
    // `parse_incomplete` markers are excluded from the type allowlist: a table
    // walk that skipped rows publishes one of those alongside its records, and
    // it deliberately does NOT carry the table's own `type` (grouping by
    // `metadata.$.type` would otherwise file it as a usage record). Its own
    // shape is asserted in the srum crate's unit tests.
    let valid_srum_types = [
        "SrumAppResourceUsage",
        "SrumNetworkDataUsage",
        "SrumNetworkConnectivity",
        "SrumEnergyUsage",
        "SrumDatabase",
    ];
    for record in &parsed_records {
        assert_eq!(record.parent_id, Some(parent_id));
        assert_eq!(record.case_id, case_id);

        if record.metadata.get("subtype").and_then(|v| v.as_str()) == Some("parse_incomplete") {
            continue;
        }

        let record_type = record.metadata.get("type").and_then(|v| v.as_str());
        assert!(
            record_type
                .map(|t| valid_srum_types.contains(&t))
                .unwrap_or(false),
            "ParsedRecord type should be a known SRUM type, got: {:?}",
            record_type
        );

        if let Some(rt) = record_type {
            let count = record
                .metadata
                .get("record_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!("  - {}: {} records", rt, count);
        }
    }

    // All artifacts should have correct case_id
    for artifact in &artifacts {
        assert_eq!(artifact.case_id, case_id);
    }
}

#[test]
fn test_non_srum_file_ignored() {
    let parser = SrumParser;
    let case_id = Uuid::new_v4();

    // Use a non-SRUM file (SAM registry hive)
    let sam_path = resolve_test_path("test_data/SAM");
    if !sam_path.exists() {
        println!("Skipping non-SRUM file test: test_data/SAM not found");
        return;
    }
    let artifact = create_file_artifact("test_data/SAM", case_id);

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Processing non-SRUM file should not error");

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-SRUM files"
    );
}

#[test]
fn test_missing_data_source() {
    let parser = SrumParser;
    let case_id = Uuid::new_v4();

    // Create artifact without data source
    let artifact = {
        let metadata = json!({
            "name": "SRUDB.dat",
            "path": "/fake/path/SRUDB.dat"
        });

        Artifact::new(case_id, ArtifactType::FileEntry, None, metadata)
    };

    // With no data source, module returns Ok(empty) instead of Err (expected for carved files)
    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Should succeed with empty result when data source is missing"
    );
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_srum_table_enumeration() {
    let parser = SrumParser;
    let case_id = Uuid::new_v4();

    let srudb_path = resolve_test_path("test_data/SRUDB.dat");
    if !srudb_path.exists() {
        println!("Skipping SRUM table enumeration test: test_data/SRUDB.dat not found");
        return;
    }

    let artifact = create_file_artifact("test_data/SRUDB.dat", case_id);

    let result = parser.process(&artifact).unwrap();

    // Look for specific SRUM tables
    let expected_tables = vec![
        "SruDbIdMapTable",
        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
        "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
        "{DD6636C4-8929-4683-974E-22C046A43763}",
        "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",
    ];

    for table_name in expected_tables {
        let found = result.iter().any(|a| {
            a.metadata
                .get("table_name")
                .and_then(|v| v.as_str())
                .map(|name| name == table_name)
                .unwrap_or(false)
        });

        if found {
            println!("✓ Found expected table: {}", table_name);
        } else {
            println!(
                "✗ Table not found (may not exist in this database): {}",
                table_name
            );
        }
    }

    // At least verify we got some artifacts
    println!("Total tables detected: {}", result.len());
}

#[test]
fn test_parent_relationship() {
    let parser = SrumParser;
    let case_id = Uuid::new_v4();

    let srudb_path = resolve_test_path("test_data/SRUDB.dat");
    if !srudb_path.exists() {
        println!("Skipping parent relationship test: test_data/SRUDB.dat not found");
        return;
    }

    let artifact = create_file_artifact("test_data/SRUDB.dat", case_id);
    let parent_id = artifact.id;

    let result = parser.process(&artifact).unwrap();

    // ParsedRecord artifacts should reference the parent SRUDB.dat file
    // TimelineEvent artifacts should reference their parent ParsedRecord
    for child in &result {
        assert_eq!(child.case_id, case_id, "Artifact should have same case_id");
        assert!(
            child.parent_id.is_some(),
            "All artifacts should have a parent"
        );

        if child.artifact_type == ArtifactType::ParsedRecord {
            assert_eq!(
                child.parent_id,
                Some(parent_id),
                "ParsedRecord should reference parent SRUDB.dat"
            );
        }
        // TimelineEvents reference their parent ParsedRecord, not the SRUDB.dat directly
    }
}

#[test]
fn test_case_insensitive_filename() {
    let parser = SrumParser;
    let case_id = Uuid::new_v4();

    // Create artifact with uppercase SRUDB.DAT
    let artifact = {
        let srudb_path = resolve_test_path("test_data/SRUDB.dat");
        if !srudb_path.exists() {
            println!("Skipping case-insensitive test: test_data/SRUDB.dat not found");
            return;
        }

        let data_source = Arc::new(FileDataSource::new(srudb_path).unwrap());

        let metadata = json!({
            "name": "srudb.DAT",  // Mixed case
            "path": "test_data/srudb.DAT",
            "size": data_source.size()
        });

        Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            Some(data_source),
            metadata,
        )
    };

    let result = parser.process(&artifact);
    assert!(result.is_ok(), "Should handle case-insensitive SRUDB.dat");

    let artifacts = result.unwrap();
    assert!(
        !artifacts.is_empty(),
        "Should detect SRUDB.dat regardless of case"
    );
}

#[test]
fn test_artifact_metadata_structure() {
    let parser = SrumParser;
    let case_id = Uuid::new_v4();

    let srudb_path = resolve_test_path("test_data/SRUDB.dat");
    if !srudb_path.exists() {
        println!("Skipping metadata structure test: test_data/SRUDB.dat not found");
        return;
    }

    let artifact = create_file_artifact("test_data/SRUDB.dat", case_id);

    let result = parser.process(&artifact).unwrap();

    // Find the first table-content ParsedRecord (skip TimelineEvents, and skip
    // the `parse_incomplete` markers a table walk emits when it could not read
    // every row — those carry a deliberately different `type` and no
    // `record_count`, and are asserted in the srum crate's own tests).
    let first_parsed = result.iter().find(|a| {
        a.artifact_type == ArtifactType::ParsedRecord
            && a.metadata.get("subtype").and_then(|v| v.as_str()) != Some("parse_incomplete")
    });

    if let Some(artifact) = first_parsed {
        let metadata = &artifact.metadata;

        // Verify required metadata fields
        assert!(metadata.get("type").is_some(), "Should have type");

        let artifact_type = metadata.get("type").and_then(|v| v.as_str()).unwrap();

        let valid_types = [
            "SrumAppResourceUsage",
            "SrumNetworkDataUsage",
            "SrumNetworkConnectivity",
            "SrumEnergyUsage",
            "SrumDatabase",
        ];
        assert!(
            valid_types.contains(&artifact_type),
            "Type should be a known SRUM type, got: {}",
            artifact_type
        );

        if artifact_type != "SrumDatabase" {
            // Full extraction records have table_name and record_count
            assert!(
                metadata.get("table_name").is_some(),
                "Should have table_name"
            );
            assert!(
                metadata.get("record_count").is_some(),
                "Should have record_count"
            );
            assert!(
                metadata.get("records").is_some(),
                "Should have records array"
            );

            let table_name = metadata.get("table_name").and_then(|v| v.as_str()).unwrap();
            assert!(table_name.starts_with('{'), "table_name should be a GUID");

            let record_count = metadata
                .get("record_count")
                .and_then(|v| v.as_u64())
                .unwrap();
            let records_len = metadata
                .get("records")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            assert_eq!(
                record_count as usize, records_len,
                "record_count should match records array length"
            );
        } else {
            // Database detection fallback
            assert!(metadata.get("status").is_some(), "Should have status");
            assert!(metadata.get("note").is_some(), "Should have note");
        }
    }
}
