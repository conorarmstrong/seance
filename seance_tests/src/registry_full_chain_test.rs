use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::FileDataSource,
    module::ForensicsModule,
};
use seance_plugin_registry::RegistryParser;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

#[test]
fn test_registry_system_hive_parsing() {
    let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/SYSTEM");

    if !test_file.exists() {
        eprintln!("Test file not found: {:?}", test_file);
        return;
    }

    let case_id = Uuid::new_v4();
    let data_source = Arc::new(FileDataSource::new(test_file.clone()).unwrap());

    let artifact = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        Some(data_source),
        serde_json::json!({
            "name": "SYSTEM"
        }),
    );

    let parser = RegistryParser;
    let result = parser.process(&artifact);

    assert!(
        result.is_ok(),
        "Registry parsing failed: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    assert!(!artifacts.is_empty(), "No artifacts produced");

    // Find the RegistryHive artifact
    let hive_artifact = artifacts
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .expect("No ParsedRecord artifact found");

    // Verify metadata structure
    let metadata = &hive_artifact.metadata;
    assert_eq!(
        metadata.get("type").and_then(|v| v.as_str()),
        Some("RegistryHive"),
        "Incorrect artifact type"
    );

    let hive_type = metadata
        .get("hive_type")
        .and_then(|v| v.as_str())
        .expect("Missing hive_type");
    assert_eq!(hive_type, "SYSTEM", "Expected SYSTEM hive type");

    let all_keys = metadata
        .get("all_keys")
        .and_then(|v| v.as_array())
        .expect("Missing all_keys array");

    let all_values = metadata
        .get("all_values")
        .and_then(|v| v.as_array())
        .expect("Missing all_values array");

    // SYSTEM hive should have many keys
    assert!(
        all_keys.len() > 100,
        "Expected > 100 keys, found {}",
        all_keys.len()
    );
    println!(
        "SYSTEM hive: {} keys, {} values",
        all_keys.len(),
        all_values.len()
    );

    // Verify key structure
    let first_key = &all_keys[0];
    assert!(first_key.get("key_path").is_some(), "Key missing key_path");
    assert!(first_key.get("key_name").is_some(), "Key missing key_name");
    assert!(first_key.get("depth").is_some(), "Key missing depth");

    // Verify some keys have values
    let keys_with_values: Vec<_> = all_keys
        .iter()
        .filter(|k| {
            let key_path = k.get("key_path").and_then(|v| v.as_str()).unwrap_or("");
            all_values
                .iter()
                .any(|v| v.get("key_path").and_then(|kp| kp.as_str()) == Some(key_path))
        })
        .collect();

    assert!(!keys_with_values.is_empty(), "No keys have values");
    println!("Keys with values: {}", keys_with_values.len());

    // Verify value structure
    if let Some(first_value) = all_values.first() {
        assert!(
            first_value.get("key_path").is_some(),
            "Value missing key_path"
        );
        assert!(
            first_value.get("value_name").is_some(),
            "Value missing value_name"
        );
        assert!(
            first_value.get("value_type").is_some(),
            "Value missing value_type"
        );
        assert!(
            first_value.get("value_data").is_some(),
            "Value missing value_data"
        );
        assert!(
            first_value.get("raw_data_size").is_some(),
            "Value missing raw_data_size"
        );
    }
}

#[test]
fn test_registry_software_hive_parsing() {
    let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/SOFTWARE");

    if !test_file.exists() {
        eprintln!("Test file not found: {:?}", test_file);
        return;
    }

    let case_id = Uuid::new_v4();
    let data_source = Arc::new(FileDataSource::new(test_file.clone()).unwrap());

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        serde_json::json!({
            "name": "SOFTWARE"
        }),
    );

    let parser = RegistryParser;
    let result = parser.process(&artifact);

    assert!(
        result.is_ok(),
        "Registry parsing failed: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    assert!(!artifacts.is_empty(), "No artifacts produced");

    let hive_artifact = artifacts
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .expect("No ParsedRecord artifact found");

    let metadata = &hive_artifact.metadata;
    let hive_type = metadata
        .get("hive_type")
        .and_then(|v| v.as_str())
        .expect("Missing hive_type");
    assert_eq!(hive_type, "SOFTWARE", "Expected SOFTWARE hive type");

    let all_keys = metadata
        .get("all_keys")
        .and_then(|v| v.as_array())
        .expect("Missing all_keys array");

    // SOFTWARE hive is typically larger than SYSTEM
    assert!(
        all_keys.len() > 100,
        "Expected > 100 keys, found {}",
        all_keys.len()
    );
    println!("SOFTWARE hive: {} keys extracted", all_keys.len());
}

#[test]
fn test_registry_sam_hive_parsing() {
    let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/SAM");

    if !test_file.exists() {
        eprintln!("Test file not found: {:?}", test_file);
        return;
    }

    let case_id = Uuid::new_v4();
    let data_source = Arc::new(FileDataSource::new(test_file.clone()).unwrap());

    let artifact = Artifact::new(
        case_id,
        ArtifactType::SystemArtifact,
        Some(data_source),
        serde_json::json!({
            "name": "SAM"
        }),
    );

    let parser = RegistryParser;
    let result = parser.process(&artifact);

    assert!(
        result.is_ok(),
        "Registry parsing failed: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    assert!(!artifacts.is_empty(), "No artifacts produced");

    let hive_artifact = artifacts
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .expect("No ParsedRecord artifact found");

    let metadata = &hive_artifact.metadata;
    let hive_type = metadata
        .get("hive_type")
        .and_then(|v| v.as_str())
        .expect("Missing hive_type");
    assert_eq!(hive_type, "SAM", "Expected SAM hive type");

    println!("SAM hive parsed successfully");
}

#[test]
fn test_registry_ntuser_hive_parsing() {
    let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/NTUSER-WIN7.DAT");

    if !test_file.exists() {
        eprintln!("Test file not found: {:?}", test_file);
        return;
    }

    let case_id = Uuid::new_v4();
    let data_source = Arc::new(FileDataSource::new(test_file.clone()).unwrap());

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        serde_json::json!({
            "name": "NTUSER-WIN7.DAT"
        }),
    );

    let parser = RegistryParser;
    let result = parser.process(&artifact);

    assert!(
        result.is_ok(),
        "Registry parsing failed: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    assert!(!artifacts.is_empty(), "No artifacts produced");

    let hive_artifact = artifacts
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .expect("No ParsedRecord artifact found");

    let metadata = &hive_artifact.metadata;

    let all_keys = metadata
        .get("all_keys")
        .and_then(|v| v.as_array())
        .expect("Missing all_keys array");

    println!("NTUSER.DAT hive: {} keys extracted", all_keys.len());

    // Verify we can find common user hive paths
    let has_software_key = all_keys.iter().any(|k| {
        k.get("key_path")
            .and_then(|v| v.as_str())
            .map(|path| path.to_lowercase().contains("software"))
            .unwrap_or(false)
    });

    assert!(
        has_software_key,
        "Expected to find Software key in NTUSER.DAT"
    );
}

#[test]
fn test_registry_non_hive_file_skipped() {
    let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/HD001_MFT.dat");

    if !test_file.exists() {
        eprintln!("Test file not found: {:?}", test_file);
        return;
    }

    let case_id = Uuid::new_v4();
    let data_source = Arc::new(FileDataSource::new(test_file.clone()).unwrap());

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        serde_json::json!({
            "name": "MFT.dat"
        }),
    );

    let parser = RegistryParser;
    let result = parser.process(&artifact);

    assert!(
        result.is_ok(),
        "Registry parser should not error on non-hive files"
    );

    let artifacts = result.unwrap();
    // Should return empty vector (file not a registry hive)
    assert_eq!(artifacts.len(), 0, "Non-hive file should be skipped");
}
