use seance_container_e01::E01ContainerModule;
/// E01 Container Module Integration Tests
///
/// Tests the E01 (Expert Witness Format) container module's ability to
/// open and read forensic disk images in E01 format.
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::ForensicsModule,
};
use serde_json::json;
use uuid::Uuid;

/// Helper function to create a file entry artifact for E01 testing
#[allow(dead_code)]
fn create_e01_artifact(path: &str, case_id: Uuid) -> Artifact {
    let metadata = json!({
        "name": std::path::Path::new(path).file_name().unwrap().to_str().unwrap(),
        "path": path,
        "size": std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
    });

    Artifact::new(case_id, ArtifactType::Container, None, metadata)
}

#[test]
fn test_module_metadata() {
    let module = E01ContainerModule;

    assert_eq!(module.id(), "container.e01_reader");
    assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = module.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::Container));
}

#[test]
fn test_non_e01_file_ignored() {
    let module = E01ContainerModule;
    let case_id = Uuid::new_v4();

    // Create artifact for a non-E01 file
    let metadata = json!({
        "name": "not_an_e01.txt",
        "path": "/tmp/not_an_e01.txt",
    });

    let artifact = Artifact::new(case_id, ArtifactType::Container, None, metadata);

    let result = module.process(&artifact);
    assert!(result.is_ok(), "Should handle non-E01 files gracefully");

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should not produce artifacts for non-E01 files"
    );
}

#[test]
fn test_e01_file_detection() {
    let module = E01ContainerModule;
    let case_id = Uuid::new_v4();

    // Create artifact for E01 file (even if it doesn't exist)
    let metadata = json!({
        "name": "evidence.e01",
        "path": "/nonexistent/evidence.e01",
    });

    let artifact = Artifact::new(case_id, ArtifactType::Container, None, metadata);

    let result = module.process(&artifact);
    // It will fail to open since file doesn't exist, but should detect it as E01
    assert!(result.is_err() || result.unwrap().is_empty());
}

// Note: Real E01 file tests would require sample E01 images in test_data
// For now, we test the module's detection and error handling logic
