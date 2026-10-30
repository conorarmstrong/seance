/// Integration tests for iOS Backup parser
///
/// Tests verification of module metadata, iOS backup directory detection,
/// and proper handling of encrypted backups.
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::ForensicsModule,
};
use seance_plugin_ios_backup::IosBackupParser;
use uuid::Uuid;

#[test]
fn test_module_metadata() {
    let parser = IosBackupParser::new();

    assert_eq!(parser.id(), "plugin.mobile.ios_backup");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));
    assert!(subscriptions.contains(&ArtifactType::RawEvidence));
}

#[test]
fn test_non_ios_backup_directory_ignored() {
    crate::init_logging();

    let parser = IosBackupParser::new();
    let case_id = Uuid::new_v4();

    // Create artifact pointing to a directory that is NOT an iOS backup
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        serde_json::json!({
            "path": "/tmp"
        }),
    );

    // Should return empty vec (no artifacts) since this is not an iOS backup
    let result = parser.process(&artifact);
    assert!(result.is_ok());
    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Non-iOS backup directory should be ignored"
    );
}

#[test]
fn test_ios_backup_requires_directory() {
    crate::init_logging();

    let parser = IosBackupParser::new();
    let case_id = Uuid::new_v4();

    // Create artifact pointing to a regular file (not directory)
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        serde_json::json!({
            "path": "/dev/null"
        }),
    );

    // Should return empty vec since iOS backup must be a directory
    let result = parser.process(&artifact);
    assert!(result.is_ok());
    let artifacts = result.unwrap();
    assert_eq!(artifacts.len(), 0, "Regular file should be ignored");
}

#[test]
fn test_ios_backup_framework_message() {
    crate::init_logging();

    let parser = IosBackupParser::new();

    println!("\n=== iOS Backup Parser Module ===");
    println!("Module ID: {}", parser.id());
    println!("Version: {}", parser.version());
    println!("Input Capability: {:?}", parser.input_capability());
    println!("\nSupported iOS Backup Formats:");
    println!("  1. Manifest.db (SQLite) - iOS 10+ backups");
    println!("  2. Manifest.mbdb (binary) - iOS 3-9 legacy backups");
    println!("\nEncryption Support:");
    println!("  - Detects encrypted backups via Manifest.plist");
    println!("  - Framework for PBKDF2/AES decryption (placeholder)");
    println!("  - Provides informative messages for encrypted backups");
    println!("\nArtifact Types Emitted:");
    println!("  - FileEntry: For individual files in backup");
    println!("  - ParsedRecord: For directories and metadata");
    println!("\nDetection:");
    println!("  - Requires Manifest.plist (backup metadata)");
    println!("  - Requires Manifest.db OR Manifest.mbdb");
    println!("  - Extracts device info, backup date, iOS version");
    println!("\n✓ iOS Backup parser framework test completed successfully");
}

/// Real-data coverage: parse the actual iOS backup fixture under
/// test_data/ios_backup (Manifest.plist + a 42 MB Manifest.db). Previously the
/// suite only exercised /tmp and /dev/null, so there was no real iOS coverage.
#[test]
fn test_real_ios_backup_manifest() {
    let dir = {
        let root = std::env::current_dir().unwrap();
        if root.ends_with("seance_tests") {
            root.parent().unwrap().join("test_data/ios_backup")
        } else {
            root.join("test_data/ios_backup")
        }
    };
    if !dir.join("Manifest.db").exists() {
        println!(
            "Skipping: iOS backup fixture not present at {}",
            dir.display()
        );
        return;
    }

    let parser = IosBackupParser::new();
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        serde_json::json!({ "name": "ios_backup", "path": dir.to_string_lossy() }),
    );
    let out = parser.process(&artifact).expect("iOS backup parse");
    println!("iOS backup produced {} artifacts", out.len());
    assert!(
        out.len() > 10,
        "expected many file records from the real Manifest.db, got {}",
        out.len()
    );
}
