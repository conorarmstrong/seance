//! ISO9660 validation against the DFTT #14 known-answer images.
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::hashing::compute_hashes;
use seance_core::module::ForensicsModule;
use seance_plugin_iso9660::Iso9660Parser;
use seance_plugin_partition::FilesystemDetector;
use std::sync::Arc;
use uuid::Uuid;

fn resolve(rel: &str) -> std::path::PathBuf {
    let root = std::env::current_dir().unwrap();
    if root.ends_with("seance_tests") {
        root.parent().unwrap().join(rel)
    } else {
        root.join(rel)
    }
}

#[test]
fn iso9660_detects_and_extracts_dftt14() {
    let img = resolve("test_data/dftt/14-iso9660/14-iso9660-1/iso-dirtree1.iso");
    if !img.exists() {
        println!("Skipping: DFTT #14 ISO not present at {}", img.display());
        return;
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));

    // Detection: the CD001 descriptor at byte 0x8001 must be recognised.
    let raw = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds.clone()),
        serde_json::json!({ "name": "cd.iso" }),
    );
    let detected = FilesystemDetector.process(&raw).expect("detect");
    assert!(
        detected
            .iter()
            .any(|a| a.metadata.get("filesystem_type").and_then(|v| v.as_str()) == Some("ISO9660")),
        "ISO9660 must be detected"
    );

    // Extraction: FILE1.TXT must come out byte-for-byte.
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        serde_json::json!({ "filesystem_type": "ISO9660", "name": "iso" }),
    );
    let out = Iso9660Parser.process(&fs).expect("parse");
    let file = out
        .iter()
        .find(|a| {
            a.metadata
                .get("path")
                .and_then(|v| v.as_str())
                .map(|p| p.to_uppercase().contains("FILE1"))
                .unwrap_or(false)
        })
        .expect("FILE1.TXT");
    let sz = file.metadata.get("size").and_then(|v| v.as_u64()).unwrap() as usize;
    let d = file.data.as_ref().unwrap();
    let mut b = vec![0u8; sz];
    let mut o = 0;
    while o < sz {
        match d.read_at(o as u64, &mut b[o..]) {
            Ok(0) => break,
            Ok(n) => o += n,
            Err(_) => break,
        }
    }
    assert_eq!(compute_hashes(&b).md5, "2022999c3e0ffe912fafe799b723499a");
}
