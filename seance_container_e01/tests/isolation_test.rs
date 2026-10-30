//! B3: E01 parsing runs in an isolated helper subprocess. Verifies the full
//! spawn/handshake/read-over-IPC path decodes a real E01 byte-identically.

use seance_container_e01::{open_e01, E01ContainerModule};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::hashing::compute_hashes;
use seance_core::module::ForensicsModule;
use serde_json::json;
use uuid::Uuid;

fn rp(rel: &str) -> std::path::PathBuf {
    let root = std::env::current_dir().unwrap();
    if root.ends_with("seance_container_e01") {
        root.parent().unwrap().join(rel)
    } else {
        root.join(rel)
    }
}

fn read_all_md5(src: &dyn DataSource) -> String {
    let size = src.size() as usize;
    let mut out = vec![0u8; size];
    let mut done = 0;
    while done < size {
        match src.read_at(done as u64, &mut out[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(_) => break,
        }
    }
    compute_hashes(&out[..done]).md5
}

/// The canon2 E01 decodes to the raw image whose md5 is 750b509d...; reading it
/// through the isolated helper must reproduce that exactly.
#[test]
fn isolated_e01_decodes_correctly() {
    let img = rp("test_data/canon2/nps-2009-canon2-gen6.E01");
    if !img.exists() {
        println!("Skipping: canon2 E01 not present");
        return;
    }
    // Force isolation and point at the helper the test build produced.
    std::env::set_var("SEANCE_E01_ISOLATED", "true");
    let helper = rp("target/release/seance-ewf-helper");
    if helper.exists() {
        std::env::set_var("SEANCE_EWF_HELPER", &helper);
    }

    let opened = open_e01(img.to_str().unwrap()).expect("open_e01");
    assert!(
        opened.isolated,
        "expected the isolated helper path to be used"
    );
    assert_eq!(opened.size, 31_129_600, "unexpected decoded media size");
    assert_eq!(
        read_all_md5(opened.source.as_ref()),
        "750b509d8fbed37a5213480aaccfdc61"
    );

    // And through the full module process() path.
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "name": "nps-2009-canon2-gen6.E01", "path": img.to_string_lossy(), "subtype": "e01" }),
    );
    let out = E01ContainerModule.process(&art).expect("process");
    let raw = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::RawEvidence)
        .expect("raw evidence");
    assert_eq!(
        raw.metadata.get("container").and_then(|v| v.as_str()),
        Some("e01")
    );
    let src = raw.data.as_ref().expect("data source");
    assert_eq!(
        read_all_md5(src.as_ref()),
        "750b509d8fbed37a5213480aaccfdc61"
    );
}
