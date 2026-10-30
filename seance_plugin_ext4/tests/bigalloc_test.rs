//! A bigalloc volume `mke2fs` wrote (EXT4-001).
//!
//! SYNTHETIC. `fixtures/ext4_bigalloc/ext4_bigalloc.img.gz` is a 128 MiB volume
//! made by `mke2fs -t ext4 -O bigalloc -b 1024 -C 4096 -d` (see
//! `scripts/synth/build_ext4_refused_fixtures.py`): four groups, four blocks to
//! a cluster, group 2 BLOCK_UNINIT, and files of 1, 5000 and 70000 bytes so
//! partly used clusters exist. The answer is `expected.json`: the per-group
//! `Free blocks:` ranges `dumpe2fs` prints and the SHA-256 of what `debugfs cat`
//! returns for each file, never anything Seance wrote. It grades the parser
//! against a volume a real tool produced and says nothing about bigalloc on
//! real-world evidence.

use flate2::read::GzDecoder;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_ext4::Ext4Parser;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::sync::Arc;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ext4_bigalloc");

fn run() -> (Vec<Artifact>, Value) {
    let key: Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/expected.json")).unwrap())
            .unwrap();
    let gz = std::fs::read(format!("{DIR}/ext4_bigalloc.img.gz")).expect("fixture");
    let mut img = Vec::new();
    GzDecoder::new(&gz[..]).read_to_end(&mut img).unwrap();
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(src),
        json!({ "subtype": "ext4", "filesystem_type": "ext4" }),
    );
    (Ext4Parser::new().process(&fs).unwrap(), key)
}

#[test]
fn free_space_equals_dumpe2fs_by_cluster() {
    let (out, key) = run();
    assert_eq!(key["synthetic"], json!(true));
    assert_eq!(key["e2fsck_clean"], json!(true));
    let mut want = BTreeSet::new();
    for g in key["groups"].as_array().unwrap() {
        for r in g["free"].as_array().unwrap() {
            want.extend(r[0].as_u64().unwrap()..=r[1].as_u64().unwrap());
        }
    }
    let mut got = BTreeSet::new();
    for a in out
        .iter()
        .filter(|a| a.metadata["source"] == json!("allocation_bitmap"))
    {
        let first = a.metadata["first_cluster"].as_u64().unwrap();
        let n = a.metadata["clusters"].as_u64().unwrap();
        got.extend(first..first + n);
    }
    let missing: Vec<_> = want.difference(&got).take(5).collect();
    let extra: Vec<_> = got.difference(&want).take(5).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "free blocks differ from dumpe2fs; missing {missing:?}, extra {extra:?}"
    );
    // Cluster-aligned: four 1 KiB blocks to a cluster, so a free run starts and
    // ends on a cluster boundary.
    for a in out
        .iter()
        .filter(|a| a.metadata["source"] == json!("allocation_bitmap"))
    {
        let first = a.metadata["first_cluster"].as_u64().unwrap();
        let n = a.metadata["clusters"].as_u64().unwrap();
        assert_eq!(first % 4, 0, "region starts inside a cluster");
        assert_eq!(n % 4, 0, "region ends inside a cluster");
    }
}

#[test]
fn the_volume_is_no_longer_refused() {
    let (out, _) = run();
    assert!(
        !out.iter()
            .any(|a| a.metadata.get("allocation_map_unavailable") == Some(&json!(true))),
        "bigalloc free space is derived, not omitted"
    );
    let map = out
        .iter()
        .find(|a| a.metadata["type"] == json!("allocation_map"))
        .expect("allocation map");
    assert_eq!(
        map.metadata["allocation_block_uninit_groups_synthesized"],
        json!(1),
        "group 2 is BLOCK_UNINIT and its bitmap is derived"
    );
}

/// Extents name blocks, not clusters: the files must still read back whole.
#[test]
fn every_file_equals_the_bytes_debugfs_cat_returned() {
    let (out, key) = run();
    for (rel, f) in key["files"].as_object().unwrap() {
        let a = out
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::FileEntry
                    && a.metadata["path"] == json!(format!("/{rel}"))
            })
            .unwrap_or_else(|| panic!("no entry for {rel}"));
        let d = a.data.as_ref().expect("content served");
        let mut buf = vec![0u8; d.size() as usize];
        let n = d.read_at(0, &mut buf).unwrap();
        assert_eq!(n as u64, f["size"].as_u64().unwrap(), "{rel}");
        let digest: String = Sha256::digest(&buf[..n])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest, f["sha256"].as_str().unwrap(), "{rel}");
    }
}
