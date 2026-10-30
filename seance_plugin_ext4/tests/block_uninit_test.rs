//! BLOCK_UNINIT groups on volumes `mke2fs` wrote (EXT4-001).
//!
//! SYNTHETIC. The images under `fixtures/ext4_uninit_*` are 64 MiB volumes made
//! by `mke2fs -t ext4 -E lazy_itable_init=1` (see
//! `scripts/synth/build_ext4_refused_fixtures.py`), so groups 2, 4 and 6 carry
//! BLOCK_UNINIT. The answer is `expected.json`, the `Free blocks:` ranges
//! `dumpe2fs` prints for every group: libext2fs computes the bitmap the kernel
//! would for an uninitialised group, independently of Seance. This grades the
//! parser against a volume a real tool produced and says nothing about
//! BLOCK_UNINIT on real-world evidence.

use flate2::read::GzDecoder;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_ext4::Ext4Parser;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::Read;
use std::sync::Arc;

fn dir(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn run(name: &str) -> (Vec<Artifact>, Value) {
    let key: Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{}/expected.json", dir(name))).expect("answer key"),
    )
    .expect("JSON");
    let gz = std::fs::read(format!("{}/{name}.img.gz", dir(name))).expect("fixture");
    let mut img = Vec::new();
    GzDecoder::new(&gz[..])
        .read_to_end(&mut img)
        .expect("gunzip");
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(src),
        json!({ "subtype": "ext4", "filesystem_type": "ext4" }),
    );
    (Ext4Parser::new().process(&fs).expect("process"), key)
}

/// Blocks the parser offers as free space, from the regions it emitted.
fn parser_free(out: &[Artifact]) -> BTreeSet<u64> {
    let mut set = BTreeSet::new();
    for a in out
        .iter()
        .filter(|a| a.metadata["source"] == json!("allocation_bitmap"))
    {
        let first = a.metadata["first_cluster"].as_u64().unwrap();
        let n = a.metadata["clusters"].as_u64().unwrap();
        set.extend(first..first + n);
    }
    set
}

/// Blocks `dumpe2fs` lists as free in every group.
fn oracle_free(key: &Value) -> BTreeSet<u64> {
    let mut set = BTreeSet::new();
    for g in key["groups"].as_array().unwrap() {
        for r in g["free"].as_array().unwrap() {
            set.extend(r[0].as_u64().unwrap()..=r[1].as_u64().unwrap());
        }
    }
    set
}

fn check(name: &str) {
    let (out, key) = run(name);
    assert_eq!(key["synthetic"], json!(true));
    assert_eq!(key["e2fsck_clean"], json!(true));
    let uninit = key["uninit_groups"].as_array().unwrap().len();
    assert!(uninit > 0, "{name}: the fixture has BLOCK_UNINIT groups");

    let want = oracle_free(&key);
    let got = parser_free(&out);
    let missing: Vec<_> = want.difference(&got).take(5).collect();
    let extra: Vec<_> = got.difference(&want).take(5).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{name}: free blocks differ from dumpe2fs; missing {missing:?}, extra {extra:?}"
    );

    let map = out
        .iter()
        .find(|a| a.metadata["type"] == json!("allocation_map"))
        .expect("allocation map");
    assert_eq!(
        map.metadata["allocation_block_uninit_groups_synthesized"],
        json!(uninit),
        "{name}: the groups whose bitmap was derived are counted"
    );
    assert!(
        map.metadata["allocation_block_uninit_basis"]
            .as_str()
            .unwrap()
            .contains("not read from disk"),
        "{name}: the basis is stated"
    );
    assert!(
        map.metadata.get("allocation_block_uninit_groups").is_none(),
        "{name}: no group is left unassessed"
    );
    assert_ne!(map.metadata["free_space_complete"], json!(false), "{name}");
}

#[test]
fn flex_bg_free_space_equals_dumpe2fs() {
    check("ext4_uninit_flex");
}

#[test]
fn no_flex_bg_free_space_equals_dumpe2fs() {
    check("ext4_uninit_noflex");
}

#[test]
fn meta_bg_free_space_equals_dumpe2fs() {
    check("ext4_uninit_meta");
}

/// 4 KiB blocks, and BLOCK_UNINIT groups 3 and 5 that each carry a backup
/// superblock, a descriptor block and 127 reserved descriptor blocks, with
/// their on-disk bitmaps zeroed: a parser that read the bitmap would call the
/// whole group free.
#[test]
fn backup_superblock_and_reserved_gdt_groups_equal_dumpe2fs() {
    check("ext4_uninit_4k");
}
