//! Inline-data inodes on a volume `mke2fs` wrote (EXT4-001).
//!
//! SYNTHETIC. `fixtures/ext4_inline/ext4_inline.img.gz` is an 8 MiB volume made
//! by `mke2fs -t ext4 -O inline_data -I 256 -d` (see
//! `scripts/synth/build_ext4_refused_fixtures.py`), with one inline directory's
//! `system.data` continuation planted through `debugfs`. It grades the parser
//! against `debugfs cat`, `debugfs ls` and `e2fsck -fn` on a volume a real tool
//! produced. It says nothing about inline data on real-world evidence.
//!
//! The answer is `expected.json`, written from `debugfs`, never from Seance.

use flate2::read::GzDecoder;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_ext4::Ext4Parser;
use serde_json::{json, Value};
use std::io::Read;
use std::sync::Arc;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ext4_inline");

fn expected() -> Value {
    let text = std::fs::read_to_string(format!("{FIXTURES}/expected.json")).expect("answer key");
    serde_json::from_str(&text).expect("answer key is JSON")
}

fn run() -> Vec<Artifact> {
    let gz = std::fs::read(format!("{FIXTURES}/ext4_inline.img.gz")).expect("fixture");
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
    Ext4Parser::new().process(&fs).expect("process")
}

fn entry<'a>(out: &'a [Artifact], path: &str) -> &'a Artifact {
    out.iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry && a.metadata["path"] == json!(path))
        .unwrap_or_else(|| panic!("no entry for {path}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn every_file_equals_the_bytes_debugfs_cat_returned() {
    let plan = expected();
    assert_eq!(
        plan["e2fsck_clean"],
        json!(true),
        "the key is for a clean volume"
    );
    let out = run();
    for (rel, f) in plan["files"].as_object().unwrap() {
        let a = entry(&out, &format!("/{rel}"));
        let want = f["hex"].as_str().unwrap();
        let d = a
            .data
            .as_ref()
            .unwrap_or_else(|| panic!("{rel}: no content served"));
        let mut buf = vec![0u8; d.size() as usize];
        let n = d.read_at(0, &mut buf).unwrap();
        assert_eq!(hex(&buf[..n]), want, "{rel}");
        assert_eq!(a.metadata["size"], f["size"], "{rel}");
        assert_eq!(
            a.metadata["inline_data"] == json!(true),
            f["inline"].as_bool().unwrap(),
            "{rel}: inline flag as debugfs stat reports it"
        );
        assert!(
            a.metadata.get("content_incomplete").is_none(),
            "{rel}: a fully assembled inline file is not incomplete"
        );
    }
}

#[test]
fn the_split_between_i_block_and_system_data_is_published() {
    let out = run();
    let h = entry(&out, "/h100.txt");
    assert_eq!(h.metadata["inline_data_bytes_in_inode"], json!(60));
    assert_eq!(h.metadata["inline_data_bytes_in_xattr"], json!(40));
    let t = entry(&out, "/tiny.txt");
    assert_eq!(t.metadata["inline_data_bytes_in_xattr"], json!(0));
    assert!(t.metadata.get("data_runs").is_none(), "no block run exists");
}

#[test]
fn directory_listings_equal_debugfs_ls() {
    let plan = expected();
    let out = run();
    for (dir, d) in plan["dirs"].as_object().unwrap() {
        let path = format!("/{dir}");
        let mut got: Vec<String> = out
            .iter()
            .filter(|a| a.metadata["parent_path"] == json!(path))
            .map(|a| a.metadata["name"].as_str().unwrap().to_string())
            .collect();
        got.sort();
        let want: Vec<String> = d["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, want, "{dir}");
        let de = entry(&out, &path);
        assert_eq!(
            de.metadata["inline_data"] == json!(true),
            d["inline"].as_bool().unwrap()
        );
        assert!(
            de.metadata.get("directory_parse_incomplete").is_none(),
            "{dir}: the listing covers the directory"
        );
    }
}

#[test]
fn the_continuation_entry_in_system_data_is_listed() {
    let out = run();
    let sub = entry(&out, "/sub");
    assert!(sub.metadata["inline_dir_parent_inode"].as_u64().is_some());
    let zz = entry(&out, "/sub/zz.txt");
    assert_eq!(zz.metadata["parent_path"], json!("/sub"));
}
