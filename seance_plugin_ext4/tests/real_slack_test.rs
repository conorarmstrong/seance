//! File slack on a real ext4 volume, graded against a plan written down before
//! the parser saw it (HUNT-124).
//!
//! `fixtures/ext4_slack/ext4_slack.img.gz` is a 2 MiB volume `mke2fs -d` wrote
//! (1 KiB blocks, no journal) holding five files whose sizes fix their tails.
//! `mke2fs` leaves every tail zero, so `scripts/synth/build_ext4_slack_fixture.py`
//! wrote recognisable bytes into two of them, at the offsets pytsk3 reports for
//! their last blocks, and recorded the plan in `expected.json`:
//!
//! * `tail_a.txt` (1,500 B) and `big.bin` (5,000 B): planted tails, one region each;
//! * `tail_zero.txt` (700 B): a tail of zeros, counted and not emitted;
//! * `exact.bin` (2,048 B) and `empty.dat`: no tail, nothing;
//! * `tail_a_link.txt`: a second name for `tail_a.txt`'s inode — one tail, offered once.
//!
//! The answer is the script's plan, checked there against pytsk3 — not
//! Séance's own output.

use flate2::read::GzDecoder;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_ext4::Ext4Parser;
use serde_json::{json, Value};
use std::io::Read;
use std::sync::Arc;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ext4_slack");

fn expected() -> Value {
    let text = std::fs::read_to_string(format!("{FIXTURES}/expected.json")).expect("plan");
    serde_json::from_str(&text).expect("plan is JSON")
}

fn run() -> Vec<Artifact> {
    let gz = std::fs::read(format!("{FIXTURES}/ext4_slack.img.gz")).expect("fixture");
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

fn bytes_of(a: &Artifact) -> Vec<u8> {
    let d = a.data.as_ref().expect("a region has bytes");
    let mut b = vec![0u8; d.size() as usize];
    let n = d.read_at(0, &mut b).expect("read");
    assert_eq!(n, b.len());
    b
}

#[test]
fn the_planted_tails_come_back_as_slack_regions_and_nothing_else_does() {
    let plan = expected();
    let out = run();
    let regions: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .collect();
    let want: Vec<&str> = plan["regions_expected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(regions.len(), want.len(), "one region per planted tail");
    for name in want {
        let t = &plan["files"][name]["tail"];
        let region = regions
            .iter()
            .find(|r| r.metadata["parent_file"] == json!(name))
            .unwrap_or_else(|| panic!("no region for {name}"));
        assert_eq!(region.metadata["offset_bytes"], t["offset"], "{name}");
        assert_eq!(region.metadata["size_bytes"], t["length"], "{name}");
        assert_eq!(region.metadata["filesystem"], json!("ext4"));
        assert_eq!(region.metadata["source"], json!("file_slack"));
        assert_eq!(region.metadata["cluster_size"], json!(1024));
        assert_eq!(region.metadata["logical_size"], plan["files"][name]["size"]);
        assert_eq!(
            bytes_of(region),
            t["planted"].as_str().unwrap().as_bytes(),
            "{name}: the region holds exactly the planted bytes"
        );
    }
}

#[test]
fn the_summary_counts_what_was_examined_including_the_zero_tail() {
    let plan = expected();
    let out = run();
    let s = out
        .iter()
        .find(|a| a.metadata["subtype"] == json!("slack_space_summary"))
        .expect("a summary is emitted for every volume");
    assert_eq!(s.metadata["filesystem"], json!("ext4"));
    assert_eq!(s.metadata["regions_emitted"], json!(2));
    assert_eq!(
        s.metadata["zero_tails"],
        json!(plan["zero_tails_expected"].as_array().unwrap().len())
    );
    // Three inodes have a tail (the hard link shares one); the block-aligned
    // and the empty file do not.
    assert_eq!(s.metadata["files_offered"], json!(3));
    assert_eq!(s.metadata["unreadable_tails"], json!(0));
    assert_eq!(s.metadata["files_not_located"], json!(0));
    assert!(s.metadata.get("content_incomplete").is_none());
}
