//! HFS+ file slack (`HUNT-282`) on the HFS+ partition of the NIST CFTT
//! string-search data set (`ss-unix-07-25-18.dd`, partition 0 at sector 2048,
//! 4,096-byte allocation blocks).
//!
//! # What is real and what is planted
//!
//! The image and its file tails are real, written by a macOS. Every one of
//! those tails is all zero, so the real run answers "no slack" and the counts
//! below prove it looked (`zero_files`). To give the reader something to find,
//! the second test plants a deterministic non-zero pattern in the tail of every
//! fifth file **in memory**, over the real bytes. The offsets and lengths of the
//! tails are The Sleuth Kit's (`scripts/cftt/hfs_slack_key.py`, key in
//! `tests/data/cftt_unix_hfsplus_slack_key.json`), not this crate's, and
//! `scripts/synth/plant_hfs_slack.py` plants the same bytes in a copy and checks
//! that `icat -s` prints exactly them. The planted volume is synthetic and says
//! nothing about what a real macOS leaves in a tail.
//!
//! Set `SEANCE_CFTT_UNIX_DD` to the `.dd`; unset, the tests skip and say so.

use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource, WindowSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use seance_plugin_hfsplus::HfsPlusParser;
use serde_json::{json, Value};

const SECTOR_OFFSET: u64 = 2048;
const PARTITION_SECTORS: u64 = 976_563;

fn key() -> Value {
    serde_json::from_str(include_str!("data/cftt_unix_hfsplus_slack_key.json")).unwrap()
}

/// The pattern `plant_hfs_slack.py` writes: byte `i` is `1 + ((cnid * 131 + i) % 250)`.
fn pattern(cnid: u64, length: u64) -> Vec<u8> {
    (0..length)
        .map(|i| (1 + (cnid * 131 + i) % 250) as u8)
        .collect()
}

/// A source that reads through to `inner` except where bytes were planted.
#[derive(Debug)]
struct Planted {
    inner: Arc<dyn DataSource>,
    patches: Vec<(u64, Vec<u8>)>,
}

impl DataSource for Planted {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read_at(offset, buf)?;
        let end = offset + n as u64;
        for (at, bytes) in &self.patches {
            let (lo, hi) = ((*at).max(offset), (*at + bytes.len() as u64).min(end));
            if lo < hi {
                buf[(lo - offset) as usize..(hi - offset) as usize]
                    .copy_from_slice(&bytes[(lo - at) as usize..(hi - at) as usize]);
            }
        }
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
}

fn partition() -> Option<Arc<dyn DataSource>> {
    let dd = corpus::path("SEANCE_CFTT_UNIX_DD")?;
    let whole: Arc<dyn DataSource> = Arc::new(FileDataSource::new(dd).expect("the corpus opens"));
    Some(Arc::new(WindowSource::new(
        whole,
        SECTOR_OFFSET * 512,
        PARTITION_SECTORS * 512,
    )))
}

fn run(source: Arc<dyn DataSource>) -> Vec<Artifact> {
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        json!({ "subtype": "hfsplus", "filesystem_type": "HFS+" }),
    );
    HfsPlusParser.process(&fs).expect("the volume parses")
}

fn summary(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata.get("type") == Some(&json!("SlackSpaceSummary")))
        .expect("the summary is always published")
}

fn bytes_of(a: &Artifact) -> Vec<u8> {
    let src = a.data.as_ref().expect("a region carries its bytes");
    let mut buf = vec![0u8; src.size() as usize];
    src.read_at(0, &mut buf).unwrap();
    buf
}

#[test]
fn the_real_volume_has_no_slack_and_the_summary_proves_it_looked() {
    let Some(source) = partition() else { return };
    let key = key();
    let out = run(source);
    assert!(
        !out.iter()
            .any(|a| a.artifact_type == ArtifactType::SlackSpace),
        "every real tail on this volume is zero"
    );
    let s = &summary(&out).metadata;
    let zero_files = key["zero_files"].as_object().unwrap().len() as u64;
    assert_eq!(s["files_offered"], json!(zero_files));
    assert_eq!(s["zero_tails"], json!(zero_files));
    assert_eq!(s["regions_emitted"], json!(0));
    assert_eq!(s["files_not_located"], json!(0));
}

#[test]
fn planted_tails_come_back_where_the_sleuth_kit_says_they_are() {
    let Some(source) = partition() else { return };
    let key = key();
    let zero_files = key["zero_files"].as_object().unwrap();
    let mut chosen: Vec<(&String, &Value)> = zero_files.iter().collect();
    chosen.sort_by_key(|(path, _)| path.to_string());
    let chosen: Vec<_> = chosen.into_iter().step_by(5).collect();
    let patches = chosen
        .iter()
        .map(|(_, t)| {
            (
                t["offset"].as_u64().unwrap(),
                pattern(t["cnid"].as_u64().unwrap(), t["length"].as_u64().unwrap()),
            )
        })
        .collect();
    let out = run(Arc::new(Planted {
        inner: source,
        patches,
    }));

    let regions: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .collect();
    assert_eq!(regions.len(), chosen.len(), "one region per planted tail");
    for (path, t) in &chosen {
        let region = regions
            .iter()
            .find(|r| r.metadata["parent_path"] == json!(path))
            .unwrap_or_else(|| panic!("no region for {path}"));
        assert_eq!(region.metadata["offset_bytes"], t["offset"], "{path}");
        assert_eq!(region.metadata["size_bytes"], t["length"], "{path}");
        assert_eq!(region.metadata["filesystem"], json!("hfsplus"));
        assert_eq!(region.metadata["cluster_size"], json!(4096));
        assert_eq!(region.metadata["logical_size"], t["size"], "{path}");
        assert_eq!(
            bytes_of(region),
            pattern(t["cnid"].as_u64().unwrap(), t["length"].as_u64().unwrap()),
            "{path}: the region holds exactly the planted bytes"
        );
    }
    let s = &summary(&out).metadata;
    assert_eq!(s["regions_emitted"], json!(chosen.len()));
    assert_eq!(
        s["zero_tails"],
        json!(zero_files.len() - chosen.len()),
        "the other tails were read and are zero"
    );
}
