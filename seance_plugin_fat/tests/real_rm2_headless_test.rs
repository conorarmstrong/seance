//! Deleted FAT entries in free clusters no `.`/`..` pair anchors (`HUNT-278`), on the NIST CFReDS Data Leakage
//! USB stick RM#2 (a 1 GiB FAT32 partition at sector 128 of a 4 GB device, quick-formatted after the files were
//! deleted).
//!
//! # Evidence and key
//!
//! `SEANCE_LEAK_RM2_RAW` names the raw image exported from `cfreds_2015_data_leakage_rm#2.E01` (`ewfexport -f raw`).
//! The key, `tests/data/cfreds_rm2_deleted_key.json`, is The Sleuth Kit's: `scripts/cftt/fat_deleted_key.py` runs `fls -r -d`
//! (which reaches deleted entries in free clusters through its `$OrphanFiles` scan) and `istat` for each size and
//! first sector. It lists 41 deleted files: the 17 the published answer key names (in five deleted directories), `desktop.ini`
//! and 23 pictures at the root level.
//!
//! The parser matches a TSK file when it publishes a deleted entry with the same size and the same first cluster.

use std::collections::BTreeSet;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource, WindowSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use seance_plugin_fat::FatParser;
use serde_json::{json, Value};

const START_SECTOR: u64 = 128;
const SECTORS: u64 = 2_097_152;

fn key() -> Value {
    serde_json::from_str(include_str!("data/cfreds_rm2_deleted_key.json")).unwrap()
}

fn run() -> Option<(Vec<Artifact>, Vec<u8>)> {
    let raw = corpus::path("SEANCE_LEAK_RM2_RAW")?;
    let whole: Arc<dyn DataSource> = Arc::new(FileDataSource::new(raw).unwrap());
    let part: Arc<dyn DataSource> =
        Arc::new(WindowSource::new(whole, START_SECTOR * 512, SECTORS * 512));
    let mut boot = vec![0u8; 512];
    part.read_at(0, &mut boot).unwrap();
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::Partition,
        Some(part),
        json!({ "name": "rm2" }),
    );
    Some((FatParser.process(&fs).expect("the volume parses"), boot))
}

/// The cluster a volume-relative sector belongs to.
fn cluster_of(boot: &[u8], sector: u64) -> u64 {
    let spc = u64::from(boot[13]);
    let reserved = u64::from(u16::from_le_bytes([boot[14], boot[15]]));
    let fats = u64::from(boot[16]);
    let fat_sectors = u64::from(u32::from_le_bytes(boot[36..40].try_into().unwrap()));
    (sector - (reserved + fats * fat_sectors)) / spc + 2
}

#[test]
fn every_deleted_file_the_sleuth_kit_finds_on_rm2_is_recovered() {
    let Some((out, boot)) = run() else { return };
    let key = key();
    let ours: BTreeSet<(u64, u64)> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter(|a| {
            a.metadata["deleted"] == json!(true) && a.metadata["is_directory"] != json!(true)
        })
        .map(|a| {
            (
                a.metadata["size"].as_u64().unwrap(),
                a.metadata["first_cluster"].as_u64().unwrap(),
            )
        })
        .collect();
    let mut missing = Vec::new();
    for (path, f) in key["files"].as_object().unwrap() {
        let want = (
            f["size"].as_u64().unwrap(),
            cluster_of(&boot, f["first_sector"].as_u64().unwrap()),
        );
        if !ours.contains(&want) {
            missing.push(path.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} TSK deleted files not recovered: {missing:?}",
        missing.len(),
        key["files"].as_object().unwrap().len()
    );
}

/// Precision on this volume: the 23 entries the headless scan publishes are all in The Sleuth Kit's list, and
/// each carries the labels that say what they are.
#[test]
fn the_headless_scan_publishes_nothing_the_sleuth_kit_does_not_list() {
    let Some((out, boot)) = run() else { return };
    let key = key();
    let want: BTreeSet<(u64, u64)> = key["files"]
        .as_object()
        .unwrap()
        .values()
        .map(|f| {
            (
                f["size"].as_u64().unwrap(),
                cluster_of(&boot, f["first_sector"].as_u64().unwrap()),
            )
        })
        .collect();
    let headless: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter(|a| a.metadata["orphan_directory_headless"] == json!(true))
        .collect();
    assert_eq!(headless.len(), 23, "the root-level pictures");
    for a in &headless {
        let k = (
            a.metadata["size"].as_u64().unwrap(),
            a.metadata["first_cluster"].as_u64().unwrap(),
        );
        assert!(
            want.contains(&k),
            "{} is not in TSK's list",
            a.metadata["path"]
        );
        assert_eq!(a.metadata["deleted"], json!(true));
        assert_eq!(a.metadata["recovered_from_free_space"], json!(true));
        assert!(a.metadata["path"]
            .as_str()
            .unwrap()
            .starts_with("/[headless directory entries, cluster "));
    }
    // The directory whose cluster holds the first ones carries a `.` that names a different cluster.
    assert!(headless.iter().any(|a| a
        .metadata
        .get("orphan_directory_dot_names_cluster")
        .is_some()));
}

/// False positives: the same scan on FAT volumes that hold plenty of file data and no headless directory
/// publishes nothing. `SEANCE_DFTT_DIR` names `forensic_corpora/dftt` and `SEANCE_CFTT_WIN_DD` the
/// string-search Windows image (partition 0 is FAT32 at sector 34).
#[test]
fn the_headless_scan_publishes_nothing_on_other_fat_volumes() {
    let mut volumes: Vec<(String, Arc<dyn DataSource>)> = Vec::new();
    if let Some(dir) = corpus::dir("SEANCE_DFTT_DIR") {
        for rel in [
            "6-undel-fat/6-undel-fat/6-fat-undel.dd",
            "2-kwsrch-fat/2-kwsrch-fat/fat-img-kw.dd",
            "11-carve-fat/11-carve-fat/11-carve-fat.dd",
            "9-fat-label/9-fat-label/9-fat-label.dd",
            "5-fat-daylight/5-fat-daylight/daylight.dd",
        ] {
            let src: Arc<dyn DataSource> =
                Arc::new(FileDataSource::new(dir.join(rel)).expect("a held DFTT image"));
            volumes.push((rel.to_string(), src));
        }
    }
    if let Some(win) = corpus::path("SEANCE_CFTT_WIN_DD") {
        let whole: Arc<dyn DataSource> = Arc::new(FileDataSource::new(win).unwrap());
        let part: Arc<dyn DataSource> = Arc::new(WindowSource::new(whole, 34 * 512, 976_528 * 512));
        volumes.push(("ss-win FAT32".to_string(), part));
    }
    for (name, source) in volumes {
        let fs = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Partition,
            Some(source),
            json!({ "name": name }),
        );
        let out = FatParser.process(&fs).expect("the volume parses");
        let headless = out
            .iter()
            .filter(|a| a.metadata["orphan_directory_headless"] == json!(true))
            .count();
        assert_eq!(
            headless, 0,
            "{name}: file bytes were read as directory entries"
        );
    }
}
