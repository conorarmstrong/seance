//! What the FAT parser makes of volumes written by Windows' own FAT32 and exFAT drivers (`HUNT-278`).
//!
//! # Evidence
//!
//! `SEANCE_WIN11_FAT_DIR` names `forensic_corpora/lab_win11_fat/`: four fixed VHDs made on 2026-10-22 on the
//! Séance Windows 11 lab VM (25H2 Enterprise Evaluation) with `diskpart` and PowerShell
//! (`win11-lab/sticky/ps/fat-shapes.ps1`; `what-was-done.log` records each step with its time and the
//! `*.listing.csv` the files left): `fat32.vhd` and `exfat.vhd` (a directory of 300 long-named files deleted
//! whole, one of 300 files with 260 deleted and the directory kept, one of 20 files deleted whole, then 40
//! files written) and `fat32-clean.vhd` / `exfat-clean.vhd` (the same, nothing written afterwards). Partition
//! 1 starts at sector 128. The answer key is what the script did; no second tool lists deleted entries of
//! a deleted directory, because Windows left none (see below).
//!
//! # What the evidence showed, and what is pinned
//!
//! * Deleted **files** in a live directory are recovered by name, exactly: 260 of 260 on all four volumes.
//! * Windows **zero-fills a deleted directory's clusters** (checked by hand: every cluster of the exFAT
//!   chain and the FAT32 first cluster is all zero), so the 300 names of the deleted directory are not on
//!   the volume to recover. The parser says so, with its own reason, and invents nothing.
//! * Where the freed first cluster was taken again (by the next new directory, or by file data) the
//!   directory says it was reallocated or holds something else; before this run those cases were silent.
//!
//! Synthetic images say nothing about what another driver leaves (Linux, macOS, a camera); this is
//! Windows 11 only.

use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource, WindowSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use seance_plugin_fat::FatParser;
use serde_json::{json, Value};

const VOLUMES: [(&str, u64); 4] = [
    ("fat32.vhd", 522_112),
    ("exfat.vhd", 260_096),
    ("fat32-clean.vhd", 522_112),
    ("exfat-clean.vhd", 260_096),
];

fn run(file: &str, sectors: u64) -> Option<Vec<Artifact>> {
    let dir = corpus::dir("SEANCE_WIN11_FAT_DIR")?;
    let whole: Arc<dyn DataSource> = Arc::new(FileDataSource::new(dir.join(file)).unwrap());
    let part: Arc<dyn DataSource> = Arc::new(WindowSource::new(whole, 128 * 512, sectors * 512));
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::Partition,
        Some(part),
        json!({ "name": file }),
    );
    Some(FatParser.process(&fs).expect("the volume parses"))
}

fn entries<'a>(out: &'a [Artifact], prefix: &str) -> Vec<&'a Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter(|a| {
            a.metadata["path"]
                .as_str()
                .is_some_and(|p| p.starts_with(prefix))
        })
        .collect()
}

fn dir<'a>(out: &'a [Artifact], path: &str) -> &'a Artifact {
    out.iter()
        .find(|a| a.metadata["path"] == json!(path) && a.metadata["is_directory"] == json!(true))
        .unwrap_or_else(|| panic!("no directory {path}"))
}

#[test]
fn the_260_deleted_files_of_a_live_directory_are_recovered_by_name() {
    for (file, sectors) in VOLUMES {
        let Some(out) = run(file, sectors) else {
            return;
        };
        let files = entries(&out, "/DirB-shrunk/");
        let mut deleted: Vec<String> = files
            .iter()
            .filter(|a| a.metadata["deleted"] == json!(true))
            .map(|a| a.metadata["name"].as_str().unwrap().to_string())
            .collect();
        let mut live: Vec<String> = files
            .iter()
            .filter(|a| a.metadata["deleted"] != json!(true))
            .map(|a| a.metadata["name"].as_str().unwrap().to_string())
            .collect();
        deleted.sort();
        live.sort();
        let name = |n: u32| format!("seance-b-long-file-name-{n:04}.txt");
        assert_eq!(
            deleted,
            (1..=260).map(name).collect::<Vec<_>>(),
            "{file}: deleted"
        );
        assert_eq!(
            live,
            (261..=300).map(name).collect::<Vec<_>>(),
            "{file}: live"
        );
        // Each deleted entry carries the size the file had: "B" + its number + CRLF.
        for a in files
            .iter()
            .filter(|a| a.metadata["deleted"] == json!(true))
        {
            let n: u32 = a.metadata["name"].as_str().unwrap()[24..28]
                .parse()
                .unwrap();
            assert_eq!(
                a.metadata["size"],
                json!(1 + n.to_string().len() + 2),
                "{file} {n}"
            );
        }
    }
}

#[test]
fn a_directory_windows_deleted_gives_up_no_names_and_says_why() {
    for (file, sectors) in VOLUMES {
        let Some(out) = run(file, sectors) else {
            return;
        };
        for path in ["/DirA-multicluster", "/DirC-reused"] {
            let d = dir(&out, path);
            assert_eq!(d.metadata["deleted"], json!(true), "{file} {path}");
            assert!(
                entries(&out, &format!("{path}/")).is_empty(),
                "{file} {path}: no name is invented for a directory Windows emptied"
            );
            assert_eq!(
                d.metadata["directory_parse_incomplete"],
                json!(true),
                "{file} {path}: an empty list is not a statement that the directory was empty"
            );
            let reason = d.metadata["directory_parse_incomplete_reason"]
                .as_str()
                .unwrap();
            assert!(
                reason.ends_with("_zeroed") || reason.ends_with("_unverified"),
                "{file} {path}: {reason}"
            );
        }
    }
}

/// Where the cluster was freed and nothing took it, Windows' zero fill is what is left.
#[test]
fn the_clean_volumes_deleted_multicluster_directory_is_all_zero() {
    for (file, sectors) in [
        ("fat32-clean.vhd", 522_112u64),
        ("exfat-clean.vhd", 260_096),
    ] {
        let Some(out) = run(file, sectors) else {
            return;
        };
        let d = dir(&out, "/DirA-multicluster");
        assert_eq!(d.metadata["directory_content_zero"], json!(true), "{file}");
        let reason = d.metadata["directory_parse_incomplete_reason"]
            .as_str()
            .unwrap();
        assert!(reason.ends_with("_zeroed"), "{file}: {reason}");
        assert!(
            d.metadata.get("directory_content_reallocated").is_none()
                || d.metadata["directory_content_reallocated"] == Value::Null
        );
    }
}

/// Where the next new directory took the freed first cluster, the deleted directory says so.
#[test]
fn a_deleted_directory_whose_first_cluster_the_next_directory_took_is_flagged() {
    for (file, sectors) in [("fat32.vhd", 522_112u64), ("exfat.vhd", 260_096)] {
        let Some(out) = run(file, sectors) else {
            return;
        };
        let d = dir(&out, "/DirA-multicluster");
        assert_eq!(
            d.metadata["directory_content_reallocated"],
            json!(true),
            "{file}"
        );
        assert!(
            d.metadata["directory_parse_incomplete_reason"]
                .as_str()
                .unwrap()
                .ends_with("_unverified"),
            "{file}"
        );
        // The live directory that took it is read in full: 40 files.
        assert_eq!(entries(&out, "/Keep/").len(), 40, "{file}");
    }
}

/// Windows zero-fills a deleted directory, so there is no entry set in a free cluster to mistake for an orphaned
/// directory: the orphan scan names nothing on either exFAT volume.
#[test]
fn the_orphan_scan_finds_nothing_on_windows_exfat_volumes() {
    for (file, sectors) in [("exfat.vhd", 260_096), ("exfat-clean.vhd", 260_096)] {
        let Some(out) = run(file, sectors) else {
            return;
        };
        let orphans = out
            .iter()
            .filter(|a| a.metadata["orphan_directory_head_cluster"].is_number())
            .count();
        assert_eq!(orphans, 0, "{file}");
    }
}
