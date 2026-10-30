//! What the FAT parser makes of volumes written by Linux's own `vfat` and `exfat` drivers (`HUNT-278`).
//!
//! # Evidence
//!
//! `SEANCE_LINUX_FAT_DIR` names `forensic_corpora/lab_linux_fat/`: four 64 MiB volumes made on 2026-10-22 inside
//! the Séance Linux lab VM (Ubuntu 22.04, kernel 5.15.0-187) with the kernel's `vfat` (512-byte clusters) and
//! `exfat` (4 KiB) drivers mounted over loop devices (`make-fat.sh`; `what-was-done.log` times each step;
//! `<fs>.<Dir>.created.txt` is `ls -1` of each directory before anything was deleted). Each volume holds `DirA`
//! (300 long-named files, deleted whole with `rm -rf`), `DirB` (300 files, 260 deleted, directory kept), `DirC`
//! (20 files, deleted whole) and `DirD` (240 files written in two bursts around 200 KB of file data, so the
//! directory is not contiguous, deleted whole). `fat32-clean`/`exfat-clean` are the volumes at that point;
//! `vfat.img`/`exfat.img` are the same with a 40-file `Keep` written afterwards. The answer key is the creation
//! listing: no tool other than this one is needed, because the driver left the names.
//!
//! # What the evidence showed
//!
//! * Linux does not zero a deleted directory (Windows does). `vfat` marks every entry `0xE5` and frees the
//!   chain in the FAT; `exfat` clears the in-use bit of each entry and frees the clusters in the allocation
//!   bitmap but **leaves the FAT chain** of a directory that used one.
//! * The exFAT chain is therefore followable, and the stream extension's DataLength bounds it.

use std::collections::BTreeSet;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use seance_plugin_fat::FatParser;
use serde_json::{json, Value};

fn run(image: &str) -> Option<Vec<Artifact>> {
    let dir = corpus::dir("SEANCE_LINUX_FAT_DIR")?;
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(dir.join(image)).unwrap());
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::Partition,
        Some(src),
        json!({ "name": image }),
    );
    Some(FatParser.process(&fs).expect("the volume parses"))
}

fn created(family: &str, d: &str) -> BTreeSet<String> {
    let dir = corpus::dir("SEANCE_LINUX_FAT_DIR").unwrap();
    std::fs::read_to_string(dir.join(format!("{family}.{d}.created.txt")))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn under(out: &[Artifact], d: &str) -> BTreeSet<String> {
    let prefix = format!("/{d}/");
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter(|a| {
            a.metadata["path"]
                .as_str()
                .is_some_and(|p| p.starts_with(&prefix))
        })
        .filter_map(|a| a.metadata["name"].as_str().map(str::to_string))
        .collect()
}

fn dir_record<'a>(out: &'a [Artifact], d: &str) -> Option<&'a Value> {
    out.iter()
        .find(|a| {
            a.metadata["path"] == json!(format!("/{d}"))
                && a.metadata["is_directory"] == json!(true)
        })
        .map(|a| &a.metadata)
}

/// Deleted files in a live directory, and a deleted single-cluster directory, as before.
#[test]
fn deleted_files_of_a_live_directory_are_recovered_exactly() {
    for (image, family) in [("vfat-clean.img", "vfat"), ("exfat-clean.img", "exfat")] {
        let Some(out) = run(image) else { return };
        assert_eq!(under(&out, "DirB"), created(family, "DirB"), "{image}");
    }
}

/// `exfat` leaves a deleted directory's FAT chain: every name of the three deleted directories is
/// recovered, the non-contiguous one included, and none is invented.
#[test]
fn a_deleted_exfat_directory_is_followed_through_the_fat_chain_the_driver_left() {
    let Some(out) = run("exfat-clean.img") else {
        return;
    };
    for d in ["DirA", "DirC", "DirD"] {
        let got = under(&out, d);
        let want = created("exfat", d);
        assert_eq!(got, want, "{d}");
        let rec = dir_record(&out, d).unwrap_or_else(|| panic!("no record for {d}"));
        assert_eq!(rec["deleted"], json!(true), "{d}");
        assert!(
            rec.get("directory_parse_incomplete").is_none()
                || rec["directory_parse_incomplete"] == Value::Null,
            "{d}: {rec}"
        );
    }
    // DirA and DirD span several clusters, and say how they were located.
    for d in ["DirA", "DirD"] {
        assert_eq!(
            dir_record(&out, d).unwrap()["directory_chain_basis"],
            json!("stale_fat_chain"),
            "{d}"
        );
    }
}

/// After `Keep` was written the freed clusters may be taken: whatever is read is a subset of what was
/// created, and a directory that could not be read in full says so.
#[test]
fn after_new_files_were_written_nothing_is_invented_and_a_short_listing_says_so() {
    for (image, family) in [
        ("exfat.img", "exfat"),
        ("vfat.img", "vfat"),
        ("vfat-clean.img", "vfat"),
    ] {
        let Some(out) = run(image) else { return };
        for d in ["DirA", "DirC", "DirD"] {
            let got = under(&out, d);
            let want = created(family, d);
            assert!(
                got.is_subset(&want),
                "{image} {d}: invented {:?}",
                got.difference(&want).collect::<Vec<_>>()
            );
            if got.len() < want.len() {
                if let Some(rec) = dir_record(&out, d) {
                    assert_eq!(
                        rec["directory_parse_incomplete"],
                        json!(true),
                        "{image} {d}: short and silent"
                    );
                }
            }
        }
    }
}

fn every_name(out: &[Artifact]) -> BTreeSet<String> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter_map(|a| a.metadata["name"].as_str().map(str::to_string))
        .collect()
}

/// `vfat` puts a long name's slots in front of its short entry, so a name whose slots straddle a cluster
/// boundary has its head in one directory cluster and its tail in the next. In a deleted directory whose
/// clusters are not adjacent (file data sits between them) the two halves are joined only by the name's own
/// 8.3 checksum, and every entry of the three deleted directories comes back under its full name.
#[test]
fn names_that_straddle_a_cluster_of_a_deleted_vfat_directory_are_joined_and_complete() {
    let Some(out) = run("vfat-clean.img") else {
        return;
    };
    let names = every_name(&out);
    for d in ["DirA", "DirC", "DirD"] {
        let missing: Vec<_> = created("vfat", d).difference(&names).cloned().collect();
        assert!(
            missing.is_empty(),
            "{d}: {} names not recovered whole, e.g. {:?}",
            missing.len(),
            missing.iter().take(3).collect::<Vec<_>>()
        );
    }
}

/// A long name that could not be joined is flagged, never shown as if it were the whole name.
#[test]
fn a_possibly_truncated_deleted_name_says_so() {
    for image in ["vfat.img", "vfat-clean.img"] {
        let Some(out) = run(image) else { return };
        let all: BTreeSet<String> = ["DirA", "DirC", "DirD"]
            .iter()
            .flat_map(|d| created("vfat", d))
            .collect();
        for a in out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        {
            let name = a.metadata["name"].as_str().unwrap_or("");
            if a.metadata["deleted"] == json!(true)
                && name.starts_with("Quarterly")
                && !all.contains(name)
                && !created("vfat", "DirB").contains(name)
            {
                assert_eq!(
                    a.metadata["long_name_possibly_truncated"],
                    json!(true),
                    "{image}: {name} is shown whole"
                );
            }
        }
    }
}

/// Write `exfat-clean.img` to a scratch file with the root-directory entry set naming `victim` blanked, so no
/// directory entry points at that directory's clusters any more. The volume is otherwise the driver's own; only
/// the one set is blanked (this pins the mechanism: no real volume held lost a parent entry by reuse).
fn exfat_without_root_entry(victim: &str) -> Option<std::path::PathBuf> {
    let dir = corpus::dir("SEANCE_LINUX_FAT_DIR")?;
    let mut img = std::fs::read(dir.join("exfat-clean.img")).unwrap();
    let u32_at =
        |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
    let sector = 1usize << img[108];
    let cluster = sector << img[109];
    let heap = u32_at(&img, 88) * sector;
    let root = heap + (u32_at(&img, 96) - 2) * cluster;
    let mut at = root;
    let mut blanked = false;
    while at < root + cluster {
        let kind = img[at];
        if kind == 0 {
            break;
        }
        // A deleted file set: 0x05, then a stream (0x40) and name entries (0x41).
        if kind == 0x05 || kind == 0x85 {
            let n = img[at + 1] as usize;
            let name: String = (0..n.saturating_sub(1))
                .flat_map(|k| {
                    let e = at + 64 + 32 * k;
                    (0..15).map(move |j| (e, j))
                })
                .map(|(e, j)| u16::from_le_bytes([img[e + 2 + 2 * j], img[e + 3 + 2 * j]]))
                .take_while(|&c| c != 0)
                .map(|c| char::from_u32(c as u32).unwrap_or('?'))
                .collect();
            if name == victim {
                // Entry type 0x01 is unknown to a reader and skipped; a zero byte would end the directory.
                for k in 0..=n {
                    img[at + 32 * k..at + 32 * (k + 1)].fill(0);
                    img[at + 32 * k] = 0x01;
                }
                blanked = true;
            }
            at += 32 * (n + 1);
        } else {
            at += 32;
        }
    }
    assert!(blanked, "no root entry set for {victim}");
    let out = std::env::temp_dir().join(format!("seance-exfat-orphan-{victim}.img"));
    std::fs::write(&out, img).unwrap();
    Some(out)
}

/// A deleted directory whose parent's entry is gone is found by looking for entry sets in free clusters no
/// listing reached: all 300 names of `DirA` (ten clusters, a stale FAT chain) come back, as orphans, with
/// nothing else invented, and each says no parent names it.
#[test]
fn a_deleted_exfat_directory_with_no_parent_entry_is_found_by_the_orphan_scan() {
    let Some(path) = exfat_without_root_entry("DirA") else {
        return;
    };
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.clone()).unwrap());
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::Partition,
        Some(src),
        json!({ "name": "orphan" }),
    );
    let out = FatParser.process(&fs).expect("the volume parses");
    std::fs::remove_file(&path).unwrap();
    let orphans: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter(|a| a.metadata["orphan_directory_head_cluster"].is_number())
        .collect();
    let names: BTreeSet<String> = orphans
        .iter()
        .filter_map(|a| a.metadata["name"].as_str().map(str::to_string))
        .collect();
    let want = created("exfat", "DirA");
    assert_eq!(
        (
            names.len(),
            names.difference(&want).collect::<Vec<_>>(),
            want.difference(&names).collect::<Vec<_>>()
        ),
        (want.len(), vec![], vec![])
    );
    assert!(orphans.iter().all(|a| a.metadata["deleted"] == json!(true)));
    // Nothing of the other deleted directories is reported as an orphan.
    assert!(under(&out, "DirC") == created("exfat", "DirC"));
}

/// Where every deleted directory still has its parent's entry, the orphan scan finds nothing: it names only
/// what no listing reached.
#[test]
fn an_intact_exfat_volume_has_no_orphans() {
    for image in ["exfat-clean.img", "exfat.img"] {
        let Some(out) = run(image) else { return };
        let orphans = out
            .iter()
            .filter(|a| a.metadata["orphan_directory_head_cluster"].is_number())
            .count();
        assert_eq!(orphans, 0, "{image}");
    }
}

/// Move the root-directory entry set naming `victim` (a set the driver wrote and later deleted) behind the
/// directory's end marker, one slot of zeros after it, leaving the original slots as type 0x01 (skipped). With
/// `corrupt` one byte of the moved set's name is flipped so its SetChecksum no longer verifies.
fn exfat_with_set_behind_marker(victim: &str, corrupt: bool) -> Option<std::path::PathBuf> {
    let dir = corpus::dir("SEANCE_LINUX_FAT_DIR")?;
    let mut img = std::fs::read(dir.join("exfat-clean.img")).unwrap();
    let u32_at =
        |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
    let sector = 1usize << img[108];
    let cluster = sector << img[109];
    let heap = u32_at(&img, 88) * sector;
    let root = heap + (u32_at(&img, 96) - 2) * cluster;
    let (mut at, mut found, mut end) = (root, None, None);
    while at < root + cluster {
        let kind = img[at];
        if kind == 0 {
            end = Some(at);
            break;
        }
        if kind == 0x05 || kind == 0x85 {
            let n = img[at + 1] as usize;
            let name: String = (0..n.saturating_sub(1))
                .flat_map(|k| {
                    let e = at + 64 + 32 * k;
                    (0..15).map(move |j| (e, j))
                })
                .map(|(e, j)| u16::from_le_bytes([img[e + 2 + 2 * j], img[e + 3 + 2 * j]]))
                .take_while(|&c| c != 0)
                .map(|c| char::from_u32(c as u32).unwrap_or('?'))
                .collect();
            if name == victim {
                found = Some((at, n + 1));
            }
            at += 32 * (n + 1);
        } else {
            at += 32;
        }
    }
    let ((from, slots), end) = (found.expect("the set"), end.expect("an end marker"));
    let to = end + 32;
    assert!(
        to + 32 * slots <= root + cluster,
        "the set fits behind the marker"
    );
    let set: Vec<u8> = img[from..from + 32 * slots].to_vec();
    img[to..to + 32 * slots].copy_from_slice(&set);
    for k in 0..slots {
        img[from + 32 * k..from + 32 * (k + 1)].fill(0);
        img[from + 32 * k] = 0x01;
    }
    if corrupt {
        img[to + 32 * 2 + 2] ^= 0x01;
    }
    let out = std::env::temp_dir().join(format!("seance-exfat-slack-{victim}-{corrupt}.img"));
    std::fs::write(&out, img).unwrap();
    Some(out)
}

fn process_image(path: &std::path::Path) -> Vec<Artifact> {
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).unwrap());
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::Partition,
        Some(src),
        json!({ "name": "slack" }),
    );
    FatParser.process(&fs).expect("the volume parses")
}

/// An entry set left in the end marker's cluster behind the marker is published as slack when its SetChecksum
/// verifies, and said to be of unknown state; one that does not verify is not published.
#[test]
fn an_exfat_entry_set_behind_the_end_marker_is_slack_only_if_its_checksum_verifies() {
    let Some(good) = exfat_with_set_behind_marker("DirC", false) else {
        return;
    };
    let Some(bad) = exfat_with_set_behind_marker("DirC", true) else {
        return;
    };
    let (out_good, out_bad) = (process_image(&good), process_image(&bad));
    std::fs::remove_file(&good).unwrap();
    std::fs::remove_file(&bad).unwrap();
    let slack = |out: &[Artifact]| {
        out.iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .filter(|a| a.metadata["recovered_from_directory_slack"] == json!(true))
            .map(|a| a.metadata["name"].as_str().unwrap_or("").to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(slack(&out_good), vec!["DirC".to_string()]);
    assert!(slack(&out_bad).is_empty());
    // The slack directory is descended like any deleted one: its 20 names come back.
    assert_eq!(under(&out_good, "DirC"), created("exfat", "DirC"));
}
