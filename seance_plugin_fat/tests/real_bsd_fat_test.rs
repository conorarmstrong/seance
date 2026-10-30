//! What the FAT parser makes of volumes written by FreeBSD's own `msdosfs` driver (`HUNT-278`).
//!
//! # Evidence
//!
//! `SEANCE_BSD_FAT_DIR` names `forensic_corpora/lab_bsd_fat/`: ten images (five volumes, each at two points) made on 2026-10-23 inside a FreeBSD
//! 14.5-RELEASE guest (the official `amd64-ufs.qcow2` VM image, run under QEMU/KVM) with `newfs_msdos` and
//! `mount_msdosfs` over virtio disks (`make-fat-bsd.sh`; `what-was-done-fat.log` times each step;
//! `<volume>.<Dir>.created.txt` is `ls -1` of each directory before anything was deleted and
//! `<volume>.<Dir>.sha256.txt` the `sha256 -r` of its files). The volumes are `fat32c1` (FAT32, 512-byte clusters),
//! `fat16c8` (FAT16, 4 KiB) and `fat32c8` (FAT32, 4 KiB). Each holds `DirA` (300 long-named files, deleted whole
//! with `rm -rf`), `DirB` (300 files, 260 deleted, directory kept), `DirC` (20 files, deleted whole) and `DirD`
//! (240 files written in two bursts around 200 KB of file data, deleted whole). `<volume>-clean.img` is the volume
//! at that point; `<volume>.img` is the same with a 40-file `Keep` written afterwards. `exfatc4` is the same shape
//! on exFAT, written through the packaged FUSE driver (`make-exfat-bsd.sh`, `what-was-done-exfat.log`).
//! `ofat32c1` and `ofat16c8` are the FAT shapes again from OpenBSD 8.0's `newfs_msdos` and `mount_msdos`
//! (`make-fat-openbsd.sh`, `what-was-done-openbsd.log`). The first group is the closest
//! legitimate stand-in for macOS's `msdos` driver, which derives from FreeBSD's `msdosfs`.
//!
//! # What the evidence showed
//!
//! * `msdosfs` does not zero a deleted directory (Windows does): it marks every entry `0xE5`, frees the chain in
//!   the FAT, and leaves the directory's clusters as they were.
//! * It allocates a new file's first data cluster between a directory's clusters, so even `DirA` (created before
//!   anything else) is not contiguous: its clusters are interleaved with the data of its own files.
//! * OpenBSD's `msdos` driver also leaves the directory whole and frees the chain, but grows a directory over
//!   consecutive clusters, so the contiguity assumption reads all of it. That exposed a defect: the same entries
//!   were published a second time as headless clusters, because the cluster scan did not know the deleted
//!   directory's walk had already read them.
//! * The FUSE `exfat` driver (relan/exfat 1.4.0) frees the whole FAT chain of a deleted directory and leaves
//!   `DataLength` at one cluster, so only the first cluster is reachable from the parent's entry.

use std::collections::BTreeSet;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use seance_plugin_fat::FatParser;
use serde_json::{json, Value};

const VOLUMES: [&str; 5] = ["fat32c1", "fat16c8", "fat32c8", "ofat32c1", "ofat16c8"];

fn run(image: &str) -> Option<Vec<Artifact>> {
    let dir = corpus::dir("SEANCE_BSD_FAT_DIR")?;
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(dir.join(image)).unwrap());
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::Partition,
        Some(src),
        json!({ "name": image }),
    );
    Some(FatParser.process(&fs).expect("the volume parses"))
}

fn created(volume: &str, d: &str) -> BTreeSet<String> {
    let dir = corpus::dir("SEANCE_BSD_FAT_DIR").unwrap();
    std::fs::read_to_string(dir.join(format!("{volume}.{d}.created.txt")))
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

fn every_name(out: &[Artifact]) -> BTreeSet<String> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter_map(|a| a.metadata["name"].as_str().map(str::to_string))
        .collect()
}

/// Deleted files of a live directory: all 260 names come back, and the 40 that survive stay live.
#[test]
fn deleted_files_of_a_live_bsd_directory_are_recovered_exactly() {
    for volume in VOLUMES {
        let Some(out) = run(&format!("{volume}-clean.img")) else {
            return;
        };
        assert_eq!(under(&out, "DirB"), created(volume, "DirB"), "{volume}");
    }
}

/// `msdosfs` leaves a deleted directory's clusters whole (not zeroed, as Windows does) and frees the FAT chain.
/// Every name of the three deleted directories comes back, whole. Only the directory's first cluster is led to
/// by its parent's entry; the later clusters have no FAT chain left and no `.` entry, so they are published as
/// headless clusters and not under the folder (see the next test), which is what this one pins.
#[test]
fn a_deleted_bsd_directory_is_recovered_whole_from_the_clusters_the_driver_left() {
    for volume in VOLUMES {
        let Some(out) = run(&format!("{volume}-clean.img")) else {
            return;
        };
        let names = every_name(&out);
        for d in ["DirA", "DirC", "DirD"] {
            let want = created(volume, d);
            let missing: Vec<_> = want.difference(&names).cloned().collect();
            assert!(
                missing.is_empty(),
                "{volume} {d}: {} of {} names not recovered whole, e.g. {:?}",
                missing.len(),
                want.len(),
                missing.iter().take(3).collect::<Vec<_>>()
            );
            let got = under(&out, d);
            assert!(
                !got.is_empty() && got.is_subset(&want),
                "{volume} {d}: {} of {} under its own path",
                got.len(),
                want.len()
            );
        }
    }
}

/// The directories are recovered from clusters no FAT entry leads to, so the listing of a multi-cluster one
/// under its own path is short, and its record says so; no entry is stated to belong to a folder it cannot be
/// shown to belong to (a recovered name's path names its cluster and says that it does).
#[test]
fn a_bsd_directory_listed_in_part_says_so_and_headless_clusters_say_what_their_path_means() {
    for volume in VOLUMES {
        let Some(out) = run(&format!("{volume}-clean.img")) else {
            return;
        };
        for d in ["DirA", "DirC", "DirD"] {
            let listed = under(&out, d).len();
            let rec = dir_record(&out, d).unwrap_or_else(|| panic!("{volume}: no record for {d}"));
            assert_eq!(rec["deleted"], json!(true), "{volume} {d}");
            if listed < created(volume, d).len() {
                assert_eq!(
                    rec["directory_parse_incomplete"],
                    json!(true),
                    "{volume} {d}: {listed} listed, silent"
                );
            }
        }
        for a in out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .filter(|a| a.metadata["orphan_directory_headless"] == json!(true))
        {
            assert!(
                a.metadata["path_basis"]
                    .as_str()
                    .is_some_and(|s| s.contains("names the cluster, not a folder")),
                "{volume}: {}",
                a.metadata["path"]
            );
        }
    }
}

/// OpenBSD's driver leaves a deleted directory whole and its clusters consecutive (it allocates the next
/// directory cluster next to the last), so the contiguity assumption reads every name under the folder, and
/// says on the directory that it assumed it.
#[test]
fn an_openbsd_deleted_directory_is_read_whole_under_its_own_path_and_says_it_assumed_contiguity() {
    for volume in ["ofat32c1", "ofat16c8"] {
        let Some(out) = run(&format!("{volume}-clean.img")) else {
            return;
        };
        for d in ["DirA", "DirC", "DirD"] {
            let (got, want) = (under(&out, d), created(volume, d));
            assert_eq!(got, want, "{volume} {d}: {} of {}", got.len(), want.len());
            let rec = dir_record(&out, d).unwrap();
            assert_eq!(rec["deleted"], json!(true), "{volume} {d}");
            assert!(rec["directory_parse_incomplete"].is_null(), "{volume} {d}");
            if rec["directory_clusters_read"].as_u64().unwrap_or(1) > 1 {
                assert_eq!(rec["directory_chain_basis"], json!("contiguous_assumed"));
            }
        }
    }
}

/// A deleted entry is published once. OpenBSD's driver grows a directory over consecutive clusters, so the walk
/// of a deleted directory that assumes contiguity reads all of them under the folder; the scan for headless
/// directory clusters must not then publish the same entries again as if nothing led to their cluster.
#[test]
fn a_deleted_entry_read_under_its_directory_is_not_published_again_as_headless() {
    for volume in VOLUMES {
        for image in [format!("{volume}.img"), format!("{volume}-clean.img")] {
            let Some(out) = run(&image) else { return };
            let mut seen = std::collections::BTreeMap::new();
            for a in out
                .iter()
                .filter(|a| a.artifact_type == ArtifactType::FileEntry)
                .filter(|a| a.metadata["deleted"] == json!(true))
                .filter(|a| a.metadata["is_directory"] != json!(true))
            {
                let key = (
                    a.metadata["name"].as_str().unwrap_or("").to_string(),
                    a.metadata["first_cluster"].as_u64(),
                );
                seen.entry(key)
                    .or_insert_with(Vec::new)
                    .push(a.metadata["path"].as_str().unwrap_or("").to_string());
            }
            let twice: Vec<_> = seen.iter().filter(|(_, v)| v.len() > 1).take(3).collect();
            assert!(twice.is_empty(), "{image}: published twice, e.g. {twice:?}");
        }
    }
}

/// Every deleted file of the three deleted directories is read back from the volume at the runs the record
/// names, and its bytes hash to the `sha256 -r` taken in the guest before anything was deleted.
#[test]
fn recovered_bsd_files_hash_to_what_the_guest_recorded() {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    let Some(dir) = corpus::dir("SEANCE_BSD_FAT_DIR") else {
        return;
    };
    for volume in VOLUMES {
        let image = format!("{volume}-clean.img");
        let out = run(&image).unwrap();
        let mut want = std::collections::BTreeMap::new();
        for d in ["DirA", "DirC", "DirD"] {
            let text =
                std::fs::read_to_string(dir.join(format!("{volume}.{d}.sha256.txt"))).unwrap();
            for line in text.lines() {
                let (hash, name) = line.split_once(' ').unwrap();
                want.insert(name.trim().to_string(), hash.to_string());
            }
        }
        let mut img = std::fs::File::open(dir.join(&image)).unwrap();
        let mut checked = 0usize;
        for a in out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        {
            let name = a.metadata["name"].as_str().unwrap_or("");
            let Some(hash) = want.get(name) else { continue };
            if a.metadata["deleted"] != json!(true) {
                continue;
            }
            let size = a.metadata["size"].as_u64().unwrap() as usize;
            let mut bytes = Vec::new();
            for run in a.metadata["data_runs"].as_array().unwrap() {
                let (off, len) = (run[0].as_u64().unwrap(), run[1].as_u64().unwrap() as usize);
                let mut buf = vec![0u8; len];
                img.seek(SeekFrom::Start(off)).unwrap();
                img.read_exact(&mut buf).unwrap();
                bytes.extend(buf);
            }
            bytes.truncate(size);
            let got: String = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(&got, hash, "{volume}: {name}");
            checked += 1;
        }
        assert_eq!(checked, want.len(), "{volume}: files checked");
    }
}

/// After `Keep` was written the freed clusters may be taken: whatever is read is a subset of what was created,
/// a directory that could not be read in full says so, and a name that could not be joined is flagged.
#[test]
fn after_new_files_were_written_to_a_bsd_volume_nothing_is_invented_and_a_short_listing_says_so() {
    for volume in VOLUMES {
        for image in [format!("{volume}.img"), format!("{volume}-clean.img")] {
            let Some(out) = run(&image) else { return };
            let all: BTreeSet<String> = ["DirA", "DirC", "DirD"]
                .iter()
                .flat_map(|d| created(volume, d))
                .collect();
            for d in ["DirA", "DirC", "DirD"] {
                let got = under(&out, d);
                let want = created(volume, d);
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
            for a in out
                .iter()
                .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            {
                let name = a.metadata["name"].as_str().unwrap_or("");
                if a.metadata["deleted"] == json!(true)
                    && name.starts_with("Quarterly")
                    && !all.contains(name)
                    && !created(volume, "DirB").contains(name)
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
}

/// The bytes of a recovered file, read from the volume at the runs its record names.
fn content_of(img: &mut std::fs::File, a: &Artifact) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let size = a.metadata["size"].as_u64().unwrap() as usize;
    let mut bytes = Vec::new();
    for run in a.metadata["data_runs"].as_array().unwrap() {
        let (off, len) = (run[0].as_u64().unwrap(), run[1].as_u64().unwrap() as usize);
        let mut buf = vec![0u8; len];
        img.seek(SeekFrom::Start(off)).unwrap();
        img.read_exact(&mut buf).unwrap();
        bytes.extend(buf);
    }
    bytes.truncate(size);
    bytes
}

/// The exFAT volume was written by the packaged FUSE driver (`fusefs-exfat` 1.4.0, relan/exfat, `mkexfatfs -s 8`,
/// 4 KiB clusters) on the same FreeBSD guest, in the same shapes. Unlike Linux's `exfat`, this driver frees the
/// whole FAT chain of a directory it deletes and writes the entry set with a `DataLength` of one cluster, so the
/// clusters after the first are led to by nothing. The one-cluster `DirC` comes back whole. `DirA` and `DirD`
/// come back in part: the first cluster under their own path, and the later clusters that happen to begin at an
/// entry set as orphans. The record says the listing is a prefix, nothing is invented, and every file read,
/// wherever it was found, hashes to what the guest recorded.
///
/// This is a limit, not a goal: a cluster that begins in the middle of an entry set (a set may straddle a
/// cluster boundary, and 4096 is not a multiple of these sets' 192 bytes) is not recognised as a directory.
#[test]
fn a_deleted_directory_on_the_bsd_fuse_exfat_volume_is_recovered_in_part_and_says_so() {
    use sha2::{Digest, Sha256};
    let Some(dir) = corpus::dir("SEANCE_BSD_FAT_DIR") else {
        return;
    };
    let Some(out) = run("exfatc4-clean.img") else {
        return;
    };
    assert_eq!(under(&out, "DirC"), created("exfatc4", "DirC"));
    assert!(dir_record(&out, "DirC").unwrap()["directory_parse_incomplete"].is_null());
    let names = every_name(&out);
    for d in ["DirA", "DirD"] {
        let (got, want) = (under(&out, d), created("exfatc4", d));
        assert!(
            !got.is_empty() && got.is_subset(&want) && got.len() < want.len(),
            "{d}: {} of {}",
            got.len(),
            want.len()
        );
        let rec = dir_record(&out, d).unwrap_or_else(|| panic!("no record for {d}"));
        assert_eq!(rec["deleted"], json!(true), "{d}");
        assert_eq!(rec["directory_parse_incomplete"], json!(true), "{d}: {rec}");
        assert_eq!(rec["directory_clusters_read"], json!(1), "{d}");
        assert!(
            want.intersection(&names).count() > got.len(),
            "{d}: the orphan scan finds nothing beyond the first cluster"
        );
    }
    let mut img = std::fs::File::open(dir.join("exfatc4-clean.img")).unwrap();
    let mut checked = 0;
    for d in ["DirA", "DirC", "DirD"] {
        let text = std::fs::read_to_string(dir.join(format!("exfatc4.{d}.sha256.txt"))).unwrap();
        for line in text.lines() {
            let (hash, name) = line.split_once(' ').unwrap();
            for a in out.iter().filter(|a| {
                a.metadata["name"] == json!(name.trim()) && a.metadata["deleted"] == json!(true)
            }) {
                let got: String = Sha256::digest(content_of(&mut img, a))
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert_eq!(got, hash, "{d}/{name}");
                checked += 1;
            }
        }
    }
    assert!(checked >= 20 + 21 + 21, "{checked} files read back");
}

/// After `Keep` was written to the exFAT volume nothing is invented and a short listing says so.
#[test]
fn after_new_files_were_written_to_the_bsd_exfat_volume_nothing_is_invented() {
    let Some(out) = run("exfatc4.img") else {
        return;
    };
    for d in ["DirA", "DirC", "DirD"] {
        let (got, want) = (under(&out, d), created("exfatc4", d));
        assert!(
            got.is_subset(&want),
            "{d}: invented {:?}",
            got.difference(&want).collect::<Vec<_>>()
        );
        if got.len() < want.len() {
            if let Some(rec) = dir_record(&out, d) {
                assert_eq!(
                    rec["directory_parse_incomplete"],
                    json!(true),
                    "{d}: short and silent"
                );
            }
        }
    }
    assert_eq!(under(&out, "DirB"), created("exfatc4", "DirB"));
    let all: BTreeSet<String> = ["DirA", "DirB", "DirC", "DirD"]
        .iter()
        .flat_map(|d| created("exfatc4", d))
        .collect();
    let invented: Vec<String> = every_name(&out)
        .into_iter()
        .filter(|n| n.starts_with("Quarterly") && !n.contains("-Keep-") && !all.contains(n))
        .collect();
    assert!(invented.is_empty(), "{invented:?}");
}
