//! What the FAT parser makes of volumes written by NetBSD 11.0's own `msdosfs` driver (`HUNT-278`).
//!
//! # Evidence
//!
//! `SEANCE_BSD_FAT_DIR` names `forensic_corpora/lab_bsd_fat/`, which holds four images (two volumes, each at two
//! points) made on 2026-10-24 inside the official NetBSD 11.0 amd64 live image run under QEMU/KVM, with
//! `newfs_msdos` and `mount_msdos -l` over virtio disks (`make-fat-netbsd.sh`, driven by `nbdisk-netbsd.py`;
//! `what-was-done-netbsd.log` times each step; `<volume>.<Dir>.created.txt` and `.sha256.txt` are the answer
//! keys taken before anything was deleted). The shape is the one of `real_bsd_fat_test.rs`: `DirA` (300
//! long-named files, deleted whole), `DirB` (300, 260 deleted), `DirC` (20, deleted whole) and `DirD` (240 in two
//! bursts around 200 KB of file data, deleted whole). `nfat16c8` is FAT16 and `nfat32c8` FAT32, both with 4 KiB
//! clusters: NetBSD's driver refused to mount a 512-byte-cluster FAT32 volume of 64 MiB (`Invalid argument`).
//!
//! # What the evidence showed
//!
//! * Like OpenBSD's, NetBSD's driver does not zero a deleted directory, frees its FAT chain, and grows a directory
//!   over consecutive clusters, so the contiguity assumption reads a deleted directory whole.
//! * Except where a long name straddles the gap the filler leaves: on the FAT16 volume the head of `DirD`'s file
//!   043 ends one cluster and its tail begins a cluster that is not adjacent. That entry is published, cut, and
//!   flagged `long_name_possibly_truncated`; nothing is shown whole that was not.
//!
//! The tests skip when the variable is unset.

use std::collections::BTreeSet;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use seance_plugin_fat::FatParser;
use serde_json::{json, Value};

const VOLUMES: [&str; 2] = ["nfat16c8", "nfat32c8"];

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

fn files(out: &[Artifact]) -> impl Iterator<Item = &Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
}

fn under(out: &[Artifact], d: &str) -> BTreeSet<String> {
    let prefix = format!("/{d}/");
    files(out)
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

/// Names cut by a cluster boundary: flagged, and each the start of a created name.
fn truncated(out: &[Artifact]) -> Vec<String> {
    files(out)
        .filter(|a| a.metadata["long_name_possibly_truncated"] == json!(true))
        .filter_map(|a| a.metadata["name"].as_str().map(str::to_string))
        .collect()
}

/// A deleted directory is read whole under its own path, on the contiguity assumption it states, wherever a
/// long name was not cut; the directory that was cut says so and the cut name is flagged, not shown whole.
#[test]
fn a_netbsd_deleted_directory_is_read_under_its_own_path_and_a_cut_name_is_flagged() {
    for volume in VOLUMES {
        let Some(out) = run(&format!("{volume}-clean.img")) else {
            return;
        };
        let cut = truncated(&out);
        for d in ["DirA", "DirC", "DirD"] {
            let (got, want) = (under(&out, d), created(volume, d));
            let rec = dir_record(&out, d).unwrap();
            assert_eq!(rec["deleted"], json!(true), "{volume} {d}");
            if got == want {
                assert!(rec["directory_parse_incomplete"].is_null(), "{volume} {d}");
            } else {
                assert!(got.is_subset(&want), "{volume} {d}: invented");
                assert_eq!(
                    rec["directory_parse_incomplete"],
                    json!(true),
                    "{volume} {d}"
                );
            }
            if rec["directory_clusters_read"].as_u64().unwrap_or(1) > 1 {
                assert_eq!(rec["directory_chain_basis"], json!("contiguous_assumed"));
            }
        }
        // Every created name is published whole somewhere, or is the one cut name and says so.
        let all: BTreeSet<String> = files(&out)
            .filter_map(|a| a.metadata["name"].as_str().map(str::to_string))
            .collect();
        for d in ["DirA", "DirC", "DirD"] {
            for name in created(volume, d) {
                if !all.contains(&name) {
                    assert!(
                        cut.iter().any(|c| name.starts_with(c.as_str())),
                        "{volume}: {name} is neither published nor flagged"
                    );
                }
            }
        }
        // DirB: every name, the 40 live and the 260 deleted.
        assert_eq!(
            under(&out, "DirB"),
            created(volume, "DirB"),
            "{volume} DirB"
        );
    }
}

/// Every whole-named deleted file is read back at the runs its record names and hashes to the `sha256` the guest
/// took before it deleted anything.
#[test]
fn recovered_netbsd_files_hash_to_what_the_guest_recorded() {
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
        for a in files(&out) {
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
        let cut = truncated(&out).len();
        assert_eq!(
            checked + cut,
            want.len(),
            "{volume}: files checked plus names cut"
        );
    }
}

/// After `Keep` was written the freed clusters may be taken: nothing is invented, a short listing says so, a
/// deleted entry is published once, and a name that could not be joined is flagged.
#[test]
fn after_new_files_were_written_to_a_netbsd_volume_nothing_is_invented_or_published_twice() {
    for volume in VOLUMES {
        let Some(out) = run(&format!("{volume}.img")) else {
            return;
        };
        let known: BTreeSet<String> = ["DirA", "DirB", "DirC", "DirD"]
            .iter()
            .flat_map(|d| created(volume, d))
            .collect();
        for d in ["DirA", "DirC", "DirD"] {
            let (got, want) = (under(&out, d), created(volume, d));
            assert!(got.is_subset(&want), "{volume} {d}: invented");
            if got.len() < want.len() {
                if let Some(rec) = dir_record(&out, d) {
                    assert_eq!(
                        rec["directory_parse_incomplete"],
                        json!(true),
                        "{volume} {d}"
                    );
                }
            }
        }
        let mut seen = std::collections::BTreeMap::new();
        for a in files(&out)
            .filter(|a| a.metadata["deleted"] == json!(true))
            .filter(|a| a.metadata["is_directory"] != json!(true))
        {
            let name = a.metadata["name"].as_str().unwrap_or("").to_string();
            if name.starts_with("Quarterly") && !known.contains(&name) {
                assert_eq!(
                    a.metadata["long_name_possibly_truncated"],
                    json!(true),
                    "{volume}: {name} is shown whole"
                );
            }
            seen.entry((name, a.metadata["first_cluster"].as_u64()))
                .or_insert_with(Vec::new)
                .push(a.metadata["path"].as_str().unwrap_or("").to_string());
        }
        let twice: Vec<_> = seen.iter().filter(|(_, v)| v.len() > 1).take(3).collect();
        assert!(
            twice.is_empty(),
            "{volume}: published twice, e.g. {twice:?}"
        );
    }
}
