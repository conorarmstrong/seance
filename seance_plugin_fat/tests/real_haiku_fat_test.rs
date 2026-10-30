//! What the FAT parser makes of volumes written by Haiku's own FAT driver (`HUNT-278`).
//!
//! # Evidence
//!
//! `SEANCE_BSD_FAT_DIR` names `forensic_corpora/lab_bsd_fat/`, which holds four images (two volumes, each at two
//! points) made on 2026-10-25 inside the official Haiku nightly `hrev60295` x86_64 live image run under QEMU/KVM,
//! with `mkfs -t fat` and `mount -t fat` over SATA disks (`make-fat-haiku.sh`, driven through the QEMU monitor by
//! `guest_haiku/boot.sh`; `what-was-done-haiku.log` times each step; `<volume>.<Dir>.created.txt` and `.sha256.txt`
//! are the answer keys taken before anything was deleted). The shape is the one of `real_bsd_fat_test.rs`: `DirA`
//! (300 long-named files, deleted whole), `DirB` (300, 260 deleted), `DirC` (20, deleted whole) and `DirD` (240 in
//! two bursts around 200 KB of file data, deleted whole). `hfat64` is FAT16 with 2 KiB clusters and `hfat300` FAT16
//! with 8 KiB clusters: Haiku's `mkfs` chose both, and took no option for either.
//!
//! # What the evidence showed
//!
//! * Haiku's driver does not mark a deleted directory's slots. It frees the FAT chain and leaves every name slot
//!   with its ordinal and every short entry with its first byte, where Windows, Linux and the BSDs write `0xE5`.
//!   The parser read a name cut by a cluster boundary as a shorter name and did not flag it (`Quarterly-rep` was a
//!   file); 35 names on `hfat64` and 8 on `hfat300` came back that way. The ordinals say exactly what is missing,
//!   so a cut is now flagged from them, and the head is joined from the cluster before when the ordinals count
//!   down without a gap and the checksum is the one of the short entry's own name.
//! * It interleaves a directory's clusters with the data of its files, as FreeBSD's does, so only the first
//!   cluster is led to by the parent's entry and the rest are headless clusters.
//! * After `Keep` was written, one name per volume has its cluster reused and is published cut and flagged.
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

const VOLUMES: [&str; 2] = ["hfat64", "hfat300"];

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

fn every_name(out: &[Artifact]) -> BTreeSet<String> {
    files(out)
        .filter_map(|a| a.metadata["name"].as_str().map(str::to_string))
        .collect()
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

/// Every name of the three deleted directories comes back whole, though no cluster after a directory's first is
/// led to by anything. Haiku left the ordinals, so every name that straddled a cluster boundary is joined from
/// the cluster before, and none is shown cut.
#[test]
fn every_name_of_a_deleted_haiku_directory_is_recovered_whole_and_none_is_shown_cut() {
    for volume in VOLUMES {
        let Some(out) = run(&format!("{volume}-clean.img")) else {
            return;
        };
        let names = every_name(&out);
        for d in ["DirA", "DirC", "DirD"] {
            let want = created(volume, d);
            let missing: Vec<_> = want.difference(&names).take(3).collect();
            assert!(
                missing.is_empty(),
                "{volume} {d}: not recovered whole, e.g. {missing:?}"
            );
            let got = under(&out, d);
            assert!(!got.is_empty() && got.is_subset(&want), "{volume} {d}");
        }
        assert_eq!(
            under(&out, "DirB"),
            created(volume, "DirB"),
            "{volume} DirB"
        );
        assert!(
            truncated(&out).is_empty(),
            "{volume}: {:?} shown cut",
            truncated(&out)
        );
        assert!(
            files(&out).any(|a| a.metadata["long_name_basis"] == json!("stitched_across_clusters")),
            "{volume}: no name was joined across a cluster boundary"
        );
    }
}

/// A directory listed in part says so, and a headless cluster's path says it names a cluster, not a folder.
#[test]
fn a_haiku_directory_listed_in_part_says_so_and_headless_clusters_say_what_their_path_means() {
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
        for a in files(&out).filter(|a| a.metadata["orphan_directory_headless"] == json!(true)) {
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

/// Every whole-named deleted file is read back at the runs its record names and hashes to the `sha256sum` the
/// guest took before it deleted anything.
#[test]
fn recovered_haiku_files_hash_to_what_the_guest_recorded() {
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
        assert_eq!(checked, want.len(), "{volume}: files checked");
    }
}

/// After `Keep` was written the freed clusters may be taken: nothing is invented, a deleted entry is published
/// once, and a name whose cluster was reused is shown cut only with the flag.
#[test]
fn after_new_files_were_written_to_a_haiku_volume_nothing_is_invented_or_published_twice() {
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
