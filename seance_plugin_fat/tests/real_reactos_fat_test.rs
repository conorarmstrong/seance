//! What the FAT parser makes of volumes written by ReactOS's own FAT driver (`HUNT-278`).
//!
//! # Evidence
//!
//! `SEANCE_BSD_FAT_DIR` names `forensic_corpora/lab_bsd_fat/`, which holds four images (two volumes, each at two
//! points) made on 2026-10-25 inside the official ReactOS 0.4.16 LiveCD (x86) run under QEMU/KVM, formatted with its
//! own `format` and written through its `cmd.exe` by batch files (`guest_reactos/gen_scripts.py` writes
//! `run1a.bat`, `run1b.bat` and `run2.bat`; `what-was-done-reactos.log` is the guest's serial output). The shape is
//! the one of `real_bsd_fat_test.rs`: `DirA` (300 long-named files, deleted whole), `DirB` (300, 260 deleted),
//! `DirC` (20, deleted whole) and `DirD` (240 in two bursts around a 3 MB file, deleted whole). `hreact64` is
//! FAT16 with 2 KiB clusters and `hreact300` FAT32 with 4 KiB. ReactOS has no hashing tool, so the answer keys are
//! made on the host from the known content (`DirX N` and a line end); 40 of 40 surviving `DirB` files on each
//! volume hash to them. The guest was left 90 s between creating and deleting and between deleting and the copy:
//! a first run deleted `DirD` at once, and 112 of its names never reached the disk, because the cache dropped the
//! directory's dirty clusters with the directory.
//!
//! # What the evidence showed
//!
//! * ReactOS's driver leaves a deleted directory's name slots as they were: ordinals and short names are not
//!   marked `0xE5` (only `DirB`'s individually deleted files are), as Haiku's driver's are. It also stores a
//!   non-zero length in a directory's own entry (`DirA`: 59,392 bytes).
//! * It interleaves a directory's clusters with the data of its files, so only the first cluster is led to.
//! * Before the fix of the same commit as `real_haiku_fat_test.rs`, three of these four tests failed: names cut by
//!   a cluster boundary were lost or published shortened with no flag (`DirA` 011, 032, 043 on `hreact64`).
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

const VOLUMES: [&str; 2] = ["hreact64", "hreact300"];

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
/// led to by anything. ReactOS left the ordinals, so every name that straddled a cluster boundary is joined from
/// the cluster before, and none is shown cut.
#[test]
fn every_name_of_a_deleted_reactos_directory_is_recovered_whole_and_none_is_shown_cut() {
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
fn a_reactos_directory_listed_in_part_says_so_and_headless_clusters_say_what_their_path_means() {
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

/// Every whole-named deleted file is read back at the runs its record names and hashes to the SHA-256 of the
/// content the guest was told to write.
#[test]
fn recovered_reactos_files_hash_to_what_the_guest_recorded() {
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
fn after_new_files_were_written_to_a_reactos_volume_nothing_is_invented_or_published_twice() {
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
