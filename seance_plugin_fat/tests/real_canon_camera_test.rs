//! What the FAT parser makes of the volume of a Canon PowerShot SD800IS SD card, at six points of its life
//! (`HUNT-278`, camera firmware).
//!
//! # Evidence
//!
//! `SEANCE_CANON2_DIR` names `forensic_corpora/lab_camera_canon2/`: the six generations of the Digital Corpora
//! `nps-2009-canon2` set (E01 images of a 31 MB card, each raw image's SHA-1 equal to the one the set's
//! `narrative.txt` publishes), as the volumes alone (`canon2-gen<N>.img`, the partition from sector 51: FAT12, the
//! narrative says FAT32). The card was shot in the camera, the photos erased in the camera and the card imaged, six
//! times over (`narrative.txt`; `files-gen6.zip` holds the JPEGs). The answer key is independent of this crate:
//! `canon2.tsk.tsv`, The Sleuth Kit's `fls -r` of each generation (live and deleted entries with their inode) and
//! the size and SHA-256 of each file's bytes by `icat`.
//!
//! The tests skip when the variable is unset.

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use seance_plugin_fat::FatParser;
use serde_json::json;

fn run(gen: u32) -> Option<Vec<Artifact>> {
    let dir = corpus::dir("SEANCE_CANON2_DIR")?;
    let image = format!("canon2-gen{gen}.img");
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(dir.join(&image)).unwrap());
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::Partition,
        Some(src),
        json!({ "name": image }),
    );
    Some(FatParser.process(&fs).expect("the volume parses"))
}

/// `(generation, deleted, path) -> (size, sha256)` from The Sleuth Kit.
fn key() -> BTreeMap<(u32, bool, String), (u64, String)> {
    let dir = corpus::dir("SEANCE_CANON2_DIR").unwrap();
    std::fs::read_to_string(dir.join("canon2.tsk.tsv"))
        .unwrap()
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (
                (f[0].parse().unwrap(), f[1] == "D", format!("/{}", f[2])),
                (f[3].parse().unwrap(), f[4].to_string()),
            )
        })
        .collect()
}

fn files(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter(|a| a.metadata["is_directory"] != json!(true))
        .filter(|a| {
            a.metadata["path"]
                .as_str()
                .is_some_and(|p| p.starts_with("/DCIM/"))
        })
        .collect()
}

/// Every file the camera left, live or erased, is listed once, as live or deleted, exactly as The Sleuth Kit lists it.
#[test]
fn the_files_of_every_generation_are_listed_as_the_sleuth_kit_lists_them() {
    if run(1).is_none() {
        return;
    }
    let key = key();
    for gen in 1..=6 {
        let out = run(gen).unwrap();
        let got: Vec<(bool, String)> = {
            let mut v: Vec<_> = files(&out)
                .iter()
                .map(|a| {
                    (
                        a.metadata["deleted"] == json!(true),
                        a.metadata["path"].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            v.sort();
            v
        };
        let want: Vec<(bool, String)> = {
            let mut v: Vec<_> = key
                .keys()
                .filter(|(g, _, _)| *g == gen)
                .map(|(_, d, p)| (*d, p.clone()))
                .collect();
            v.sort();
            v
        };
        assert_eq!(got, want, "generation {gen}");
    }
}

fn bytes_of(img: &mut std::fs::File, a: &Artifact) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let size = a.metadata["size"].as_u64().unwrap() as usize;
    let mut out = Vec::new();
    for run in a.metadata["data_runs"].as_array().unwrap() {
        let (off, len) = (run[0].as_u64().unwrap(), run[1].as_u64().unwrap() as usize);
        let mut buf = vec![0u8; len];
        img.seek(SeekFrom::Start(off)).unwrap();
        img.read_exact(&mut buf).unwrap();
        out.extend(buf);
    }
    out.truncate(size);
    out
}

fn sha(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// Every live file of every generation reads back byte for byte as The Sleuth Kit reads it. Every erased file is
/// flagged incomplete (read on the contiguity assumption, or short of the size: the camera frees the chain and
/// later photos reuse the clusters),
/// and the product recovers exactly the photos The Sleuth Kit recovers, where "recovered" means equal to the
/// photo's bytes as a generation that still held it live: 7 of the 26 erased files (a fragmented or overwritten
/// photo is not recoverable from a freed chain by either, and the product says so on every one).
#[test]
fn live_files_read_as_the_sleuth_kit_reads_them_and_erased_ones_are_flagged_and_recovered_no_worse()
{
    let Some(dir) = corpus::dir("SEANCE_CANON2_DIR") else {
        return;
    };
    let key = key();
    // The photo's bytes: its live copy in whichever generation held it live.
    let mut truth: BTreeMap<String, String> = BTreeMap::new();
    for ((_, deleted, path), (_, h)) in &key {
        if !deleted {
            truth.insert(path.rsplit('/').next().unwrap().to_string(), h.clone());
        }
    }
    let (mut erased, mut ours_exact) = (0, 0);
    for gen in 1..=6 {
        let out = run(gen).unwrap();
        let mut img = std::fs::File::open(dir.join(format!("canon2-gen{gen}.img"))).unwrap();
        for a in files(&out) {
            let path = a.metadata["path"].as_str().unwrap().to_string();
            let deleted = a.metadata["deleted"] == json!(true);
            let got = sha(&bytes_of(&mut img, a));
            let (_, tsk) = &key[&(gen, deleted, path.clone())];
            if !deleted {
                assert_eq!(&got, tsk, "generation {gen}: live {path}");
                continue;
            }
            erased += 1;
            assert_eq!(
                a.metadata["content_incomplete"],
                json!(true),
                "gen {gen} {path}"
            );
            assert!(
                [
                    "deleted_contiguous_assumed",
                    "deleted_clusters_assumed_in_order",
                    "deleted_reconstruction_short",
                ]
                .iter()
                .any(|r| a.metadata["content_incomplete_reason"] == json!(r)),
                "gen {gen} {path}: {}",
                a.metadata["content_incomplete_reason"]
            );
            // `_MG_0025.JPG` is `IMG_0025.JPG` with its first character erased.
            let name = format!("IMG{}", &path.rsplit('/').next().unwrap()[3..]);
            let want = truth.get(&name);
            assert_eq!(
                want == Some(&got),
                want == Some(tsk),
                "gen {gen} {path}: the product and The Sleuth Kit differ in whether they recovered the photo"
            );
            if want == Some(&got) {
                ours_exact += 1;
            }
        }
    }
    assert_eq!(erased, 26);
    eprintln!("EXACT {ours_exact}");
    assert_eq!(ours_exact, 7);
}
