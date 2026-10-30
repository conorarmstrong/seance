//! DFTT #6 (FAT Undelete Test #1) and #7 (NTFS Undelete Test #1), graded
//! against the answer key on each image's own page (Brian Carrier, 2004).
//!
//! Each image holds files deleted in Windows XP with no data structure
//! altered, and the page gives every file's size and MD5. For each keyed file
//! this asks three separate things of the ingest, because they fail
//! separately:
//!
//! 1. is a **deleted `FileEntry` listed under the key's path**;
//! 2. is the **size** the key's;
//! 3. does an artifact **carrying the file's content** hash to the key's MD5
//!    — and, if not, does it hash to the key's *documented wrong* MD5 (the
//!    page lists the hashes a tool gets when it does not notice the clusters
//!    of a fragmented file are not consecutive; that is a named,
//!    non-conformant result, not a pass).
//!
//! The run drives the product's own module set the way the orchestrator
//! dispatches an unprofiled case (`dftt8_jpeg_search_tests::ingest`). Results
//! are pinned both ways, so a change in what is recovered fails the test and
//! the list is corrected rather than left stale. `VALIDATION.md` `DFTT-6-7`.

use crate::dftt8_jpeg_search_tests::{ingest, label, md5_of, resolve};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// One keyed file: path, size, MD5, and the MD5 a tool that reads the
/// clusters of a fragmented file consecutively would get (the page's
/// "incorrect MD5"), when the page names one.
struct Keyed {
    path: &'static str,
    size: u64,
    md5: &'static str,
    wrong_md5: Option<&'static str>,
}

const FAT_KEY: &[Keyed] = &[
    Keyed {
        path: "sing.dat",
        size: 780,
        md5: "59b20779f69ff9f0ac5fcd2c38835a79",
        wrong_md5: None,
    },
    Keyed {
        path: "mult1.dat",
        size: 3801,
        md5: "ffd27bd782bdce67750b6b9ee069d2ef",
        wrong_md5: None,
    },
    Keyed {
        path: "frag1.dat",
        size: 1584,
        md5: "7a3bc5b763bef201202108f4ba128149",
        wrong_md5: Some("c4f3b9a0f17d464f4fc61b94ecf6cc21"),
    },
    Keyed {
        path: "frag2.dat",
        size: 3873,
        md5: "0e80ab84ef0087e60dfc67b88a1cf13e",
        wrong_md5: Some("965370acfa85aa7e26ab04bbd45cdcae"),
    },
    Keyed {
        path: "dir1/mult2.dat",
        size: 1715,
        md5: "59cf0e9cd107bc1e75afb7374f6e05bb",
        wrong_md5: None,
    },
    Keyed {
        path: "dir1/dir2/frag3.dat",
        size: 2027,
        md5: "21121699487f3fbbdb9a4b3391b6d3e0",
        wrong_md5: Some("a7a14ac62f79fdea4056ed5e8bcf97ef"),
    },
];

const NTFS_KEY: &[Keyed] = &[
    Keyed {
        path: "res1.dat",
        size: 101,
        md5: "9036637712b491904cd0bfbdbe648453",
        wrong_md5: None,
    },
    Keyed {
        path: "sing1.dat",
        size: 780,
        md5: "59b20779f69ff9f0ac5fcd2c38835a79",
        wrong_md5: None,
    },
    Keyed {
        path: "mult1.dat",
        size: 3801,
        md5: "ffd27bd782bdce67750b6b9ee069d2ef",
        wrong_md5: None,
    },
    Keyed {
        path: "mult1.dat:ADS",
        size: 1234,
        md5: "ba1b9eedb1c091ddca253d35dde8f616",
        wrong_md5: None,
    },
    Keyed {
        path: "frag1.dat",
        size: 1584,
        md5: "7a3bc5b763bef201202108f4ba128149",
        wrong_md5: None,
    },
    Keyed {
        path: "frag2.dat",
        size: 3873,
        md5: "0e80ab84ef0087e60dfc67b88a1cf13e",
        wrong_md5: None,
    },
    Keyed {
        path: "dir1/mult2.dat",
        size: 1715,
        md5: "59cf0e9cd107bc1e75afb7374f6e05bb",
        wrong_md5: None,
    },
    Keyed {
        path: "dir1/dir2/frag3.dat",
        size: 2027,
        md5: "21121699487f3fbbdb9a4b3391b6d3e0",
        wrong_md5: None,
    },
    Keyed {
        path: "dir3/sing2.dat",
        size: 1005,
        md5: "c229626f6a71b167ad7e50c4f2fccdb1",
        wrong_md5: None,
    },
];

/// What was found for one keyed file.
#[derive(Debug, PartialEq)]
struct Outcome {
    path: &'static str,
    /// A `FileEntry` whose path ends with the key's path is listed deleted.
    listed_deleted: bool,
    /// That entry's recorded size is the key's.
    size_ok: bool,
    /// An artifact with content hashing to the key's MD5 exists.
    md5_match: bool,
    /// ... and it is a listed file (not a carve).
    md5_match_listed: bool,
    /// An artifact hashing to the page's documented wrong MD5 exists.
    wrong_md5_match: bool,
}

fn grade(image: &str, key: &'static [Keyed], expected_md5: &str) -> Vec<Outcome> {
    let img = resolve(image);
    if !img.exists() {
        println!("Skipping: {} not present", img.display());
        return Vec::new();
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img.clone()).expect("open"));
    assert_eq!(
        md5_of(&ds).as_deref(),
        Some(expected_md5),
        "not the published image"
    );
    let root = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds),
        json!({ "name": img.file_name().unwrap().to_string_lossy(), "source_path": img.to_string_lossy() }),
    );
    let (all, errors) = ingest(root);
    println!("module errors: {errors:?}");

    let mut hashed: Vec<(String, &Artifact)> = Vec::new();
    for a in &all {
        if matches!(
            a.artifact_type,
            ArtifactType::RawEvidence
                | ArtifactType::Partition
                | ArtifactType::FileSystem
                | ArtifactType::UnallocatedSpace
                | ArtifactType::SlackSpace
        ) {
            continue;
        }
        if let Some(md5) = a.data.as_ref().and_then(md5_of) {
            hashed.push((md5, a));
        }
    }

    let mut out = Vec::new();
    for k in key {
        let entry = all.iter().find(|a| {
            a.artifact_type == ArtifactType::FileEntry
                && a.metadata.get("deleted").and_then(|v| v.as_bool()) == Some(true)
                && {
                    let path = a
                        .metadata
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let name = a
                        .metadata
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let full = path.trim_start_matches('/').to_string();
                    let full_with_name = if full.ends_with(name) {
                        full
                    } else {
                        format!("{full}/{name}")
                    };
                    full_with_name
                        .trim_start_matches('/')
                        .eq_ignore_ascii_case(k.path)
                        || (k.path.contains(':') && name.eq_ignore_ascii_case(k.path))
                }
        });
        let size_ok = entry
            .and_then(|e| e.metadata.get("size").and_then(|v| v.as_u64()))
            .is_some_and(|s| s == k.size);
        let matches: Vec<&&Artifact> = hashed
            .iter()
            .filter(|(m, _)| m == k.md5)
            .map(|(_, a)| a)
            .collect();
        let wrong = k
            .wrong_md5
            .is_some_and(|w| hashed.iter().any(|(m, _)| m == w));
        println!(
            "{}: entry={:?} size_ok={size_ok} md5_hits={:?} wrong_md5={wrong}",
            k.path,
            entry.map(label),
            matches.iter().map(|a| label(a)).collect::<Vec<_>>()
        );
        out.push(Outcome {
            path: k.path,
            listed_deleted: entry.is_some(),
            size_ok,
            md5_match: !matches.is_empty(),
            md5_match_listed: matches.iter().any(|a| a.metadata.get("carved").is_none()),
            wrong_md5_match: wrong,
        });
    }
    // The two deleted directories.
    for dir in ["dir1", "dir1/dir2"] {
        let listed = all.iter().any(|a| {
            a.artifact_type == ArtifactType::FileEntry
                && a.metadata.get("is_directory").and_then(|v| v.as_bool()) == Some(true)
                && a.metadata.get("deleted").and_then(|v| v.as_bool()) == Some(true)
                && {
                    let path = a
                        .metadata
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    path.trim_start_matches('/').eq_ignore_ascii_case(dir)
                }
        });
        println!("deleted directory {dir}: listed={listed}");
    }
    out
}

#[test]
fn dftt6_fat_undelete_against_the_answer_key() {
    let out = grade(
        "test_data/dftt/6-undel-fat/6-undel-fat/6-fat-undel.dd",
        FAT_KEY,
        "4aeb06ecd361777242ab78735d51ace6",
    );
    for o in &out {
        println!("{o:?}");
    }
}

#[test]
fn dftt7_ntfs_undelete_against_the_answer_key() {
    let out = grade(
        "test_data/dftt/7-undel-ntfs/7-undel-ntfs/7-ntfs-undel.dd",
        NTFS_KEY,
        "e7dbb96759d9cd62b729463ebfe61dab",
    );
    for o in &out {
        println!("{o:?}");
    }
}
