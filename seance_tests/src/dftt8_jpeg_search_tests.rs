//! DFTT #8 (JPEG Search Test #1): which of the image's JPEGs the ingest finds.
//!
//! An NTFS volume holding ten JPEG pictures placed to test a "find all
//! pictures" search: allocated with and without a JPEG extension, deleted with
//! and without one, inside a ZIP, inside a ZIP named `.boo`, inside a
//! `.tar.gz`, appended to 1,572 bytes of random data, embedded in a Word
//! document, and in an alternate data stream — plus three files that are not
//! JPEGs and must not be reported as ones. The answer key (`index.html`, by
//! Brian Carrier, 2004) gives an MD5 per picture.
//!
//! The test drives the product's own module set (`build_module_set`), with
//! the orchestrator's dispatch rule — every automatic module subscribed to an
//! artifact's type processes it, and what it produces is dispatched in turn —
//! from a `RawEvidence` of the image. It then hashes every file-like artifact
//! that carries data and grades the key's MD5s against them. What is found is
//! pinned both ways, so a picture that starts or stops being found fails the
//! test and the list is corrected rather than left stale.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource, SourceCursor};
use seance_core::hashing::compute_hashes_streaming_with_progress;
use seance_core::module::{ExecutionMode, ForensicsModule};
use seance_core::orchestrator::Orchestrator;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) fn resolve(relative: &str) -> std::path::PathBuf {
    let root = std::env::current_dir().unwrap();
    if root.ends_with("seance_tests") {
        root.parent().unwrap().join(relative)
    } else {
        root.join(relative)
    }
}

/// The key's pictures, by the number the key gives them: (name, MD5).
/// `file11.dat` and `file12.doc` are keyed by the MD5 of the container only;
/// they are graded separately below.
const DFTT8_PICTURES: &[(&str, &str)] = &[
    ("1 alloc/file1.jpg", "75b8d00568815a36c3809b46fc84ba6d"),
    ("2 alloc/file2.dat", "de5d83153339931371719f4e5c924eba"),
    ("6 del1/file6.jpg", "afd55222024a4e22f7f5a3a665320763"),
    ("7 del2/file7.hmm", "0c452c5800fcfa7c66027ae89c4f068a"),
    (
        "8 archive/file8.zip:file8.jpg",
        "f9956284a89156ef6967b49eced9d1b1",
    ),
    (
        "9 archive/file9.boo:file9.jpg",
        "c5a6917669c77d20f30ecb39d389eb7d",
    ),
    (
        "10 archive/file10.tar.gz:file10.jpg",
        "c476a66ccdc2796b4f6f8e27273dd788",
    ),
    (
        "13 misc/file13.dll:here",
        "9b787e63e3b64562730c5aecaab1e1f8",
    ),
];

/// Measured 2026-09-26: all eight keyed pictures are found, each by its MD5 —
/// the allocated and deleted files by the NTFS walk (and again by carving
/// where they lie on sector boundaries), the ZIP, `.boo` and `.tar.gz` members
/// by the container modules, and the ADS by the MFT walk.
const DFTT8_FOUND: &[&str] = &[
    "1 alloc/file1.jpg",
    "2 alloc/file2.dat",
    "6 del1/file6.jpg",
    "7 del2/file7.hmm",
    "8 archive/file8.zip:file8.jpg",
    "9 archive/file9.boo:file9.jpg",
    "10 archive/file10.tar.gz:file10.jpg",
    "13 misc/file13.dll:here",
];

/// The two pictures the key names by their container: (name, container MD5).
const DFTT8_EMBEDDED: &[(&str, &str)] = &[
    ("11 misc/file11.dat", "f407ab92da959c7ab03292cfe596a99d"),
    ("12 misc/file12.doc", "61c0b55639e52d1ce82aba834ada2bab"),
];

/// Measured 2026-09-26: neither embedded picture is found (see the test).
const DFTT8_EMBEDDED_FOUND: &[&str] = &[];

/// The three decoys: (name, MD5 of the file itself).
const DFTT8_NOT_JPEGS: &[(&str, &str)] = &[
    ("3 invalid/file3.jpg", "1ba4e91591f0541eda255ee26f7533bc"),
    ("4 invalid/file4.jpg", "c8de721102617158e8492121bdad3711"),
    ("5 invalid/file5.rtf", "86f14fc525648c39d878829f288c0543"),
];

/// Every module that returned an error rather than looking, as `"module on
/// ArtifactType"`, sorted. Pinned so a change in what is found cannot hide
/// behind a module that stopped looking (measured 2026-09-27).
///
/// The iOS backup parser subscribes to every `FileEntry` and `RawEvidence` but
/// needs a host `path`, and returns an error for each artifact without one
/// (carved files, container members, the image itself). It cannot find a
/// JPEG, so this does not bear on the pictures below; it is pinned so that
/// any other module starting to fail here is seen.
const DFTT8_MODULE_ERRORS: &[&str] = &[
    "plugin.mobile.ios_backup on FileEntry",
    "plugin.mobile.ios_backup on RawEvidence",
];

/// Every artifact the module set produces from `root`, dispatched the way the
/// orchestrator dispatches an unprofiled case, and every module error as
/// `"module on ArtifactType"` (sorted, deduplicated).
pub(crate) fn ingest(root: Artifact) -> (Vec<Artifact>, Vec<String>) {
    let dir = std::env::temp_dir().join(format!("seance-dftt8-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let search = Arc::new(seance_search::SearchService::new(&dir).expect("search service"));
    let orchestrator = Orchestrator::new(None, 10);
    let modules = seance_api::modules::build_module_set(
        &orchestrator,
        seance_api::modules::ModuleSetOptions {
            search_service: search,
            carver_defs: None,
            unlock: Default::default(),
            yara_rules: None,
            memory_regex: None,
            memory_strings: None,
        },
    )
    .expect("module set builds");
    let mut by_type: HashMap<ArtifactType, Vec<Arc<dyn ForensicsModule>>> = HashMap::new();
    for m in modules {
        if m.execution_mode() == ExecutionMode::Automatic {
            for t in m.subscribes_to() {
                by_type.entry(t).or_default().push(m.clone());
            }
        }
    }

    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut queue = VecDeque::from([root]);
    while let Some(a) = queue.pop_front() {
        assert!(out.len() < 200_000, "runaway ingest");
        for m in by_type.get(&a.artifact_type).into_iter().flatten() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| m.process(&a)));
            match result {
                Ok(Ok(produced)) => queue.extend(produced),
                Ok(Err(e)) => {
                    println!("{} on {:?}: {e}", m.id(), a.artifact_type);
                    errors.push(format!("{} on {:?}", m.id(), a.artifact_type));
                }
                Err(_) => panic!("{} panicked on {:?}", m.id(), a.artifact_type),
            }
        }
        out.push(a);
    }
    let _ = std::fs::remove_dir_all(&dir);
    errors.sort();
    errors.dedup();
    (out, errors)
}

pub(crate) fn md5_of(ds: &Arc<dyn DataSource>) -> Option<String> {
    if ds.size() > 64 * 1024 * 1024 {
        return None;
    }
    let mut done = 0u64;
    let h = compute_hashes_streaming_with_progress(
        &mut SourceCursor::new(ds.clone()),
        1024 * 1024,
        |d| done = d,
    )
    .ok()?;
    (done == ds.size()).then_some(h.md5)
}

pub(crate) fn label(a: &Artifact) -> String {
    let m = &a.metadata;
    let s = |k: &str| m.get(k).and_then(|v| v.as_str()).unwrap_or("");
    format!(
        "{:?} {} {} offset={:?} deleted={:?}",
        a.artifact_type,
        s("path"),
        s("name"),
        m.get("carving_offset"),
        m.get("deleted")
    )
}

#[test]
fn dftt8_jpeg_search_against_the_answer_key() {
    let img = resolve("test_data/dftt/8-jpeg-search/8-jpeg-search/8-jpeg-search.dd");
    if !img.exists() {
        println!("Skipping: DFTT #8 image not present at {}", img.display());
        return;
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img.clone()).expect("open"));
    assert_eq!(
        md5_of(&ds).as_deref(),
        Some("9bdb9c76b80e90d155806a1fc7846db5"),
        "not the published DFTT #8 image"
    );
    let root = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds),
        json!({ "name": "8-jpeg-search.dd", "source_path": img.to_string_lossy() }),
    );
    let (all, module_errors) = ingest(root);
    assert_eq!(
        module_errors, DFTT8_MODULE_ERRORS,
        "the set of modules that failed to look changed"
    );

    // Every artifact with data of its own (not the image, not a volume).
    let mut hashed: Vec<(String, String, &Artifact)> = Vec::new();
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
            hashed.push((md5, label(a), a));
        }
    }
    let with_md5 = |md5: &str| -> Vec<&Artifact> {
        hashed
            .iter()
            .filter(|(m, _, _)| m == md5)
            .map(|(_, _, a)| *a)
            .collect()
    };

    let mut found = Vec::new();
    for (name, md5) in DFTT8_PICTURES {
        let hits = with_md5(md5);
        println!(
            "{name}: {:?}",
            hits.iter().map(|a| label(a)).collect::<Vec<_>>()
        );
        if !hits.is_empty() {
            found.push(*name);
        }
    }
    println!(
        "DFTT #8 keyed pictures found {}/{}: {found:?}",
        found.len(),
        DFTT8_PICTURES.len()
    );
    assert_eq!(found, DFTT8_FOUND, "the set of pictures found changed");

    // Where carved JPEGs start in the image, and where a file's byte lies.
    let carve_starts: Vec<u64> = all
        .iter()
        .filter(|a| a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("JPEG"))
        .filter_map(|c| {
            c.metadata
                .get("carving_offset_absolute")
                .and_then(|v| v.as_u64())
        })
        .collect();
    let disk_offset = |file: &Artifact, byte: u64| -> u64 {
        // `data_runs` are relative to the file system window, which on this
        // partition image starts at byte 0 of the image.
        let fs = all
            .iter()
            .find(|p| Some(p.id) == file.parent_id)
            .expect("the file's parent");
        let fs_at = fs
            .metadata
            .get("offset_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let mut left = byte;
        for run in file.metadata["data_runs"].as_array().expect("data_runs") {
            let (off, len) = (
                run[0].as_u64().expect("allocated"),
                run[1].as_u64().unwrap(),
            );
            if left < len {
                return fs_at + off + left;
            }
            left -= len;
        }
        panic!("byte {byte} is past the file's runs")
    };
    let read_all = |a: &Artifact| -> Vec<u8> {
        let d = a.data.as_ref().expect("data");
        let mut buf = vec![0u8; d.size() as usize];
        let n = d.read_at(0, &mut buf).expect("read");
        buf.truncate(n);
        buf
    };
    let listed = |md5: &str| -> &Artifact {
        with_md5(md5)
            .into_iter()
            .find(|a| a.metadata.get("carved").is_none() && a.metadata.get("data_runs").is_some())
            .unwrap_or_else(|| panic!("no listed file has MD5 {md5}"))
    };

    // The two embedded pictures, keyed by their container only. Each
    // container is listed by the NTFS walk. The picture inside it counts as
    // found when a JPEG carve starts where the picture starts on disk (their
    // heads cannot be matched instead: both are copies of pictures the image
    // holds elsewhere, which are carved). Neither is found: the carver looks
    // for a header only at a 512-byte boundary, and file11's picture starts 36
    // bytes past one (1,572 bytes into the file), file12's 329 bytes past one.
    // A stated limit, kept by the owner's 2026-09-26 decision.
    let mut embedded_found = Vec::new();
    for (name, container_md5) in DFTT8_EMBEDDED {
        let file = listed(container_md5);
        let body = read_all(file);
        let at = body
            .windows(4)
            .position(|w| w == [0xFF, 0xD8, 0xFF, 0xE0])
            .expect("the container holds a JPEG") as u64;
        let picture_at = disk_offset(file, at);
        let carved = carve_starts.contains(&picture_at);
        println!(
            "{name}: picture at byte {at} of the file, disk offset {picture_at} ({} past a \
             sector boundary); carved: {carved}",
            picture_at % 512
        );
        if carved {
            embedded_found.push(*name);
        }
    }
    assert_eq!(
        embedded_found, DFTT8_EMBEDDED_FOUND,
        "embedded pictures found changed"
    );

    // The decoys are listed as files (they are files) and never carved as
    // JPEGs: no JPEG carve has a decoy's MD5 or starts where a decoy starts.
    for (name, md5) in DFTT8_NOT_JPEGS {
        let decoy = listed(md5);
        let by_md5 = with_md5(md5)
            .iter()
            .filter(|a| {
                a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("JPEG")
            })
            .count();
        let start = disk_offset(decoy, 0);
        let by_position = carve_starts.contains(&start);
        println!(
            "{name} (decoy) at {start}: {by_md5} JPEG carve(s) by MD5, carved there: {by_position}"
        );
        assert_eq!(
            (by_md5, by_position),
            (0, false),
            "{name} was carved as a JPEG"
        );
    }
}
