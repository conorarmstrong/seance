//! DFTT #12 (Basic Data Carving Test #2): ext2 indirect-block carving.
//!
//! This image is an ext2 volume with an intentionally CORRUPTED superblock, so
//! it cannot be mounted and files must be recovered by carving alone. Its whole
//! point is to test *indirect-block detection*: ext2 interleaves indirect block
//! pointers between file-content blocks, so a signature-only carver that copies
//! a contiguous header..footer run includes the indirect block and produces a
//! file that is the right size but byte-wrong.
//!
//! Since 2026-09-26 the carver rebuilds a carve that runs across in-line ext2
//! pointer blocks (`seance_carving::ext2_indirect`), verifying every pointer
//! entry before leaving a block out. This test grades that against the image's
//! published answer key (`12-carve-ext2.html`, MD5 per file).

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_carver::FileCarver;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

fn resolve(relative: &str) -> std::path::PathBuf {
    let root = std::env::current_dir().unwrap();
    if root.ends_with("seance_tests") {
        root.parent().unwrap().join(relative)
    } else {
        root.join(relative)
    }
}

// Ground-truth md5s of the correctly-reconstructed files, from the DFTT #12
// answer key (12-carve-ext2.html). main_dive.jpg is stored contiguously (17
// blocks, no IND); every other file has an IND block in line after its 12th
// block, and n_lin_ss.pdf also a DIND with two INDs under it.
const MAIN_DIVE_JPG_MD5: &str = "937846adb96773ee25fcb34821230976";
const HAXOR2_BMP_MD5: &str = "f9633fe6b9ef2a0a5edd6de70d22c0f5";

/// (name, md5, size) for every file the answer key lists.
const DFTT12_KEY: &[(&str, &str, u64)] = &[
    ("haxor2.bmp", HAXOR2_BMP_MD5, 163878),
    ("jimmy.doc", "2f3f914dd74819df42d1d941c7275c16", 12800),
    ("jn.jpg", "270a0a913fa9603db8121fdf78d63aca", 28949),
    ("lin_test.pdf", "1c64456776075d1f0a662e1f6c09e340", 26618),
    ("main_dive.jpg", MAIN_DIVE_JPG_MD5, 8463),
    ("n_lin_ss.pdf", "97be95ed3e710b63bc75e5c0775062d9", 734652),
    ("blogo.gif", "5e10b2176016885a85bffc074a142524", 18663),
    ("sherry.jpg", "3834e72d2ee266ccfb9733d716b89f2b", 133249),
    ("stats.xls", "6351df9c1543c41c3df8eea63e06a219", 15360),
    ("test.ppt", "99941c129cc8cfbadc15c55086982efc", 17408),
];

/// Measured 2026-09-26: every file in the key carves byte-exact. main_dive.jpg
/// needs no rebuild; the other nine are rebuilt without their in-line pointer
/// blocks. Six of them also needed a carving fix to reach their true end:
/// blogo.gif (a `0x3B` in image data is not the trailer), lin_test.pdf (a
/// linearized file's first `%%EOF` is not its end), sherry.jpg (an Exif
/// thumbnail's EOI is not the image's), n_lin_ss.pdf (a `0x95` byte in its
/// content no longer passes for an OpenPGP key and cuts it), and
/// stats.xls/test.ppt (the compound file is sized through the layout, not
/// through the IND block).
fn carve_dftt12() -> Option<Vec<Artifact>> {
    let img = resolve("test_data/dftt/12-carve-ext2/12-carve-ext2/12-carve-ext2.dd");
    if !img.exists() {
        println!(
            "Skipping: DFTT #12 ext2 carving image not present at {}",
            img.display()
        );
        return None;
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    // UnallocatedSpace makes region_carve treat the whole image as one carve region.
    let region = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(ds),
        json!({ "name": "dftt12", "offset_bytes": 0 }),
    );
    Some(
        FileCarver::new()
            .process(&region)
            .expect("carve")
            .into_iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect(),
    )
}

#[test]
fn dftt12_ext2_indirect_block_carving_against_the_answer_key() {
    let Some(files) = carve_dftt12() else { return };
    assert!(!files.is_empty(), "carver recovered nothing from DFTT #12");

    let carved: Vec<(&str, u64, &str, Option<&str>)> = files
        .iter()
        .map(|a| {
            let m = &a.metadata;
            (
                m["carving_signature"].as_str().unwrap_or(""),
                m["carving_offset"].as_u64().unwrap_or(0),
                m["md5"].as_str().unwrap_or(""),
                m.get("carving_reconstruction").and_then(|v| v.as_str()),
            )
        })
        .collect();

    let mut missed = Vec::new();
    for (name, md5, size) in DFTT12_KEY {
        match carved.iter().find(|c| c.2 == *md5) {
            None => missed.push(*name),
            Some((sig, offset, _, recon)) => {
                let entry = files
                    .iter()
                    .find(|a| a.metadata["md5"].as_str() == Some(md5))
                    .unwrap();
                let validated = entry.metadata.get("carving_validated");
                println!(
                    "{name}: {sig} at sector {} {recon:?} validated={validated:?}",
                    offset / 512
                );
                // Every file here ends where the key says; a flag of `false`
                // would describe an end the published file does not have.
                assert_ne!(
                    validated,
                    Some(&serde_json::json!(false)),
                    "{name} matches the key byte-exact but is published as not validated"
                );
                assert_eq!(entry.metadata["size"].as_u64(), Some(*size), "{name}");
                // A file past 12 blocks at 1 KiB has an IND in line and must
                // have been rebuilt without it; main_dive.jpg (17 sectors)
                // must not have been touched.
                let expect_rebuilt = *size > 12 * 1024;
                assert_eq!(recon.is_some(), expect_rebuilt, "{name}");
            }
        }
    }
    assert!(
        missed.is_empty(),
        "DFTT #12 files not carved byte-exact: {missed:?}"
    );
}

/// DFTT #11 (Basic Data Carving Test #1): a FAT32 volume with a corrupted boot
/// sector (carve-only) holding 15 known files of varied formats, several placed
/// immediately adjacent to Office/OLE2 documents. It regression-guards the OLE2
/// sizing fix: OLE2's header can only be estimated to a worst-case length, and
/// an over-carve used to swallow the file that follows it on disk (the overlap
/// dedup then dropped that real file). With FAT-based sizing, doc/xls/ppt carve
/// at their true length and the adjacent ZIP, PDF, and WMV survive.
#[test]
fn dftt11_ole2_sizing_recovers_adjacent_files() {
    let img = resolve("test_data/dftt/11-carve-fat/11-carve-fat/11-carve-fat.dd");
    if !img.exists() {
        println!(
            "Skipping: DFTT #11 FAT carving image not present at {}",
            img.display()
        );
        return;
    }

    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let region = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(ds),
        json!({ "name": "dftt11", "offset_bytes": 0 }),
    );
    let carved = FileCarver::new().process(&region).expect("carve");

    let mut by_ext: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for a in carved
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
    {
        if let Some(name) = a.metadata.get("name").and_then(|v| v.as_str()) {
            let ext = name.rsplit('.').next().unwrap_or("").to_string();
            *by_ext.entry(ext).or_insert(0) += 1;
        }
    }

    // The files that were swallowed by oversized OLE2 carves before the fix.
    assert!(
        by_ext.get("zip").copied().unwrap_or(0) >= 1,
        "wword60t.zip not recovered (OLE2 over-carve regression): {by_ext:?}"
    );
    assert!(
        by_ext.get("pdf").copied().unwrap_or(0) >= 2,
        "expected 2 PDFs (2.pdf, nlin_14.pdf): {by_ext:?}"
    );
    assert!(
        by_ext.get("wmv").copied().unwrap_or(0) >= 2,
        "expected 2 WMVs (surf, domopers): {by_ext:?}"
    );
    // And the OLE2 documents themselves are still recovered.
    for ext in ["doc", "xls", "ppt"] {
        assert!(
            by_ext.get(ext).copied().unwrap_or(0) >= 1,
            "OLE2 {ext} missing: {by_ext:?}"
        );
    }

    let total: usize = by_ext.values().sum();
    assert!(
        total >= 15,
        "expected >=15 carved files matching PhotoRec, got {total}: {by_ext:?}"
    );
    println!("DFTT #11: {total} files carved, OLE2-adjacent zip/pdf/wmv recovered: {by_ext:?}");
}

/// DFTT #11's answer key (`11-carve-fat.html`): name, MD5, size.
const DFTT11_KEY: &[(&str, &str, u64)] = &[
    (
        "2003_document.doc",
        "e72f388b36f9370f19696b164c308482",
        19968,
    ),
    ("enterprise.wav", "7629b89adade055f6783dc1773274215", 318895),
    ("haxor2.jpg", "84e1dceac2eb127fef5bfdcb0eae324b", 24367),
    ("holly.xls", "7917baf0219645afef8b381570c41211", 23040),
    ("lin_1.2.pdf", "e026ec863410725ba1f5765a1874800d", 1399508),
    ("nlin_14.pdf", "5b3e806e8c9c06a475cd45bf821af709", 122434),
    ("paul.jpg", "37a49f97ed279832cd4f7bd002c826a2", 29885),
    ("pumpkin.jpg", "6c9859e5121ff54d5d6298f65f0bf3b3", 444314),
    ("shark.jpg", "d83428b8742a075b57b0dc424cd297c4", 99298),
    ("sm1.gif", "d25fb845e6a41395adaed8bd14db7bf2", 5498),
    ("surf.mov", "5328d2b066f428ea95b2793849ab97fa", 550653),
    ("surf.wmv", "ff085d0c4d0e0fdc8f3427db68e26266", 1036994),
    ("test.ppt", "7b74c2c608d92f4bb76c1d3b6bd1decc", 11264),
    ("wword60t.zip", "c0be59d49b7ee0fdc492d2df32f2c6c6", 78899),
    ("domopers.wmv", "63c0c6986cf0a446cb54b0ac65a921a5", 8037267),
];

/// Which DFTT #11 files carve byte-exact, pinned both ways: a file that
/// starts or stops matching its key fails this test so the list is kept true.
/// Measured 2026-09-26: 12 of 15 (7 before that day's GIF, JPEG, PDF and
/// OpenPGP fixes: paul.jpg, shark.jpg, sm1.gif, lin_1.2.pdf and wword60t.zip
/// were short). Not byte-exact, `CARVE-017`: pumpkin.jpg (its Exif
/// thumbnail's own SOI sits on a block boundary 1,024 bytes in and cuts it)
/// and enterprise.wav (one byte short, 318,894 of 318,895).
/// Measured 2026-10-22: 13 of 15. surf.mov, 550,912 against 550,653 on the day
/// above, now carves to the key's MD5 (550,653 bytes). The change that moved
/// it was found while running the full gate after the register merges and was
/// not attributed to one commit; the MD5 is the independent answer key's.
const DFTT11_BYTE_EXACT: &[&str] = &[
    "2003_document.doc",
    "haxor2.jpg",
    "holly.xls",
    "lin_1.2.pdf",
    "nlin_14.pdf",
    "paul.jpg",
    "shark.jpg",
    "sm1.gif",
    "surf.mov",
    "surf.wmv",
    "test.ppt",
    "wword60t.zip",
    "domopers.wmv",
];

#[test]
fn dftt11_byte_exact_files_against_the_answer_key() {
    let img = resolve("test_data/dftt/11-carve-fat/11-carve-fat/11-carve-fat.dd");
    if !img.exists() {
        println!("Skipping: DFTT #11 image not present at {}", img.display());
        return;
    }
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let region = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(ds),
        json!({ "name": "dftt11", "offset_bytes": 0 }),
    );
    let carved = FileCarver::new().process(&region).expect("carve");
    let md5s: Vec<&str> = carved
        .iter()
        .filter_map(|a| a.metadata.get("md5").and_then(|v| v.as_str()))
        .collect();
    let exact: Vec<&str> = DFTT11_KEY
        .iter()
        .filter(|(_, md5, _)| md5s.contains(md5))
        .map(|(name, _, _)| *name)
        .collect();
    println!(
        "DFTT #11 byte-exact {}/{}: {exact:?}",
        exact.len(),
        DFTT11_KEY.len()
    );
    assert_eq!(exact, DFTT11_BYTE_EXACT);
}
