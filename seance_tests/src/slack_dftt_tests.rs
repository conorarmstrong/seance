//! File slack graded against third-party ground truth (HUNT-124).
//!
//! DFTT #2 (FAT) and DFTT #3 (NTFS) are keyword-search images whose
//! `index.html` publishes, for each keyword, the sector and byte offset it was
//! written at and whether it sits in a file, in that file's slack, or across
//! the boundary between the two. That makes them a known answer for the
//! per-file slack regions the $MFT and FAT parsers emit: a region must exist
//! for exactly the file the image's author named, must cover the documented
//! bytes, and must NOT cover the part of a straddling keyword that lies in the
//! file's own content.
//!
//! Offsets below are the published `sector * 512 + offset`, and each was
//! checked against the image bytes before this test was written. Both images
//! are whole volumes (no partition table), so the regions' volume-relative
//! `offset_bytes` are image offsets.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_fat::FatParser;
use seance_plugin_mft::MftParser;
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

fn volume(path: &std::path::Path, meta: serde_json::Value) -> Artifact {
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).unwrap());
    Artifact::new(Uuid::new_v4(), ArtifactType::FileSystem, Some(ds), meta)
}

/// The slack regions whose owner is `name` (case-insensitive: a FAT file with
/// no long-name entry is published under its 8.3 name).
fn slack_of<'a>(out: &'a [Artifact], name: &str) -> Vec<&'a Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .filter(|a| {
            a.metadata["parent_file"]
                .as_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
        .collect()
}

fn span(r: &Artifact) -> (u64, u64) {
    let start = r.metadata["offset_bytes"].as_u64().unwrap();
    (start, start + r.metadata["size_bytes"].as_u64().unwrap())
}

/// Read `len` bytes of the region at the absolute image offset `at`.
fn read_region(r: &Artifact, at: u64, len: usize) -> Vec<u8> {
    let (start, _) = span(r);
    let mut buf = vec![0u8; len];
    let n = r
        .data
        .as_ref()
        .unwrap()
        .read_at(at - start, &mut buf)
        .unwrap();
    buf.truncate(n);
    buf
}

/// DFTT #3: "n-slack" at sector 8062, offset 485 — "Slack space of a
/// non-resident allocated file", file-n-4.dat.
#[test]
fn dftt3_slack_region_covers_documented_offset() {
    let img = resolve("test_data/dftt/3-kwsrch-ntfs/3-kwsrch-ntfs/ntfs-img-kw-1.dd");
    if !img.exists() {
        println!("Skipping: DFTT #3 not present at {}", img.display());
        return;
    }
    let fs = volume(
        &img,
        serde_json::json!({"name": "ntfs", "subtype": "ntfs", "filesystem_type": "NTFS"}),
    );
    let out = MftParser::new().process(&fs).expect("MFT parse");
    let regions = slack_of(&out, "file-n-4.dat");
    assert_eq!(regions.len(), 1, "one slack region for file-n-4.dat");
    let r = regions[0];
    let at = 8062 * 512 + 485;
    let (start, end) = span(r);
    assert!(
        start <= at && at + 7 <= end,
        "n-slack at {at} is outside the region [{start}, {end})"
    );
    assert_eq!(read_region(r, at, 7), b"n-slack");
    assert_eq!(r.parent_id, Some(fs.id));
    // No other file on this volume is credited with those bytes.
    let others = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .filter(|a| {
            let (s, e) = span(a);
            s <= at && at < e
        })
        .count();
    assert_eq!(others, 1);
}

/// DFTT #2: "3slack3" wholly in file4.dat's slack; "1slack1" crossing from a
/// file's content into its slack (see the note on which file below);
/// "2slack2" crossing from file3.dat's slack into the next file.
#[test]
fn dftt2_slack_regions_cover_documented_offsets() {
    let img = resolve("test_data/dftt/2-kwsrch-fat/2-kwsrch-fat/fat-img-kw.dd");
    if !img.exists() {
        println!("Skipping: DFTT #2 not present at {}", img.display());
        return;
    }
    let fs = volume(&img, serde_json::json!({"name": "fat", "subtype": "fat"}));
    let out = FatParser.process(&fs).expect("FAT parse");
    // In slack: the whole keyword inside file4.dat's slack region.
    let at = 277 * 512 + 385;
    let r4 = slack_of(&out, "file4.dat");
    assert_eq!(r4.len(), 1, "one slack region for file4.dat");
    let (s, e) = span(r4[0]);
    assert!(s <= at && at + 7 <= e, "3slack3 at {at} outside [{s}, {e})");
    assert_eq!(read_region(r4[0], at, 7), b"3slack3");

    // Crosses a file into slack: the region starts INSIDE the keyword, at the
    // file's logical end, so the file's own bytes are not in it.
    //
    // The published table names this row "file1.dat and file1.dat slack", but
    // the sector it gives, 272, is file2.dat's cluster by the same table's own
    // row 2 ("SECOND 272 288 file2.dat in file"), and the image agrees:
    // file1.dat is exactly 512 bytes in a 512-byte cluster and has no slack,
    // while file2.dat (400 bytes at 139264) ends at 139664, inside the keyword.
    // Graded against the published sector and offset, with the file those
    // bytes belong to.
    let at = 272 * 512 + 396;
    assert!(
        slack_of(&out, "file1.dat").is_empty(),
        "file1.dat fills its cluster"
    );
    let r1 = slack_of(&out, "file2.dat");
    assert_eq!(r1.len(), 1, "one slack region for file2.dat");
    let (s, _) = span(r1[0]);
    assert!(
        at < s && s < at + 7,
        "file2.dat's slack must begin inside 1slack1 ({at}..{}), began at {s}",
        at + 7
    );
    let tail = &b"1slack1"[(s - at) as usize..];
    assert_eq!(read_region(r1[0], s, tail.len()), tail);

    // Crosses slack into a file: file3.dat's slack region ENDS inside the
    // keyword, at the end of file3.dat's last cluster.
    let at = 274 * 512 + 508;
    let r3 = slack_of(&out, "file3.dat");
    assert_eq!(r3.len(), 1, "one slack region for file3.dat");
    let (s, e) = span(r3[0]);
    assert!(
        at < e && e < at + 7,
        "file3.dat's slack must end inside 2slack2 ({at}..{}), ended at {e}",
        at + 7
    );
    let head = &b"2slack2"[..(e - at) as usize];
    assert!(s <= at);
    assert_eq!(read_region(r3[0], at, head.len()), head);
}
