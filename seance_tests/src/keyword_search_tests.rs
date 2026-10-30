//! Keyword-search validation on real image-derived content.
//!
//! Parses the DFTT #7 NTFS image (real forensic test data with known deleted
//! files), indexes the resulting file artifacts with the real Tantivy search
//! service, and confirms keyword queries return the expected artifacts. This
//! exercises the whole path an examiner uses: image -> parser -> index -> query,
//! rather than only synthetic in-memory artifacts.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_ext4::Ext4Parser;
use seance_plugin_mft::MftParser;
use seance_search::SearchService;
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

#[tokio::test]
async fn keyword_search_finds_files_in_real_ntfs_image() {
    let img = resolve("test_data/dftt/7-undel-ntfs/7-ntfs-undel.dd");
    if !img.exists() {
        println!(
            "Skipping: DFTT #7 NTFS image not present at {}",
            img.display()
        );
        return;
    }

    // Parse the NTFS volume into file artifacts.
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open image"));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        serde_json::json!({
            "name": "ntfs", "subtype": "ntfs",
            "filesystem_type": "NTFS", "type": "FileSystem",
        }),
    );
    let case_id = fs.case_id;
    let artifacts = MftParser::new().process(&fs).expect("MFT parse");
    assert!(
        artifacts.len() > 5,
        "expected several file artifacts, got {}",
        artifacts.len()
    );

    // The image's known files must appear by name (these are the DFTT #7
    // fixtures used to test undelete/recovery).
    let names: Vec<String> = artifacts
        .iter()
        .filter_map(|a| {
            a.metadata
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase())
        })
        .collect();
    for expected in ["sing1.dat", "frag1.dat", "mult1.dat"] {
        assert!(
            names.iter().any(|n| n == expected),
            "expected file {} in parsed names",
            expected
        );
    }

    // Index every artifact in a scratch index, then query.
    let dir = resolve(&format!("target/_kwsearch_idx_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let svc = SearchService::new(&dir).expect("search service");
    for a in &artifacts {
        // Some artifacts (e.g. directories) may not index; that's fine.
        let _ = svc.add_artifact_to_index(a).await;
    }
    svc.commit().await.expect("commit index");

    // Each keyword must resolve to its file. Searching by the base name
    // exercises the tokenised name field on real recovered entries.
    for term in ["sing1", "frag1", "mult1"] {
        let hits = svc.search(case_id, term, 20).await.expect("search");
        assert!(
            hits.iter().any(|h| h.name.to_lowercase().contains(term)),
            "keyword '{}' did not return its file (hits: {:?})",
            term,
            hits.iter().map(|h| &h.name).collect::<Vec<_>>()
        );
    }

    // A term absent from the image must return nothing (no false positives).
    let none = svc
        .search(case_id, "zzz_no_such_keyword_qwerty", 20)
        .await
        .expect("search");
    assert!(none.is_empty(), "unexpected hits for an absent keyword");

    let _ = std::fs::remove_dir_all(&dir);
}

/// DFTT #3 (NTFS Keyword Search Test #1) hides a distinct keyword in the
/// *content* of files across every hard case: resident, non-resident, deleted,
/// alternate data streams, fragmented, and slack. This is the content-search
/// counterpart to the name-based test above, and exercises both the MFT scan
/// alignment fix (512-byte clusters) and file-content indexing.
#[tokio::test]
async fn keyword_search_finds_content_in_dftt3() {
    let img = resolve("test_data/dftt/3-kwsrch-ntfs/3-kwsrch-ntfs/ntfs-img-kw-1.dd");
    if !img.exists() {
        println!(
            "Skipping: DFTT #3 NTFS keyword image not present at {}",
            img.display()
        );
        return;
    }

    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        serde_json::json!({ "name": "ntfs", "subtype": "ntfs", "filesystem_type": "NTFS" }),
    );
    let case_id = fs.case_id;
    let artifacts = MftParser::new().process(&fs).expect("MFT parse");
    // The alignment fix must recover the user files, not just the 4 system files.
    let files = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .count();
    assert!(
        files > 20,
        "expected the user files to be recovered, got {files}"
    );

    let dir = resolve(&format!("target/_kw3_idx_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let svc = SearchService::new(&dir).expect("search service");
    for a in &artifacts {
        let _ = svc.add_artifact_to_index(a).await;
    }
    svc.commit().await.expect("commit");

    // The image hides 10 keywords, one per file class (see its index.html).
    // Eight of them live inside the logical content of a file this parser can
    // reach, and every one of those must resolve — named individually rather
    // than counted, so a class that stops working says which class it was
    // instead of nudging a total.
    //
    // One limit of this shape, stated so it is not mistaken for more than it
    // is: the image's ground truth puts the four `r-*` keywords in `$LogFile`
    // as well as in the file named below, so a hit for those proves the keyword
    // is reachable, not that the resident-file path specifically produced it.
    // Tightening that means asserting which artifact the hit came from.
    let must_resolve = [
        ("r-alloc", "resident content of the allocated file-r-1.dat"),
        ("r-unalloc", "resident content of the deleted file-r-2.dat"),
        ("r-fads", "resident ADS file-r-3.dat:here"),
        ("r-dads", "resident ADS on the directory dir-r-4:there"),
        ("n-alloc", "non-resident allocated file-n-1.dat"),
        ("n-frag", "fragmented non-resident file-n-3.dat"),
        ("n-fads", "non-resident ADS file-n-5.dat:here"),
        ("n-dads", "non-resident ADS on the directory dir-n-6:there"),
    ];
    let mut missing = Vec::new();
    for (kw, where_it_lives) in must_resolve {
        // `expect`, not `unwrap_or_default`: an index that failed to answer is
        // not an index that answered "nothing". Folding the two together is the
        // same false negative this test exists to catch, one layer up.
        let hits = svc.search(case_id, kw, 20).await.expect("search");
        if hits.is_empty() {
            missing.push(format!("{kw} ({where_it_lives})"));
        }
    }
    assert!(
        missing.is_empty(),
        "DFTT #3 keywords that no longer resolve: {}",
        missing.join(", ")
    );

    // The remaining two are not in any file's logical content, and neither is
    // reachable by indexing file content — which is the only content path this
    // test drives. They are recorded here rather than folded into a tolerance,
    // because "we know why this one does not resolve" and "the count came out
    // one short" must not read alike:
    //
    //   n-unalloc  file-n-2.dat is deleted and non-resident, and NTFS frees the
    //              run list on delete, so nothing points at its clusters. Only
    //              carving the unallocated area can reach it.
    //   n-slack    the keyword sits in the cluster slack past the end of
    //              file-n-4.dat. Slack is deliberately excluded from a file's
    //              content (it belongs to the cluster's previous tenant, not to
    //              this file, and including it corrupts every hash and export).
    //              Since HUNT-124 (2026-09-26) slack IS surfaced as its own
    //              artifact — a `SlackSpace` region per live file, graded on
    //              this image by `slack_dftt_tests` — but the search indexer
    //              does not subscribe to `SlackSpace`, so at ingest a slack
    //              region is not indexed at all, bytes or metadata (a backfill
    //              would add its metadata, never its bytes: the text index
    //              reads bytes only for `CONTENT_INDEXED_TYPES`). The byte
    //              sweep reaches it; this keyword-index path does not.
    //
    // Pinned, not printed. Eight of ten is a *ceiling this build cannot exceed*,
    // and a ceiling that is only mentioned in captured stdout is a coverage gap
    // nothing enforces in either direction. Asserting these two still find
    // nothing does not bless the gap: it makes the day one of them starts
    // resolving — because slack was surfaced as its own artifact, or because
    // unallocated carving was wired into this pipeline — turn this test red and
    // say so, so the keyword is moved into `must_resolve` above and stays
    // required from then on. Without that, the gap closes silently and the
    // coverage quietly slips back later with nothing to notice.
    for (kw, why) in [
        ("n-unalloc", "deleted non-resident file, run list freed"),
        (
            "n-slack",
            "cluster slack: a SlackSpace region exists, but the search indexer does not \
             subscribe to SlackSpace, so the region is not indexed at ingest",
        ),
    ] {
        let hits = svc.search(case_id, kw, 20).await.expect("search");
        assert!(
            hits.is_empty(),
            "DFTT #3 '{kw}' now resolves ({} hit(s)); it was unreachable because: {why}. \
             The gap is closed — move '{kw}' into `must_resolve` above so it stays required, \
             and update the comment above it.",
            hits.len()
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// DFTT #4 (EXT3FS Keyword Search): allocated + fragmented file content on a
/// real ext3 volume (128-byte inodes, no extents). Also passes an uppercase
/// filesystem_type to lock in the case-insensitive parser gate: a wrong-case
/// value must not silently skip the whole volume.
#[tokio::test]
async fn keyword_search_finds_content_in_dftt4_ext3() {
    let img = resolve("test_data/dftt/4-kwsrch-ext3/4-kwsrch-ext3/ext3-img-kw-1.dd");
    if !img.exists() {
        println!(
            "Skipping: DFTT #4 ext3 image not present at {}",
            img.display()
        );
        return;
    }

    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        // Uppercase on purpose: the gate must accept it.
        serde_json::json!({ "name": "ext3", "filesystem_type": "EXT4" }),
    );
    let case_id = fs.case_id;
    let artifacts = Ext4Parser::new().process(&fs).expect("ext parse");
    let files = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .count();
    assert!(files >= 3, "expected the ext3 user files, got {files}");

    let dir = resolve(&format!("target/_kw4_idx_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let svc = SearchService::new(&dir).expect("search service");
    for a in &artifacts {
        let _ = svc.add_artifact_to_index(a).await;
    }
    svc.commit().await.expect("commit");

    // Named individually rather than counted. A bare "2 of 4" is satisfied by
    // any two, so either reachable class could stop working and the total would
    // still be met — the failure would be invisible, which is the only kind
    // that matters here.
    //
    // "third" (in the deleted /file3, which is not recovered) and "slacker" (in
    // cluster slack, which is deliberately not served as a file's content) are
    // the two known content-search limits and are not required.
    let mut missing = Vec::new();
    for (kw, where_it_lives) in [
        ("first", "content of the allocated /file1"),
        ("second", "content of the fragmented /file2"),
    ] {
        // An index that failed to answer is not an index that answered
        // "nothing"; `unwrap_or_default` here would report a broken search as a
        // clean miss.
        let hits = svc.search(case_id, kw, 20).await.expect("search");
        if hits.is_empty() {
            missing.push(format!("{kw} ({where_it_lives})"));
        }
    }
    assert!(
        missing.is_empty(),
        "ext3 content keywords that no longer resolve: {}",
        missing.join(", ")
    );

    let _ = std::fs::remove_dir_all(&dir);
}
