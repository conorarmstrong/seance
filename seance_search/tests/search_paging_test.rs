//! Paging a search result set, and the ordering guarantee paging rests on.
//!
//! Before `search_page` existed, a search returned a page and nothing could ask
//! for the next one: the match after the last row on screen was unreachable in
//! the product. Adding an offset is only half the fix, and the smaller half.
//! The other half is that a page is meaningless unless the enumeration behind
//! it is STABLE — page 2 has to continue page 1, not re-roll the same result
//! set and hand back an arbitrary second sample of it.
//!
//! That guarantee was genuinely absent. The two scan paths (plain-substring and
//! regex, which between them serve every query that is not full-text syntax)
//! enumerated matches by iterating the `HashSet<DocAddress>` that tantivy's
//! `DocSetCollector` returns. Rust seeds a `HashSet`'s hasher per instance, so
//! two identical searches in one process walked the case's documents in two
//! different orders and returned two different subsets of the same match set.
//! Offset-slicing that would have produced pages that silently repeat some
//! matches and skip others — an enumeration that LOOKS complete and is not,
//! which is a worse artifact for a witness statement than the dead end it
//! replaced.
//!
//! So these tests assert determinism directly, and each of them fails against
//! the pre-paging engine: `pages_are_stable_across_identical_requests` fails
//! because the same request returned different rows, and `pages_partition_*`
//! fails because concatenating two pages produced duplicates and gaps.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_search::{SearchOptions, SearchService};
use serde_json::json;
use uuid::Uuid;

/// Enough matching documents that a page size of 4 leaves several pages, and
/// enough that a nondeterministic enumeration is overwhelmingly unlikely to
/// coincide with a deterministic one by chance.
const DOCS: usize = 40;

/// A term every seeded document contains, so the match set is the whole case.
const COMMON_TERM: &str = "kestrel";

/// Build a service over a fresh index holding [`DOCS`] matching documents.
///
/// The `TempDir` is returned rather than dropped so the index outlives the
/// call; dropping it would delete the directory out from under the reader.
fn seeded() -> (tempfile::TempDir, SearchService, Uuid) {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(dir.path()).expect("search service");
    let case_id = Uuid::new_v4();
    for i in 0..DOCS {
        // The index is committed in several batches on purpose: a single commit
        // produces one segment, and a one-segment index would hide an ordering
        // bug that only appears once matches are spread across segments.
        let art = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": format!("report_{i:03}.txt"),
                "content": format!("{COMMON_TERM} sighting number {i}"),
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
        if i % 9 == 8 {
            svc.commit_sync().expect("commit");
        }
    }
    svc.commit_sync().expect("commit");
    (dir, svc, case_id)
}

fn opts(query: &str, limit: usize, use_regex: bool) -> SearchOptions {
    SearchOptions {
        query: query.to_string(),
        limit,
        artifact_types: None,
        use_regex,
        file_extensions: None,
        fuzzy: None,
    }
}

/// The artifact ids of one page, in the order the engine returned them.
async fn page_ids(
    svc: &SearchService,
    case_id: Uuid,
    options: SearchOptions,
    offset: usize,
) -> Vec<Uuid> {
    svc.search_page(case_id, options, offset)
        .await
        .expect("search")
        .results
        .iter()
        .map(|r| r.artifact_id)
        .collect()
}

/// Every query shape the engine routes differently, so each test covers all
/// three rather than only the one that happened to be easiest to write:
/// a plain keyword (substring scan), a regex (regex scan), and a query using
/// full-text syntax (tantivy's ranked `TopDocs` path).
fn all_paths() -> Vec<(&'static str, SearchOptions)> {
    vec![
        ("substring scan", opts(COMMON_TERM, 4, false)),
        ("regex scan", opts("kestre[l]", 4, true)),
        // Quoting is what routes a query away from the substring scan and onto
        // tantivy's ranked `TopDocs` path; see `is_plain_query`.
        (
            "full-text ranked",
            opts(&format!("\"{COMMON_TERM}\""), 4, false),
        ),
    ]
}

#[tokio::test]
async fn pages_are_stable_across_identical_requests() {
    let (_dir, svc, case_id) = seeded();

    for (label, options) in all_paths() {
        for offset in [0usize, 4, 12] {
            let first = page_ids(&svc, case_id, options.clone(), offset).await;
            let second = page_ids(&svc, case_id, options.clone(), offset).await;
            assert!(
                !first.is_empty(),
                "{label}: offset {offset} should still be inside the match set"
            );
            assert_eq!(
                first, second,
                "{label}: the same request twice against an unchanged index must \
                 return the same page in the same order (offset {offset})"
            );
        }
    }
}

#[tokio::test]
async fn pages_partition_the_match_set_with_no_repeats_and_no_gaps() {
    let (_dir, svc, case_id) = seeded();

    for (label, options) in all_paths() {
        let page_size = options.limit;
        let mut walked: Vec<Uuid> = Vec::new();
        let mut offset = 0usize;
        // Walk further than the match set to prove the walk terminates rather
        // than looping on a final page that keeps returning rows.
        while offset < DOCS + page_size {
            let page = page_ids(&svc, case_id, options.clone(), offset).await;
            assert!(
                page.len() <= page_size,
                "{label}: a page must never exceed the requested limit"
            );
            walked.extend(page);
            offset += page_size;
        }

        assert_eq!(
            walked.len(),
            DOCS,
            "{label}: walking every page must yield each match exactly once"
        );
        let unique: std::collections::HashSet<Uuid> = walked.iter().copied().collect();
        assert_eq!(
            unique.len(),
            DOCS,
            "{label}: no artifact may appear on two pages"
        );
    }
}

#[tokio::test]
async fn total_count_is_the_match_set_not_the_page_and_does_not_move_with_offset() {
    let (_dir, svc, case_id) = seeded();

    for (label, options) in all_paths() {
        for offset in [0usize, 8, 36] {
            let response = svc
                .search_page(case_id, options.clone(), offset)
                .await
                .expect("search");
            // `total_count` is quoted as a term's prevalence in the case. A
            // figure that shrank as the examiner paged would be read as the
            // case shrinking under them.
            assert_eq!(
                response.total_count, DOCS,
                "{label}: total_count must stay the size of the match set at offset {offset}"
            );
            assert_eq!(
                response.offset, offset,
                "{label}: the response must state which page it is, so a page \
                 can never be mistaken for the head of the result set"
            );
        }
    }
}

#[tokio::test]
async fn an_offset_past_the_last_match_is_an_empty_page_not_an_error() {
    let (_dir, svc, case_id) = seeded();

    for (label, options) in all_paths() {
        let response = svc
            .search_page(case_id, options.clone(), DOCS * 4)
            .await
            .expect("search");
        assert!(
            response.results.is_empty(),
            "{label}: there is nothing past the end of the match set"
        );
        // Still the true match count: "you have gone past the end of 40 matches"
        // and "there are no matches" are different statements, and the second
        // one would be a false negative in a witness statement.
        assert_eq!(
            response.total_count, DOCS,
            "{label}: running off the end must not report the case as empty"
        );
    }
}

#[tokio::test]
async fn the_index_snapshot_identifies_what_a_page_was_served_from() {
    let (_dir, svc, case_id) = seeded();
    let options = opts(COMMON_TERM, 4, false);

    let before = svc
        .search_page(case_id, options.clone(), 0)
        .await
        .expect("search");
    assert!(
        !before.index_snapshot.is_empty(),
        "every response must name the snapshot it was served from"
    );
    // Two pages of one unchanged index are two views of one enumeration, and
    // say so.
    let second_page = svc
        .search_page(case_id, options.clone(), 4)
        .await
        .expect("search");
    assert_eq!(
        before.index_snapshot, second_page.index_snapshot,
        "pages of an unchanged index must carry the same snapshot"
    );

    // Ingest appending to the case is the ordinary S1 case: the examiner starts
    // paging while evidence is still arriving. The stable order is stable only
    // against a FIXED index, so page 2 taken after this point is not guaranteed
    // to continue page 1 — and the only way the UI can say so is if the
    // snapshot it holds stops matching the one it is handed.
    let extra = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "late_arrival.txt", "content": format!("{COMMON_TERM} arrived late") }),
    );
    svc.add_artifact_to_index_sync(&extra).expect("index");
    svc.commit_sync().expect("commit");

    let after = svc.search_page(case_id, options, 0).await.expect("search");
    assert_ne!(
        before.index_snapshot, after.index_snapshot,
        "a committed change to the index must change the snapshot, or a reader \
         holding a page from before it cannot tell that its enumeration moved"
    );
}

#[tokio::test]
async fn search_with_options_is_the_first_page() {
    let (_dir, svc, case_id) = seeded();
    let options = opts(COMMON_TERM, 4, false);

    // Every existing caller uses `search_with_options` and must keep getting
    // exactly what it got before paging existed.
    let paged = page_ids(&svc, case_id, options.clone(), 0).await;
    let unpaged: Vec<Uuid> = svc
        .search_with_options(case_id, options)
        .await
        .expect("search")
        .results
        .iter()
        .map(|r| r.artifact_id)
        .collect();
    assert_eq!(paged, unpaged);
}

#[tokio::test]
async fn paging_holds_under_an_extension_filter() {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(dir.path()).expect("search service");
    let case_id = Uuid::new_v4();
    // Half the documents carry the extension being filtered for, so a page that
    // ignored the filter would be caught by the count as well as by the rows.
    for i in 0..DOCS {
        let ext = if i % 2 == 0 { "txt" } else { "log" };
        let art = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": format!("report_{i:03}.{ext}"),
                "content": format!("{COMMON_TERM} sighting number {i}"),
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
    }
    svc.commit_sync().expect("commit");

    let mut options = opts(COMMON_TERM, 4, false);
    options.file_extensions = Some(vec!["txt".to_string()]);

    let mut walked: Vec<Uuid> = Vec::new();
    for offset in (0..DOCS).step_by(4) {
        walked.extend(page_ids(&svc, case_id, options.clone(), offset).await);
    }
    let unique: std::collections::HashSet<Uuid> = walked.iter().copied().collect();
    assert_eq!(
        unique.len(),
        DOCS / 2,
        "paging under an extension filter must reach every filtered match once"
    );
    assert_eq!(
        walked.len(),
        DOCS / 2,
        "and must not hand the same filtered match out on two pages"
    );
}
