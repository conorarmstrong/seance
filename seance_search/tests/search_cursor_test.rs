//! Walking a result set past the point an offset can reach, and refusing to
//! pretend when the ground has moved.
//!
//! Offset paging had a ceiling because every page cost a walk of the whole
//! case: the two scan paths materialised the case's document set and
//! match-tested every document in it before slicing out the rows the page
//! wanted. Reaching match 4,000,000 that way costs 40,000 such walks. The
//! ceiling capped the bill by making the matches past it unreachable, which
//! answers the cost question by refusing the evidence.
//!
//! A cursor answers it instead. It names a POSITION in the enumeration, so a
//! page resumes where the last one stopped rather than starting again, and the
//! whole set costs one walk rather than one walk per page.
//!
//! A position is only meaningful against the enumeration it was taken from, and
//! this index moves constantly — ingest commits while an examiner reads. So
//! these tests pin both halves: a cursor walks the set exactly, and a cursor
//! whose index has moved underneath it is REFUSED, never quietly re-based onto
//! whatever the enumeration has become.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_search::{CursorRefusal, CursorRefused, SearchOptions, SearchResponse, SearchService};
use serde_json::json;
use std::collections::HashSet;
use uuid::Uuid;

/// Enough matching documents for several pages at a page size of 4, spread over
/// several segments so an ordering bug that only shows across segments is
/// caught.
const DOCS: usize = 40;

const COMMON_TERM: &str = "kestrel";

fn seeded() -> (tempfile::TempDir, SearchService, Uuid) {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(dir.path()).expect("search service");
    let case_id = Uuid::new_v4();
    for i in 0..DOCS {
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

/// Wait until the index has stopped changing under the test.
///
/// A cursor walk is refused when the snapshot it named no longer exists, which
/// is correct and is the whole point of `CR-009`. `seeded()` commits every nine
/// documents to build a multi-segment index — which is what these tests are
/// about — and Tantivy's merge threads run **after** a commit returns, so on a
/// loaded machine a background merge can land between two pages of a walk and
/// the second page is refused. The product is behaving exactly as designed; the
/// test was assuming a settled index without saying so, and failed roughly once
/// per full-workspace run while passing every time in isolation.
///
/// Stated rather than slept on: two consecutive searches must report the same
/// snapshot before the walk starts. A `sleep` would be a guess about how long
/// merging takes, and would still be a guess on a slower machine.
async fn settled(svc: &SearchService, case_id: Uuid) {
    let probe = opts(COMMON_TERM, 1, false);
    let mut last = String::new();
    for _ in 0..200 {
        let page = svc
            .search_after(case_id, probe.clone(), None)
            .await
            .expect("probe search");
        if page.index_snapshot == last {
            return;
        }
        last = page.index_snapshot;
        tokio::task::yield_now().await;
    }
    panic!("the index never settled: merges are still landing after 200 probes");
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

/// Every query shape the engine routes differently: a plain keyword (substring
/// scan), a regex (regex scan), and full-text syntax (tantivy's ranked path).
fn all_paths() -> Vec<(&'static str, SearchOptions)> {
    vec![
        ("substring scan", opts(COMMON_TERM, 4, false)),
        ("regex scan", opts("kestre[l]", 4, true)),
        (
            "full-text ranked",
            opts(&format!("\"{COMMON_TERM}\""), 4, false),
        ),
    ]
}

/// One page, or `None` when it was refused because the index moved under the
/// walk.
///
/// Every other refusal panics: a mangled cursor or a changed query is a defect
/// these tests exist to catch, and only a moved index is the product working
/// as designed. See [`cursor_walk`] for why a moved index is retried.
async fn try_page(
    svc: &SearchService,
    case_id: Uuid,
    options: &SearchOptions,
    cursor: Option<&str>,
) -> Option<SearchResponse> {
    match svc.search_after(case_id, options.clone(), cursor).await {
        Ok(page) => Some(page),
        Err(err) => match err.downcast_ref::<CursorRefused>().map(|r| r.refusal) {
            Some(CursorRefusal::IndexMoved) => None,
            _ => panic!("search: {err}"),
        },
    }
}

/// Walk the whole result set with cursors, returning every row in order plus
/// the number of requests it took.
///
/// Returns `None` when a page was refused because the index moved under the
/// walk. That refusal is the product working — `CR-009` exists to make a walk
/// across two states of the index impossible — and a background merge landing
/// mid-walk triggers it legitimately, so a caller asserting *exactness over one
/// consistent set* must start again rather than treat it as a failure. See
/// [`consistent_cursor_walk`].
async fn try_cursor_walk(
    svc: &SearchService,
    case_id: Uuid,
    options: SearchOptions,
) -> Option<(Vec<Uuid>, usize)> {
    let mut cursor: Option<String> = None;
    let mut rows: Vec<Uuid> = Vec::new();
    let mut requests = 0usize;
    loop {
        let page = try_page(svc, case_id, &options, cursor.as_deref()).await?;
        requests += 1;
        assert!(
            page.results.len() <= options.limit,
            "a page must never exceed the requested limit"
        );
        rows.extend(page.results.iter().map(|r| r.artifact_id));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
        assert!(
            requests < 100,
            "the walk must terminate rather than loop on a cursor that never advances"
        );
    }
    Some((rows, requests))
}

/// A first page and the cursor it hands back, retried until both come from one
/// consistent state of the index.
///
/// The shape several tests need: one page, then a second request resuming from
/// it. A merge landing between the two refuses the second, which is the
/// product working — see [`cursor_walk`].
async fn first_page_and_cursor(
    svc: &SearchService,
    case_id: Uuid,
    options: &SearchOptions,
    label: &str,
) -> (SearchResponse, String) {
    for _ in 0..6 {
        let Some(page) = try_page(svc, case_id, options, None).await else {
            settled(svc, case_id).await;
            continue;
        };
        let Some(cursor) = page.next_cursor.clone() else {
            panic!("{label}: more matches follow page one")
        };
        // Prove the cursor is still serviceable before the caller builds on
        // it, so a merge between these two requests is retried here rather
        // than failing the caller's own assertion.
        if try_page(svc, case_id, options, Some(&cursor))
            .await
            .is_some()
        {
            return (page, cursor);
        }
        settled(svc, case_id).await;
    }
    panic!("{label}: the index never settled long enough for two consecutive requests")
}

/// One walk across one consistent state of the index.
///
/// `settled()` establishes that the index has stopped changing *at the instant
/// it returns*, which is not the same as "no merge will land during the next
/// fifteen walks". Tantivy's merge threads run after a commit returns, and
/// `seeded()` deliberately commits five times to build a multi-segment index,
/// so on a loaded machine a merge can land between two pages — and the second
/// page is then correctly refused. That is what failed this test about once per
/// full-workspace run while it passed every time in isolation.
///
/// The assertion these tests make is that a walk over one consistent set is
/// exact. So a refused page starts the walk again rather than failing it, with
/// a bound: if six attempts in a row cannot complete one walk, the index really
/// is not settling and that is a defect worth failing for.
async fn cursor_walk(
    svc: &SearchService,
    case_id: Uuid,
    options: SearchOptions,
) -> (Vec<Uuid>, usize) {
    for _ in 0..6 {
        if let Some(walked) = try_cursor_walk(svc, case_id, options.clone()).await {
            return walked;
        }
        settled(svc, case_id).await;
    }
    panic!(
        "six consecutive walks were refused because the index moved under them; the index is \
         not settling and a cursor walk cannot be completed at all"
    )
}

#[tokio::test]
async fn a_cursor_walk_reaches_every_match_exactly_once() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    for (label, base) in all_paths() {
        // Page sizes that divide the match set, that do not, that equal it, and
        // that exceed it. The boundary cases are where a walk is most likely to
        // hand back a cursor onto nothing or to stop one row early.
        for limit in [1usize, 4, 6, DOCS, DOCS * 2] {
            let mut options = base.clone();
            options.limit = limit;
            let (rows, requests) = cursor_walk(&svc, case_id, options).await;
            assert_eq!(
                rows.len(),
                DOCS,
                "{label} at {limit} a page: the walk must yield every match \
                 ({requests} requests)"
            );
            let unique: HashSet<Uuid> = rows.iter().copied().collect();
            assert_eq!(
                unique.len(),
                DOCS,
                "{label} at {limit} a page: no artifact may be handed out twice"
            );
        }
    }
}

#[tokio::test]
async fn a_request_for_no_rows_gets_the_count_and_no_walk_position() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    // Keyword triage reads `total_count` as a term's prevalence and does not
    // need the rows. A page size of zero is the degenerate form of that ask,
    // and it must NOT come back with a cursor: no row was delivered, so a
    // position placed after the matches this request looked at would step over
    // them on the next one — matches silently skipped in the middle of a walk.
    for (label, base) in all_paths() {
        let mut options = base;
        options.limit = 0;
        let page = svc
            .search_after(case_id, options, None)
            .await
            .expect("search");
        assert!(page.results.is_empty(), "{label}: no rows were asked for");
        assert_eq!(
            page.total_count, DOCS,
            "{label}: the count is what such a caller is after"
        );
        assert!(
            page.next_cursor.is_none(),
            "{label}: a page that delivered nothing cannot name where to resume"
        );
    }
}

#[tokio::test]
async fn resuming_with_no_rows_asked_for_does_not_step_over_the_matches_it_skipped() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    // The page size is not part of the position a cursor names, so a walk can
    // legitimately arrive here: page one at four rows, then a request for the
    // count alone. The engine looks at matches it is not allowed to return, and
    // if it minted a cursor after them the next page of the walk would start
    // past matches nobody ever saw — a silent skip in the middle of a review
    // that reports itself as a complete walk.
    for (label, base) in all_paths() {
        let (_first, cursor) = first_page_and_cursor(&svc, case_id, &base, label).await;

        let mut counting = base.clone();
        counting.limit = 0;
        let counted = svc
            .search_after(case_id, counting, Some(&cursor))
            .await
            .expect("search");
        assert!(counted.results.is_empty(), "{label}");
        assert!(
            counted.next_cursor.is_none(),
            "{label}: a page that returned no rows must not advance the walk past \
             the matches it looked at"
        );

        // The original cursor is still the honest way on, and it still lands on
        // the matches that request declined to return.
        let resumed = svc
            .search_after(case_id, base.clone(), Some(&cursor))
            .await
            .expect("search");
        assert_eq!(resumed.offset, base.limit, "{label}");
        assert_eq!(resumed.results.len(), base.limit, "{label}");
    }
}

#[tokio::test]
async fn a_cursor_walk_is_the_same_enumeration_as_the_offset_walk() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    for (label, options) in all_paths() {
        let (by_cursor, _) = cursor_walk(&svc, case_id, options.clone()).await;

        let mut by_offset: Vec<Uuid> = Vec::new();
        let mut offset = 0usize;
        while offset < DOCS {
            let page = svc
                .search_page(case_id, options.clone(), offset)
                .await
                .expect("search");
            by_offset.extend(page.results.iter().map(|r| r.artifact_id));
            offset += options.limit;
        }

        assert_eq!(
            by_cursor, by_offset,
            "{label}: a cursor names a position in the SAME enumeration an offset \
             indexes into; two walks of one order must agree row for row"
        );
    }
}

#[tokio::test]
async fn the_position_a_page_states_is_where_the_cursor_left_off() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    for (label, options) in all_paths() {
        // Restarted when a background merge moves the index mid-walk; see
        // `cursor_walk`.
        let mut expected_offset = 0usize;
        'walk: for attempt in 0..6 {
            assert!(attempt < 5, "{label}: the index never settled for one walk");
            let mut cursor: Option<String> = None;
            expected_offset = 0;
            loop {
                let Some(page) = try_page(&svc, case_id, &options, cursor.as_deref()).await else {
                    settled(&svc, case_id).await;
                    continue 'walk;
                };
                // The response states which matches these are. An examiner reads
                // "matches 1,001-1,100 of 34,000" off this, and a screenshot of it
                // outlives the request that produced it.
                assert_eq!(
                    page.offset, expected_offset,
                    "{label}: a cursor page must state its position in the match set"
                );
                assert_eq!(
                    page.total_count, DOCS,
                    "{label}: the match count is a property of the set, not of the page"
                );
                expected_offset += page.results.len();
                match page.next_cursor {
                    Some(next) => cursor = Some(next),
                    None => break 'walk,
                }
            }
        }
        assert_eq!(expected_offset, DOCS, "{label}: the walk covered the set");
    }
}

#[tokio::test]
async fn the_last_page_of_a_walk_offers_no_cursor() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    for (label, options) in all_paths() {
        // A page size that divides the match set exactly is the case where an
        // engine is most tempted to hand back a cursor onto an empty page: the
        // last row of the set is also the last row of a full page.
        let mut options = options;
        options.limit = DOCS / 4;
        let (_, pages) = cursor_walk(&svc, case_id, options).await;
        assert_eq!(
            pages, 4,
            "{label}: four full pages cover the set; a fifth, empty page means \
             the engine offered a cursor past the end of its own enumeration"
        );
    }
}

#[tokio::test]
async fn a_cursor_is_refused_when_the_index_moved_under_it_rather_than_re_based() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    for (label, options) in all_paths() {
        let first = svc
            .search_after(case_id, options.clone(), None)
            .await
            .expect("search");
        let cursor = first
            .next_cursor
            .expect("more matches follow the first page");

        // Ingest committing while an examiner pages is the ordinary case, not
        // an edge one. It re-segments the index, and the position the cursor
        // names is a position in the enumeration the OLD index produced.
        let late = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": "late_arrival.txt", "content": format!("{COMMON_TERM} arrived late") }),
        );
        svc.add_artifact_to_index_sync(&late).expect("index");
        svc.commit_sync().expect("commit");

        let err = svc
            .search_after(case_id, options.clone(), Some(&cursor))
            .await
            .expect_err("a cursor from a superseded index must not be served");
        let refused = err
            .downcast_ref::<CursorRefused>()
            .unwrap_or_else(|| panic!("{label}: expected a typed refusal, got: {err:#}"));
        assert_eq!(
            refused.refusal,
            CursorRefusal::IndexMoved,
            "{label}: the refusal must say WHICH promise the cursor can no longer keep"
        );
    }
}

#[tokio::test]
async fn a_cursor_from_a_different_query_is_refused() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    let first = svc
        .search_after(case_id, opts(COMMON_TERM, 4, false), None)
        .await
        .expect("search");
    let cursor = first.next_cursor.expect("more matches follow");

    // A position in one result set is not a position in another. Serving it
    // would put rows on screen numbered against a match count they have
    // nothing to do with.
    for (label, other) in [
        ("a different term", opts("sighting", 4, false)),
        ("the same term as a regex", opts(COMMON_TERM, 4, true)),
        (
            "the same term with a type filter",
            SearchOptions {
                artifact_types: Some(vec!["FileEntry".to_string()]),
                ..opts(COMMON_TERM, 4, false)
            },
        ),
        (
            "the same term with an extension filter",
            SearchOptions {
                file_extensions: Some(vec!["txt".to_string()]),
                ..opts(COMMON_TERM, 4, false)
            },
        ),
    ] {
        let err = svc
            .search_after(case_id, other, Some(&cursor))
            .await
            .expect_err("a cursor is not transferable between result sets");
        let refused = err
            .downcast_ref::<CursorRefused>()
            .unwrap_or_else(|| panic!("{label}: expected a typed refusal, got: {err:#}"));
        assert_eq!(refused.refusal, CursorRefusal::QueryChanged, "{label}");
    }
}

#[tokio::test]
async fn a_cursor_belonging_to_another_case_is_refused() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;
    let first = svc
        .search_after(case_id, opts(COMMON_TERM, 4, false), None)
        .await
        .expect("search");
    let cursor = first.next_cursor.expect("more matches follow");

    // The gravest confusion this could produce: case B's screen, case A's
    // enumeration. Refused on the same footing as a changed query.
    let err = svc
        .search_after(Uuid::new_v4(), opts(COMMON_TERM, 4, false), Some(&cursor))
        .await
        .expect_err("a cursor is scoped to the case it was minted in");
    let refused = err.downcast_ref::<CursorRefused>().expect("typed refusal");
    assert_eq!(refused.refusal, CursorRefusal::QueryChanged);
}

#[tokio::test]
async fn a_malformed_cursor_is_refused_rather_than_read_as_the_first_page() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    for bad in ["", "not-a-cursor", "zzzz", "00", "0a0b0c"] {
        let err = svc
            .search_after(case_id, opts(COMMON_TERM, 4, false), Some(bad))
            .await
            .expect_err("an unreadable cursor is not a request for page one");
        let refused = err
            .downcast_ref::<CursorRefused>()
            .unwrap_or_else(|| panic!("cursor {bad:?}: expected a typed refusal, got: {err:#}"));
        assert_eq!(refused.refusal, CursorRefusal::Malformed, "cursor {bad:?}");
    }
}

#[tokio::test]
async fn a_cursor_walk_holds_under_an_extension_filter() {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(dir.path()).expect("search service");
    let case_id = Uuid::new_v4();
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

    for (label, base) in all_paths() {
        let mut options = base;
        options.file_extensions = Some(vec!["txt".to_string()]);
        let (rows, _) = cursor_walk(&svc, case_id, options).await;
        let unique: HashSet<Uuid> = rows.iter().copied().collect();
        assert_eq!(
            rows.len(),
            DOCS / 2,
            "{label}: the walk must reach every filtered match once"
        );
        assert_eq!(unique.len(), DOCS / 2, "{label}: and only once");
    }
}

#[tokio::test]
async fn a_cursor_walk_holds_under_an_artifact_type_filter() {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(dir.path()).expect("search service");
    let case_id = Uuid::new_v4();
    for i in 0..DOCS {
        let kind = if i % 2 == 0 {
            ArtifactType::FileEntry
        } else {
            ArtifactType::ParsedRecord
        };
        let art = Artifact::new(
            case_id,
            kind,
            None,
            json!({
                "name": format!("report_{i:03}.txt"),
                "content": format!("{COMMON_TERM} sighting number {i}"),
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
    }
    svc.commit_sync().expect("commit");

    for (label, base) in all_paths() {
        let mut options = base;
        options.artifact_types = Some(vec!["FileEntry".to_string()]);
        let (rows, _) = cursor_walk(&svc, case_id, options).await;
        assert_eq!(
            rows.len(),
            DOCS / 2,
            "{label}: the walk must reach every type-filtered match once"
        );
    }
}

#[tokio::test]
async fn the_first_cursor_page_is_the_first_offset_page() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    for (label, options) in all_paths() {
        let cursored = svc
            .search_after(case_id, options.clone(), None)
            .await
            .expect("search");
        let offset_paged = svc
            .search_page(case_id, options.clone(), 0)
            .await
            .expect("search");
        let a: Vec<Uuid> = cursored.results.iter().map(|r| r.artifact_id).collect();
        let b: Vec<Uuid> = offset_paged.results.iter().map(|r| r.artifact_id).collect();
        assert_eq!(
            a, b,
            "{label}: page one is page one however it was asked for"
        );
        assert_eq!(cursored.total_count, offset_paged.total_count, "{label}");
        assert_eq!(
            cursored.index_snapshot, offset_paged.index_snapshot,
            "{label}: both name the snapshot they were served from"
        );
    }
}

#[tokio::test]
async fn an_offset_page_hands_back_a_cursor_so_a_walk_can_continue_from_it() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    for (label, options) in all_paths() {
        // The offset pager and the cursor walk are the same enumeration, so an
        // examiner who paged by offset to the ceiling can carry on past it.
        // Retried when a background merge moves the index between the offset
        // page and the resumed one; see `cursor_walk`.
        let mut pair = None;
        for _ in 0..6 {
            let by_offset = svc
                .search_page(case_id, options.clone(), 8)
                .await
                .expect("search");
            let cursor = by_offset.next_cursor.clone().unwrap_or_else(|| {
                panic!(
                    "{label}: an offset page with matches after it must hand back a cursor \
                     onto them"
                )
            });
            if let Some(next) = try_page(&svc, case_id, &options, Some(&cursor)).await {
                pair = Some((by_offset, next));
                break;
            }
            settled(&svc, case_id).await;
        }
        let (by_offset, next) = pair.unwrap_or_else(|| {
            panic!("{label}: the index never settled for two consecutive requests")
        });
        assert_eq!(
            next.offset,
            8 + by_offset.results.len(),
            "{label}: the continuation starts where the offset page ended"
        );

        let straight = svc
            .search_page(case_id, options.clone(), 8 + by_offset.results.len())
            .await
            .expect("search");
        let a: Vec<Uuid> = next.results.iter().map(|r| r.artifact_id).collect();
        let b: Vec<Uuid> = straight.results.iter().map(|r| r.artifact_id).collect();
        assert_eq!(
            a, b,
            "{label}: and it is the same page the offset would give"
        );
    }
}

/// The cost claim behind removing the ceiling, asserted rather than described.
///
/// `examined_documents` is how many stored documents the request actually
/// retrieved and match-tested. Offset paging re-examines the whole case for
/// every page, which is why deep paging had to be capped; a cursor page
/// examines only what lies between where the last page stopped and where this
/// one ends.
#[tokio::test]
async fn a_cursor_page_does_not_re_examine_the_documents_behind_it() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;
    // The scan paths are the ones that retrieve every stored document; the
    // ranked path never did, and reports zero examined for that reason.
    for (label, options) in [
        ("substring scan", opts(COMMON_TERM, 4, false)),
        ("regex scan", opts("kestre[l]", 4, true)),
    ] {
        let deep_by_offset = svc
            .search_page(case_id, options.clone(), 32)
            .await
            .expect("search");
        assert_eq!(
            deep_by_offset.examined_documents, DOCS,
            "{label}: an offset page walks the whole case to reach its rows"
        );

        // Walk to the same depth with cursors and look at the last page.
        // Restarted when a background merge moves the index mid-walk; see
        // `cursor_walk`.
        let page = 'walk: loop {
            let mut cursor: Option<String>;
            let Some(mut page) = try_page(&svc, case_id, &options, None).await else {
                settled(&svc, case_id).await;
                continue 'walk;
            };
            for _ in 0..8 {
                match page.next_cursor.clone() {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
                let Some(next_page) = try_page(&svc, case_id, &options, cursor.as_deref()).await
                else {
                    settled(&svc, case_id).await;
                    continue 'walk;
                };
                page = next_page;
                if page.offset >= 32 {
                    break;
                }
            }
            break page;
        };
        assert_eq!(page.offset, 32, "{label}: walked to the same depth");
        assert!(
            page.examined_documents <= options.limit + 1,
            "{label}: a resumed page examined {} documents to return {} rows; it must \
             examine only what lies ahead of the cursor, not the whole case",
            page.examined_documents,
            page.results.len()
        );
    }
}

/// A cursor walk is never refused for the reason an OFFSET walk is refused.
///
/// `SHIP-034` refuses an offset jump the scan's budget cannot reach, and says so
/// by naming the two routes that do: the cursor, and the export. That refusal
/// was not gated on `resuming`, so it also fired on **cursor** pages — the very
/// walk it recommends.
///
/// The mechanism, because the condition looks innocent: a resumed page inherits
/// `total` from the cursor and never recounts (the counting is itself inside
/// `!resuming`), while `offset` is how far the walk has consumed. On a case
/// larger than the scan budget `offset` overtakes the inherited `total` after a
/// few pages, and the next page that crosses a barren stretch and hits the
/// budget with no rows satisfies every other clause. The walk aborted with
/// advice to follow the cursor the caller had just followed.
#[tokio::test]
async fn a_cursor_page_is_not_refused_for_a_budget_an_offset_jump_would_hit() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;

    // A scan (substring, not the ranked path) so the walk goes through the
    // routing that carried the defect.
    let mut options = opts(COMMON_TERM, 3, true);
    options.limit = 3;

    // Walk the whole set. Every page must be served; not one may be refused
    // with the offset-unreachable error, whose advice is to do what this is
    // doing: `try_page` panics on any refusal but a moved index, which a
    // background merge can cause mid-walk and which starts the walk again, as
    // in `cursor_walk`.
    let mut walked = None;
    for _ in 0..6 {
        walked = try_cursor_walk(&svc, case_id, options.clone()).await;
        if walked.is_some() {
            break;
        }
        settled(&svc, case_id).await;
    }
    let (rows, requests) =
        walked.expect("the index never settled long enough for one whole cursor walk");

    // Every seeded document carries the term, so the walk must end having
    // delivered all of them, one page at a time, and not have stopped early.
    assert_eq!(rows.len(), DOCS, "the walk must reach every matching row");
    assert_eq!(
        requests,
        DOCS.div_ceil(options.limit),
        "{} rows at {} per page",
        DOCS,
        options.limit
    );
    let distinct: std::collections::HashSet<_> = rows.iter().collect();
    assert_eq!(distinct.len(), DOCS, "no row may be served twice");
}

#[tokio::test]
async fn a_cursor_survives_a_change_of_page_size() {
    let (_dir, svc, case_id) = seeded();
    settled(&svc, case_id).await;
    // A cursor names a position in the match set, not a page number, so an
    // examiner who changes the page size mid-walk keeps their place instead of
    // being thrown back to the top of the set.
    let mut options = opts(COMMON_TERM, 4, false);
    // Retried when a background merge moves the index between the two
    // requests; see `cursor_walk`.
    let mut resumed = None;
    for _ in 0..6 {
        let (_first, cursor) =
            first_page_and_cursor(&svc, case_id, &options, "a change of page size").await;
        let mut wider = options.clone();
        wider.limit = 10;
        if let Some(second) = try_page(&svc, case_id, &wider, Some(&cursor)).await {
            resumed = Some(second);
            break;
        }
        settled(&svc, case_id).await;
    }
    let second = resumed.expect("the index never settled for two consecutive requests");
    options.limit = 10;
    assert_eq!(second.offset, 4);
    assert_eq!(second.results.len(), 10);

    let by_offset = svc.search_page(case_id, options, 4).await.expect("search");
    let a: Vec<Uuid> = second.results.iter().map(|r| r.artifact_id).collect();
    let b: Vec<Uuid> = by_offset.results.iter().map(|r| r.artifact_id).collect();
    assert_eq!(a, b);
}
