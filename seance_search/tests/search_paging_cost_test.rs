//! What one page of a search costs, and how that cost moves with depth.
//!
//! The paging ceiling this crate used to carry was not an arbitrary number: it
//! was where the cost of a deep page was capped. Removing the ceiling is only
//! defensible if the cost is measured rather than assumed, so the measurement
//! lives here as a test that can be re-run rather than as a number in a commit
//! message that nobody can check.
//!
//! What it found, at 60,000 documents on a release build, page size 100:
//!
//! ```text
//! substring scan   offset 0: 42 ms  offset 50,000: 33 ms   (60,000 docs examined, every page)
//! regex scan       offset 0: 33 ms  offset 50,000: 33 ms   (60,000 docs examined, every page)
//! full-text ranked offset 0:  2 ms  offset 50,000:  3 ms   (100 docs examined)
//!
//! substring scan   cursor page at depth 50,000: 0 ms       (100 docs examined)
//! whole-set walk   600 pages by cursor: 429 ms   by offset: ~20,000 ms
//! ```
//!
//! Two things follow, and the second is the one that matters.
//!
//! An offset is NOT what makes a deep page expensive: the curve is flat, because
//! the engine walks the case either way. The paging ceiling was therefore never
//! protecting against depth. What it was capping is the WALK — 600 offset pages
//! cost 600 walks of the case, and the cost of reading a result set to the end
//! grows with the square of its size. A cursor page resumes instead of
//! re-walking, which is why the same walk costs one pass.
//!
//! Scaled to S5 (4,000,000 artifacts) that is ~2.8 s per scan page whatever its
//! depth, and the difference between one walk and forty thousand of them.
//!
//! # What a DEEP RANDOM-ACCESS JUMP costs
//!
//! The second measurement (`measure_what_a_deep_random_access_jump_costs`) asks
//! the question `seance_api`'s `SEARCH_MAX_OFFSET` turns on: now that a pinned
//! searcher makes a server-side walk coherent, should a jump to an arbitrary
//! offset be honoured by walking there? Same corpus, release build, page 100:
//!
//! ```text
//! one offset page, substring scan:  offset 0: 74 ms   offset 59,000: 83 ms  (60,000 docs examined every time)
//! one offset page, ranked:          offset 0:  4 ms   offset 59,000:  8 ms  (100 docs retrieved)
//! one offset page, ranked + ext:    offset 0:  5 ms   offset 10,000: 67 ms  offset 30,000: 71 ms and ZERO rows
//!
//! walking there on a pinned snapshot, to depth 50,000:
//!   substring scan   453 ms over 500 pages   (~9 ms per 1,000 matches)
//!   ranked          1288 ms over 500 pages   (~26 ms per 1,000 matches)
//! ```
//!
//! Walking is not affordable as a page: its cost is LINEAR in depth, so the
//! 100,000 ceiling would be ~0.9–2.6 s of server time for one hundred rows and
//! an offset ten times deeper would be ~9–26 s inside one request. Serving it
//! the current way is cheap in time but sizes a `TopDocs` heap of
//! `offset + limit` scored documents from a number the CLIENT chose, which is
//! the amplification the `limit` clamp exists to stop. And the ranked routing's
//! extension post-filter already fails well below the advertised ceiling — see
//! `a_deep_offset_under_an_extension_filter_is_refused_not_served_empty`. So
//! the refusal stays; the reasoning is recorded at the constant.
//!
//! Ignored by default: it builds an index big enough for the shape of the curve
//! to be visible, which takes longer than a unit test should. Run it with
//!
//! ```text
//! cargo test -p seance_search --release --test search_paging_cost_test -- --ignored --nocapture
//! ```

use seance_core::artifact::{Artifact, ArtifactType};
use seance_search::{SearchOptions, SearchService};
use serde_json::json;
use std::time::Instant;
use uuid::Uuid;

/// Documents in the measured case. Large enough that a deep page is genuinely
/// deep, small enough that seeding it is a minute rather than an hour.
const DOCS: usize = 60_000;

const COMMON_TERM: &str = "kestrel";

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
                "name": format!("report_{i:06}.txt"),
                "content": format!(
                    "{COMMON_TERM} sighting number {i}; the observer recorded a long enough \
                     line of text that decoding the stored field is not free, which is the \
                     cost a deep page is supposed to stop paying"
                ),
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
        if i % 5_000 == 4_999 {
            svc.commit_sync().expect("commit");
        }
    }
    svc.commit_sync().expect("commit");
    (dir, svc, case_id)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; builds a 60k-document index"]
async fn measure_page_cost_against_depth() {
    let (_dir, svc, case_id) = seeded();
    let page_size = 100;

    for (label, options) in [
        ("substring scan", opts(COMMON_TERM, page_size, false)),
        ("regex scan", opts("kestre[l]", page_size, true)),
        (
            "full-text ranked",
            opts(&format!("\"{COMMON_TERM}\""), page_size, false),
        ),
    ] {
        println!("\n--- {label} ---");

        // Offset paging: the cost of one page at increasing depth.
        for offset in [0usize, 10_000, 30_000, 50_000] {
            let started = Instant::now();
            let page = svc
                .search_page(case_id, options.clone(), offset)
                .await
                .expect("search");
            println!(
                "  offset {offset:>6}: {:>6} ms, {} rows, {} documents examined",
                started.elapsed().as_millis(),
                page.results.len(),
                page.examined_documents,
            );
        }

        // Cursor paging: the cost of walking to the same depths one page at a
        // time, and the cost of each page along the way.
        let mut cursor: Option<String> = None;
        let mut walked = 0usize;
        let mut first_page_ms = 0u128;
        let mut deep_page_ms = 0u128;
        let mut deep_page_examined = 0usize;
        let walk_started = Instant::now();
        loop {
            let started = Instant::now();
            let page = svc
                .search_after(case_id, options.clone(), cursor.as_deref())
                .await
                .expect("search");
            let elapsed = started.elapsed().as_millis();
            if walked == 0 {
                first_page_ms = elapsed;
            }
            if walked == 50_000 {
                deep_page_ms = elapsed;
                deep_page_examined = page.examined_documents;
                println!(
                    "  cursor at {walked:>6}: {elapsed:>6} ms, {} documents examined",
                    page.examined_documents
                );
            }
            walked += page.results.len();
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        println!(
            "  cursor walk of all {walked} matches: {} ms total; first page {first_page_ms} ms, \
             page at depth 50,000 {deep_page_ms} ms",
            walk_started.elapsed().as_millis()
        );

        assert_eq!(walked, DOCS, "{label}: the walk must reach every match");
        // The claim, asserted rather than printed: a page at depth 50,000 must
        // not have re-read the 50,000 documents behind it. Stated in documents
        // rather than milliseconds, because this machine is shared and a
        // wall-clock assertion would fail under someone else's load.
        assert!(
            deep_page_examined <= page_size + 1,
            "{label}: the page at depth 50,000 examined {deep_page_examined} documents \
             to return {page_size} rows; a cursor must resume, not re-walk"
        );
    }
}

/// What a DEEP RANDOM-ACCESS JUMP costs, which is the question behind
/// `seance_api`'s `SEARCH_MAX_OFFSET`.
///
/// The measurement above answers "does depth make a page dearer?" for the scan
/// routings, and the answer is no: they walk the case whatever the offset, so
/// the ceiling was never capping a curve. That left the ceiling looking
/// arbitrary — and a ceiling nobody can justify is a ceiling that gets raised
/// or removed on a hunch.
///
/// This one measures the two things that decide it:
///
/// * the RANKED routing, where an offset is not free. Tantivy's `TopDocs` keeps
///   `offset + limit` scored documents in a heap, so the request's server-side
///   working set is sized by a number the CLIENT chose — the exact shape
///   `clamp_search_limit` exists to stop on `limit`.
/// * the cost of the alternative: honouring a deep jump by WALKING there by
///   cursor, one page at a time, which is what a scan routing would have to do
///   and what a pinned searcher now makes coherent to do inside one request.
///
/// Ignored by default, and run the same way as the measurement above:
///
/// ```text
/// cargo test -p seance_search --release --test search_paging_cost_test -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; builds a 60k-document index"]
async fn measure_what_a_deep_random_access_jump_costs() {
    let (_dir, svc, case_id) = seeded();
    let page_size = 100;

    println!("\n--- a single offset page, by routing and depth ---");
    for (label, options) in [
        ("substring scan", opts(COMMON_TERM, page_size, false)),
        (
            "full-text ranked",
            opts(&format!("\"{COMMON_TERM}\""), page_size, false),
        ),
    ] {
        for offset in [0usize, 1_000, 10_000, 30_000, 59_000] {
            let started = Instant::now();
            let page = svc
                .search_page(case_id, options.clone(), offset)
                .await
                .expect("search");
            println!(
                "  {label:<16} offset {offset:>6}: {:>6} ms, {} rows, {} documents examined, \
                 total {}{}",
                started.elapsed().as_millis(),
                page.results.len(),
                page.examined_documents,
                page.total_count,
                if page.count_is_lower_bound {
                    " (floor)"
                } else {
                    ""
                },
            );
        }
    }

    // The extension post-filter is the case where a deep offset is not merely
    // dear but UNSERVEABLE: the ranked routing filters after retrieval, so it
    // can only skip rows it retrieved, and its candidate window is capped.
    println!("\n--- an offset page with an extension post-filter (ranked) ---");
    for offset in [0usize, 1_000, 10_000, 30_000] {
        let mut options = opts(&format!("\"{COMMON_TERM}\""), page_size, false);
        options.file_extensions = Some(vec!["txt".to_string()]);
        let started = Instant::now();
        let page = svc
            .search_page(case_id, options, offset)
            .await
            .expect("search");
        println!(
            // forensic-lint: allow RAGGED-STRING — column alignment in a measurement table.
            "  ranked+ext       offset {offset:>6}: {:>6} ms, {} rows, total {}{}, cursor: {}",
            started.elapsed().as_millis(),
            page.results.len(),
            page.total_count,
            if page.count_is_lower_bound {
                " (floor)"
            } else {
                ""
            },
            if page.next_cursor.is_some() {
                "yes"
            } else {
                "NONE"
            },
        );
    }

    // The alternative implementation of a deep jump: walk there. Held on ONE
    // pinned snapshot, because a server-side walk that spanned several index
    // states would land on a position in an enumeration that no longer exists.
    println!("\n--- reaching the same depth by walking, on a pinned snapshot ---");
    for (label, options) in [
        ("substring scan", opts(COMMON_TERM, page_size, false)),
        (
            "full-text ranked",
            opts(&format!("\"{COMMON_TERM}\""), page_size, false),
        ),
    ] {
        let pin = svc.pin_searcher().expect("pin");
        let started = Instant::now();
        let mut cursor: Option<String> = None;
        let mut walked = 0usize;
        let mut pages = 0usize;
        while walked < 50_000 {
            let page = svc
                .search_after_pinned(&pin, case_id, options.clone(), cursor.as_deref())
                .await
                .expect("search");
            walked += page.results.len();
            pages += 1;
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        let elapsed = started.elapsed().as_millis();
        println!(
            "  {label:<16} walked to {walked} in {pages} pages: {elapsed} ms \
             ({:.2} ms per 1,000 matches)",
            elapsed as f64 / (walked.max(1) as f64 / 1_000.0),
        );
    }

    // The claim that has to hold whatever the timings say on a shared machine:
    // a ranked offset page's server-side working set is sized by the offset the
    // CLIENT asked for, and a scan offset page's is sized by the case. Neither
    // is bounded by the page the examiner will actually read, which is why the
    // random-access form of the enumeration needs a ceiling and the cursor form
    // does not.
    let deep = svc
        .search_page(
            case_id,
            opts(&format!("\"{COMMON_TERM}\""), page_size, false),
            50_000,
        )
        .await
        .expect("search");
    assert_eq!(
        deep.results.len(),
        page_size,
        "the deep ranked page must still be served correctly; the ceiling is \
         about what it costs, not about whether it works"
    );
    let shallow = svc
        .search_page(
            case_id,
            opts(&format!("\"{COMMON_TERM}\""), page_size, false),
            0,
        )
        .await
        .expect("search");
    assert_eq!(shallow.results.len(), page_size);
}

/// The ceiling that is NOT the one the API names, found while measuring the one
/// that is.
///
/// On the ranked routing an extension filter is a POST-filter: the engine
/// retrieves a candidate window, filters it, and can then skip only rows it
/// retrieved. The window is `(offset + limit) * 5`, capped at
/// `MAX_EXTENSION_CANDIDATES`. So the depth a random-access jump can actually
/// reach is not `SEARCH_MAX_OFFSET` and is not any constant: it is however many
/// candidates in that window happen to survive the filter — and on the ordinary
/// forensic shape, a rare extension in a large case, that is a small number.
///
/// Here 6,000 matches contain 100 `.txt` files. A jump to offset 200 is well
/// inside the advertised 100,000 ceiling and well inside the 25,000 candidate
/// cap, and still cannot be served: the window holds 1,500 candidates, ~25 of
/// them survive the filter, and there is nothing at row 200 to return.
///
/// The page that comes back is empty, its count is flagged a floor and it
/// carries no cursor. That is disclosed rather than false — but it is shaped
/// exactly like "you have paged past the end of the result set", which is the
/// one reading an examiner must not take from it. The boundary is pinned here
/// so it cannot drift unnoticed, and so the decision recorded at
/// `SEARCH_MAX_OFFSET` is made against the real figure rather than the
/// advertised one.
#[tokio::test]
async fn a_deep_offset_under_an_extension_filter_is_refused_not_served_empty() {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(dir.path()).expect("search service");
    let case_id = Uuid::new_v4();

    // The shape that bites: one extension of interest, thinly spread through a
    // case of something else. Every document matches the QUERY; one in sixty
    // survives the FILTER.
    let docs = 6_000usize;
    let wanted = 100usize;
    for i in 0..docs {
        let extension = if i % (docs / wanted) == 0 {
            "txt"
        } else {
            "log"
        };
        let art = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": format!("report_{i:06}.{extension}"),
                "content": format!("{COMMON_TERM} sighting number {i}"),
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
    }
    svc.commit_sync().expect("commit");

    let mut options = opts(&format!("\"{COMMON_TERM}\""), 100, false);
    options.file_extensions = Some(vec!["txt".to_string()]);

    // The control: shallow, the window covers the rows it must skip, and the
    // count is exact.
    let shallow = svc
        .search_page(case_id, options.clone(), 0)
        .await
        .expect("search");
    assert!(
        !shallow.results.is_empty(),
        "the fixture must have matches to page through"
    );

    assert!(
        shallow.count_is_lower_bound && shallow.truncated,
        "the window is exhausted on this fixture, so the first page's count is a \
         floor and the page says so"
    );
    assert!(
        shallow.next_cursor.is_some(),
        "a first page whose window was exhausted must carry a cursor, or the \
         walk past the window can never begin"
    );

    // Offset 200: inside SEARCH_MAX_OFFSET (100,000), inside
    // MAX_EXTENSION_CANDIDATES (25,000), and past what this window can reach.
    // The answer is a refusal, not an empty page: an empty page here is shaped
    // exactly like the end of the result set, and the result set has not
    // ended (SHIP-034).
    let err = svc
        .search_page(case_id, options.clone(), 200)
        .await
        .expect_err(
            "the boundary has moved: a jump to offset 200 is now served, so the \
             reasoning recorded at SEARCH_MAX_OFFSET about the extension-filtered \
             ranked routing needs re-checking",
        );
    let refused = err
        .downcast_ref::<seance_search::OffsetUnreachable>()
        .unwrap_or_else(|| panic!("the refusal must be typed, so the API can name it: {err}"));
    assert_eq!(refused.offset, 200);
    assert!(
        refused.reachable < wanted,
        "the reach really is short of the {wanted} matching .txt files: {}",
        refused.reachable
    );
    assert!(
        refused.examined >= refused.reachable,
        "every reachable row was among the examined candidates"
    );
    let message = refused.to_string();
    for must_say in ["not the end of the match set", "next_cursor", "export"] {
        assert!(
            message.contains(must_say),
            "the refusal must say {must_say:?} — that the match set goes on, and the \
             two routes that reach it — got: {message}"
        );
    }
    assert!(
        !message.contains("missing"),
        "nothing is missing from the INDEX here — the window was too small, which \
         is a different fact and must not borrow that one's weight: {message}"
    );

    // The window can be walked past by cursor from the first page: that is
    // the route the refusal names, so it has to actually get there. The walk
    // is pinned to one index snapshot, as the export's is, because a fixture
    // this size is still being merged in the background and an unpinned walk
    // would be refused mid-way for the index having moved — a different
    // refusal, and a correct one, but not the one under test.
    let pin = svc.pin_searcher().expect("pin");
    let first = svc
        .search_after_pinned(&pin, case_id, options.clone(), None)
        .await
        .expect("first pinned page");
    assert!(
        first.next_cursor.is_some(),
        "the pinned first page also walks on"
    );
    let mut cursor = first.next_cursor.clone();
    let mut seen = first.results.len();
    let mut pages = 0;
    while let Some(token) = cursor {
        let page = svc
            .search_after_pinned(&pin, case_id, options.clone(), Some(&token))
            .await
            .expect("cursor page");
        seen += page.results.len();
        cursor = page.next_cursor.clone();
        pages += 1;
        assert!(pages < 1_000, "the walk must terminate");
    }
    assert_eq!(
        seen, wanted,
        "walking by cursor reaches every .txt match the jump could not"
    );
}
