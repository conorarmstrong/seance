//! Pinning ONE searcher for the life of a whole-result-set walk.
//!
//! A cursor is a position in an enumeration, and this engine's enumerations are
//! only meaningful against a fixed index. So a cursor carries the index
//! snapshot it was minted against and is REFUSED when that snapshot moves
//! (`search_cursor_test.rs` pins that, and it must stay pinned: a cursor handed
//! back to a browser minutes or hours later has to be refused, because by then
//! the enumeration it names really is gone).
//!
//! That refusal put a ceiling on the EXPORT, which is a different animal. An
//! export walks a result set start-to-finish inside one request, and the index
//! moves for background segment MERGES as well as for ingest commits — so on a
//! case that is still being ingested, a large export routinely stopped part-way
//! and disclosed a moved index. The file said so, which made it a ceiling
//! rather than a lie, but the ceiling should not have been there.
//!
//! The answer is not to re-base a refused cursor onto whatever the index has
//! since become — that splices two different result sets together with nothing
//! marking the seam. It is to hold ONE searcher open for the walk, so every
//! page reads the same segments and there is nothing to refuse. Tantivy's
//! `Searcher` owns its segment readers and, in tantivy's own words, "guarantees
//! that the `Segment` will not be removed before the destruction of the
//! `Searcher`".
//!
//! These tests pin every half of that trade:
//!
//! * a pinned walk finishes across a commit that refuses an unpinned one;
//! * it enumerates the snapshot it pinned and nothing that arrived after it,
//!   so the exhibit is still ONE result set;
//! * interactive paging is unchanged — it pins nothing and is still refused;
//! * a PURGE is the line the pin must not cross. A held searcher owns its store
//!   readers, so it goes on serving the name and content of an artifact deleted
//!   after the pin — and a purge here is normally material ruled privileged or
//!   out of scope. The pin absorbs movement that ADDS or reorganises and never
//!   movement that REMOVES: the walk is stopped and the segments released;
//! * the pin is bounded and released, because a held searcher holds segment
//!   FILES and a leaked pin is disk that never comes back — including when the
//!   holder never drops anything, which is what a client that stops reading
//!   does.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_search::{CursorRefusal, CursorRefused, PinRevoked, SearchOptions, SearchService};
use serde_json::json;
use std::collections::HashSet;
use std::time::Duration;
use uuid::Uuid;

/// Enough matching documents for several pages at a page size of 4, spread over
/// several segments so a walk that only works within one segment is caught.
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
/// They have separate cursor positions and separate resume paths, so a pin
/// proven over one of them is not proven over the others.
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

/// Commit a document that did not exist when the walk began. This is what
/// ingest does constantly on a live case, and it re-segments the index.
fn commit_a_late_document(svc: &SearchService, case_id: Uuid, name: &str) {
    let late = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": name, "content": format!("{COMMON_TERM} arrived late") }),
    );
    svc.add_artifact_to_index_sync(&late).expect("index");
    svc.commit_sync().expect("commit");
}

/// THE DEFECT. An export walks the whole set inside one request; before the pin
/// existed, an ingest commit or a background merge landing between two of its
/// pages ended the walk with a refusal, and the file was short.
#[tokio::test]
async fn a_pinned_walk_finishes_across_a_commit_that_refuses_an_unpinned_one() {
    for (label, options) in all_paths() {
        let (_dir, svc, case_id) = seeded();
        let pin = svc.pin_searcher().expect("pin the snapshot");

        let first = svc
            .search_after_pinned(&pin, case_id, options.clone(), None)
            .await
            .expect("first page");
        let cursor = first
            .next_cursor
            .clone()
            .expect("more matches follow the first page");

        // The index moves under the walk, exactly as it does in the field.
        commit_a_late_document(&svc, case_id, "late_arrival.txt");

        // The same cursor, on the interactive route, is still refused. That is
        // the forensic property this work must not break: a position in an
        // enumeration that no longer exists is not served.
        let err = svc
            .search_after(case_id, options.clone(), Some(&cursor))
            .await
            .expect_err("interactive paging must still refuse a cursor whose index moved");
        let refused = err
            .downcast_ref::<CursorRefused>()
            .unwrap_or_else(|| panic!("{label}: expected a typed refusal, got: {err:#}"));
        assert_eq!(
            refused.refusal,
            CursorRefusal::IndexMoved,
            "{label}: interactive paging keeps the refusal"
        );

        // The pinned walk reads the segments it is holding, so there is nothing
        // to refuse and the walk finishes.
        let mut rows: Vec<Uuid> = first.results.iter().map(|r| r.artifact_id).collect();
        let mut cursor = Some(cursor);
        let mut requests = 1usize;
        while let Some(token) = cursor {
            let page = svc
                .search_after_pinned(&pin, case_id, options.clone(), Some(&token))
                .await
                .unwrap_or_else(|e| {
                    panic!("{label}: a pinned walk must not be refused mid-export: {e:#}")
                });
            rows.extend(page.results.iter().map(|r| r.artifact_id));
            cursor = page.next_cursor;
            requests += 1;
            assert!(requests < 100, "{label}: the walk must terminate");
        }

        assert_eq!(
            rows.len(),
            DOCS,
            "{label}: the pinned walk must reach every match that was in the \
             snapshot it pinned"
        );
        let unique: HashSet<&Uuid> = rows.iter().collect();
        assert_eq!(unique.len(), DOCS, "{label}: no match may be walked twice");
    }
}

/// The pin is not a licence to splice. A document committed after the walk
/// began is not in the snapshot the walk is reading, and must not appear in it —
/// the exhibit is one enumeration of one index state, which is precisely what
/// the refusal used to protect.
#[tokio::test]
async fn a_pinned_walk_enumerates_the_snapshot_it_pinned_and_nothing_after_it() {
    let (_dir, svc, case_id) = seeded();
    let pin = svc.pin_searcher().expect("pin the snapshot");
    let pinned_snapshot = pin.snapshot().to_string();
    let options = opts(COMMON_TERM, 4, false);

    let mut names: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = svc
            .search_after_pinned(&pin, case_id, options.clone(), cursor.as_deref())
            .await
            .expect("pinned page");
        assert_eq!(
            page.index_snapshot, pinned_snapshot,
            "every page of a pinned walk must name the ONE snapshot it read \
             from; a page that names another has read from another"
        );
        names.extend(page.results.iter().map(|r| r.name.clone()));
        // Ingest keeps landing for the whole walk, as it does during triage.
        commit_a_late_document(&svc, case_id, &format!("late_{}.txt", names.len()));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    assert_eq!(names.len(), DOCS, "the walk covers the pinned population");
    assert!(
        !names.iter().any(|n| n.starts_with("late_")),
        "a document that appeared after the walk began must not be spliced into \
         it: {names:?}"
    );

    // And the index really did move underneath the walk, or this fixture proves
    // nothing at all.
    let now = svc
        .search_after(case_id, options, None)
        .await
        .expect("search");
    assert_ne!(
        now.index_snapshot, pinned_snapshot,
        "the fixture must actually move the index"
    );
}

/// A cursor minted under a pin is still a position in a snapshot. Handed back
/// later on the interactive route — a browser resuming a walk, a bookmarked
/// link — it must be refused like any other, because by then the enumeration it
/// names is gone and nothing is holding it open.
#[tokio::test]
async fn a_cursor_minted_under_a_pin_is_still_refused_by_interactive_paging() {
    let (_dir, svc, case_id) = seeded();
    let options = opts(COMMON_TERM, 4, false);

    let cursor = {
        let pin = svc.pin_searcher().expect("pin");
        svc.search_after_pinned(&pin, case_id, options.clone(), None)
            .await
            .expect("first page")
            .next_cursor
            .expect("more matches follow")
    };
    commit_a_late_document(&svc, case_id, "late_arrival.txt");

    let err = svc
        .search_after(case_id, options, Some(&cursor))
        .await
        .expect_err("a cursor whose snapshot is gone must be refused");
    let refused = err.downcast_ref::<CursorRefused>().expect("typed refusal");
    assert_eq!(refused.refusal, CursorRefusal::IndexMoved);
}

/// THE LINE THE PIN MUST NOT CROSS.
///
/// A pin absorbs index movement that ADDS or REORGANISES — an ingest commit, a
/// background merge — because neither can make the exhibit wrong: documents
/// that arrive after the pin belong to a later index state, the file names the
/// state it holds, and nothing in it is false. It must NOT absorb movement that
/// REMOVES.
///
/// A purge in this product is not a performance detail. It is normally someone
/// ruling material privileged, out of scope, or outside a warrant, and the whole
/// point of the ruling is that the material stops leaving the building. But a
/// held searcher owns its store readers, so `searcher.doc()` goes on returning
/// the stored name and content of a purged artifact for as long as the pin
/// lives — which means a large export running while an admin purges would write
/// the destroyed evidence into a file the examiner then holds. Disclosing that
/// in the preamble would not un-write it.
///
/// Before the pin existed, the purge's own commit moved the snapshot and the
/// walk stopped. That posture is restored here deliberately and narrowly: the
/// engine refuses to serve any further page from a snapshot a purge has
/// superseded, and drops the searcher so the segment files holding the purged
/// documents are released too. The completeness guarantee loses in exactly the
/// case where it should lose, and the caller is told which case that was.
///
/// The same rule elsewhere in the codebase, stated in the reindex handler: a
/// batch that would put destroyed evidence back into the index is refused
/// rather than applied.
#[tokio::test]
async fn a_purge_after_the_pin_stops_the_walk_rather_than_exporting_destroyed_evidence() {
    let (_dir, svc, case_id) = seeded();
    let options = opts(COMMON_TERM, 4, false);
    let pin = svc.pin_searcher().expect("pin");

    let first = svc
        .search_after_pinned(&pin, case_id, options.clone(), None)
        .await
        .expect("first page");
    let cursor = first.next_cursor.clone().expect("more to walk");
    let on_first_page: HashSet<Uuid> = first.results.iter().map(|r| r.artifact_id).collect();

    // Something the walk has not reached yet, purged mid-walk. This is the
    // admin running a delete thirty seconds into someone else's export.
    let everything = svc
        .search_after(case_id, opts(COMMON_TERM, DOCS, false), None)
        .await
        .expect("search");
    let doomed = everything
        .results
        .iter()
        .map(|r| r.artifact_id)
        .find(|id| !on_first_page.contains(id))
        .expect("a match the first page did not deliver");
    svc.delete_artifact(doomed).await.expect("purge");

    let refused = svc
        .search_after_pinned(&pin, case_id, options.clone(), Some(&cursor))
        .await
        .expect_err(
            "a pinned walk must stop once a purge has superseded the snapshot it is reading: continuing would write destroyed evidence into an exhibit, which is the exact outcome the purge existed to prevent",
        );
    assert_eq!(
        refused.downcast_ref::<PinRevoked>().copied(),
        Some(PinRevoked::Purged),
        "and must say WHY, so the file can name the cause rather than reporting a generic failure: {refused}"
    );

    // The disk goes too. A pin whose walk has been stopped has no reader left
    // and no reason to hold the segment files that contain the purged
    // documents open.
    assert_eq!(
        pin.pinned_segments(),
        0,
        "a revoked pin must release the segments it was holding, not merely refuse to read them"
    );
}

/// The bound on a pin nobody is reading.
///
/// A pin lives as long as the response body it was moved into, and nothing in
/// the server bounds that: `tower_http`'s `TimeoutLayer` bounds the response
/// FUTURE, not body streaming. A client that takes the headers and then stops
/// reading — a tab left open, a half-open TCP connection, a slow-loris — holds
/// a whole index snapshot's segments open for as long as it likes, and there is
/// deliberately no cap on how many exports may run at once. A handful of
/// stalled downloads on a large case is then an evidence volume filling up.
///
/// `Drop` answers a body that is dropped. This answers a body that never is: a
/// pin that has gone unread for longer than its idle bound is revoked, its
/// searcher dropped and its segments released, and the next page it is asked
/// for says so.
#[tokio::test]
async fn a_pin_nobody_is_reading_is_revoked_rather_than_held_for_ever() {
    let (_dir, svc, case_id) = seeded();
    let options = opts(COMMON_TERM, 4, false);
    let pin = svc
        .pin_searcher_with_idle_limit(Duration::from_millis(200))
        .expect("pin");

    let first = svc
        .search_after_pinned(&pin, case_id, options.clone(), None)
        .await
        .expect("first page");
    let cursor = first.next_cursor.clone().expect("more to walk");
    assert!(pin.pinned_segments() > 0, "the fixture must pin something");

    // The client takes the headers and stops reading.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    assert_eq!(
        pin.pinned_segments(),
        0,
        "an unread pin must not hold segment files open indefinitely: the disk is an evidence volume and the holder is a client that has gone away"
    );
    let refused = svc
        .search_after_pinned(&pin, case_id, options, Some(&cursor))
        .await
        .expect_err("and a revoked pin cannot serve another page");
    assert_eq!(
        refused.downcast_ref::<PinRevoked>().copied(),
        Some(PinRevoked::Idle),
        "named as an idle timeout rather than as a purge, because the two call for entirely different actions: {refused}"
    );
}

/// The other half of the idle bound: it must never cut off a walk that is
/// actually being read. An export of a very large case is minutes of work, and
/// a bound that fired on a healthy download would be the very failure the pin
/// was introduced to remove.
#[tokio::test]
async fn a_pin_that_is_being_read_is_not_revoked_by_the_idle_bound() {
    let (_dir, svc, case_id) = seeded();
    let options = opts(COMMON_TERM, 4, false);
    let pin = svc
        .pin_searcher_with_idle_limit(Duration::from_millis(400))
        .expect("pin");

    let mut cursor: Option<String> = None;
    let mut rows = 0usize;
    loop {
        // Slower than half the idle bound, so a bound measured from the PIN
        // rather than from the last read would fire well before the walk ends.
        tokio::time::sleep(Duration::from_millis(250)).await;
        let page = svc
            .search_after_pinned(&pin, case_id, options.clone(), cursor.as_deref())
            .await
            .expect("a walk that keeps reading must not be revoked");
        rows += page.results.len();
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(rows, DOCS, "the whole walk must survive");
}

/// THE COST. A held searcher holds the segment FILES of the snapshot it pinned:
/// a merge that supersedes them still runs, but the superseded files cannot go
/// away while the pin lives. That is the bound, and it is bounded exactly
/// because the pinned set is FIXED — nothing committed or merged after the pin
/// joins it, so the disk held is the index as it stood when the export began,
/// however long the export runs.
#[tokio::test]
async fn a_pin_holds_a_fixed_set_of_segments_however_much_the_index_moves() {
    let (_dir, svc, case_id) = seeded();
    let pin = svc.pin_searcher().expect("pin");
    let segments = pin.pinned_segments();
    let documents = pin.pinned_documents();
    let snapshot = pin.snapshot().to_string();
    assert!(segments > 0, "the fixture must pin something");

    for i in 0..12 {
        commit_a_late_document(&svc, case_id, &format!("late_{i}.txt"));
    }

    assert_eq!(
        pin.pinned_segments(),
        segments,
        "a pin must not grow: what it holds is what it pinned"
    );
    assert_eq!(
        pin.pinned_documents(),
        documents,
        "and the documents it holds open are the ones it pinned"
    );
    assert_eq!(
        pin.snapshot(),
        snapshot,
        "the fingerprint of a pinned snapshot is fixed for its life"
    );
    assert_ne!(
        svc.pin_searcher().expect("a fresh pin").snapshot(),
        snapshot,
        "the live index moved on, so a fixed fingerprint is the pin's own"
    );
}

/// THE RELEASE. An export can be abandoned — the examiner closes the tab, the
/// download is cancelled — and the pin has to go with it. A pin that outlives
/// its export is disk that never comes back.
#[tokio::test]
async fn a_pin_is_counted_while_it_lives_and_released_when_it_is_dropped() {
    let (_dir, svc, case_id) = seeded();
    assert_eq!(svc.live_pinned_searchers(), 0, "nothing is pinned yet");

    {
        let pin = svc.pin_searcher().expect("pin");
        assert_eq!(
            svc.live_pinned_searchers(),
            1,
            "a live pin must be visible: the disk an export holds open is the \
             sum over live pins, and an operator who cannot count them cannot \
             account for it"
        );
        // Whatever the walk does, the count is a count of walks.
        svc.search_after_pinned(&pin, case_id, opts(COMMON_TERM, 4, false), None)
            .await
            .expect("page");
        assert_eq!(svc.live_pinned_searchers(), 1);
    }

    assert_eq!(
        svc.live_pinned_searchers(),
        0,
        "dropping the pin — which is what an abandoned export does — must \
         release it"
    );
}

/// Interactive paging pins NOTHING. It reads whatever the index has committed
/// now, which is what makes its cursor refusable, and it must not leave a
/// searcher held open behind a browser that has wandered off.
#[tokio::test]
async fn interactive_paging_pins_nothing() {
    let (_dir, svc, case_id) = seeded();
    let options = opts(COMMON_TERM, 4, false);

    let page = svc
        .search_after(case_id, options.clone(), None)
        .await
        .expect("page");
    assert_eq!(
        svc.live_pinned_searchers(),
        0,
        "an interactive page must not pin a snapshot"
    );

    svc.search_page(case_id, options, 0).await.expect("page");
    assert_eq!(svc.live_pinned_searchers(), 0);
    assert!(page.next_cursor.is_some());
}
