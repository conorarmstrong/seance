//! The search export walks the whole match set, and says so in the file.
//!
//! Cursor paging gave the interactive endpoint a route past the 100,000-match
//! random-access ceiling, and the export did not follow: it asked for one page
//! of 100,000 hits and stopped. So the product could SHOW an examiner a match it
//! could not EXPORT, which is the worst way round — the screen promises a hit
//! the exhibit does not contain.
//!
//! Closing that gap by draining the cursor into a `String` would have swapped a
//! visible ceiling for an invisible one: a 4,000,000-match case would build a
//! multi-gigabyte body in server memory and die. The export therefore STREAMS
//! off the cursor loop, one bounded page at a time, and these tests pin the
//! forensic consequences of that choice rather than the plumbing:
//!
//! * every export ends with a verdict row, INCLUDING a complete one, so a file
//!   cut short in transit is missing something a whole file has;
//! * the file states its own population before its first row;
//! * an index that moves mid-drain is never spliced over — the seam the cursor
//!   work exists to expose survives into the export.
//!
//! That last one used to be bought with a REFUSAL: a commit or a background
//! segment merge landing mid-walk ended the export, and the file disclosed it.
//! Honest, but a ceiling — and it bound hardest on a case still being ingested,
//! which is when an examiner most needs the exhibit. The export now pins one
//! searcher for the life of the walk, so the seam cannot open in the first
//! place: every page reads the same segments, and documents that arrive during
//! the export belong to a later index state and are simply not in the file. The
//! tests below hold both halves of that — the walk completes, and nothing from
//! after it is spliced in — plus the two things a pin makes possible to get
//! wrong: a stale disclosure, and a pin that outlives an abandoned download.

use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request, StatusCode},
};
use futures::StreamExt;
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    orchestrator::{CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

/// Matching documents seeded into the case under test.
///
/// Deliberately more than one drain page, so a test that walks the export is
/// testing the WALK and not a single page that happened to hold everything.
const DOCS: usize = 1_050;

/// A term every seeded document contains.
const TERM: &str = "kestrel";

/// The marker that opens the row ending a finished export.
const TERMINAL: &str = "### END OF EXPORT ###";

async fn setup() -> (
    axum::Router,
    Uuid,
    Arc<seance_search::SearchService>,
    Arc<SqliteConnection>,
) {
    // One commit: a settled, single-segment index, which is the fixture every
    // test that is not about a MOVING index wants.
    setup_seeded(DOCS, DOCS).await
}

/// `docs` matching documents, committed every `commit_every` of them.
///
/// The commit interval is the whole point of the parameter. Each commit lands a
/// segment, and tantivy merges segments in the background once enough of them
/// accumulate — so a case seeded in many commits is still moving under a search
/// for some time after the last document is indexed, which is exactly the state
/// a case is in during triage.
async fn setup_seeded(
    docs: usize,
    commit_every: usize,
) -> (
    axum::Router,
    Uuid,
    Arc<seance_search::SearchService>,
    Arc<SqliteConnection>,
) {
    let index_dir = tempfile::tempdir().unwrap();
    let service =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    // Leaked deliberately, as the other search API tests do: the service
    // outlives the `TempDir` guard.
    std::mem::forget(index_dir);

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Search Export Case", "examiner")
        .await
        .unwrap();

    for i in 0..docs {
        let artifact = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": format!("note_{i:05}.txt"),
                "content": format!("{TERM} observation {i}"),
            }),
        );
        service
            .add_artifact_to_index_sync(&artifact)
            .expect("index");
        if commit_every > 0 && (i + 1).is_multiple_of(commit_every) {
            service.commit_sync().expect("commit");
        }
    }
    service.commit_sync().expect("commit");

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: Some(service.clone()),
        ingestion_service: orchestrator.ingestion_service(),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: EvidenceRootPolicy::unrestricted(),
        cancellation: CancellationHandle::new(),
    };
    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: String::new(),
        enabled: false,
    };
    (
        router_with_auth(app_state, Some(auth_config)),
        case_id,
        service,
        db,
    )
}

fn export_request(case_id: Uuid, format: &str, query: &str) -> Request<Body> {
    Request::builder()
        .uri(format!(
            "/api/v1/cases/{case_id}/search/export/{format}?{query}"
        ))
        .body(Body::empty())
        .unwrap()
}

async fn export(
    app: &axum::Router,
    case_id: Uuid,
    format: &str,
    query: &str,
) -> (StatusCode, HeaderMap, String) {
    let response = app
        .clone()
        .oneshot(export_request(case_id, format, query))
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

/// The hit rows of a search-export CSV: not the `#` preamble, not the column
/// header, not the terminal verdict.
fn data_rows(csv: &str) -> Vec<&str> {
    csv.lines()
        .filter(|l| {
            !l.starts_with('#')
                && !l.starts_with("Artifact ID,")
                && !l.contains(TERMINAL)
                && !l.is_empty()
        })
        .collect()
}

/// The verdict row, if this file has one. A `#` preamble line that QUOTES the
/// marker (to teach the reader what to look for) is not a verdict.
fn verdict(csv: &str) -> Option<&str> {
    csv.lines()
        .rfind(|l| !l.starts_with('#') && l.contains(TERMINAL))
}

#[tokio::test]
async fn the_csv_export_holds_every_match_not_just_the_first_drain_page() {
    let (app, case_id, _service, _db) = setup().await;

    let (status, _headers, csv) = export(&app, case_id, "csv", &format!("q={TERM}")).await;
    assert_eq!(status, StatusCode::OK);

    let rows = data_rows(&csv);
    assert_eq!(
        rows.len(),
        DOCS,
        "the export must reach every match the walk reaches, not one page of them"
    );
    let unique: std::collections::HashSet<&&str> = rows.iter().collect();
    assert_eq!(unique.len(), DOCS, "no match may be exported twice");
}

/// `seance_search` has TWO enumerations and picks between them by the shape of
/// the query: a plain keyword is an unranked scan of the case in index order,
/// while a fuzzy or structured query is a BM25-ranked walk. They have separate
/// cursor positions and separate resume paths, so an export proven over one of
/// them is not proven over the other — and a drain that stopped early on the
/// ranked path would quietly shorten the exhibit for every boolean and fuzzy
/// search in the product.
#[tokio::test]
async fn the_export_walks_the_ranked_routing_as_well_as_the_scan() {
    let (app, case_id, _service, _db) = setup().await;

    let (status, _headers, csv) = export(&app, case_id, "csv", &format!("q={TERM}&fuzzy=1")).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        data_rows(&csv).len(),
        DOCS,
        "the ranked routing must be drained to the end too"
    );
    let last = csv.lines().last().expect("a non-empty file");
    assert!(last.contains("VERDICT: COMPLETE"), "{last}");
    assert!(
        csv.contains("# filter.fuzzy_edit_distance,1"),
        "and the file must say that the match set is a fuzzy one: a reader who \
         takes these rows for exact hits has been misled about what matched"
    );
}

#[tokio::test]
async fn a_whole_export_ends_with_a_verdict_that_says_it_is_whole() {
    let (app, case_id, _service, _db) = setup().await;

    let (_, _, csv) = export(&app, case_id, "csv", &format!("q={TERM}")).await;

    let last = csv.lines().last().expect("a non-empty file");
    assert!(
        last.contains(TERMINAL),
        "the verdict must be the LAST row; anywhere else and a file cut short \
         in transit could still carry it. Last line: {last}"
    );
    assert!(
        last.contains("VERDICT: COMPLETE"),
        "this export really is whole and must say so: {last}"
    );
    assert!(
        last.contains(&format!("all {DOCS} of {DOCS}")),
        "the verdict must state the population, not just a mood: {last}"
    );
}

#[tokio::test]
async fn a_fragment_is_missing_the_verdict_and_the_preamble_says_how_to_tell() {
    let (app, case_id, _service, _db) = setup().await;

    let (_, _, csv) = export(&app, case_id, "csv", &format!("q={TERM}")).await;

    // What an examiner is left holding when the connection dies mid-download:
    // a prefix of the real file. It must not be able to pass for the whole one.
    let cut = &csv[..csv.len() / 2];
    assert!(
        verdict(cut).is_none(),
        "a truncated export must not carry the verdict that certifies a whole one"
    );
    // And the fragment still carries the instruction for spotting itself,
    // because the preamble is the first thing written.
    assert!(
        cut.contains(TERMINAL),
        "the preamble must name the row a whole export ends with; a warning that \
         only appears at the end cannot warn about a file that has no end"
    );
    assert!(
        cut.contains("cut short"),
        "and must say in words what a missing verdict row means"
    );
}

#[tokio::test]
async fn the_export_states_its_population_before_its_first_row() {
    let (app, case_id, _service, _db) = setup().await;

    let (_, headers, csv) =
        export(&app, case_id, "csv", &format!("q={TERM}&types=FileEntry")).await;

    let preamble: String = csv
        .lines()
        .take_while(|l| l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!preamble.is_empty(), "the file must open with a preamble");
    assert!(preamble.contains(TERM), "what was asked for: {preamble}");
    assert!(
        preamble.contains("FileEntry"),
        "the filters in force are part of what was asked for: {preamble}"
    );
    assert!(
        preamble.contains(&DOCS.to_string()),
        "the size of the match set: {preamble}"
    );
    assert!(
        preamble.contains(&case_id.to_string()),
        "the case the population belongs to: {preamble}"
    );

    // The snapshot the walk is pinned to, in the file and on the response, so
    // two exports of one query can be told apart when the index moved between
    // them.
    let snapshot = headers
        .get("X-Export-Index-Snapshot")
        .and_then(|v| v.to_str().ok())
        .expect("the snapshot must reach the caller as a header too");
    assert!(
        preamble.contains(snapshot),
        "the file must name the index snapshot it was taken from: {preamble}"
    );
}

/// The headers cannot state completeness: they are sent before the first row is
/// read, and the walk can fail at any byte after that. An `X-Export-Incomplete:
/// false` header on a streamed export would be a promise made before the facts
/// were in.
#[tokio::test]
async fn the_headers_point_at_the_file_for_the_verdict_rather_than_guessing_one() {
    let (app, case_id, _service, _db) = setup().await;

    let (_, headers, _) = export(&app, case_id, "csv", &format!("q={TERM}")).await;

    assert!(
        headers.get("X-Export-Incomplete").is_none(),
        "a streamed export must not assert completeness in a header sent before \
         the rows were read"
    );
    assert_eq!(
        headers
            .get("X-Export-Completeness")
            .and_then(|v| v.to_str().ok()),
        Some("stated-in-final-row"),
        "the caller has to be told where the verdict actually is"
    );
}

/// An index that moves mid-export used to END the export. It no longer does —
/// the walk holds one searcher for its whole life, so the segments it is
/// reading stay readable and there is nothing to refuse — and the property the
/// refusal existed to protect is kept intact by the pin rather than by the
/// refusal: the file still holds exactly ONE enumeration of ONE index state,
/// and a document committed after the walk began is still not in it.
#[tokio::test]
async fn a_commit_mid_export_no_longer_ends_the_walk_and_is_still_never_spliced_in() {
    let (app, case_id, service, _db) = setup().await;

    let response = app
        .clone()
        .oneshot(export_request(case_id, "csv", &format!("q={TERM}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let pinned_snapshot = response
        .headers()
        .get("X-Export-Index-Snapshot")
        .and_then(|v| v.to_str().ok())
        .expect("the export names the snapshot it pinned")
        .to_string();

    // Ingest committing mid-export is the ordinary case on a live case, not an
    // edge one. The response is already open — the first drain page was read
    // before the handler returned — and the body is lazy, so this commit lands
    // between drain pages.
    let late = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "late.txt", "content": format!("{TERM} arrived late") }),
    );
    service.add_artifact_to_index_sync(&late).expect("index");
    service.commit_sync().expect("commit");

    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must not abort: the file has to survive to explain itself");
    let body = String::from_utf8(bytes.to_vec()).unwrap();

    let last = body.lines().last().expect("a non-empty file");
    assert!(
        last.contains(TERMINAL),
        "the file must still end with a verdict: {last}"
    );
    assert!(
        last.contains("VERDICT: COMPLETE"),
        "a commit landing mid-export must no longer cut the exhibit short: {last}"
    );
    assert_eq!(
        data_rows(&body).len(),
        DOCS,
        "and every match in the pinned snapshot must be in the file"
    );

    // The rows belong to ONE enumeration. Nothing from the second, different
    // result set may be spliced onto the end of the first.
    assert!(
        !body.contains("late.txt"),
        "a document that appeared after the walk began must not be exported as \
         part of it"
    );

    // The fixture must actually have moved the index, or it proves nothing.
    let after = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{case_id}/search?q={TERM}&limit=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let page: Value =
        serde_json::from_slice(&to_bytes(after.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_ne!(
        page["index_snapshot"].as_str().unwrap(),
        pinned_snapshot,
        "the commit must genuinely have moved the index under the export"
    );
}

/// THE DELIVERABLE, proved the way the defect was found.
///
/// Measured before the pin: exporting 20,000 matches immediately after indexing
/// them stopped at row 18,000 with the moved-index verdict, and completed in
/// full only once tantivy's background merges had settled. So an export taken
/// during triage — the busiest, most time-critical hour of a case — routinely
/// ended short.
///
/// The fixture reproduces that state rather than simulating it: the case is
/// seeded in many commits, so segments are still merging in the background, and
/// ingest keeps committing WHILE the body streams. Both of those move the index
/// snapshot, and both used to end the walk.
#[tokio::test]
async fn an_export_taken_during_active_ingest_and_merging_still_holds_every_match() {
    // Several commits' worth of segments, so tantivy's merge policy has work to
    // do at the moment the export starts, and more than one drain page of rows
    // so the walk is a walk.
    const BUSY_DOCS: usize = 2_400;
    let (app, case_id, service, _db) = setup_seeded(BUSY_DOCS, 200).await;

    // No settling wait: the export starts immediately, with merges in flight.
    let response = app
        .clone()
        .oneshot(export_request(case_id, "csv", &format!("q={TERM}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let pinned_snapshot = response
        .headers()
        .get("X-Export-Index-Snapshot")
        .and_then(|v| v.to_str().ok())
        .expect("snapshot header")
        .to_string();

    // Read the body a frame at a time, committing more ingest as it goes. This
    // is triage: the export and the ingest are running at once.
    let mut stream = response.into_body().into_data_stream();
    let mut body = String::new();
    let mut late = 0usize;
    while let Some(frame) = stream.next().await {
        let bytes = frame.expect("the body must not abort mid-file");
        body.push_str(std::str::from_utf8(&bytes).unwrap());
        if late < 12 {
            let artifact = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({
                    "name": format!("late_{late:03}.txt"),
                    "content": format!("{TERM} arrived during the export"),
                }),
            );
            service
                .add_artifact_to_index_sync(&artifact)
                .expect("index");
            service.commit_sync().expect("commit");
            late += 1;
        }
    }

    let last = body.lines().last().expect("a non-empty file");
    assert!(
        last.contains("VERDICT: COMPLETE"),
        "an export taken during ingest must reach the end of its match set: {last}"
    );
    assert_eq!(
        data_rows(&body).len(),
        BUSY_DOCS,
        "and hold every match that was in the snapshot it pinned"
    );
    assert!(
        !body.contains("late_"),
        "while still holding ONE enumeration: documents that arrived during the \
         export belong to a later index state, not to this exhibit"
    );

    // The fixture must actually have moved the index under the walk.
    let after = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{case_id}/search?q={TERM}&limit=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let page: Value =
        serde_json::from_slice(&to_bytes(after.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_ne!(
        page["index_snapshot"].as_str().unwrap(),
        pinned_snapshot,
        "the index must have moved during the export, or this fixture proves \
         nothing"
    );
}

/// An abandoned download must release what it was holding. The export pins a
/// searcher, and a pinned searcher holds the segment FILES of its snapshot open
/// — a merge cannot reclaim them while it lives. A pin that outlives the
/// request that made it is disk that never comes back, on a server where a
/// dropped download is an everyday event.
#[tokio::test]
async fn an_abandoned_export_releases_the_searcher_it_pinned() {
    let (app, case_id, service, _db) = setup().await;
    assert_eq!(service.live_pinned_searchers(), 0);

    let response = app
        .clone()
        .oneshot(export_request(case_id, "csv", &format!("q={TERM}")))
        .await
        .unwrap();
    let mut stream = response.into_body().into_data_stream();

    // Enough frames to be sure the walk is under way and the pin is held.
    let mut seen = 0usize;
    while seen < 3 {
        stream.next().await.expect("frames").expect("a frame");
        seen += 1;
    }
    assert_eq!(
        service.live_pinned_searchers(),
        1,
        "a running export holds exactly one pinned searcher"
    );

    // The examiner closes the tab.
    drop(stream);

    assert_eq!(
        service.live_pinned_searchers(),
        0,
        "an abandoned export must release its pin; otherwise every cancelled \
         download leaks a held index view and the disk it is holding open"
    );
}

/// The file's own account of itself has to keep pace with the mechanism. It
/// used to warn that a moved index would end the walk; a pinned walk cannot end
/// that way, and a warning about an impossible condition is as stale a claim as
/// a missing one.
#[tokio::test]
async fn the_preamble_says_the_snapshot_is_held_for_the_whole_export() {
    let (app, case_id, _service, _db) = setup().await;

    let (_, _, csv) = export(&app, case_id, "csv", &format!("q={TERM}")).await;
    let preamble: String = csv
        .lines()
        .take_while(|l| l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        preamble.contains("held open"),
        "the preamble must say that the snapshot it names was held open for the \
         whole export, so a reader knows the rows are one index state and not \
         several: {preamble}"
    );
    assert!(
        preamble.contains("cut short"),
        "and must keep the one way a file can still be short — stopping in \
         transit: {preamble}"
    );
    assert!(
        preamble.contains("A PURGE is the one exception") && preamble.contains("STOPPED"),
        "and must state the edge the pin must not cross: the held snapshot \
         still contains artifacts a later purge removed, so the walk is stopped \
         rather than allowed to write destroyed evidence into the file: \
         {preamble}"
    );
    assert!(
        preamble.contains("rows written before the purge landed may still include"),
        "including the one thing a reader of this file cannot work out for \
         themselves — that the rows already written are not covered by the \
         stop: {preamble}"
    );

    let (_, _, json) = export(&app, case_id, "json", &format!("q={TERM}")).await;
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        parsed["index_snapshot_pinned"],
        json!(true),
        "and the JSON export must state the same fact in a field a script can \
         read, rather than only in prose"
    );
}

#[tokio::test]
async fn the_json_export_holds_every_match_and_ends_with_its_verdict() {
    let (app, case_id, _service, _db) = setup().await;

    let (status, _, body) = export(&app, case_id, "json", &format!("q={TERM}")).await;
    assert_eq!(status, StatusCode::OK);

    let parsed: Value = serde_json::from_str(&body).expect("a whole export must be valid JSON");
    assert_eq!(
        parsed["results"].as_array().expect("results").len(),
        DOCS,
        "the JSON export must reach every match too"
    );
    assert_eq!(parsed["completeness"]["complete"], json!(true));
    assert_eq!(parsed["completeness"]["rows"], json!(DOCS));
    assert_eq!(parsed["population"]["matching_artifacts"], json!(DOCS));
    assert!(
        parsed["completeness"]["statement"]
            .as_str()
            .unwrap_or_default()
            .contains(TERMINAL),
        "one verdict sentence, worded the same in both formats"
    );

    // A JSON export cut short is not merely missing its verdict, it will not
    // parse: the completeness object is the last thing written, after the
    // results array is closed.
    let cut = &body[..body.len() / 2];
    assert!(
        serde_json::from_str::<Value>(cut).is_err(),
        "a fragment must not parse as a document"
    );
}

/// The export and the interactive walk must enumerate ONE set. A screen that
/// shows a hit the exhibit does not contain is the defect this work exists to
/// close, and it comes back the moment the two paths diverge.
#[tokio::test]
async fn the_export_and_a_cursor_walk_agree_on_the_match_set() {
    let (app, case_id, _service, _db) = setup().await;

    let mut walked: Vec<String> = Vec::new();
    let mut query = format!("q={TERM}&limit=500");
    loop {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/cases/{case_id}/search?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let page: Value = serde_json::from_slice(&bytes).unwrap();
        walked.extend(
            page["results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["artifact_id"].as_str().unwrap().to_string()),
        );
        match page["next_cursor"].as_str() {
            Some(cursor) => query = format!("q={TERM}&limit=500&cursor={cursor}"),
            None => break,
        }
    }

    let (_, _, csv) = export(&app, case_id, "csv", &format!("q={TERM}")).await;
    let exported: Vec<String> = data_rows(&csv)
        .iter()
        .map(|row| row.split(',').next().unwrap().to_string())
        .collect();

    assert_eq!(
        exported, walked,
        "the export must hold exactly the matches the walk reaches, in the same \
         order"
    );
}

/// A search that cannot run must fail as a REQUEST, before a single byte of
/// file is written. An examiner who is handed a 200 and a two-line file has an
/// exhibit; an examiner who is handed a 500 has an error.
#[tokio::test]
async fn a_search_that_cannot_run_is_refused_instead_of_starting_a_file() {
    let (app, case_id, _service, _db) = setup().await;

    let (status, _, body) = export(&app, case_id, "csv", "q=%5B&regex=true").await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an unrunnable search must not open an export: {body}"
    );
    assert!(
        !body.contains("Artifact ID,"),
        "and must not emit the shape of an export file: {body}"
    );
}

// --- A floor on the TOTAL is not rows missing from the FILE (B8-0xx) ---

/// Documents seeded for the capped-candidate-window fixture.
///
/// It has to exceed the ranked routing's first-page candidate window, which is
/// `SEARCH_EXPORT_PAGE * 5` = 5,000 when an extension post-filter is active.
/// Below that the window is never exhausted, the count is exact, and the defect
/// under test cannot be reproduced at all.
const RANKED_WINDOW_DOCS: usize = 6_000;

/// The fixture that makes a completed walk report a floor for its count.
///
/// The ranked routing filters by extension AFTER retrieval, so it over-fetches
/// five candidates per wanted row and, when that window comes back full, cannot
/// know how many matches lie beyond it — so it reports its count as a floor.
/// That bounds the COUNT and nothing else: the walk resumes past the window
/// from the last candidate it examined and goes on to enumerate every match.
async fn ranked_window_export(format: &str) -> (StatusCode, String) {
    let (app, case_id, _service, _db) = setup_seeded(RANKED_WINDOW_DOCS, RANKED_WINDOW_DOCS).await;
    let (status, _headers, body) = export(
        &app,
        case_id,
        format,
        &format!("q=%22{TERM}%22&extensions=txt"),
    )
    .await;
    (status, body)
}

/// The serious one: a file whose rows are complete must never be stamped
/// INCOMPLETE, and must never be given a cause that is not true of it.
///
/// The export's verdict used to be `Exhausted && !count_is_floor`, and
/// `count_is_floor` was ORed from every page's `count_is_lower_bound`. But that
/// flag is set by bounds on the COUNT — a per-page scan budget the next cursor
/// page resumes past, and a capped candidate window on the ranked routing's
/// extension post-filter — neither of which skips a row. So a walk that reached
/// the end of the enumeration, holding every matching artifact, ended with a
/// sentence telling the examiner that documents were missing from the search
/// index and that matches existed which were absent from this file and from
/// every other export of the query. That sentence goes into an exhibit.
#[tokio::test]
async fn a_walk_that_reached_the_end_is_not_stamped_incomplete_for_a_floored_total() {
    let (status, csv) = ranked_window_export("csv").await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        data_rows(&csv).len(),
        RANKED_WINDOW_DOCS,
        "the fixture is only meaningful if the walk actually reached the end"
    );
    // The fixture is doing what it claims: the stated population really is a
    // floor, and really is short of the truth.
    assert!(
        csv.contains("# matching_artifacts,at least "),
        "this fixture must produce a floored population, or it is testing \
         nothing: {}",
        csv.lines().take(12).collect::<Vec<_>>().join("\n")
    );

    let verdict = verdict(&csv).expect("a whole export ends with a verdict");
    assert!(
        !verdict.contains("VERDICT: INCOMPLETE"),
        "every matching artifact is in this file; stamping it INCOMPLETE tells \
         an examiner under oath that rows are missing when none are: {verdict}"
    );
    assert!(
        !verdict.contains("documents are missing from the search index"),
        "and the cause given was not true either — the index is whole, only the \
         count was bounded: {verdict}"
    );
    assert!(
        !verdict.contains("absent from this file"),
        "nothing is absent from this file: {verdict}"
    );
    // What it must say instead: the rows are all here, and the number the
    // preamble stated was a floor that the completed walk has now resolved.
    assert!(
        verdict.contains(&format!("{RANKED_WINDOW_DOCS}")),
        "the verdict must state the exact figure the walk established, which is \
         the row count of this file: {verdict}"
    );
    assert!(
        verdict.to_lowercase().contains("floor"),
        "and must say that the population stated in the preamble was a floor, \
         so a reader who compares the two is not left to guess which is right: \
         {verdict}"
    );
    assert!(
        verdict.contains("lower bound"),
        "and must reconcile the two numbers explicitly rather than printing \
         both and leaving the reader to pick: {verdict}"
    );
}

/// The same fact where a script reads it. A client that branches on `complete`
/// must not be told the file is short when it is whole, and must still be able
/// to see that the stated population was a floor.
#[tokio::test]
async fn the_json_verdict_separates_a_floored_total_from_missing_rows() {
    let (status, json) = ranked_window_export("json").await;
    assert_eq!(status, StatusCode::OK);

    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        parsed["results"].as_array().expect("results").len(),
        RANKED_WINDOW_DOCS
    );
    assert_eq!(
        parsed["population"]["matching_artifacts_is_floor"],
        json!(true),
        "the fixture must produce a floored population"
    );
    assert_eq!(
        parsed["completeness"]["complete"],
        json!(true),
        "the walk reached the end and no row is missing, so the file IS the \
         whole match set"
    );
    assert_eq!(
        parsed["completeness"]["walk_reached_end"],
        json!(true),
        "and the facts that decide that must be readable on their own, rather \
         than inferred from a flag that also moves for a bounded count"
    );
    assert_eq!(
        parsed["completeness"]["index_missing_documents"],
        json!(false),
        "nothing is missing from the index either"
    );
    assert_eq!(
        parsed["completeness"]["stated_total_was_floor"],
        json!(true),
        "while the qualification on the stated total stays visible: the \
         preamble said 'at least N' and a reader must be able to see that the \
         verdict resolved it"
    );
    assert_eq!(
        parsed["completeness"]["rows"],
        json!(RANKED_WINDOW_DOCS),
        "and the row count is the exact figure the floor was standing in for"
    );
}

// --- The outcome is recorded even when nobody is left to read the file ---

/// Every `search_export_completed` event on the case, newest first.
async fn export_outcome_events(db: &SqliteConnection, case_id: Uuid) -> Vec<String> {
    db.get_audit_log(case_id, 200, 0)
        .await
        .expect("audit log")
        .into_iter()
        .filter(|e| e["action"].as_str() == Some("search_export_completed"))
        .map(|e| e["details"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// Wait briefly for an outcome record to land.
///
/// The abandonment record is written from the release path rather than from the
/// request, so it is not ordered against the caller's next statement. A short
/// poll is the honest way to wait for it; a bare sleep would pass on a fast
/// machine and fail on a loaded one.
async fn await_export_outcome_events(db: &SqliteConnection, case_id: Uuid) -> Vec<String> {
    for _ in 0..200 {
        let events = export_outcome_events(db, case_id).await;
        if !events.is_empty() {
            return events;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    export_outcome_events(db, case_id).await
}

/// The record that exists FOR the abandoned case must fire on the abandoned
/// case.
///
/// `search_export_completed` is the custody record of an export's outcome, and
/// its whole justification is that without it the only evidence of an
/// interruption lives in a file the examiner may discard. It was written inside
/// the stream body after the drain loop — so when the examiner closed the tab
/// the generator was dropped mid-loop and neither the verdict row nor the audit
/// event was ever produced. In the one case it was added for, it was silent:
/// the server had no record that a partial exhibit had left it.
#[tokio::test]
async fn an_abandoned_export_records_its_outcome_even_though_no_file_says_so() {
    let (app, case_id, _service, db) = setup().await;
    assert!(
        export_outcome_events(&db, case_id).await.is_empty(),
        "nothing has been exported yet"
    );

    let response = app
        .clone()
        .oneshot(export_request(case_id, "csv", &format!("q={TERM}")))
        .await
        .unwrap();
    let mut stream = response.into_body().into_data_stream();

    // Enough frames that rows have gone out: this is the state that matters,
    // because the examiner is now holding part of an exhibit.
    let mut seen = 0usize;
    while seen < 3 {
        stream.next().await.expect("frames").expect("a frame");
        seen += 1;
    }

    // The examiner closes the tab.
    drop(stream);

    let events = await_export_outcome_events(&db, case_id).await;
    assert_eq!(
        events.len(),
        1,
        "an abandoned export must leave exactly one outcome record: without it \
         the server cannot show that a partial exhibit was produced, and the \
         only account of the interruption is a file that may be discarded"
    );
    let detail = &events[0];
    assert!(
        detail.contains("stopped: abandoned"),
        "and it must name the outcome as an abandonment rather than pass for an \
         ordinary one: {detail}"
    );
    assert!(
        detail.contains("complete: false"),
        "an abandoned download is a fragment with no verdict row, and the \
         record must not let it read as a finished export: {detail}"
    );
    assert!(
        detail.contains("rows: "),
        "and must say how much of the exhibit left the server, which is the \
         only measure of it anyone still has: {detail}"
    );
}

/// The path that already worked must keep working, and must not gain a second
/// record from the release path once the stream is dropped normally.
#[tokio::test]
async fn a_finished_export_records_exactly_one_outcome() {
    let (app, case_id, _service, db) = setup().await;

    let (status, _, csv) = export(&app, case_id, "csv", &format!("q={TERM}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(verdict(&csv).is_some());

    let events = await_export_outcome_events(&db, case_id).await;
    assert_eq!(
        events.len(),
        1,
        "one export, one outcome: a release path that recorded a second would \
         make the audit log claim two exports happened"
    );
    let detail = &events[0];
    assert!(detail.contains("complete: true"), "{detail}");
    assert!(detail.contains("stopped: exhausted"), "{detail}");
    assert!(
        detail.contains(&format!("rows: {DOCS}")),
        "and the row count is the one in the file: {detail}"
    );
}

// --- A purge landing mid-export is not written into the exhibit ---

/// THE LINE THE PIN MUST NOT CROSS.
///
/// The pin holds the segment files AND the store readers, so `searcher.doc()`
/// goes on returning the stored name and content of an artifact purged after the
/// pin was taken. An examiner starts a CSV export of a large case; thirty
/// seconds in, an admin runs a delete — material ruled privileged, out of scope,
/// or outside a warrant. Without this, the export runs for minutes more and
/// writes that destroyed evidence into the file the examiner then holds, which
/// is precisely the outcome the ruling existed to prevent. Disclosing it in the
/// preamble would not un-write it.
///
/// Before the pin existed, the purge's own commit moved the index snapshot and
/// the walk stopped. That posture is restored deliberately and narrowly: a pin
/// absorbs movement that ADDS or reorganises, and never movement that REMOVES.
#[tokio::test]
async fn a_purge_mid_export_stops_the_walk_and_the_file_names_the_purge() {
    let (app, case_id, service, _db) = setup().await;

    let response = app
        .clone()
        .oneshot(export_request(case_id, "csv", &format!("q={TERM}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The admin's delete lands between drain pages: the first page was read
    // before the handler returned, and the body is lazy.
    service.delete_case(case_id).await.expect("purge");

    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must not abort: the file has to survive to explain itself");
    let body = String::from_utf8(bytes.to_vec()).unwrap();

    let verdict = verdict(&body).expect("the file must still end with a verdict");
    assert!(
        verdict.contains("VERDICT: INCOMPLETE"),
        "a walk stopped by a purge is short, and the file must say so: {verdict}"
    );
    assert!(
        verdict.to_lowercase().contains("purge"),
        "and must name the purge as the cause. 'The export failed' would leave \
         the reader unable to tell evidence being destroyed from a server \
         fault, and re-running would not help either way: {verdict}"
    );
    assert!(
        data_rows(&body).len() < DOCS,
        "the walk must actually have been stopped, or this test proves nothing"
    );
    assert!(
        !verdict.contains("the export failed after row"),
        "and must not be reported as a generic failure that happens to mention \
         a purge in the engine's error text: a reader and a script both have to \
         be able to tell this outcome from a server fault: {verdict}"
    );

    // The same fact where a script reads it, rather than only in prose. A
    // stopped_because it has to grep the statement for is not a code.
    let (app, case_id, service, _db) = setup().await;
    let response = app
        .clone()
        .oneshot(export_request(case_id, "json", &format!("q={TERM}")))
        .await
        .unwrap();
    service.delete_case(case_id).await.expect("purge");
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert_eq!(
        parsed["completeness"]["stopped_because"],
        json!("purged"),
        "a purge must be its own outcome code, distinct from 'failed'"
    );
    assert_eq!(parsed["completeness"]["complete"], json!(false));
    assert_eq!(
        parsed["completeness"]["walk_reached_end"],
        json!(false),
        "rows really are missing from this file: the walk stopped before the \
         end of the enumeration"
    );
    assert_eq!(
        parsed["completeness"]["index_missing_documents"],
        json!(false),
        "and not because the index lost anything — the distinction the two \
         fields exist to keep"
    );
}
