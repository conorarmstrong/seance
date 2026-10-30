//! Reaching match 100,101.
//!
//! Offset paging gave the endpoint a route to the 1,001st match and a ceiling at
//! the 100,000th. The ceiling was not arbitrary: the server serves an offset by
//! walking the case from the beginning and discarding what it passes, so every
//! page costs a full walk and reading a result set page by page costs one walk
//! per page. Capping the offset capped that bill by declaring the matches past
//! it unreachable — and the export ceiling was the same number, so they were
//! unreachable by every route the product had. An examiner under an obligation
//! to review every hit was told how many hits they could not open.
//!
//! `?cursor=` is the route onward. It names the position the last page reached
//! rather than a distance from the start, so the server resumes instead of
//! re-walking and no depth is out of reach.
//!
//! What it cannot do is survive the index changing underneath it, and this
//! product's whole premise is working a case while it is still being ingested.
//! So these tests pin the refusal as hard as they pin the walk: a cursor whose
//! snapshot has moved comes back 409 with a code the client can branch on, and
//! never as a page of rows that look like a continuation of a set that gained
//! members at the seam.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
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
const DOCS: usize = 25;

/// A term every seeded document contains.
const TERM: &str = "kestrel";

/// The router, the case, and the live search service — the last so a test can
/// commit to the index mid-walk, which is the case that matters most here.
///
/// The index directory is leaked deliberately, as the other search API tests
/// do, because the service outlives the `TempDir` guard.
async fn setup() -> (
    axum::Router,
    Uuid,
    Arc<seance_search::SearchService>,
    Arc<SqliteConnection>,
) {
    let index_dir = tempfile::tempdir().unwrap();
    let service =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    std::mem::forget(index_dir);

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Search Cursor Case", "examiner")
        .await
        .unwrap();

    for i in 0..DOCS {
        let artifact = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": format!("note_{i:03}.txt"),
                "content": format!("{TERM} observation {i}"),
            }),
        );
        service
            .add_artifact_to_index_sync(&artifact)
            .expect("index");
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

async fn search(app: &axum::Router, case_id: Uuid, query: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{}/search?{}", case_id, query))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn ids(body: &Value) -> Vec<String> {
    body["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|r| r["artifact_id"].as_str().unwrap().to_string())
        .collect()
}

fn next_cursor(body: &Value) -> Option<String> {
    body["next_cursor"].as_str().map(|s| s.to_string())
}

#[tokio::test]
async fn a_cursor_walk_over_the_endpoint_reaches_every_match_exactly_once() {
    let (app, case_id, _service, _db) = setup().await;

    let mut seen: Vec<String> = Vec::new();
    let mut query = format!("q={TERM}&limit=10");
    let mut requests = 0;
    loop {
        let (status, body) = search(&app, case_id, &query).await;
        assert_eq!(status, StatusCode::OK);
        seen.extend(ids(&body));
        requests += 1;
        assert!(requests < 20, "the walk must terminate");
        match next_cursor(&body) {
            Some(cursor) => query = format!("q={TERM}&limit=10&cursor={cursor}"),
            None => break,
        }
    }

    assert_eq!(
        seen.len(),
        DOCS,
        "walking by cursor must yield every match exactly once"
    );
    let unique: std::collections::HashSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), DOCS, "no match may be served on two pages");
}

#[tokio::test]
async fn a_cursor_walk_and_an_offset_walk_are_the_same_enumeration() {
    let (app, case_id, _service, _db) = setup().await;

    let mut by_cursor: Vec<String> = Vec::new();
    let mut query = format!("q={TERM}&limit=7");
    loop {
        let (_, body) = search(&app, case_id, &query).await;
        by_cursor.extend(ids(&body));
        match next_cursor(&body) {
            Some(cursor) => query = format!("q={TERM}&limit=7&cursor={cursor}"),
            None => break,
        }
    }

    let mut by_offset: Vec<String> = Vec::new();
    let mut offset = 0;
    while offset < DOCS {
        let (_, body) = search(&app, case_id, &format!("q={TERM}&limit=7&offset={offset}")).await;
        by_offset.extend(ids(&body));
        offset += 7;
    }

    assert_eq!(
        by_cursor, by_offset,
        "the two routes index into ONE enumeration; if they disagree, a screen \
         that mixes them is showing two different result sets as one"
    );
}

#[tokio::test]
async fn the_last_page_offers_no_cursor_and_states_its_position() {
    let (app, case_id, _service, _db) = setup().await;

    let mut query = format!("q={TERM}&limit=10");
    let mut pages = 0;
    let last;
    loop {
        let (_, body) = search(&app, case_id, &query).await;
        pages += 1;
        match next_cursor(&body) {
            Some(cursor) => query = format!("q={TERM}&limit=10&cursor={cursor}"),
            None => {
                last = body;
                break;
            }
        }
    }
    assert_eq!(pages, 3, "25 matches at 10 a page is three pages");
    // An absent cursor is a claim that the set ended here, and the position the
    // page states is what makes that claim checkable: 21-25 of 25.
    assert_eq!(last["offset"], 20);
    assert_eq!(last["total_count"], DOCS);
    assert_eq!(last["results"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn a_cursor_page_states_where_it_is_and_how_big_the_set_is() {
    let (app, case_id, _service, _db) = setup().await;

    let (_, first) = search(&app, case_id, &format!("q={TERM}&limit=10")).await;
    let cursor = next_cursor(&first).expect("more matches follow the first page");
    let (status, second) =
        search(&app, case_id, &format!("q={TERM}&limit=10&cursor={cursor}")).await;

    assert_eq!(status, StatusCode::OK);
    // The two facts a screenshot needs to mean anything on its own.
    assert_eq!(second["offset"], 10, "matches 11-20, and it says so");
    assert_eq!(
        second["total_count"], DOCS,
        "the count describes the match set, not the page cut out of it"
    );
    assert_eq!(second["limit"], 10);
    assert_eq!(
        second["index_snapshot"], first["index_snapshot"],
        "one walk of one snapshot"
    );
}

#[tokio::test]
async fn a_cursor_is_refused_when_the_index_moved_rather_than_re_based() {
    let (app, case_id, service, _db) = setup().await;

    let (_, first) = search(&app, case_id, &format!("q={TERM}&limit=10")).await;
    let cursor = next_cursor(&first).expect("more matches follow");

    // Ingest committing mid-walk is the ordinary case on a live case, not an
    // edge one.
    let late = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "late.txt", "content": format!("{TERM} arrived late") }),
    );
    service.add_artifact_to_index_sync(&late).expect("index");
    service.commit_sync().expect("commit");

    let (status, body) = search(&app, case_id, &format!("q={TERM}&limit=10&cursor={cursor}")).await;

    // 409, not 400 and not 500: the request was well formed and the server is
    // healthy. What changed is the world the cursor described.
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a superseded cursor must be refused, not served: body {body}"
    );
    assert_eq!(
        body["error"]["code"], "SEARCH_CURSOR_REFUSED",
        "the client has to be able to tell this from a malformed request \
         WITHOUT reading the prose"
    );
    assert_eq!(body["error"]["details"]["refusal"], "index_moved");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("first page"),
        "the refusal must tell the examiner what to do next, got: {message}"
    );
    // And nothing that looks like a page of results came back with it.
    assert!(
        body["results"].is_null(),
        "a refusal must not also carry rows"
    );
}

#[tokio::test]
async fn a_cursor_for_a_different_query_is_refused() {
    let (app, case_id, _service, _db) = setup().await;

    let (_, first) = search(&app, case_id, &format!("q={TERM}&limit=10")).await;
    let cursor = next_cursor(&first).expect("more matches follow");

    // A position in one result set says nothing about another. Serving it would
    // number rows against a match count they have nothing to do with.
    let (status, body) = search(
        &app,
        case_id,
        &format!("q=observation&limit=10&cursor={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "SEARCH_CURSOR_REFUSED");
    assert_eq!(body["error"]["details"]["refusal"], "query_changed");
}

#[tokio::test]
async fn a_malformed_cursor_is_refused_rather_than_read_as_the_first_page() {
    let (app, case_id, _service, _db) = setup().await;

    for bad in ["abc", "zz", "00", "deadbeef"] {
        let (status, body) =
            search(&app, case_id, &format!("q={TERM}&limit=10&cursor={bad}")).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "cursor={bad} must be refused; serving page one instead would tell a \
             client that believes it is deep in a walk that it is at the top"
        );
        assert_eq!(
            body["error"]["code"], "SEARCH_CURSOR_REFUSED",
            "cursor={bad}"
        );
        assert_eq!(
            body["error"]["details"]["refusal"], "malformed",
            "cursor={bad}"
        );
    }
}

#[tokio::test]
async fn an_empty_cursor_parameter_is_the_first_page() {
    let (app, case_id, _service, _db) = setup().await;

    // `?cursor=` is what a client sends when it has cleared the parameter but
    // left it in the query string. It is an absent position, not a broken one.
    let (status, body) = search(&app, case_id, &format!("q={TERM}&limit=5&cursor=")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["offset"], 0);
    let (_, plain) = search(&app, case_id, &format!("q={TERM}&limit=5")).await;
    assert_eq!(ids(&body), ids(&plain));
}

#[tokio::test]
async fn a_request_naming_both_an_offset_and_a_cursor_is_refused() {
    let (app, case_id, _service, _db) = setup().await;

    let (_, first) = search(&app, case_id, &format!("q={TERM}&limit=10")).await;
    let cursor = next_cursor(&first).expect("more matches follow");

    // The two need not name the same place. Picking one by precedence would put
    // rows on screen belonging to a page the client did not ask for — the same
    // defect a silently clamped offset would be.
    let (status, body) = search(
        &app,
        case_id,
        &format!("q={TERM}&limit=10&offset=10&cursor={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("cursor") && message.contains("offset"),
        "the refusal must name both parameters, got: {message}"
    );
}

#[tokio::test]
async fn the_offset_ceiling_refusal_points_at_the_route_that_does_reach() {
    let (app, case_id, _service, _db) = setup().await;

    let (_, body) = search(&app, case_id, &format!("q={TERM}&limit=10")).await;
    let max_offset = body["max_offset"].as_u64().expect("max_offset stated");

    let (status, body) = search(
        &app,
        case_id,
        &format!("q={TERM}&limit=10&offset={}", max_offset + 1),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"]["message"].as_str().unwrap_or_default();
    // The ceiling still binds on the random-access form, but it is no longer
    // the end of the evidence, and the refusal must not imply that it is. It
    // used to say the matches beyond it were unreachable and that narrowing the
    // query was the only option; that is now untrue.
    assert!(
        message.contains("next_cursor"),
        "the refusal must name the route that does reach, got: {message}"
    );
    assert!(
        !message.contains("not reachable"),
        "the refusal must no longer claim the matches beyond it cannot be \
         reached, got: {message}"
    );
    // Two routes reach past the ceiling, and naming only one leaves an examiner
    // who wants the whole set clicking Next several thousand times. The export
    // walks the same enumeration to the end in one request and is the answer to
    // "I need to review everything"; a refusal that omits it reads as a dead
    // end to anyone whose actual task is not "look at page 3,400".
    assert!(
        message.contains("export"),
        "the refusal must also name the export, which walks the whole match set \
         in one request, got: {message}"
    );
    // And the ceiling has to read as a bound on ONE FORM of the request rather
    // than as a bound on the evidence.
    assert!(
        message.contains("random-access"),
        "the refusal must say which form of the request it bounds, got: \
         {message}"
    );
}

#[tokio::test]
async fn every_page_reports_what_it_cost_to_serve() {
    let (app, case_id, _service, _db) = setup().await;

    // `examined_documents` is the claim behind removing the ceiling, on the
    // wire where an operator can watch it: an offset page on a scan routing
    // re-reads the whole case, a cursor page reads only what lies ahead of it.
    let (_, first) = search(&app, case_id, &format!("q={TERM}&limit=5")).await;
    assert_eq!(
        first["examined_documents"], DOCS,
        "an offset page walks the case to reach its rows"
    );

    let cursor = next_cursor(&first).expect("more matches follow");
    let (_, second) = search(&app, case_id, &format!("q={TERM}&limit=5&cursor={cursor}")).await;
    let examined = second["examined_documents"].as_u64().expect("stated");
    assert!(
        examined <= 6,
        "a resumed page examined {examined} documents to return 5 rows; it must \
         not re-read the page behind it"
    );
}

#[tokio::test]
async fn the_audit_trail_records_which_route_reached_the_page() {
    let (app, case_id, _service, db) = setup().await;

    let (_, first) = search(&app, case_id, &format!("q={TERM}&limit=10")).await;
    let cursor = next_cursor(&first).expect("more matches follow");
    let (status, _) = search(&app, case_id, &format!("q={TERM}&limit=10&cursor={cursor}")).await;
    assert_eq!(status, StatusCode::OK);

    let entries = db.get_audit_log(case_id, 50, 0).await.expect("audit log");
    let details: Vec<String> = entries
        .iter()
        .filter(|e| e["action"] == "search_executed")
        .filter_map(|e| e["details"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        details.iter().any(|d| d.contains("reached by offset")),
        "the first page was a jump, and the record must say so: {details:?}"
    );
    assert!(
        details.iter().any(|d| d.contains("reached by cursor")),
        "the second page continued a pinned walk, which is a different claim \
         about what was on screen: {details:?}"
    );
}

/// A jump to an offset the extension-filtered ranked routing cannot reach is
/// refused, not answered with an empty page (SHIP-034).
///
/// The extension filter runs after retrieval over a bounded candidate window,
/// so on a case where the wanted extension is thinly spread the deepest
/// position a jump can reach is small and data-dependent. An empty page there
/// is shaped exactly like the end of the match set; the refusal says how far a
/// jump reaches, that the match set goes on, and which routes reach it.
#[tokio::test]
async fn a_jump_past_the_filtered_window_is_refused_and_names_the_routes_that_reach() {
    let (app, case_id, service, _db) = setup().await;

    // Bury the 25 `.txt` notes the fixture seeds under 3,000 `.log` files that
    // match the same term, so a window sized for offset 100 holds only a
    // handful of `.txt` survivors.
    for i in 0..3_000 {
        let artifact = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": format!("daemon_{i:05}.log"),
                "content": format!("{TERM} logged {i}"),
            }),
        );
        service
            .add_artifact_to_index_sync(&artifact)
            .expect("index");
    }
    service.commit_sync().expect("commit");

    // The first page is always served, even when the window holds no
    // survivor: it carries the cursor a walk past the window starts from.
    let (status, first) = search(
        &app,
        case_id,
        &format!("q=%22{TERM}%22&limit=10&extensions=txt"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the first page is never refused: {first}"
    );
    assert!(
        first["next_cursor"].is_string(),
        "an exhausted first window must hand over a cursor: {first}"
    );

    let (status, body) = search(
        &app,
        case_id,
        &format!("q=%22{TERM}%22&limit=10&extensions=txt&offset=100"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a jump past the reachable band must be refused, not served empty: {body}"
    );
    assert_eq!(
        body["error"]["code"], "SEARCH_OFFSET_UNREACHABLE",
        "the client must be able to tell this from a refused cursor and from a \
         malformed request without reading the prose: {body}"
    );
    let details = &body["error"]["details"];
    assert_eq!(details["offset"], 100);
    let reachable = details["reachable"].as_u64().expect("reach stated");
    let examined = details["examined"].as_u64().expect("examined stated");
    assert!(reachable < 100 && examined >= reachable, "{details}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    for must_say in ["not the end of the match set", "next_cursor", "export"] {
        assert!(
            message.contains(must_say),
            "the refusal must say {must_say:?}, got: {message}"
        );
    }
    assert!(
        body["results"].is_null(),
        "a refusal must not also carry rows"
    );

    // That the route it names actually gets there — a cursor walk from the
    // first page reaching every `.txt` match the jump could not — is pinned in
    // the engine, on a pinned snapshot
    // (`a_deep_offset_under_an_extension_filter_is_refused_not_served_empty`).
    // A fixture this size is still being merged in the background when the
    // walk would start, and an unpinned walk over the endpoint is then refused
    // for the index having moved: the right answer, and not the one under test.
}
