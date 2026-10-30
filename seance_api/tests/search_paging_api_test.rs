//! Reaching match 1,001.
//!
//! `GET /cases/:id/search` used to take `q` and `limit` and nothing else. The
//! limit was clamped at 1,000, the response honestly reported "at least 34,000
//! matching artifacts", and there was no parameter, header or second endpoint
//! by which anything could ask for the 1,001st. An examiner who has to review
//! every hit — a keyword list, a disclosure obligation — could be told exactly
//! how many matches they had not seen and given no way to see them.
//!
//! These tests pin the route onward: an `offset` parameter, a page that states
//! which page it is, a stated ceiling on how deep the server will go, and a
//! count that keeps describing the match set rather than the page cut out of
//! it.

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

/// Build the router around a real Tantivy index seeded with [`DOCS`] matches.
///
/// The index directory is leaked deliberately, as `search_reindex_test` does,
/// because the service outlives the `TempDir` guard.
async fn setup() -> (axum::Router, Uuid) {
    let index_dir = tempfile::tempdir().unwrap();
    let service =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    std::mem::forget(index_dir);

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Search Paging Case", "examiner")
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
        search_service: Some(service),
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
    (router_with_auth(app_state, Some(auth_config)), case_id)
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

#[tokio::test]
async fn offset_walks_the_whole_match_set_exactly_once() {
    let (app, case_id) = setup().await;

    let mut seen: Vec<String> = Vec::new();
    let mut offset = 0;
    while offset < DOCS + 10 {
        let (status, body) =
            search(&app, case_id, &format!("q={TERM}&limit=10&offset={offset}")).await;
        assert_eq!(status, StatusCode::OK);
        seen.extend(ids(&body));
        offset += 10;
    }

    assert_eq!(
        seen.len(),
        DOCS,
        "paging the endpoint must yield every match exactly once"
    );
    let unique: std::collections::HashSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), DOCS, "no match may be served on two pages");
}

#[tokio::test]
async fn a_page_states_which_page_it_is_and_how_big_the_match_set_is() {
    let (app, case_id) = setup().await;

    let (status, body) = search(&app, case_id, &format!("q={TERM}&limit=10&offset=10")).await;
    assert_eq!(status, StatusCode::OK);
    // Without these two facts a screenshot of rows 11–20 is indistinguishable
    // from a screenshot of the whole result set, which is the confusion that
    // puts a wrong population into a witness statement.
    assert_eq!(body["offset"], 10);
    assert_eq!(body["total_count"], DOCS);
    assert_eq!(body["limit"], 10, "the APPLIED limit, after clamping");
    assert_eq!(body["results"].as_array().unwrap().len(), 10);
}

#[tokio::test]
async fn the_paging_ceiling_is_stated_and_enforced_rather_than_silently_applied() {
    let (app, case_id) = setup().await;

    let (_, body) = search(&app, case_id, &format!("q={TERM}&limit=10")).await;
    let max_offset = body["max_offset"].as_u64().expect("max_offset stated");
    assert!(max_offset > 0);

    // Past the ceiling the server refuses and says so. It does not quietly
    // serve a different page than the one asked for: a clamped offset would
    // make the rows on screen belong to a page the caller never requested,
    // which is exactly the silent-cap defect this endpoint is being fixed for.
    let (status, body) = search(
        &app,
        case_id,
        &format!("q={TERM}&limit=10&offset={}", max_offset + 1),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains(&max_offset.to_string()),
        "the refusal must name the ceiling it enforced, got: {message}"
    );
}

#[tokio::test]
async fn every_page_names_the_index_snapshot_it_was_served_from() {
    let (app, case_id) = setup().await;

    let (_, first) = search(&app, case_id, &format!("q={TERM}&limit=10&offset=0")).await;
    let (_, second) = search(&app, case_id, &format!("q={TERM}&limit=10&offset=10")).await;

    let snapshot = first["index_snapshot"].as_str().expect("snapshot");
    assert!(!snapshot.is_empty());
    // Pages of one unchanged index join up, and say so. A reader that finds two
    // different values knows its enumeration moved under it — which is the only
    // way ingest running during a paged review can be disclosed rather than
    // silently producing a walk that repeats and skips rows.
    assert_eq!(second["index_snapshot"].as_str(), Some(snapshot));
}

#[tokio::test]
async fn a_negative_or_unparsable_offset_is_refused_not_read_as_zero() {
    let (app, case_id) = setup().await;

    for bad in ["-5", "abc", "1e3"] {
        let (status, _) = search(&app, case_id, &format!("q={TERM}&limit=10&offset={bad}")).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "offset={bad} must be refused; silently reading it as 0 would serve \
             page 1 while the caller believes it asked for another page"
        );
    }
}

#[tokio::test]
async fn omitting_offset_is_the_first_page() {
    let (app, case_id) = setup().await;

    let (_, without) = search(&app, case_id, &format!("q={TERM}&limit=5")).await;
    let (_, with_zero) = search(&app, case_id, &format!("q={TERM}&limit=5&offset=0")).await;
    assert_eq!(ids(&without), ids(&with_zero));
    assert_eq!(without["offset"], 0);
}
