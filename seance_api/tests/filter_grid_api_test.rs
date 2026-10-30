//! A saved filter's population, opened in the file grid.
//!
//! The compound filter builder can save a filter and `/filters/:id/apply` can
//! count and page its matches, but that listing is its own: no grid sort, no
//! grid selection, no grid export. A filter is the one instrument in this
//! product that DEFINES a population, so the population it defines has to be
//! openable in the view that works on populations.
//!
//! Two things must survive that journey and both are asserted here.
//!
//! The first is that the grid's population is the filter's population — the same
//! evaluator, not a second one that agrees most of the time. Where two engines
//! disagreed, the grid would list a different set of files from the one the
//! apply endpoint counted and nothing on either screen would say which was
//! right.
//!
//! The second is the disclosure. The apply path reports `scan_complete` and
//! `undecodable`; a filtered grid that scanned part of the case must carry them
//! too, alongside its own ceiling on how much of a population it will list.

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

/// Four files and one parsed record. The record matters: it matches the filter
/// on size but is not a FileEntry, so the grid legitimately lists fewer rows
/// than the filter matched, and the response has to say which number is which.
fn population() -> Vec<(ArtifactType, Value)> {
    vec![
        (
            ArtifactType::FileEntry,
            json!({"name": "alpha.jpg", "size": 5_000_000}),
        ),
        (
            ArtifactType::FileEntry,
            json!({"name": "bravo.jpg", "size": 9_000_000}),
        ),
        (
            ArtifactType::FileEntry,
            json!({"name": "charlie.jpg", "size": 10}),
        ),
        (
            ArtifactType::FileEntry,
            json!({"name": "delta.txt", "size": 8_000_000}),
        ),
        (
            ArtifactType::ParsedRecord,
            json!({"type": "Doc", "name": "echo-record", "size": 7_000_000}),
        ),
    ]
}

async fn setup() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Filter Grid", "examiner").await.unwrap();

    for (artifact_type, metadata) in population() {
        let artifact = Artifact::new(case_id, artifact_type, None, metadata);
        db.record_artifact(&artifact).await.unwrap();
    }

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: None,
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

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn get(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    (status, json_body(response).await)
}

async fn save_filter(app: &axum::Router, case_id: Uuid, name: &str, condition: Value) -> Uuid {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{case_id}/filters"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": name, "filter": condition}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    Uuid::parse_str(body["id"].as_str().expect("filter id")).expect("uuid")
}

fn big_files() -> Value {
    json!({"type": "simple", "field": "size", "operator": "gt", "value": 1_000_000})
}

fn names(body: &Value) -> Vec<String> {
    body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["name"].as_str().unwrap_or("?").to_string())
        .collect()
}

#[tokio::test]
async fn the_grid_lists_the_saved_filters_population() {
    let (app, case_id) = setup().await;
    let filter_id = save_filter(&app, case_id, "over 1 MB", big_files()).await;

    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/files?filter_id={filter_id}&sort=name&order=asc"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(names(&body), vec!["alpha.jpg", "bravo.jpg", "delta.txt"]);
    assert_eq!(body["total_count"], 3);
}

#[tokio::test]
async fn the_grid_states_the_filters_own_match_count_beside_what_it_listed() {
    let (app, case_id) = setup().await;
    let filter_id = save_filter(&app, case_id, "over 1 MB", big_files()).await;

    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/files?filter_id={filter_id}"),
    )
    .await;

    let filter = &body["filter"];
    assert_eq!(filter["filter_id"], filter_id.to_string());
    assert_eq!(filter["filter_name"], "over 1 MB");
    assert_eq!(
        filter["matched"], 4,
        "the filter matched four artifacts, one of which is a parsed record"
    );
    assert_eq!(
        filter["listed"], 3,
        "the file grid can only show FileEntry rows; the gap must be stated, not \
         left to look like rows going missing"
    );
    assert_eq!(filter["scan_complete"], true);
    assert_eq!(filter["undecodable"], 0);
    assert_eq!(filter["population_capped"], false);
    assert_eq!(filter["inventory_incomplete"], false);
    assert_eq!(filter["inventory_incomplete_reason"], Value::Null);
}

#[tokio::test]
async fn a_grid_with_no_filter_carries_no_filter_block_at_all() {
    let (app, case_id) = setup().await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/files")).await;
    assert!(
        body.get("filter").is_none(),
        "an absent block is 'no filter was applied'; a present block with zeroes \
         would read as 'a filter was applied and everything was fine'"
    );
    assert_eq!(body["total_count"], 4, "every FileEntry in the case");
}

#[tokio::test]
async fn the_grids_own_filters_narrow_the_population_further() {
    let (app, case_id) = setup().await;
    let filter_id = save_filter(&app, case_id, "over 1 MB", big_files()).await;

    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/files?filter_id={filter_id}&extension=jpg&sort=name"),
    )
    .await;
    assert_eq!(names(&body), vec!["alpha.jpg", "bravo.jpg"]);
    assert_eq!(body["total_count"], 2);
    assert_eq!(
        body["filter"]["matched"], 4,
        "the filter's population is unchanged by the grid narrowing it"
    );
    assert_eq!(body["filter"]["listed"], 2);
}

#[tokio::test]
async fn a_filter_that_matches_nothing_opens_an_empty_grid_not_the_whole_case() {
    let (app, case_id) = setup().await;
    let filter_id = save_filter(
        &app,
        case_id,
        "impossible",
        json!({"type": "simple", "field": "size", "operator": "gt", "value": 999_999_999_999i64}),
    )
    .await;

    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/files?filter_id={filter_id}"),
    )
    .await;
    assert_eq!(
        body["total_count"], 0,
        "an empty population rendered as no restriction would show an examiner \
         the entire case under a filter's name"
    );
    assert!(body["items"].as_array().unwrap().is_empty());
    assert_eq!(body["filter"]["matched"], 0);
}

#[tokio::test]
async fn a_filter_from_another_case_is_not_found_rather_than_applied() {
    let (app, case_id) = setup().await;
    let stranger = Uuid::new_v4();

    let (status, _body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/files?filter_id={stranger}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_source_scoped_grid_takes_a_filter_too() {
    let (app, case_id) = setup().await;
    let filter_id = save_filter(&app, case_id, "over 1 MB", big_files()).await;

    // No source subtree exists in this fixture, so the population intersected
    // with an empty subtree is empty — but the filter block must still be there,
    // stating what the filter matched.
    let source = Uuid::new_v4();
    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/sources/{source}/files?filter_id={filter_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["total_count"], 0);
    assert_eq!(body["filter"]["matched"], 4);
}

#[tokio::test]
async fn the_grid_pages_a_filters_population_without_repeating_a_row() {
    let (app, case_id) = setup().await;
    let filter_id = save_filter(&app, case_id, "over 1 MB", big_files()).await;

    let mut seen: Vec<String> = Vec::new();
    for page in 1..=3 {
        let (_, body) = get(
            &app,
            format!(
                "/api/v1/cases/{case_id}/files?filter_id={filter_id}&sort=name&page={page}&page_size=1"
            ),
        )
        .await;
        assert_eq!(body["total_count"], 3);
        assert_eq!(body["total_pages"], 3);
        seen.extend(names(&body));
    }
    assert_eq!(seen, vec!["alpha.jpg", "bravo.jpg", "delta.txt"]);
}
