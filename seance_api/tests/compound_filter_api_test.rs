//! What a compound filter actually means, end to end.
//!
//! `seance_core::filter` evaluates arbitrary AND/OR/NOT trees, and the client's
//! type model has always described them, but no screen could build one and
//! nothing exercised the nested shapes over the wire. Before a UI is put on top
//! of an evaluator, the population it returns has to be pinned: a filter is a
//! POPULATION-DEFINING instrument in this product — its result is what gets
//! bulk-tagged, exported and counted in a statement — so a tree that evaluates
//! subtly differently from how the screen reads is not a cosmetic bug, it is a
//! wrong answer about the evidence.
//!
//! These tests run through the real endpoints (`POST /cases/:id/filters` then
//! `GET /cases/:id/filters/:id/apply`) with the exact JSON the client model
//! serialises, so they cover the serde tagging and the SQL-backed scan as well
//! as the predicate logic. They are written against the evaluator AS IT STANDS,
//! to find out what it does rather than to assert what it ought to do.
//!
//! The one that matters most is [`an_empty_and_matches_every_artifact`]. An AND
//! with no conditions is vacuously TRUE, so a filter saved with an empty
//! condition list silently matches the entire case while carrying a name that
//! says otherwise. That is the single worst thing a builder UI could emit, and
//! the reason the builder refuses to.

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

/// The case's whole population, six artifacts chosen so that every trap below
/// has a row that falls into it.
///
/// `echo.jpg` carries NO `deleted` key at all. Absent is not false here — it is
/// null, and a null compares unequal to both `true` and `false` — which is the
/// asymmetry a builder has to be honest about, because "not deleted" and "no
/// deletion state recorded" are different findings about a disk.
fn population() -> Vec<(&'static str, Value)> {
    vec![
        (
            "alpha.exe",
            json!({"name": "alpha.exe", "deleted": true, "size": 2_000_000}),
        ),
        (
            "bravo.exe",
            json!({"name": "bravo.exe", "deleted": false, "size": 4_000_000}),
        ),
        (
            "charlie.dll",
            json!({"name": "charlie.dll", "deleted": true, "size": 10}),
        ),
        (
            "delta.txt",
            json!({"name": "delta.txt", "deleted": true, "size": 9_000_000}),
        ),
        // No `deleted` key: the field is absent, not false.
        ("echo.jpg", json!({"name": "echo.jpg", "size": 8_000_000})),
        (
            "foxtrot.jpg",
            json!({"name": "foxtrot.jpg", "deleted": false, "size": 1}),
        ),
    ]
}

async fn setup() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Compound Filter Case", "examiner")
        .await
        .unwrap();

    for (_, metadata) in population() {
        let artifact = Artifact::new(case_id, ArtifactType::FileEntry, None, metadata);
        db.record_artifact(&artifact).await.expect("record");
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

/// Save `condition` as a named filter and return its id.
async fn save(app: &axum::Router, case_id: Uuid, name: &str, condition: Value) -> Uuid {
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
    assert_eq!(response.status(), StatusCode::OK, "saving {name}");
    let body = json_body(response).await;
    Uuid::parse_str(body["id"].as_str().expect("filter id")).expect("uuid")
}

/// The names this filter matches, sorted, plus the stated total.
async fn matched(app: &axum::Router, case_id: Uuid, filter_id: Uuid) -> (Vec<String>, u64) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{case_id}/filters/{filter_id}/apply?limit=100&offset=0"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let mut names: Vec<String> = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| r["metadata"]["name"].as_str().unwrap_or("?").to_string())
        .collect();
    names.sort();
    (names, body["total"].as_u64().expect("total"))
}

/// Save and apply in one step, for the many tests that do nothing else.
async fn population_of(app: &axum::Router, case_id: Uuid, name: &str, cond: Value) -> Vec<String> {
    let id = save(app, case_id, name, cond).await;
    matched(app, case_id, id).await.0
}

fn simple(field: &str, operator: &str, value: Value) -> Value {
    json!({"type": "simple", "field": field, "operator": operator, "value": value})
}

#[tokio::test]
async fn a_two_level_tree_mixing_and_with_or_matches_the_population_it_reads_as() {
    // "(an executable OR a big file) AND deleted" — the shape the bread-and-
    // butter triage query takes, and the first one the old single-condition
    // form could not express at all.
    let (app, case_id) = setup().await;

    let names = population_of(
        &app,
        case_id,
        "deleted executables or big deleted files",
        json!({
            "type": "compound",
            "logic": "and",
            "conditions": [
                {
                    "type": "compound",
                    "logic": "or",
                    "conditions": [
                        simple("extension", "in", json!(["exe", "dll"])),
                        simple("size", "gt", json!(5_000_000)),
                    ],
                },
                simple("deleted", "eq", json!(true)),
            ],
        }),
    )
    .await;

    assert_eq!(
        names,
        vec!["alpha.exe", "charlie.dll", "delta.txt"],
        "nesting must bind as written: bravo.exe is an executable but not \
         deleted, echo.jpg is big but has no deletion state, foxtrot.jpg is \
         neither"
    );
}

#[tokio::test]
async fn an_empty_and_matches_every_artifact_in_the_case() {
    // Vacuous truth. This is not a defect in the evaluator — it is what an
    // empty conjunction means — but it is a loaded gun pointed at the UI: a
    // filter called "Deleted executables" whose condition list is empty matches
    // the entire case and says nothing about it. The builder must be incapable
    // of emitting this, and this test is what makes that requirement concrete.
    let (app, case_id) = setup().await;

    let names = population_of(
        &app,
        case_id,
        "empty and",
        json!({"type": "compound", "logic": "and", "conditions": []}),
    )
    .await;

    assert_eq!(names.len(), population().len());
}

#[tokio::test]
async fn an_empty_or_matches_nothing() {
    // The mirror image, and just as dangerous in the other direction: a filter
    // that reads as a question about the evidence and returns "0 matches" from
    // having asked nothing at all.
    let (app, case_id) = setup().await;

    let names = population_of(
        &app,
        case_id,
        "empty or",
        json!({"type": "compound", "logic": "or", "conditions": []}),
    )
    .await;

    assert!(names.is_empty());
}

#[tokio::test]
async fn a_compound_with_a_single_child_is_exactly_that_child() {
    let (app, case_id) = setup().await;

    let wrapped = population_of(
        &app,
        case_id,
        "one child",
        json!({
            "type": "compound",
            "logic": "and",
            "conditions": [simple("extension", "eq", json!("jpg"))],
        }),
    )
    .await;
    let bare = population_of(
        &app,
        case_id,
        "bare",
        simple("extension", "eq", json!("jpg")),
    )
    .await;

    assert_eq!(wrapped, vec!["echo.jpg", "foxtrot.jpg"]);
    assert_eq!(wrapped, bare, "wrapping a condition must not change it");
}

#[tokio::test]
async fn a_negation_inside_an_or_negates_only_its_own_branch() {
    // NOT binds to the condition it wraps, not to the branch it sits in. The
    // row that proves it is echo.jpg: it has no `deleted` key, so `deleted = true`
    // is false for it, so NOT(deleted = true) is TRUE — an artifact with no
    // recorded deletion state satisfies "not deleted". That is defensible and it
    // is also a trap, which is why the builder names the operator rather than
    // offering a "not deleted" checkbox that hides it.
    let (app, case_id) = setup().await;

    let names = population_of(
        &app,
        case_id,
        "not deleted, or a dll",
        json!({
            "type": "compound",
            "logic": "or",
            "conditions": [
                {"type": "not", "condition": simple("deleted", "eq", json!(true))},
                simple("extension", "eq", json!("dll")),
            ],
        }),
    )
    .await;

    assert_eq!(
        names,
        vec!["bravo.exe", "charlie.dll", "echo.jpg", "foxtrot.jpg"],
        "charlie.dll is deleted and still matches, through the OR's second \
         branch; echo.jpg matches because absent is not true"
    );
}

#[tokio::test]
async fn an_absent_field_is_absent_and_not_false() {
    // Three questions that would collapse into one if absent meant false.
    let (app, case_id) = setup().await;

    let is_true = population_of(
        &app,
        case_id,
        "deleted true",
        simple("deleted", "eq", json!(true)),
    )
    .await;
    let is_false = population_of(
        &app,
        case_id,
        "deleted false",
        simple("deleted", "eq", json!(false)),
    )
    .await;
    let recorded = population_of(
        &app,
        case_id,
        "deleted exists",
        simple("deleted", "exists", json!(true)),
    )
    .await;

    assert_eq!(is_true, vec!["alpha.exe", "charlie.dll", "delta.txt"]);
    assert_eq!(
        is_false,
        vec!["bravo.exe", "foxtrot.jpg"],
        "echo.jpg has no deletion state; it must not be counted as not-deleted"
    );
    assert_eq!(
        recorded.len(),
        5,
        "five of six artifacts record the field at all"
    );
    assert!(!recorded.contains(&"echo.jpg".to_string()));
}

#[tokio::test]
async fn the_stated_total_counts_the_matched_population_not_the_returned_page() {
    // The filters screen prints this number beside a filter's name, and a page
    // size masquerading as a match count is the same defect class the search
    // page's `total_count` exists to avoid.
    let (app, case_id) = setup().await;
    let id = save(
        &app,
        case_id,
        "everything",
        simple("artifact_type", "eq", json!("FileEntry")),
    )
    .await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/cases/{case_id}/filters/{id}/apply?limit=2&offset=0"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = json_body(response).await;

    assert_eq!(body["results"].as_array().unwrap().len(), 2);
    assert_eq!(body["total"].as_u64(), Some(population().len() as u64));
}

#[tokio::test]
async fn a_saved_compound_survives_the_round_trip_through_storage() {
    // The condition is stored as JSON and re-parsed on every apply, so the
    // shape the client writes has to be the shape the evaluator reads. A tag or
    // an operator spelling that does not survive would fail here rather than in
    // front of an examiner as a filter that matches nothing.
    let (app, case_id) = setup().await;
    let condition = json!({
        "type": "compound",
        "logic": "and",
        "conditions": [
            simple("name", "starts_with", json!("alpha")),
            {"type": "not", "condition": simple("size", "lt", json!(1000))},
        ],
    });
    let id = save(&app, case_id, "round trip", condition.clone()).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{case_id}/filters/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let stored = json_body(response).await;
    assert_eq!(stored["filter"], condition);

    assert_eq!(matched(&app, case_id, id).await.0, vec!["alpha.exe"]);
}

#[tokio::test]
async fn a_filter_apply_states_whether_it_saw_the_whole_case() {
    // The screen reads these two fields to decide whether a match count is a
    // count or a floor. They have to be present on an ordinary, complete apply
    // as well, because "absent" is read as "not stated" rather than as "fine".
    let (app, case_id) = setup().await;
    let id = save(&app, case_id, "all", simple("name", "exists", json!(true))).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{case_id}/filters/{id}/apply"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = json_body(response).await;

    assert_eq!(body["scan_complete"], json!(true));
    assert_eq!(body["undecodable"], json!(0));
}
