//! The review ledger over the wire.
//!
//! The ledger's whole reason to exist is the handover: examiner B inherits
//! examiner A's case and needs to know what A did and what nobody has opened. A
//! browser-local ledger answers that question with "nothing", which is worse
//! than no answer at all, so the ledger moved to the server and became
//! per-examiner.
//!
//! What these tests pin, endpoint by endpoint, is that the two assertions the
//! ledger makes stay two assertions. `opened` and `reviewed` are separate
//! numbers with separate meanings; a client that could add them, or a server
//! that let a scroll-past become a review, would turn "somebody's eyes passed
//! over this row" into "somebody examined this exhibit".

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

async fn setup() -> (axum::Router, Uuid, Vec<Uuid>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Handover", "examiner").await.unwrap();

    let artifacts: Vec<Artifact> = (0..6)
        .map(|i| {
            Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({"name": format!("file{i}.txt")}),
            )
        })
        .collect();
    let ids: Vec<Uuid> = artifacts.iter().map(|a| a.id).collect();
    for a in &artifacts {
        db.record_artifact(a).await.unwrap();
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
    (router_with_auth(app_state, Some(auth_config)), case_id, ids)
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn post_marks(app: &axum::Router, case_id: Uuid, marks: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{case_id}/artifact_reviews"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"marks": marks}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, json_body(response).await)
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

#[tokio::test]
async fn a_batch_of_openings_is_recorded_in_one_request() {
    let (app, case_id, ids) = setup().await;

    // Openings arrive in bursts as an examiner scrolls; one request per row is
    // what made this browser-local in the first place.
    let marks: Vec<Value> = ids[..4]
        .iter()
        .map(|id| json!({"artifact_id": id, "state": "opened"}))
        .collect();
    let (status, body) = post_marks(&app, case_id, json!(marks)).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["openings_recorded"], 4);
    assert_eq!(body["reviews_recorded"], 0);
    assert_eq!(
        body["examiner"], "local",
        "the ledger must attribute the openings to the authenticated examiner"
    );
}

#[tokio::test]
async fn opening_rows_never_appears_in_the_reviewed_listing() {
    let (app, case_id, ids) = setup().await;
    let marks: Vec<Value> = ids[..3]
        .iter()
        .map(|id| json!({"artifact_id": id, "state": "opened"}))
        .collect();
    post_marks(&app, case_id, json!(marks)).await;

    let (_, opened) = get(
        &app,
        format!("/api/v1/cases/{case_id}/artifact_reviews/ids?state=opened"),
    )
    .await;
    assert_eq!(opened["total"], 3);

    let (_, reviewed) = get(
        &app,
        format!("/api/v1/cases/{case_id}/artifact_reviews/ids?state=reviewed"),
    )
    .await;
    assert_eq!(
        reviewed["total"], 0,
        "scrolling past three rows is not having examined them"
    );
    assert_eq!(reviewed["ids"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn the_ids_listing_names_the_state_and_the_examiner_it_answered_for() {
    let (app, case_id, ids) = setup().await;
    post_marks(
        &app,
        case_id,
        json!([{"artifact_id": ids[0], "state": "reviewed"}]),
    )
    .await;

    let (_, all) = get(
        &app,
        format!("/api/v1/cases/{case_id}/artifact_reviews/ids?state=reviewed"),
    )
    .await;
    assert_eq!(all["state"], "reviewed");
    assert_eq!(
        all["scope"], "case",
        "with no examiner named, the answer is about the whole case and must say so"
    );
    assert_eq!(all["examiner"], Value::Null);
    assert_eq!(all["capped"], false);

    let (_, mine) = get(
        &app,
        format!("/api/v1/cases/{case_id}/artifact_reviews/ids?state=reviewed&examiner=local"),
    )
    .await;
    assert_eq!(mine["scope"], "examiner");
    assert_eq!(mine["examiner"], "local");
    assert_eq!(mine["ids"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_capped_id_listing_says_so_and_still_states_the_real_total() {
    let (app, case_id, ids) = setup().await;
    let marks: Vec<Value> = ids
        .iter()
        .map(|id| json!({"artifact_id": id, "state": "reviewed"}))
        .collect();
    post_marks(&app, case_id, json!(marks)).await;

    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/artifact_reviews/ids?state=reviewed&limit=2"),
    )
    .await;

    assert_eq!(body["ids"].as_array().unwrap().len(), 2);
    assert_eq!(body["returned"], 2);
    assert!(
        body["capped"].as_bool().unwrap(),
        "a client marks rows off this list; a silently short list renders every \
         artifact past the ceiling as never-opened"
    );
    assert_eq!(body["total"], 6);
    assert_eq!(body["cap"], 2);
}

#[tokio::test]
async fn the_stats_panel_gets_a_denominator_it_can_name() {
    let (app, case_id, ids) = setup().await;
    post_marks(
        &app,
        case_id,
        json!([
            {"artifact_id": ids[0], "state": "reviewed"},
            {"artifact_id": ids[1], "state": "opened"},
        ]),
    )
    .await;

    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/artifact_reviews/stats"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let examiners = body["examiners"].as_array().expect("examiners");
    assert_eq!(examiners.len(), 1);
    assert_eq!(examiners[0]["examiner"], "local");
    assert_eq!(examiners[0]["opened"], 2);
    assert_eq!(examiners[0]["reviewed"], 1);

    assert_eq!(body["case"]["opened"], 2);
    assert_eq!(body["case"]["reviewed"], 1);

    // The denominator. A count with no stated population is a number nobody can
    // check, and this panel used to print exactly that.
    assert_eq!(body["population"]["total"], 6);
    assert!(
        body["population"]["label"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "the population must be NAMED, not left for the client to assume"
    );
    assert_eq!(
        body["reviewed_is_subset_of_opened"], true,
        "the two counts overlap; a response that does not say so invites a client \
         to add them"
    );
}

#[tokio::test]
async fn withdrawing_a_review_keeps_the_opening_and_the_history() {
    let (app, case_id, ids) = setup().await;
    post_marks(
        &app,
        case_id,
        json!([{"artifact_id": ids[0], "state": "reviewed"}]),
    )
    .await;
    let (status, body) = post_marks(
        &app,
        case_id,
        json!([{"artifact_id": ids[0], "state": "unreviewed"}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["reviews_withdrawn"], 1);

    let (_, opened) = get(
        &app,
        format!("/api/v1/cases/{case_id}/artifact_reviews/ids?state=opened"),
    )
    .await;
    assert_eq!(
        opened["total"], 1,
        "withdrawing the review must not withdraw the opening"
    );

    let (_, reviewed) = get(
        &app,
        format!("/api/v1/cases/{case_id}/artifact_reviews/ids?state=reviewed"),
    )
    .await;
    assert_eq!(reviewed["total"], 0);

    let (status, history) = get(
        &app,
        format!(
            "/api/v1/cases/{case_id}/artifact_reviews/history?artifact_id={}",
            ids[0]
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {history}");
    let actions: Vec<&str> = history["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        vec!["opened", "reviewed", "review_withdrawn"],
        "a review made and retracted must not read like a review never made"
    );
}

#[tokio::test]
async fn an_artifact_from_another_case_is_named_in_the_refusal() {
    let (app, case_id, ids) = setup().await;
    let stranger = Uuid::new_v4();

    let (status, body) = post_marks(
        &app,
        case_id,
        json!([
            {"artifact_id": ids[0], "state": "opened"},
            {"artifact_id": stranger, "state": "opened"},
        ]),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["openings_recorded"], 1);
    let rejected: Vec<String> = body["rejected"]
        .as_array()
        .expect("rejected")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(rejected, vec![stranger.to_string()]);
}

#[tokio::test]
async fn an_oversized_batch_is_refused_rather_than_truncated() {
    let (app, case_id, ids) = setup().await;
    let marks: Vec<Value> = (0..1_001)
        .map(|_| json!({"artifact_id": ids[0], "state": "opened"}))
        .collect();

    let (status, body) = post_marks(&app, case_id, json!(marks)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a truncated batch would leave the browser believing it recorded openings \
         the server never saw; body: {body}"
    );
    assert_eq!(body["error"]["code"], "INVALID_REQUEST");
}

#[tokio::test]
async fn an_unknown_state_word_is_refused_rather_than_guessed() {
    let (app, case_id, ids) = setup().await;
    let (status, body) = post_marks(
        &app,
        case_id,
        json!([{"artifact_id": ids[0], "state": "skimmed"}]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn an_empty_case_reports_zeros_against_a_stated_population() {
    let (app, case_id, _ids) = setup().await;
    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/artifact_reviews/stats"),
    )
    .await;
    assert_eq!(body["examiners"].as_array().unwrap().len(), 0);
    assert_eq!(body["case"]["opened"], 0);
    assert_eq!(
        body["population"]["total"], 6,
        "nothing reviewed is not nothing to review; the denominator stands"
    );
}
