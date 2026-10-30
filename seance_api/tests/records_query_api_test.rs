//! Filtering, sorting and exporting a parsed-record table over the wire.
//!
//! Record tables could only filter the rows already fetched. On any type larger
//! than a page that meant the box searched a slice, and a term missing from the
//! slice looked exactly like a term missing from the case. The screen said so —
//! it named both populations and warned that an absence there was not an absence
//! in the evidence — but the caveat existed only because the endpoint could not
//! do the work.
//!
//! The assertion that carries the most weight here is
//! [`the_total_is_the_filtered_count_not_the_types_count`]. Every record table
//! prints "N of T" above itself, and it reads T from this response. If T keeps
//! counting the type while the rows are filtered, that line becomes a false
//! statement about the evidence the instant anybody types.
//!
//! The export gets the same parameters for the same reason: an export that
//! silently held something other than what the examiner was looking at is a
//! worse exhibit than no export at all.

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

async fn setup() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Records", "examiner").await.unwrap();

    let rows = vec![
        json!({"type": "WhatsApp", "body": "Meet me at the DOCK", "sender": "alice", "seq": 3}),
        json!({"type": "WhatsApp", "body": "dock is closed", "sender": "bob", "seq": 1}),
        json!({"type": "WhatsApp", "body": "nothing here", "sender": "dockside ltd", "seq": 2}),
        json!({"type": "WhatsApp", "body": "unrelated", "sender": "carol", "seq": 4}),
        json!({"type": "Skype", "body": "dock dock dock", "sender": "dave", "seq": 9}),
    ];
    for metadata in rows {
        let artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata);
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

async fn get_text(app: &axum::Router, uri: String) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn bodies(body: &Value) -> Vec<String> {
    body["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|r| r["metadata"]["body"].as_str().unwrap_or("?").to_string())
        .collect()
}

#[tokio::test]
async fn the_total_is_the_filtered_count_not_the_types_count() {
    let (app, case_id) = setup().await;

    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/records?type=WhatsApp&q=dock&q_keys=body"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["total"], 2,
        "the 'N of T' line above the table reads T from here; leaving it as the \
         type's count makes that line false the moment the filter is used"
    );
    assert_eq!(
        body["type_total"], 4,
        "and the type's own population stays sayable alongside it"
    );
    assert_eq!(body["records"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn the_response_repeats_the_filter_it_actually_applied() {
    let (app, case_id) = setup().await;
    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/records?type=WhatsApp&q=dock&q_keys=body,sender"),
    )
    .await;

    assert_eq!(body["q"], "dock");
    assert_eq!(body["q_keys"], json!(["body", "sender"]));
    assert_eq!(body["filtered"], true);
    assert_eq!(
        body["total"], 3,
        "matching across body OR sender picks up 'dockside ltd'"
    );
    assert!(
        body["q_match"].as_str().is_some_and(|s| !s.is_empty()),
        "the matching rule must be named, not assumed: an examiner reading a \
         result set needs to know it was a substring match and how case was folded"
    );
}

#[tokio::test]
async fn a_term_with_no_keys_is_refused_rather_than_searched_somewhere_arbitrary() {
    let (app, case_id) = setup().await;
    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/records?type=WhatsApp&q=dock"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "guessing which keys to search would make the population a term matches \
         depend on what a parser happened to write; body: {body}"
    );
    assert_eq!(body["error"]["code"], "INVALID_REQUEST");
}

#[tokio::test]
async fn a_key_name_that_is_not_a_bare_key_is_refused() {
    let (app, case_id) = setup().await;
    for bad in ["body.text", "body'", "body[0]"] {
        let (status, body) = get(
            &app,
            format!("/api/v1/cases/{case_id}/records?type=WhatsApp&q=x&q_keys={bad}"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "'{bad}' must be refused; body: {body}"
        );
    }
}

#[tokio::test]
async fn an_unfiltered_listing_does_not_claim_zero_unreadable_rows() {
    let (app, case_id) = setup().await;
    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/records?type=WhatsApp"),
    )
    .await;
    assert_eq!(body["total"], 4);
    assert_eq!(body["type_total"], 4);
    assert_eq!(body["filtered"], false);
    assert_eq!(
        body["unfilterable_metadata"],
        Value::Null,
        "with no term, nothing was tested for readability; null is 'not looked \
         up' and 0 would assert a check that never ran"
    );
}

#[tokio::test]
async fn sorting_by_a_metadata_key_reorders_the_listing() {
    let (app, case_id) = setup().await;

    let (_, asc) = get(
        &app,
        format!("/api/v1/cases/{case_id}/records?type=WhatsApp&sort=seq&order=asc"),
    )
    .await;
    assert_eq!(
        bodies(&asc),
        vec![
            "dock is closed",
            "nothing here",
            "Meet me at the DOCK",
            "unrelated"
        ]
    );
    assert_eq!(asc["sort"], "seq");
    assert_eq!(asc["order"], "asc");

    let (_, desc) = get(
        &app,
        format!("/api/v1/cases/{case_id}/records?type=WhatsApp&sort=seq&order=desc"),
    )
    .await;
    assert_eq!(
        bodies(&desc),
        vec![
            "unrelated",
            "Meet me at the DOCK",
            "nothing here",
            "dock is closed"
        ]
    );
}

#[tokio::test]
async fn an_unsorted_listing_says_the_order_is_ingest_order() {
    let (app, case_id) = setup().await;
    let (_, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/records?type=WhatsApp"),
    )
    .await;
    assert_eq!(body["sort"], Value::Null);
    assert_eq!(
        body["order_by"], "ingest",
        "ingest order is not the records' own event time, and a table that \
         presented it as 'most recent' would be stating a chronology the \
         evidence never claimed"
    );
}

#[tokio::test]
async fn a_bad_sort_key_is_refused_rather_than_silently_ignored() {
    let (app, case_id) = setup().await;
    let (status, body) = get(
        &app,
        format!("/api/v1/cases/{case_id}/records?type=WhatsApp&sort=body.text"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "falling back to the default order would show an examiner a table they \
         did not ask for, in an order they did not choose; body: {body}"
    );
}

#[tokio::test]
async fn the_csv_export_holds_exactly_what_the_filtered_table_shows() {
    let (app, case_id) = setup().await;
    let (status, csv) = get_text(
        &app,
        format!(
            "/api/v1/cases/{case_id}/records/export/csv?type=WhatsApp&q=dock&q_keys=body&sort=seq&order=asc"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {csv}");
    let lines: Vec<&str> = csv.lines().collect();
    assert!(lines[0].starts_with("Artifact ID,Parent ID,Record Type"));
    assert_eq!(
        lines.len(),
        3,
        "a header and the two matching rows, nothing else: {csv}"
    );
    assert!(lines[1].contains("dock is closed"), "{csv}");
    assert!(lines[2].contains("Meet me at the DOCK"), "{csv}");
    assert!(
        !csv.contains("unrelated"),
        "the export must match the filtered table, not the type: {csv}"
    );
}

#[tokio::test]
async fn the_csv_export_names_its_columns_or_takes_them_from_the_caller() {
    let (app, case_id) = setup().await;

    let (_, derived) = get_text(
        &app,
        format!("/api/v1/cases/{case_id}/records/export/csv?type=WhatsApp"),
    )
    .await;
    let header = derived.lines().next().unwrap();
    assert_eq!(
        header, "Artifact ID,Parent ID,Record Type,body,sender,seq,type",
        "derived columns are the union of the exported rows' top-level keys, \
         sorted, so the same query always yields the same sheet: {header}"
    );

    let (_, chosen) = get_text(
        &app,
        format!("/api/v1/cases/{case_id}/records/export/csv?type=WhatsApp&columns=sender,body"),
    )
    .await;
    assert_eq!(
        chosen.lines().next().unwrap(),
        "Artifact ID,Parent ID,Record Type,sender,body"
    );
}

#[tokio::test]
async fn the_csv_export_is_audited() {
    let (app, case_id) = setup().await;
    let (status, _csv) = get_text(
        &app,
        format!("/api/v1/cases/{case_id}/records/export/csv?type=WhatsApp"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, log) = get(&app, format!("/api/v1/cases/{case_id}/audit_log")).await;
    let actions: Vec<String> = log["events"]
        .as_array()
        .expect("audit events")
        .iter()
        .map(|e| e["action"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(
        actions.iter().any(|a| a == "records_exported"),
        "an export becomes an exhibit; it has to be accounted for: {actions:?}"
    );
}

#[tokio::test]
async fn a_records_query_still_refuses_a_missing_type() {
    let (app, case_id) = setup().await;
    let (status, _body) = get(&app, format!("/api/v1/cases/{case_id}/records")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _body) =
        get_text(&app, format!("/api/v1/cases/{case_id}/records/export/csv")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
