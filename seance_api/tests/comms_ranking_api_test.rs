//! The server-side communications league table (LIVE-024).
//!
//! The correlation page used to rank "most contacted" in the browser from a
//! 2,000-record-per-type prefix of up to 78,237 records. A tally of a sample is
//! a lower bound; a RANKING of a sample is simply the wrong order. These tests
//! pin what the endpoint promises instead: an exact order over the whole case,
//! a census that adds up, a clamp the client cannot talk its way past, and a
//! refusal — never an empty table — for a channel nobody parses.

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

/// A case whose ten comms records exercise every bucket the census names.
///
/// Deliberately small and hand-counted, so the assertions below quote numbers a
/// reader can re-derive from this function rather than numbers the code
/// produced.
///
/// * `iMessage` — alice x3, bob x1, plus one parser tally row (`subtype`
///   `summary`) that is a count OF messages rather than a message.
/// * `WhatsApp` — alice x1, a correspondent genuinely named "Unknown" x1, and
///   one record carrying none of the ten counterparty keys.
/// * `CallLog`  — two rows the device recorded with no number, which the
///   call-history parser writes as the literal "Unknown".
async fn setup() -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Comms Ranking", "examiner").await.unwrap();

    let rec =
        |meta: serde_json::Value| Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta);

    for _ in 0..3 {
        db.record_artifact(&rec(json!({"type": "iMessage", "contact": "alice"})))
            .await
            .unwrap();
    }
    db.record_artifact(&rec(json!({"type": "iMessage", "contact": "bob"})))
        .await
        .unwrap();
    db.record_artifact(&rec(json!({"type": "WhatsApp", "contact": "alice"})))
        .await
        .unwrap();
    // A WhatsApp correspondent whose display name genuinely is "Unknown" is a
    // real party and must stay in the table; only CallLog writes that literal
    // as a placeholder.
    db.record_artifact(&rec(json!({"type": "WhatsApp", "contact": "Unknown"})))
        .await
        .unwrap();
    for _ in 0..2 {
        db.record_artifact(&rec(json!({"type": "CallLog", "contact": "Unknown"})))
            .await
            .unwrap();
    }
    db.record_artifact(&rec(
        json!({"type": "WhatsApp", "text": "no counterparty here"}),
    ))
    .await
    .unwrap();
    db.record_artifact(&rec(
        json!({"type": "iMessage", "subtype": "summary", "contact": "alice", "count": 999}),
    ))
    .await
    .unwrap();

    // A record of a type the comms view does not correlate, to prove the
    // population is the sixteen named types and not "everything parsed".
    db.record_artifact(&rec(json!({"type": "exif", "contact": "alice"})))
        .await
        .unwrap();

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
    let app = router_with_auth(app_state, Some(auth_config));
    (app, case_id, db)
}

async fn get(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn ranking_uri(case_id: Uuid, query: &str) -> String {
    if query.is_empty() {
        format!("/api/v1/cases/{case_id}/comms/ranking")
    } else {
        format!("/api/v1/cases/{case_id}/comms/ranking?{query}")
    }
}

#[tokio::test]
async fn ranks_every_record_in_the_case_in_exact_order() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, ranking_uri(case_id, "")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let contacts = body["contacts"].as_array().unwrap();
    let pairs: Vec<(&str, i64)> = contacts
        .iter()
        .map(|c| (c["contact"].as_str().unwrap(), c["count"].as_i64().unwrap()))
        .collect();
    // alice is the only correspondent whose records span two channels, so a
    // per-type slice would have understated her; ties break on contact ascending
    // (binary collation, so "Unknown" precedes "bob") to keep the order
    // deterministic between runs.
    assert_eq!(pairs, vec![("alice", 4), ("Unknown", 1), ("bob", 1)]);
    assert_eq!(body["distinct_contacts"], 3);
    assert_eq!(body["has_more"], false);
}

#[tokio::test]
async fn by_type_serialises_as_name_count_pairs() {
    let (app, case_id, _db) = setup().await;
    let (_status, body) = get(&app, ranking_uri(case_id, "")).await;

    // The frontend reads these positionally; an object would silently break it.
    assert_eq!(body["by_type"], json!([["iMessage", 4], ["WhatsApp", 2]]));
}

#[tokio::test]
async fn the_census_adds_up() {
    let (app, case_id, _db) = setup().await;
    for query in ["", "channel=CallLog", "channel=WhatsApp", "q=ali"] {
        let (status, body) = get(&app, ranking_uri(case_id, query)).await;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        let by_type: i64 = body["by_type"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row[1].as_i64().unwrap())
            .sum();
        assert_eq!(
            body["total_records"].as_i64().unwrap(),
            by_type
                + body["summary_records"].as_i64().unwrap()
                + body["unrankable_records"].as_i64().unwrap()
                + body["records_without_counterparty"].as_i64().unwrap(),
            "census does not add up for '{query}': {body}"
        );
    }
}

#[tokio::test]
async fn the_four_populations_are_never_merged() {
    let (app, case_id, _db) = setup().await;
    let (_status, body) = get(&app, ranking_uri(case_id, "")).await;

    assert_eq!(body["total_records"], 10);
    // The parser tally row: a count OF messages, not a message.
    assert_eq!(body["summary_records"], 1);
    // The WhatsApp record carrying none of the ten counterparty keys.
    assert_eq!(body["unrankable_records"], 1);
    // The two call-log rows the device recorded with no number.
    assert_eq!(body["records_without_counterparty"], 2);
}

#[tokio::test]
async fn a_search_term_narrows_the_table_and_never_the_census() {
    let (app, case_id, _db) = setup().await;
    let (_status, before) = get(&app, ranking_uri(case_id, "")).await;
    let (status, after) = get(&app, ranking_uri(case_id, "q=ALI")).await;
    assert_eq!(status, StatusCode::OK, "body: {after}");

    // Case-insensitive on the counterparty, and it bounds the table only.
    assert_eq!(after["contacts"].as_array().unwrap().len(), 1);
    assert_eq!(after["contacts"][0]["contact"], "alice");
    assert_eq!(after["distinct_contacts"], 1);

    for field in [
        "by_type",
        "total_records",
        "summary_records",
        "unrankable_records",
        "records_without_counterparty",
    ] {
        assert_eq!(
            after[field], before[field],
            "'{field}' describes the case and must not move when an examiner types"
        );
    }
}

#[tokio::test]
async fn a_channel_narrows_the_census_to_that_channel() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, ranking_uri(case_id, "channel=CallLog")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // Both CallLog rows are placeholders, so the channel has a census and no
    // rankable party at all.
    assert_eq!(body["total_records"], 2);
    assert_eq!(body["records_without_counterparty"], 2);
    assert_eq!(body["by_type"], json!([]));
    assert_eq!(body["contacts"], json!([]));
    assert_eq!(body["distinct_contacts"], 0);
}

#[tokio::test]
async fn an_unparsed_channel_is_refused_by_name_not_answered_with_an_empty_table() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, ranking_uri(case_id, "channel=Mastodon")).await;

    // An empty ranking would read as "this case holds no such records", which is
    // a claim about the evidence nobody checked.
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let text = body.to_string();
    assert!(
        text.contains("Mastodon"),
        "must name what was rejected: {text}"
    );
    for accepted in ["iMessage", "WhatsApp", "TwitterDM"] {
        assert!(
            text.contains(accepted),
            "must name the accepted values, missing {accepted}: {text}"
        );
    }
}

#[tokio::test]
async fn limit_is_clamped_and_the_applied_cap_is_reported() {
    let (app, case_id, _db) = setup().await;

    let (_s, defaulted) = get(&app, ranking_uri(case_id, "")).await;
    assert_eq!(defaulted["limit"], 20, "default page size");

    let (_s, huge) = get(&app, ranking_uri(case_id, "limit=100000")).await;
    assert_eq!(
        huge["limit"], 200,
        "an authenticated request must not size an unbounded heap"
    );

    // Floor 1: limit=0 would return an empty table, and an empty table reads as
    // "there was nobody there".
    let (_s, zero) = get(&app, ranking_uri(case_id, "limit=0")).await;
    assert_eq!(zero["limit"], 1);
    assert_eq!(zero["contacts"].as_array().unwrap().len(), 1);

    // A full page is not evidence of more rows; `has_more` is, and
    // `distinct_contacts` says how many were left off.
    let (_s, one) = get(&app, ranking_uri(case_id, "limit=1")).await;
    assert_eq!(one["has_more"], true);
    assert_eq!(one["distinct_contacts"], 3);
}

#[tokio::test]
async fn a_non_numeric_limit_falls_back_to_the_default() {
    let (app, case_id, _db) = setup().await;
    let (status, body) = get(&app, ranking_uri(case_id, "limit=lots")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["limit"], 20);
}

#[tokio::test]
async fn reading_the_ranking_is_audited() {
    let (app, case_id, db) = setup().await;
    let (status, _body) = get(&app, ranking_uri(case_id, "channel=WhatsApp&q=ali")).await;
    assert_eq!(status, StatusCode::OK);

    let rows = db
        .get_audit_log_filtered(
            case_id,
            None,
            Some("comms_ranking_executed"),
            None,
            None,
            None,
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "one read, one audit row: {rows:?}");
    let details = rows[0]["details"].as_str().unwrap_or_default().to_string();
    assert!(
        details.contains("WhatsApp") && details.contains("ali"),
        "the audit row must record what was asked for: {details}"
    );
}

/// The route carries no access check of its own; it inherits the router-level
/// per-case gate every `/api/v1/cases/:id/...` route sits behind. Pinned here
/// because a correspondent league table is among the most disclosive answers
/// this API gives, and inheriting a guard is only safe while the route is
/// actually inside it.
#[tokio::test]
async fn an_examiner_with_no_grant_on_the_case_is_refused() {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    db.create_user(
        "erin",
        &seance_api::hash_password("examinerpw1").unwrap(),
        "examiner",
    )
    .await
    .unwrap();
    let case_id = db.create_case("Comms Ranking", "examiner").await.unwrap();

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
        jwt_secret: "comms-ranking-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: seance_api::hash_password("bootstrap-admin-pw").unwrap(),
        enabled: true,
    };
    let app = router_with_auth(app_state, Some(auth_config.clone()));
    let (token, _) = auth_config.generate_token("erin", "examiner").unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(ranking_uri(case_id, ""))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
