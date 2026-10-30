//! Pinning a pivot to the case (`ROADMAP.md` §5.13).
//!
//! The pivot is the move an examiner makes constantly, and its answer was a
//! transient panel: nothing carried "these eleven artifacts are what referenced
//! that account" into the report, so it was re-run while writing or transcribed
//! into prose where nothing could check it.
//!
//! The assertion that carries the weight is
//! [`a_report_shows_both_what_was_pinned_and_what_the_case_says_now`]. A report
//! that rendered only the snapshot would describe a case that has since grown;
//! one that rendered only a fresh re-run would quietly say something different
//! from what the examiner saw, with nothing to show that it had changed. Both
//! are carried, and a difference between them is itself on the record.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use seance_api::{gather_report_data, router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::orchestrator::{CancellationHandle, Orchestrator};
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

struct Harness {
    app: axum::Router,
    state: AppState,
    case_id: Uuid,
    db: Arc<SqliteConnection>,
    search: Arc<seance_search::SearchService>,
}

async fn setup() -> Harness {
    let index_dir = tempfile::tempdir().unwrap();
    let search =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    std::mem::forget(index_dir);

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Traced", "examiner").await.unwrap();

    let c2 = "203.78.103.109";
    for (kind, meta) in [
        (
            ArtifactType::ParsedRecord,
            json!({"type": "NetworkFlow", "name": format!("tcp 10.42.85.115 -> {c2}:443")}),
        ),
        (
            ArtifactType::ParsedRecord,
            json!({"type": "DnsResolution", "name": format!("evil.example resolved to {c2}")}),
        ),
        (
            ArtifactType::FileEntry,
            json!({"name": "unrelated.txt", "path": "/nothing here"}),
        ),
    ] {
        let a = Artifact::new(case_id, kind, None, meta);
        db.record_artifact(&a).await.unwrap();
        search.add_artifact_to_index_sync(&a).unwrap();
    }
    search.commit_sync().unwrap();

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: Some(search.clone()),
        ingestion_service: orchestrator.ingestion_service(),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: EvidenceRootPolicy::unrestricted(),
        cancellation: CancellationHandle::new(),
    };
    let app = router_with_auth(
        state.clone(),
        Some(AuthConfig {
            jwt_secret: "t".into(),
            admin_username: "admin".into(),
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );
    Harness {
        app,
        state,
        case_id,
        db,
        search,
    }
}

async fn call(app: &axum::Router, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    let request = if body.is_null() {
        request.body(Body::empty()).unwrap()
    } else {
        request.body(Body::from(body.to_string())).unwrap()
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        },
    )
}

#[tokio::test]
async fn pinning_a_pivot_stores_the_answer_the_examiner_saw() {
    let h = setup().await;
    let (status, body) = call(
        &h.app,
        "POST",
        &format!("/api/v1/cases/{}/pivots", h.case_id),
        json!({ "value": "203.78.103.109", "note": "the address the exfil connected to" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(body["value"], "203.78.103.109");
    assert_eq!(body["total_matches"], 2);
    assert_eq!(body["truncated"], false);
    assert_eq!(body["note"], "the address the exfil connected to");
    // The grouped answer is stored verbatim, so the report renders what the
    // examiner saw and not a re-rendering of it.
    let kinds: Vec<&str> = body["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"NetworkFlow"), "{body}");
    assert!(kinds.contains(&"DnsResolution"), "{body}");

    // And it is listed back with the sentence that says what it is.
    let (_, listed) = call(
        &h.app,
        "GET",
        &format!("/api/v1/cases/{}/pivots", h.case_id),
        Value::Null,
    )
    .await;
    assert_eq!(listed["count"], 1);
    assert!(listed["note"]
        .as_str()
        .unwrap()
        .contains("at the moment it was pinned"));

    // Examiner-authored content that reaches the report, so the log records who
    // put it there.
    let events = h.db.get_audit_log(h.case_id, 50, 0).await.unwrap();
    assert!(
        events.iter().any(|e| e["action"] == "pivot_pinned"),
        "the pin must be audited: {:?}",
        events
            .iter()
            .map(|e| e["action"].clone())
            .collect::<Vec<_>>()
    );
}

/// Pinning the same value twice is the same assertion, not a second one — and
/// the pin keeps its identity so a report that cited it still cites the same
/// pin.
#[tokio::test]
async fn pinning_the_same_value_twice_refreshes_the_pin_in_place() {
    let h = setup().await;
    let uri = format!("/api/v1/cases/{}/pivots", h.case_id);
    let (_, first) = call(
        &h.app,
        "POST",
        &uri,
        json!({ "value": "203.78.103.109", "note": "first" }),
    )
    .await;
    let (_, second) = call(
        &h.app,
        "POST",
        &uri,
        json!({ "value": "203.78.103.109", "note": "second" }),
    )
    .await;

    assert_eq!(first["id"], second["id"], "the pin keeps its identity");
    assert_eq!(second["note"], "second");
    let (_, listed) = call(&h.app, "GET", &uri, Value::Null).await;
    assert_eq!(listed["count"], 1, "no duplicate: {listed}");
}

#[tokio::test]
async fn unpinning_removes_it_and_is_audited_and_says_so_when_there_was_nothing_to_remove() {
    let h = setup().await;
    let uri = format!("/api/v1/cases/{}/pivots", h.case_id);
    let (_, pin) = call(&h.app, "POST", &uri, json!({ "value": "203.78.103.109" })).await;
    let id = pin["id"].as_str().unwrap().to_string();

    let (status, _) = call(&h.app, "DELETE", &format!("{uri}/{id}"), Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    let (_, listed) = call(&h.app, "GET", &uri, Value::Null).await;
    assert_eq!(listed["count"], 0);

    // Removing something the report carried is as significant as adding it.
    let events = h.db.get_audit_log(h.case_id, 50, 0).await.unwrap();
    assert!(events.iter().any(|e| e["action"] == "pivot_unpinned"));

    // A delete that removed nothing is reported as not found rather than as a
    // success that did nothing.
    let (status, _) = call(&h.app, "DELETE", &format!("{uri}/{id}"), Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_empty_value_is_refused_rather_than_pinned() {
    let h = setup().await;
    let (status, _) = call(
        &h.app,
        "POST",
        &format!("/api/v1/cases/{}/pivots", h.case_id),
        json!({ "value": "   " }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The whole point of the section. A report showing only the snapshot would
/// describe a case that has since grown; one showing only a fresh re-run would
/// quietly say something different from what the examiner saw.
#[tokio::test]
async fn a_report_shows_both_what_was_pinned_and_what_the_case_says_now() {
    let h = setup().await;
    call(
        &h.app,
        "POST",
        &format!("/api/v1/cases/{}/pivots", h.case_id),
        json!({ "value": "203.78.103.109", "note": "the C2" }),
    )
    .await;

    // Unchanged: the report says so rather than staying silent, because
    // silence would leave the snapshot reading as current.
    let data = gather_report_data(&h.state, h.case_id).await.unwrap();
    assert_eq!(data.traced_values.len(), 1);
    let t = &data.traced_values[0];
    assert_eq!(t.value, "203.78.103.109");
    // Auth is disabled in this harness, so the injected identity is "local".
    assert_eq!(t.examiner, "local");
    assert_eq!(t.matches_when_pinned, 2);
    assert_eq!(t.matches_now, Some(2));
    assert_eq!(t.recheck_unavailable_reason, None);
    assert!(t
        .groups_when_pinned
        .iter()
        .any(|(kind, count)| kind == "NetworkFlow" && *count == 1));
    let html = seance_reporting::render_html(&data);
    assert!(html.contains("Values Traced Across the Evidence"), "{html}");
    assert!(html.contains("still 2 artifact(s)"));

    // Now the case grows. The same value answers differently, and the report
    // carries both figures.
    let extra = Artifact::new(
        h.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({"type": "NetworkFlow", "name": "tcp 10.42.85.200 -> 203.78.103.109:443"}),
    );
    h.db.record_artifact(&extra).await.unwrap();
    h.search.add_artifact_to_index_sync(&extra).unwrap();
    h.search.commit_sync().unwrap();

    let data = gather_report_data(&h.state, h.case_id).await.unwrap();
    let t = &data.traced_values[0];
    assert_eq!(
        t.matches_when_pinned, 2,
        "the snapshot is what the examiner saw and does not move"
    );
    assert_eq!(t.matches_now, Some(3));
    let html = seance_reporting::render_html(&data);
    assert!(
        html.contains("3 artifact(s) now reference this value"),
        "{html}"
    );
    assert!(html.contains("differently on the two dates"));
}

/// A build with no search index cannot re-ask the question. The snapshot is
/// still the examiner's assertion, so the report carries it with the reason
/// rather than failing — and never as a zero, because "we could not look
/// again" and "it matches nothing now" are different facts.
#[tokio::test]
async fn a_pin_survives_a_report_from_a_build_that_cannot_search() {
    let h = setup().await;
    call(
        &h.app,
        "POST",
        &format!("/api/v1/cases/{}/pivots", h.case_id),
        json!({ "value": "203.78.103.109" }),
    )
    .await;

    let mut blind = h.state.clone();
    blind.search_service = None;
    let data = gather_report_data(&blind, h.case_id).await.unwrap();
    let t = &data.traced_values[0];
    assert_eq!(t.matches_when_pinned, 2);
    assert_eq!(t.matches_now, None, "an unasked question is not a zero");
    assert!(t
        .recheck_unavailable_reason
        .as_deref()
        .unwrap()
        .contains("no search index"));

    let html = seance_reporting::render_html(&data);
    assert!(html.contains("could NOT be re-checked"), "{html}");
    assert!(!html.contains("0 artifact(s) now reference"));
}
