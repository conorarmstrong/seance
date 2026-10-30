//! `GET /cases/{id}/timeline/recent/{period}` at route level.
//!
//! `CORE_DESIGN.md` §4.9 documents this route as API-only and states two
//! things an examiner calling it must know: the window is measured back from
//! the SERVER'S wall clock at the moment of the request, not from any time in
//! the evidence, and only `24h`, `7d` and `30d` are accepted. Until these tests
//! only `recent_period_hours` and `CappedListing::judge` were unit-tested, so
//! neither claim was pinned where the route answers. These are
//! characterisation tests of shipped behaviour on synthetic events.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

async fn setup_test_app() -> (axum::Router, Uuid, Arc<SqliteConnection>) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Recent Window", "Examiner").await.unwrap();

    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, _ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let app_state = AppState {
        db: db.clone(),
        // A counted submitter over the test channel; the counter is the test's own
        // because nothing here submits through it.
        orchestrator_sender: seance_core::orchestrator::TaskSubmitter::new(
            tx,
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        ),
        ad_hoc_sender: ad_hoc_tx,
        event_sender: event_tx.clone(),
        status_sender: status_tx,
        active_tasks: active_tasks.clone(),
        search_service: None,
        ingestion_service: seance_core::ingestion::IngestionService::new(
            Some(db.clone()),
            task_tx,
            event_tx,
            active_tasks,
        ),
        module_registry: vec![],
        signing_config: None,
        evidence_roots: seance_api::EvidenceRootPolicy::from_env(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };
    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: "".to_string(),
        enabled: false,
    };
    let app = router_with_auth(app_state, Some(auth_config));
    (app, case_id, db)
}

async fn add_event(db: &Arc<SqliteConnection>, case_id: Uuid, ts: i64) {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::TimelineEvent,
        metadata: serde_json::json!({
            "timestamp": ts,
            "timestamp_desc": "Test Event",
            "source_module": "TestModule",
            "short_desc": "desc",
            "full_details": "{}",
        }),
        data: None,
    };
    db.record_artifact(&artifact).await.unwrap();
}

async fn get_json(app: &axum::Router, uri: String) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn timestamps(v: &serde_json::Value) -> Vec<i64> {
    v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .map(|e| e["timestamp"].as_i64().expect("timestamp"))
        .collect()
}

#[tokio::test]
async fn the_24h_window_is_measured_from_the_server_clock_not_the_evidence() {
    const HOUR: i64 = 3_600;
    let (app, case_id, db) = setup_test_app().await;
    let t = now();
    let inside = t - HOUR;
    let three_days_ago = t - 72 * HOUR;
    // The case's own latest activity is years ago: a window measured from the
    // evidence would include it; one measured from the server clock must not.
    let evidence_time = 1_600_000_000;
    let future = t + 48 * HOUR;
    for ts in [inside, three_days_ago, evidence_time, future] {
        add_event(&db, case_id, ts).await;
    }

    let (status, v) = get_json(
        &app,
        format!("/api/v1/cases/{}/timeline/recent/24h", case_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(timestamps(&v), vec![inside], "{v}");

    let from = v["from_ts"].as_i64().unwrap();
    let to = v["to_ts"].as_i64().unwrap();
    assert_eq!(to - from, 24 * HOUR, "the window is exactly 24 hours: {v}");
    // `to_ts` is the server's clock at the request, within the test's own span.
    assert!(
        to >= t && to <= now(),
        "to_ts {to} is not the server's now ({t})"
    );
    assert_eq!(v["period"], "24h");
    assert_eq!(v["truncated"], false, "{v}");
}

#[tokio::test]
async fn the_7d_and_30d_windows_widen_from_the_same_clock() {
    const DAY: i64 = 86_400;
    let (app, case_id, db) = setup_test_app().await;
    let t = now();
    let three_days = t - 3 * DAY;
    let twenty_days = t - 20 * DAY;
    let sixty_days = t - 60 * DAY;
    for ts in [three_days, twenty_days, sixty_days] {
        add_event(&db, case_id, ts).await;
    }

    let (_, week) = get_json(
        &app,
        format!("/api/v1/cases/{}/timeline/recent/7d", case_id),
    )
    .await;
    assert_eq!(timestamps(&week), vec![three_days], "{week}");

    let (_, month) = get_json(
        &app,
        format!("/api/v1/cases/{}/timeline/recent/30d", case_id),
    )
    .await;
    let mut got = timestamps(&month);
    got.sort_unstable();
    assert_eq!(got, vec![twenty_days, three_days], "{month}");
}

#[tokio::test]
async fn an_unlisted_period_is_refused_rather_than_answered_with_another() {
    let (app, case_id, _db) = setup_test_app().await;
    for period in ["90d", "1h", "24H", "week"] {
        let (status, v) = get_json(
            &app,
            format!("/api/v1/cases/{}/timeline/recent/{}", case_id, period),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{period}: {v}");
    }
}
