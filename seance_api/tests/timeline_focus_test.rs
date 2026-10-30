//! `focus=auto` on the two chart endpoints (`UI-010`).
//!
//! A case whose extent runs across four decades because of one FAT-epoch 1980
//! timestamp used to be drawn in one-year buckets: the bucket width was chosen
//! against the whole extent, so a fortnight of real work collapsed into one or
//! two bars. With `focus=auto` the server narrows the window to where the
//! events are, re-queries at a width chosen for THAT window, and reports what
//! it left out. Without the parameter the answer is unchanged, which is what
//! keeps the REPL and the report layer on the contract they were written to.

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
    let case_id = db.create_case("Count Skip", "Examiner").await.unwrap();

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

async fn get_json(app: &axum::Router, uri: String) -> serde_json::Value {
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// One 1980 stamp, a decades-wide void, then a fortnight of real activity: the
/// case `UI-010` was raised for.
async fn setup_outlier_case() -> (axum::Router, Uuid) {
    const DAY: i64 = 86_400;
    const MASS_START: i64 = 1_700_000_000;
    let (app, case_id, db) = setup_test_app().await;
    // The artefactual timestamp: 1980-01-01, a FAT epoch a parser recovered.
    add_event(&db, case_id, 315_532_800).await;
    for d in 0..14 {
        for n in 0..40 {
            add_event(&db, case_id, MASS_START + d * DAY + n * 600).await;
        }
    }
    (app, case_id)
}

#[tokio::test]
async fn an_artefactual_timestamp_no_longer_chooses_the_histogram_resolution() {
    let (app, case_id) = setup_outlier_case().await;

    let unfocused = get_json(
        &app,
        format!("/api/v1/cases/{}/timeline/histogram?buckets=120", case_id),
    )
    .await;
    let focused = get_json(
        &app,
        format!(
            "/api/v1/cases/{}/timeline/histogram?buckets=120&focus=auto",
            case_id
        ),
    )
    .await;

    let coarse = unfocused["bucket_seconds"].as_i64().unwrap();
    let fine = focused["bucket_seconds"].as_i64().unwrap();
    assert!(
        fine < coarse,
        "the focused window must be drawn finer than the whole extent: {fine} vs {coarse}"
    );

    // What was left out is stated, and it is the outlier.
    let focus = &focused["focus"];
    assert_eq!(focus["events_before"].as_i64().unwrap(), 1);
    assert_eq!(focus["events_after"].as_i64().unwrap(), 0);
    assert!(focus["from"].as_i64().unwrap() > 315_532_800);

    // And the extent itself is still reported as the extent: the endpoint says
    // where the case really starts, so a client can say so beside the chart.
    assert_eq!(focused["min_ts"].as_i64().unwrap(), 315_532_800);
    assert_eq!(
        focused["min_ts"], unfocused["min_ts"],
        "focusing the drawing must not restate the case's own span"
    );

    // Every drawn bucket is inside the window it declared.
    let from = focus["from"].as_i64().unwrap();
    let to = focus["to"].as_i64().unwrap();
    for b in focused["buckets"].as_array().unwrap() {
        let start = b["start"].as_i64().unwrap();
        assert!(
            start >= from && start < to,
            "bucket {start} is outside the declared window {from}..{to}"
        );
    }
}

#[tokio::test]
async fn the_focused_bars_and_what_is_outside_them_account_for_every_event() {
    let (app, case_id) = setup_outlier_case().await;
    let focused = get_json(
        &app,
        format!(
            "/api/v1/cases/{}/timeline/histogram?buckets=120&focus=auto",
            case_id
        ),
    )
    .await;

    let drawn: i64 = focused["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["count"].as_i64().unwrap())
        .sum();
    let outside = focused["focus"]["events_before"].as_i64().unwrap()
        + focused["focus"]["events_after"].as_i64().unwrap();
    assert_eq!(
        drawn + outside,
        14 * 40 + 1,
        "a focused chart narrows what is drawn, never what is counted"
    );
}

#[tokio::test]
async fn the_swimlanes_focus_on_the_same_window_as_the_histogram() {
    let (app, case_id) = setup_outlier_case().await;
    let hist = get_json(
        &app,
        format!(
            "/api/v1/cases/{}/timeline/histogram?buckets=120&focus=auto",
            case_id
        ),
    )
    .await;
    let lanes = get_json(
        &app,
        format!(
            "/api/v1/cases/{}/timeline/swimlanes?buckets=120&focus=auto",
            case_id
        ),
    )
    .await;

    // Same window, same width: the two charts are drawn one above the other on
    // the timeline page, and two axes for one case on one screen is the defect
    // this shares its window to avoid.
    assert_eq!(hist["focus"]["from"], lanes["focus"]["from"]);
    assert_eq!(hist["focus"]["to"], lanes["focus"]["to"]);
    assert_eq!(
        hist["focus"]["events_before"],
        lanes["focus"]["events_before"]
    );
    assert_eq!(hist["bucket_seconds"], lanes["bucket_seconds"]);
}

#[tokio::test]
async fn without_the_parameter_both_endpoints_answer_exactly_as_before() {
    let (app, case_id) = setup_outlier_case().await;
    for endpoint in ["histogram", "swimlanes"] {
        let json = get_json(
            &app,
            format!(
                "/api/v1/cases/{}/timeline/{}?buckets=120",
                case_id, endpoint
            ),
        )
        .await;
        assert!(
            json["focus"].is_null(),
            "{endpoint} focused a request that did not ask for it"
        );
    }
}

#[tokio::test]
async fn a_case_with_no_outliers_is_not_focused_and_costs_no_second_query() {
    let (app, case_id, db) = setup_test_app().await;
    for n in 0..100 {
        add_event(&db, case_id, 1_700_000_000 + n * 600).await;
    }
    let json = get_json(
        &app,
        format!(
            "/api/v1/cases/{}/timeline/histogram?buckets=120&focus=auto",
            case_id
        ),
    )
    .await;
    assert!(
        json["focus"].is_null(),
        "nothing was trimmed, so there is nothing to disclose and no window to re-ask about"
    );
}
