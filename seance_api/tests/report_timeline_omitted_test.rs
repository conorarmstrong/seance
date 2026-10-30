//! CR-048: a timeline event dropped for want of a usable timestamp is counted
//! and the report says so, in the completeness statement and the Timeline
//! section. Synthetic: one good and one bad-timestamp TimelineEvent.

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
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup() -> (axum::Router, Arc<SqliteConnection>, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("T", "examiner").await.unwrap();
    let index_dir = tempfile::tempdir().unwrap();
    let search_service =
        Arc::new(seance_search::SearchService::new(index_dir.path()).expect("search index"));
    std::mem::forget(index_dir);

    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: orchestrator.task_submitter(),
        event_sender: orchestrator.event_sender(),
        ad_hoc_sender: orchestrator.ad_hoc_submitter(),
        status_sender: orchestrator.status_sender(),
        active_tasks: orchestrator.active_tasks(),
        search_service: Some(search_service),
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
    (router_with_auth(app_state, Some(auth_config)), db, case_id)
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, bytes.to_vec())
}

fn event(ts: serde_json::Value, desc: &str) -> Artifact {
    Artifact::new(
        Uuid::nil(),
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": ts,
            "timestamp_desc": "Created",
            "source_module": "test.module",
            "short_desc": desc,
            "full_details": "{}",
        }),
    )
}

#[tokio::test]
async fn the_report_discloses_timeline_events_that_could_not_be_placed() {
    let (app, db, case) = setup().await;
    let mut good = event(json!(1_700_000_000), "placed event");
    let mut bad = event(json!("garbage"), "unplaced event");
    good.case_id = case;
    bad.case_id = case;
    db.record_artifacts_batch(&[good, bad]).await.unwrap();

    let (status, body) = get(&app, &format!("/api/v1/cases/{case}/export/html")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    let sentence = "1 timeline event(s) could not be placed on the timeline";
    assert!(
        html.matches(sentence).count() >= 2,
        "the completeness statement and the Timeline section must both say so"
    );
    let timeline = html
        .split("<h2>Timeline</h2>")
        .nth(1)
        .expect("timeline section");
    assert!(
        timeline.contains(sentence),
        "the Timeline section is silent"
    );
    assert!(html.contains("INCOMPLETE RESULTS"));
}

#[tokio::test]
async fn a_clean_timeline_makes_no_such_statement() {
    let (app, db, case) = setup().await;
    let mut good = event(json!(1_700_000_000), "placed event");
    good.case_id = case;
    db.record_artifacts_batch(&[good]).await.unwrap();
    let (_, body) = get(&app, &format!("/api/v1/cases/{case}/export/html")).await;
    assert!(!String::from_utf8_lossy(&body).contains("could not be placed on the timeline"));
}
