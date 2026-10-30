//! Paging parameters at the edges of their range must be answered, not
//! panicked on. `overflow-checks = true` is set for release builds, so an
//! unchecked multiply on a request parameter is a live 500, not a wrap.

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

async fn setup() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Paging Case", "examiner").await.unwrap();
    for i in 0..5 {
        let e = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_700_000_000 + i,
                "timestamp_desc": "File Created",
                "source_module": "plugin.ntfs.mft_parser",
                "short_desc": format!("event {i}"),
                "full_details": "{}",
            }),
        );
        db.record_artifact(&e).await.unwrap();
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

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

/// `(page - 1) * page_size` overflowed `i64` at the largest page a client can
/// name, and with overflow checks on in release that was a panic in the
/// handler, not an empty page.
#[tokio::test]
async fn the_largest_page_number_is_an_empty_page_not_a_panic() {
    let (app, case) = setup().await;
    let (status, body) = get(
        &app,
        &format!("/api/v1/cases/{case}/timeline?page=9223372036854775807&page_size=100"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["events"].as_array().map(Vec::len), Some(0), "{body}");
    assert_eq!(
        body["pagination"]["total_count"], 5,
        "the population is still stated: {body}"
    );
}

/// The floor and the ceiling of the two parameters are honoured rather than
/// wrapped: page 0 is page 1, and a page size past the cap is the cap.
#[tokio::test]
async fn out_of_range_paging_parameters_are_clamped() {
    let (app, case) = setup().await;
    let (status, body) = get(
        &app,
        &format!("/api/v1/cases/{case}/timeline?page=0&page_size=99999999999"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["events"].as_array().map(Vec::len), Some(5), "{body}");
    assert_eq!(body["pagination"]["page"], 1, "{body}");
}
