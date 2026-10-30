//! The /geo/points endpoint returns every GPS point in one request, applying
//! the record-type rules server-side: EXIF needs an explicit has_gps flag,
//! other coordinate-carrying types qualify on finite coords, and non-geo
//! records are excluded. Replaces the frontend's per-type scan (capped at 500).

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
    let case_id = db.create_case("Geo Case", "examiner").await.unwrap();

    let rec =
        |meta: serde_json::Value| Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta);

    // 1) EXIF photo WITH has_gps -> included, rich fields.
    db.record_artifact(&rec(json!({
        "type": "exif", "has_gps": true,
        "gps_lat": 37.7749, "gps_lon": -122.4194,
        "make": "Canon", "model": "EOS",
        "datetime_original": "2023:06:15 14:30:00",
        "source_name": "IMG_1.JPG",
    })))
    .await
    .unwrap();

    // 2) EXIF photo WITHOUT has_gps -> excluded even though it has coords.
    db.record_artifact(&rec(json!({
        "type": "exif", "gps_lat": 1.0, "gps_lon": 2.0, "source_name": "IMG_2.JPG",
    })))
    .await
    .unwrap();

    // 3) Non-exif location record with coords -> included (no flag needed).
    db.record_artifact(&rec(json!({
        "type": "browser_location", "gps_lat": 51.5, "gps_lon": -0.12, "source_name": "history.db",
    })))
    .await
    .unwrap();

    // 4) A record with no coordinates -> excluded.
    db.record_artifact(&rec(json!({ "type": "exif", "source_name": "no_gps.jpg" })))
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
    (router_with_auth(app_state, Some(auth_config)), case_id)
}

#[tokio::test]
async fn geo_points_endpoint_applies_record_rules() {
    let (app, case) = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cases/{case}/geo/points"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // One flat listing envelope, like every other: `items` plus the flags. The
    // body used to be `{"points":{"points":[...],"unusable":N}}` -- the struct
    // wrapped a second time -- so nothing reading `points` as an array ever saw
    // a point.
    let points = v["items"]
        .as_array()
        .expect("geo points travel under `items`");

    // Only the has_gps EXIF and the browser_location record qualify.
    assert_eq!(
        points.len(),
        2,
        "excludes no-flag exif and the coord-less record"
    );

    // A map has no scrollback, so this call refuses past its ceiling rather
    // than truncating: `has_more` is false by contract, and the ceiling is
    // still named so a caller can quote it.
    assert_eq!(v["has_more"], serde_json::json!(false));
    assert_eq!(v["truncated"], serde_json::json!(false));
    assert_eq!(v["limit"], serde_json::json!(seance_db::GEO_MAP_POINT_CAP));
    // Rows the SQL said carried a fix but that would not decode. Zero here, and
    // it must be a real zero: `null` would mean "not determined", and a map
    // missing fixes must never be drawn as a map of every fix (B8-009). The
    // no-flag EXIF and the coord-less record are qualification failures, not
    // decode failures, so neither counts towards this.
    assert_eq!(
        v["undecodable"],
        serde_json::json!(0),
        "the count of unusable GPS rows must reach the map, not just the log"
    );

    let exif = points
        .iter()
        .find(|p| p["type"] == "exif")
        .expect("exif point present");
    assert_eq!(exif["lat"], 37.7749);
    assert_eq!(exif["lon"], -122.4194);
    assert_eq!(
        exif["camera"], "Canon EOS",
        "camera falls back to make+model"
    );
    assert_eq!(exif["timestamp"], "2023:06:15 14:30:00");
    assert_eq!(exif["sourceName"], "IMG_1.JPG");
    // id is a dashed UUID (the jump-to-artifact target).
    assert!(
        Uuid::parse_str(exif["id"].as_str().unwrap()).is_ok(),
        "id is a dashed UUID"
    );

    assert!(
        points.iter().any(|p| p["type"] == "browser_location"),
        "non-exif coordinate record included"
    );
}
