//! End-to-end verification that every report / export endpoint produces valid
//! output. Builds a small case with files, a timeline event, a bookmark, and a
//! GPS-tagged record, then exercises HTML, PDF, KML, GeoJSON, timeline
//! (JSON/CSV/PDF), search (JSON/CSV), and bookmark (JSON/CSV) exports.

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
    let case_id = db
        .create_case("Report Export Case", "examiner")
        .await
        .unwrap();

    // A file, a GPS-tagged photo record, and a timeline event.
    let file = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "report.pdf", "path": "/docs/report.pdf", "size": 2048 }),
    );
    db.record_artifact(&file).await.unwrap();

    let photo = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "exif",
            "name": "IMG_1234.JPG",
            "source_path": "/dcim/IMG_1234.JPG",
            "has_gps": true,
            "gps_lat": 37.7749,
            "gps_lon": -122.4194,
            "gps_altitude": 12.5,
            "timestamp": "2023-06-15T14:30:00+00:00",
        }),
    );
    db.record_artifact(&photo).await.unwrap();

    let event = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": 1_700_000_000,
            "timestamp_desc": "File Created",
            "source_module": "plugin.ntfs.mft_parser",
            "short_desc": "report.pdf created",
            "full_details": "{\"filename\": \"report.pdf\"}",
        }),
    );
    db.record_artifact(&event).await.unwrap();

    // A real (empty) search index so the search-export endpoints resolve rather
    // than 500 on a missing service. The index is intentionally leaked for the
    // test's lifetime; it lives in a temp dir the OS reclaims.
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

#[tokio::test]
async fn all_report_exports_produce_valid_output() {
    let (app, _db, case) = setup().await;
    let base = format!("/api/v1/cases/{case}");

    // --- Case HTML ---
    let (s, b) = get(&app, &format!("{base}/export/html")).await;
    assert_eq!(s, StatusCode::OK, "html status");
    let html = String::from_utf8_lossy(&b);
    assert!(html.starts_with("<!DOCTYPE html>"), "html doctype");
    assert!(html.contains("Report Export Case"), "html has case name");

    // --- Case PDF ---
    let (s, b) = get(&app, &format!("{base}/export/pdf")).await;
    assert_eq!(s, StatusCode::OK, "pdf status");
    assert!(b.starts_with(b"%PDF"), "pdf magic");

    // --- KML (new) — must contain the GPS coordinate ---
    let (s, b) = get(&app, &format!("{base}/export/kml")).await;
    assert_eq!(s, StatusCode::OK, "kml status");
    let kml = String::from_utf8_lossy(&b);
    assert!(kml.contains("<kml"), "kml root");
    assert!(kml.contains("-122.4194"), "kml has longitude");
    assert!(kml.contains("37.7749"), "kml has latitude");

    // --- GeoJSON (new) — valid JSON with the coordinate ---
    let (s, b) = get(&app, &format!("{base}/export/geojson")).await;
    assert_eq!(s, StatusCode::OK, "geojson status");
    let geo: serde_json::Value = serde_json::from_slice(&b).expect("geojson is valid json");
    assert_eq!(geo["type"], "FeatureCollection");
    assert!(
        !geo["features"].as_array().unwrap().is_empty(),
        "geojson has a feature"
    );

    // --- Timeline JSON / CSV / PDF ---
    let (s, b) = get(&app, &format!("{base}/timeline/export/json")).await;
    assert_eq!(s, StatusCode::OK, "timeline json status");
    let _: serde_json::Value = serde_json::from_slice(&b).expect("timeline json valid");

    let (s, b) = get(&app, &format!("{base}/timeline/export/csv")).await;
    assert_eq!(s, StatusCode::OK, "timeline csv status");
    assert!(
        String::from_utf8_lossy(&b).contains(','),
        "timeline csv has columns"
    );

    let (s, b) = get(&app, &format!("{base}/timeline/export/pdf")).await;
    assert_eq!(s, StatusCode::OK, "timeline pdf status");
    assert!(b.starts_with(b"%PDF"), "timeline pdf magic");

    // --- Search JSON / CSV ---
    let (s, b) = get(&app, &format!("{base}/search/export/json?q=report")).await;
    assert_eq!(s, StatusCode::OK, "search json status");
    let _: serde_json::Value = serde_json::from_slice(&b).expect("search json valid");

    let (s, _b) = get(&app, &format!("{base}/search/export/csv?q=report")).await;
    assert_eq!(s, StatusCode::OK, "search csv status");

    // --- Bookmarks JSON / CSV ---
    let (s, b) = get(&app, &format!("{base}/bookmarks/export/json")).await;
    assert_eq!(s, StatusCode::OK, "bookmarks json status");
    let _: serde_json::Value = serde_json::from_slice(&b).expect("bookmarks json valid");

    let (s, _b) = get(&app, &format!("{base}/bookmarks/export/csv")).await;
    assert_eq!(s, StatusCode::OK, "bookmarks csv status");
}

/// B4-018: the GPS query behind both exports stops at 100,000 points and says
/// nothing, so a capped KML/GeoJSON file was byte-identical to a complete one.
/// Every export now carries a truncation verdict — including `false`, because a
/// disclosure that appears only on bad news teaches readers that its absence is
/// an assurance.
#[tokio::test]
async fn geo_exports_state_whether_the_point_list_was_capped() {
    let (app, _db, case) = setup().await;
    let base = format!("/api/v1/cases/{case}");

    for format in ["kml", "geojson"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{base}/export/{format}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{format} status");
        assert_eq!(
            resp.headers()
                .get("x-geo-points-truncated")
                .and_then(|v| v.to_str().ok()),
            Some("false"),
            "{format} export must state its truncation verdict"
        );
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("AT LEAST"),
            "{format}: an uncapped export must not carry the cap notice"
        );
    }
}
