//! The layer export over HTTP (ROADMAP §5.3, the `layerwriter` equivalent).
//!
//! `GET /cases/{id}/memory/layer/{image}/manifest` states the holes of the
//! image's decoded physical layer; `GET …/raw` streams that layer as an
//! address-aligned raw file whose fill ranges are exactly the manifest's, and
//! names the manifest it belongs to by digest.
//!
//! The fixture is a synthetic LiME file built here: three 4 KiB runs at
//! 0x0000, 0x2000 and 0x4000, so the decoded space is 0x5000 bytes with two
//! 4 KiB holes. It pins the mechanism, not the behaviour on real evidence; that
//! is `seance_memory/tests/layer_export_real_test.rs` on the corpus crash dump.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
};
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

struct Harness {
    app: axum::Router,
    db: Arc<SqliteConnection>,
    case_id: Uuid,
    _dir: tempfile::TempDir,
    image_record: Uuid,
    evidence: Uuid,
}

fn lime_file() -> Vec<u8> {
    fn header(start: u64, end: u64) -> Vec<u8> {
        let mut h = Vec::with_capacity(32);
        h.extend_from_slice(&0x4C69_4D45u32.to_le_bytes());
        h.extend_from_slice(&1u32.to_le_bytes());
        h.extend_from_slice(&start.to_le_bytes());
        h.extend_from_slice(&end.to_le_bytes());
        h.extend_from_slice(&0u64.to_le_bytes());
        h
    }
    let mut file = Vec::new();
    for (start, fill) in [(0x0000u64, 0xA1u8), (0x2000, 0xB2), (0x4000, 0xC3)] {
        file.extend_from_slice(&header(start, start + 0xFFF));
        file.extend_from_slice(&[fill; 0x1000]);
    }
    file
}

async fn harness(addressable: u64) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("capture.lime");
    std::fs::write(&image, lime_file()).unwrap();

    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Layer export", "Examiner").await.unwrap();

    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, _ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(100);
    let active_tasks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let app_state = AppState {
        db: db.clone(),
        orchestrator_sender: seance_core::orchestrator::TaskSubmitter::new(
            tx,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
        evidence_roots: seance_api::EvidenceRootPolicy::unrestricted(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };
    let app = router_with_auth(
        app_state,
        Some(AuthConfig {
            jwt_secret: "test-secret".to_string(),
            admin_username: "admin".to_string(),
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );

    let evidence = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "capture.lime",
            "path": image.to_string_lossy(),
            "source_path": image.to_string_lossy(),
        }),
    );
    db.record_artifact(&evidence).await.unwrap();
    let record = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "MemoryImage",
            "name": "Memory image (lime)",
            "image_format": "lime",
            "addressable_bytes": addressable,
        }),
    )
    .with_parent(evidence.id);
    db.record_artifact(&record).await.unwrap();

    Harness {
        app,
        db,
        case_id,
        _dir: dir,
        image_record: record.id,
        evidence: evidence.id,
    }
}

async fn get(app: &axum::Router, uri: String) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    (status, headers, bytes)
}

#[tokio::test]
async fn the_manifest_names_the_holes_of_the_decoded_layer() {
    let h = harness(0x5000).await;
    let (status, _, body) = get(
        &h.app,
        format!(
            "/api/v1/cases/{}/memory/layer/{}/manifest",
            h.case_id, h.image_record
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let v: Value = serde_json::from_slice(&body).unwrap();
    let m = &v["manifest"];
    assert_eq!(m["total_bytes"], 0x5000);
    assert_eq!(m["hole_count"], 2);
    assert_eq!(m["hole_bytes"], 0x2000);
    assert_eq!(m["holes"][0]["start"], 0x1000);
    assert_eq!(m["holes"][1]["start"], 0x3000);
    assert_eq!(m["source"]["image_id"], h.image_record.to_string());
    assert_eq!(m["source"]["image_format"], "lime");
    assert!(v["manifest_sha256"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn the_raw_export_is_address_aligned_and_names_its_manifest() {
    let h = harness(0x5000).await;
    let (_, _, manifest) = get(
        &h.app,
        format!(
            "/api/v1/cases/{}/memory/layer/{}/manifest",
            h.case_id, h.image_record
        ),
    )
    .await;
    let manifest: Value = serde_json::from_slice(&manifest).unwrap();

    let (status, headers, body) = get(
        &h.app,
        format!(
            "/api/v1/cases/{}/memory/layer/{}/raw",
            h.case_id, h.image_record
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body.len(), 0x5000);
    assert!(body[..0x1000].iter().all(|b| *b == 0xA1));
    assert!(body[0x1000..0x2000].iter().all(|b| *b == 0));
    assert!(body[0x2000..0x3000].iter().all(|b| *b == 0xB2));
    assert!(body[0x3000..0x4000].iter().all(|b| *b == 0));
    assert!(body[0x4000..].iter().all(|b| *b == 0xC3));
    assert_eq!(headers["content-length"], "20480");
    assert_eq!(headers["x-layer-hole-count"], "2");
    assert_eq!(headers["x-layer-hole-bytes"], "8192");
    assert_eq!(
        headers["x-layer-manifest-sha256"].to_str().unwrap(),
        manifest["manifest_sha256"].as_str().unwrap(),
        "the raw file must name the manifest that describes it"
    );

    // Handing evidence bytes out of the product is audited.
    let (_, _, audit) = get(&h.app, format!("/api/v1/cases/{}/audit_log", h.case_id)).await;
    assert!(
        String::from_utf8_lossy(&audit).contains("memory_layer_exported"),
        "the export must be in the audit log"
    );
}

#[tokio::test]
async fn a_sub_range_is_exported_and_a_range_past_the_layer_is_refused() {
    let h = harness(0x5000).await;
    let (status, headers, body) = get(
        &h.app,
        format!(
            "/api/v1/cases/{}/memory/layer/{}/raw?start=4096&end=12288",
            h.case_id, h.image_record
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), 0x2000);
    assert!(body[..0x1000].iter().all(|b| *b == 0));
    assert_eq!(headers["x-layer-hole-count"], "1");

    let (status, _, _) = get(
        &h.app,
        format!(
            "/api/v1/cases/{}/memory/layer/{}/raw?start=0&end=40960",
            h.case_id, h.image_record
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_image_that_no_longer_decodes_to_what_the_record_says_is_refused() {
    let h = harness(0x6000).await;
    let (status, _, body) = get(
        &h.app,
        format!(
            "/api/v1/cases/{}/memory/layer/{}/manifest",
            h.case_id, h.image_record
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn only_a_memory_image_record_in_this_case_is_exported() {
    let h = harness(0x5000).await;
    let (status, _, _) = get(
        &h.app,
        format!(
            "/api/v1/cases/{}/memory/layer/{}/raw",
            h.case_id, h.evidence
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = get(
        &h.app,
        format!(
            "/api/v1/cases/{}/memory/layer/{}/raw",
            h.case_id,
            Uuid::new_v4()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let _ = &h.db;
}
