//! The API must gzip-compress responses when the client offers
//! `Accept-Encoding: gzip`. Forensic JSON/HTML is highly compressible, so this
//! is a large bandwidth win across every endpoint. Verifies the compressed body
//! round-trips to exactly the uncompressed body.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use flate2::read::GzDecoder;
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    orchestrator::{CancellationHandle, Orchestrator},
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::io::Read;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Compression Case", "examiner")
        .await
        .unwrap();

    // Timeline events give a deterministic, compressible export body (no
    // per-request timestamp), comfortably over the compressor's min size.
    for i in 0..60 {
        let e = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": 1_700_000_000 + i,
                "timestamp_desc": "File Created",
                "source_module": "plugin.ntfs.mft_parser",
                "short_desc": format!("event number {i} on the timeline"),
                "full_details": format!("{{\"filename\": \"file_{i}.txt\"}}"),
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

#[tokio::test]
async fn json_export_is_gzip_compressed_when_requested() {
    let (app, case) = setup().await;
    let uri = format!("/api/v1/cases/{case}/timeline/export/json");

    // Baseline: no Accept-Encoding -> plain, uncompressed body.
    let plain_resp = app
        .clone()
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(plain_resp.status(), StatusCode::OK);
    assert!(
        plain_resp.headers().get(header::CONTENT_ENCODING).is_none(),
        "unrequested response must not be encoded"
    );
    let plain = to_bytes(plain_resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    // With Accept-Encoding: gzip -> gzipped body that decodes to the same bytes.
    let gz_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(header::ACCEPT_ENCODING, "gzip")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(gz_resp.status(), StatusCode::OK);
    assert_eq!(
        gz_resp
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "gzip must be negotiated when offered"
    );

    let gz_body = to_bytes(gz_resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    assert!(
        gz_body.len() < plain.len(),
        "compressed body ({}) must be smaller than plain ({})",
        gz_body.len(),
        plain.len()
    );

    let mut decoded = Vec::new();
    GzDecoder::new(&gz_body[..])
        .read_to_end(&mut decoded)
        .expect("body must be valid gzip");
    // The two exports were taken at two instants, and each states its own
    // `exported_at`; compare the documents with that one field blanked.
    let without_export_time = |bytes: &[u8]| -> serde_json::Value {
        let mut doc: serde_json::Value = serde_json::from_slice(bytes).expect("valid JSON");
        doc["exported_at"] = serde_json::Value::Null;
        doc
    };
    assert_eq!(
        without_export_time(&decoded),
        without_export_time(&plain),
        "decompressed body must match the plain body"
    );
}
