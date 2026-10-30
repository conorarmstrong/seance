//! `GET /api/v1/cases/:id/export/docx` (ROADMAP §2.10), and the
//! communications network the five document exports carry.
//!
//! The DOCX renderer landed in `seance_reporting` with a `ReportExtras`
//! carrier for the communications graph, but the API kept calling the plain
//! `render_*` forms, so every live HTML/PDF/RTF/XML report printed "not
//! computed" for a network the store could have supplied. These tests drive
//! the real router: the DOCX route exists, is audited, and every document
//! export names the participants the case actually holds.

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
use std::io::Read;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const DOCX_MIME: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

async fn setup() -> (axum::Router, Arc<SqliteConnection>, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Docx Export Case", "examiner")
        .await
        .unwrap();

    // Two WhatsApp messages with one correspondent: the communications graph
    // is "this device" linked to that one peer, weight 2.
    for body in ["first", "second"] {
        let msg = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "WhatsApp",
                "contact_jid": "447700900123@s.whatsapp.net",
                "body": body,
                "timestamp": "2023-06-15T14:30:00+00:00",
            }),
        );
        db.record_artifact(&msg).await.unwrap();
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
    (router_with_auth(app_state, Some(auth_config)), db, case_id)
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, bytes.to_vec())
}

/// One part of the OOXML package, as text.
fn docx_part(bytes: &[u8], name: &str) -> String {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("a ZIP archive");
    let mut file = zip.by_name(name).unwrap_or_else(|e| panic!("{name}: {e}"));
    let mut s = String::new();
    file.read_to_string(&mut s).unwrap();
    s
}

#[tokio::test]
async fn the_docx_route_serves_a_word_document_named_for_the_case() {
    let (app, _db, case) = setup().await;
    let (status, headers, bytes) = get(&app, &format!("/api/v1/cases/{case}/export/docx")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(headers["content-type"], DOCX_MIME);
    assert_eq!(
        headers["content-disposition"],
        "attachment; filename=\"report_Docx_Export_Case.docx\""
    );
    assert!(bytes.starts_with(b"PK"), "a DOCX is a ZIP package");

    let types = docx_part(&bytes, "[Content_Types].xml");
    assert!(
        types.contains("wordprocessingml.document.main+xml"),
        "{types}"
    );
    let document = docx_part(&bytes, "word/document.xml");
    assert!(
        document.contains("Docx Export Case"),
        "case name in the body"
    );
}

#[tokio::test]
async fn the_docx_export_is_audited_like_its_siblings() {
    let (app, _db, case) = setup().await;
    let (status, _, _) = get(&app, &format!("/api/v1/cases/{case}/export/docx")).await;
    assert_eq!(status, StatusCode::OK);

    let (_, _, log) = get(&app, &format!("/api/v1/cases/{case}/audit_log")).await;
    let log: serde_json::Value = serde_json::from_slice(&log).unwrap();
    let exported: Vec<&serde_json::Value> = log["events"]
        .as_array()
        .expect("audit events")
        .iter()
        .filter(|e| e["action"] == "case_report_exported")
        .collect();
    assert!(
        exported
            .iter()
            .any(|e| e["details"].as_str() == Some("format: docx")),
        "an export becomes an exhibit and has to be accounted for: {exported:?}"
    );
}

/// The store computes the network; the renderer prints it only when the API
/// hands it over. Before this change every document export printed the
/// "not computed" sentence over a case that held messaging records.
#[tokio::test]
async fn every_document_export_carries_the_computed_communications_network() {
    let (app, _db, case) = setup().await;
    let base = format!("/api/v1/cases/{case}");
    let peer = "447700900123@s.whatsapp.net";

    let (status, _, bytes) = get(&app, &format!("{base}/export/docx")).await;
    assert_eq!(status, StatusCode::OK);
    let document = docx_part(&bytes, "word/document.xml");
    assert!(document.contains("Communications Network"), "{document}");
    assert!(
        !document.contains(seance_reporting::report::COMMUNICATIONS_NOT_COMPUTED),
        "docx: the network was computed, so the report must not say it was not"
    );
    assert!(document.contains(peer), "docx names the correspondent");
    assert!(
        document.contains("This device"),
        "docx names the device node"
    );

    for (format, mime_hint) in [("html", "<h2>"), ("rtf", "{\\rtf"), ("xml", "<?xml")] {
        let (status, _, bytes) = get(&app, &format!("{base}/export/{format}")).await;
        assert_eq!(status, StatusCode::OK, "{format}");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains(mime_hint),
            "{format}: not the expected document"
        );
        assert!(
            !text.contains(seance_reporting::report::COMMUNICATIONS_NOT_COMPUTED),
            "{format}: the network was computed, so the report must not say it was not"
        );
        assert!(text.contains(peer), "{format} names the correspondent");
    }

    // The PDF's content streams are compressed, so its text cannot be grepped
    // here; the extras-carrying render is pinned in seance_reporting's own
    // tests, and this checks only that the route still produces a PDF.
    let (status, _, bytes) = get(&app, &format!("{base}/export/pdf")).await;
    assert_eq!(status, StatusCode::OK, "pdf");
    assert!(bytes.starts_with(b"%PDF"));
}

/// A case with no messaging or email records: the network was computed and
/// found nobody. That is a different sentence from "not computed", and the
/// export must print the one that is true.
#[tokio::test]
async fn a_case_with_no_correspondents_says_the_network_was_computed_and_empty() {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case = db.create_case("Quiet Case", "examiner").await.unwrap();
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
    let app = router_with_auth(
        app_state,
        Some(AuthConfig {
            jwt_secret: "test-secret".to_string(),
            admin_username: "admin".to_string(),
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );

    let (status, _, bytes) = get(&app, &format!("/api/v1/cases/{case}/export/html")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&bytes);
    assert!(!html.contains(seance_reporting::report::COMMUNICATIONS_NOT_COMPUTED));
    assert!(
        html.contains("found no participants"),
        "computed-and-empty is stated as such: {html}"
    );
}
