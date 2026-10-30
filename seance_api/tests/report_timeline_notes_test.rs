//! An examiner's reason for tagging a timeline event has to survive into the
//! report, and the report is the only place a court ever sees it.
//!
//! `gather_report_data` mapped tagged events through `|(event, _examiner,
//! _note)|` — both fields discarded on the way to the renderer — so the
//! "Timeline Highlights" table printed a bare MFT description under a heading
//! that asserted the event mattered, with nothing anywhere saying why or who
//! said so. The renderers are unit-tested in `seance_reporting`; this test
//! covers the join between them, which is where the fields were being dropped.

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

const NOTE: &str = "matches CCTV entry time - key exhibit for interview 2";
const EXAMINER: &str = "Analyst A";

async fn setup() -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Tagged Timeline Case", "examiner")
        .await
        .unwrap();

    let tagged = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": 1_700_000_000,
            "timestamp_desc": "Device Connected",
            "source_module": "plugin.windows.registry",
            "short_desc": "USB device inserted",
            "full_details": "{}",
        }),
    );
    db.record_artifact(&tagged).await.unwrap();

    // An untagged event, so the test can tell "the note reached the highlight"
    // apart from "the note was printed against everything".
    let untagged = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": 1_700_000_500,
            "timestamp_desc": "File Created",
            "source_module": "plugin.ntfs.mft_parser",
            "short_desc": "ordinary.txt created",
            "full_details": "{}",
        }),
    );
    db.record_artifact(&untagged).await.unwrap();

    db.create_timeline_tag(case_id, tagged.id, Some(EXAMINER), Some(NOTE))
        .await
        .unwrap();

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
    (router_with_auth(app_state, Some(auth_config)), case_id)
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
async fn the_examiners_reason_for_a_highlight_reaches_the_html_report() {
    let (app, case) = setup().await;
    let (status, body) = get(&app, &format!("/api/v1/cases/{case}/export/html")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);

    assert!(
        html.contains("USB device inserted"),
        "the tagged event is missing from the report"
    );
    assert!(
        html.contains(NOTE),
        "the examiner's note did not reach the report: this is the defect"
    );
    assert!(
        html.contains(EXAMINER),
        "the examiner who tagged the event did not reach the report"
    );

    // The highlights table is the only place the annotation belongs. The full
    // timeline below it lists events nobody tagged, and a Note column there
    // would print a blank beside every one of them — which reads as an examiner
    // having looked and found nothing worth saying.
    let full_timeline = html
        .split("<h2>Timeline</h2>")
        .nth(1)
        .expect("the report has a full timeline section");
    assert!(
        !full_timeline.contains("<th>Note</th>"),
        "the full timeline grew an annotation column it has no data for"
    );
    assert!(
        full_timeline.contains("ordinary.txt created"),
        "the untagged event should still be in the full timeline"
    );
}

#[tokio::test]
async fn the_workbook_carries_the_note_the_html_report_does() {
    let (app, case) = setup().await;
    let (status, body) = get(&app, &format!("/api/v1/cases/{case}/export/xlsx")).await;
    assert_eq!(status, StatusCode::OK);
    // A workbook is a ZIP of XML; the shared-strings part holds the cell text.
    // Searching the raw bytes is enough to prove the note was written into the
    // document rather than dropped before it got there.
    assert!(body.starts_with(b"PK"), "the xlsx export is not a workbook");
    let text = String::from_utf8_lossy(&body);
    // The strings part is deflated, so the note is not necessarily findable in
    // the raw bytes. Decompress the workbook and look in the parts.
    let mut found = text.contains(NOTE);
    if !found {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&body[..])).expect("valid zip");
        for i in 0..zip.len() {
            use std::io::Read;
            let mut part = zip.by_index(i).unwrap();
            let mut contents = String::new();
            if part.read_to_string(&mut contents).is_ok() && contents.contains(NOTE) {
                found = true;
                break;
            }
        }
    }
    assert!(found, "the examiner's note did not reach the workbook");
}
