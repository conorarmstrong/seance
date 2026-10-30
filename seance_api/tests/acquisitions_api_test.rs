//! The acquisition dead zone, and the ingest that failed while nobody was
//! looking.
//!
//! An ingest used to be observable only by the browser tab that submitted it:
//! progress and outcome went out on a broadcast with no replay, and the one
//! durable trace was an audit event written at REQUEST time under the name
//! `evidence_ingested` — a claim that the evidence had been ingested, recorded
//! before a single byte had been hashed. A colleague, a second tab, or the same
//! examiner after a reload saw a case with nothing running and nothing failed.
//!
//! These tests pin the replacement: the request-time event says an ingest was
//! REQUESTED, the background task records the outcome, and
//! `GET /cases/:id/acquisitions` answers "what is this case acquiring, and what
//! has failed?" for any reader, from state that does not depend on having been
//! connected at the time.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use seance_api::{router_with_auth, AppState, AuthConfig};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

/// Big enough that its acquisition hash is still running when the test asks
/// what the case is acquiring.
const SLOW_SOURCE_BYTES: usize = 32 * 1024 * 1024;

/// The 8-byte signature every real EWF segment file begins with. Segment-set
/// detection is content-based, so a synthetic set needs it.
const EWF_MAGIC: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";

/// The receivers the server would ordinarily hold: the orchestrator draining
/// the ingest queue, and the SSE fan-out. A test that drops them closes the
/// queue, and every ingest then fails on the send — which is a real failure
/// mode, but not the one under test here.
struct RuntimeEnds {
    _orchestrator: tokio::sync::mpsc::UnboundedReceiver<seance_core::artifact::Artifact>,
    _tasks: tokio::sync::mpsc::UnboundedReceiver<seance_core::artifact::Artifact>,
    _ad_hoc: tokio::sync::mpsc::Receiver<seance_core::profile::AdHocRequest>,
    _events: tokio::sync::broadcast::Receiver<seance_core::artifact::Artifact>,
    _status: tokio::sync::broadcast::Receiver<seance_core::orchestrator::OrchestratorEvent>,
}

async fn setup_test_app() -> (axum::Router, Uuid, Arc<SqliteConnection>, RuntimeEnds) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db
        .create_case("Acquisition Visibility Case", "Test Examiner")
        .await
        .unwrap();

    let (tx, orchestrator_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = tokio::sync::broadcast::channel(100);
    let (task_tx, task_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ad_hoc_tx, ad_hoc_rx) = tokio::sync::mpsc::channel(100);
    let (status_tx, status_rx) = tokio::sync::broadcast::channel(256);
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
        evidence_roots: seance_api::EvidenceRootPolicy::unrestricted(),
        cancellation: seance_core::orchestrator::CancellationHandle::new(),
    };

    let auth_config = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        admin_username: "admin".to_string(),
        admin_password_hash: String::new(),
        enabled: false,
    };
    (
        router_with_auth(app_state, Some(auth_config)),
        case_id,
        db,
        RuntimeEnds {
            _orchestrator: orchestrator_rx,
            _tasks: task_rx,
            _ad_hoc: ad_hoc_rx,
            _events: event_rx,
            _status: status_rx,
        },
    )
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn get(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

async fn ingest(app: &axum::Router, case_id: Uuid, path: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/cases/{}/ingest", case_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "path": path }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

async fn acquisitions(app: &axum::Router, case_id: Uuid) -> Value {
    let (status, body) = get(app, format!("/api/v1/cases/{}/acquisitions", case_id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn audit_actions(db: &SqliteConnection, case_id: Uuid) -> Vec<String> {
    db.get_audit_log(case_id, 200, 0)
        .await
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// Poll the audit log until `action` appears, so a background outcome can be
/// awaited without reaching for the broadcast this whole feature exists to stop
/// depending on.
async fn await_audit(db: &SqliteConnection, case_id: Uuid, action: &str) {
    for _ in 0..600 {
        if audit_actions(db, case_id).await.iter().any(|a| a == action) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!(
        "audit action '{action}' never appeared; the case recorded {:?}",
        audit_actions(db, case_id).await
    );
}

/// The request-time audit event must claim only what has happened at the moment
/// it is written: an ingest was requested. The old name asserted the evidence
/// had been ingested, before the first byte was read — and if the hash then
/// failed, that claim stayed on the record uncorrected.
#[tokio::test]
async fn ingest_audits_a_request_and_then_its_outcome() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    let path = std::env::temp_dir().join(format!("seance_acq_{}.bin", Uuid::new_v4()));
    std::fs::write(&path, b"hello").unwrap();

    let (status, body) = ingest(&app, case_id, path.to_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    await_audit(&db, case_id, "evidence_ingest_completed").await;
    let actions = audit_actions(&db, case_id).await;
    assert!(
        actions.iter().any(|a| a == "evidence_ingest_requested"),
        "the requester's event must say an ingest was requested: {actions:?}"
    );
    assert!(
        !actions.iter().any(|a| a == "evidence_ingested"),
        "no event may claim the evidence was ingested before the hash ran: {actions:?}"
    );

    // The requester is still named on the request event — attribution was the
    // reason it is written at request time in the first place.
    let requested = db
        .get_audit_log_filtered(
            case_id,
            None,
            Some("evidence_ingest_requested"),
            None,
            None,
            None,
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(requested.len(), 1);
    // Auth is disabled in this harness, so the requester is the local user; the
    // point is that the event names WHO asked, not which name it is.
    assert_eq!(requested[0]["user_id"], "local");
    assert!(requested[0]["details"]
        .as_str()
        .unwrap()
        .contains(path.to_str().unwrap()));

    std::fs::remove_file(&path).ok();
}

/// The dead zone itself: a second reader — another tab, another examiner — asks
/// the case what it is acquiring and gets the exhibit, its phase and its size.
#[tokio::test]
async fn a_running_acquisition_is_reported_to_any_reader() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    let empty = acquisitions(&app, case_id).await;
    assert_eq!(empty["in_flight"].as_array().unwrap().len(), 0);
    assert_eq!(empty["in_flight_count"], 0);
    assert!(
        empty["population"].as_str().is_some(),
        "the response must state what population it is reporting"
    );

    let path = std::env::temp_dir().join(format!("seance_acq_{}.img", Uuid::new_v4()));
    std::fs::write(&path, vec![0x5a; SLOW_SOURCE_BYTES]).unwrap();
    let (status, body) = ingest(&app, case_id, path.to_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let artifact_id = body["artifact_id"].as_str().unwrap().to_string();

    let running = acquisitions(&app, case_id).await;
    let entries = running["in_flight"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{running}");
    assert_eq!(entries[0]["artifact_id"], artifact_id);
    assert_eq!(entries[0]["source_path"], path.to_str().unwrap());
    assert_eq!(
        entries[0]["live"], true,
        "this server is carrying the ingest, and must say so"
    );
    assert!(
        entries[0]["phase"] == "hashing" || entries[0]["phase"] == "queued",
        "{running}"
    );
    assert_eq!(running["live_count"], 1, "{running}");

    await_audit(&db, case_id, "evidence_ingest_completed").await;
    let finished = acquisitions(&app, case_id).await;
    assert_eq!(
        finished["in_flight"].as_array().unwrap().len(),
        0,
        "a finished acquisition must stop being reported as in flight: {finished}"
    );
    assert_eq!(
        finished["unresolved"].as_array().unwrap().len(),
        0,
        "nor may it reappear as an attempt whose disposition is unknown — its outcome is on \
         the record: {finished}"
    );
    assert_eq!(finished["attempts_resolved_by_outcome"], 1, "{finished}");

    std::fs::remove_file(&path).ok();
}

/// A failed ingest has to outlive the tab that submitted it. The toast is gone,
/// the SSE event was never heard, and the examiner is back at their desk: the
/// case must still be able to say the exhibit was attempted and failed, and
/// what the case now holds because of it.
#[tokio::test]
async fn a_failed_ingest_is_reported_after_the_submitting_tab_is_gone() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    // An EWF set with a hole in it: segment 1 and segment 3, no segment 2.
    // Acquisition hashing refuses it rather than record a baseline that would
    // appear to cover the whole set, so the ingest fails deterministically
    // after the artifact row has been persisted.
    let dir = tempfile::tempdir().unwrap();
    let segment = |name: &str| {
        let mut body = EWF_MAGIC.to_vec();
        body.extend_from_slice(&[0x11; 512]);
        std::fs::write(dir.path().join(name), &body).unwrap();
    };
    segment("holed.E01");
    segment("holed.E03");
    let path = dir.path().join("holed.E01");

    let (status, body) = ingest(&app, case_id, path.to_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let artifact_id = body["artifact_id"].as_str().unwrap().to_string();

    await_audit(&db, case_id, "evidence_ingest_failed").await;

    let reported = acquisitions(&app, case_id).await;
    let failed = reported["failed"].as_array().unwrap();
    assert_eq!(failed.len(), 1, "{reported}");
    assert_eq!(failed[0]["artifact_id"], artifact_id);
    assert_eq!(failed[0]["source_path"], path.to_str().unwrap());
    assert_eq!(failed[0]["requested_by"], "local");
    let detail = failed[0]["detail"].as_str().unwrap();
    assert!(
        detail.contains("incomplete"),
        "the failure must carry the reason verbatim from the record: {detail}"
    );
    assert_eq!(
        failed[0]["evidence_row_exists"], true,
        "the exhibit stayed in the case marked acquisition_failed, and the response must \
         say so rather than leave the examiner guessing: {reported}"
    );
    assert_eq!(reported["failed_count"], 1);

    // A failed acquisition is finished, not running.
    assert_eq!(reported["in_flight"].as_array().unwrap().len(), 0);
}

/// A request whose outcome was never recorded — the server was killed
/// mid-hash — must be reported as exactly that: an attempt of unknown
/// disposition, not a running acquisition this server can vouch for.
#[tokio::test]
async fn an_attempt_with_no_outcome_is_reported_as_state_unknown() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    let artifact_id = Uuid::new_v4();
    db.record_audit_event(
        Some(case_id),
        "alice",
        "evidence_ingest_requested",
        Some("artifact"),
        Some(artifact_id),
        Some("/evidence/OP-KESTREL/img_003.E01"),
    )
    .await
    .unwrap();

    let reported = acquisitions(&app, case_id).await;
    assert_eq!(
        reported["in_flight"].as_array().unwrap().len(),
        0,
        "nothing is being acquired, so nothing may be listed as in flight: {reported}"
    );
    let entries = reported["unresolved"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{reported}");
    assert_eq!(entries[0]["artifact_id"], artifact_id.to_string());
    assert_eq!(
        entries[0]["source_path"],
        "/evidence/OP-KESTREL/img_003.E01"
    );
    assert_eq!(entries[0]["requested_by"], "alice");
    assert_eq!(
        entries[0]["live"], false,
        "this server is not running it, and must not imply that it is"
    );
    assert_eq!(entries[0]["phase"], "unknown");
    assert_eq!(
        entries[0]["disposition"], "no_outcome_recorded",
        "an outcome event could have been written for this request and was not: {reported}"
    );
    assert!(
        entries[0]["bytes_total"].is_null() && entries[0]["percent"].is_null(),
        "no progress is known for it, and none may be invented: {reported}"
    );
    assert!(entries[0]["state_note"]
        .as_str()
        .unwrap()
        .contains("no outcome"));
    assert_eq!(
        reported["live_count"], 0,
        "nothing is running here, and only the attempts this server carries may be counted \
         as running: {reported}"
    );
    assert_eq!(reported["unresolved_count"], 1, "{reported}");
}

/// The migration defect this endpoint was one release away from shipping. Every
/// ingest on a case created by an older build recorded `evidence_ingested` and
/// nothing else — outcome events did not exist to be written. Inferring "no
/// outcome recorded, therefore possibly still acquiring" from those rows turns
/// the entire history of an inherited case into a list of exhibits apparently
/// mid-hash (S3, and then S4 when that list is quoted).
#[tokio::test]
async fn a_legacy_ingest_is_reported_as_unknown_not_as_an_acquisition_in_progress() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    let artifact_id = Uuid::new_v4();
    db.record_audit_event(
        Some(case_id),
        "alice",
        // The name the request event carried before it was corrected.
        "evidence_ingested",
        Some("artifact"),
        Some(artifact_id),
        Some("/evidence/OP-KESTREL/img_001.E01"),
    )
    .await
    .unwrap();

    let reported = acquisitions(&app, case_id).await;
    assert_eq!(
        reported["in_flight"].as_array().unwrap().len(),
        0,
        "an ingest recorded six months ago is not an acquisition in progress: {reported}"
    );
    assert_eq!(reported["in_flight_count"], 0, "{reported}");
    let entries = reported["unresolved"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "the attempt is still part of the case and must not vanish: {reported}"
    );
    assert_eq!(
        entries[0]["disposition"], "predates_outcome_events",
        "the absence of an outcome for a legacy row is a fact about the build, not about the \
         ingest: {reported}"
    );
    let note = entries[0]["state_note"].as_str().unwrap();
    assert!(
        note.contains("No outcome event could have been recorded"),
        "the note must say why nothing followed the request: {note}"
    );
    assert!(
        note.contains("not evidence"),
        "the note must refuse the interrupted-acquisition reading it would otherwise invite: \
         {note}"
    );
}

/// A legacy ingest is not always unknown: the build that wrote
/// `evidence_ingested` also wrote an `evidence_acquisition_hashed` event for
/// every baseline it recorded, and that event is a durable statement that the
/// acquisition ran to its end. An attempt with its baseline on the record is
/// resolved, and reporting it as unresolved would overstate doubt about a case
/// where nothing is in doubt.
#[tokio::test]
async fn an_attempt_whose_baseline_is_on_the_record_is_resolved() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    let artifact_id = Uuid::new_v4();
    db.record_audit_event(
        Some(case_id),
        "alice",
        "evidence_ingested",
        Some("artifact"),
        Some(artifact_id),
        Some("/evidence/OP-KESTREL/img_002.E01"),
    )
    .await
    .unwrap();
    db.record_audit_event(
        Some(case_id),
        "system",
        "evidence_acquisition_hashed",
        Some("artifact"),
        Some(artifact_id),
        Some("md5=d41d8c sha1=da39a3 sha256=e3b0c4"),
    )
    .await
    .unwrap();

    let reported = acquisitions(&app, case_id).await;
    assert_eq!(reported["in_flight"].as_array().unwrap().len(), 0);
    assert_eq!(
        reported["unresolved"].as_array().unwrap().len(),
        0,
        "its acquisition baseline is on the record, so its disposition is not unknown: \
         {reported}"
    );
    assert_eq!(
        reported["attempts_resolved_by_baseline"], 1,
        "an attempt excluded from both lists must still be counted, or the stated population \
         is short: {reported}"
    );
    assert!(
        reported["population"]
            .as_str()
            .unwrap()
            .contains("acquisition baseline"),
        "the population sentence must account for the attempts it resolved this way: {reported}"
    );
}

/// A baseline recorded BEFORE an attempt says nothing about that attempt. An
/// exhibit ingested twice — the first run baselined, the second interrupted —
/// must not have its second attempt excused by the first attempt's record.
#[tokio::test]
async fn an_older_baseline_does_not_resolve_a_later_attempt() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    let artifact_id = Uuid::new_v4();
    for (user, action, detail) in [
        ("alice", "evidence_ingest_requested", "/evidence/img.E01"),
        (
            "system",
            "evidence_acquisition_hashed",
            "md5=d41d8c sha1=da39a3 sha256=e3b0c4",
        ),
        ("alice", "evidence_ingest_requested", "/evidence/img.E01"),
    ] {
        db.record_audit_event(
            Some(case_id),
            user,
            action,
            Some("artifact"),
            Some(artifact_id),
            Some(detail),
        )
        .await
        .unwrap();
    }

    let reported = acquisitions(&app, case_id).await;
    assert_eq!(
        reported["unresolved"].as_array().unwrap().len(),
        1,
        "the newest attempt has nothing after it and its disposition is unknown: {reported}"
    );
    assert_eq!(reported["attempts_resolved_by_baseline"], 0, "{reported}");
}

/// An attempt that finished is not in flight, however it finished.
#[tokio::test]
async fn a_requested_attempt_with_a_recorded_outcome_is_not_in_flight() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    for (artifact_id, outcome) in [
        (Uuid::new_v4(), "evidence_ingest_completed"),
        (Uuid::new_v4(), "evidence_ingest_failed"),
    ] {
        db.record_audit_event(
            Some(case_id),
            "alice",
            "evidence_ingest_requested",
            Some("artifact"),
            Some(artifact_id),
            Some("/evidence/img.E01"),
        )
        .await
        .unwrap();
        db.record_audit_event(
            Some(case_id),
            "system",
            outcome,
            Some("artifact"),
            Some(artifact_id),
            Some("Background ingest of '/evidence/img.E01' finished."),
        )
        .await
        .unwrap();
    }

    let reported = acquisitions(&app, case_id).await;
    assert_eq!(
        reported["in_flight"].as_array().unwrap().len(),
        0,
        "{reported}"
    );
    assert_eq!(
        reported["unresolved"].as_array().unwrap().len(),
        0,
        "both attempts have an outcome on the record, so neither disposition is unknown: \
         {reported}"
    );
    assert_eq!(
        reported["failed"].as_array().unwrap().len(),
        1,
        "the failed attempt is still reported, as a failure: {reported}"
    );
}

/// The disclosure has to distinguish "read everything and found nothing older"
/// from "did not look further back". A scan that comes back full proves the
/// second, and a response that answered "0 older attempts" to it would be
/// stating a population it never counted.
#[tokio::test]
async fn a_full_scan_window_says_it_did_not_look_further_back() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    // One more than the endpoint's per-action scan window, so the window comes
    // back full and older attempts provably exist that it never read.
    for i in 0..201 {
        db.record_audit_event(
            Some(case_id),
            "alice",
            "evidence_ingest_requested",
            Some("artifact"),
            Some(Uuid::new_v4()),
            Some(&format!("/evidence/img_{i:03}.E01")),
        )
        .await
        .unwrap();
    }

    let reported = acquisitions(&app, case_id).await;
    assert_eq!(
        reported["attempts_scan_filled_window"], true,
        "the scan filled its window and must say so: {reported}"
    );
    assert_eq!(
        reported["attempts_scanned"], 200,
        "only the window's worth was read: {reported}"
    );
    let population = reported["population"].as_str().unwrap();
    assert!(
        !population.contains("0 older attempt"),
        "a bounded scan may not report a count of what it never read: {population}"
    );
    assert!(
        population.contains("their number is not known here"),
        "the response must say the older attempts are uncounted, not absent: {population}"
    );
}

/// The other side of the same disclosure: when the scan did NOT fill its
/// window, every request event the case holds was read, and saying so is what
/// makes the count above it worth anything.
#[tokio::test]
async fn a_scan_that_did_not_fill_its_window_says_it_read_everything() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    db.record_audit_event(
        Some(case_id),
        "alice",
        "evidence_ingest_requested",
        Some("artifact"),
        Some(Uuid::new_v4()),
        Some("/evidence/img.E01"),
    )
    .await
    .unwrap();

    let reported = acquisitions(&app, case_id).await;
    assert_eq!(reported["attempts_scan_filled_window"], false, "{reported}");
    assert_eq!(reported["failures_scan_filled_window"], false, "{reported}");
    let population = reported["population"].as_str().unwrap();
    assert!(
        population.contains("Every ingest request event this case holds was read"),
        "{population}"
    );
}

/// One case's acquisitions must never appear on another's screen.
#[tokio::test]
async fn acquisitions_are_scoped_to_the_case() {
    let (app, case_id, db, _ends) = setup_test_app().await;
    let other_case = db.create_case("Other Case", "Test Examiner").await.unwrap();

    db.record_audit_event(
        Some(case_id),
        "alice",
        "evidence_ingest_requested",
        Some("artifact"),
        Some(Uuid::new_v4()),
        Some("/evidence/img.E01"),
    )
    .await
    .unwrap();

    assert_eq!(
        acquisitions(&app, other_case).await["unresolved"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        acquisitions(&app, case_id).await["unresolved"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

/// The source card is where "0 artifacts" gets read, and during acquisition it
/// means "not processed yet", not "this exhibit yielded nothing". The row has
/// to carry the artifact's acquisition state so the difference can be shown —
/// and unlike the in-flight list, this survives a restart, because it is the
/// artifact's own record.
#[tokio::test]
async fn a_source_row_carries_the_acquisition_state_of_its_exhibit() {
    let (app, case_id, db, _ends) = setup_test_app().await;

    let mut ids = Vec::new();
    for (name, state) in [
        ("acquiring.E01", Some("verifying")),
        ("done.E01", Some("baseline_recorded")),
        ("broken.E01", Some("acquisition_failed")),
        ("legacy.E01", None),
    ] {
        let artifact = seance_core::artifact::Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type: seance_core::artifact::ArtifactType::RawEvidence,
            data: None,
            metadata: match state {
                Some(state) => json!({ "name": name, "integrity_state": state,
                                       "acquisition_error": "read failed at 62%" }),
                None => json!({ "name": name }),
            },
        };
        db.record_artifact(&artifact).await.unwrap();
        ids.push((name, artifact.id));
    }

    let (status, body) = get(&app, format!("/api/v1/cases/{}/stats/sources", case_id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sources = body["sources"].as_array().unwrap();
    let row = |name: &str| -> Value {
        sources
            .iter()
            .find(|s| s["name"] == name)
            .unwrap_or_else(|| panic!("source {name} missing from {body}"))
            .clone()
    };

    assert_eq!(row("acquiring.E01")["integrity_state"], "verifying");
    assert_eq!(row("acquiring.E01")["artifact_count"], 0);
    assert_eq!(row("done.E01")["integrity_state"], "baseline_recorded");
    assert_eq!(
        row("broken.E01")["integrity_state"],
        "acquisition_failed",
        "a source with no baseline must say so where its count is read"
    );
    assert_eq!(
        row("broken.E01")["acquisition_error"],
        "read failed at 62%",
        "the reason belongs with the state"
    );
    assert!(
        row("legacy.E01")["integrity_state"].is_null(),
        "a source ingested before integrity states existed reports none, rather than \
         being given one it never had"
    );

    // The state is a vocabulary token; the sentence beside the count is what an
    // examiner actually reads, and what gets quoted. The server writes it, so a
    // card cannot render a bare "0 artifacts" beside a state it did not know
    // how to phrase, and so the two halves cannot drift apart.
    let note = |name: &str| -> String {
        row(name)["acquisition_note"]
            .as_str()
            .unwrap_or_else(|| panic!("source {name} must carry an acquisition note: {body}"))
            .to_string()
    };
    assert!(
        note("acquiring.E01").contains("not processed yet"),
        "a zero under a running acquisition means 'not yet', and the row must say so: {}",
        note("acquiring.E01")
    );
    assert!(
        note("broken.E01").contains("cannot vouch"),
        "an exhibit with no baseline is held and unvouched-for, not empty: {}",
        note("broken.E01")
    );
    assert!(
        note("legacy.E01").contains("No acquisition state is recorded"),
        "an absent state must be stated as absent rather than left to read as clean: {}",
        note("legacy.E01")
    );
    assert!(
        row("done.E01")["acquisition_note"].is_null(),
        "an exhibit with its baseline recorded needs no qualification, and inventing one \
         would put words on a screen that say nothing: {body}"
    );
}

/// HUNT-113. Acquisition is the hash; processing is the walk, and a walk a
/// stopped process never finished used to leave no trace. The endpoint lists
/// the processing runs the record holds, and the sources listing carries the
/// run's outcome beside the count it qualifies.
#[tokio::test]
async fn an_interrupted_processing_run_is_listed_and_its_source_says_so() {
    use seance_core::db::DatabaseConnection;
    use seance_core::profile::IngestRun;
    let (app, case_id, db, _ends) = setup_test_app().await;

    let root = seance_core::artifact::Artifact::new(
        case_id,
        seance_core::artifact::ArtifactType::RawEvidence,
        None,
        serde_json::json!({
            "name": "CoreServices",
            "source_path": "/evidence/CoreServices",
            "processing_state": "interrupted",
            "inventory_incomplete": true,
            "inventory_incomplete_reason": "ingest_interrupted",
            "incomplete_detail": "processing of this source was interrupted by a stopped process; 1 artifacts were recorded under it before it stopped",
        }),
    );
    db.record_artifact(&root).await.unwrap();
    db.record_artifact(
        &seance_core::artifact::Artifact::new(
            case_id,
            seance_core::artifact::ArtifactType::FileEntry,
            None,
            serde_json::json!({"name": "a"}),
        )
        .with_parent(root.id),
    )
    .await
    .unwrap();
    db.start_ingest_run(&IngestRun {
        id: Uuid::new_v4(),
        case_id,
        source_artifact_id: root.id,
        source_label: "/evidence/CoreServices".to_string(),
        started_at: 1_000,
        finished_at: None,
        status: IngestRun::RUNNING.to_string(),
        artifacts_recorded: None,
        detail: None,
    })
    .await
    .unwrap();
    let swept = db
        .mark_interrupted_ingest_runs(2_000, "stopped")
        .await
        .unwrap();
    assert_eq!(swept.len(), 1);

    let reported = acquisitions(&app, case_id).await;
    let runs = reported["processing_runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1, "{reported}");
    assert_eq!(runs[0]["source_artifact_id"], root.id.to_string());
    assert_eq!(runs[0]["status"], "interrupted");
    assert_eq!(runs[0]["artifacts_recorded"], 1);
    assert_eq!(runs[0]["detail"], "stopped");
    assert_eq!(reported["processing_runs_unfinished"], 1);

    let (status, sources) = get(&app, format!("/api/v1/cases/{case_id}/stats/sources")).await;
    assert_eq!(status, StatusCode::OK, "{sources}");
    let row = sources["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source_artifact_id"] == root.id.to_string())
        .expect("the source is listed");
    assert_eq!(row["artifact_count"], 1);
    assert_eq!(row["processing_state"], "interrupted");
    assert!(
        row["processing_note"]
            .as_str()
            .unwrap()
            .contains("1 artifacts were recorded"),
        "the count beside the name must carry the sentence that qualifies it: {row}"
    );
}
