//! An ingest that is still acquiring, and one that failed, must be visible to
//! somebody who was not holding the submitting connection.
//!
//! Two gaps this file pins down. First, for the whole acquisition hash of a
//! large exhibit the only trace of the attempt was a stream of broadcast
//! events: whoever was not listening at the time — a second browser tab, a
//! colleague, the examiner who closed the laptop — had no way to ask "is
//! anything being acquired for this case?". `acquisitions_in_flight` is that
//! question, answered from shared state rather than from a broadcast nobody
//! replays. Second, a background ingest that failed left the SSE event and a
//! log line, neither of which survives the session, so the durable record said
//! only that an ingest had been requested. The background task now writes the
//! outcome — completed or failed — into the audit log, so the request and its
//! outcome pair up for an examiner reading the case weeks later (S3).

use seance_core::artifact::ArtifactType;
use seance_core::db::DatabaseConnection;
use seance_core::ingestion::{AcquisitionPhase, IngestionService};
use seance_core::orchestrator::OrchestratorEvent;
use seance_db::SqliteConnection;
use serde_json::json;
use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Big enough that hashing it cannot complete between the call returning and
/// the assertion that follows, on any runtime flavour: the point of these tests
/// is what a reader sees WHILE an acquisition is running, so the acquisition
/// has to still be running.
const SLOW_SOURCE_BYTES: usize = 32 * 1024 * 1024;

fn make_service(
    db: Option<Arc<dyn DatabaseConnection>>,
) -> (
    IngestionService,
    tokio::sync::mpsc::UnboundedReceiver<seance_core::artifact::Artifact>,
    tokio::sync::broadcast::Receiver<OrchestratorEvent>,
) {
    let (task_sender, task_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (event_broadcaster, _) = tokio::sync::broadcast::channel(16);
    let (status_sender, status_receiver) = tokio::sync::broadcast::channel(256);
    let service = IngestionService::new(
        db,
        task_sender,
        event_broadcaster,
        Arc::new(AtomicUsize::new(0)),
    )
    .with_status_sender(status_sender);
    (service, task_receiver, status_receiver)
}

async fn setup_db() -> (Arc<SqliteConnection>, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Test Case", "Test Examiner").await.unwrap();
    (db, case_id)
}

/// A source whose hash takes long enough to observe. Returned as a
/// `NamedTempFile` so it outlives the ingest that is reading it.
fn slow_source() -> (tempfile::NamedTempFile, String) {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&vec![0x5a; SLOW_SOURCE_BYTES]).unwrap();
    file.flush().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    (file, path)
}

/// Wait for the background ingest of `artifact_id` to report an outcome.
/// Returns the error text when it failed.
async fn await_outcome(
    status_rx: &mut tokio::sync::broadcast::Receiver<OrchestratorEvent>,
    artifact_id: Uuid,
) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::IngestCompleted {
                    artifact_id: id, ..
                }) if id == artifact_id => return Ok(()),
                Ok(OrchestratorEvent::IngestFailed {
                    artifact_id: id,
                    error,
                    ..
                }) if id == artifact_id => return Err(error),
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("status channel closed: {e}"),
            }
        }
    })
    .await
    .expect("the background ingest must report an outcome")
}

/// The dead zone: while a 200 GB exhibit is being hashed there is no completed
/// evidence to look at, and until now nothing a second reader could ask. Any
/// holder of the service — which is to say any HTTP request, from any tab —
/// must be able to see that this case has an acquisition running, which exhibit
/// it is, and that it has not finished.
#[tokio::test]
async fn an_acquisition_in_progress_is_visible_to_a_reader_who_did_not_submit_it() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx, mut status_rx) = make_service(Some(db.clone()));
    let (_keep, path) = slow_source();

    // The reader is a separate handle, exactly as the API's shared state is.
    let reader = service.clone();
    assert!(
        reader.acquisitions_in_flight(case_id).is_empty(),
        "a case with no ingest running must report nothing in flight"
    );

    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"source_path": path, "name": "exhibit-1.E01"}),
    );

    let in_flight = reader.acquisitions_in_flight(case_id);
    assert_eq!(in_flight.len(), 1, "the running acquisition must be listed");
    assert_eq!(in_flight[0].artifact_id, artifact.id);
    assert_eq!(in_flight[0].source_path.as_deref(), Some(path.as_str()));
    assert_eq!(in_flight[0].name.as_deref(), Some("exhibit-1.E01"));
    assert!(in_flight[0].started_at > 0);

    await_outcome(&mut status_rx, artifact.id)
        .await
        .expect("the ingest must succeed");

    // The entry is removed BEFORE the outcome is announced, so a reader that
    // acts on the outcome never sees a finished acquisition still claimed to be
    // running.
    assert!(
        reader.acquisitions_in_flight(case_id).is_empty(),
        "a finished acquisition must not still be reported as in flight"
    );
}

/// One examiner's acquisition must never appear on another case's screen: the
/// list is a per-case population claim.
#[tokio::test]
async fn in_flight_acquisitions_are_scoped_to_their_case() {
    let (db, case_id) = setup_db().await;
    let other_case = db.create_case("Other Case", "Test Examiner").await.unwrap();
    let (service, _task_rx, mut status_rx) = make_service(Some(db.clone()));
    let (_keep, path) = slow_source();

    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"source_path": path, "name": "exhibit-1.E01"}),
    );

    assert_eq!(service.acquisitions_in_flight(case_id).len(), 1);
    assert!(
        service.acquisitions_in_flight(other_case).is_empty(),
        "an acquisition must not be reported against a case it does not belong to"
    );

    await_outcome(&mut status_rx, artifact.id)
        .await
        .expect("the ingest must succeed");
}

/// "Exhibit 1, hashing, 62%" — the progress a submitting tab used to receive
/// privately over SSE has to be readable from the shared state too, or a second
/// reader can only be told that something is running, not how far along it is.
#[tokio::test]
async fn acquisition_progress_is_readable_while_the_hash_runs() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx, mut status_rx) = make_service(Some(db.clone()));
    let (_keep, path) = slow_source();

    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"source_path": path, "name": "exhibit-1.E01"}),
    );

    // Before the hash starts there is nothing to report but the queue position,
    // and the entry says so rather than showing a fabricated zero percent.
    let queued = service.acquisitions_in_flight(case_id);
    assert_eq!(queued[0].phase, AcquisitionPhase::Queued);
    assert_eq!(queued[0].bytes_total, None);

    let mut hashing = None;
    for _ in 0..3000 {
        if let Some(entry) = service
            .acquisitions_in_flight(case_id)
            .into_iter()
            .find(|a| a.artifact_id == artifact.id && a.phase == AcquisitionPhase::Hashing)
        {
            hashing = Some(entry);
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let hashing = hashing.expect("the hashing phase must be observable in the in-flight list");
    assert_eq!(
        hashing.bytes_total,
        Some(SLOW_SOURCE_BYTES as u64),
        "the size being hashed is what makes a percentage meaningful"
    );
    assert!(hashing.bytes_done <= SLOW_SOURCE_BYTES as u64);

    await_outcome(&mut status_rx, artifact.id)
        .await
        .expect("the ingest must succeed");
}

/// The audit log must not say an ingest happened while it is still hashing, and
/// must say so once it has. The request-time event names the requester; this is
/// the outcome that pairs with it.
#[tokio::test]
async fn a_completed_background_ingest_is_audited_as_completed() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx, mut status_rx) = make_service(Some(db.clone()));

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"hello").unwrap();
    file.flush().unwrap();
    let path = file.path().to_str().unwrap().to_string();

    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"source_path": path, "name": "exhibit-1.E01"}),
    );
    await_outcome(&mut status_rx, artifact.id)
        .await
        .expect("the ingest must succeed");

    let audit = db.get_audit_log(case_id, 100, 0).await.unwrap();
    let completed = audit
        .iter()
        .find(|e| e["action"].as_str() == Some("evidence_ingest_completed"))
        .expect("a completed background ingest must be audited as completed");
    assert_eq!(
        completed["resource_id"].as_str(),
        Some(artifact.id.to_string().as_str())
    );
    let details = completed["details"].as_str().unwrap_or_default();
    assert!(
        details.contains(&path),
        "the outcome must name the source it was recorded for: {completed:?}"
    );
    // The sentence claims an acquisition record, so the record has to be there.
    // Asserting the claim without asserting the thing it claims would pin the
    // wording and nothing else.
    assert!(
        details.contains("acquisition record"),
        "a hashed source's outcome must say its acquisition record is in the case: {details}"
    );
    assert!(
        audit.iter().any(
            |e| e["action"].as_str() == Some("evidence_acquisition_hashed")
                && e["resource_id"].as_str() == Some(artifact.id.to_string().as_str())
        ),
        "the acquisition record the outcome claims must exist: {audit:?}"
    );
}

/// The failure the examiner never sees: the tab was closed, the toast expired,
/// and the only durable record used to be a request-time event claiming the
/// evidence had been ingested. The outcome is now on the record too, naming the
/// source, the error, and whether an evidence row exists for it.
#[tokio::test]
async fn a_failed_background_ingest_is_audited_as_failed_naming_the_source() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx, mut status_rx) = make_service(Some(db.clone()));

    let missing = "/nonexistent/path/to/evidence.img";
    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"source_path": missing, "name": "missing.img"}),
    );
    let error = await_outcome(&mut status_rx, artifact.id)
        .await
        .expect_err("an unreadable source must fail");
    assert!(error.contains("acquisition hashes"), "{error}");

    let audit = db.get_audit_log(case_id, 100, 0).await.unwrap();
    let failed = audit
        .iter()
        .find(|e| e["action"].as_str() == Some("evidence_ingest_failed"))
        .expect("a failed background ingest must be audited as failed");
    assert_eq!(
        failed["resource_id"].as_str(),
        Some(artifact.id.to_string().as_str())
    );
    let details = failed["details"].as_str().unwrap_or_default();
    assert!(
        details.contains(missing),
        "the failure must name the source that failed: {details}"
    );
    assert!(
        details.contains("acquisition hashes"),
        "the failure must carry the error: {details}"
    );
    // Parse-while-hashing persists the row before hashing, so the exhibit IS in
    // the case (marked acquisition_failed) and the audit must not imply it
    // vanished. Asserted as the whole disposition sentence, not as the phrase
    // "evidence row": every arm of `evidence_row_disposition` contains that
    // phrase, so a test that looked for it alone would pass just as happily on
    // "No evidence row was created: the exhibit is NOT in the case" — the exact
    // wrong sentence this outcome event exists to prevent.
    assert!(
        details.contains("An evidence row for it exists in the case"),
        "the failure must say the exhibit IS in the case, because it is: {details}"
    );
    assert!(
        !details.contains("NOT in the case"),
        "the exhibit was persisted before the hash ran, so the audit must not say it vanished: \
         {details}"
    );

    assert!(
        service.acquisitions_in_flight(case_id).is_empty(),
        "a failed acquisition must not be left claimed as running"
    );
}

/// A directory has no bytes to hash, so it never enters the hashing phase; it
/// is still an ingest in flight until it is queued, and it still gets an
/// outcome on the record.
#[tokio::test]
async fn a_sourceless_ingest_is_tracked_and_audited_too() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx, mut status_rx) = make_service(Some(db.clone()));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();
    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"path": path, "is_directory": true, "name": "seized-folder"}),
    );

    let listed = service.acquisitions_in_flight(case_id);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].phase, AcquisitionPhase::Queued);
    assert_eq!(
        listed[0].source_path, None,
        "a directory has no source file to hash, and the entry must not invent one"
    );

    await_outcome(&mut status_rx, artifact.id)
        .await
        .expect("a directory ingest must succeed");
    assert!(service.acquisitions_in_flight(case_id).is_empty());

    let audit = db.get_audit_log(case_id, 100, 0).await.unwrap();
    let completed = audit
        .iter()
        .find(|e| e["action"].as_str() == Some("evidence_ingest_completed"))
        .expect("a directory ingest must record its outcome as well");

    // A directory has no bytes of its own, so nothing hashed it and no baseline
    // exists for it. The outcome event is the line that gets exhibited to show
    // what integrity work was done, and it must not assert an acquisition
    // record that was never computed.
    let details = completed["details"].as_str().unwrap_or_default();
    assert!(
        !details.contains("acquisition record are in the case"),
        "nothing hashed this exhibit, so the audit must not claim an acquisition record for \
         it: {details}"
    );
    assert!(
        details.contains("No acquisition baseline was computed"),
        "the outcome must say the baseline is absent, not leave the examiner to assume one: \
         {details}"
    );
    assert!(
        !audit
            .iter()
            .any(|e| e["action"].as_str() == Some("evidence_acquisition_hashed")),
        "no baseline was hashed for a directory, and none was recorded: {audit:?}"
    );
}
