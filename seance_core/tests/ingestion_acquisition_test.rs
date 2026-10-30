//! Tests for acquisition hashing at ingest (C1).
//!
//! Ingesting evidence with a source_path must compute MD5/SHA1/SHA256 of the
//! source file, store them as immutable acquisition_* metadata fields, record
//! an integrity_checks baseline row, and write an audit event. An unreadable
//! source file must fail the ingest.

use seance_core::artifact::ArtifactType;
use seance_core::db::DatabaseConnection;
use seance_core::ingestion::IngestionService;
use seance_core::orchestrator::OrchestratorEvent;
use seance_db::SqliteConnection;
use serde_json::json;
use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn make_service(
    db: Option<Arc<dyn DatabaseConnection>>,
) -> (
    IngestionService,
    tokio::sync::mpsc::UnboundedReceiver<seance_core::artifact::Artifact>,
) {
    let (task_sender, task_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (event_broadcaster, _) = tokio::sync::broadcast::channel(16);
    let service = IngestionService::new(
        db,
        task_sender,
        event_broadcaster,
        Arc::new(AtomicUsize::new(0)),
    );
    (service, task_receiver)
}

fn make_service_with_status(
    db: Option<Arc<dyn DatabaseConnection>>,
) -> (
    IngestionService,
    tokio::sync::mpsc::UnboundedReceiver<seance_core::artifact::Artifact>,
    tokio::sync::broadcast::Receiver<OrchestratorEvent>,
) {
    let (task_sender, task_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (event_broadcaster, _) = tokio::sync::broadcast::channel(16);
    let (status_sender, status_receiver) = tokio::sync::broadcast::channel(64);
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

#[tokio::test]
async fn ingest_computes_acquisition_hashes() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx) = make_service(Some(db.clone()));

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"hello").unwrap();
    file.flush().unwrap();
    let path = file.path().to_str().unwrap().to_string();

    let artifact = service
        .ingest_artifact(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({"source_path": path, "name": "evidence.bin"}),
        )
        .await
        .expect("ingest must succeed");

    // Known test vectors for b"hello"
    assert_eq!(
        artifact.metadata["acquisition_md5"].as_str().unwrap(),
        "5d41402abc4b2a76b9719d911017c592"
    );
    assert_eq!(
        artifact.metadata["acquisition_sha1"].as_str().unwrap(),
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    );
    assert_eq!(
        artifact.metadata["acquisition_sha256"].as_str().unwrap(),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert!(artifact.metadata["acquisition_hashed_at"].as_i64().unwrap() > 0);

    // Hashes must be persisted in the DB copy of the artifact
    let stored = db.get_artifact(artifact.id).await.unwrap().unwrap();
    assert_eq!(
        stored.metadata["acquisition_md5"].as_str().unwrap(),
        "5d41402abc4b2a76b9719d911017c592"
    );

    // An integrity baseline row must exist
    let checks = db.get_integrity_checks(artifact.id).await.unwrap();
    assert_eq!(
        checks.len(),
        1,
        "exactly one baseline integrity check expected"
    );
    assert_eq!(checks[0]["status"].as_str().unwrap(), "baseline");
    assert_eq!(
        checks[0]["computed_md5"].as_str().unwrap(),
        "5d41402abc4b2a76b9719d911017c592"
    );

    // An audit event must be recorded
    let audit = db.get_audit_log(case_id, 100, 0).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|e| e["action"].as_str() == Some("evidence_acquisition_hashed")),
        "audit log must contain the acquisition hashing event"
    );
}

/// Re-ingesting a source ALWAYS re-reads and re-hashes the bytes: the acquisition
/// baseline is never carried over from a prior artifact on the strength of a
/// path/size/mtime match. This is the forensic-soundness guarantee behind
/// CR-001/CR-002 — a reused digest keyed on a forgeable (path, size, mtime)
/// identity could record a chain-of-custody hash that does not match the bytes.
///
/// The test proves it the only way that distinguishes reuse from a fresh hash:
/// change the bytes but keep the SAME length and force the SAME mtime, so the
/// old reuse key matches exactly. A reused baseline would report the first
/// file's digest; a fresh hash reports the second file's.
#[tokio::test]
async fn reingesting_rehashes_and_never_reuses_a_stale_baseline() {
    use filetime::{set_file_mtime, FileTime};

    let (db, case_id) = setup_db().await;
    let (service, _task_rx) = make_service(Some(db.clone()));

    // A persistent path (not the auto-deleting NamedTempFile) so we can rewrite
    // it in place and re-ingest the same path.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evidence.bin");
    std::fs::write(&path, b"original evidence AAAA").unwrap();
    let path_str = path.to_str().unwrap().to_string();

    // Pin an mtime we can restore after rewriting the bytes.
    let pinned = FileTime::from_unix_time(1_700_000_000, 0);
    set_file_mtime(&path, pinned).unwrap();

    let first = service
        .ingest_artifact(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({"source_path": path_str, "name": "evidence.bin"}),
        )
        .await
        .unwrap();
    let first_md5 = first.metadata["acquisition_md5"]
        .as_str()
        .unwrap()
        .to_string();
    let first_sha256 = first.metadata["acquisition_sha256"]
        .as_str()
        .unwrap()
        .to_string();

    // Tamper: different bytes, IDENTICAL length, and restore the pinned mtime —
    // so (path, size, mtime) is byte-for-byte what the prior baseline matched on.
    std::fs::write(&path, b"tampered evidence BBBB").unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        22,
        "the tampered file must keep the original length for the test to bite"
    );
    set_file_mtime(&path, pinned).unwrap();

    let second = service
        .ingest_artifact(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({"source_path": path_str, "name": "evidence.bin"}),
        )
        .await
        .unwrap();

    // The recorded baseline must be the hash of the bytes actually on disk now,
    // not the stale first digest.
    assert_ne!(
        second.metadata["acquisition_md5"].as_str().unwrap(),
        first_md5,
        "the re-ingest recorded the FIRST file's digest — a stale reused baseline"
    );
    assert_ne!(
        second.metadata["acquisition_sha256"].as_str().unwrap(),
        first_sha256,
        "the re-ingest recorded the FIRST file's sha256 — a stale reused baseline"
    );

    // And the baseline row must never be labelled a reuse.
    let checks = db.get_integrity_checks(second.id).await.unwrap();
    assert!(
        checks.iter().any(|c| c["status"] == "baseline"
            && c["details"].as_str().is_some_and(|d| !d.contains("REUSED"))),
        "the baseline must be recorded as a fresh hash, never a reuse: {checks:?}"
    );
    let audit = db.get_audit_log(case_id, 100, 0).await.unwrap();
    assert!(
        !audit
            .iter()
            .any(|e| e["action"].as_str() == Some("evidence_acquisition_hash_reused")),
        "there must be no reuse audit action — reuse was removed"
    );
}

/// When acquisition hashing fails AFTER the artifact was queued for processing
/// (the parse-while-hashing path), the failure is a durable chain-of-custody
/// record, not just a transient status that scrolls past. The evidence stays —
/// processing may already have touched it, so it cannot vanish — marked
/// `acquisition_failed`, with an integrity-check failure row and an audit event.
/// "We could not establish a baseline for this evidence" belongs on the record
/// (CR-003), while the concurrency that let processing start early is preserved.
#[tokio::test]
async fn background_ingest_records_a_custody_trail_when_hashing_fails() {
    use seance_core::orchestrator::OrchestratorEvent;

    let (db, case_id) = setup_db().await;
    let (service, mut task_rx, mut status_rx) = make_service_with_status(Some(db.clone()));

    // A directory as the source persists and enqueues fine, but reading it to
    // hash fails (EISDIR), so hashing fails only AFTER the artifact is queued.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();

    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"source_path": path, "name": "evidence.bin"}),
    );

    // It WAS queued for processing — the concurrency is preserved.
    let queued = tokio::time::timeout(Duration::from_secs(5), task_rx.recv())
        .await
        .expect("queued artifact must arrive")
        .expect("task channel open");
    assert_eq!(queued.id, artifact.id);

    // The background task reports the failure, not completion.
    let failed_id = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::IngestFailed { artifact_id, .. }) => return artifact_id,
                Ok(OrchestratorEvent::IngestCompleted { .. }) => {
                    panic!("an unhashable source must not report IngestCompleted")
                }
                Ok(_) => {}
                Err(e) => panic!("status channel closed: {e}"),
            }
        }
    })
    .await
    .expect("a failure event must arrive");
    assert_eq!(failed_id, artifact.id);

    // Durable custody: the root is marked, an integrity failure row exists, and
    // the failure is audited under its own action.
    let stored = db.get_artifact(artifact.id).await.unwrap().unwrap();
    assert_eq!(stored.metadata["integrity_state"], "acquisition_failed");
    assert!(stored.metadata.get("acquisition_error").is_some());

    let checks = db.get_integrity_checks(artifact.id).await.unwrap();
    assert!(
        checks.iter().any(|c| c["status"] == "acquisition_failed"),
        "a failed acquisition must leave an integrity-check row: {checks:?}"
    );
    let audit = db.get_audit_log(case_id, 100, 0).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|e| e["action"].as_str() == Some("evidence_acquisition_failed")),
        "the failed acquisition must be audited under its own action"
    );
}

/// A baseline that was recorded must not be reported as one that could not be
/// established because the decoded stream failed to verify afterwards.
#[tokio::test]
async fn a_decoded_verification_failure_leaves_the_recorded_baseline_alone() {
    use seance_core::data_source::DataSource;

    #[derive(Debug)]
    struct Unreadable;
    impl DataSource for Unreadable {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("decoded stream unreadable"))
        }
        fn size(&self) -> u64 {
            4096
        }
    }

    let (db, case_id) = setup_db().await;
    let (service, mut task_rx, mut status_rx) = make_service_with_status(Some(db.clone()));
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"hello").unwrap();
    file.flush().unwrap();
    let path = file.path().to_str().unwrap().to_string();

    let decoded: Arc<dyn DataSource> = Arc::new(Unreadable);
    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        Some(decoded),
        json!({"source_path": path, "name": "img.E01", "stored_md5": "0".repeat(32)}),
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), task_rx.recv()).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(OrchestratorEvent::IngestFailed { .. }) = status_rx.recv().await {
                return;
            }
        }
    })
    .await
    .expect("the verification failure must be reported");

    let stored = db.get_artifact(artifact.id).await.unwrap().unwrap();
    assert_eq!(
        stored.metadata["integrity_state"],
        "decoded_verification_failed"
    );
    assert!(stored.metadata.get("acquisition_error").is_none());
    assert!(
        stored.metadata.get("acquisition_md5").is_some(),
        "baseline kept"
    );
    let checks = db.get_integrity_checks(artifact.id).await.unwrap();
    assert!(checks.iter().any(|c| c["status"] == "baseline"));
    assert!(!checks.iter().any(|c| c["status"] == "acquisition_failed"));
    let audit = db.get_audit_log(case_id, 100, 0).await.unwrap();
    assert!(audit
        .iter()
        .any(|e| e["action"].as_str() == Some("evidence_decoded_verification_failed")));
    assert!(!audit
        .iter()
        .any(|e| e["action"].as_str() == Some("evidence_acquisition_failed")));
}

#[tokio::test]
async fn ingest_fails_when_source_file_unreadable() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx) = make_service(Some(db.clone()));

    let result = service
        .ingest_artifact(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({"source_path": "/nonexistent/path/to/evidence.img", "name": "missing.img"}),
        )
        .await;

    let err = result.expect_err("ingest of unreadable source must fail");
    assert!(
        err.to_string().contains("acquisition hashes"),
        "error must name acquisition hashing: {}",
        err
    );
}

#[tokio::test]
async fn ingest_without_source_path_skips_hashing() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx) = make_service(Some(db.clone()));

    let artifact = service
        .ingest_artifact(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({"name": "synthetic.bin"}),
        )
        .await
        .expect("ingest without source_path must still succeed");

    assert!(artifact.metadata.get("acquisition_md5").is_none());
    let checks = db.get_integrity_checks(artifact.id).await.unwrap();
    assert!(checks.is_empty(), "no baseline row without a source file");
}

#[tokio::test]
async fn blocking_ingest_emits_acquisition_hash_progress() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx, mut status_rx) = make_service_with_status(Some(db.clone()));

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"hello").unwrap();
    file.flush().unwrap();
    let path = file.path().to_str().unwrap().to_string();

    service
        .ingest_artifact(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({"source_path": path, "name": "evidence.bin"}),
        )
        .await
        .expect("ingest must succeed");

    // The final hashing progress callback always fires, so at least one
    // AcquisitionHashProgress with the full byte count must be on the bus.
    let mut saw_progress = false;
    while let Ok(event) = status_rx.try_recv() {
        if let OrchestratorEvent::AcquisitionHashProgress {
            source,
            bytes_done,
            bytes_total,
            segment_count,
            ..
        } = event
        {
            assert_eq!(source, path);
            assert_eq!(bytes_done, 5);
            assert_eq!(bytes_total, 5);
            // A plain single file is not an EWF set.
            assert_eq!(segment_count, None);
            saw_progress = true;
        }
    }
    assert!(saw_progress, "expected an AcquisitionHashProgress event");
}

#[tokio::test]
async fn background_ingest_hashes_persists_and_queues() {
    let (db, case_id) = setup_db().await;
    let (service, mut task_rx, mut status_rx) = make_service_with_status(Some(db.clone()));

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"hello").unwrap();
    file.flush().unwrap();
    let path = file.path().to_str().unwrap().to_string();

    // Returns immediately with a stable artifact ID
    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"source_path": path, "name": "evidence.bin"}),
    );

    // IngestCompleted must arrive for that artifact
    let completed_id = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::IngestCompleted { artifact_id, .. }) => return artifact_id,
                Ok(OrchestratorEvent::IngestFailed { error, .. }) => {
                    panic!("background ingest failed: {}", error)
                }
                Ok(_) => {}
                Err(e) => panic!("status channel closed: {}", e),
            }
        }
    })
    .await
    .expect("IngestCompleted must be emitted");
    assert_eq!(completed_id, artifact.id);

    // The persisted row must carry the acquisition baseline
    let stored = db.get_artifact(artifact.id).await.unwrap().unwrap();
    assert_eq!(
        stored.metadata["acquisition_md5"].as_str().unwrap(),
        "5d41402abc4b2a76b9719d911017c592"
    );
    let checks = db.get_integrity_checks(artifact.id).await.unwrap();
    assert_eq!(
        checks.len(),
        1,
        "exactly one baseline integrity check expected"
    );

    // The artifact must be queued for processing
    let queued = tokio::time::timeout(Duration::from_secs(5), task_rx.recv())
        .await
        .expect("queued artifact must arrive")
        .expect("task channel must stay open");
    assert_eq!(queued.id, artifact.id);
}

/// Parse-while-hashing: the background ingest queues the artifact for
/// processing BEFORE its acquisition baseline is hashed, so processing starts
/// immediately; the baseline lands afterward and flips the integrity state.
#[tokio::test]
async fn background_ingest_queues_before_hashing_then_records_the_baseline() {
    let (db, case_id) = setup_db().await;
    let (service, mut task_rx, mut status_rx) = make_service_with_status(Some(db.clone()));

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"hello").unwrap();
    file.flush().unwrap();
    let path = file.path().to_str().unwrap().to_string();

    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"source_path": path, "name": "evidence.bin"}),
    );

    // The queued artifact is captured at enqueue time — before hashing — so it
    // carries the pending integrity state and NO baseline digest yet. This is
    // the proof that processing is not gated behind the hash.
    let queued = tokio::time::timeout(Duration::from_secs(5), task_rx.recv())
        .await
        .expect("queued artifact must arrive")
        .expect("task channel must stay open");
    assert_eq!(queued.id, artifact.id);
    assert_eq!(
        queued.metadata["integrity_state"], "verifying",
        "the artifact is queued with its integrity still pending"
    );
    assert!(
        queued.metadata.get("acquisition_md5").is_none(),
        "the baseline is not yet computed when the artifact is queued"
    );

    // After IngestCompleted, the baseline has landed: the persisted row carries
    // the acquisition digest and the integrity state has flipped.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::IngestCompleted { .. }) => return,
                Ok(OrchestratorEvent::IngestFailed { error, .. }) => {
                    panic!("ingest failed: {error}")
                }
                Ok(_) => {}
                Err(e) => panic!("status channel closed: {e}"),
            }
        }
    })
    .await
    .expect("IngestCompleted must be emitted");

    let stored = db.get_artifact(artifact.id).await.unwrap().unwrap();
    assert_eq!(
        stored.metadata["acquisition_md5"].as_str().unwrap(),
        "5d41402abc4b2a76b9719d911017c592",
        "the baseline is recorded once hashing completes"
    );
    assert_eq!(stored.metadata["integrity_state"], "baseline_recorded");
    let checks = db.get_integrity_checks(artifact.id).await.unwrap();
    assert_eq!(checks.len(), 1, "exactly one baseline row");
}

#[tokio::test]
async fn background_ingest_failure_emits_ingest_failed() {
    let (db, case_id) = setup_db().await;
    let (service, _task_rx, mut status_rx) = make_service_with_status(Some(db.clone()));

    let artifact = service.ingest_artifact_background(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"source_path": "/nonexistent/path/to/evidence.img", "name": "missing.img"}),
    );

    let (failed_id, error) = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::IngestFailed {
                    artifact_id, error, ..
                }) => return (artifact_id, error),
                Ok(OrchestratorEvent::IngestCompleted { .. }) => {
                    panic!("ingest of unreadable source must fail")
                }
                Ok(_) => {}
                Err(e) => panic!("status channel closed: {}", e),
            }
        }
    })
    .await
    .expect("IngestFailed must be emitted");

    assert_eq!(failed_id, artifact.id);
    assert!(
        error.contains("acquisition hashes"),
        "error must name acquisition hashing: {}",
        error
    );

    // Parse-while-hashing queues (and so persists) the artifact before hashing,
    // so a hash failure cannot make it vanish — the evidence was ingested and
    // may already be processed. The artifact remains, marked acquisition_failed
    // so the un-established baseline is a recorded finding, never hidden.
    let stored = db
        .get_artifact(artifact.id)
        .await
        .unwrap()
        .expect("the queued artifact remains after a baseline failure");
    assert_eq!(
        stored.metadata["integrity_state"], "acquisition_failed",
        "a failed baseline must be recorded on the artifact, not hidden"
    );
    assert!(
        stored.metadata.get("acquisition_md5").is_none(),
        "no baseline digest was established"
    );
}

/// C4: a container that recorded its decoded-media hash (E01 stored_md5) must
/// have that hash re-verified against the actual decoded stream at ingest, with
/// a pass/fail integrity row -- not just a hash of the container file on disk.
#[tokio::test]
async fn ingest_verifies_container_decoded_media_hash() {
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::hashing::compute_hashes;

    let media = b"decoded evidence media bytes".to_vec();
    let real_md5 = compute_hashes(&media).md5;

    // Matching stored_md5 -> "verified".
    {
        let (db, case_id) = setup_db().await;
        let (service, _rx) = make_service(Some(db.clone()));
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(media.clone()));
        let art = service
            .ingest_artifact(
                case_id,
                ArtifactType::RawEvidence,
                Some(ds),
                json!({ "name": "img.E01", "container": "e01", "stored_md5": real_md5 }),
            )
            .await
            .unwrap();
        let checks = db.get_integrity_checks(art.id).await.unwrap();
        assert!(
            checks.iter().any(|c| c["status"] == "verified"),
            "expected a 'verified' decoded-media integrity row, got {checks:?}"
        );
    }

    // Wrong stored_md5 -> "integrity_failed" (surfaced, not silent).
    {
        let (db, case_id) = setup_db().await;
        let (service, _rx) = make_service(Some(db.clone()));
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(media.clone()));
        let art = service
            .ingest_artifact(
                case_id,
                ArtifactType::RawEvidence,
                Some(ds),
                json!({ "name": "img.E01", "container": "e01",
                        "stored_md5": "00000000000000000000000000000000" }),
            )
            .await
            .unwrap();
        let checks = db.get_integrity_checks(art.id).await.unwrap();
        assert!(
            checks.iter().any(|c| c["status"] == "integrity_failed"),
            "a decoded/stored hash mismatch must record integrity_failed, got {checks:?}"
        );
    }
}

/// The decoded-media verification pass — a second full read of a large image —
/// must report progress rather than hash in silence, so the UI can show it is
/// working instead of appearing to hang.
#[tokio::test]
async fn decoded_media_verification_reports_progress() {
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::hashing::compute_hashes;

    let media = b"decoded evidence media bytes for a progress event".to_vec();
    let real_md5 = compute_hashes(&media).md5;

    let (db, case_id) = setup_db().await;
    let (service, _task_rx, mut status_rx) = make_service_with_status(Some(db.clone()));
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(media.clone()));
    service
        .ingest_artifact(
            case_id,
            ArtifactType::RawEvidence,
            Some(ds),
            json!({ "name": "img.E01", "container": "e01", "stored_md5": real_md5 }),
        )
        .await
        .unwrap();

    // At least the final progress call must have been broadcast, reporting the
    // full size so a client renders a determinate bar rather than a silent wait.
    let mut saw_progress = false;
    while let Ok(ev) = status_rx.try_recv() {
        if let OrchestratorEvent::DecodedMediaHashProgress {
            bytes_done,
            bytes_total,
            ..
        } = ev
        {
            assert_eq!(bytes_total, media.len() as u64, "reports the decoded size");
            assert_eq!(
                bytes_done,
                media.len() as u64,
                "final call reports the total"
            );
            saw_progress = true;
        }
    }
    assert!(
        saw_progress,
        "the decoded-media hash must report progress, not hash in silence"
    );
}
