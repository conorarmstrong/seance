/// Orchestrator integration test: synthetic data → modules → DB → verify.
///
/// Tests the full pipeline without requiring external test data files:
/// 1. Creates an in-memory DB
/// 2. Registers a minimal set of modules
/// 3. Injects a synthetic artifact with known content
/// 4. Verifies artifacts flow through the pipeline and reach the DB
/// 5. Verifies module output is correct
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    db::DatabaseConnection,
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::Orchestrator,
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::io;
use std::sync::Arc;
use uuid::Uuid;

// --- In-memory data source for test ---

#[derive(Debug)]
struct MemoryDataSource {
    data: Vec<u8>,
}

impl DataSource for MemoryDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = offset as usize;
        if off >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - off;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[off..off + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

// --- Test module that produces predictable output ---

/// A simple module that reads the first 4 bytes of a FileEntry artifact,
/// treats them as a LE u32 "record count", and produces that many ParsedRecord artifacts.
struct TestRecordExtractor;

impl ForensicsModule for TestRecordExtractor {
    fn id(&self) -> &str {
        "test.record_extractor"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(Vec::new()),
        };

        // Check metadata for our test marker
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if name != "test_records.bin" {
            return Ok(Vec::new());
        }

        // Read first 4 bytes as record count
        let mut buf = [0u8; 4];
        let n = data_source
            .read_at(0, &mut buf)
            .map_err(ModuleError::IoError)?;
        if n < 4 {
            return Ok(Vec::new());
        }

        let record_count = u32::from_le_bytes(buf) as usize;
        let mut results = Vec::with_capacity(record_count);

        for i in 0..record_count {
            let record = Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "subtype": "test_record",
                    "index": i,
                    "source": "test_records.bin",
                }),
            )
            .with_parent(artifact.id);
            results.push(record);
        }

        Ok(results)
    }
}

// --- Test module that produces timeline events from ParsedRecords ---

struct TestTimelineGenerator;

impl ForensicsModule for TestTimelineGenerator {
    fn id(&self) -> &str {
        "test.timeline_generator"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::ParsedRecord]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Only process our test records
        let subtype = artifact
            .metadata
            .get("subtype")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if subtype != "test_record" {
            return Ok(Vec::new());
        }

        let index = artifact
            .metadata
            .get("index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let event = Artifact::new(
            artifact.case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": format!("2024-01-01T00:00:{:02}Z", index.min(59)),
                "timestamp_desc": "Test Event",
                "short_desc": format!("Test event #{}", index),
                "source_module": "test.timeline_generator",
            }),
        )
        .with_parent(artifact.id);

        Ok(vec![event])
    }
}

// --- Integration tests ---

async fn setup_test_db() -> (SqliteConnection, String) {
    // Under the system temp dir, not the working directory: these files used
    // to land in the repository root, and the WAL-mode sidecars (`-wal`,
    // `-shm`) outlived the main file that teardown removed (HUNT-039).
    let db_name = std::env::temp_dir()
        .join(format!("test_orchestrator_{}.sqlite", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned();
    let db_url = format!("sqlite:{}?mode=rwc", db_name);

    if std::path::Path::new(&db_name).exists() {
        let _ = std::fs::remove_file(&db_name);
    }

    let conn = SqliteConnection::new(&db_url)
        .await
        .expect("Failed to create DB");
    conn.initialize().await.expect("Failed to initialize DB");

    (conn, db_name)
}

fn teardown_db(path: &str) {
    // The main file and both WAL-mode sidecars; SQLite leaves the sidecars
    // behind when the last connection was not closed cleanly.
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
}

#[tokio::test]
async fn test_orchestrator_end_to_end() {
    let (db, db_path) = setup_test_db().await;
    let db_arc: Arc<dyn DatabaseConnection> = Arc::new(db);

    // Create a case
    let case_id = db_arc
        .create_case("Orchestrator Test", "Integration Tester")
        .await
        .expect("Failed to create case");

    // Build orchestrator with test modules
    let mut orchestrator = Orchestrator::new(Some(db_arc.clone()), 100)
        .with_exit_on_idle(true)
        .with_worker_count(2);

    orchestrator.register_module(Arc::new(TestRecordExtractor));
    orchestrator.register_module(Arc::new(TestTimelineGenerator));

    let task_sender = orchestrator.task_submitter();

    // Spawn orchestrator
    let orch_handle = tokio::spawn(async move {
        orchestrator.run().await;
    });

    // Create test data: 5 records
    let record_count: u32 = 5;
    let mut data = record_count.to_le_bytes().to_vec();
    data.extend_from_slice(&[0u8; 60]); // padding

    let data_source: Arc<dyn DataSource> = Arc::new(MemoryDataSource { data });

    // Create and ingest the initial artifact
    let initial_artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({
            "name": "test_records.bin",
            "size": 64,
        }),
    );

    // Record it in DB first (as the API would)
    db_arc
        .record_artifact(&initial_artifact)
        .await
        .expect("Failed to record initial artifact");

    // Increment active_tasks before sending (as ingest_artifact() does)
    // The submitter counts the task itself (HUNT-043).
    task_sender
        .send(initial_artifact)
        .expect("Failed to send artifact");

    // Drop the sender so only the orchestrator's internal clone remains
    drop(task_sender);

    // Wait for processing to complete
    // The orchestrator exits after 10s idle, so we need >10s timeout
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(20), orch_handle).await;
    assert!(
        timeout.is_ok(),
        "Orchestrator did not complete within 20 seconds"
    );

    // Use a fresh pool to query the DB directly
    let pool = sqlx::sqlite::SqlitePool::connect(&format!("sqlite:{}", db_path))
        .await
        .expect("Failed to connect to DB for verification");

    // Count all artifacts for this case
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM artifacts WHERE case_id = ?")
        .bind(case_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to count artifacts");

    // We expect: 1 FileEntry + 5 ParsedRecords + 5 TimelineEvents = 11
    // The orchestrator's shutdown awaits the background artifact writer flush,
    // so all artifacts are in the DB by the time orch_handle completes.
    println!("Total artifacts in DB for case {}: {}", case_id, total.0);
    assert_eq!(
        total.0, 11,
        "Should have 11 artifacts (1 FileEntry + 5 ParsedRecords + 5 TimelineEvents), got {}",
        total.0
    );

    // Verify counts by type
    let parsed_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM artifacts WHERE case_id = ? AND artifact_type = 'ParsedRecord'",
    )
    .bind(case_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(parsed_count.0, 5, "Should have 5 ParsedRecord artifacts");

    let timeline_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM artifacts WHERE case_id = ? AND artifact_type = 'TimelineEvent'",
    )
    .bind(case_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(timeline_count.0, 5, "Should have 5 TimelineEvent artifacts");

    println!("Full pipeline verification passed: 1 FileEntry → 5 ParsedRecords → 5 TimelineEvents");

    pool.close().await;
    teardown_db(&db_path);
}

#[tokio::test]
async fn test_orchestrator_no_db() {
    // Test that the orchestrator works without a database (DB = None)
    let mut orchestrator = Orchestrator::new(None, 100)
        .with_exit_on_idle(true)
        .with_worker_count(1);

    orchestrator.register_module(Arc::new(TestRecordExtractor));

    let task_sender = orchestrator.task_submitter();

    let orch_handle = tokio::spawn(async move {
        orchestrator.run().await;
    });

    // Create test data: 3 records
    let record_count: u32 = 3;
    let data = record_count.to_le_bytes().to_vec();
    let data_source: Arc<dyn DataSource> = Arc::new(MemoryDataSource { data });

    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({
            "name": "test_records.bin",
            "size": 4,
        }),
    );

    // The submitter counts the task itself (HUNT-043).
    task_sender.send(artifact).expect("Failed to send");
    drop(task_sender);

    let timeout = tokio::time::timeout(std::time::Duration::from_secs(15), orch_handle).await;
    assert!(timeout.is_ok(), "Orchestrator should complete without DB");
}

#[tokio::test]
async fn test_orchestrator_empty_input() {
    // Test that the orchestrator handles artifacts with no data source gracefully
    let mut orchestrator = Orchestrator::new(None, 100)
        .with_exit_on_idle(true)
        .with_worker_count(1);

    orchestrator.register_module(Arc::new(TestRecordExtractor));

    let task_sender = orchestrator.task_submitter();

    let orch_handle = tokio::spawn(async move {
        orchestrator.run().await;
    });

    let case_id = Uuid::new_v4();
    // Artifact with no data source — module should return Ok(vec![])
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "test_records.bin",
            "size": 0,
        }),
    );

    // The submitter counts the task itself (HUNT-043).
    task_sender.send(artifact).expect("Failed to send");
    drop(task_sender);

    let timeout = tokio::time::timeout(std::time::Duration::from_secs(15), orch_handle).await;
    assert!(
        timeout.is_ok(),
        "Orchestrator should handle empty artifacts"
    );
}

#[tokio::test]
async fn test_orchestrator_module_chaining() {
    // Verify that output from one module feeds as input to the next
    // TestRecordExtractor (FileEntry → ParsedRecord) → TestTimelineGenerator (ParsedRecord → TimelineEvent)
    let mut orchestrator = Orchestrator::new(None, 100)
        .with_exit_on_idle(true)
        .with_worker_count(2);

    orchestrator.register_module(Arc::new(TestRecordExtractor));
    orchestrator.register_module(Arc::new(TestTimelineGenerator));

    // Subscribe to events to count them
    let mut event_receiver = orchestrator.event_receiver();
    let task_sender = orchestrator.task_submitter();

    let orch_handle = tokio::spawn(async move {
        orchestrator.run().await;
    });

    // Create test data: 2 records
    let record_count: u32 = 2;
    let data = record_count.to_le_bytes().to_vec();
    let data_source: Arc<dyn DataSource> = Arc::new(MemoryDataSource { data });

    let case_id = Uuid::new_v4();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({
            "name": "test_records.bin",
            "size": 4,
        }),
    );

    // The submitter counts the task itself (HUNT-043).
    task_sender.send(artifact).expect("Failed to send");
    drop(task_sender);

    // Collect broadcast events
    let event_collector = tokio::spawn(async move {
        let mut parsed_count = 0u32;
        let mut timeline_count = 0u32;
        while let Ok(Ok(art)) =
            tokio::time::timeout(std::time::Duration::from_secs(5), event_receiver.recv()).await
        {
            match art.artifact_type {
                ArtifactType::ParsedRecord => parsed_count += 1,
                ArtifactType::TimelineEvent => timeline_count += 1,
                _ => {}
            }
        }
        (parsed_count, timeline_count)
    });

    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), orch_handle).await;

    let (parsed, timeline) = event_collector.await.expect("Event collector panicked");

    // The orchestrator broadcasts artifacts twice for chained types:
    // - Once when produced (output of module A)
    // - Once when entering processing (input to module B)
    // So 2 ParsedRecords × 2 broadcasts = 4
    // TimelineEvents are NOT re-queued (terminal type), so broadcast only once each = 2
    println!(
        "Broadcast events: {} ParsedRecords, {} TimelineEvents",
        parsed, timeline
    );
    assert_eq!(
        parsed, 4,
        "Should broadcast 4 ParsedRecord events (2 produced + 2 re-queued)"
    );
    assert_eq!(
        timeline, 2,
        "Should broadcast 2 TimelineEvent events (terminal, not re-queued)"
    );
}

/// A job still `pending` or `running` in the database when an orchestrator
/// starts was queued in the memory of a process that has stopped; nothing will
/// run it. The orchestrator marks it failed, with a message that says so,
/// before it accepts work (HUNT-050). A job that has already finished keeps
/// its own record.
#[tokio::test]
async fn jobs_a_stopped_process_left_running_are_failed_when_the_next_one_starts() {
    use seance_core::profile::{AdHocJob, JobStatus};

    let (db, db_path) = setup_test_db().await;
    let db_arc: Arc<dyn DatabaseConnection> = Arc::new(db);
    let case_id = db_arc
        .create_case("Restart", "Integration Tester")
        .await
        .expect("Failed to create case");
    let target = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        serde_json::json!({ "name": "target" }),
    );
    db_arc.record_artifact(&target).await.unwrap();

    // Both were left by "the previous process": created before this one starts.
    let earlier = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs() as i64
        - 60;
    let job = |status: JobStatus, error_message: Option<&str>| AdHocJob {
        id: Uuid::new_v4(),
        case_id,
        module_id: "test.module".to_string(),
        target_artifact_id: target.id,
        status,
        artifacts_produced: 0,
        error_message: error_message.map(str::to_string),
        created_at: earlier,
        completed_at: None,
    };
    let running = job(JobStatus::Running, None);
    let pending = job(JobStatus::Pending, None);
    let complete = AdHocJob {
        completed_at: Some(earlier + 1),
        ..job(JobStatus::Complete, None)
    };
    for j in [&running, &pending, &complete] {
        db_arc.create_job(j).await.unwrap();
    }

    let orchestrator = Orchestrator::new(Some(db_arc.clone()), 8)
        .with_exit_on_idle(true)
        .with_worker_count(1);
    tokio::time::timeout(std::time::Duration::from_secs(30), orchestrator.run())
        .await
        .expect("an idle orchestrator exits");

    for j in [&running, &pending] {
        let after = db_arc.get_job(j.id).await.unwrap().unwrap();
        assert_eq!(
            after.status,
            JobStatus::Failed,
            "job {} left {}",
            j.id,
            j.status
        );
        assert_eq!(
            after.error_message.as_deref(),
            Some(seance_core::orchestrator::INTERRUPTED_JOB_MESSAGE)
        );
        assert!(after.completed_at.is_some());
    }
    let after = db_arc.get_job(complete.id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Complete);
    assert_eq!(after.completed_at, Some(earlier + 1));

    teardown_db(&db_path);
}

/// HUNT-113. An ingest a stopped process never finished left a case that read
/// as complete. Now: the run is a row opened when the root is queued and
/// closed when the case goes idle; a row still open at the next start is
/// marked interrupted and its source is stamped incomplete in the vocabulary
/// the census and the report already read.
#[tokio::test]
async fn an_ingest_run_is_recorded_and_a_stopped_one_marks_its_source_incomplete() {
    use seance_core::profile::IngestRun;
    let (db, db_path) = setup_test_db().await;
    let db_arc: Arc<dyn DatabaseConnection> = Arc::new(db);
    let case_id = db_arc.create_case("Runs", "Tester").await.unwrap();

    // What a killed process leaves: a root with part of its subtree recorded
    // and a run row nobody closed, started before this process.
    let killed_root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"name": "CoreServices", "source_path": "/evidence/CoreServices"}),
    );
    db_arc.record_artifact(&killed_root).await.unwrap();
    db_arc
        .record_artifact(
            &Artifact::new(case_id, ArtifactType::FileEntry, None, json!({"name": "a"}))
                .with_parent(killed_root.id),
        )
        .await
        .unwrap();
    db_arc
        .start_ingest_run(&IngestRun {
            id: Uuid::new_v4(),
            case_id,
            source_artifact_id: killed_root.id,
            source_label: "/evidence/CoreServices".to_string(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 60,
            finished_at: None,
            status: IngestRun::RUNNING.to_string(),
            artifacts_recorded: None,
            detail: None,
        })
        .await
        .unwrap();

    let mut orchestrator = Orchestrator::new(Some(db_arc.clone()), 100)
        .with_exit_on_idle(true)
        .with_idle_timeout(std::time::Duration::from_secs(2))
        .with_worker_count(2);
    orchestrator.register_module(Arc::new(TestRecordExtractor));
    let ingestion = orchestrator.ingestion_service();
    let orch_handle = tokio::spawn(async move {
        orchestrator.run().await;
    });

    // A fresh ingest through the service, which is what opens a run row.
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&[0u8; 60]);
    let source: Arc<dyn DataSource> = Arc::new(MemoryDataSource { data });
    let fresh = ingestion
        .ingest_artifact(
            case_id,
            ArtifactType::FileEntry,
            Some(source),
            json!({"name": "test_records.bin", "size": 64}),
        )
        .await
        .expect("ingested");
    drop(ingestion);

    tokio::time::timeout(std::time::Duration::from_secs(20), orch_handle)
        .await
        .expect("orchestrator exits on idle")
        .unwrap();

    let runs = db_arc.list_ingest_runs(case_id).await.unwrap();
    let by_source = |id: Uuid| runs.iter().find(|r| r.source_artifact_id == id).unwrap();

    let killed = by_source(killed_root.id);
    assert_eq!(killed.status, "interrupted");
    assert_eq!(
        killed.artifacts_recorded,
        Some(1),
        "what the walk had recorded"
    );
    assert!(killed.finished_at.is_some());

    let done = by_source(fresh.id);
    assert_eq!(done.status, "completed");
    assert_eq!(
        done.artifacts_recorded,
        Some(2),
        "the two records the module produced"
    );

    // The source artifacts say it, in the vocabulary every consumer reads.
    let pool = sqlx::sqlite::SqlitePool::connect(&format!("sqlite:{}", db_path))
        .await
        .unwrap();
    let pool_ref = &pool;
    let meta = |id: Uuid| async move {
        let (json,): (String,) = sqlx::query_as("SELECT metadata_json FROM artifacts WHERE id = ?")
            .bind(id)
            .fetch_one(pool_ref)
            .await
            .unwrap();
        serde_json::from_str::<serde_json::Value>(&json).unwrap()
    };
    let killed_meta = meta(killed_root.id).await;
    assert_eq!(killed_meta["processing_state"], "interrupted");
    assert_eq!(killed_meta["inventory_incomplete"], true);
    assert_eq!(
        killed_meta["inventory_incomplete_reason"],
        "ingest_interrupted"
    );
    assert_eq!(killed_meta["content_incomplete"], true);
    let detail = killed_meta["incomplete_detail"].as_str().unwrap();
    assert!(detail.contains("1 artifacts were recorded"), "{detail}");
    assert!(detail.contains("absent from this case, not from the evidence"));

    let fresh_meta = meta(fresh.id).await;
    assert_eq!(fresh_meta["processing_state"], "completed");
    assert!(fresh_meta.get("inventory_incomplete").is_none());

    pool.close().await;
    teardown_db(&db_path);
}
