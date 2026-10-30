//! The memory governor, end to end through the real orchestrator.
//!
//! A budget the process is already over must end an ingest cleanly: the run
//! stops, says so, and leaves the source marked incomplete with the reason and
//! the remedy. It must neither hang nor run on regardless, and it must not end
//! as a silent `ProcessingComplete`.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::memory_guard::{MemoryGuard, MemoryReader, MemorySample};
use seance_core::module::{ForensicsModule, InputCapability, ModuleError};
use seance_core::orchestrator::{Orchestrator, OrchestratorEvent};
use seance_db::SqliteConnection;
use serde_json::json;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

const MIB: u64 = 1 << 20;

/// A reading in which the process holds `anon` bytes on an otherwise idle host.
struct Fixed(MemorySample);

impl MemoryReader for Fixed {
    fn sample(&self) -> Option<MemorySample> {
        Some(self.0)
    }
}

fn reading(anon: u64) -> Arc<dyn MemoryReader> {
    Arc::new(Fixed(MemorySample {
        process_anon: anon,
        process_rss: anon,
        host_total: 64 * 1024 * MIB,
        host_available: 60 * 1024 * MIB,
        cgroup_limit: None,
        cgroup_anon: None,
    }))
}

/// The source produces forty files; each file takes a moment to examine. Enough
/// work that the governor, sampling every quarter second, meets the run in
/// the middle of it.
struct Expand;

impl ForensicsModule for Expand {
    fn id(&self) -> &str {
        "test.expand"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::RawEvidence]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, parent: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok((0..40)
            .map(|i| {
                Artifact::new(
                    parent.case_id,
                    ArtifactType::FileEntry,
                    None,
                    json!({"name": format!("f{i}")}),
                )
                .with_parent(parent.id)
            })
            .collect())
    }
}

struct Examine;

impl ForensicsModule for Examine {
    fn id(&self) -> &str {
        "test.examine"
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
    fn process(&self, _artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        std::thread::sleep(Duration::from_millis(30));
        Ok(Vec::new())
    }
}

async fn drive(
    budget: u64,
    anon: u64,
) -> (
    Arc<SqliteConnection>,
    uuid::Uuid,
    Vec<OrchestratorEvent>,
    MemoryGuard,
    uuid::Uuid,
) {
    drive_with(budget, anon, true, false).await
}

async fn drive_with(
    budget: u64,
    anon: u64,
    with_modules: bool,
    // Start the run and let the governor reach its verdict before the source
    // is ingested, so a worker finds the gate already closed.
    ingest_after_verdict: bool,
) -> (
    Arc<SqliteConnection>,
    uuid::Uuid,
    Vec<OrchestratorEvent>,
    MemoryGuard,
    uuid::Uuid,
) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Memory", "Examiner").await.unwrap();

    let guard = MemoryGuard::with_budget(budget, Duration::from_millis(400));
    let mut orch = Orchestrator::new(Some(db.clone()), 64)
        .with_worker_count(2)
        .with_exit_on_idle(true)
        .with_idle_timeout(Duration::from_millis(if ingest_after_verdict {
            3000
        } else {
            300
        }))
        .with_memory_guard(guard.clone(), reading(anon));
    if with_modules {
        orch.register_module(Arc::new(Expand));
        orch.register_module(Arc::new(Examine));
    }
    let mut status = orch.status_sender().subscribe();

    // A small synthetic image: 64 KiB of bytes is all the pipeline needs to
    // treat it as a source.
    let mut image = tempfile::NamedTempFile::new().unwrap();
    image.write_all(&[0u8; 64 * 1024]).unwrap();
    image.flush().unwrap();
    let ingestion = orch.ingestion_service();
    let handle = tokio::spawn(orch.run());
    if ingest_after_verdict {
        for _ in 0..100 {
            if guard.pressure() != seance_core::memory_guard::Pressure::Ok {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let source = ingestion
        .ingest_artifact(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({"source_path": image.path().to_str().unwrap(), "name": "synthetic.dd"}),
        )
        .await
        .expect("the source must be accepted");

    tokio::time::timeout(Duration::from_secs(30), handle)
        .await
        .expect("a run under a memory limit must end, not hang")
        .expect("the orchestrator must not panic");

    let mut events = Vec::new();
    while let Ok(e) = status.try_recv() {
        events.push(e);
    }
    (db, case_id, events, guard, source.id)
}

#[tokio::test]
async fn a_limit_the_process_is_already_over_stops_the_ingest_cleanly_and_says_so() {
    // 10 MiB budget, 50 MiB in use: Critical from the first sample.
    let (db, case_id, events, guard, source_id) = drive(10 * MIB, 50 * MIB).await;

    assert!(
        events.iter().any(|e| matches!(
            e,
            OrchestratorEvent::ProcessingCancelled { case_id: Some(c), .. } if *c == case_id
        )),
        "the run must end as stopped, not silently: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, OrchestratorEvent::ProcessingComplete { .. })),
        "a run stopped for memory must never be reported complete"
    );
    assert_eq!(guard.stats().stops, 1);
    assert!(
        guard.take_stop().is_none(),
        "the stop was reported and consumed"
    );

    // The persisted half: the ingest run is closed, and the source carries the
    // reason, the numbers and the remedy, in the fields every screen reads.
    let runs = db.list_ingest_runs(case_id).await.unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].status, "cancelled",
        "a finished row, not a `running` one"
    );
    assert_eq!(runs[0].source_artifact_id, source_id);

    let source = db.get_artifact(source_id).await.unwrap().unwrap();
    let meta = &source.metadata;
    assert_eq!(meta["processing_state"], "cancelled");
    assert_eq!(meta["inventory_incomplete"], json!(true));
    let detail = meta["incomplete_detail"].as_str().unwrap();
    assert!(
        detail.starts_with("stopped: memory limit reached at 50 MiB"),
        "{detail}"
    );
    assert!(detail.contains(" tasks done"), "{detail}");
    // Forty-one artifacts were there to do; the run did not get through them.
    assert!(!detail.contains("41 tasks done"), "{detail}");
    assert!(detail.contains("SEANCE_MEMORY_LIMIT"), "{detail}");
    assert!(detail.contains("SEANCE_WORKERS"), "{detail}");
}

#[tokio::test]
async fn a_process_inside_its_budget_is_not_touched() {
    // 1 GiB budget, 50 MiB in use: Ok throughout.
    let (db, case_id, events, guard, source_id) = drive(1024 * MIB, 50 * MIB).await;

    assert!(events.iter().any(|e| matches!(
        e,
        OrchestratorEvent::ProcessingComplete { case_id: c, total_artifacts: 41, .. }
            if *c == case_id
    )));
    assert_eq!(guard.stats().stops, 0);
    let runs = db.list_ingest_runs(case_id).await.unwrap();
    assert_eq!(runs[0].status, "completed");
    let source = db.get_artifact(source_id).await.unwrap().unwrap();
    assert_eq!(source.metadata["processing_state"], "completed");
}

/// The case a real scan hit: one source, nothing queued behind it. The only
/// task is held by a worker parked at the gate, where it is in neither the
/// queue nor the in-flight census, so a stop that cancelled only the cases it
/// could see would cancel nothing and the run would finish "complete".
#[tokio::test]
async fn a_stop_reaches_the_task_a_parked_worker_is_holding() {
    let (db, case_id, events, guard, source_id) = drive_with(10 * MIB, 50 * MIB, false, true).await;

    assert_eq!(guard.stats().stops, 1);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, OrchestratorEvent::ProcessingComplete { .. })),
        "reported complete after a memory stop: {events:?}"
    );
    assert!(events.iter().any(|e| matches!(
        e,
        OrchestratorEvent::ProcessingCancelled { case_id: Some(c), .. } if *c == case_id
    )));
    let runs = db.list_ingest_runs(case_id).await.unwrap();
    assert_eq!(runs[0].status, "cancelled");
    let source = db.get_artifact(source_id).await.unwrap().unwrap();
    assert!(source.metadata["incomplete_detail"]
        .as_str()
        .unwrap()
        .starts_with("stopped: memory limit reached"));
}
