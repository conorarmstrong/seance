//! The fold has to happen on the path ingest actually takes.
//!
//! `HUNT-074` folds "this module ran over this artifact and produced nothing"
//! into one row per artifact instead of one row per module. The database layer
//! was tested with hand-built rows and passed, and the wiring in the
//! orchestrator was missing: a real ingest still wrote 515 rows where it should
//! have written 17, and nothing in the suite noticed. This test drives the
//! orchestrator itself.

use async_trait::async_trait;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::{DatabaseConnection, ProcessingLogRow},
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::Orchestrator,
    profile::{AdHocJob, IngestionProfile, ProcessingLogEntry},
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Produces `output` artifacts every time it runs.
struct Module {
    id: String,
    output: usize,
}

impl std::fmt::Debug for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)
    }
}

impl ForensicsModule for Module {
    fn id(&self) -> &str {
        &self.id
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
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok((0..self.output)
            .map(|_| {
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    serde_json::json!({"type": "Test"}),
                )
            })
            .collect())
    }
}

/// A database that keeps the processing-log rows exactly as they were written.
#[derive(Default)]
struct LogCapturingDb {
    rows: Arc<Mutex<Vec<ProcessingLogRow>>>,
}

#[async_trait]
impl DatabaseConnection for LogCapturingDb {
    async fn initialize(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn create_case(&self, _name: &str, _examiner: &str) -> anyhow::Result<Uuid> {
        Ok(Uuid::new_v4())
    }
    async fn record_artifact(&self, _artifact: &Artifact) -> anyhow::Result<()> {
        Ok(())
    }
    async fn get_artifact(&self, _id: Uuid) -> anyhow::Result<Option<Artifact>> {
        Ok(None)
    }
    async fn create_profile(&self, _p: &IngestionProfile) -> anyhow::Result<()> {
        Ok(())
    }
    async fn get_active_profile(&self, _c: Uuid) -> anyhow::Result<Option<IngestionProfile>> {
        Ok(None)
    }
    async fn list_profiles(&self, _c: Uuid) -> anyhow::Result<Vec<IngestionProfile>> {
        Ok(vec![])
    }
    async fn set_active_profile(&self, _c: Uuid, _p: Uuid) -> anyhow::Result<()> {
        Ok(())
    }
    async fn delete_profile(&self, _p: Uuid) -> anyhow::Result<()> {
        Ok(())
    }
    async fn create_job(&self, _j: &AdHocJob) -> anyhow::Result<()> {
        Ok(())
    }
    async fn update_job(&self, _j: &AdHocJob) -> anyhow::Result<()> {
        Ok(())
    }
    async fn get_job(&self, _id: Uuid) -> anyhow::Result<Option<AdHocJob>> {
        Ok(None)
    }
    async fn list_jobs(&self, _c: Uuid) -> anyhow::Result<Vec<AdHocJob>> {
        Ok(vec![])
    }
    async fn record_processing_log(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        module_id: &str,
        status: &str,
        artifacts_produced: usize,
        error_message: Option<&str>,
        duration_ms: u64,
    ) -> anyhow::Result<()> {
        self.rows.lock().unwrap().push(ProcessingLogRow::single(
            case_id,
            artifact_id,
            module_id.to_string(),
            status.to_string(),
            artifacts_produced,
            error_message.map(str::to_string),
            duration_ms,
        ));
        Ok(())
    }
    async fn record_processing_log_batch(
        &self,
        entries: &[ProcessingLogRow],
    ) -> anyhow::Result<()> {
        self.rows.lock().unwrap().extend(entries.iter().cloned());
        Ok(())
    }
    async fn get_processing_log_for_artifact(
        &self,
        _a: Uuid,
        _l: Option<usize>,
    ) -> anyhow::Result<Vec<ProcessingLogEntry>> {
        Ok(vec![])
    }
    async fn count_processing_log_for_artifact(&self, _a: Uuid) -> anyhow::Result<usize> {
        Ok(0)
    }
    async fn list_jobs_for_artifact(&self, _a: Uuid) -> anyhow::Result<Vec<AdHocJob>> {
        Ok(vec![])
    }
}

#[tokio::test]
async fn an_ingest_folds_the_modules_that_produced_nothing_into_one_row() {
    let db = Arc::new(LogCapturingDb::default());
    let rows = db.rows.clone();
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let case_id = Uuid::new_v4();

    for i in 0..6 {
        orchestrator.register_module(Arc::new(Module {
            id: format!("module.quiet.{i}"),
            output: 0,
        }));
    }
    orchestrator.register_module(Arc::new(Module {
        id: "module.loud".to_string(),
        output: 2,
    }));

    let submitter = orchestrator.task_submitter();
    let runner = tokio::spawn(async move { orchestrator.run().await });

    submitter
        .send(Artifact::new(
            case_id,
            ArtifactType::RawEvidence,
            None,
            serde_json::json!({"name": "evidence"}),
        ))
        .unwrap();

    // The log writer flushes on a 500ms tick.
    let mut folded = None;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let seen = rows.lock().unwrap().clone();
        if let Some(row) = seen.iter().find(|r| r.zero_yield.is_some()) {
            folded = Some((row.clone(), seen));
            break;
        }
    }
    runner.abort();

    let (folded, seen) = folded.expect("the six quiet modules must be folded into one row");
    let names: Vec<String> = folded
        .zero_yield
        .as_ref()
        .unwrap()
        .iter()
        .map(|(m, _)| m.clone())
        .collect();
    assert_eq!(names.len(), 6, "every quiet module is named: {names:?}");
    assert!(names.iter().all(|n| n.starts_with("module.quiet.")));
    assert!(
        folded.module_id.is_empty(),
        "a folded row is about several modules"
    );
    assert_eq!(folded.status, "complete");

    // The module that produced something keeps its own row, with its count.
    let loud = seen
        .iter()
        .find(|r| r.module_id == "module.loud")
        .expect("a module that produced artifacts keeps its own row");
    assert_eq!(loud.artifacts_produced, 2);

    // And nothing wrote a row per quiet module beside the fold.
    assert!(
        !seen
            .iter()
            .any(|r| r.module_id.starts_with("module.quiet.")),
        "a quiet module must not also get its own row"
    );
}
