use async_trait::async_trait;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::{Orchestrator, OrchestratorEvent},
    profile::{AdHocJob, AdHocRequest, IngestionProfile, JobStatus, ProcessingLogEntry},
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use uuid::Uuid;

// --- Mock Module ---

struct MockModule {
    id: String,
    subscribes_to: Vec<ArtifactType>,
    run_count: Arc<Mutex<usize>>,
    notifier: Arc<Notify>,
}

impl MockModule {
    fn new(id: &str, subscribes_to: Vec<ArtifactType>) -> Self {
        Self {
            id: id.to_string(),
            subscribes_to,
            run_count: Arc::new(Mutex::new(0)),
            notifier: Arc::new(Notify::new()),
        }
    }
}

impl ForensicsModule for MockModule {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        self.subscribes_to.clone()
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, _artifact: &Artifact) -> anyhow::Result<Vec<Artifact>, ModuleError> {
        let mut count = self.run_count.lock().unwrap();
        *count += 1;
        self.notifier.notify_one();
        Ok(Vec::new())
    }
}

// --- Mock Database ---

struct MockDatabase {
    artifacts: Arc<Mutex<HashMap<Uuid, Artifact>>>,
    jobs: Arc<Mutex<HashMap<Uuid, AdHocJob>>>,
    profiles: Arc<Mutex<HashMap<Uuid, IngestionProfile>>>, // active profiles map case_id -> profile
}

impl MockDatabase {
    fn new() -> Self {
        Self {
            artifacts: Arc::new(Mutex::new(HashMap::new())),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            profiles: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl DatabaseConnection for MockDatabase {
    async fn initialize(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn record_artifact(&self, artifact: &Artifact) -> anyhow::Result<()> {
        self.artifacts
            .lock()
            .unwrap()
            .insert(artifact.id, artifact.clone());
        Ok(())
    }
    async fn get_artifact(&self, id: Uuid) -> anyhow::Result<Option<Artifact>> {
        Ok(self.artifacts.lock().unwrap().get(&id).cloned())
    }

    async fn create_case(&self, _n: &str, _e: &str) -> anyhow::Result<Uuid> {
        Ok(Uuid::new_v4())
    }

    // Profile management
    async fn create_profile(&self, _profile: &IngestionProfile) -> anyhow::Result<()> {
        Ok(())
    }
    async fn get_active_profile(&self, case_id: Uuid) -> anyhow::Result<Option<IngestionProfile>> {
        Ok(self.profiles.lock().unwrap().get(&case_id).cloned())
    }
    async fn list_profiles(&self, _case_id: Uuid) -> anyhow::Result<Vec<IngestionProfile>> {
        Ok(vec![])
    }
    async fn set_active_profile(&self, _case_id: Uuid, _profile_id: Uuid) -> anyhow::Result<()> {
        Ok(())
    }
    async fn delete_profile(&self, _profile_id: Uuid) -> anyhow::Result<()> {
        Ok(())
    }

    // Ad-hoc job management
    async fn create_job(&self, job: &AdHocJob) -> anyhow::Result<()> {
        self.jobs.lock().unwrap().insert(job.id, job.clone());
        Ok(())
    }
    async fn update_job(&self, job: &AdHocJob) -> anyhow::Result<()> {
        self.jobs.lock().unwrap().insert(job.id, job.clone());
        Ok(())
    }
    async fn get_job(&self, id: Uuid) -> anyhow::Result<Option<AdHocJob>> {
        Ok(self.jobs.lock().unwrap().get(&id).cloned())
    }
    async fn list_jobs(&self, _case_id: Uuid) -> anyhow::Result<Vec<AdHocJob>> {
        Ok(vec![])
    }

    // Processing log
    async fn record_processing_log(
        &self,
        _case_id: Uuid,
        _artifact_id: Uuid,
        _module_id: &str,
        _status: &str,
        _artifacts_produced: usize,
        _error_message: Option<&str>,
        _duration_ms: u64,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn get_processing_log_for_artifact(
        &self,
        _artifact_id: Uuid,
        _limit: Option<usize>,
    ) -> anyhow::Result<Vec<ProcessingLogEntry>> {
        Ok(vec![])
    }
    async fn count_processing_log_for_artifact(&self, _artifact_id: Uuid) -> anyhow::Result<usize> {
        Ok(0)
    }
    async fn list_jobs_for_artifact(&self, _artifact_id: Uuid) -> anyhow::Result<Vec<AdHocJob>> {
        Ok(vec![])
    }
}

/// Poll a job until it reaches Complete or Failed, failing the test (rather
/// than hanging) if it does not within five seconds.
async fn wait_for_terminal_job(db: &MockDatabase, job_id: Uuid) -> AdHocJob {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(job) = db.get_job(job_id).await.unwrap() {
                if matches!(job.status, JobStatus::Complete | JobStatus::Failed) {
                    return job;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("job must reach a terminal status")
}

// --- Tests ---

#[tokio::test]
async fn test_orchestrator_profile_filtering() {
    let db = Arc::new(MockDatabase::new());
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let case_id = Uuid::new_v4();

    // 1. Setup Modules
    let module_a = Arc::new(MockModule::new("module.a", vec![ArtifactType::RawEvidence]));
    let module_b = Arc::new(MockModule::new("module.b", vec![ArtifactType::RawEvidence]));

    orchestrator.register_module(module_a.clone());
    orchestrator.register_module(module_b.clone());

    // 2. Setup Profile: Enable Module A, Disable Module B
    let mut profile = IngestionProfile::new(
        case_id,
        "Test Profile".to_string(),
        "Test Description".to_string(),
    );
    profile.enabled_modules = vec!["module.a".to_string()]; // Allow list

    // Set profile in Orchestrator (simulating loading from DB)
    orchestrator.set_profile(case_id, Some(profile)).await;

    // 3. Start Orchestrator
    let task_submitter = orchestrator.task_submitter();
    let runner = tokio::spawn(async move {
        orchestrator.run().await;
    });

    // 4. Submit Artifact
    let artifact = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        serde_json::json!({}),
    );
    task_submitter.send(artifact).unwrap();

    // 5. Wait for processing
    // Wait for module A to run; a regression must fail here, not hang.
    tokio::time::timeout(Duration::from_secs(5), module_a.notifier.notified())
        .await
        .expect("module A must run");

    // Give a little time for module B to POTENTIALLY run (it shouldn't)
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // 6. Verify Results
    assert_eq!(
        *module_a.run_count.lock().unwrap(),
        1,
        "Module A should have run"
    );
    assert_eq!(
        *module_b.run_count.lock().unwrap(),
        0,
        "Module B should have been skipped"
    );

    // Cleanup: the test is done; abort the runner rather than wait out the
    // idle window.
    runner.abort();
}

#[tokio::test]
async fn test_orchestrator_ad_hoc_execution() {
    let db = Arc::new(MockDatabase::new());
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100).with_exit_on_idle(true);
    let case_id = Uuid::new_v4();
    let artifact_id = Uuid::new_v4();
    let job_id = Uuid::new_v4();

    // 1. Setup DB with Artifact and Job
    let artifact = Artifact {
        id: artifact_id,
        case_id,
        artifact_type: ArtifactType::RawEvidence,
        parent_id: None,
        data: None,
        metadata: serde_json::json!({}),
    };
    db.record_artifact(&artifact).await.unwrap();

    let job = AdHocJob {
        id: job_id,
        case_id,
        module_id: "module.c".to_string(),
        target_artifact_id: artifact_id,
        status: JobStatus::Pending,
        artifacts_produced: 0,
        error_message: None,
        created_at: 0,
        completed_at: None,
    };
    db.update_job(&job).await.unwrap();

    // 2. Setup Module C
    let module_c = Arc::new(MockModule::new("module.c", vec![ArtifactType::RawEvidence]));
    orchestrator.register_module(module_c.clone());

    // 3. Start Orchestrator
    let ad_hoc_submitter = orchestrator.ad_hoc_submitter();
    let runner = tokio::spawn(async move {
        orchestrator.run().await;
    });

    // 4. Send Ad-Hoc Request
    let request = AdHocRequest {
        job_id,
        case_id,
        artifact_id,
        module_id: "module.c".to_string(),
        data_source: None,
        credential: None,
    };
    ad_hoc_submitter.send(request).await.unwrap();

    // 5. Wait for processing. The module notifies from inside `process()`,
    // before the orchestrator can persist the job's final status, so poll the
    // job to a terminal state rather than reading it straight after the notify.
    tokio::time::timeout(Duration::from_secs(5), module_c.notifier.notified())
        .await
        .expect("module C must run");
    let updated_job = wait_for_terminal_job(&db, job_id).await;

    // 6. Verify Results
    assert_eq!(
        *module_c.run_count.lock().unwrap(),
        1,
        "Module C should have run"
    );
    assert_eq!(
        updated_job.status,
        JobStatus::Complete,
        "Job should be complete"
    );

    // Cleanup
    runner.abort();
}

/// Regression: a run that finishes ENTIRELY between two 2-second progress ticks
/// (so `was_busy` is never armed) must still emit ProcessingComplete. With
/// exit-on-idle off (as the server runs), the progress tick is the only
/// completion path, so before the fix a sub-tick-fast ingest never completed and
/// the UI stalled on its last phase.
#[tokio::test]
async fn fast_run_between_ticks_still_emits_processing_complete() {
    let db = Arc::new(MockDatabase::new());
    // Default exit_on_idle = false, matching the server.
    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let case_id = Uuid::new_v4();

    let mut status_rx = orchestrator.status_sender().subscribe();
    let sender = orchestrator.task_submitter();

    // One artifact, processed in milliseconds -- well under a 2s tick.
    // The submitter counts the task itself (HUNT-043).
    sender
        .send(Artifact::new(
            case_id,
            ArtifactType::RawEvidence,
            None,
            serde_json::json!({}),
        ))
        .unwrap();

    let runner = tokio::spawn(orchestrator.run());

    let got = tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::ProcessingComplete {
                    total_artifacts, ..
                }) => return Some(total_artifacts),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten();

    runner.abort();
    assert!(
        matches!(got, Some(n) if n >= 1),
        "a sub-tick-fast run must still emit ProcessingComplete; got {:?}",
        got
    );
}

/// B2-059: activating a different ingestion profile must reach a process that is
/// already running.
///
/// The orchestrator cached each case's profile the first time it processed an
/// artifact and never looked again, so switching triage -> deep (or to a custom
/// profile) changed the database row and the UI while the live module selection
/// stayed on the first profile for the lifetime of the process. The examiner is
/// then shown "deep" while triage-scope processing is what actually runs.
#[tokio::test]
async fn an_activated_profile_reaches_a_running_orchestrator() {
    let db = Arc::new(MockDatabase::new());
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let case_id = Uuid::new_v4();

    let module_a = Arc::new(MockModule::new("module.a", vec![ArtifactType::RawEvidence]));
    let module_b = Arc::new(MockModule::new("module.b", vec![ArtifactType::RawEvidence]));
    orchestrator.register_module(module_a.clone());
    orchestrator.register_module(module_b.clone());

    // Profile 1 (active in the DB before the run starts): only module.a.
    let mut first = IngestionProfile::new(case_id, "first".to_string(), String::new());
    first.enabled_modules = vec!["module.a".to_string()];
    db.profiles.lock().unwrap().insert(case_id, first);

    let sender = orchestrator.task_submitter();
    let runner = tokio::spawn(orchestrator.run());

    let submit = |n: usize| {
        for _ in 0..n {
            // The submitter counts the task itself (HUNT-043).
            sender
                .send(Artifact::new(
                    case_id,
                    ArtifactType::RawEvidence,
                    None,
                    serde_json::json!({}),
                ))
                .unwrap();
        }
    };

    submit(1);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(*module_a.run_count.lock().unwrap(), 1, "profile 1 allows A");
    assert_eq!(*module_b.run_count.lock().unwrap(), 0, "profile 1 blocks B");

    // The examiner activates a different profile: now only module.b.
    let mut second = IngestionProfile::new(case_id, "second".to_string(), String::new());
    second.enabled_modules = vec!["module.b".to_string()];
    db.profiles.lock().unwrap().insert(case_id, second);

    // Past the refresh interval, the new selection must be in force.
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    submit(1);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let a_runs = *module_a.run_count.lock().unwrap();
    let b_runs = *module_b.run_count.lock().unwrap();
    runner.abort();

    assert_eq!(
        b_runs, 1,
        "the newly activated profile must decide which modules run"
    );
    assert_eq!(
        a_runs, 1,
        "the superseded profile must stop selecting modules"
    );
}

/// BUG-027 / BUG-043 / B2-115: the orchestrator kept ONE set of progress
/// counters for the whole process, stamped with whichever case had written to
/// them most recently. Two cases ingesting at the same time were reported as a
/// single run whose totals were the sum of both, under a case_id decided by a
/// race — so an examiner watching case A was told how much of case B had been
/// processed, and a client filtering by case_id could not tell the difference.
///
/// Each case must terminate with its own event carrying its own count.
#[tokio::test]
async fn concurrent_cases_are_reported_separately() {
    let db = Arc::new(MockDatabase::new());
    // Default exit_on_idle = false, matching the server: the progress tick is
    // the only completion path.
    let orchestrator = Orchestrator::new(Some(db.clone()), 200);
    let case_a = Uuid::new_v4();
    let case_b = Uuid::new_v4();

    let mut status_rx = orchestrator.status_sender().subscribe();
    let sender = orchestrator.task_submitter();

    // Two artifacts for case A, three for case B, queued before the run starts
    // so both cases are in flight within the same run.
    for (case_id, count) in [(case_a, 2usize), (case_b, 3usize)] {
        for _ in 0..count {
            // The submitter counts the task itself (HUNT-043).
            sender
                .send(Artifact::new(
                    case_id,
                    ArtifactType::RawEvidence,
                    None,
                    serde_json::json!({}),
                ))
                .unwrap();
        }
    }

    let runner = tokio::spawn(orchestrator.run());

    let mut totals: HashMap<Uuid, usize> = HashMap::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            match status_rx.recv().await {
                Ok(OrchestratorEvent::ProcessingComplete {
                    case_id,
                    total_artifacts,
                    ..
                }) => {
                    totals.insert(case_id, total_artifacts);
                    if totals.len() == 2 {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    })
    .await;

    runner.abort();

    assert_eq!(
        totals.get(&case_a),
        Some(&2),
        "case A must be reported with its own two artifacts, got {:?}",
        totals
    );
    assert_eq!(
        totals.get(&case_b),
        Some(&3),
        "case B must be reported with its own three artifacts, got {:?}",
        totals
    );
}

/// A module that declines every input.
struct DecliningModule;

impl ForensicsModule for DecliningModule {
    fn id(&self) -> &str {
        "module.decliner"
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
    fn process(&self, _artifact: &Artifact) -> anyhow::Result<Vec<Artifact>, ModuleError> {
        Err(ModuleError::InvalidInputFormat("not a thing I read".into()))
    }
}

/// A module that ran and declined its input is not a module that ran and found
/// nothing: the job completes, but says why it produced nothing.
#[tokio::test]
async fn an_ad_hoc_job_whose_module_declined_the_input_says_so() {
    let db = Arc::new(MockDatabase::new());
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let (case_id, artifact_id, job_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    db.record_artifact(&Artifact {
        id: artifact_id,
        case_id,
        artifact_type: ArtifactType::RawEvidence,
        parent_id: None,
        data: None,
        metadata: serde_json::json!({}),
    })
    .await
    .unwrap();
    db.update_job(&AdHocJob {
        id: job_id,
        case_id,
        module_id: "module.decliner".to_string(),
        target_artifact_id: artifact_id,
        status: JobStatus::Pending,
        artifacts_produced: 0,
        error_message: None,
        created_at: 0,
        completed_at: None,
    })
    .await
    .unwrap();
    orchestrator.register_module(Arc::new(DecliningModule));
    let submitter = orchestrator.ad_hoc_submitter();
    let runner = tokio::spawn(orchestrator.run());
    submitter
        .send(AdHocRequest {
            job_id,
            case_id,
            artifact_id,
            module_id: "module.decliner".to_string(),
            data_source: None,
            credential: None,
        })
        .await
        .unwrap();

    let job = wait_for_terminal_job(&db, job_id).await;
    assert_eq!(job.status, JobStatus::Complete);
    assert_eq!(job.artifacts_produced, 0);
    let message = job.error_message.expect("a decline must be explained");
    assert!(
        message.starts_with("module declined this input"),
        "{message}"
    );
    assert!(message.contains("not a thing I read"), "{message}");
    runner.abort();
}

/// A module that produces one child artifact.
struct ChildProducer;

impl ForensicsModule for ChildProducer {
    fn id(&self) -> &str {
        "module.child"
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
    fn process(&self, artifact: &Artifact) -> anyhow::Result<Vec<Artifact>, ModuleError> {
        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::json!({"from": "ad hoc"}),
        )
        .with_parent(artifact.id)])
    }
}

/// When the job row cannot be found after the module ran, what the module
/// produced is still recorded and the completion is still announced.
#[tokio::test]
async fn an_ad_hoc_run_is_recorded_even_when_its_job_row_is_missing() {
    let db = Arc::new(MockDatabase::new());
    let mut orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let (case_id, artifact_id, job_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    db.record_artifact(&Artifact {
        id: artifact_id,
        case_id,
        artifact_type: ArtifactType::RawEvidence,
        parent_id: None,
        data: None,
        metadata: serde_json::json!({}),
    })
    .await
    .unwrap();
    // No job row is created.
    orchestrator.register_module(Arc::new(ChildProducer));
    let mut status_rx = orchestrator.status_sender().subscribe();
    let submitter = orchestrator.ad_hoc_submitter();
    let runner = tokio::spawn(orchestrator.run());
    submitter
        .send(AdHocRequest {
            job_id,
            case_id,
            artifact_id,
            module_id: "module.child".to_string(),
            data_source: None,
            credential: None,
        })
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(OrchestratorEvent::ModuleCompleted { module_id, .. }) = status_rx.recv().await
            {
                if module_id == "module.child" {
                    break;
                }
            }
        }
    })
    .await
    .expect("ModuleCompleted must be emitted though the job row is missing");
    let stored = db.artifacts.lock().unwrap();
    assert!(
        stored
            .values()
            .any(|a| a.metadata.get("from") == Some(&serde_json::json!("ad hoc"))),
        "the produced artifact must be recorded"
    );
    drop(stored);
    runner.abort();
}
