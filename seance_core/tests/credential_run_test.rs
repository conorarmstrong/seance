//! HUNT-120: an examiner-supplied credential reaches the module for one run,
//! and what the module does with it decides what the case records.
//!
//! A mock "volume decryptor" stands in for BitLocker/LUKS/7z/Signal (each has
//! its own test on real bytes); what is under test here is the orchestrator's
//! half: the credential is visible only to the one `process` call on the one
//! artifact, a rejected secret leaves the locked record standing and records
//! nothing new, an accepted one supersedes it, both outcomes reach the audit
//! log by kind, and the secret is nowhere in the database file afterwards.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    credential::{self, CredentialKind, RunCredential},
    db::DatabaseConnection,
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::Orchestrator,
    profile::{AdHocJob, AdHocRequest, JobStatus},
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const MODULE_ID: &str = "plugin.crypto.luks_decryptor";
const RIGHT: &str = "right-horse-battery-7731";
const WRONG: &str = "wrong-horse-battery-9914";

/// Reads the credential exactly as the real decryptors do, and reports.
struct MockDecryptor;

impl ForensicsModule for MockDecryptor {
    fn id(&self) -> &str {
        MODULE_ID
    }
    fn version(&self) -> &str {
        "test"
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Partition]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let locked = |status: &str| {
            Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "VolumeDecryption",
                    "status": status,
                    "scheme": "LUKS",
                    "content_incomplete": true,
                    "content_incomplete_reason": "encrypted",
                }),
            )
            .with_parent(artifact.id)
        };
        let Some(cred) = credential::for_artifact(artifact.id, &[CredentialKind::LuksPassphrase])
        else {
            return Ok(vec![locked("NotUnlocked")]);
        };
        if cred.expose_secret() == RIGHT {
            cred.accepted();
            Ok(vec![
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::Partition,
                    None,
                    json!({"name": "vol (LUKS decrypted)", "luks_decrypted": true}),
                )
                .with_parent(artifact.id),
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({"type": "VolumeDecryption", "status": "Unlocked", "scheme": "LUKS"}),
                )
                .with_parent(artifact.id),
            ])
        } else {
            cred.rejected("no keyslot could be unlocked with the supplied passphrase");
            Ok(vec![locked("UnlockFailed")])
        }
    }
}

struct Case {
    db: Arc<SqliteConnection>,
    db_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
    case_id: Uuid,
    volume: Uuid,
    locked: Uuid,
    submit: tokio::sync::mpsc::Sender<AdHocRequest>,
    runner: tokio::task::JoinHandle<()>,
}

async fn case() -> Case {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("case.db");
    let db = Arc::new(
        SqliteConnection::new(&format!("sqlite:{}?mode=rwc", db_path.display()))
            .await
            .unwrap(),
    );
    db.initialize().await.unwrap();
    let case_id = db.create_case("Credential", "Examiner").await.unwrap();

    let volume = Artifact::new(
        case_id,
        ArtifactType::Partition,
        None,
        json!({"name": "vol", "offset_bytes": 0, "size_bytes": 1024}),
    );
    db.record_artifact(&volume).await.unwrap();
    let locked = MockDecryptor.process(&volume).unwrap().remove(0);
    db.record_artifact(&locked).await.unwrap();
    // The supersession compares creation times; the re-run must come after.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut orchestrator = Orchestrator::new(Some(db.clone() as Arc<dyn DatabaseConnection>), 64);
    orchestrator.register_module(Arc::new(MockDecryptor));
    let submit = orchestrator.ad_hoc_submitter();
    let runner = tokio::spawn(async move { orchestrator.run().await });
    Case {
        db,
        db_path,
        _dir: dir,
        case_id,
        volume: volume.id,
        locked: locked.id,
        submit,
        runner,
    }
}

async fn run_with(c: &Case, secret: &str) -> AdHocJob {
    let cred = Arc::new(RunCredential::new(
        c.volume,
        CredentialKind::LuksPassphrase,
        secret.to_string(),
        "erin",
    ));
    let request =
        AdHocRequest::new(c.case_id, MODULE_ID.to_string(), c.volume).with_credential(cred);
    let job = AdHocJob::new(&request);
    c.db.create_job(&job).await.unwrap();
    c.submit.send(request).await.unwrap();
    for _ in 0..200 {
        let j = c.db.get_job(job.id).await.unwrap().unwrap();
        if matches!(j.status, JobStatus::Complete | JobStatus::Failed) {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the credential job never finished");
}

async fn superseded(c: &Case, id: Uuid) -> bool {
    let a = c.db.get_artifact(id).await.unwrap().unwrap();
    a.metadata.get("superseded").and_then(|v| v.as_bool()) == Some(true)
}

async fn children_of_volume(c: &Case) -> usize {
    c.db.count_child_artifacts(c.volume).await.unwrap() as usize
}

#[tokio::test]
async fn a_wrong_secret_changes_nothing_and_a_right_one_supersedes_the_locked_record() {
    let c = case().await;
    assert_eq!(children_of_volume(&c).await, 1);

    // Wrong: the job fails, nothing new is recorded, the locked record stands.
    let job = run_with(&c, WRONG).await;
    assert_eq!(job.status, JobStatus::Failed);
    let msg = job.error_message.clone().unwrap();
    assert!(msg.contains("did not open this artifact"), "{msg}");
    assert!(msg.contains("still stands"), "{msg}");
    assert!(!msg.contains(WRONG));
    assert!(
        !superseded(&c, c.locked).await,
        "a wrong secret must not supersede"
    );
    assert_eq!(
        children_of_volume(&c).await,
        1,
        "a wrong secret's own 'unlock failed' record is not persisted"
    );

    // Right: the decrypted volume appears beneath, the locked record is superseded.
    let job = run_with(&c, RIGHT).await;
    assert_eq!(job.status, JobStatus::Complete, "{:?}", job.error_message);
    assert!(
        superseded(&c, c.locked).await,
        "the locked record must be superseded"
    );
    assert_eq!(children_of_volume(&c).await, 3);

    // The audit log: both attempts, by kind and outcome, never by value.
    let audit = c.db.get_audit_log(c.case_id, 100, 0).await.unwrap();
    let outcomes: Vec<String> = audit
        .iter()
        .filter(|e| e["action"] == json!("credential_outcome"))
        .map(|e| e["details"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(outcomes.len(), 2, "{audit:?}");
    assert!(outcomes.iter().any(|d| d.contains("outcome=rejected")));
    assert!(outcomes.iter().any(|d| d.contains("outcome=accepted")));
    assert!(outcomes.iter().all(|d| d.contains("kind=luks_passphrase")));
    assert!(audit
        .iter()
        .all(|e| e["user_id"] == json!("erin") || e["action"] != json!("credential_outcome")));

    // Neither secret is anywhere in the database, its WAL or its shm.
    c.runner.abort();
    let _ = c.runner.await;
    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{}", c.db_path.display(), suffix);
        if let Ok(bytes) = std::fs::read(&path) {
            for secret in [RIGHT, WRONG] {
                assert!(
                    !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "{secret} was written to {path}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_credential_bound_to_another_artifact_is_refused() {
    let c = case().await;
    let cred = Arc::new(RunCredential::new(
        Uuid::new_v4(),
        CredentialKind::LuksPassphrase,
        RIGHT.to_string(),
        "erin",
    ));
    let request =
        AdHocRequest::new(c.case_id, MODULE_ID.to_string(), c.volume).with_credential(cred);
    let job = AdHocJob::new(&request);
    c.db.create_job(&job).await.unwrap();
    c.submit.send(request).await.unwrap();
    let mut done = None;
    for _ in 0..200 {
        let j = c.db.get_job(job.id).await.unwrap().unwrap();
        if matches!(j.status, JobStatus::Complete | JobStatus::Failed) {
            done = Some(j);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let job = done.expect("job finished");
    assert_eq!(job.status, JobStatus::Failed);
    assert!(!superseded(&c, c.locked).await);
    assert_eq!(children_of_volume(&c).await, 1);
    c.runner.abort();
}
