//! A record that answers an earlier statement (`supersedes_status`) is honoured
//! in the automatic pipeline too, not only in an ad-hoc re-run.
//!
//! The case that needs it (ROADMAP §5.7): a WhatsApp `crypt14` backup is read
//! before the key file that opens it, so the module first files "awaiting the
//! key" under the backup, and later — while processing the key, in the same
//! automatic ingest — files the decrypted answer under the same backup. Unless
//! the answer marks the earlier statement superseded, the census goes on
//! counting a decrypted backup as missing data.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::Orchestrator,
};
use seance_db::SqliteConnection;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Files "awaiting" under a `backup` entry, and the answer under the backup
/// the `key` entry names.
struct PairingModule;

impl ForensicsModule for PairingModule {
    fn id(&self) -> &str {
        "plugin.test.pairing"
    }
    fn version(&self) -> &str {
        "test"
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact.metadata["name"].as_str().unwrap_or_default();
        let record = |parent: Uuid, meta: serde_json::Value| {
            Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
                .with_parent(parent)
        };
        Ok(match name {
            "backup" => vec![record(
                artifact.id,
                json!({"type": "PairedBackup", "status": "AwaitingKey",
                       "content_incomplete": true, "content_incomplete_reason": "encrypted"}),
            )],
            "key" => {
                let backup: Uuid = artifact.metadata["pairs_with"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .expect("the key names its backup");
                vec![record(
                    backup,
                    json!({"type": "PairedBackup", "status": "Decrypted",
                           "supersedes_status": "AwaitingKey"}),
                )]
            }
            _ => Vec::new(),
        })
    }
}

#[tokio::test]
async fn an_answer_filed_during_ingest_supersedes_the_earlier_statement() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("case.db");
    let db = Arc::new(
        SqliteConnection::new(&format!("sqlite:{}?mode=rwc", db_path.display()))
            .await
            .unwrap(),
    );
    db.initialize().await.unwrap();
    let case_id = db.create_case("Pairing", "Examiner").await.unwrap();

    let backup = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "backup"}),
    );
    let key = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "key", "pairs_with": backup.id.to_string()}),
    );
    db.record_artifact(&backup).await.unwrap();
    db.record_artifact(&key).await.unwrap();

    let mut orchestrator = Orchestrator::new(Some(db.clone() as Arc<dyn DatabaseConnection>), 64)
        .with_worker_count(1)
        .with_exit_on_idle(true);
    orchestrator.register_module(Arc::new(PairingModule));
    let sender = orchestrator.task_submitter();
    sender.send(backup.clone()).unwrap();
    sender.send(key.clone()).unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::spawn(orchestrator.run()),
    )
    .await
    .expect("the orchestrator idles out")
    .expect("the run does not panic");

    let children = db
        .get_child_artifacts(case_id, Some(backup.id), Some(50), 0)
        .await
        .unwrap();
    let status_of = |status: &str| {
        children
            .items
            .iter()
            .find(|a| a.metadata["status"] == status)
            .unwrap_or_else(|| panic!("a {status} record under the backup"))
            .clone()
    };
    let awaiting = status_of("AwaitingKey");
    let decrypted = status_of("Decrypted");
    assert_eq!(
        awaiting
            .metadata
            .get("superseded")
            .and_then(|v| v.as_bool()),
        Some(true),
        "the awaiting statement is superseded by the answer filed in the same ingest"
    );
    assert_eq!(
        awaiting.metadata["superseded_by"],
        json!(decrypted.id.to_string())
    );
    assert!(
        decrypted.metadata.get("superseded").is_none(),
        "the answer itself stands"
    );
}
