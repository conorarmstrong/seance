//! A statement a later run answered must stop counting as missing data.
//!
//! An encrypted iOS backup ingested without a password records, correctly, that
//! no files from it are in the case — with the incompleteness pair that puts it
//! in the report's "not recovered" section. Supplying the password is the action
//! that record asks for; it produced 15,972 artifacts and left the sentence
//! standing, so a census taken afterwards still counted the backup among the
//! evidence that was never recovered (HUNT-090).
//!
//! The earlier record is marked, never deleted: that the refusal happened is
//! itself part of the case. What changes is which statement the census reads.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

async fn record(
    db: &SqliteConnection,
    case_id: Uuid,
    parent: Uuid,
    metadata: serde_json::Value,
) -> Result<Uuid> {
    let art =
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent);
    db.record_artifact(&art).await?;
    Ok(art.id)
}

fn locked() -> serde_json::Value {
    json!({
        "type": "IosBackupInfo",
        "status": "encrypted_no_password",
        "content_incomplete": true,
        "content_incomplete_reason": "encrypted",
        "inventory_incomplete": true,
        "inventory_incomplete_reason": "encrypted",
    })
}

#[tokio::test]
async fn a_superseded_statement_leaves_the_census_and_is_still_counted() -> Result<()> {
    let db = db().await?;
    let case_id = db.create_case("Supersession", "Examiner").await?;
    let backup = Uuid::new_v4();
    let root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"name": "backup", "is_directory": true}),
    );
    let root = Artifact { id: backup, ..root };
    db.record_artifact(&root).await?;

    let stale = record(&db, case_id, backup, locked()).await?;

    let before = db.get_case_incompleteness(case_id).await?;
    assert_eq!(before.content_incomplete, 1);
    assert_eq!(before.inventory_incomplete, 1);
    assert_eq!(before.superseded, 0);

    // The run that decrypts emits its own record and supersedes the refusal.
    let answer = record(
        &db,
        case_id,
        backup,
        json!({
            "type": "IosBackupInfo",
            "status": "decrypted",
            "supersedes_status": "encrypted_no_password",
        }),
    )
    .await?;
    let marked = db
        .mark_records_superseded(
            case_id,
            backup,
            "IosBackupInfo",
            "status",
            "encrypted_no_password",
            answer,
        )
        .await?;
    assert_eq!(marked, 1);

    let after = db.get_case_incompleteness(case_id).await?;
    assert_eq!(
        after.content_incomplete, 0,
        "a backup this case holds the files of is not evidence that was not recovered"
    );
    assert_eq!(after.inventory_incomplete, 0);
    assert_eq!(
        after.superseded, 1,
        "the exclusion must be stated, not silently applied"
    );
    assert!(!after.any());

    // Marked, not deleted: the refusal is still in the case, and still says
    // what it said.
    let kept = db.get_artifact(stale).await?.expect("the record is kept");
    assert_eq!(kept.metadata["status"], "encrypted_no_password");
    assert_eq!(kept.metadata["content_incomplete"], json!(true));
    assert_eq!(kept.metadata["superseded"], json!(true));
    assert_eq!(kept.metadata["superseded_by"], json!(answer.to_string()));
    assert!(kept.metadata.get("superseded_at").is_some());

    Ok(())
}

#[tokio::test]
async fn one_backups_password_does_not_answer_another_backup() -> Result<()> {
    let db = db().await?;
    let case_id = db.create_case("Two phones", "Examiner").await?;

    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    for parent in [first, second] {
        let root = Artifact::new(
            case_id,
            ArtifactType::RawEvidence,
            None,
            json!({"name": "backup", "is_directory": true}),
        );
        db.record_artifact(&Artifact { id: parent, ..root }).await?;
        record(&db, case_id, parent, locked()).await?;
    }

    let answer = record(
        &db,
        case_id,
        first,
        json!({"type": "IosBackupInfo", "status": "decrypted"}),
    )
    .await?;
    let marked = db
        .mark_records_superseded(
            case_id,
            first,
            "IosBackupInfo",
            "status",
            "encrypted_no_password",
            answer,
        )
        .await?;

    assert_eq!(marked, 1, "only the backup that was opened is answered");
    let census = db.get_case_incompleteness(case_id).await?;
    assert_eq!(
        census.content_incomplete, 1,
        "the second phone is still locked and must still be reported as such"
    );
    assert_eq!(census.superseded, 1);
    Ok(())
}

/// The memory stages record their state in `analysis_stage`, not `status`: a
/// symbol pack that arrives after the first pass is the case HUNT-090 named,
/// and a matcher that only ever looked at `status` could not answer it.
#[tokio::test]
async fn a_record_can_name_the_field_its_state_lives_in() -> Result<()> {
    let db = db().await?;
    let case_id = db.create_case("Memory", "Examiner").await?;
    let image = Uuid::new_v4();
    let root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"name": "memdump.mem"}),
    );
    db.record_artifact(&Artifact { id: image, ..root }).await?;

    let failed = record(
        &db,
        case_id,
        image,
        json!({
            "type": "MemoryProfile",
            "analysis_stage": "discovery_failed",
            "failure": "no symbol file matches the kernel",
        }),
    )
    .await?;

    let analysed = record(
        &db,
        case_id,
        image,
        json!({
            "type": "MemoryProfile",
            "analysis_stage": "analysed",
            "supersedes_status": "discovery_failed",
            "supersedes_field": "analysis_stage",
        }),
    )
    .await?;

    let marked = db
        .mark_records_superseded(
            case_id,
            image,
            "MemoryProfile",
            "analysis_stage",
            "discovery_failed",
            analysed,
        )
        .await?;
    assert_eq!(marked, 1);

    let kept = db.get_artifact(failed).await?.expect("kept, not deleted");
    assert_eq!(kept.metadata["superseded"], json!(true));
    assert_eq!(kept.metadata["analysis_stage"], "discovery_failed");
    Ok(())
}
