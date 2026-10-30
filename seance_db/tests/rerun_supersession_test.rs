//! Running a module again must not leave the case holding both answers.
//!
//! Re-running a parser is an ordinary act of examination: a mailbox splitter is
//! fixed, a password arrives, a symbol pack is fetched. Before this, the second
//! run's records simply landed beside the first run's, with nothing on either
//! saying which run wrote it — the Magnet 2022 Linux mailbox held 4 messages
//! from the old parse and 49 from the new, 53 in total, and a report drawn from
//! that case would have said 53 (HUNT-107).
//!
//! The earlier records are marked, never deleted: that the first run said what
//! it said is part of the examination's history. What changes is which
//! statement is current.

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

async fn superseded(db: &SqliteConnection, case_id: Uuid, id: Uuid) -> Result<bool> {
    let art = db.get_artifact_details(case_id, id).await?;
    Ok(art.metadata.get("superseded").and_then(|v| v.as_bool()) == Some(true))
}

#[tokio::test]
async fn a_second_run_supersedes_what_the_first_run_said() -> Result<()> {
    let db = db().await?;
    let case_id = db.create_case("Re-run", "Examiner").await?;
    let mailbox = Uuid::new_v4();
    let root = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "INBOX"}),
    );
    let root = Artifact {
        id: mailbox,
        ..root
    };
    db.record_artifact(&root).await?;

    let first = record(
        &db,
        case_id,
        mailbox,
        json!({"type": "EmailMessage", "subject": "read by the old parser"}),
    )
    .await?;
    // A record of another kind under the same parent, written by another
    // module: a re-run of the mail parser says nothing about it.
    let other = record(
        &db,
        case_id,
        mailbox,
        json!({"type": "FileSignatureAnalysis", "filename": "INBOX"}),
    )
    .await?;

    let run_started = chrono::Utc::now().to_rfc3339();
    let second = record(
        &db,
        case_id,
        mailbox,
        json!({"type": "EmailMessage", "subject": "read by the fixed parser"}),
    )
    .await?;

    let marked = db
        .supersede_records_from_an_earlier_run(
            case_id,
            mailbox,
            "type",
            "EmailMessage",
            &run_started,
            second,
            "plugin.email.parser",
        )
        .await?;
    assert_eq!(marked, 1, "only the earlier record of this kind is marked");

    assert!(superseded(&db, case_id, first).await?);
    assert!(
        !superseded(&db, case_id, second).await?,
        "this run's own record is current"
    );
    assert!(
        !superseded(&db, case_id, other).await?,
        "a record another module wrote is not this module's to supersede"
    );

    let stale = db.get_artifact_details(case_id, first).await?;
    assert_eq!(stale.metadata["superseded_by"], second.to_string());
    assert_eq!(
        stale.metadata["superseded_reason"],
        "plugin.email.parser was run again on this artifact"
    );
    Ok(())
}

#[tokio::test]
async fn a_record_already_superseded_is_not_marked_twice() -> Result<()> {
    let db = db().await?;
    let case_id = db.create_case("Re-run", "Examiner").await?;
    let mailbox = Uuid::new_v4();
    let root = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "INBOX"}),
    );
    let root = Artifact {
        id: mailbox,
        ..root
    };
    db.record_artifact(&root).await?;
    let first = record(
        &db,
        case_id,
        mailbox,
        json!({"type": "EmailMessage", "subject": "first"}),
    )
    .await?;

    let run_started = chrono::Utc::now().to_rfc3339();
    let second = record(
        &db,
        case_id,
        mailbox,
        json!({"type": "EmailMessage", "subject": "second"}),
    )
    .await?;
    db.supersede_records_from_an_earlier_run(
        case_id,
        mailbox,
        "type",
        "EmailMessage",
        &run_started,
        second,
        "plugin.email.parser",
    )
    .await?;

    let later_started = chrono::Utc::now().to_rfc3339();
    let third = record(
        &db,
        case_id,
        mailbox,
        json!({"type": "EmailMessage", "subject": "third"}),
    )
    .await?;
    let marked = db
        .supersede_records_from_an_earlier_run(
            case_id,
            mailbox,
            "type",
            "EmailMessage",
            &later_started,
            third,
            "plugin.email.parser",
        )
        .await?;
    assert_eq!(
        marked, 1,
        "the run before this one is marked; the one already marked is left as it was"
    );
    let stale = db.get_artifact_details(case_id, first).await?;
    assert_eq!(
        stale.metadata["superseded_by"],
        second.to_string(),
        "the first record still names the run that answered it"
    );
    Ok(())
}

#[tokio::test]
async fn a_timeline_event_is_matched_by_the_module_that_wrote_it() -> Result<()> {
    // Timeline events carry no record `type`; what tells one module's events
    // from another's is `source_module`.
    let db = db().await?;
    let case_id = db.create_case("Re-run", "Examiner").await?;
    let mailbox = Uuid::new_v4();
    let root = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "INBOX"}),
    );
    let root = Artifact {
        id: mailbox,
        ..root
    };
    db.record_artifact(&root).await?;

    let old_event = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({"timestamp": "2022-02-02T00:00:00+00:00", "source_module": "plugin.email.parser"}),
    )
    .with_parent(mailbox);
    db.record_artifact(&old_event).await?;
    let other_event = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({"timestamp": "2022-02-02T00:00:00+00:00", "source_module": "plugin.exif"}),
    )
    .with_parent(mailbox);
    db.record_artifact(&other_event).await?;

    let run_started = chrono::Utc::now().to_rfc3339();
    let new_event = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({"timestamp": "2022-02-02T00:00:00+00:00", "source_module": "plugin.email.parser"}),
    )
    .with_parent(mailbox);
    db.record_artifact(&new_event).await?;

    let marked = db
        .supersede_records_from_an_earlier_run(
            case_id,
            mailbox,
            "source_module",
            "plugin.email.parser",
            &run_started,
            new_event.id,
            "plugin.email.parser",
        )
        .await?;
    assert_eq!(marked, 1);
    assert!(superseded(&db, case_id, old_event.id).await?);
    assert!(!superseded(&db, case_id, other_event.id).await?);
    Ok(())
}
