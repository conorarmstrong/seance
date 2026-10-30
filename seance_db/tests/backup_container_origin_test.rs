//! `find_backup_container_origin` resolves a container by NAME, so it must
//! refuse to answer when the name does not pin one origin, rather than hand
//! back whichever same-named row SQLite visited first.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Backups", "Examiner").await?;
    Ok((db, case_id))
}

async fn add_container(
    db: &SqliteConnection,
    case_id: Uuid,
    name: &str,
    relative_path: &str,
) -> Result<()> {
    let a = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": name,
            "domain": "AppDomainGroup-group.net.whatsapp.WhatsApp.shared",
            "relative_path": relative_path,
        }),
    );
    db.record_artifact(&a).await
}

#[tokio::test]
async fn a_name_that_pins_one_origin_resolves_it() -> Result<()> {
    let (db, case_id) = setup().await?;
    add_container(&db, case_id, "WhatsApp media.zip", "Message/Media/alice/x").await?;

    let origin = db
        .find_backup_container_origin(case_id, "WhatsApp media.zip")
        .await?
        .expect("one container carries the name");
    assert_eq!(origin["relative_path"], "Message/Media/alice/x");

    assert!(db
        .find_backup_container_origin(case_id, "no such file.zip")
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn two_backups_with_the_same_name_and_different_origins_are_ambiguous() -> Result<()> {
    let (db, case_id) = setup().await?;
    add_container(&db, case_id, "WhatsApp media.zip", "Message/Media/alice/x").await?;
    add_container(&db, case_id, "WhatsApp media.zip", "Message/Media/bob/y").await?;

    let err = db
        .find_backup_container_origin(case_id, "WhatsApp media.zip")
        .await
        .expect_err("two different origins must not resolve to either one");
    assert!(err.to_string().contains("different origins"), "{err}");
    Ok(())
}

#[tokio::test]
async fn same_name_with_identical_origin_is_not_ambiguous() -> Result<()> {
    let (db, case_id) = setup().await?;
    add_container(&db, case_id, "WhatsApp media.zip", "Message/Media/alice/x").await?;
    add_container(&db, case_id, "WhatsApp media.zip", "Message/Media/alice/x").await?;

    assert!(db
        .find_backup_container_origin(case_id, "WhatsApp media.zip")
        .await?
        .is_some());
    Ok(())
}
