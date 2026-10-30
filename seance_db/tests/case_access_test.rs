//! Unit tests for per-case access control (multi-user v1.0) and the rounded-out
//! user-management DB methods (get_user_by_id / update_user_role / delete_user).

use anyhow::Result;
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use uuid::Uuid;

async fn setup() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

async fn make_case(db: &SqliteConnection) -> Result<Uuid> {
    db.create_case_with_metadata(Some("Case".to_string()), None, Some("Ex".to_string()))
        .await
}

#[tokio::test]
async fn grant_and_check_access_roundtrip() -> Result<()> {
    let db = setup().await?;
    let case = make_case(&db).await?;
    let user = db.create_user("erin", "h", "examiner").await?;

    // No grant yet.
    assert!(!db.user_can_access_case(user, case).await?);

    db.grant_case_access(case, user, "read_write", None).await?;
    assert!(db.user_can_access_case(user, case).await?);
    Ok(())
}

#[tokio::test]
async fn grant_is_idempotent_and_updates_level() -> Result<()> {
    let db = setup().await?;
    let case = make_case(&db).await?;
    let owner = db.create_user("o", "h", "examiner").await?;

    db.grant_case_access(case, owner, "read_only", None).await?;
    db.grant_case_access(case, owner, "owner", Some(owner))
        .await?;

    let access = db.list_case_access(case).await?;
    assert_eq!(access.len(), 1, "re-grant must upsert, not duplicate");
    assert_eq!(
        access[0].2, "owner",
        "level must be updated to the latest grant"
    );
    Ok(())
}

#[tokio::test]
async fn revoke_removes_access_and_reports_existence() -> Result<()> {
    let db = setup().await?;
    let case = make_case(&db).await?;
    let user = db.create_user("erin", "h", "examiner").await?;
    db.grant_case_access(case, user, "read_write", None).await?;

    assert!(
        db.revoke_case_access(case, user).await?,
        "existing grant removed"
    );
    assert!(!db.user_can_access_case(user, case).await?);
    // Revoking a non-existent grant reports no row removed.
    assert!(!db.revoke_case_access(case, user).await?);
    Ok(())
}

#[tokio::test]
async fn list_accessible_case_ids_is_scoped_per_user() -> Result<()> {
    let db = setup().await?;
    let c1 = make_case(&db).await?;
    let c2 = make_case(&db).await?;
    let erin = db.create_user("erin", "h", "examiner").await?;
    let dana = db.create_user("dana", "h", "examiner").await?;
    db.grant_case_access(c1, erin, "read_write", None).await?;
    db.grant_case_access(c2, dana, "read_write", None).await?;

    assert_eq!(db.list_accessible_case_ids(erin).await?, vec![c1]);
    assert_eq!(db.list_accessible_case_ids(dana).await?, vec![c2]);
    // A user with no grants sees nothing.
    let nobody = db.create_user("nobody", "h", "examiner").await?;
    assert!(db.list_accessible_case_ids(nobody).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn list_case_access_joins_username() -> Result<()> {
    let db = setup().await?;
    let case = make_case(&db).await?;
    let erin = db.create_user("erin", "h", "examiner").await?;
    db.grant_case_access(case, erin, "owner", Some(erin))
        .await?;

    let access = db.list_case_access(case).await?;
    assert_eq!(access.len(), 1);
    assert_eq!(access[0].0, erin);
    assert_eq!(access[0].1, "erin");
    assert_eq!(access[0].2, "owner");
    Ok(())
}

#[tokio::test]
async fn invalid_access_level_rejected_by_check_constraint() -> Result<()> {
    let db = setup().await?;
    let case = make_case(&db).await?;
    let erin = db.create_user("erin", "h", "examiner").await?;
    assert!(
        db.grant_case_access(case, erin, "superuser", None)
            .await
            .is_err(),
        "access_level CHECK constraint must reject values outside the enum"
    );
    Ok(())
}

#[tokio::test]
async fn deleting_case_cascades_access() -> Result<()> {
    let db = setup().await?;
    let case = make_case(&db).await?;
    let erin = db.create_user("erin", "h", "examiner").await?;
    db.grant_case_access(case, erin, "read_write", None).await?;

    db.delete_case(case).await?;
    // FK (case_id) ON DELETE CASCADE removed the grant.
    assert!(db.list_accessible_case_ids(erin).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn deleting_user_cascades_access() -> Result<()> {
    let db = setup().await?;
    let case = make_case(&db).await?;
    let erin = db.create_user("erin", "h", "examiner").await?;
    db.grant_case_access(case, erin, "read_write", None).await?;

    assert!(db.delete_user(erin).await?);
    // FK (user_id) ON DELETE CASCADE removed the grant.
    assert!(db.list_case_access(case).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn get_user_by_id_and_update_role() -> Result<()> {
    let db = setup().await?;
    let id = db.create_user("erin", "h", "examiner").await?;

    assert_eq!(db.get_user_by_id(id).await?.unwrap().role, "examiner");
    assert!(db.update_user_role(id, "admin").await?);
    assert_eq!(db.get_user_by_id(id).await?.unwrap().role, "admin");

    // Unknown id reports no row updated / no user.
    assert!(!db.update_user_role(Uuid::new_v4(), "admin").await?);
    assert!(db.get_user_by_id(Uuid::new_v4()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn update_user_role_rejects_invalid_role() -> Result<()> {
    let db = setup().await?;
    let id = db.create_user("erin", "h", "examiner").await?;
    // CHECK constraint on users.role rejects anything outside admin/examiner.
    assert!(db.update_user_role(id, "superuser").await.is_err());
    Ok(())
}
