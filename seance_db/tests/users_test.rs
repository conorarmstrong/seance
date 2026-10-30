//! Unit tests for the multi-user (RBAC) DB methods.

use anyhow::Result;
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;

async fn setup_test_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

#[tokio::test]
async fn create_and_fetch_user_roundtrip() -> Result<()> {
    let db = setup_test_db().await?;
    let id = db.create_user("erin", "hash-abc", "examiner").await?;

    let user = db
        .get_user_by_username("erin")
        .await?
        .expect("user should exist");
    assert_eq!(user.id, id);
    assert_eq!(user.username, "erin");
    assert_eq!(user.password_hash, "hash-abc");
    assert_eq!(user.role, "examiner");
    assert!(user.active, "new users are active by default");
    Ok(())
}

#[tokio::test]
async fn get_unknown_user_returns_none() -> Result<()> {
    let db = setup_test_db().await?;
    assert!(db.get_user_by_username("nobody").await?.is_none());
    Ok(())
}

#[tokio::test]
async fn count_users_tracks_inserts() -> Result<()> {
    let db = setup_test_db().await?;
    assert_eq!(db.count_users().await?, 0);
    db.create_user("a", "h", "admin").await?;
    db.create_user("b", "h", "examiner").await?;
    assert_eq!(db.count_users().await?, 2);
    Ok(())
}

#[tokio::test]
async fn duplicate_username_is_rejected() -> Result<()> {
    let db = setup_test_db().await?;
    db.create_user("erin", "h", "examiner").await?;
    // UNIQUE(username) constraint must reject the second insert.
    assert!(db.create_user("erin", "h2", "admin").await.is_err());
    Ok(())
}

#[tokio::test]
async fn invalid_role_is_rejected_by_check_constraint() -> Result<()> {
    let db = setup_test_db().await?;
    assert!(
        db.create_user("erin", "h", "superuser").await.is_err(),
        "role CHECK constraint must reject values outside admin/examiner"
    );
    Ok(())
}

#[tokio::test]
async fn set_user_active_toggles_and_reports_existence() -> Result<()> {
    let db = setup_test_db().await?;
    let id = db.create_user("erin", "h", "examiner").await?;

    assert!(
        db.set_user_active(id, false).await?,
        "existing user updated"
    );
    let user = db.get_user_by_username("erin").await?.unwrap();
    assert!(!user.active);

    assert!(db.set_user_active(id, true).await?);
    assert!(db.get_user_by_username("erin").await?.unwrap().active);

    // Unknown id reports no row updated.
    assert!(!db.set_user_active(uuid::Uuid::new_v4(), false).await?);
    Ok(())
}

#[tokio::test]
async fn update_user_password_changes_hash() -> Result<()> {
    let db = setup_test_db().await?;
    let id = db.create_user("erin", "old-hash", "examiner").await?;

    assert!(db.update_user_password(id, "new-hash").await?);
    assert_eq!(
        db.get_user_by_username("erin")
            .await?
            .unwrap()
            .password_hash,
        "new-hash"
    );

    // Unknown id reports no row updated.
    assert!(!db.update_user_password(uuid::Uuid::new_v4(), "x").await?);
    Ok(())
}

#[tokio::test]
async fn list_users_returns_all_sorted() -> Result<()> {
    let db = setup_test_db().await?;
    db.create_user("carol", "h", "examiner").await?;
    db.create_user("alice", "h", "admin").await?;
    db.create_user("bob", "h", "examiner").await?;

    let users = db.list_users().await?;
    let names: Vec<&str> = users.iter().map(|u| u.username.as_str()).collect();
    assert_eq!(names, vec!["alice", "bob", "carol"]);
    Ok(())
}

#[tokio::test]
async fn changing_password_stamps_password_changed_at() -> Result<()> {
    // BUG-076: update_user_password must record when the password changed so the
    // auth middleware can invalidate tokens issued before it.
    let db = setup_test_db().await?;
    let id = db.create_user("erin", "old-hash", "examiner").await?;

    let before = db.get_user_by_username("erin").await?.unwrap();
    assert_eq!(
        before.password_changed_at, 0,
        "a freshly created user has no recorded password change"
    );

    assert!(db.update_user_password(id, "new-hash").await?);

    let after = db.get_user_by_username("erin").await?.unwrap();
    assert!(
        after.password_changed_at > 0,
        "changing the password must stamp password_changed_at"
    );
    Ok(())
}
