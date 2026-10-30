//! Tests for server-side audit log filtering
//! (get_audit_log_filtered / get_audit_log_count_filtered).

mod common;

use anyhow::Result;
use common::file_db;
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;

async fn setup_test_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

#[tokio::test]
async fn audit_log_filters_by_user_action_and_resource_type() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    db.record_audit_event(
        Some(case_id),
        "alice",
        "case.view",
        Some("case"),
        Some(case_id),
        None,
    )
    .await?;
    db.record_audit_event(
        Some(case_id),
        "bob",
        "case.view",
        Some("case"),
        Some(case_id),
        None,
    )
    .await?;
    db.record_audit_event(
        Some(case_id),
        "alice",
        "artifact.delete",
        Some("artifact"),
        None,
        Some("cleanup"),
    )
    .await?;

    // user_id
    let rows = db
        .get_audit_log_filtered(case_id, Some("alice"), None, None, None, None, 100, 0)
        .await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r["user_id"] == "alice"));
    let count = db
        .get_audit_log_count_filtered(case_id, Some("alice"), None, None, None, None)
        .await?;
    assert_eq!(count, 2);

    // action
    let rows = db
        .get_audit_log_filtered(case_id, None, Some("case.view"), None, None, None, 100, 0)
        .await?;
    assert_eq!(rows.len(), 2);

    // resource_type
    let rows = db
        .get_audit_log_filtered(case_id, None, None, Some("artifact"), None, None, 100, 0)
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["details"], "cleanup");

    // combined
    let rows = db
        .get_audit_log_filtered(
            case_id,
            Some("alice"),
            Some("case.view"),
            None,
            None,
            None,
            100,
            0,
        )
        .await?;
    assert_eq!(rows.len(), 1);
    Ok(())
}

#[tokio::test]
async fn audit_log_filters_by_timestamp_range() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    db.record_audit_event(Some(case_id), "alice", "first", None, None, None)
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let mid = chrono::Utc::now().to_rfc3339();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    db.record_audit_event(Some(case_id), "alice", "second", None, None, None)
        .await?;

    // from mid: only the second event
    let rows = db
        .get_audit_log_filtered(case_id, None, None, None, Some(&mid), None, 100, 0)
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["action"], "second");

    // up to mid: only the first event
    let rows = db
        .get_audit_log_filtered(case_id, None, None, None, None, Some(&mid), 100, 0)
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["action"], "first");

    let count = db
        .get_audit_log_count_filtered(case_id, None, None, None, Some(&mid), None)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn audit_log_filtered_pagination_and_order() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    for i in 0..5 {
        db.record_audit_event(
            Some(case_id),
            "alice",
            &format!("action{}", i),
            None,
            None,
            None,
        )
        .await?;
    }

    // Newest first (id DESC), like get_audit_log
    let page = db
        .get_audit_log_filtered(case_id, Some("alice"), None, None, None, None, 2, 0)
        .await?;
    assert_eq!(page.len(), 2);
    assert_eq!(page[0]["action"], "action4");
    assert_eq!(page[1]["action"], "action3");

    let page = db
        .get_audit_log_filtered(case_id, Some("alice"), None, None, None, None, 2, 4)
        .await?;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0]["action"], "action0");
    Ok(())
}

#[tokio::test]
async fn unfiltered_audit_log_still_works() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    db.record_audit_event(Some(case_id), "alice", "a", None, None, None)
        .await?;
    db.record_audit_event(Some(case_id), "bob", "b", None, None, None)
        .await?;

    // Original unfiltered API keeps its behavior
    let rows = db.get_audit_log(case_id, 100, 0).await?;
    assert_eq!(rows.len(), 2);
    assert_eq!(db.get_audit_log_count(case_id).await?, 2);

    // Filtered variant with no filters matches it
    let rows = db
        .get_audit_log_filtered(case_id, None, None, None, None, None, 100, 0)
        .await?;
    assert_eq!(rows.len(), 2);
    Ok(())
}

/// A resource id that will not decode is shown under a visible marker, not as
/// the empty string that reads as "no resource".
#[tokio::test]
async fn an_undecodable_resource_id_is_marked_not_blanked() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    sqlx::query(
        "INSERT INTO audit_log (case_id, timestamp, user_id, action, resource_type, resource_id) \
         VALUES (?, '2026-01-01T00:00:00Z', 'mallory', 'case.view', 'case', X'010203')",
    )
    .bind(case_id)
    .execute(&pool)
    .await?;
    pool.close().await;

    let rows = db
        .get_audit_log_filtered(case_id, None, None, None, None, None, 10, 0)
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["resource_id"], "<undecodable resource_id: 3 bytes>");
    Ok(())
}
