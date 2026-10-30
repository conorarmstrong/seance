//! Tests for get_timeline_histogram and get_timeline_extent.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use uuid::Uuid;

async fn setup_test_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

async fn create_event(
    db: &SqliteConnection,
    case_id: Uuid,
    ts: i64,
    source_module: &str,
) -> Result<()> {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::TimelineEvent,
        metadata: serde_json::json!({
            "timestamp": ts,
            "timestamp_desc": "Test Event",
            "source_module": source_module,
            "short_desc": "desc",
            "full_details": "{\"filename\": \"f.txt\"}",
        }),
        data: None,
    };
    db.record_artifact(&artifact).await?;
    Ok(())
}

#[tokio::test]
async fn histogram_buckets_and_orders_events() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    // bucket [0, 60): 5, 59; bucket [60, 120): 60; bucket [180, 240): 200
    for ts in [5, 59, 60, 200] {
        create_event(&db, case_id, ts, "ModA").await?;
    }

    let histo = db
        .get_timeline_histogram(case_id, None, None, None, None, None, None, None, 60)
        .await?;

    assert_eq!(histo, vec![(0, 2), (60, 1), (180, 1)]);
    Ok(())
}

#[tokio::test]
async fn activity_buckets_by_weekday_and_hour_utc() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    // 1970-01-01 00:00:00 UTC is a Thursday (dow=4). Two events land in the
    // Thu-00:00 cell; one an hour later in Thu-01:00. (Epoch 0 itself is the
    // "missing timestamp" sentinel and is deliberately excluded, so both
    // hour-0 events use positive seconds.)
    for ts in [100, 200] {
        create_event(&db, case_id, ts, "ModA").await?;
    }
    create_event(&db, case_id, 3700, "ModA").await?;

    let mut cells = db.get_timeline_activity(case_id).await?;
    cells.sort();
    assert_eq!(cells, vec![(4, 0, 2), (4, 1, 1)]);

    // The epoch-0 sentinel must not appear as spurious activity.
    create_event(&db, case_id, 0, "ModA").await?;
    let after = db.get_timeline_activity(case_id).await?;
    assert_eq!(after.iter().map(|(_, _, n)| n).sum::<i64>(), 3);
    Ok(())
}

#[tokio::test]
async fn histogram_floors_negative_timestamps() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    // With bucket 10: -10 and -5 belong to bucket -10 (floor), 5 to bucket 0.
    // Truncating division would wrongly put -5 in bucket 0.
    for ts in [-10, -5, 5] {
        create_event(&db, case_id, ts, "ModA").await?;
    }

    let histo = db
        .get_timeline_histogram(case_id, None, None, None, None, None, None, None, 10)
        .await?;

    assert_eq!(histo, vec![(-10, 2), (0, 1)]);
    Ok(())
}

#[tokio::test]
async fn histogram_respects_filters() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    create_event(&db, case_id, 10, "ModA").await?;
    create_event(&db, case_id, 20, "ModB").await?;
    create_event(&db, case_id, 500, "ModA").await?;

    // source module filter
    let modules = vec!["ModA".to_string()];
    let histo = db
        .get_timeline_histogram(
            case_id,
            None,
            None,
            Some(&modules),
            None,
            None,
            None,
            None,
            100,
        )
        .await?;
    assert_eq!(histo, vec![(0, 1), (500, 1)]);

    // date range filter
    let histo = db
        .get_timeline_histogram(
            case_id,
            Some(0),
            Some(100),
            None,
            None,
            None,
            None,
            None,
            100,
        )
        .await?;
    assert_eq!(histo, vec![(0, 2)]);
    Ok(())
}

#[tokio::test]
async fn histogram_rejects_nonpositive_bucket() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    assert!(db
        .get_timeline_histogram(case_id, None, None, None, None, None, None, None, 0,)
        .await
        .is_err());
    assert!(db
        .get_timeline_histogram(case_id, None, None, None, None, None, None, None, -60,)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn extent_returns_min_max_or_none() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    // Empty case: no extent
    assert_eq!(
        db.get_timeline_extent(case_id, None, None, None, None, None, None, None,)
            .await?,
        None
    );

    create_event(&db, case_id, -50, "ModA").await?;
    create_event(&db, case_id, 100, "ModB").await?;
    create_event(&db, case_id, 42, "ModA").await?;

    assert_eq!(
        db.get_timeline_extent(case_id, None, None, None, None, None, None, None,)
            .await?,
        Some((-50, 100))
    );

    // Filtered extent
    let modules = vec!["ModA".to_string()];
    assert_eq!(
        db.get_timeline_extent(case_id, None, None, Some(&modules), None, None, None, None,)
            .await?,
        Some((-50, 42))
    );
    Ok(())
}

/// The heatmap leaves out events at or before the epoch (a "no date" sentinel);
/// the count of what it left out is available so the caller can disclose it.
#[tokio::test]
async fn activity_heatmap_excludes_epoch_events_and_counts_them() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    for ts in [1_700_000_000_i64, 1_700_000_100, 0, -86_400] {
        create_event(&db, case_id, ts, "ModA").await?;
    }

    let cells = db.get_timeline_activity(case_id).await?;
    assert_eq!(cells.iter().map(|c| c.2).sum::<i64>(), 2);
    assert_eq!(db.count_timeline_activity_excluded(case_id).await?, 2);
    Ok(())
}
