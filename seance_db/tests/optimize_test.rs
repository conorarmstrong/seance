//! `optimize()` must populate the SQLite query-planner statistics
//! (`sqlite_stat1`) so the planner chooses among the ~9 overlapping `artifacts`
//! indices from real cardinality rather than guessing. Bounded by the
//! per-connection `analysis_limit` so it stays cheap on large tables.

mod common;

use anyhow::Result;
use common::file_db;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use serde_json::json;
use sqlx::Row;

#[tokio::test]
async fn optimize_populates_planner_stats() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Opt", "Examiner").await?;

    // Enough rows that ANALYZE has something to sample.
    let batch: Vec<_> = (0..500)
        .map(|i| {
            Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": format!("f{i}.bin"), "path": format!("/d/f{i}.bin"), "size": i }),
            )
        })
        .collect();
    db.record_artifacts_batch(&batch).await?;

    db.optimize().await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    let n: i64 = sqlx::query("SELECT COUNT(*) AS n FROM sqlite_stat1")
        .fetch_one(&pool)
        .await?
        .get("n");
    assert!(
        n > 0,
        "optimize() must populate sqlite_stat1 (got {n} rows)"
    );

    Ok(())
}

#[tokio::test]
async fn optimize_truncates_the_wal() -> Result<()> {
    // With wal_autocheckpoint deferred, the WAL grows during a write burst;
    // optimize()'s truncating checkpoint must fold it back and shrink the -wal
    // file (rather than leaving it large after ingest).
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Wal", "Examiner").await?;
    let batch: Vec<_> = (0..3000)
        .map(|i| {
            Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": format!("f{i}.bin"), "path": format!("/d/f{i}.bin"), "size": i }),
            )
        })
        .collect();
    db.record_artifacts_batch(&batch).await?;

    let wal_path = format!("{}-wal", path);
    let before = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);

    assert!(
        before > 0,
        "premise: the WAL must be non-empty before optimize()"
    );

    db.optimize().await?; // ANALYZE + truncating WAL checkpoint

    let after = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        after, 0,
        "optimize() must truncate the WAL ({before} -> {after})"
    );

    Ok(())
}
