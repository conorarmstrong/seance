//! Concurrency regression: every pooled connection must carry the
//! per-connection `busy_timeout`, so many concurrent writers serialize and wait
//! for the single SQLite write lock instead of failing immediately with
//! `SQLITE_BUSY`.
//!
//! Before the fix, the pragmas were applied via a one-off `.execute(&pool)`,
//! which configured only one of the pool's connections; writers landing on any
//! of the other (default `busy_timeout = 0`) connections failed instantly under
//! load, dropping processing-log batches during a large ingest.

mod common;

use anyhow::Result;
use common::file_db;
use seance_core::db::DatabaseConnection;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_writers_survive_lock_contention() -> Result<()> {
    let (db, _path) = file_db().await?;
    let case_id = db.create_case("Concurrency", "Examiner").await?;
    let db = Arc::new(db);

    // 24 writers, each committing 25 batches of 50 rows = 30,000 rows total,
    // all racing for the write lock. With the per-connection busy_timeout in
    // place they all succeed; without it, connections with busy_timeout = 0
    // return "database is locked" and a task errors.
    let mut handles = Vec::new();
    for w in 0..24u32 {
        let db = db.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..25 {
                let batch: Vec<_> = (0..50)
                    .map(|_| {
                        seance_core::db::ProcessingLogRow::single(
                            case_id,
                            Uuid::new_v4(),
                            format!("mod{w}"),
                            "complete".to_string(),
                            1,
                            None,
                            5,
                        )
                    })
                    .collect();
                db.record_processing_log_batch(&batch).await?;
            }
            Ok::<(), anyhow::Error>(())
        }));
    }

    // Any SQLITE_BUSY failure surfaces here as an Err.
    for h in handles {
        h.await??;
    }

    Ok(())
}
