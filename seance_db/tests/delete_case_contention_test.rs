//! Regression: a case purge must survive a busy database.
//!
//! `delete_case` empties a case's bulk tables in batches. Each batch is its own
//! statement, so a batch that loses a write window under a concurrent ingest
//! used to abort the whole purge: the case stayed marked `deleting` and made no
//! further progress until the process was restarted. Three multi-million-row
//! cases stalled that way (HUNT-086). Batches are now retried, so the purge
//! finishes while another case is being written.

mod common;

use anyhow::Result;
use common::file_db;
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use uuid::Uuid;

async fn fill_log(db: &SqliteConnection, case_id: Uuid, rows: usize) -> Result<()> {
    for chunk in 0..(rows / 500) {
        let batch: Vec<_> = (0..500)
            .map(|_| {
                seance_core::db::ProcessingLogRow::single(
                    case_id,
                    Uuid::new_v4(),
                    format!("mod{chunk}"),
                    "complete".to_string(),
                    1,
                    None,
                    5,
                )
            })
            .collect();
        db.record_processing_log_batch(&batch).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn delete_case_finishes_while_another_case_is_written() -> Result<()> {
    let (db, _path) = file_db().await?;
    let doomed = db.create_case("Doomed", "Examiner").await?;
    let live = db.create_case("Live", "Examiner").await?;

    // More rows than one delete batch, so the purge takes several statements
    // and has to keep going across contention.
    fill_log(&db, doomed, 45_000).await?;

    let db = Arc::new(db);
    let stop = Arc::new(AtomicBool::new(false));

    // Eight writers hammering the live case for the whole purge.
    let mut writers = Vec::new();
    for w in 0..8u32 {
        let db = db.clone();
        let stop = stop.clone();
        writers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let batch: Vec<_> = (0..200)
                    .map(|_| {
                        seance_core::db::ProcessingLogRow::single(
                            live,
                            Uuid::new_v4(),
                            format!("live{w}"),
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

    db.delete_case(doomed).await?;

    stop.store(true, Ordering::Relaxed);
    for h in writers {
        h.await??;
    }

    // The purged case is gone, rows and all.
    assert_eq!(db.case_status(doomed).await?, None);
    let (entries, total) = db.get_processing_log_for_case(doomed, 10).await?;
    assert!(
        entries.is_empty() && total == 0,
        "purged case still has processing_log rows: {total} groups"
    );

    // The live case was untouched by the purge.
    let (_, live_groups) = db.get_processing_log_for_case(live, 10).await?;
    assert!(live_groups > 0, "concurrent writer wrote nothing");

    Ok(())
}

/// A purge writes nothing but deletions, and every deleted page sits in the
/// WAL until something checkpoints it. Nothing did: a 72-million-row purge
/// left a 45 GB WAL beside a 46 GB database, and the next start timed out
/// trying to recover it before any connection opened (HUNT-088).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn purging_a_case_gives_its_wal_back() -> Result<()> {
    let (db, path) = file_db().await?;
    let doomed = db.create_case("Doomed", "Examiner").await?;
    fill_log(&db, doomed, 60_000).await?;

    let wal = format!("{path}-wal");
    let before = std::fs::metadata(&wal)?.len();
    assert!(
        before > 1_000_000,
        "the fill should have left a WAL worth reclaiming, found {before} bytes"
    );

    db.delete_case(doomed).await?;

    let after = std::fs::metadata(&wal)?.len();
    assert!(
        after < 100_000,
        "the purge left {after} bytes of WAL behind (was {before})"
    );

    Ok(())
}

/// The server now finishes this on its way out, so what the log holds is not
/// the next start's problem. Stopping used to leave it entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncate_wal_gives_the_log_file_back() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Busy", "Examiner").await?;
    fill_log(&db, case_id, 60_000).await?;

    let wal = format!("{path}-wal");
    let before = std::fs::metadata(&wal)?.len();
    assert!(before > 1_000_000, "nothing to reclaim: {before} bytes");

    db.truncate_wal().await;

    let after = std::fs::metadata(&wal)?.len();
    assert!(after < 100_000, "{after} bytes of WAL left (was {before})");

    Ok(())
}
