//! Helpers shared by the integration tests that need a real, file-backed
//! database (several pooled connections that can contend for the write lock, or
//! a second raw pool for `EXPLAIN QUERY PLAN`). Each test crate uses only a
//! subset, hence the `dead_code` allowance.
#![allow(dead_code)]

use anyhow::Result;
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use sqlx::Row;
use std::fmt;
use uuid::Uuid;

/// A temporary database path. Dropping it removes the database and its `-wal`
/// and `-shm` files, so a test that fails an assertion does not leak them.
pub struct TempDb(String);

impl TempDb {
    pub fn path(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TempDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(format!("{}-wal", self.0));
        let _ = std::fs::remove_file(format!("{}-shm", self.0));
    }
}

/// A fresh, initialised file-backed database in the temp directory.
pub async fn file_db() -> Result<(SqliteConnection, TempDb)> {
    let path = TempDb(format!(
        "{}/seance_test_{}.db",
        std::env::temp_dir().display(),
        Uuid::new_v4().simple()
    ));
    let db = SqliteConnection::new(&format!("sqlite:{}?mode=rwc", path)).await?;
    db.initialize().await?;
    Ok((db, path))
}

/// The `detail` column of every `EXPLAIN QUERY PLAN` row for `sql`, joined.
pub async fn explain_plan(pool: &sqlx::SqlitePool, sql: &str) -> Result<String> {
    let rows = sqlx::query(&format!("EXPLAIN QUERY PLAN {sql}"))
        .fetch_all(pool)
        .await?;
    let mut out = String::new();
    for r in rows {
        let detail: String = r.try_get("detail")?;
        out.push_str(&detail);
        out.push('\n');
    }
    Ok(out)
}

/// Fail when any line of an `EXPLAIN QUERY PLAN` reads every row of `alias`:
/// `SCAN a`, `SCAN a USING INDEX ..` or `SCAN a USING COVERING INDEX ..`. The
/// last two are index-backed full scans, which a plain `SCAN a\n` match misses.
/// `SEARCH a ..` lines are seeks and pass.
pub fn assert_no_full_scan(plan: &str, alias: &str, what: &str) {
    let bare = format!("scan {}", alias.to_lowercase());
    for line in plan.lines() {
        let l = line.trim().to_lowercase();
        assert!(
            !(l == bare || l.starts_with(&format!("{bare} "))),
            "{what} must not full-scan `{alias}`; offending plan line `{}`; plan was:\n{plan}",
            line.trim()
        );
    }
}
