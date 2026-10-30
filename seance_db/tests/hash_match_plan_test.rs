//! Query-plan regression for hash-set matching. Every match compares
//! `LOWER(hash_set_entries.hash_value)`; before migration 0047 no index served
//! that expression, so each match scanned the whole entries table (millions of
//! rows for an NSRL-sized set), and the file grid paid it per displayed row.
//!
//! Plans the SQL the shipped functions BUILD, never a retyping of it.

mod common;

use anyhow::Result;
use common::{assert_no_full_scan, explain_plan, file_db};
use seance_db::SqliteConnection;
use uuid::Uuid;

const INDEX: &str = "idx_hash_set_entries_lower_hash";

#[tokio::test]
async fn hash_matching_seeks_the_lower_hash_index_never_scans_entries() -> Result<()> {
    let (db, path) = file_db().await?;
    drop(db);
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    let case_id = Uuid::new_v4();

    let known_filter = format!(
        "SELECT a.id FROM artifacts a WHERE a.case_id = X'{}' AND a.id IN ({})",
        case_id.simple(),
        SqliteConnection::known_any_match_sql(case_id)
    );
    let known_status = format!(
        "SELECT {} AS known_status FROM artifacts a WHERE a.case_id = ?",
        SqliteConnection::KNOWN_STATUS_SQL
    );
    let statements = [
        ("lookup_hash", SqliteConnection::HASH_LOOKUP_SQL.to_string()),
        (
            "list_hash_hits",
            format!(
                "SELECT a.id {}",
                SqliteConnection::hash_hits_body_sql(false)
            ),
        ),
        (
            "list_hash_hits (one set)",
            format!("SELECT a.id {}", SqliteConnection::hash_hits_body_sql(true)),
        ),
        (
            "count_hash_matches_for_case",
            format!(
                "SELECT COUNT(DISTINCT a.id) {}",
                SqliteConnection::hash_hits_body_sql(false)
            ),
        ),
        ("known filter", known_filter),
        ("known_status column", known_status),
    ];

    for (label, sql) in statements {
        let plan = explain_plan(&pool, &sql).await?;
        assert!(
            plan.contains(&format!("USING INDEX {INDEX}")),
            "{label} must seek {INDEX}; plan was:\n{plan}"
        );
        for alias in ["e", "hse"] {
            assert_no_full_scan(&plan, alias, label);
        }
    }
    Ok(())
}
