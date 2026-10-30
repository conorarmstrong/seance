//! Query-plan regression: the recent-artifact and child-listing queries must be
//! served by a composite index, not a full scan + temp-b-tree sort. Uses
//! `EXPLAIN QUERY PLAN` so the assertion is about the plan the optimizer picks,
//! independent of row counts. The live timeline-page plan is asserted in
//! `subsec_incompleteness_index_plan_test.rs`.

mod common;

use anyhow::Result;
use common::{explain_plan, file_db};
use seance_core::db::DatabaseConnection;

#[tokio::test]
async fn recent_artifacts_query_uses_case_created_index() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Idx2", "Examiner").await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    let sql = format!(
        "SELECT id FROM artifacts WHERE case_id = X'{}' ORDER BY created_at DESC LIMIT 20",
        case_id.simple()
    );
    let p = explain_plan(&pool, &sql).await?;

    assert!(
        p.contains("idx_artifacts_case_created"),
        "recent-artifacts query must use the (case_id, created_at) index; plan was:\n{p}"
    );

    Ok(())
}

/// The evidence-tree listing (`get_child_artifacts_filtered`) filters on
/// `parent_id` and orders by `(created_at, id)`. With no index carrying both,
/// SQLite chose `idx_artifacts_case_created` for the ordering and walked every
/// artifact in the case to find one node's children — a four-row page on a
/// 220,000-artifact case cost 42 ms (release), a 1,000-row page no more, and
/// a case ten times the size ten times as much.
#[tokio::test]
async fn child_listing_seeks_the_parent_and_pages_in_index_order() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Idx3", "Examiner").await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    // The exact statement shapes from get_child_artifacts_filtered and
    // get_child_artifacts: one for a node's children, one for the roots.
    for parent_clause in ["a.parent_id = X'00'", "a.parent_id IS NULL"] {
        let sql = format!(
            "SELECT a.id AS id, a.metadata_json AS metadata_json, \
                    (SELECT COUNT(*) FROM artifacts c WHERE c.parent_id = a.id) AS child_count \
             FROM artifacts a WHERE a.case_id = X'{}' AND {parent_clause} \
             ORDER BY a.created_at ASC, a.id ASC LIMIT 1001 OFFSET 0",
            case_id.simple()
        );
        let p = explain_plan(&pool, &sql).await?;
        assert!(
            p.contains("idx_artifacts_children_created"),
            "child listing ({parent_clause}) must seek the parent through the \
             (case_id, parent_id, created_at, id) index; plan was:\n{p}"
        );
        assert!(
            !p.contains("TEMP B-TREE"),
            "child listing ({parent_clause}) must page in index order, not sort; plan was:\n{p}"
        );
    }

    Ok(())
}
