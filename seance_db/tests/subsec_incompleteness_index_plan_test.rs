//! Query-plan regression for migration 0028.
//!
//! Two queries outgrew the indices that used to serve them:
//!
//! 1. Timeline pagination gained a sub-second tiebreak
//!    (`ORDER BY timestamp DESC, timestamp_subsec_nanos DESC, id ASC`). The
//!    0023 index stops at `(case_id, timestamp DESC, id ASC)`, so SQLite can
//!    still seek by case but must materialise the case's rows and build a
//!    TEMP B-TREE for the second sort key — on every page and every export.
//! 2. The completeness census filters on a `json_extract` flag with no index
//!    behind it, so each of its six queries reads and JSON-parses every
//!    artifact row in the case, and the two grouped ones then sort.
//!
//! `EXPLAIN QUERY PLAN` is the assertion target so the test is about the plan
//! the optimizer picks, not about row counts. Both plans were captured against
//! the migration set with and without 0028, so the RED states below are
//! observed, not assumed:
//!
//! * timeline, without 0028:
//!   `SEARCH timeline_events USING INDEX idx_timeline_events_case_id (case_id=?)`
//!   followed by `USE TEMP B-TREE FOR ORDER BY`;
//! * census, without 0028:
//!   `SEARCH artifacts USING INDEX idx_artifacts_case_id (case_id=?)` followed
//!   by `USE TEMP B-TREE FOR GROUP BY` and `USE TEMP B-TREE FOR ORDER BY`.
//!
//! Note the census RED is a `SEARCH` on the plain `case_id` index, NOT a
//! `SCAN`: every artifact IN THE CASE is read and JSON-parsed, and the reason
//! groups are then sorted in a temp b-tree. Asserting the absence of a `SCAN`
//! would therefore pass against the unfixed schema and prove nothing; the
//! GROUP BY b-tree is the term that actually changes.

mod common;

use anyhow::Result;
use common::{explain_plan, file_db};
use seance_core::db::DatabaseConnection;
use uuid::Uuid;

#[tokio::test]
async fn timeline_page_with_subsec_tiebreak_needs_no_temp_btree() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Subsec", "Examiner").await?;
    drop(db); // release the pool; reopen a raw pool for EXPLAIN

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    // The exact hot query from get_timeline_events (lib.rs).
    let sql = format!(
        "SELECT id, case_id, artifact_id, timestamp, timestamp_subsec_nanos, \
                source_utc_offset_seconds, timestamp_desc, source_module, short_desc, full_details \
         FROM timeline_events \
         WHERE case_id = x'{}' \
         ORDER BY timestamp DESC, timestamp_subsec_nanos DESC, id ASC \
         LIMIT 100 OFFSET 0",
        hex(case_id)
    );
    let p = explain_plan(&pool, &sql).await?;

    assert!(
        !p.contains("TEMP B-TREE"),
        "timeline pagination must be served in index order; sorting the whole case per page \
         is what 0028 exists to remove. Plan was:\n{p}"
    );
    assert!(
        p.contains("idx_timeline_events_case_ts_subsec"),
        "the four-column index must be the one chosen. Plan was:\n{p}"
    );

    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn incompleteness_census_uses_the_partial_indices() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Census", "Examiner").await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    for (axis, index) in [
        ("content", "idx_artifacts_content_incomplete"),
        ("inventory", "idx_artifacts_inventory_incomplete"),
    ] {
        // The exact grouped query from get_case_incompleteness (lib.rs): the
        // heaviest of the six, and the only one that both reads every artifact
        // in the case and then sorts what it found.
        let sql = format!(
            "SELECT json_extract(metadata_json, '$.{axis}_incomplete_reason') AS reason, \
                    COUNT(*) AS n \
             FROM artifacts \
             WHERE case_id = x'{}' \
               AND json_extract(metadata_json, '$.{axis}_incomplete') = 1 \
             GROUP BY reason ORDER BY n DESC, reason ASC LIMIT 50",
            hex(case_id)
        );
        let p = explain_plan(&pool, &sql).await?;

        assert!(
            p.contains(index),
            "the {axis} census must use the partial index, not scan every artifact in the \
             case and parse its JSON. Plan was:\n{p}"
        );
        // Without 0028 the reason groups are collected into a temp b-tree,
        // because idx_artifacts_case_id carries no reason column. Carrying the
        // reason as the partial index's second column makes the GROUP BY
        // index-ordered, so this term disappears. The `ORDER BY n DESC` b-tree
        // stays and must stay: no index can order by a count.
        assert!(
            !p.contains("TEMP B-TREE FOR GROUP BY"),
            "grouping the census reasons must be served in index order; sorting them per \
             export is half of what 0028 removes. Plan was:\n{p}"
        );
    }

    pool.close().await;
    Ok(())
}

/// UUIDs are stored as BLOBs, so an inlined literal has to be an X'..' blob for
/// the planner to treat the comparison the way the real bound query does.
fn hex(id: Uuid) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
