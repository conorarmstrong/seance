//! Query-plan regressions for the reads that would otherwise scan every
//! artifact in a case and parse JSON per row: the record-type census, the
//! record listing, the GPS map query and the comms counterparty ranking.
//! `EXPLAIN QUERY PLAN` makes each assertion one about the optimizer's choice
//! rather than about row counts. RED before the 0024/0025 index migrations.
//!
//! EVERY test here plans the SQL the shipped function BUILDS, obtained from the
//! same builder production calls, and binds its parameters in the same order.
//! They used to plan hand-written copies of those statements, and the copies
//! drifted: two of them were passing over a query shape that no longer used the
//! index at all, so the file reported a performance guarantee that nothing held.
//! A plan test that plans a copy of the query is worse than no plan test. Keep
//! it that way — if a statement is not reachable from a builder, expose the
//! builder rather than retyping the SQL here.

mod common;

use anyhow::Result;
use common::{assert_no_full_scan, explain_plan, file_db};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use sqlx::Row;
use uuid::Uuid;

/// The record-type census must be answered from the expression index, with the
/// grouping served by index order rather than a temp b-tree.
///
/// EXPLAINs the statement `record_type_counts` actually builds. Its predecessor
/// planned a hand-written copy of it, and the copy had already drifted: it
/// lacked the `CAST(... AS TEXT)` the shipped statement wrapped the grouped
/// discriminator in. That CAST is not something an index can match, so the
/// shipped census had silently gone back to searching
/// idx_artifacts_browse_type_name and sorting the GROUP BY in a temp b-tree —
/// both of the things asserted against below — while the test passed on its
/// copy. Both source scopes are planned here because both ship.
#[tokio::test]
async fn record_type_counts_uses_expression_index_no_groupby_sort() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Expr", "Examiner").await?;
    drop(db); // release the pool; reopen a raw pool for EXPLAIN

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    for source_scoped in [false, true] {
        let sql = SqliteConnection::record_type_counts_sql(case_id, source_scoped);
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        // Bound in the order the shipped call binds them: the subtree anchor
        // first when scoped, then the body's case_id re-filter.
        let mut q = sqlx::query(&explain);
        if source_scoped {
            q = q
                .bind(case_id.as_bytes().to_vec())
                .bind(Uuid::new_v4().as_bytes().to_vec());
        }
        q = q.bind(case_id.as_bytes().to_vec());
        let mut p = String::new();
        for r in q.fetch_all(&pool).await? {
            p.push_str(r.try_get::<String, _>("detail")?.as_str());
            p.push('\n');
        }

        assert!(
            p.contains("idx_artifacts_record_type"),
            "record-type count must use the expression index on the type \
             discriminator (source_scoped={source_scoped}); plan was:\n{p}"
        );
        // GROUP BY must be satisfied by index order. The ORDER BY count (an
        // aggregate) still needs its own sort -- that temp-b-tree is expected and
        // tiny (one row per record type), so we only forbid the GROUP-BY one.
        assert!(
            !p.to_uppercase().contains("TEMP B-TREE FOR GROUP BY"),
            "record-type GROUP BY must be served by index order, not a temp-b-tree \
             (source_scoped={source_scoped}); plan was:\n{p}"
        );
    }

    Ok(())
}

/// The map query reads only the GPS-bearing records, so it must seek the
/// partial index rather than scan every artifact in the case.
///
/// EXPLAINs the statement `get_geo_map_points` actually runs.
#[tokio::test]
async fn geo_points_query_uses_partial_index_no_scan() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Geo", "Examiner").await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    // Bind order as shipped: the case id, then the row ceiling.
    let explain = format!(
        "EXPLAIN QUERY PLAN {}",
        SqliteConnection::GEO_MAP_POINTS_SQL
    );
    let mut p = String::new();
    for r in sqlx::query(&explain)
        .bind(case_id.as_bytes().to_vec())
        .bind(1_i64)
        .fetch_all(&pool)
        .await?
    {
        p.push_str(r.try_get::<String, _>("detail")?.as_str());
        p.push('\n');
    }

    assert!(
        p.contains("SEARCH a USING INDEX idx_artifacts_geo (case_id=?)"),
        "geo-points query must use the partial GPS index; plan was:\n{p}"
    );
    assert_no_full_scan(&p, "a", "geo-points query");

    Ok(())
}

/// The comms counterparty ranking (LIVE-024) reads every comms record in the
/// case, so it must seek the record-type expression index rather than scan the
/// artifact table and parse ten JSON keys out of every row in it.
///
/// This test EXPLAINs the statements `comms_contact_ranking` actually builds,
/// over the full `COMMS_RECORD_TYPES` list it uses when no channel tile is
/// selected — the default the comms page loads with. It used to plan a
/// hand-written two-type imitation of them instead, and that is why it passed
/// while the shipped query had already stopped using the index: at sixteen
/// VALUES rows SQLite reversed the join and walked every ParsedRecord in the
/// case. A plan test that plans a copy of the query reports a guarantee nobody
/// holds, so it is worse than no test at all.
#[tokio::test]
async fn comms_ranking_seeks_by_the_record_type_index() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Rank", "Examiner").await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    // Every shape the endpoint can ask for: the whole comms set and a single
    // channel, each with and without an examiner's search term.
    for types in [seance_db::COMMS_RECORD_TYPES.len(), 1] {
        for has_needle in [false, true] {
            let sql = SqliteConnection::comms_ranking_sql(types, has_needle, 20);
            for (which, stmt) in [("census", &sql.census), ("ranking", &sql.ranking)] {
                // Bound in the order the shipped call binds them: one record
                // type per VALUES row, then the case id, then the pattern.
                let explain = format!("EXPLAIN QUERY PLAN {stmt}");
                let mut q = sqlx::query(&explain);
                for t in seance_db::COMMS_RECORD_TYPES.iter().take(types) {
                    q = q.bind(*t);
                }
                q = q.bind(case_id.as_bytes().to_vec());
                if has_needle && which == "ranking" {
                    q = q.bind("%needle%");
                }
                let mut p = String::new();
                for r in q.fetch_all(&pool).await? {
                    p.push_str(r.try_get::<String, _>("detail")?.as_str());
                    p.push('\n');
                }
                let case = format!("{which}, {types} type(s), needle={has_needle}");

                assert!(
                    p.contains("SEARCH a USING INDEX idx_artifacts_record_type"),
                    "the comms ranking must seek by the record-type expression \
                     index ({case}); plan was:\n{p}"
                );
                // Seeking that index on `case_id` alone would still walk every
                // ParsedRecord in the case; the discriminator equality is the
                // half that makes it a comms-only read.
                assert!(
                    p.contains("<expr>=?"),
                    "the seek must use the discriminator, not just case_id \
                     ({case}); plan was:\n{p}"
                );
                assert_no_full_scan(&p, "a", &format!("the comms ranking ({case})"));
            }
        }
    }

    // The formulation this replaced -- `<expr> IN (...)` -- is the regression
    // this test exists to catch: the planner answers it from
    // idx_artifacts_browse_type_name and re-parses the metadata JSON of every
    // ParsedRecord in the case, comms or not.
    let type_expr = "COALESCE(\
         json_extract(a.metadata_json, '$.type'), \
         json_extract(a.metadata_json, '$.subtype'), \
         json_extract(a.metadata_json, '$.record_type'), \
         json_extract(a.metadata_json, '$.analysis_type'), \
         'Unknown')";
    let in_list = format!(
        "SELECT COUNT(*) FROM artifacts a \
         WHERE a.case_id = X'{case}' AND a.artifact_type = 'ParsedRecord' \
           AND {type_expr} IN ('WhatsApp','iMessage')",
        case = case_id.simple()
    );
    assert!(
        !explain_plan(&pool, &in_list)
            .await?
            .contains("idx_artifacts_record_type"),
        "if an IN list now seeks the expression index the comment on the VALUES \
         join in comms_ranking_sql is stale and should be revisited"
    );

    Ok(())
}

/// A newest-ingested-first record listing must still ride
/// idx_artifacts_record_type_created. SQLite can walk an index backwards, so
/// reversing BOTH ordering columns keeps the page a seek plus LIMIT rows; had
/// only one column been reversed the planner would have had to materialise and
/// sort every record of that type in the case.
///
/// EXPLAINs the statement `list_records_by_type_ordered` builds, for both
/// directions: a copy of it planned here could stay fast while the shipped one
/// stopped being, which is the whole reason this file plans shipped SQL now.
#[tokio::test]
async fn newest_first_record_listing_still_uses_the_ordered_index() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Order", "Examiner").await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    for order in [
        seance_db::RecordOrder::OldestIngestedFirst,
        seance_db::RecordOrder::NewestIngestedFirst,
    ] {
        let sql = SqliteConnection::record_listing_sql(
            case_id,
            "WhatsApp",
            false,
            order,
            100,
            0,
            &seance_db::RecordListingRefinement::none(),
        );
        let explain = format!("EXPLAIN QUERY PLAN {}", sql.page);
        // Bind order as shipped: case_id, then the record type.
        let p_rows = sqlx::query(&explain)
            .bind(case_id.as_bytes().to_vec())
            .bind("WhatsApp")
            .fetch_all(&pool)
            .await?;
        let mut p = String::new();
        for r in p_rows {
            p.push_str(r.try_get::<String, _>("detail")?.as_str());
            p.push('\n');
        }

        assert!(
            p.contains("idx_artifacts_record_type_created"),
            "a {order:?} listing must use the ordered record-type index; plan was:\n{p}"
        );
        // Any temp b-tree at all, not just a whole-ORDER-BY one: reversing only
        // `created_at` and leaving the `id` tiebreaker ascending leaves SQLite
        // able to walk the index for the first column and sort the rest, which
        // it reports as "USE TEMP B-TREE FOR LAST TERM OF ORDER BY" — a plan
        // that still materialises every record of the type in the case.
        assert!(
            !p.to_uppercase().contains("TEMP B-TREE"),
            "a {order:?} listing must be served by an index walk, not a sort; \
             plan was:\n{p}"
        );
    }

    // The one listing that knowingly gives the index up: a label that could be
    // a number's rendering has to compare `CAST(<expr> AS TEXT)`, because the
    // census folds an INTEGER 1 and a TEXT '1' into one type and the drill-down
    // must show both. No index carries that CAST, so the plan changes — and it
    // is asserted here so the trade is visible rather than looking like a
    // regression. Sharpening it later (an index over the coerced discriminator,
    // say) should fail this assertion, which is the right way to find out.
    let numeric = SqliteConnection::record_listing_sql(
        case_id,
        "1",
        false,
        seance_db::RecordOrder::OldestIngestedFirst,
        100,
        0,
        &seance_db::RecordListingRefinement::none(),
    );
    let mut np = String::new();
    for r in sqlx::query(&format!("EXPLAIN QUERY PLAN {}", numeric.page))
        .bind(case_id.as_bytes().to_vec())
        .bind("1")
        .fetch_all(&pool)
        .await?
    {
        np.push_str(r.try_get::<String, _>("detail")?.as_str());
        np.push('\n');
    }
    assert!(
        !np.contains("idx_artifacts_record_type_created"),
        "if a numeric label's listing now rides the ordered expression index, \
         the cost comment in record_listing_sql is stale and should be \
         revisited; plan was:\n{np}"
    );

    Ok(())
}

/// Every recursive walk over the artifact tree must SEEK the parent index at
/// each step, never scan its own queue.
///
/// This is the plan that took the gallery down (`UI-024`). SQLite is free to
/// reorder an inner join, and for a recursive CTE it has no cardinality
/// estimate for the queue, so it chose `artifacts` as the outer loop: each step
/// SEARCHed `idx_artifacts_case_id` — every artifact in the case — and SCANned
/// the queue for each row. Quadratic. On a 163,000-artifact case the
/// counts-by-source walk had not finished after ten minutes, the endpoint gave
/// up at its 300-second timeout, and the page waited on it for ever.
///
/// The fix is `CROSS JOIN` with the queue written first. It is invisible in a
/// diff and reads like a typo, so it is exactly the kind of thing a later
/// tidy-up removes — which is why the guarantee is asserted here rather than
/// left to the comment that explains it. Writing the queue first WITHOUT
/// `CROSS` does not work: the planner reorders it anyway, and this test fails
/// if someone tries.
#[tokio::test]
async fn artifact_tree_walks_seek_the_parent_index() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Walks", "Examiner").await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    let root = Uuid::new_v4();

    // The shipped statements, from the builders that produce them.
    let subtree = format!(
        "{} SELECT COUNT(*) FROM subtree",
        seance_db::subtree_cte(case_id)
    );
    let cases: [(&str, &str, usize); 2] = [
        ("subtree_cte", subtree.as_str(), 2),
        (
            "counts_by_source",
            SqliteConnection::counts_by_source_sql(),
            2,
        ),
    ];

    for (name, sql, binds) in cases {
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let mut q = sqlx::query(&explain);
        for i in 0..binds {
            // subtree_cte binds (case_id, root id); counts_by_source binds the
            // case id twice. Both are blobs, so the shapes coincide.
            q = if i == 1 && name == "subtree_cte" {
                q.bind(root.as_bytes().to_vec())
            } else {
                q.bind(case_id.as_bytes().to_vec())
            };
        }
        let mut p = String::new();
        for r in q.fetch_all(&pool).await? {
            p.push_str(r.try_get::<String, _>("detail")?.as_str());
            p.push('\n');
        }

        // The recursive step must seek by (case_id, parent_id). Any index that
        // carries that pair is acceptable; what is not acceptable is a seek on
        // case_id alone, which is every artifact in the case.
        assert!(
            p.contains("parent_id=?"),
            "{name}: the recursive step must seek the parent index; plan was:\n{p}"
        );
        // The queue is the thing that must be walked, not the thing that is
        // searched for each artifact. `SCAN a` or a bare `case_id=?` seek on the
        // artifacts side is the quadratic plan coming back.
        assert!(
            !p.contains("SEARCH a USING INDEX idx_artifacts_case_id (case_id=?)"),
            "{name}: the recursive step is scanning the whole case per row — the \
             quadratic plan is back; plan was:\n{p}"
        );
    }

    Ok(())
}

/// HUNT-107's exclusion must ride an index, not a scan.
///
/// The first fix excluded the records a later run answered with a predicate on
/// every count, and that predicate reads `metadata_json` for every record in the
/// case: the Analysis index on a 1.75M-artifact case went from a fraction of a
/// second to 96. The census now counts the type's whole population as before and
/// subtracts what `idx_artifacts_superseded` holds — a partial index over
/// exactly the superseded rows, which is empty on a case where no module has
/// been re-run.
#[tokio::test]
async fn the_superseded_census_rides_its_own_partial_index() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Superseded plan", "examiner").await?;
    drop(db); // release the pool; reopen a raw one for EXPLAIN
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    let sql = SqliteConnection::superseded_type_counts_sql(case_id, false);
    let detail = explain_plan(&pool, &sql).await?;
    assert!(
        detail.contains("idx_artifacts_superseded"),
        "the superseded census must use its partial index; plan was:\n{detail}"
    );
    assert_no_full_scan(&detail, "a", "the superseded census");

    // The census it feeds must still be answered from the record-type index.
    let census = SqliteConnection::record_type_counts_sql(case_id, false);
    let detail = explain_plan(&pool, &census).await?;
    assert!(
        detail.contains("idx_artifacts_record_type"),
        "the record-type census must stay on its index; plan was:\n{detail}"
    );

    Ok(())
}
