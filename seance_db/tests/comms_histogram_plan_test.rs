//! Query-plan regression for the comms volume histogram, over the SQL THAT
//! SHIPS — obtained from the builder production calls, bound in the same order.
//!
//! The histogram runs on the same page load as the ranking, over the same rows,
//! so it inherits the ranking's cliff: measured on SQLite 3.46 over a
//! 200,000-record case, letting the planner reverse the loops costs 0.438s
//! against 0.040s for the seek (`comms_ranking_sql`, lib.rs). The three hints
//! that avoid it — a VALUES join, `CROSS JOIN` to pin loop order, `INDEXED BY`
//! to pin the index — are asserted here against the real statements.
//!
//! It is also honest about what CANNOT be indexed: the bars GROUP BY a bucket
//! computed per row from JSON, and no index can serve that. The temp b-tree is
//! expected, and asserting its absence would be asserting a lie.

mod common;

use anyhow::Result;
use common::{assert_no_full_scan, file_db};
use seance_core::db::DatabaseConnection;
use seance_db::{SqliteConnection, COMMS_RECORD_TYPES, COMMS_TIME_KEYS};
use sqlx::Row;
use uuid::Uuid;

async fn plan(
    pool: &sqlx::SqlitePool,
    sql: &str,
    types: &[&str],
    case_id: Uuid,
    needle: Option<&str>,
    contact: Option<&str>,
) -> Result<String> {
    let explain = format!("EXPLAIN QUERY PLAN {sql}");
    let mut q = sqlx::query(&explain);
    for t in types {
        q = q.bind(*t);
    }
    q = q.bind(case_id.as_bytes().to_vec());
    if let Some(n) = needle {
        q = q.bind(n.to_string());
    }
    if let Some(c) = contact {
        q = q.bind(c.to_string());
    }
    let rows = q.fetch_all(pool).await?;
    let mut out = String::new();
    for r in rows {
        out.push_str(&r.try_get::<String, _>("detail")?);
        out.push('\n');
    }
    Ok(out)
}

/// Both statements must seek the record-type expression index once per type,
/// with `artifacts` as the INNER loop. The failure this pins is the planner
/// making `artifacts` the outer loop and re-parsing every record's JSON: the
/// sixteen-type default is exactly where it used to do that.
#[tokio::test]
async fn the_histogram_seeks_by_the_record_type_index() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Plan", "Examiner").await?;
    // ANALYZE with sampled statistics is what makes the planner's estimates
    // indistinguishable between the single-column and expression indexes; the
    // hints must hold with those statistics in place, not only without them.
    db.optimize().await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    // Every combination the API can ask for, at the sixteen-type default that
    // used to fall off the cliff.
    for (needle, contact) in [
        (None, None),
        (Some("%ali%"), None),
        (None, Some("bob")),
        (Some("%ali%"), Some("bob")),
    ] {
        let sql = SqliteConnection::comms_histogram_sql(
            COMMS_TIME_KEYS,
            COMMS_RECORD_TYPES.len(),
            needle.is_some(),
            contact.is_some(),
            86_400,
        )?;
        for (label, stmt) in [("census", &sql.census), ("buckets", &sql.buckets)] {
            let detail = plan(&pool, stmt, COMMS_RECORD_TYPES, case_id, needle, contact).await?;
            assert!(
                detail.contains("SEARCH a USING INDEX idx_artifacts_record_type"),
                "{label} must seek the record-type expression index, not scan \
                 every ParsedRecord in the case:\n{detail}"
            );
            // Seeking on `case_id` alone would still walk every ParsedRecord
            // in the case; the discriminator equality is the half that makes
            // it a comms-only read.
            assert!(
                detail.contains("<expr>=?"),
                "{label} must seek on the discriminator, not just case_id:\n{detail}"
            );
            // The CROSS JOIN pins `artifacts` as the inner loop.
            assert_no_full_scan(&detail, "a", label);
            // The two extraction CTEs must stay materialised. Flattened, SQLite
            // substitutes their column expressions into every reference, so the
            // band CASE re-parses `metadata_json` a dozen times per row:
            // measured 2.26s/2.89s flattened against 0.52s/0.52s materialised
            // over 200,000 records, on a page that also pays for the ranking.
            assert_eq!(
                detail.matches("MATERIALIZE").count(),
                2,
                "{label} must materialise both extraction CTEs:\n{detail}"
            );
        }
    }

    drop(pool);
    Ok(())
}

/// What cannot be indexed, said out loud.
///
/// The census groups on a class computed from JSON per row, and the bars group
/// on a bucket computed from an epoch expression per row. Neither grouping can
/// be served by an index in any schema, so both sort in a temp b-tree over the
/// match set. This test asserts the temp b-tree IS there, so that a later change
/// which appears to remove it is examined rather than celebrated: the only ways
/// to lose it are to stop grouping (a different answer) or to materialise the
/// bucket in a column (a write-time decision with its own retroactivity cost).
#[tokio::test]
async fn the_grouped_bucket_needs_a_temp_btree_and_no_index_can_serve_it() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Plan", "Examiner").await?;
    db.optimize().await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    let sql = SqliteConnection::comms_histogram_sql(
        COMMS_TIME_KEYS,
        COMMS_RECORD_TYPES.len(),
        false,
        false,
        86_400,
    )?;

    let buckets = plan(&pool, &sql.buckets, COMMS_RECORD_TYPES, case_id, None, None).await?;
    assert!(
        buckets.contains("TEMP B-TREE"),
        "the bars group on a computed bucket; a plan without a temp b-tree \
         would mean the grouping changed, not that it got faster:\n{buckets}"
    );

    // The census, by contrast, returns at most one row per (class, type)
    // however large the case: six classes by sixteen types, one pass, no
    // truncation.
    let census = plan(&pool, &sql.census, COMMS_RECORD_TYPES, case_id, None, None).await?;
    assert!(census.contains("idx_artifacts_record_type"), "{census}");
    // Carrying the record type into the census grouping must widen the ANSWER
    // and not the PLAN: the type is already a column of the materialised
    // extraction, so the case is still read exactly once. A second seek here
    // would mean the breakdown had quietly become a second query over the same
    // records — which is precisely what it must never be, because a per-type
    // set that could disagree with the total it decomposes is the failure the
    // breakdown exists to avoid.
    assert_eq!(
        census.matches("SEARCH a USING INDEX").count(),
        1,
        "the census must read the case once:\n{census}"
    );

    drop(pool);
    Ok(())
}

/// The discriminator inside the histogram's CTE must stay byte-identical to the
/// one the index carries. `INDEXED BY` turns a drift into a statement that
/// refuses to prepare, which is the loud failure we want — but only if the
/// statement is actually prepared somewhere, which is what this does.
#[tokio::test]
async fn every_shipped_variant_prepares_against_the_named_index() -> Result<()> {
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Plan", "Examiner").await?;
    drop(db);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    for type_count in [1, COMMS_RECORD_TYPES.len()] {
        for needle in [false, true] {
            for contact in [false, true] {
                let sql = SqliteConnection::comms_histogram_sql(
                    COMMS_TIME_KEYS,
                    type_count,
                    needle,
                    contact,
                    3_600,
                )?;
                let types = &COMMS_RECORD_TYPES[..type_count];
                for stmt in [&sql.census, &sql.buckets] {
                    plan(
                        &pool,
                        stmt,
                        types,
                        case_id,
                        needle.then_some("%a%"),
                        contact.then_some("a"),
                    )
                    .await?;
                }
            }
        }
    }

    drop(pool);
    Ok(())
}
