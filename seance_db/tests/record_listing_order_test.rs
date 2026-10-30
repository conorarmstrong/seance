//! `list_records_by_type` has always ordered `created_at ASC, id ASC`, and every
//! caller that caps its paging therefore reads the OLDEST-INGESTED rows.
//!
//! On a 78,237-record chat store the correlation and comms pages load 2,000
//! records per type and then present them "newest first" — newest within the
//! earliest-ingested 2,000, which can exclude every genuinely recent message in
//! the case. The ascending order is load-bearing for the callers that page all
//! the way through (a stable total order is what stops a row appearing on two
//! pages or none), so it stays the default and the direction becomes an
//! explicit argument instead.
//!
//! `created_at` is INGEST time, not the record's own event time. These tests are
//! deliberately written in those words: a newest-first listing returns the
//! most-recently-INGESTED rows, and no caller may present that as "the most
//! recent messages".

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::{RecordOrder, SqliteConnection};
use serde_json::json;
use std::collections::HashSet;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Order", "Examiner").await?;
    Ok((db, case_id))
}

/// Ingest `n` records tagged `batch`, in a batch of their own so they share one
/// `created_at` that is strictly later than any earlier batch's.
async fn ingest_batch(
    db: &SqliteConnection,
    case_id: Uuid,
    batch: &str,
    n: usize,
) -> Result<Vec<Uuid>> {
    let artifacts: Vec<Artifact> = (0..n)
        .map(|i| Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type: ArtifactType::ParsedRecord,
            metadata: json!({"type": "WhatsApp", "batch": batch, "seq": i}),
            data: None,
        })
        .collect();
    let ids = artifacts.iter().map(|a| a.id).collect();
    db.record_artifacts_batch(&artifacts).await?;
    // `record_artifacts_batch` stamps one `created_at` per call, so batches must
    // be separated in time for their relative order to mean anything.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    Ok(ids)
}

fn batches_of(records: &[Artifact]) -> Vec<String> {
    records
        .iter()
        .map(|r| r.metadata["batch"].as_str().unwrap_or("?").to_string())
        .collect()
}

/// The existing contract, unchanged: callers that page the whole match set (the
/// system-info and analyze-category loops, the memory stage reader) keep the
/// stable ascending order they were written against.
#[tokio::test]
async fn the_default_listing_stays_oldest_ingest_first() -> Result<()> {
    let (db, case_id) = setup().await?;
    ingest_batch(&db, case_id, "old", 3).await?;
    ingest_batch(&db, case_id, "new", 3).await?;

    let (page, total) = db
        .list_records_by_type(case_id, "WhatsApp", None, 1, 3)
        .await?;
    assert_eq!(total, 6);
    assert_eq!(batches_of(&page), vec!["old", "old", "old"]);

    let (explicit, _) = db
        .list_records_by_type_ordered(
            case_id,
            "WhatsApp",
            None,
            1,
            3,
            RecordOrder::OldestIngestedFirst,
        )
        .await?;
    assert_eq!(batches_of(&explicit), vec!["old", "old", "old"]);

    Ok(())
}

/// The fix LIVE-024 needs from this layer: a caller that can only afford N rows
/// can ask for the N most recently ingested ones instead of the N oldest.
#[tokio::test]
async fn a_newest_first_listing_returns_the_most_recently_ingested_records() -> Result<()> {
    let (db, case_id) = setup().await?;
    ingest_batch(&db, case_id, "old", 3).await?;
    ingest_batch(&db, case_id, "new", 3).await?;

    let (page, total) = db
        .list_records_by_type_ordered(
            case_id,
            "WhatsApp",
            None,
            1,
            3,
            RecordOrder::NewestIngestedFirst,
        )
        .await?;

    assert_eq!(total, 6, "the count is of the match set, not of the page");
    assert_eq!(batches_of(&page), vec!["new", "new", "new"]);

    Ok(())
}

/// The order must stay a TOTAL order under either direction, or a caller paging
/// to the end loses rows to the page boundary. `created_at` alone is not one:
/// a whole batch shares a timestamp, so `id` is the tiebreaker and it must
/// reverse with the timestamp.
#[tokio::test]
async fn paging_newest_first_covers_the_whole_match_set_exactly_once() -> Result<()> {
    let (db, case_id) = setup().await?;
    let mut expected: HashSet<Uuid> = HashSet::new();
    for batch in ["a", "b", "c"] {
        expected.extend(ingest_batch(&db, case_id, batch, 7).await?);
    }

    let mut seen: Vec<Uuid> = Vec::new();
    for page in 1..=5u32 {
        let (rows, total) = db
            .list_records_by_type_ordered(
                case_id,
                "WhatsApp",
                None,
                page,
                5,
                RecordOrder::NewestIngestedFirst,
            )
            .await?;
        assert_eq!(total, 21);
        seen.extend(rows.iter().map(|r| r.id));
    }

    assert_eq!(seen.len(), 21, "no row appeared twice or went missing");
    assert_eq!(seen.iter().copied().collect::<HashSet<_>>(), expected);

    // The last batch ingested comes back first.
    let (first_page, _) = db
        .list_records_by_type_ordered(
            case_id,
            "WhatsApp",
            None,
            1,
            5,
            RecordOrder::NewestIngestedFirst,
        )
        .await?;
    assert!(first_page.iter().all(|r| r.metadata["batch"] == json!("c")));

    Ok(())
}

/// The source-scoped variant walks a subtree before it orders; the direction has
/// to survive that too, or the memory views would silently keep the old order.
#[tokio::test]
async fn a_scoped_listing_honours_the_requested_direction() -> Result<()> {
    let (db, case_id) = setup().await?;

    let source = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::RawEvidence,
        metadata: json!({"name": "image.dd"}),
        data: None,
    };
    db.record_artifact(&source).await?;

    for batch in ["old", "new"] {
        let children: Vec<Artifact> = (0..3)
            .map(|i| Artifact {
                id: Uuid::new_v4(),
                case_id,
                parent_id: Some(source.id),
                artifact_type: ArtifactType::ParsedRecord,
                metadata: json!({"type": "WhatsApp", "batch": batch, "seq": i}),
                data: None,
            })
            .collect();
        db.record_artifacts_batch(&children).await?;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let (asc, total) = db
        .list_records_by_type(case_id, "WhatsApp", Some(source.id), 1, 3)
        .await?;
    assert_eq!(total, 6);
    assert_eq!(batches_of(&asc), vec!["old", "old", "old"]);

    let (desc, total) = db
        .list_records_by_type_ordered(
            case_id,
            "WhatsApp",
            Some(source.id),
            1,
            3,
            RecordOrder::NewestIngestedFirst,
        )
        .await?;
    assert_eq!(total, 6);
    assert_eq!(batches_of(&desc), vec!["new", "new", "new"]);

    Ok(())
}
