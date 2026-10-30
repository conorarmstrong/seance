//! A source-scoped record listing must cost one recursive subtree walk per
//! page, and must answer with exactly the rows the unscoped listing would.
//!
//! The walk is the whole cost of `list_records_by_type` when a scope is given:
//! it visits every artifact under the scope. Running it twice per page -- once
//! to COUNT, once to read the window -- doubled that, and the memory endpoints
//! page the same scope dozens of times per request, so `/memory/coverage` on a
//! 512 MiB capture never returned at all. Nothing about the answers was wrong;
//! they were simply unreachable, which is why no correctness test caught it.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn test_db() -> SqliteConnection {
    let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
    db.initialize().await.unwrap();
    db
}

/// A `MemoryImage`-shaped scope artifact with `count` records hanging off it.
async fn image_with_records(
    db: &SqliteConnection,
    case_id: Uuid,
    record_type: &str,
    count: usize,
) -> Uuid {
    let image = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({"type": "MemoryImage", "name": "capture.raw"}),
    );
    db.record_artifact(&image).await.unwrap();

    for i in 0..count {
        let record = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"type": record_type, "pid": i}),
        )
        .with_parent(image.id);
        db.record_artifact(&record).await.unwrap();
    }
    image.id
}

#[tokio::test]
async fn a_scoped_record_page_walks_the_subtree_once_not_once_per_statement() {
    let db = test_db().await;
    let case_id = db.create_case("Memory", "Examiner").await.unwrap();
    let image = image_with_records(&db, case_id, "MemoryProcess", 10).await;

    let before = db.scoped_record_walks();
    let (records, total) = db
        .list_records_by_type(case_id, "MemoryProcess", Some(image), 1, 4)
        .await
        .unwrap();

    assert_eq!(records.len(), 4, "the page is the page size");
    assert_eq!(total, 10, "the count is the whole match set, not the page");
    assert_eq!(
        db.scoped_record_walks() - before,
        1,
        "the count must ride along with the page: a second walk here is paid \
         again on every page, and the memory views page dozens of times"
    );
}

#[tokio::test]
async fn a_scoped_record_listing_returns_the_same_rows_as_the_unscoped_one() {
    let db = test_db().await;
    let case_id = db.create_case("Memory", "Examiner").await.unwrap();
    let image = image_with_records(&db, case_id, "MemoryProcess", 7).await;

    let (scoped, scoped_total) = db
        .list_records_by_type(case_id, "MemoryProcess", Some(image), 1, 100)
        .await
        .unwrap();
    let (unscoped, unscoped_total) = db
        .list_records_by_type(case_id, "MemoryProcess", None, 1, 100)
        .await
        .unwrap();

    assert_eq!(scoped_total, unscoped_total);
    assert_eq!(
        scoped.iter().map(|a| a.id).collect::<Vec<_>>(),
        unscoped.iter().map(|a| a.id).collect::<Vec<_>>(),
        "scoping to the only image in the case must not change the answer"
    );
}

#[tokio::test]
async fn a_scoped_record_listing_never_reaches_another_images_records() {
    let db = test_db().await;
    let case_id = db.create_case("Memory", "Examiner").await.unwrap();
    let first = image_with_records(&db, case_id, "MemoryProcess", 3).await;
    let second = image_with_records(&db, case_id, "MemoryProcess", 5).await;

    let (records, total) = db
        .list_records_by_type(case_id, "MemoryProcess", Some(first), 1, 100)
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(records.len(), 3);
    for record in &records {
        assert_eq!(
            record.parent_id,
            Some(first),
            "a process list is a statement about one capture"
        );
    }

    let (_, second_total) = db
        .list_records_by_type(case_id, "MemoryProcess", Some(second), 1, 100)
        .await
        .unwrap();
    assert_eq!(second_total, 5);
}

#[tokio::test]
async fn a_scoped_page_past_the_end_still_reports_the_true_total() {
    let db = test_db().await;
    let case_id = db.create_case("Memory", "Examiner").await.unwrap();
    let image = image_with_records(&db, case_id, "MemoryProcess", 3).await;

    let (records, total) = db
        .list_records_by_type(case_id, "MemoryProcess", Some(image), 9, 10)
        .await
        .unwrap();

    assert!(records.is_empty());
    assert_eq!(
        total, 3,
        "an empty page is 'you asked past the end', never 'there are none'"
    );
}

#[tokio::test]
async fn a_scoped_listing_of_a_type_with_no_records_reports_zero_in_one_walk() {
    let db = test_db().await;
    let case_id = db.create_case("Memory", "Examiner").await.unwrap();
    let image = image_with_records(&db, case_id, "MemoryProcess", 2).await;

    let before = db.scoped_record_walks();
    let (records, total) = db
        .list_records_by_type(case_id, "MemoryNetworkConnection", Some(image), 1, 10)
        .await
        .unwrap();

    assert!(records.is_empty());
    assert_eq!(total, 0);
    assert_eq!(
        db.scoped_record_walks() - before,
        1,
        "an empty first page IS the count; the coverage view asks this of every \
         stage that did not run, and a confirming walk each time is what it cost"
    );
}
