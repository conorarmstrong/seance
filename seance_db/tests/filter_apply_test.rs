//! BUG-270: applying a filter must search the whole case, not just the
//! top-level sources.
//!
//! The predefined filters ("All Graphics", "Deleted Files", "Large Files", …)
//! test `FileEntry` fields that only exist deep in the tree. Evaluating only
//! `parent_id IS NULL` rows reported zero matches on evidence full of hits —
//! a silent false negative in triage.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::filter::{FilterCondition, FilterOp};
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn mem_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

async fn insert(
    db: &SqliteConnection,
    case_id: Uuid,
    parent_id: Option<Uuid>,
    artifact_type: ArtifactType,
    metadata: serde_json::Value,
) -> Result<Uuid> {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id,
        artifact_type,
        metadata,
        data: None,
    };
    let id = artifact.id;
    db.record_artifact(&artifact).await?;
    Ok(id)
}

fn jpg_filter() -> FilterCondition {
    FilterCondition::Simple {
        field: "extension".to_string(),
        operator: FilterOp::Eq,
        value: json!("jpg"),
    }
}

/// root(RawEvidence) -> FileSystem -> N FileEntries. Returns (fs_id, jpg ids).
async fn seed(db: &SqliteConnection, case_id: Uuid, jpgs: usize) -> Result<(Uuid, Vec<Uuid>)> {
    let root = insert(
        db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        json!({ "name": "disk.raw" }),
    )
    .await?;
    let fs = insert(
        db,
        case_id,
        Some(root),
        ArtifactType::FileSystem,
        json!({ "name": "ntfs" }),
    )
    .await?;
    let mut ids = Vec::new();
    for i in 0..jpgs {
        ids.push(
            insert(
                db,
                case_id,
                Some(fs),
                ArtifactType::FileEntry,
                json!({ "name": format!("photo_{i}.jpg"), "path": format!("/DCIM/photo_{i}.jpg") }),
            )
            .await?,
        );
    }
    // Non-matching noise at the same depth.
    insert(
        db,
        case_id,
        Some(fs),
        ArtifactType::FileEntry,
        json!({ "name": "notes.txt", "path": "/notes.txt" }),
    )
    .await?;
    Ok((fs, ids))
}

#[tokio::test]
async fn apply_without_parent_searches_the_whole_case() -> Result<()> {
    let db = mem_db().await?;
    let case_id = db.create_case("Filter", "Examiner").await?;
    let (_fs, jpgs) = seed(&db, case_id, 3).await?;

    let page = db
        .get_filtered_artifacts(case_id, None, &jpg_filter(), 100, 0)
        .await?;

    assert_eq!(page.total, 3, "every .jpg in the case must be found");
    assert!(page.scan_complete);
    let mut got: Vec<Uuid> = page.items.iter().map(|a| a.id).collect();
    got.sort();
    let mut want = jpgs;
    want.sort();
    assert_eq!(got, want);
    Ok(())
}

#[tokio::test]
async fn apply_paginates_over_the_case_wide_matches() -> Result<()> {
    let db = mem_db().await?;
    let case_id = db.create_case("Filter page", "Examiner").await?;
    seed(&db, case_id, 5).await?;

    let first = db
        .get_filtered_artifacts(case_id, None, &jpg_filter(), 2, 0)
        .await?;
    assert_eq!(first.total, 5, "total must count every match, not the page");
    assert_eq!(first.items.len(), 2);

    let last = db
        .get_filtered_artifacts(case_id, None, &jpg_filter(), 2, 4)
        .await?;
    assert_eq!(last.total, 5);
    assert_eq!(last.items.len(), 1, "the tail page holds the remainder");

    // The pages must not overlap.
    for a in &first.items {
        assert!(!last.items.iter().any(|b| b.id == a.id));
    }
    Ok(())
}

#[tokio::test]
async fn apply_with_explicit_parent_stays_scoped_to_that_level() -> Result<()> {
    let db = mem_db().await?;
    let case_id = db.create_case("Filter scoped", "Examiner").await?;
    let (fs, jpgs) = seed(&db, case_id, 2).await?;

    // Scoped to the filesystem: its direct children are the file entries.
    let scoped = db
        .get_filtered_artifacts(case_id, Some(fs), &jpg_filter(), 100, 0)
        .await?;
    assert_eq!(scoped.total, jpgs.len() as u64);

    // Scoped to a leaf with no children: no matches, and not an error.
    let leaf = db
        .get_filtered_artifacts(case_id, Some(jpgs[0]), &jpg_filter(), 100, 0)
        .await?;
    assert_eq!(leaf.total, 0);
    assert!(leaf.scan_complete);
    Ok(())
}

#[tokio::test]
async fn apply_does_not_cross_case_boundaries() -> Result<()> {
    let db = mem_db().await?;
    let case_a = db.create_case("A", "Examiner").await?;
    let case_b = db.create_case("B", "Examiner").await?;
    seed(&db, case_a, 2).await?;
    seed(&db, case_b, 7).await?;

    let page = db
        .get_filtered_artifacts(case_a, None, &jpg_filter(), 100, 0)
        .await?;
    assert_eq!(page.total, 2, "case B's files must not be counted");
    Ok(())
}

/// CR-047. SYNTHETIC: a `Not` chain 33 deep, one past the evaluator's limit.
/// Unvalidated it evaluates to `false` for every row, so the scan would return
/// `Ok` with no matches for a population the examiner never asked to be empty.
fn too_deep_filter() -> FilterCondition {
    let mut f = jpg_filter();
    for _ in 0..33 {
        f = FilterCondition::Not {
            condition: Box::new(f),
        };
    }
    f
}

#[tokio::test]
async fn a_filter_nested_past_the_limit_is_an_error_never_an_empty_result() -> Result<()> {
    let db = mem_db().await?;
    let case_id = db.create_case("Deep", "Examiner").await?;
    seed(&db, case_id, 2).await?;

    let page = db
        .get_filtered_artifacts(case_id, None, &too_deep_filter(), 100, 0)
        .await;
    let err = match page {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a too-deep filter is refused"),
    };
    assert!(err.contains("33"), "names the depth: {err}");

    let ids = db
        .filtered_artifact_ids(case_id, None, &too_deep_filter(), 1_000)
        .await;
    assert!(ids.is_err(), "filtered_artifact_ids must refuse it too");
    Ok(())
}
