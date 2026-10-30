//! The `parent_id` subtree walks must reach the bottom of a deeply nested
//! source, and must terminate on a cyclic `parent_id`.
//!
//! These walks used to stop at `depth < 32` with no signal that they had. A
//! file inside an archive inside an archive inside a disk image dropped out of
//! the browse listing, out of the per-type record counts, out of the directory
//! size treemap and out of the per-source artifact count at the same time --
//! so four independent views agreed on the same wrong answer and an examiner
//! had nothing to notice. "No such file in this evidence" is an argument made
//! in court; it must not be an artefact of a hard-coded recursion limit.

mod common;

use anyhow::Result;
use common::file_db;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::{FileEntryFilters, FileListScope, SqliteConnection};
use serde_json::json;
use uuid::Uuid;

/// How deep the chain of nested containers runs. Comfortably past the old
/// depth-32 ceiling so the test fails against the capped implementation.
const CHAIN_DEPTH: usize = 40;

async fn child(
    db: &SqliteConnection,
    case: Uuid,
    ty: ArtifactType,
    parent: Option<Uuid>,
    meta: serde_json::Value,
) -> Uuid {
    let mut a = Artifact::new(case, ty, None, meta);
    if let Some(p) = parent {
        a = a.with_parent(p);
    }
    db.record_artifact(&a).await.unwrap();
    a.id
}

/// Build: root -> 40 nested FileEntry "containers" -> one leaf file at the
/// bottom, plus one ParsedRecord hanging off the leaf. Returns (root, leaf).
async fn nested_chain(db: &SqliteConnection, case: Uuid) -> (Uuid, Uuid) {
    let root = child(
        db,
        case,
        ArtifactType::FileSystem,
        None,
        json!({"name": "ntfs"}),
    )
    .await;

    let mut parent = root;
    let mut path = String::from("/nest");
    for level in 0..CHAIN_DEPTH {
        path = format!("{path}/l{level}");
        parent = child(
            db,
            case,
            ArtifactType::FileEntry,
            Some(parent),
            json!({
                "name": format!("l{level}"),
                "path": path,
                "is_directory": true,
                "size": 0,
            }),
        )
        .await;
    }

    let leaf = child(
        db,
        case,
        ArtifactType::FileEntry,
        Some(parent),
        json!({
            "name": "buried.txt",
            "path": format!("{path}/buried.txt"),
            "is_directory": false,
            "size": 4096,
        }),
    )
    .await;

    child(
        db,
        case,
        ArtifactType::ParsedRecord,
        Some(leaf),
        json!({"type": "BuriedRecord", "name": "buried record"}),
    )
    .await;

    (root, leaf)
}

#[tokio::test]
async fn a_file_nested_past_the_old_depth_ceiling_is_still_listed() -> Result<()> {
    let (db, _path) = file_db().await?;
    let case = db.create_case("Deep", "Examiner").await?;
    let (root, leaf) = nested_chain(&db, case).await;

    let (rows, total) = db
        .list_file_entries(
            case,
            FileListScope::Subtree(root),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            5000,
            false,
        )
        .await?;

    assert_eq!(
        total,
        CHAIN_DEPTH as i64 + 1,
        "every nested container plus the buried file must be counted"
    );
    assert!(
        rows.iter().any(|r| r.id == leaf),
        "the file at depth {} is missing from the listing: a browse view that \
         silently omits it reads as evidence the file was never there",
        CHAIN_DEPTH + 1
    );
    assert!(
        !rows.iter().any(|r| r.id == root),
        "the scope artifact itself is not one of its own files"
    );

    Ok(())
}

#[tokio::test]
async fn a_record_nested_past_the_old_depth_ceiling_is_still_counted() -> Result<()> {
    let (db, _path) = file_db().await?;
    let case = db.create_case("Deep", "Examiner").await?;
    let (root, _leaf) = nested_chain(&db, case).await;

    let (records, total) = db
        .list_records_by_type(case, "BuriedRecord", Some(root), 1, 100)
        .await?;

    assert_eq!(
        total, 1,
        "a parsed record below the old depth ceiling must still be counted"
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].metadata["type"], "BuriedRecord");

    Ok(())
}

#[tokio::test]
async fn deeply_nested_bytes_still_reach_the_directory_treemap() -> Result<()> {
    let (db, _path) = file_db().await?;
    let case = db.create_case("Deep", "Examiner").await?;
    let (root, _leaf) = nested_chain(&db, case).await;

    // "/nest" is the first path segment; its aggregate size must include the
    // 4 KiB file buried 40 levels down.
    let children = db.get_dir_children_sizes(case, root, "").await?;
    let nest = children
        .iter()
        .find(|c| c.name == "nest")
        .expect("the top-level directory must appear in the treemap");

    assert_eq!(
        nest.total_size, 4096,
        "the treemap under-reports the directory: bytes below the old depth \
         ceiling were dropped from the aggregate"
    );
    assert_eq!(nest.file_count, 1);

    Ok(())
}

#[tokio::test]
async fn per_source_artifact_counts_include_deeply_nested_descendants() -> Result<()> {
    let (db, _path) = file_db().await?;
    let case = db.create_case("Deep", "Examiner").await?;
    let (root, _leaf) = nested_chain(&db, case).await;

    let counts = db.get_artifact_counts_by_source(case).await?;
    let (_, count) = counts
        .iter()
        .find(|(id, _)| *id == root)
        .expect("the root source must be counted");

    // CHAIN_DEPTH containers + the buried file + its parsed record.
    assert_eq!(
        *count,
        CHAIN_DEPTH as i64 + 2,
        "the source's artifact count stops short: descendants below the old \
         depth ceiling were never walked"
    );

    Ok(())
}

#[tokio::test]
async fn a_cyclic_parent_id_terminates_instead_of_looping_forever() -> Result<()> {
    // The depth cap was also standing in for cycle protection. Without it the
    // walk must still terminate, which is what UNION (not UNION ALL) buys.
    let (db, path) = file_db().await?;
    let case = db.create_case("Cycle", "Examiner").await?;

    let root = child(
        &db,
        case,
        ArtifactType::FileSystem,
        None,
        json!({"name": "ntfs"}),
    )
    .await;
    let a = child(
        &db,
        case,
        ArtifactType::FileEntry,
        Some(root),
        json!({"name": "a", "path": "/a", "size": 1}),
    )
    .await;
    let b = child(
        &db,
        case,
        ArtifactType::FileEntry,
        Some(a),
        json!({"name": "b", "path": "/a/b", "size": 1}),
    )
    .await;
    // Point A's parent back at B: a two-node cycle reachable from the root.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    sqlx::query("UPDATE artifacts SET parent_id = ? WHERE id = ?")
        .bind(b.as_bytes().to_vec())
        .bind(a.as_bytes().to_vec())
        .execute(&pool)
        .await?;
    pool.close().await;

    // If this walk did not terminate, the fix would have traded a silent
    // truncation for a hang. UNION refuses to re-add an id already in the
    // result, so the cycle closes after one lap.
    let (rows, total) = db
        .list_file_entries(
            case,
            FileListScope::Subtree(a),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            100,
            false,
        )
        .await?;

    // B is reachable from A exactly once; A itself is the scope, not a result.
    assert_eq!(total, 1);
    assert_eq!(rows[0].id, b);

    Ok(())
}
