//! Nested bookmark folders (ROADMAP §3.15).
//!
//! A folder may sit under another folder of the same case, to a bounded depth.
//! The refusals matter more than the happy path: a folder under another case's
//! folder would be deleted from underneath it, a cycle would make a branch
//! unreachable, and an unbounded chain is a walk with no end.

mod common;

use anyhow::Result;
use common::file_db;
use seance_core::db::DatabaseConnection;
use seance_db::{SqliteConnection, CATEGORY_DEPTH_MAX};
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Folders", "Examiner").await?;
    Ok((db, case_id))
}

async fn folder(db: &SqliteConnection, case: Uuid, name: &str, parent: Option<Uuid>) -> Uuid {
    db.create_bookmark_folder(case, name, None, parent)
        .await
        .unwrap()
        .unwrap_or_else(|r| panic!("{name} refused: {r:?}"))
}

#[tokio::test]
async fn a_folder_nests_under_another_folder_of_the_same_case() -> Result<()> {
    let (db, case) = setup().await?;
    let root = folder(&db, case, "Emails", None).await;
    let child = folder(&db, case, "Suspect", Some(root)).await;

    let listed = db.list_bookmark_categories(case).await?;
    let find = |id| listed.iter().find(|c| c.id == id).unwrap();
    assert_eq!(find(root).parent_id, None);
    assert_eq!(find(child).parent_id, Some(root));
    Ok(())
}

#[tokio::test]
async fn a_parent_from_another_case_or_that_does_not_exist_is_refused() -> Result<()> {
    let (db, case) = setup().await?;
    let other = db.create_case("Other", "Examiner").await?;
    let theirs = folder(&db, other, "Theirs", None).await;

    let foreign = db
        .create_bookmark_folder(case, "Child", None, Some(theirs))
        .await?;
    assert_eq!(foreign, Err(seance_db::FolderRefusal::ParentNotInCase));
    let unknown = db
        .create_bookmark_folder(case, "Child", None, Some(Uuid::new_v4()))
        .await?;
    assert_eq!(unknown, Err(seance_db::FolderRefusal::ParentNotInCase));
    assert!(db.list_bookmark_categories(case).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn nesting_is_bounded_in_depth() -> Result<()> {
    let (db, case) = setup().await?;
    let mut parent = None;
    for level in 1..=CATEGORY_DEPTH_MAX {
        parent = Some(folder(&db, case, &format!("level {level}"), parent).await);
    }
    let too_deep = db
        .create_bookmark_folder(case, "one too many", None, parent)
        .await?;
    assert_eq!(too_deep, Err(seance_db::FolderRefusal::TooDeep));
    Ok(())
}

#[tokio::test]
async fn a_folder_cannot_be_moved_under_itself_or_its_own_descendant() -> Result<()> {
    let (db, case) = setup().await?;
    let a = folder(&db, case, "A", None).await;
    let b = folder(&db, case, "B", Some(a)).await;
    let c = folder(&db, case, "C", Some(b)).await;

    assert_eq!(
        db.move_bookmark_folder(case, a, Some(a)).await?,
        Err(seance_db::FolderRefusal::Cycle)
    );
    assert_eq!(
        db.move_bookmark_folder(case, a, Some(c)).await?,
        Err(seance_db::FolderRefusal::Cycle),
        "a folder under its own descendant would be unreachable"
    );
    // A legitimate move: C to the top level, then B under C.
    assert_eq!(db.move_bookmark_folder(case, c, None).await?, Ok(()));
    assert_eq!(db.move_bookmark_folder(case, b, Some(c)).await?, Ok(()));
    let listed = db.list_bookmark_categories(case).await?;
    assert_eq!(
        listed.iter().find(|x| x.id == b).unwrap().parent_id,
        Some(c)
    );
    assert_eq!(listed.iter().find(|x| x.id == c).unwrap().parent_id, None);
    Ok(())
}

#[tokio::test]
async fn a_move_that_would_exceed_the_depth_is_refused() -> Result<()> {
    let (db, case) = setup().await?;
    let mut chain = None;
    for level in 1..=CATEGORY_DEPTH_MAX {
        chain = Some(folder(&db, case, &format!("deep {level}"), chain).await);
    }
    // A folder with its own child, moved under the bottom of a full chain.
    let top = folder(&db, case, "loose", None).await;
    let _under = folder(&db, case, "loose child", Some(top)).await;
    assert_eq!(
        db.move_bookmark_folder(case, top, chain).await?,
        Err(seance_db::FolderRefusal::TooDeep)
    );
    Ok(())
}

#[tokio::test]
async fn deleting_a_folder_leaves_its_subfolders_at_the_top_level() -> Result<()> {
    let (db, case) = setup().await?;
    let parent = folder(&db, case, "Parent", None).await;
    let child = folder(&db, case, "Child", Some(parent)).await;

    assert!(db.delete_bookmark_category(case, parent).await?);
    let listed = db.list_bookmark_categories(case).await?;
    assert_eq!(listed.len(), 1, "the subfolder survives");
    assert_eq!(listed[0].id, child);
    assert_eq!(listed[0].parent_id, None, "promoted to the top level");
    Ok(())
}

/// The cycle check and the write are one transaction: two moves that are each
/// valid against the tree as it was must not both land.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_opposite_moves_cannot_make_a_cycle() -> Result<()> {
    let (db, _path) = file_db().await?;
    let case = db.create_case("Race", "Examiner").await?;
    for i in 0..20 {
        let a = folder(&db, case, &format!("A{i}"), None).await;
        let b = folder(&db, case, &format!("B{i}"), None).await;
        let (d1, d2) = (db.clone(), db.clone());
        let t1 = tokio::spawn(async move { d1.move_bookmark_folder(case, a, Some(b)).await });
        let t2 = tokio::spawn(async move { d2.move_bookmark_folder(case, b, Some(a)).await });
        let (r1, r2) = (t1.await??, t2.await??);
        assert!(
            r1.is_ok() != r2.is_ok(),
            "exactly one move may land: {r1:?} / {r2:?}"
        );
        let loser = if r1.is_ok() { r2 } else { r1 };
        assert_eq!(loser, Err(seance_db::FolderRefusal::Cycle));
        let listed = db.list_bookmark_categories(case).await?;
        let find = |id| listed.iter().find(|c| c.id == id).unwrap().parent_id;
        assert!(
            find(a).is_none() || find(b).is_none(),
            "one of the two must still be at the top level"
        );
    }
    Ok(())
}
