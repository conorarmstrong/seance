//! Recursive artifact deletion must remove the whole subtree and all dependent
//! rows (timeline events/tags, processing log) in one shot, leaving unrelated
//! cases untouched. Guards the N+1 -> recursive-CTE rewrite: same rows deleted,
//! same counts returned.

mod common;

use anyhow::Result;
use common::file_db;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

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

#[tokio::test]
async fn delete_removes_whole_subtree_and_dependents_only() -> Result<()> {
    let (db, path) = file_db().await?;
    let case = db.create_case("Del", "Examiner").await?;

    // Subtree: fs -> {fileA -> event; fileB}
    let fs = child(
        &db,
        case,
        ArtifactType::FileSystem,
        None,
        json!({"name":"ntfs"}),
    )
    .await;
    let file_a = child(
        &db,
        case,
        ArtifactType::FileEntry,
        Some(fs),
        json!({"name":"a.txt","path":"/a.txt"}),
    )
    .await;
    let _file_b = child(
        &db,
        case,
        ArtifactType::FileEntry,
        Some(fs),
        json!({"name":"b.txt","path":"/b.txt"}),
    )
    .await;
    let event = child(
        &db,
        case,
        ArtifactType::TimelineEvent,
        Some(file_a),
        json!({
            "timestamp": 1_700_000_000,
            "timestamp_desc": "Created",
            "source_module": "test",
            "short_desc": "a.txt created",
            "full_details": "{}",
        }),
    )
    .await;

    // A tag on the event and a processing-log row on file_a.
    db.create_timeline_tag(case, event, None, Some("note"))
        .await?;
    db.record_processing_log_batch(&[seance_core::db::ProcessingLogRow::single(
        case,
        file_a,
        "plugin.test".to_string(),
        "complete".to_string(),
        1,
        None,
        5,
    )])
    .await?;

    // An unrelated sibling subtree in the SAME case that must survive.
    let survivor = child(
        &db,
        case,
        ArtifactType::FileSystem,
        None,
        json!({"name":"survivor"}),
    )
    .await;

    // Impact preview and delete must agree: 4 artifacts (fs, fileA, fileB, event).
    let (imp_artifacts, imp_events) = db.get_artifact_deletion_impact(fs).await?;
    assert_eq!(imp_artifacts, 4, "impact artifact count");
    assert_eq!(imp_events, 1, "impact timeline-event count");

    let (del_artifacts, del_events) = db.delete_artifact_recursive(case, fs).await?;
    assert_eq!(del_artifacts, 4, "deleted artifact count");
    assert_eq!(del_events, 1, "deleted timeline-event count");

    // Everything in the subtree is gone; the survivor and its row remain.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    let count = |sql: String| {
        let pool = pool.clone();
        async move {
            sqlx::query(&sql)
                .fetch_one(&pool)
                .await
                .unwrap()
                .get::<i64, _>("n")
        }
    };

    let fs_hex = fs.simple().to_string();
    let survivor_hex = survivor.simple().to_string();
    assert_eq!(
        count(format!(
            "SELECT COUNT(*) n FROM artifacts WHERE id = X'{fs_hex}'"
        ))
        .await,
        0,
        "root deleted"
    );
    assert_eq!(
        count("SELECT COUNT(*) n FROM timeline_events".to_string()).await,
        0,
        "timeline events gone"
    );
    assert_eq!(
        count("SELECT COUNT(*) n FROM timeline_tags".to_string()).await,
        0,
        "timeline tags gone"
    );
    assert_eq!(
        count("SELECT COUNT(*) n FROM processing_log".to_string()).await,
        0,
        "processing log gone"
    );
    assert_eq!(
        count(format!(
            "SELECT COUNT(*) n FROM artifacts WHERE id = X'{survivor_hex}'"
        ))
        .await,
        1,
        "unrelated artifact survives"
    );

    Ok(())
}

#[tokio::test]
async fn subtree_ids_returns_root_and_all_descendants() -> Result<()> {
    let (db, _path) = file_db().await?;
    let case = db.create_case("Sub", "Examiner").await?;

    // fs -> {a -> a1; b}
    let fs = child(
        &db,
        case,
        ArtifactType::FileSystem,
        None,
        json!({"name":"fs"}),
    )
    .await;
    let a = child(
        &db,
        case,
        ArtifactType::FileEntry,
        Some(fs),
        json!({"name":"a"}),
    )
    .await;
    let a1 = child(
        &db,
        case,
        ArtifactType::ParsedRecord,
        Some(a),
        json!({"name":"a1"}),
    )
    .await;
    let b = child(
        &db,
        case,
        ArtifactType::FileEntry,
        Some(fs),
        json!({"name":"b"}),
    )
    .await;
    // An unrelated root that must NOT be in the subtree.
    let other = child(
        &db,
        case,
        ArtifactType::FileSystem,
        None,
        json!({"name":"other"}),
    )
    .await;

    let mut ids = db.subtree_artifact_ids(fs).await?;
    ids.sort();
    let mut want = vec![fs, a, a1, b];
    want.sort();
    assert_eq!(ids, want, "subtree is root + all descendants");
    assert!(!ids.contains(&other), "unrelated root excluded");

    Ok(())
}

#[tokio::test]
async fn delete_handles_a_wide_subtree() -> Result<()> {
    // Many direct children exercise the set-wise delete (the old path issued
    // ~4 statements per child).
    let (db, _path) = file_db().await?;
    let case = db.create_case("Wide", "Examiner").await?;
    let root = child(
        &db,
        case,
        ArtifactType::FileSystem,
        None,
        json!({"name":"root"}),
    )
    .await;
    for i in 0..300 {
        child(
            &db,
            case,
            ArtifactType::FileEntry,
            Some(root),
            json!({"name": format!("f{i}"), "path": format!("/f{i}")}),
        )
        .await;
    }

    let (n, _) = db.delete_artifact_recursive(case, root).await?;
    assert_eq!(n, 301, "root + 300 children deleted");

    Ok(())
}

/// B5-025: the delete/subtree/impact walks used `UNION ALL` while the browse
/// walk used `UNION`. A cyclic same-case `parent_id` — corrupt evidence, or an
/// adversarial one — makes an ALL walk re-add ids until SQLite aborts the
/// recursion, so DELETE fails outright while browse still shows the subtree.
/// The two views of the same case then disagree about what exists.
#[tokio::test]
async fn a_cyclic_parent_link_does_not_break_delete_or_the_subtree_walk() -> Result<()> {
    let (db, path) = file_db().await?;
    let case = db.create_case("Cycle", "Examiner").await?;

    let root = child(
        &db,
        case,
        ArtifactType::FileSystem,
        None,
        json!({"name":"root"}),
    )
    .await;
    let a = child(
        &db,
        case,
        ArtifactType::FileEntry,
        Some(root),
        json!({"name":"a","path":"/a"}),
    )
    .await;
    let b = child(
        &db,
        case,
        ArtifactType::FileEntry,
        Some(a),
        json!({"name":"b","path":"/a/b"}),
    )
    .await;

    // Close the loop: a's parent becomes its own descendant b, so a -> b -> a
    // inside the same case.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
    sqlx::query("UPDATE artifacts SET parent_id = ? WHERE id = ?")
        .bind(b.as_bytes().to_vec())
        .bind(a.as_bytes().to_vec())
        .execute(&pool)
        .await?;
    pool.close().await;

    // The subtree walk must terminate and name every reachable artifact once.
    let mut ids = db.subtree_artifact_ids(a).await?;
    ids.sort();
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(
        ids, want,
        "a cyclic parent link must not duplicate or lose subtree members"
    );

    // The impact preview must terminate too.
    let (impact, _) = db.get_artifact_deletion_impact(a).await?;
    assert_eq!(impact, 2, "deletion impact must count each artifact once");

    // And the delete itself must succeed rather than exhausting recursion.
    let (n, _) = db.delete_artifact_recursive(case, a).await?;
    assert_eq!(n, 2, "both artifacts in the cycle deleted");

    Ok(())
}
