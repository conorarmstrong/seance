//! Regression tests for the 2026-07-26 seance_db fixes:
//!
//! - BUG-083: recursive artifact CTEs must be scoped to a single case, so a
//!   corrupt/malicious cross-case `parent_id` (which has no FK enforcing
//!   same-case) can never inflate deletion impact, surface another case's
//!   files, purge the wrong search docs, or inflate per-source counts.
//! - BUG-125: `find_cached_media_thumbnail` must match `media_name` literally,
//!   so `_` (ubiquitous in iOS names like IMG_0001.MOV) is not a LIKE wildcard.
//! - BUG-078: `stream_export_timeline` must never return an unfiltered export
//!   when a search was requested but advanced parsing failed or yielded no
//!   predicate.
//! - BUG-079: `get_timeline_events_filtered` / `_count` must fall back to simple
//!   LIKE when advanced parsing succeeds but yields no predicate.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::{FileEntryFilters, FileListScope, SqliteConnection};
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

// ── BUG-083: cross-case parent_id must not leak across recursive CTEs ────────

#[tokio::test]
async fn deletion_impact_and_subtree_exclude_cross_case_child() -> Result<()> {
    let db = mem_db().await?;
    let case_a = db.create_case("A", "Examiner").await?;
    let case_b = db.create_case("B", "Examiner").await?;

    // Case A: fsA -> fileA.
    let fs_a = insert(
        &db,
        case_a,
        None,
        ArtifactType::FileSystem,
        json!({"name":"fsA"}),
    )
    .await?;
    let file_a = insert(
        &db,
        case_a,
        Some(fs_a),
        ArtifactType::FileEntry,
        json!({"name":"a.txt","path":"/a.txt"}),
    )
    .await?;

    // Case B artifact whose parent_id points INTO case A's subtree. parent_id
    // has no FK enforcing same-case, so this insert succeeds.
    let victim_b = insert(
        &db,
        case_b,
        Some(fs_a),
        ArtifactType::FileEntry,
        json!({"name":"victim.txt","path":"/victim.txt"}),
    )
    .await?;

    // Impact counts only case A's subtree {fsA, fileA} = 2, never victim_b.
    let (imp_artifacts, imp_events) = db.get_artifact_deletion_impact(fs_a).await?;
    assert_eq!(imp_artifacts, 2, "cross-case child must not inflate impact");
    assert_eq!(imp_events, 0);

    // Subtree ids are {fsA, fileA} only.
    let mut ids = db.subtree_artifact_ids(fs_a).await?;
    ids.sort();
    let mut want = vec![fs_a, file_a];
    want.sort();
    assert_eq!(ids, want, "subtree must not include cross-case child");
    assert!(!ids.contains(&victim_b), "cross-case child excluded");

    Ok(())
}

#[tokio::test]
async fn list_file_entries_subtree_excludes_cross_case_child() -> Result<()> {
    let db = mem_db().await?;
    let case_a = db.create_case("A", "Examiner").await?;
    let case_b = db.create_case("B", "Examiner").await?;

    let source_a = insert(
        &db,
        case_a,
        None,
        ArtifactType::RawEvidence,
        json!({"name":"disk"}),
    )
    .await?;
    insert(
        &db,
        case_a,
        Some(source_a),
        ArtifactType::FileEntry,
        json!({"name":"a.txt","path":"/a.txt"}),
    )
    .await?;
    // Case B FileEntry pointing at case A's source.
    insert(
        &db,
        case_b,
        Some(source_a),
        ArtifactType::FileEntry,
        json!({"name":"victim.txt","path":"/victim.txt"}),
    )
    .await?;

    let (rows, total) = db
        .list_file_entries(
            case_a,
            FileListScope::Subtree(source_a),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    assert_eq!(
        total, 1,
        "cross-case file must not surface in subtree listing"
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name.as_deref(), Some("a.txt"));

    Ok(())
}

#[tokio::test]
async fn counts_by_source_excludes_cross_case_child() -> Result<()> {
    let db = mem_db().await?;
    let case_a = db.create_case("A", "Examiner").await?;
    let case_b = db.create_case("B", "Examiner").await?;

    let root_a = insert(
        &db,
        case_a,
        None,
        ArtifactType::RawEvidence,
        json!({"name":"root"}),
    )
    .await?;
    insert(
        &db,
        case_a,
        Some(root_a),
        ArtifactType::FileEntry,
        json!({"name":"child"}),
    )
    .await?;
    // Cross-case descendant pointing into case A's root.
    insert(
        &db,
        case_b,
        Some(root_a),
        ArtifactType::FileEntry,
        json!({"name":"victim"}),
    )
    .await?;

    let counts = db.get_artifact_counts_by_source(case_a).await?;
    let root_count = counts
        .iter()
        .find(|(id, _)| *id == root_a)
        .map(|(_, n)| *n)
        .expect("root A present");
    assert_eq!(
        root_count, 1,
        "cross-case descendant must not inflate the count"
    );

    Ok(())
}

// ── BUG-125: cached-thumbnail LIKE must match media_name literally ──────────

#[tokio::test]
async fn cached_thumbnail_underscore_is_literal_not_wildcard() -> Result<()> {
    let db = mem_db().await?;
    let case_id = db.create_case("Thumb", "Examiner").await?;
    let source = insert(
        &db,
        case_id,
        None,
        ArtifactType::FileSystem,
        json!({"name":"backup"}),
    )
    .await?;

    // The media file the thumbnail is requested for.
    let media = insert(
        &db,
        case_id,
        Some(source),
        ArtifactType::FileEntry,
        json!({ "name": "IMG_0001.MOV", "relative_path": "Media/DCIM/100APPLE/IMG_0001.MOV" }),
    )
    .await?;

    // Correct match for "IMG_0001.MOV" (small size).
    let underscore = insert(
        &db,
        case_id,
        Some(source),
        ArtifactType::FileEntry,
        json!({
            "relative_path": "Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0001.MOV/5005.JPG",
            "is_directory": false,
            "size": 10,
        }),
    )
    .await?;
    // A different media where '_' is replaced by 'x'. If '_' were a wildcard this
    // would also match and, being larger, win the ORDER BY size DESC.
    insert(
        &db,
        case_id,
        Some(source),
        ArtifactType::FileEntry,
        json!({
            "relative_path": "Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMGx0001.MOV/9999.JPG",
            "is_directory": false,
            "size": 9999,
        }),
    )
    .await?;

    let found = db
        .find_cached_media_thumbnail(case_id, media, "IMG_0001.MOV")
        .await?;
    assert_eq!(
        found,
        Some(underscore),
        "underscore must match literally; the larger 'IMGx' decoy must not win"
    );

    Ok(())
}

// ── BUG-280: a cached thumbnail must belong to the REQUESTED file ────────────

#[tokio::test]
async fn cached_thumbnail_is_bound_to_the_requesting_artifact() -> Result<()> {
    let db = mem_db().await?;
    let case_id = db.create_case("Thumb scope", "Examiner").await?;

    // Two imports of the same phone, each with an IMG_0001.MOV.
    let import_a = insert(
        &db,
        case_id,
        None,
        ArtifactType::FileSystem,
        json!({"name":"import-a"}),
    )
    .await?;
    let import_b = insert(
        &db,
        case_id,
        None,
        ArtifactType::FileSystem,
        json!({"name":"import-b"}),
    )
    .await?;

    let media_a = insert(
        &db,
        case_id,
        Some(import_a),
        ArtifactType::FileEntry,
        json!({ "name": "IMG_0001.MOV", "relative_path": "Media/DCIM/100APPLE/IMG_0001.MOV" }),
    )
    .await?;
    let thumb_a = insert(
        &db,
        case_id,
        Some(import_a),
        ArtifactType::FileEntry,
        json!({
            "relative_path": "Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0001.MOV/5005.JPG",
            "is_directory": false,
            "size": 10,
        }),
    )
    .await?;
    // Same basename in the other import, and larger, so a basename-only lookup
    // would prefer it.
    insert(
        &db,
        case_id,
        Some(import_b),
        ArtifactType::FileEntry,
        json!({
            "relative_path": "Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0001.MOV/9999.JPG",
            "is_directory": false,
            "size": 9999,
        }),
    )
    .await?;

    assert_eq!(
        db.find_cached_media_thumbnail(case_id, media_a, "IMG_0001.MOV")
            .await?,
        Some(thumb_a),
        "the thumbnail must come from the requesting file's own source"
    );

    // A different file whose basename collides but whose path does not: the
    // cache directory mirrors the media's path, so no thumbnail is bound.
    let media_c = insert(
        &db,
        case_id,
        Some(import_a),
        ArtifactType::FileEntry,
        json!({ "name": "IMG_0001.MOV", "relative_path": "Media/DCIM/101APPLE/IMG_0001.MOV" }),
    )
    .await?;
    assert_eq!(
        db.find_cached_media_thumbnail(case_id, media_c, "IMG_0001.MOV")
            .await?,
        None,
        "a different directory must not inherit another file's cached thumbnail"
    );

    // An artifact from another case is never resolved at all.
    let other_case = db.create_case("Other", "Examiner").await?;
    assert_eq!(
        db.find_cached_media_thumbnail(other_case, media_a, "IMG_0001.MOV")
            .await?,
        None
    );

    Ok(())
}

// ── BUG-078: export must never be unfiltered when a search was requested ────

fn timeline_event(case: Uuid, ts: i64, short_desc: &str) -> Artifact {
    Artifact::new(
        case,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": ts,
            "timestamp_desc": "Created",
            "source_module": "test.module",
            "short_desc": short_desc,
            "full_details": "{}",
        }),
    )
}

async fn drain_export(
    mut rx: tokio::sync::mpsc::Receiver<
        std::result::Result<seance_core::models::TimelineEventResponse, String>,
    >,
) -> Vec<seance_core::models::TimelineEventResponse> {
    let mut out = Vec::new();
    while let Some(item) = rx.recv().await {
        out.push(item.expect("export row must be Ok"));
    }
    out
}

#[tokio::test]
async fn export_falls_back_on_advanced_parse_failure() -> Result<()> {
    let db = mem_db().await?;
    let case = db.create_case("Export", "Examiner").await?;
    // ":" triggers advanced mode; "alpha:" parses to an invalid column filter
    // (empty value) -> parse error -> must fall back to simple LIKE "%alpha:%".
    db.record_artifacts_batch(&[
        timeline_event(case, 100, "alpha:bravo marker"),
        timeline_event(case, 200, "charlie delta"),
    ])
    .await?;

    let events = drain_export(db.stream_export_timeline(
        case,
        None,
        None,
        None,
        Some("alpha:".into()),
        None,
        None,
        None,
    ))
    .await;
    assert_eq!(
        events.len(),
        1,
        "parse-failing search must still filter export"
    );
    assert_eq!(events[0].short_desc, "alpha:bravo marker");

    Ok(())
}

#[tokio::test]
async fn export_falls_back_on_empty_advanced_predicate() -> Result<()> {
    let db = mem_db().await?;
    let case = db.create_case("Export", "Examiner").await?;
    // "-" triggers advanced mode and parses OK but yields no predicate -> must
    // fall back to simple LIKE "%-%".
    db.record_artifacts_batch(&[
        timeline_event(case, 100, "alpha-bravo"),
        timeline_event(case, 200, "charlie delta"),
    ])
    .await?;

    let events = drain_export(db.stream_export_timeline(
        case,
        None,
        None,
        None,
        Some("-".into()),
        None,
        None,
        None,
    ))
    .await;
    assert_eq!(
        events.len(),
        1,
        "empty-predicate search must still filter export"
    );
    assert_eq!(events[0].short_desc, "alpha-bravo");

    Ok(())
}

// ── BUG-079: filtered/count must fall back when advanced yields no predicate ─

#[tokio::test]
async fn filtered_and_count_fall_back_on_empty_advanced_predicate() -> Result<()> {
    let db = mem_db().await?;
    let case = db.create_case("Filt", "Examiner").await?;
    db.record_artifacts_batch(&[
        timeline_event(case, 100, "alpha-bravo"),
        timeline_event(case, 200, "charlie delta"),
    ])
    .await?;

    // "-" -> advanced mode, parses to empty predicate -> simple LIKE "%-%".
    let events = db
        .get_timeline_events_filtered(
            case,
            None,
            None,
            None,
            Some("-"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(
        events.len(),
        1,
        "empty-predicate search must still filter rows"
    );
    assert_eq!(events[0].short_desc, "alpha-bravo");

    let count = db
        .get_timeline_events_count(case, None, None, None, Some("-"), None, None, None)
        .await?;
    assert_eq!(
        count, 1,
        "empty-predicate search must still filter the count"
    );

    Ok(())
}
