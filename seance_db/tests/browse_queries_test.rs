//! Tests for SQL-side file browsing: generated columns (migration 0018),
//! paginated file listing, disk regions, per-source counts, and the
//! file size histogram.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::{FileEntryFilters, FileListScope, SqliteConnection};
use uuid::Uuid;

async fn setup_test_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

/// File-backed db so raw-SQL verification can open a second pool
/// (in-memory SQLite is per-connection). Mirrors seance_tests/src/db_tests.rs.
async fn setup_file_db() -> Result<(SqliteConnection, String)> {
    let db_name = format!("test_browse_{}.sqlite", Uuid::new_v4());
    let db = SqliteConnection::new(&format!("sqlite:{}?mode=rwc", db_name)).await?;
    db.initialize().await?;
    Ok((db, db_name))
}

fn teardown_file_db(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path));
    let _ = std::fs::remove_file(format!("{}-shm", path));
}

async fn insert_artifact(
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

async fn insert_file(
    db: &SqliteConnection,
    case_id: Uuid,
    parent_id: Uuid,
    metadata: serde_json::Value,
) -> Result<Uuid> {
    insert_artifact(
        db,
        case_id,
        Some(parent_id),
        ArtifactType::FileEntry,
        metadata,
    )
    .await
}

// ── Migration 0018: generated columns ────────────────────────────

#[tokio::test]
async fn generated_columns_extract_browse_fields() -> Result<()> {
    let (db, path) = setup_file_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({}),
    )
    .await?;

    let file_id = insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({
            "name": "report.pdf",
            "path": "/docs/report.pdf",
            "size": 2048,
            "is_directory": false,
            "deleted": true,
            "modified": "2026-01-02T03:04:05+00:00",
        }),
    )
    .await?;

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;

    let row = sqlx::query_as::<
        _,
        (
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        ),
    >(
        "SELECT name, path, size, is_directory, is_deleted, modified FROM artifacts WHERE id = ?",
    )
    .bind(file_id)
    .fetch_one(&pool)
    .await?;

    assert_eq!(row.0.as_deref(), Some("report.pdf"));
    assert_eq!(row.1.as_deref(), Some("/docs/report.pdf"));
    assert_eq!(row.2, Some(2048));
    assert_eq!(row.3, Some(0)); // JSON false extracts as 0
    assert_eq!(row.4, Some(1)); // JSON true extracts as 1
    assert_eq!(row.5.as_deref(), Some("2026-01-02T03:04:05+00:00"));

    // Keys absent from metadata_json extract as NULL
    let row = sqlx::query_as::<_, (Option<String>, Option<i64>, Option<i64>)>(
        "SELECT name, size, is_deleted FROM artifacts WHERE id = ?",
    )
    .bind(source_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(row, (None, None, None));

    pool.close().await;
    teardown_file_db(&path);
    Ok(())
}

// ── list_file_entries ─────────────────────────────────────────────

#[tokio::test]
async fn list_direct_children_only_returns_file_entries_at_level() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.dd"}),
    )
    .await?;

    let dir_id = insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "docs", "is_directory": true}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "a.txt", "size": 10}),
    )
    .await?;
    // Nested file must NOT appear in DirectChildren of source
    insert_file(
        &db,
        case_id,
        dir_id,
        serde_json::json!({"name": "nested.txt", "size": 20}),
    )
    .await?;
    // Non-FileEntry child must not appear
    insert_artifact(
        &db,
        case_id,
        Some(source_id),
        ArtifactType::Partition,
        serde_json::json!({"name": "part1"}),
    )
    .await?;

    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            50,
            false,
        )
        .await?;

    assert_eq!(total, 2);
    let names: Vec<_> = rows.iter().map(|r| r.name.as_deref().unwrap()).collect();
    assert_eq!(names, vec!["a.txt", "docs"]); // default sort: name ASC
    Ok(())
}

#[tokio::test]
async fn list_subtree_recurses_through_directories() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.dd"}),
    )
    .await?;

    let dir_id = insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "docs", "is_directory": true}),
    )
    .await?;
    let subdir_id = insert_file(
        &db,
        case_id,
        dir_id,
        serde_json::json!({"name": "sub", "is_directory": true}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        subdir_id,
        serde_json::json!({"name": "deep.txt", "size": 5}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "top.txt", "size": 1}),
    )
    .await?;

    // File in a different case must not leak in
    let other_case = db.create_case("Other", "Examiner").await?;
    let other_source = insert_artifact(
        &db,
        other_case,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "other.dd"}),
    )
    .await?;
    insert_file(
        &db,
        other_case,
        other_source,
        serde_json::json!({"name": "foreign.txt"}),
    )
    .await?;

    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::Subtree(source_id),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            50,
            false,
        )
        .await?;

    assert_eq!(total, 4);
    let names: Vec<_> = rows.iter().map(|r| r.name.as_deref().unwrap()).collect();
    assert_eq!(names, vec!["deep.txt", "docs", "sub", "top.txt"]);
    Ok(())
}

#[tokio::test]
async fn list_path_children_reconstructs_tree_from_paths() -> Result<()> {
    // Real parsers (ext4, MFT) store every file as a FLAT child of the
    // FileSystem artifact, encoding the hierarchy only in the `path` string.
    // PathChildren must rebuild each tree level from `path`, independent of
    // parent_id nesting.
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.E01"}),
    )
    .await?;
    let fs_id = insert_artifact(
        &db,
        case_id,
        Some(source_id),
        ArtifactType::FileSystem,
        serde_json::json!({"name": "ext4"}),
    )
    .await?;

    // Everything is a flat child of the FileSystem artifact; hierarchy is in path.
    for (path, is_dir) in [
        ("/bin", true),
        ("/bin/ls", false),
        ("/etc", true),
        ("/etc/hosts", false),
        ("/etc/init.d", true),
        ("/etc/init.d/rc", false),
        // Escape check: '_' must be treated literally, so /a_b's children must
        // not include /axb's children.
        ("/a_b", true),
        ("/a_b/inside", false),
        ("/axb", true),
        ("/axb/other", false),
    ] {
        let name = path.rsplit('/').next().unwrap();
        insert_file(
            &db,
            case_id,
            fs_id,
            serde_json::json!({"name": name, "path": path, "is_directory": is_dir}),
        )
        .await?;
    }

    // Root level: only the four top-level directories, no descendants.
    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::PathChildren(source_id, String::new()),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    assert_eq!(total, 4, "four top-level entries");
    let names: Vec<_> = rows.iter().map(|r| r.name.as_deref().unwrap()).collect();
    assert_eq!(names, vec!["a_b", "axb", "bin", "etc"]);

    // /etc level: hosts (file) and init.d (dir), but not /etc/init.d/rc.
    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::PathChildren(source_id, "/etc".to_string()),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    assert_eq!(total, 2);
    let names: Vec<_> = rows.iter().map(|r| r.name.as_deref().unwrap()).collect();
    assert_eq!(names, vec!["hosts", "init.d"]);

    // Escape check: /a_b has exactly one child; /axb is not confused for it.
    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::PathChildren(source_id, "/a_b".to_string()),
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
        "underscore is escaped, so /axb children are excluded"
    );
    assert_eq!(rows[0].name.as_deref(), Some("inside"));
    Ok(())
}

/// SQLite's LIKE folds ASCII case, so `/Users` and `/users` (distinct on a
/// case-sensitive filesystem) must not be merged by the prefix test.
#[tokio::test]
async fn path_children_and_treemap_keep_differently_cased_directories_apart() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.E01"}),
    )
    .await?;
    for (path, size) in [("/Users/x", 10), ("/users/y", 1000), ("/Users/z/deep", 5)] {
        let name = path.rsplit('/').next().unwrap();
        insert_file(
            &db,
            case_id,
            source_id,
            serde_json::json!({"name": name, "path": path, "size": size, "is_directory": false}),
        )
        .await?;
    }
    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::PathChildren(source_id, "/Users".to_string()),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    let names: Vec<_> = rows.iter().map(|r| r.name.as_deref().unwrap()).collect();
    assert_eq!(
        names,
        vec!["x"],
        "only /Users/x is a direct child of /Users"
    );
    assert_eq!(total, 1);

    let sizes = db
        .get_dir_children_sizes(case_id, source_id, "/Users")
        .await?;
    let total_size: i64 = sizes.iter().map(|c| c.total_size).sum();
    assert_eq!(total_size, 15, "/users/y must not be counted under /Users");
    Ok(())
}

#[tokio::test]
async fn list_file_entries_pagination_and_total() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.dd"}),
    )
    .await?;

    for i in 0..7 {
        insert_file(
            &db,
            case_id,
            source_id,
            serde_json::json!({"name": format!("file{}.txt", i), "size": i * 100}),
        )
        .await?;
    }

    let (page1, total) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters::default(),
            Some("name"),
            Some("asc"),
            1,
            3,
            false,
        )
        .await?;
    let (page3, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters::default(),
            Some("name"),
            Some("asc"),
            3,
            3,
            false,
        )
        .await?;

    assert_eq!(total, 7);
    assert_eq!(page1.len(), 3);
    assert_eq!(page3.len(), 1);
    assert_eq!(page1[0].name.as_deref(), Some("file0.txt"));
    assert_eq!(page3[0].name.as_deref(), Some("file6.txt"));

    // Page 0 clamps to page 1 rather than underflowing
    let (page0, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters::default(),
            Some("name"),
            Some("asc"),
            0,
            3,
            false,
        )
        .await?;
    assert_eq!(page0[0].name.as_deref(), Some("file0.txt"));
    Ok(())
}

#[tokio::test]
async fn list_file_entries_filters() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.dd"}),
    )
    .await?;

    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "Report.PDF", "size": 100}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "notes.txt", "size": 50, "deleted": true}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "docs", "is_directory": true}),
    )
    .await?;

    // name_contains is case-insensitive
    let (rows, total) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters {
                name_contains: Some("report".into()),
                ..Default::default()
            },
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    assert_eq!(total, 1);
    assert_eq!(rows[0].name.as_deref(), Some("Report.PDF"));

    // extension suffix match, case-insensitive
    let (rows, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters {
                extension: Some("pdf".into()),
                ..Default::default()
            },
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name.as_deref(), Some("Report.PDF"));

    // deleted_only
    let (rows, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters {
                deleted_only: true,
                ..Default::default()
            },
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name.as_deref(), Some("notes.txt"));
    assert!(rows[0].is_deleted);

    // directories: only
    let (rows, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters {
                directories: Some(true),
                ..Default::default()
            },
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].is_directory);

    // directories: exclude (files lacking the key count as non-directories)
    let (rows, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters {
                directories: Some(false),
                ..Default::default()
            },
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| !r.is_directory));
    Ok(())
}

#[tokio::test]
async fn list_file_entries_sorting_with_id_tiebreaker() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.dd"}),
    )
    .await?;

    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "b.txt", "size": 300, "modified": "2026-01-03T00:00:00+00:00"}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "a.txt", "size": 100, "modified": "2026-01-01T00:00:00+00:00"}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "c.txt", "size": 200, "modified": "2026-01-02T00:00:00+00:00"}),
    )
    .await?;

    let (rows, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters::default(),
            Some("size"),
            Some("desc"),
            1,
            50,
            false,
        )
        .await?;
    let sizes: Vec<_> = rows.iter().map(|r| r.size.unwrap()).collect();
    assert_eq!(sizes, vec![300, 200, 100]);

    let (rows, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters::default(),
            Some("modified"),
            Some("asc"),
            1,
            50,
            false,
        )
        .await?;
    let names: Vec<_> = rows.iter().map(|r| r.name.as_deref().unwrap()).collect();
    assert_eq!(names, vec!["a.txt", "c.txt", "b.txt"]);

    // Duplicate sort keys: paginating one row at a time must visit each row
    // exactly once (id tiebreaker keeps ordering stable).
    let dup_source = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk2.dd"}),
    )
    .await?;
    for _ in 0..5 {
        insert_file(
            &db,
            case_id,
            dup_source,
            serde_json::json!({"name": "same.txt", "size": 1}),
        )
        .await?;
    }
    let mut seen = std::collections::HashSet::new();
    for page in 1..=5u32 {
        let (rows, total) = db
            .list_file_entries(
                case_id,
                FileListScope::DirectChildren(dup_source),
                &FileEntryFilters::default(),
                Some("name"),
                Some("asc"),
                page,
                1,
                false,
            )
            .await?;
        assert_eq!(total, 5);
        assert_eq!(rows.len(), 1);
        assert!(seen.insert(rows[0].id), "row {} returned twice", rows[0].id);
    }
    Ok(())
}

#[tokio::test]
async fn list_file_entries_metadata_and_timestamps() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.dd"}),
    )
    .await?;

    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({
            "name": "a.txt",
            "created": "2026-01-01T00:00:00+00:00",
            "accessed": "2026-01-05T00:00:00+00:00",
            "extra": "kept",
        }),
    )
    .await?;

    // Lean payload: metadata_json excluded
    let (rows, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            50,
            false,
        )
        .await?;
    assert!(rows[0].metadata_json.is_none());
    assert_eq!(
        rows[0].created.as_deref(),
        Some("2026-01-01T00:00:00+00:00")
    );
    assert_eq!(
        rows[0].accessed.as_deref(),
        Some("2026-01-05T00:00:00+00:00")
    );
    assert_eq!(rows[0].parent_id, Some(source_id));

    // Full payload: metadata_json included
    let (rows, _) = db
        .list_file_entries(
            case_id,
            FileListScope::DirectChildren(source_id),
            &FileEntryFilters::default(),
            None,
            None,
            1,
            50,
            true,
        )
        .await?;
    let meta: serde_json::Value = serde_json::from_str(rows[0].metadata_json.as_deref().unwrap())?;
    assert_eq!(meta.get("extra").and_then(|v| v.as_str()), Some("kept"));
    Ok(())
}

// ── get_disk_regions ──────────────────────────────────────────────

#[tokio::test]
async fn disk_regions_returns_partitions_gaps_and_filesystems_by_offset() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let root_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.dd"}),
    )
    .await?;

    let part1 = insert_artifact(
        &db,
        case_id,
        Some(root_id),
        ArtifactType::Partition,
        serde_json::json!({
            "partition_scheme": "MBR",
            "partition_type_name": "NTFS",
            "name": "part1",
            "offset_bytes": 1048576u64,
            "size_bytes": 104857600u64,
        }),
    )
    .await?;
    insert_artifact(
        &db,
        case_id,
        Some(root_id),
        ArtifactType::UnallocatedSpace,
        serde_json::json!({
            "partition_scheme": "MBR",
            "offset_bytes": 512u64,
            "size_bytes": 1048064u64,
        }),
    )
    .await?;
    let fs = insert_artifact(
        &db,
        case_id,
        Some(part1),
        ArtifactType::FileSystem,
        serde_json::json!({
            "filesystem_type": "NTFS",
            "offset_bytes": 1048576u64,
            "size_bytes": 104857600u64,
        }),
    )
    .await?;

    // FileEntry under the filesystem must not appear
    insert_file(&db, case_id, fs, serde_json::json!({"name": "f.txt"})).await?;

    // Region-typed artifacts nested below the filesystem: an LVM/RAID volume
    // inside a partition, a container inside a container. The walk used to stop
    // at 3 parent links, so `deep` here vanished from the disk map with nothing
    // to say a region was missing. Depth must not decide whether a region is
    // shown.
    let d3 = insert_artifact(
        &db,
        case_id,
        Some(fs),
        ArtifactType::Partition,
        serde_json::json!({"offset_bytes": 999u64}),
    )
    .await?;
    let deep = insert_artifact(
        &db,
        case_id,
        Some(d3),
        ArtifactType::Partition,
        serde_json::json!({"offset_bytes": 998u64}),
    )
    .await?;

    let regions = db.get_disk_regions(case_id, root_id).await?;

    // gap, part1, fs, and BOTH nested partitions. The FileEntry is still
    // excluded -- by artifact type, which is the only thing that should exclude
    // anything here.
    assert_eq!(regions.len(), 5);
    assert!(
        regions.iter().any(|r| r.artifact_id == deep),
        "a region four parent links down must still reach the disk map"
    );
    assert!(
        regions.iter().any(|r| r.artifact_id == d3),
        "a region three parent links down must still reach the disk map"
    );
    assert_eq!(regions[0].artifact_type, "UnallocatedSpace");
    assert_eq!(regions[0].offset_bytes, Some(512));
    assert_eq!(regions[0].scheme.as_deref(), Some("MBR"));

    let p = regions.iter().find(|r| r.artifact_id == part1).unwrap();
    assert_eq!(p.name.as_deref(), Some("part1"));
    assert_eq!(p.size_bytes, Some(104857600));
    assert_eq!(p.parent_id, Some(root_id));

    let f = regions.iter().find(|r| r.artifact_id == fs).unwrap();
    assert_eq!(f.fs_type.as_deref(), Some("NTFS"));

    // Ordered by offset ascending
    let offsets: Vec<_> = regions.iter().map(|r| r.offset_bytes.unwrap()).collect();
    let mut sorted = offsets.clone();
    sorted.sort();
    assert_eq!(offsets, sorted);
    Ok(())
}

// ── get_artifact_counts_by_source ─────────────────────────────────

#[tokio::test]
async fn artifact_counts_by_source_groups_descendants_per_root() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;

    let source_a = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "a.dd"}),
    )
    .await?;
    let source_b = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "b.dd"}),
    )
    .await?;

    // source_a: partition -> 2 files (3 descendants)
    let part = insert_artifact(
        &db,
        case_id,
        Some(source_a),
        ArtifactType::Partition,
        serde_json::json!({}),
    )
    .await?;
    insert_file(&db, case_id, part, serde_json::json!({"name": "1.txt"})).await?;
    insert_file(&db, case_id, part, serde_json::json!({"name": "2.txt"})).await?;

    // source_b: no descendants

    let counts = db.get_artifact_counts_by_source(case_id).await?;
    let map: std::collections::HashMap<_, _> = counts.into_iter().collect();
    assert_eq!(map.get(&source_a), Some(&3));
    assert_eq!(map.get(&source_b), Some(&0));
    Ok(())
}

// ── get_file_size_histogram ───────────────────────────────────────

#[tokio::test]
async fn file_size_histogram_buckets_by_power_of_two() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Test", "Examiner").await?;
    let source_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::RawEvidence,
        serde_json::json!({"name": "disk.dd"}),
    )
    .await?;

    // Bucket 0: [0, 2)
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "z", "size": 0}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "o", "size": 1}),
    )
    .await?;
    // Bucket 1: [2, 4)
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "t", "size": 3}),
    )
    .await?;
    // Bucket 10: [1024, 2048)
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "k", "size": 1024}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "k2", "size": 2047}),
    )
    .await?;
    // Excluded: directory with size, file without size
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "dir", "is_directory": true, "size": 4096}),
    )
    .await?;
    insert_file(
        &db,
        case_id,
        source_id,
        serde_json::json!({"name": "nosize"}),
    )
    .await?;

    let histo = db.get_file_size_histogram(case_id).await?;
    let map: std::collections::HashMap<_, _> = histo.iter().cloned().collect();
    assert_eq!(map.get(&0), Some(&2));
    assert_eq!(map.get(&1), Some(&1));
    assert_eq!(map.get(&10), Some(&2));
    assert_eq!(map.len(), 3);

    // Buckets ordered ascending
    let buckets: Vec<_> = histo.iter().map(|(b, _)| *b).collect();
    assert_eq!(buckets, vec![0, 1, 10]);
    Ok(())
}

// ── get_dir_children_sizes: treemap directory aggregation ────────

#[tokio::test]
async fn dir_children_sizes_aggregates_subtree_bytes() -> Result<()> {
    let (db, path) = setup_file_db().await?;
    let case_id = db.create_case("Treemap", "Examiner").await?;
    let fs_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::FileSystem,
        serde_json::json!({ "name": "root" }),
    )
    .await?;

    // A small tree: two dirs plus a file at the root.
    for (p, size) in [
        ("/etc/passwd", 100i64),
        ("/etc/hosts", 50),
        ("/usr/bin/ls", 1000),
        ("/usr/lib/libc.so", 5000),
        ("/readme.txt", 10),
    ] {
        let name = p.rsplit('/').next().unwrap();
        insert_file(
            &db,
            case_id,
            fs_id,
            serde_json::json!({ "name": name, "path": p, "size": size }),
        )
        .await?;
    }

    // A directory artifact under /usr must not inflate its file count.
    insert_file(
        &db,
        case_id,
        fs_id,
        serde_json::json!({ "name": "emptydir", "path": "/usr/emptydir", "size": 0, "is_directory": true }),
    )
    .await?;

    // Root: usr (6000) > etc (150) > readme.txt (10), largest first.
    let root = db.get_dir_children_sizes(case_id, fs_id, "").await?;
    let names: Vec<_> = root.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["usr", "etc", "readme.txt"]);
    assert_eq!(root[0].total_size, 6000);
    assert!(root[0].is_dir);
    // Two files (ls, libc.so); the directory entry under /usr is excluded.
    assert_eq!(root[0].file_count, 2);
    assert_eq!(root[1].total_size, 150);
    assert!(root[1].is_dir);
    // A file directly at the root is a leaf, not a directory.
    assert_eq!(root[2].total_size, 10);
    assert!(!root[2].is_dir);
    assert_eq!(root[2].path, "/readme.txt");

    // Drill into /usr: two subdirs, largest first.
    let usr = db.get_dir_children_sizes(case_id, fs_id, "/usr").await?;
    let usr_names: Vec<_> = usr.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(usr_names, vec!["lib", "bin"]);
    assert_eq!(usr[0].total_size, 5000);
    assert_eq!(usr[0].path, "/usr/lib");
    assert!(usr[0].is_dir);

    // Leaf level: /etc holds two files.
    let etc = db.get_dir_children_sizes(case_id, fs_id, "/etc").await?;
    assert_eq!(etc.len(), 2);
    assert!(etc.iter().all(|c| !c.is_dir));
    assert_eq!(etc.iter().map(|c| c.total_size).sum::<i64>(), 150);

    // A trailing slash on the prefix is tolerated.
    let etc_slash = db.get_dir_children_sizes(case_id, fs_id, "/etc/").await?;
    assert_eq!(etc_slash.len(), 2);

    teardown_file_db(&path);
    Ok(())
}

#[tokio::test]
async fn dir_children_sizes_handles_multibyte_paths() -> Result<()> {
    // Regression: the substr offset must be a character count, not a byte
    // length, or drilling into a directory whose name contains multi-byte
    // UTF-8 characters corrupts the child segment names.
    let (db, path) = setup_file_db().await?;
    let case_id = db.create_case("Unicode", "Examiner").await?;
    let fs_id = insert_artifact(
        &db,
        case_id,
        None,
        ArtifactType::FileSystem,
        serde_json::json!({ "name": "root" }),
    )
    .await?;
    for (p, size) in [("/café/alpha.txt", 100i64), ("/café/beta.txt", 50)] {
        let name = p.rsplit('/').next().unwrap();
        insert_file(
            &db,
            case_id,
            fs_id,
            serde_json::json!({ "name": name, "path": p, "size": size }),
        )
        .await?;
    }

    // Root aggregates the multi-byte directory correctly.
    let root = db.get_dir_children_sizes(case_id, fs_id, "").await?;
    assert_eq!(root.len(), 1);
    assert_eq!(root[0].name, "café");
    assert_eq!(root[0].total_size, 150);

    // Drilling in must yield the real file names, not truncated segments.
    let inner = db.get_dir_children_sizes(case_id, fs_id, "/café").await?;
    let mut names: Vec<_> = inner.iter().map(|c| c.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["alpha.txt", "beta.txt"]);
    assert!(inner.iter().all(|c| !c.is_dir));

    teardown_file_db(&path);
    Ok(())
}
