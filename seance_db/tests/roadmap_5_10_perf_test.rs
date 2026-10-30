//! ROADMAP §5.10: two seance_db items "verified by reading and unmeasured" —
//! the file-size histogram's per-call `CASE` construction and the correlated
//! `child_count` subquery in the evidence-tree listing. Each has a row-for-row
//! oracle test and a measurement; the measurements print, they do not assert.

use std::collections::HashMap;
use std::time::Instant;

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use uuid::Uuid;

async fn setup_test_db() -> Result<SqliteConnection> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    Ok(db)
}

fn artifact(
    case_id: Uuid,
    parent_id: Option<Uuid>,
    artifact_type: ArtifactType,
    metadata: serde_json::Value,
) -> Artifact {
    Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id,
        artifact_type,
        metadata,
        data: None,
    }
}

/// Sizes drawn from a fixed xorshift stream, spread over every power-of-two
/// bucket a real volume shows (0 bytes up to a few GB), with the
/// bucket-boundary values 2^p and 2^p - 1 mixed in.
fn deterministic_sizes(n: usize) -> Vec<i64> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..n)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let p = (state % 33) as u32;
            match i % 4 {
                0 => 1i64 << p,
                1 => (1i64 << p) - 1,
                _ => (state >> 20) as i64 % (1i64 << p).max(1),
            }
        })
        .collect()
}

fn floor_log2_bucket(size: i64) -> u32 {
    if size < 2 {
        0
    } else {
        63 - size.leading_zeros()
    }
}

async fn volume_with_files(db: &SqliteConnection, case_id: Uuid, sizes: &[i64]) -> Result<Uuid> {
    let fs = artifact(
        case_id,
        None,
        ArtifactType::FileSystem,
        serde_json::json!({"name": "vol"}),
    );
    let fs_id = fs.id;
    db.record_artifact(&fs).await?;
    let files: Vec<Artifact> = sizes
        .iter()
        .enumerate()
        .map(|(i, size)| {
            artifact(
                case_id,
                Some(fs_id),
                ArtifactType::FileEntry,
                serde_json::json!({"name": format!("f{i}"), "path": format!("/f{i}"), "size": size}),
            )
        })
        .collect();
    for chunk in files.chunks(5_000) {
        db.record_artifacts_batch(chunk).await?;
    }
    Ok(fs_id)
}

#[tokio::test]
async fn file_size_histogram_agrees_with_floor_log2_over_every_bucket() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Histogram", "Examiner").await?;
    let sizes = deterministic_sizes(20_000);
    volume_with_files(&db, case_id, &sizes).await?;

    let mut expected: HashMap<u32, i64> = HashMap::new();
    for size in &sizes {
        *expected.entry(floor_log2_bucket(*size)).or_default() += 1;
    }
    let mut expected: Vec<(u32, i64)> = expected.into_iter().collect();
    expected.sort();

    let histogram = db.get_file_size_histogram(case_id).await?;
    assert_eq!(histogram, expected);
    assert!(
        histogram.len() >= 30,
        "the fixture must exercise most buckets, got {}",
        histogram.len()
    );
    Ok(())
}

/// Not an assertion, a measurement. 200,000 FileEntry rows is a small
/// laptop image. Recorded 2026-09-19 on this host, debug / release, with the
/// `CASE` chain over the VIRTUAL `size` column: expression built in 24 µs,
/// query 3.66 s / 1.0 s a call; over the materialised sizes: 1.24 s / 0.3-0.4 s.
/// The per-call expression build the roadmap named was never the cost.
#[tokio::test]
async fn measure_file_size_histogram() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Histogram", "Examiner").await?;
    let sizes = deterministic_sizes(200_000);
    volume_with_files(&db, case_id, &sizes).await?;

    let start = Instant::now();
    let mut bucket_expr = String::from("CASE");
    for p in (1..=62u32).rev() {
        bucket_expr.push_str(&format!(" WHEN size >= {} THEN {}", 1i64 << p, p));
    }
    bucket_expr.push_str(" ELSE 0 END");
    let build_expr = start.elapsed();

    db.get_file_size_histogram(case_id).await?;
    let start = Instant::now();
    let runs = 5;
    for _ in 0..runs {
        db.get_file_size_histogram(case_id).await?;
    }
    let per_call = start.elapsed() / runs;
    eprintln!(
        "file-size histogram over {} files: CASE expression ({} bytes) built in {build_expr:?}; \
         query {per_call:?} per call",
        sizes.len(),
        bucket_expr.len()
    );
    Ok(())
}

#[tokio::test]
async fn tree_page_child_counts_agree_with_a_count_per_row() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Tree", "Examiner").await?;
    let partition = artifact(
        case_id,
        None,
        ArtifactType::Partition,
        serde_json::json!({"name": "p1"}),
    );
    db.record_artifact(&partition).await?;
    let mut expected = Vec::new();
    for (i, children) in [0usize, 1, 7, 300, 2].into_iter().enumerate() {
        let fs = artifact(
            case_id,
            Some(partition.id),
            ArtifactType::FileSystem,
            serde_json::json!({"name": format!("vol{i}")}),
        );
        let files: Vec<Artifact> = (0..children)
            .map(|j| {
                artifact(
                    case_id,
                    Some(fs.id),
                    ArtifactType::FileEntry,
                    serde_json::json!({"name": format!("f{j}"), "size": j}),
                )
            })
            .collect();
        expected.push((fs.id, children as i64));
        db.record_artifact(&fs).await?;
        db.record_artifacts_batch(&files).await?;
    }

    let page = db
        .get_child_artifacts_filtered(case_id, Some(partition.id), false, None, 0)
        .await?;
    assert_eq!(page.items.len(), expected.len());
    assert!(!page.has_more);
    assert_eq!(page.undecodable, 0);
    for child in &page.items {
        let (_, want) = expected
            .iter()
            .find(|(id, _)| *id == child.artifact.id)
            .expect("every volume is listed");
        assert_eq!(
            child.child_count, *want,
            "{}",
            child.artifact.metadata["name"]
        );
        assert_eq!(
            child.child_count,
            db.count_child_artifacts(child.artifact.id).await?,
            "the folded count and the counting query disagree"
        );
    }
    Ok(())
}

/// Not an assertion, a measurement. The two shapes that stress the folded
/// count: a full page of 1,000 nodes each with a few children, and a short
/// page whose few nodes each carry tens of thousands of files (a volume's
/// files hang flat off it). Recorded 2026-09-19 on this host, release, before
/// migration 0042: 50 ms and 44 ms a page, the folded counts 1-3 ms of each
/// and the rest a scan of every artifact in the case; after: 9 ms and 5.6 ms,
/// the plain listing 8 ms and 0.15 ms.
#[tokio::test]
async fn measure_tree_page_child_counts() -> Result<()> {
    let db = setup_test_db().await?;
    let case_id = db.create_case("Tree", "Examiner").await?;

    let wide = artifact(
        case_id,
        None,
        ArtifactType::Partition,
        serde_json::json!({"name": "wide"}),
    );
    db.record_artifact(&wide).await?;
    let mut nodes = Vec::new();
    let mut leaves = Vec::new();
    for i in 0..1_000 {
        let node = artifact(
            case_id,
            Some(wide.id),
            ArtifactType::ParsedRecord,
            serde_json::json!({"type": "dir", "name": format!("d{i}")}),
        );
        for j in 0..20 {
            leaves.push(artifact(
                case_id,
                Some(node.id),
                ArtifactType::FileEntry,
                serde_json::json!({"name": format!("f{j}"), "size": j}),
            ));
        }
        nodes.push(node);
    }
    db.record_artifacts_batch(&nodes).await?;
    for chunk in leaves.chunks(5_000) {
        db.record_artifacts_batch(chunk).await?;
    }

    let deep = artifact(
        case_id,
        None,
        ArtifactType::Partition,
        serde_json::json!({"name": "deep"}),
    );
    db.record_artifact(&deep).await?;
    for i in 0..4 {
        let fs = artifact(
            case_id,
            Some(deep.id),
            ArtifactType::FileSystem,
            serde_json::json!({"name": format!("vol{i}")}),
        );
        db.record_artifact(&fs).await?;
        let files: Vec<Artifact> = (0..50_000)
            .map(|j| {
                artifact(
                    case_id,
                    Some(fs.id),
                    ArtifactType::FileEntry,
                    serde_json::json!({"name": format!("f{j}"), "size": j}),
                )
            })
            .collect();
        for chunk in files.chunks(5_000) {
            db.record_artifacts_batch(chunk).await?;
        }
    }

    for (label, parent) in [
        ("wide: 1,000 nodes x 20", wide.id),
        ("deep: 4 nodes x 50,000", deep.id),
    ] {
        db.get_child_artifacts_filtered(case_id, Some(parent), false, None, 0)
            .await?;
        let runs = 5;
        let start = Instant::now();
        for _ in 0..runs {
            let page = db
                .get_child_artifacts_filtered(case_id, Some(parent), false, None, 0)
                .await?;
            assert!(!page.items.is_empty());
        }
        let with_counts = start.elapsed() / runs;
        let start = Instant::now();
        for _ in 0..runs {
            let page = db
                .get_child_artifacts(case_id, Some(parent), None, 0)
                .await?;
            assert!(!page.items.is_empty());
        }
        let without_counts = start.elapsed() / runs;
        eprintln!(
            "tree page, {label}: with folded child_count {with_counts:?}, \
             plain listing {without_counts:?} per page"
        );
    }
    Ok(())
}
