//! Tripwire (`HUNT-124`): file slack is never counted as free space by the
//! consumers that read `UnallocatedSpace` from the database.
//!
//! Slack is allocated to its owner. The owner decision of 2026-09-26 made it
//! its own `ArtifactType::SlackSpace` so no free-space figure can count it, and
//! asked for tripwires on the consumers rather than on the type alone. This
//! records a volume's free regions and its slack regions — each built by the
//! producer the parsers use (`free_space::emit_free_regions`,
//! `slack::SlackCollector`) — and then asks the real consumers:
//!
//! * `get_disk_regions`, the disk map and the source of the ad-hoc carve's
//!   targets (`seance_api::carve_source`), must list the free regions and not
//!   one slack region;
//! * the free-space total an examiner reads off that map — the sum of its
//!   `UnallocatedSpace` rows — must be the bitmap's free clusters exactly,
//!   although a slack window sits inside an allocated cluster beside them;
//! * the carve-target selection `carve_source` applies to that list (types
//!   `FileSystem` and `UnallocatedSpace`) must name no slack region.
//!
//! Synthetic: it pins the mechanism on a 64 KiB volume, not a real image.

mod common;

use common::file_db;
use std::sync::Arc;

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::db::DatabaseConnection;
use seance_core::free_space::{emit_free_regions, AllocationBitmap, BitMeaning, FreeSpaceLabels};
use seance_core::slack::{slack_window, SlackCollector, SlackLabels, SlackOwner};
use serde_json::json;
use uuid::Uuid;

const CLUSTER: u64 = 4096;

#[tokio::test]
async fn slack_regions_are_not_free_space_to_the_disk_map_or_the_carve_targets() -> Result<()> {
    let (db, _path) = file_db().await?;
    let case_id = db.create_case("slack tripwire", "Examiner").await?;

    let root = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"name": "disk.dd"}),
    );
    db.record_artifact(&root).await?;
    let fs = Artifact::new(
        case_id,
        ArtifactType::FileSystem,
        None,
        json!({"filesystem_type": "NTFS", "offset_bytes": 0u64, "size_bytes": 65536u64}),
    )
    .with_parent(root.id);
    db.record_artifact(&fs).await?;

    // Clusters 0-7 free, 8-15 allocated. Two live files in allocated clusters
    // 8 and 9, each with a non-zero byte in its slack.
    let mut bytes = vec![0u8; 64 * 1024];
    bytes[8 * 4096 + 700] = b'z';
    bytes[9 * 4096 + 3000] = b'q';
    let vol: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let bits = [0x00u8, 0xFF];
    let bitmap = AllocationBitmap {
        bits: &bits,
        total_clusters: 16,
        cluster_size: CLUSTER,
        first_cluster: 0,
        first_cluster_offset: 0,
        bit_meaning: BitMeaning::SetIsAllocated,
    };
    let (free, _) = emit_free_regions(
        &fs,
        &vol,
        &bitmap,
        FreeSpaceLabels {
            filesystem: "NTFS",
            offset_basis: "the volume",
        },
    );
    let mut collector = SlackCollector::new(
        SlackLabels {
            filesystem: "NTFS",
            offset_basis: "the volume",
        },
        CLUSTER,
    );
    for (cluster, logical) in [(8u64, 100u64), (9, 2000)] {
        let w = slack_window(&[(Some(cluster * CLUSTER), CLUSTER)], logical, CLUSTER)
            .expect("a slack window");
        collector.offer(
            &fs,
            &vol,
            SlackOwner {
                artifact_id: Uuid::new_v4(),
                name: "host.doc",
                path: Some("/host.doc"),
                logical_size: logical,
            },
            w,
        );
    }
    let (slack, _) = collector.finish(&fs);

    let free_ids: Vec<Uuid> = free
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .map(|a| a.id)
        .collect();
    let slack_ids: Vec<Uuid> = slack
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .map(|a| a.id)
        .collect();
    assert!(!free_ids.is_empty(), "the bitmap proves clusters 0-7 free");
    assert_eq!(slack_ids.len(), 2, "both non-zero tails are published");

    for a in free.iter().chain(slack.iter()) {
        let mut a = a.clone();
        a.case_id = case_id;
        db.record_artifact(&a).await?;
    }

    let regions = db.get_disk_regions(case_id, root.id).await?;

    // The disk map lists no slack region.
    for r in &regions {
        assert!(
            !slack_ids.contains(&r.artifact_id),
            "slack region {} appeared in the disk map as {}",
            r.artifact_id,
            r.artifact_type
        );
        assert_ne!(r.artifact_type, "SlackSpace");
    }

    // The free total read off the map is the bitmap's eight clusters exactly.
    let free_total: i64 = regions
        .iter()
        .filter(|r| r.artifact_type == "UnallocatedSpace")
        .filter_map(|r| r.size_bytes)
        .sum();
    assert_eq!(free_total, 8 * CLUSTER as i64);

    // The ad-hoc carve's target selection (seance_api::carve_source) names
    // every free region and no slack region.
    let targets: Vec<Uuid> = regions
        .iter()
        .filter(|r| r.artifact_type == "FileSystem" || r.artifact_type == "UnallocatedSpace")
        .map(|r| r.artifact_id)
        .collect();
    for id in &free_ids {
        assert!(targets.contains(id), "free region {id} is a carve target");
    }
    for id in &slack_ids {
        assert!(
            !targets.contains(id),
            "slack region {id} is not a carve target"
        );
    }

    Ok(())
}
