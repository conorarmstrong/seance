/// Integration tests for VSS (Volume Shadow Copy) Enumerator
///
/// Tests the VssEnumerator module against VSS volume test data
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource, WindowSource},
    module::ForensicsModule,
};
use seance_plugin_vss::{reconstruct_snapshot_content, VssEnumerator};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper function to resolve test data path from workspace or seance_tests directory
fn resolve_test_path(relative_path: &str) -> std::path::PathBuf {
    let project_root = std::env::current_dir().unwrap();
    if project_root.ends_with("seance_tests") {
        project_root.parent().unwrap().join(relative_path)
    } else {
        project_root.join(relative_path)
    }
}

/// Helper function to create a FileSystem or RawEvidence artifact from a path
fn create_volume_artifact(path: &str, case_id: Uuid, as_filesystem: bool) -> Artifact {
    let file_path = resolve_test_path(path);

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let data_source = Arc::new(
        FileDataSource::new(file_path.clone())
            .unwrap_or_else(|e| panic!("Failed to open {}: {}", file_path.display(), e)),
    );

    let metadata = if as_filesystem {
        json!({
            "filesystem_type": "NTFS",
            "volume_name": "VSS Test Volume",
            "size": data_source.size(),
            "artifact_source": "test"
        })
    } else {
        json!({
            "name": file_name,
            "path": path,
            "size": data_source.size(),
            "artifact_source": "test"
        })
    };

    Artifact::new(
        case_id,
        if as_filesystem {
            ArtifactType::FileSystem
        } else {
            ArtifactType::RawEvidence
        },
        Some(data_source),
        metadata,
    )
}

#[test]
fn test_vss_module_metadata() {
    let enumerator = VssEnumerator;

    assert_eq!(enumerator.id(), "plugin.windows.vss_enumerator");
    assert_eq!(enumerator.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = enumerator.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileSystem));
    assert!(subscriptions.contains(&ArtifactType::RawEvidence));

    use seance_core::module::InputCapability;
    assert_eq!(enumerator.input_capability(), InputCapability::RandomAccess);
}

#[test]
fn test_non_vss_volume_ignored() {
    let enumerator = VssEnumerator;
    let case_id = Uuid::new_v4();

    // Use a non-VSS file (SAM registry hive)
    let sam_path = resolve_test_path("test_data/SAM");
    if !sam_path.exists() {
        println!("Skipping non-VSS volume test: test_data/SAM not found");
        return;
    }
    let artifact = create_volume_artifact("test_data/SAM", case_id, true);

    let result = enumerator.process(&artifact);
    assert!(result.is_ok(), "Processing non-VSS volume should not error");

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-VSS volumes"
    );
}

#[test]
fn test_non_ntfs_filesystem_ignored() {
    let enumerator = VssEnumerator;
    let case_id = Uuid::new_v4();

    // Create artifact with non-NTFS filesystem type
    let artifact = {
        let metadata = json!({
            "filesystem_type": "EXT4",
            "volume_name": "Linux Volume"
        });

        Artifact::new(case_id, ArtifactType::FileSystem, None, metadata)
    };

    let result = enumerator.process(&artifact);
    assert!(result.is_ok(), "Processing non-NTFS should not error");

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts for non-NTFS"
    );
}

#[test]
fn test_missing_data_source() {
    let enumerator = VssEnumerator;
    let case_id = Uuid::new_v4();

    // Create artifact without data source
    let artifact = {
        let metadata = json!({
            "filesystem_type": "NTFS",
            "volume_name": "Test Volume"
        });

        Artifact::new(case_id, ArtifactType::FileSystem, None, metadata)
    };

    let result = enumerator.process(&artifact);
    assert!(
        result.is_ok(),
        "Should handle missing data source gracefully"
    );

    let artifacts = result.unwrap();
    assert_eq!(
        artifacts.len(),
        0,
        "Should produce no artifacts without data source"
    );
}

/// `vss_1_vol.raw` (dfir_ntfs corpus) is a GPT disk; its NTFS volume with two
/// shadow copies starts at this byte offset (the GPT basic-data partition, LBA
/// 67584). The VSS enumerator reads volume-relative offsets, so it must be given
/// the partition window the partition parser produces in real ingestion.
const VSS_1_VOL_NTFS_PARTITION_OFFSET: u64 = 34603008;

#[test]
fn test_vss_volume_parsing() {
    let enumerator = VssEnumerator;
    let case_id = Uuid::new_v4();

    let vss_path = resolve_test_path("test_data/vss_extracted/vss_1_vol.raw");
    if !vss_path.exists() {
        println!("Skipping VSS volume test: vss_1_vol.raw not found");
        println!("Note: This test requires extracting test_data/vss_1_vol.tar.gz");
        return;
    }

    // Window the NTFS partition, mirroring the partition parser's output.
    let disk: Arc<dyn DataSource> = Arc::new(FileDataSource::new(vss_path).unwrap());
    let vol: Arc<dyn DataSource> = Arc::new(WindowSource::new(
        disk.clone(),
        VSS_1_VOL_NTFS_PARTITION_OFFSET,
        disk.size() - VSS_1_VOL_NTFS_PARTITION_OFFSET,
    ));
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileSystem,
        Some(vol),
        json!({ "filesystem_type": "NTFS", "volume_name": "VSS Test Volume" }),
    );
    let parent_id = artifact.id;

    let artifacts = enumerator
        .process(&artifact)
        .expect("VSS parsing should succeed");

    // This volume has exactly two shadow copies (dfir_ntfs vss_1_vol), both
    // enumerable from type-2 catalog entries alone.
    assert_eq!(
        artifacts.len(),
        2,
        "expected 2 shadow copies from vss_1_vol, got {}",
        artifacts.len()
    );

    let mut snapshot_ids = Vec::new();
    for artifact in &artifacts {
        assert_eq!(artifact.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(artifact.parent_id, Some(parent_id));
        assert_eq!(artifact.case_id, case_id);

        let metadata = &artifact.metadata;
        assert_eq!(
            metadata.get("type").and_then(|v| v.as_str()),
            Some("VssSnapshot")
        );
        assert_eq!(
            metadata.get("source").and_then(|v| v.as_str()),
            Some("VssEnumerator")
        );
        // Both snapshots span the whole 5.33 GB volume and were taken 2021-03-10.
        assert_eq!(
            metadata.get("volume_size").and_then(|v| v.as_u64()),
            Some(5333057536)
        );
        assert!(
            metadata
                .get("creation_time")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .starts_with("2021-03-10"),
            "unexpected creation_time: {:?}",
            metadata.get("creation_time")
        );
        snapshot_ids.push(
            metadata
                .get("snapshot_id")
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string(),
        );
    }

    // The two store GUIDs are stable properties of this reference image.
    snapshot_ids.sort();
    assert_eq!(
        snapshot_ids,
        vec![
            "bbaa765b-8204-11eb-90f4-080027768df7".to_string(),
            "bbaa7663-8204-11eb-90f4-080027768df7".to_string(),
        ]
    );
}

#[test]
fn test_vss_bitmap_file() {
    let enumerator = VssEnumerator;
    let case_id = Uuid::new_v4();

    // Test with smaller VSS bitmap file
    let bitmap_path = resolve_test_path("test_data/vss_1_vol_bm.bin");
    if !bitmap_path.exists() {
        println!("Skipping VSS bitmap test: vss_1_vol_bm.bin not found");
        return;
    }

    let artifact = create_volume_artifact("test_data/vss_1_vol_bm.bin", case_id, false);

    let result = enumerator.process(&artifact);
    assert!(
        result.is_ok(),
        "VSS bitmap file processing should not error"
    );

    let artifacts = result.unwrap();
    println!("VSS bitmap file produced {} artifacts", artifacts.len());

    // Bitmap file might not have VSS volume header at expected offset
    // This is expected - just verify it doesn't crash
}

#[test]
fn test_parent_relationship() {
    let enumerator = VssEnumerator;
    let case_id = Uuid::new_v4();

    // Skip if no VSS test data
    let vss_path = resolve_test_path("test_data/vss_extracted/vss_1_vol.raw");
    if !vss_path.exists() {
        println!("Skipping parent relationship test: VSS test data not available");
        return;
    }

    let artifact = create_volume_artifact("test_data/vss_extracted/vss_1_vol.raw", case_id, true);
    let parent_id = artifact.id;

    let result = enumerator.process(&artifact).unwrap();

    for snapshot in &result {
        assert_eq!(
            snapshot.parent_id,
            Some(parent_id),
            "Snapshot should reference parent volume"
        );
        assert_eq!(
            snapshot.case_id, case_id,
            "Snapshot should have same case_id"
        );
    }
}

#[test]
fn test_snapshot_metadata_structure() {
    let enumerator = VssEnumerator;
    let case_id = Uuid::new_v4();

    // Skip if no VSS test data
    let vss_path = resolve_test_path("test_data/vss_extracted/vss_1_vol.raw");
    if !vss_path.exists() {
        println!("Skipping metadata structure test: VSS test data not available");
        return;
    }

    let artifact = create_volume_artifact("test_data/vss_extracted/vss_1_vol.raw", case_id, true);

    let result = enumerator.process(&artifact).unwrap();

    if let Some(snapshot) = result.first() {
        let metadata = &snapshot.metadata;

        // Verify all expected metadata fields exist
        assert!(metadata.get("type").is_some(), "Should have type");
        assert!(
            metadata.get("snapshot_id").is_some(),
            "Should have snapshot_id"
        );
        assert!(metadata.get("store_id").is_some(), "Should have store_id");
        assert!(
            metadata.get("volume_size").is_some(),
            "Should have volume_size"
        );
        assert!(
            metadata.get("creation_time").is_some(),
            "Should have creation_time"
        );
        assert!(
            metadata.get("store_header_offset").is_some(),
            "Should have store_header_offset"
        );
        assert!(
            metadata.get("block_list_offset").is_some(),
            "Should have block_list_offset"
        );
        assert!(
            metadata.get("bitmap_offset").is_some(),
            "Should have bitmap_offset"
        );
        assert!(metadata.get("source").is_some(), "Should have source");

        // Verify GUID format for snapshot_id
        let snapshot_id = metadata
            .get("snapshot_id")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(
            snapshot_id.contains('-'),
            "Snapshot ID should be formatted as GUID"
        );

        // Verify volume_size is a number
        assert!(
            metadata
                .get("volume_size")
                .and_then(|v| v.as_u64())
                .is_some(),
            "volume_size should be a number"
        );

        // Verify offsets are numbers
        assert!(
            metadata
                .get("store_header_offset")
                .and_then(|v| v.as_u64())
                .is_some(),
            "store_header_offset should be a number"
        );
        assert!(
            metadata
                .get("block_list_offset")
                .and_then(|v| v.as_u64())
                .is_some(),
            "block_list_offset should be a number"
        );
        assert!(
            metadata
                .get("bitmap_offset")
                .and_then(|v| v.as_u64())
                .is_some(),
            "bitmap_offset should be a number"
        );
    }
}

/// The API content resolver cannot persist a VSS snapshot's reconstruction as
/// data_runs (the bytes are assembled virtually from scattered diff-area
/// locations across the store chain), so it rebuilds the source on demand via
/// `reconstruct_snapshot_content`. This test proves that resolver path re-serves
/// byte-identically to the DataSource the enumerator attaches at ingest -- i.e.
/// shadow-copy content is actually reachable from the GUI/TUI on the DB
/// round-trip, not just in-memory at parse time.
///
/// Uses the dfir_ntfs vss_2003 image (6 shadow copies with real diff areas).
/// Extract test_data/vss_2003.tgz to test_data/vss_2003.raw to run.
#[test]
fn vss_reconstruction_re_serves_through_resolver_path() {
    let img = resolve_test_path("test_data/vss_2003.raw");
    if !img.exists() {
        println!("Skipping VSS resolver round-trip: vss_2003.raw not found (extract vss_2003.tgz)");
        return;
    }

    let disk: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    // The NTFS + VSS partition starts at byte 32256; the enumerator reads
    // volume-relative offsets, so give it that window.
    let vol: Arc<dyn DataSource> =
        Arc::new(WindowSource::new(disk.clone(), 32256, disk.size() - 32256));

    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(vol.clone()),
        json!({ "name": "v", "subtype": "ntfs", "filesystem_type": "NTFS" }),
    )
    .with_parent(Uuid::new_v4());

    let snapshots = VssEnumerator.process(&art).expect("enumerate");
    let reconstructed: Vec<&Artifact> = snapshots
        .iter()
        .filter(|a| {
            a.metadata
                .get("content_reconstruction")
                .and_then(|v| v.as_str())
                == Some("reconstructed")
                && a.data.is_some()
        })
        .collect();
    assert!(
        !reconstructed.is_empty(),
        "expected at least one reconstructed shadow copy"
    );

    let mut any_nonzero = false;
    for snap in reconstructed {
        let ingest_ds = snap.data.as_ref().unwrap();
        let stack = snap
            .metadata
            .get("stack_position")
            .and_then(|v| v.as_u64())
            .expect("reconstructed snapshot must carry stack_position");

        // Rebuild exactly as the API content resolver does: volume window + stack.
        let resolver_ds =
            reconstruct_snapshot_content(vol.clone(), stack).expect("resolver reconstruction");

        // Sample the first 1 MiB in 16 KiB blocks; the resolver source must
        // return byte-identical data to the validated ingest source.
        for blk in 0..64u64 {
            let off = blk * 16384;
            let mut a = vec![0u8; 16384];
            let mut b = vec![0u8; 16384];
            let na = ingest_ds.read_at(off, &mut a).unwrap_or(0);
            let nb = resolver_ds.read_at(off, &mut b).unwrap_or(0);
            assert_eq!(na, nb, "read length differs at stack {stack} offset {off}");
            assert_eq!(
                a, b,
                "resolver bytes differ from ingest at stack {stack} offset {off}"
            );
            if a.iter().any(|&x| x != 0) {
                any_nonzero = true;
            }
        }
    }
    assert!(
        any_nonzero,
        "sampled reconstructions were entirely zero -- likely a degenerate result"
    );
}
