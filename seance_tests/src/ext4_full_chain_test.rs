use seance_container_e01::E01ContainerModule;
/// Test E01 → Partition → Ext4 → File Access Chain
///
/// This test validates the complete chain:
/// 1. E01 container parsing (libewf)
/// 2. Partition detection (MBR/GPT)
/// 3. Ext4 filesystem parsing
/// 4. File content extraction
///
/// Uses test_data/full_image/001.E01 which contains a Linux filesystem
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::ForensicsModule,
};
use seance_plugin_ext4::Ext4Parser;
use seance_plugin_partition::{FilesystemDetector, PartitionParser};
use serde_json::json;
use tracing::{debug, info};
use uuid::Uuid;

#[allow(dead_code)] // Helper function
fn init_logging() {
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;
    let _ = FmtSubscriber::builder()
        .with_max_level(Level::INFO) // INFO level to see what's happening
        .try_init();
}

#[test]
fn test_e01_to_ext4_timezone_file() -> anyhow::Result<()> {
    init_logging();

    let test_image_path = "../test_data/full_image/001.E01";

    // Check if test image exists
    if !std::path::Path::new(test_image_path).exists() {
        eprintln!("Skipping E01→Ext4 test: {} not found", test_image_path);
        return Ok(());
    }

    let case_id = Uuid::new_v4();

    info!("=== Step 1: Parse E01 Container ===");
    let e01_module = E01ContainerModule;

    // Create FileEntry artifact pointing to E01 file
    let e01_artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "001.E01",
            "path": test_image_path,
            "size": std::fs::metadata(test_image_path)?.len(),
        }),
    );

    let raw_evidence_artifacts = e01_module.process(&e01_artifact)?;
    assert_eq!(
        raw_evidence_artifacts.len(),
        1,
        "Should produce one RawEvidence artifact"
    );

    let raw_evidence = &raw_evidence_artifacts[0];
    assert_eq!(raw_evidence.artifact_type, ArtifactType::RawEvidence);
    assert!(
        raw_evidence.data.is_some(),
        "RawEvidence should have a data source"
    );

    info!(
        "✓ E01 opened: {} bytes",
        raw_evidence
            .metadata
            .get("size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    );

    info!("=== Step 2: Parse Partition Table ===");
    let partition_parser = PartitionParser;
    let partition_artifacts = partition_parser.process(raw_evidence)?;

    assert!(
        !partition_artifacts.is_empty(),
        "Should find at least one partition"
    );
    info!("✓ Found {} partition(s)", partition_artifacts.len());

    // Look for the Linux partition (type 0x83)
    let linux_partition = partition_artifacts
        .iter()
        .find(|p| {
            p.metadata
                .get("partition_type")
                .and_then(|v| v.as_str())
                .map(|s| s == "0x83")
                .unwrap_or(false)
        })
        .expect("Should find Linux partition (type 0x83)");

    info!("✓ Found Linux partition: {:?}", linux_partition.metadata);

    info!("=== Step 3: Detect Filesystem ===");
    let fs_detector = FilesystemDetector;
    let filesystem_artifacts = fs_detector.process(linux_partition)?;

    assert_eq!(
        filesystem_artifacts.len(),
        1,
        "Should detect one filesystem"
    );
    let filesystem = &filesystem_artifacts[0];

    assert_eq!(filesystem.artifact_type, ArtifactType::FileSystem);
    let fs_type = filesystem
        .metadata
        .get("filesystem_type")
        .and_then(|v| v.as_str())
        .expect("Should have filesystem_type");
    assert_eq!(fs_type, "ext4", "Should detect ext4 filesystem");

    info!("✓ Detected {} filesystem", fs_type);

    info!("=== Step 4: Parse Ext4 Filesystem ===");
    let ext4_parser = Ext4Parser::new();
    let file_artifacts = ext4_parser.process(filesystem)?;

    info!(
        "✓ Parsed ext4, found {} files/directories",
        file_artifacts.len()
    );

    // Debug: Print first 20 files to see what we have
    debug!("First 20 files found:");
    for (i, artifact) in file_artifacts.iter().take(20).enumerate() {
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let size = artifact
            .metadata
            .get("size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        debug!("  [{}] {} ({} bytes)", i, path, size);
    }

    info!("=== Step 5: Find and Read /etc/timezone ===");
    let timezone_artifact = file_artifacts
        .iter()
        .find(|a| {
            a.metadata
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| s == "/etc/timezone")
                .unwrap_or(false)
        })
        .expect("Should find /etc/timezone file");

    info!("✓ Found /etc/timezone: {:?}", timezone_artifact.metadata);

    // Read the file content
    let data_source = timezone_artifact
        .data
        .as_ref()
        .expect("timezone file should have a data source");

    let file_size = timezone_artifact
        .metadata
        .get("size")
        .and_then(|v| v.as_u64())
        .expect("Should have file size");

    let mut buffer = vec![0u8; file_size as usize];
    let bytes_read = data_source.read_at(0, &mut buffer)?;

    assert_eq!(bytes_read, file_size as usize, "Should read entire file");

    let content = String::from_utf8_lossy(&buffer[..bytes_read]);
    let content = content.trim();

    info!("✓ Read /etc/timezone content: '{}'", content);

    // Verify expected content (based on your manual test showing "Europe/London")
    assert_eq!(content, "Europe/London", "Timezone should be Europe/London");

    println!("\n=== SUCCESS ===");
    println!("Successfully accessed /etc/timezone from E01 image!");
    println!("Content: {}", content);
    println!("Full chain working: E01 → Partition → Ext4 → File");

    Ok(())
}

#[test]
fn test_e01_to_ext4_file_listing() -> anyhow::Result<()> {
    init_logging();

    let test_image_path = "../test_data/full_image/001.E01";

    if !std::path::Path::new(test_image_path).exists() {
        eprintln!(
            "Skipping E01→Ext4 file listing test: {} not found",
            test_image_path
        );
        return Ok(());
    }

    let case_id = Uuid::new_v4();

    // Step 1: E01
    let e01_module = E01ContainerModule;
    let e01_artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "001.E01",
            "path": test_image_path,
        }),
    );
    let raw_evidence_artifacts = e01_module.process(&e01_artifact)?;
    let raw_evidence = &raw_evidence_artifacts[0];

    // Step 2: Partition
    let partition_parser = PartitionParser;
    let partition_artifacts = partition_parser.process(raw_evidence)?;
    let linux_partition = partition_artifacts
        .iter()
        .find(|p| {
            p.metadata
                .get("partition_type")
                .and_then(|v| v.as_str())
                .map(|s| s == "0x83")
                .unwrap_or(false)
        })
        .expect("Should find Linux partition");

    // Step 3: Filesystem
    let fs_detector = FilesystemDetector;
    let filesystem_artifacts = fs_detector.process(linux_partition)?;
    let filesystem = &filesystem_artifacts[0];

    // Step 4: Parse Ext4
    let ext4_parser = Ext4Parser::new();
    let file_artifacts = ext4_parser.process(filesystem)?;

    // Verify we can find common Linux directories
    let expected_paths = vec!["/etc", "/home", "/usr", "/var", "/bin", "/sbin"];

    for expected_path in expected_paths {
        let found = file_artifacts.iter().any(|a| {
            a.metadata
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| s == expected_path)
                .unwrap_or(false)
        });
        assert!(found, "Should find {}", expected_path);
        info!("✓ Found {}", expected_path);
    }

    println!("\n✓ Successfully listed files from ext4 filesystem in E01 image");

    Ok(())
}

/// **The free blocks of a real ext4 volume become carvable regions**
/// (`ROADMAP` §5.4), on the 67 GB ext4 partition of the Magnet 2022 Linux CTF
/// image.
///
/// Point `SEANCE_LINUX_CTF` at the directory holding `LenovoFinal.E01`. Absent,
/// this skips; named and missing, it fails — see
/// [`seance_core::test_support::corpus`].
///
/// ext4's own conventions are what this grades, and they differ from both
/// FAT-family filesystems: blocks are numbered from the **volume's start** so a
/// block's offset is its own number times the block size, and there is one
/// bitmap per **block group**, so the free runs have to be stitched across
/// groups. The structural assertions are independent of the code that produced
/// the regions — inside the volume, non-overlapping, in address order, each
/// offset equal to its own first block's address — and the one that would catch
/// a base-cluster error is that **block 0 is never in a region**: it is below
/// `first_data_block` and the reader counts the boot area as in use.
#[test]
fn a_real_ext4_volume_publishes_its_free_blocks_as_regions() -> anyhow::Result<()> {
    init_logging();
    let Some(image) =
        seance_core::test_support::corpus::file("SEANCE_LINUX_CTF", "LenovoFinal.E01")
    else {
        eprintln!("skipping: SEANCE_LINUX_CTF not set");
        return Ok(());
    };

    let case_id = Uuid::new_v4();
    let e01 = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "LenovoFinal.E01",
            "path": image.to_string_lossy(),
            "size": std::fs::metadata(&image)?.len(),
        }),
    );
    let raw = E01ContainerModule
        .process(&e01)?
        .into_iter()
        .next()
        .expect("one image is one RawEvidence");

    // The ext4 volume is the large GPT partition; the other is the EFI system
    // partition, which is FAT.
    let mut graded = false;
    for partition in PartitionParser.process(&raw)? {
        for fs in FilesystemDetector.process(&partition).unwrap_or_default() {
            let kind = fs
                .metadata
                .get("filesystem_type")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !kind.contains("ext") {
                continue;
            }
            let volume_bytes = fs.data.as_ref().map(|d| d.size()).unwrap_or(0);
            let produced = Ext4Parser::new().process(&fs)?;
            let Some(map) = produced.iter().find(|a| {
                a.metadata.get("type").and_then(|v| v.as_str()) == Some("allocation_map")
            }) else {
                continue;
            };
            let block_size = map.metadata["allocation_cluster_size"]
                .as_u64()
                .expect("the map states its block size");
            let regions: Vec<&Artifact> = produced
                .iter()
                .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
                .collect();
            eprintln!(
                "  ext4: {} block(s) of {block_size} bytes; {} free region(s), {} bytes, \
                 {} run(s) dropped covering {} bytes, {} block(s) behind a short group bitmap",
                map.metadata["allocation_total_clusters"],
                map.metadata["free_regions_emitted"],
                map.metadata["free_bytes_emitted"],
                map.metadata["free_runs_dropped"],
                map.metadata["free_bytes_dropped"],
                map.metadata
                    .get("free_space_blocks_short_group_bitmaps")
                    .cloned()
                    .unwrap_or(json!(0)),
            );
            assert!(
                !regions.is_empty(),
                "a 67 GB ext4 volume has free blocks; none was emitted"
            );
            // A real, used ext4 volume is fragmented into far more free runs
            // than any region ceiling would hold, which is exactly what the
            // ceiling is for -- and what it declined has to be a byte total
            // rather than silence. The largest runs are kept, so the bytes
            // dropped are a small fraction of the bytes emitted despite the
            // dropped COUNT being far larger.
            let dropped_runs = map.metadata["free_runs_dropped"].as_u64().unwrap_or(0);
            if dropped_runs > 0 {
                let dropped_bytes = map.metadata["free_bytes_dropped"]
                    .as_u64()
                    .expect("a ceiling that dropped runs states the bytes they covered");
                let emitted_bytes = map.metadata["free_bytes_emitted"].as_u64().unwrap();
                assert!(dropped_bytes > 0);
                assert!(
                    dropped_bytes < emitted_bytes,
                    "largest-first selection must keep more free space than it drops: \
                     {emitted_bytes} emitted against {dropped_bytes} dropped"
                );
                assert_eq!(map.metadata["free_region_cap_reached"], true);
                assert_eq!(map.metadata["free_space_complete"], false);
                let said = map.metadata["free_space_incomplete_detail"]
                    .as_str()
                    .expect("the sentence");
                assert!(said.contains("region ceiling"), "{said}");
                assert!(said.contains("will not be carved"), "{said}");
            }

            let mut previous_end = 0u64;
            for region in &regions {
                let offset = region.metadata["offset_bytes"].as_u64().expect("offset");
                let size = region.metadata["size_bytes"].as_u64().expect("size");
                let first_block = region.metadata["first_cluster"].as_u64().expect("block");
                assert!(size > 0);
                assert!(
                    first_block > 0,
                    "block 0 is below first_data_block and the reader counts the boot area as \
                     in use; a region at block 0 means the base was read wrong"
                );
                assert_eq!(
                    offset,
                    first_block * block_size,
                    "ext4 numbers blocks from the volume's start, so a block's offset is its \
                     own number times the block size"
                );
                assert!(
                    offset >= previous_end,
                    "regions overlap or are out of order at {offset} after {previous_end}"
                );
                assert!(
                    volume_bytes == 0 || offset + size <= volume_bytes,
                    "a region at {offset}+{size} reaches past the volume's {volume_bytes} bytes"
                );
                assert_eq!(region.metadata["filesystem"], "ext4");
                previous_end = offset + size;
            }
            graded = true;
        }
    }
    assert!(graded, "the image's ext4 partition must be reached");
    Ok(())
}
