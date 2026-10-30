//! DFTT (Digital Forensics Tool Testing) known-answer regression tests.
//!
//! Each DFTT image tests one capability against a documented expected result.
//! These lock in the comparisons validated during the testing campaign so they
//! cannot silently regress. All are skip-if-absent (the images are gitignored).
//! Keyword/undelete/carving/ISO images are covered in their own test modules;
//! this module holds the partition, volume-label, and timestamp cases.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_fat::FatParser;
use seance_plugin_partition::PartitionParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

fn resolve(relative: &str) -> std::path::PathBuf {
    let root = std::env::current_dir().unwrap();
    if root.ends_with("seance_tests") {
        root.parent().unwrap().join(relative)
    } else {
        root.join(relative)
    }
}

fn raw_evidence(path: &std::path::Path) -> Artifact {
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).expect("open"));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds),
        json!({ "name": path.to_string_lossy(), "path": path.to_string_lossy() }),
    )
}

/// DFTT #1 (Extended DOS Partition Test): a hand-edited extended partition with
/// a non-standard third logical entry. The documented answer is "show all six
/// FAT16 partitions". The parser must walk the full EBR chain and must NOT emit
/// the 0x05 extended container itself as a data partition.
#[test]
fn dftt1_extended_partition_finds_all_six() {
    let img = resolve("test_data/dftt/1-extend-part/1-extend-part/ext-part-test-2.dd");
    if !img.exists() {
        println!("Skipping DFTT #1: {} not present", img.display());
        return;
    }

    let produced = PartitionParser
        .process(&raw_evidence(&img))
        .expect("partition parse");
    let partitions: Vec<&Artifact> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::Partition)
        .collect();

    let fat16 = partitions
        .iter()
        .filter(|p| {
            matches!(
                p.metadata.get("partition_type").and_then(|v| v.as_str()),
                Some("0x04") | Some("0x06") | Some("0x0e") | Some("0x0E")
            )
        })
        .count();
    assert_eq!(fat16, 6, "expected all six FAT16 partitions, got {fat16}");
    assert_eq!(
        partitions.len(),
        6,
        "expected exactly six partitions (no extended container)"
    );

    // The extended container (0x05/0x0F/0x85) must never be surfaced as a partition.
    let container = partitions.iter().any(|p| {
        matches!(
            p.metadata.get("partition_type").and_then(|v| v.as_str()),
            Some("0x05") | Some("0x0f") | Some("0x0F") | Some("0x85")
        )
    });
    assert!(
        !container,
        "extended container must not be emitted as a data partition"
    );
}

/// DFTT #9 (FAT Volume Label Test #1): the boot-sector volume label is "LABEL1".
#[test]
fn dftt9_fat_volume_label() {
    let img = resolve("test_data/dftt/9-fat-label/9-fat-label/9-fat-label.dd");
    if !img.exists() {
        println!("Skipping DFTT #9: {} not present", img.display());
        return;
    }

    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "subtype": "fat16", "filesystem_type": "FAT16" }),
    );
    let produced = FatParser.process(&fs).expect("fat parse");
    let label = produced
        .iter()
        .find_map(|a| a.metadata.get("volume_label").and_then(|v| v.as_str()));
    assert_eq!(
        label,
        Some("LABEL1"),
        "expected boot-sector volume label LABEL1"
    );
}

/// **The free clusters of a real FAT16 volume become carvable regions**
/// (`ROADMAP` §5.4), on an image from NIST's own Digital Forensics Tool Testing
/// set.
///
/// The assertions are structural and independent of the code that produced the
/// regions: inside the volume, non-overlapping, in address order, and — the one
/// that would catch a wrong reading of the FAT — **never a cluster below 2**,
/// because 0 and 1 are the FAT's own reserved entries and are not data clusters
/// at all. A region over them would mean the base cluster was taken as 0, which
/// is what NTFS uses and what FAT does not.
#[test]
fn dftt9_free_clusters_become_carvable_regions() {
    let img = resolve("test_data/dftt/9-fat-label/9-fat-label/9-fat-label.dd");
    if !img.exists() {
        println!("Skipping DFTT #9 free space: {} not present", img.display());
        return;
    }

    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let volume_bytes = ds.size();
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "subtype": "fat16", "filesystem_type": "FAT16" }),
    );
    let produced = FatParser.process(&fs).expect("fat parse");
    let map = produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("allocation_map"))
        .expect("the allocation map");
    let cluster_size = map.metadata["allocation_cluster_size"]
        .as_u64()
        .expect("size");
    let regions: Vec<&Artifact> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .collect();
    eprintln!(
        "  DFTT #9: {} cluster(s) of {cluster_size} bytes; {} free region(s), {} bytes, \
         {} run(s) dropped",
        map.metadata["allocation_total_clusters"],
        map.metadata["free_regions_emitted"],
        map.metadata["free_bytes_emitted"],
        map.metadata["free_runs_dropped"],
    );
    assert!(
        !regions.is_empty(),
        "a FAT16 test volume holding one labelled filesystem has free clusters"
    );

    let mut previous_end = 0u64;
    for region in &regions {
        let offset = region.metadata["offset_bytes"].as_u64().expect("offset");
        let size = region.metadata["size_bytes"].as_u64().expect("size");
        let first_cluster = region.metadata["first_cluster"].as_u64().expect("cluster");
        assert!(size > 0);
        assert!(
            first_cluster >= 2,
            "clusters 0 and 1 are the FAT's own reserved entries, not data clusters; a region \
             at cluster {first_cluster} means the base cluster was read as NTFS's 0"
        );
        assert!(
            offset >= previous_end,
            "regions overlap or are out of order at {offset} after {previous_end}"
        );
        assert!(
            offset + size <= volume_bytes,
            "a region at {offset}+{size} reaches past the image's {volume_bytes} bytes"
        );
        assert_eq!(region.metadata["filesystem"], "FAT16");
        assert_eq!(
            region.data.as_ref().map(|d| d.size()),
            Some(size),
            "the window is the length the record declares"
        );
        previous_end = offset + size;
    }
}

/// DFTT #5 (FAT Daylight Savings Test): a FAT12 floppy with two files whose
/// contents record their creation time. FAT stores wall-clock local time with
/// no timezone, so the parser must surface both files with parseable timestamps
/// that carry the ~1h summer/winter offset the test is designed around.
#[test]
fn dftt5_fat_daylight_two_files_with_timestamps() {
    let img = resolve("test_data/dftt/5-fat-daylight/5-fat-daylight/daylight.dd");
    if !img.exists() {
        println!("Skipping DFTT #5: {} not present", img.display());
        return;
    }

    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "subtype": "fat12", "filesystem_type": "FAT12" }),
    );
    let produced = FatParser.process(&fs).expect("fat parse");
    let files: Vec<&Artifact> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect();

    // Both the summer and winter files must be present with a timestamp.
    for want in ["summer.txt", "winter.txt"] {
        let f = files.iter().find(|a| {
            a.metadata
                .get("name")
                .and_then(|v| v.as_str())
                .map(|n| n.eq_ignore_ascii_case(want))
                .unwrap_or(false)
        });
        let f = f.unwrap_or_else(|| panic!("DFTT #5 file {want} not recovered"));
        let has_ts = ["modified", "created", "mtime", "accessed"]
            .iter()
            .any(|k| f.metadata.get(*k).and_then(|v| v.as_str()).is_some());
        assert!(has_ts, "{want} has no parseable timestamp");
    }
}
