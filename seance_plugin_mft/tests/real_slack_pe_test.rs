//! HUNT-124 (SLACK-2): `carved_executable_in_slack` fires from a real NTFS
//! volume inside a partitioned disk, and the offsets it reports are the ones an
//! independent reader (`ntfscluster`) put the planted bytes at.
//!
//! SYNTHETIC. The volume is real `mkntfs` output in an MBR partition starting
//! at LBA 2048, but the PE image in `host.bin`'s cluster slack was planted by
//! `scripts/synth/build_ntfs_slack_pe_fixture.py`. This grades the mechanism on
//! a real file system volume with a non-zero partition start. It says nothing
//! about how often real evidence holds an executable in slack. The answer is
//! `expected.json`, written by the script from `ntfscluster`'s output, never
//! from Séance.

use std::io::Read;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_carver::UnallocatedCarver;
use seance_plugin_findings::PeFindings;
use seance_plugin_mft::MftParser;
use seance_plugin_partition::{FilesystemDetector, PartitionParser};
use seance_plugin_pe::PeSignatureParser;
use serde_json::{json, Value};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ntfs_slack_pe");

fn disk() -> Vec<u8> {
    let gz = std::fs::File::open(format!("{DIR}/ntfs_slack_pe.img.gz")).expect("fixture");
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut raw)
        .unwrap();
    raw
}

#[test]
fn carved_executable_in_slack_fires_on_a_real_partitioned_ntfs_volume() {
    let expected: Value =
        serde_json::from_slice(&std::fs::read(format!("{DIR}/expected.json")).unwrap()).unwrap();
    assert_eq!(expected["synthetic"], true);
    let raw_bytes = disk();
    let pe_at = expected["pe_disk_offset"].as_u64().unwrap();
    let part_start = expected["partition_start_bytes"].as_u64().unwrap();
    assert!(part_start > 0, "the point is a non-zero partition start");
    assert_eq!(
        &raw_bytes[pe_at as usize..pe_at as usize + 2],
        b"MZ",
        "the planted bytes are where the answer key says"
    );

    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(raw_bytes.clone()));
    let raw = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(source),
        json!({ "name": "ntfs_slack_pe.img" }),
    );
    let partitions: Vec<Artifact> = PartitionParser
        .process(&raw)
        .unwrap()
        .into_iter()
        .filter(|a| a.artifact_type == ArtifactType::Partition)
        .collect();
    assert_eq!(partitions.len(), 1, "one MBR partition");
    let filesystems: Vec<Artifact> = FilesystemDetector
        .process(&partitions[0])
        .unwrap()
        .into_iter()
        .filter(|a| a.artifact_type == ArtifactType::FileSystem)
        .collect();
    assert_eq!(filesystems.len(), 1);

    let out = MftParser::new().process(&filesystems[0]).unwrap();
    let regions: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .collect();
    let hosts: Vec<&str> = regions
        .iter()
        .map(|r| r.metadata["parent_file"].as_str().unwrap())
        .collect();
    assert_eq!(hosts, ["host.bin"], "only the planted tail is a region");
    let region = regions[0];

    let lcn = expected["lcn"]["host.bin"].as_u64().unwrap();
    let cluster = expected["cluster_size"].as_u64().unwrap();
    assert_eq!(
        region.metadata["offset_bytes"].as_u64().unwrap(),
        lcn * cluster + 1000,
        "region offset is volume-relative: the tail starts at the logical end"
    );

    let carved = UnallocatedCarver::new().process(region).unwrap();
    let exe = carved
        .iter()
        .find(|a| a.artifact_type == ArtifactType::FileEntry)
        .expect("the PE in slack is carved");
    let volume_relative = pe_at - part_start;
    assert_eq!(
        exe.metadata["carving_offset_absolute"].as_u64().unwrap(),
        volume_relative,
        "carving_offset_absolute is the offset in the parent FileSystem"
    );
    // Composed with the partition start the FileSystem artifact carries, it is
    // the device offset ntfscluster implies.
    assert_eq!(
        filesystems[0].metadata["offset_bytes"].as_u64().unwrap() + volume_relative,
        pe_at
    );
    assert!(region.metadata["offset_basis"]
        .as_str()
        .unwrap()
        .contains("start of this volume"));

    let findings: Vec<Artifact> = PeSignatureParser
        .process(exe)
        .unwrap()
        .iter()
        .flat_map(|r| PeFindings::new().process(r).unwrap())
        .collect();
    let slack: Vec<&Artifact> = findings
        .iter()
        .filter(|f| f.metadata["finding_kind"] == "carved_executable_in_slack")
        .collect();
    assert_eq!(slack.len(), 1, "{findings:?}");
    assert!(slack[0].metadata["observation"]
        .as_str()
        .unwrap()
        .contains("host.bin"));
}
