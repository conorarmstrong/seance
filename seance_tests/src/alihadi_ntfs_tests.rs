//! End-to-end regression against Ali Hadi's NTFS challenge image.
//!
//! A second public corpus beside CFReDS, and a different kind of check. CFReDS
//! publishes answers about the *contents* of a disk; this image publishes the
//! FTK Imager acquisition log, which states what the bytes themselves hash to.
//! That makes it the one test here that can say Séance's E01 decoder returns
//! exactly the stream a third party acquired — not merely something that parses.
//!
//! The image is small (474 KB compressed, 97 MB decoded), so unlike the other
//! corpora this one is cheap enough to run on every developer machine that has
//! it. Point `SEANCE_ALIHADI_NTFS` at a directory holding
//! `NTFS-HiddenFiles.E01`. Absent, these skip; named and missing, they fail —
//! see [`seance_core::test_support::corpus`].
//!
//! From `NTFS-HiddenFiles.E01.txt`, distributed beside the image:
//!
//! | Field | Value |
//! |---|---|
//! | Case / Evidence number | `003` |
//! | Description | `NTFS File System Case (ADS and Friends)` |
//! | Examiner | `AHMK` |
//! | Sector count × size | 198,656 × 512 = 101,711,872 bytes |
//! | MD5 of acquired data | `e7d5b36a407d5a02d0872d4dd3f3f9d0` |
//! | SHA1 of acquired data | `5edc4c6efda9d266ecabcab5629694d0063e9d7f` |
//!
//! Requires the `e01` feature: without libewf there is no way in.

use seance_container_e01::E01ContainerModule;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::ForensicsModule,
    test_support::corpus,
};
use serde_json::json;
use uuid::Uuid;

const CORPUS_VAR: &str = "SEANCE_ALIHADI_NTFS";
const IMAGE: &str = "NTFS-HiddenFiles.E01";

/// What FTK Imager recorded when it made this image.
const ACQUIRED_MD5: &str = "e7d5b36a407d5a02d0872d4dd3f3f9d0";
const ACQUIRED_SHA1: &str = "5edc4c6efda9d266ecabcab5629694d0063e9d7f";
const SECTOR_COUNT: u64 = 198_656;
const SECTOR_SIZE: u64 = 512;

/// E01 → RawEvidence, or `None` to skip.
fn raw_evidence(case_id: Uuid) -> Option<Artifact> {
    let path = corpus::file(CORPUS_VAR, IMAGE)?;
    let size = std::fs::metadata(&path)
        .expect("the corpus gate proved this path exists")
        .len();
    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": IMAGE,
            "path": path.to_string_lossy(),
            "size": size,
        }),
    );
    let produced = E01ContainerModule
        .process(&artifact)
        .expect("libewf opens the image");
    let raw = produced
        .into_iter()
        .next()
        .expect("one image is one RawEvidence");
    assert!(
        raw.data.is_some(),
        "a RawEvidence with no data source reads as an empty disk rather than \
         as a failure to open one"
    );
    Some(raw)
}

/// The acquisition log's header fields, which no parsing of the disk reaches.
#[test]
fn the_ewf_header_carries_the_published_acquisition_metadata() {
    let Some(raw) = raw_evidence(Uuid::new_v4()) else {
        return;
    };
    let ewf = raw
        .metadata
        .get("e01_metadata")
        .expect("the E01 reader publishes the header it read");

    assert_eq!(ewf.get("case_number").and_then(|v| v.as_str()), Some("003"));
    assert_eq!(
        ewf.get("examiner").and_then(|v| v.as_str()),
        Some("AHMK"),
        "the examiner of record"
    );

    // The embedded header and the `.txt` acquisition log beside it disagree
    // about this one field: the header says "Advanced ADS and File Systems",
    // the log's "Unique description" says "NTFS File System Case (ADS and
    // Friends)". Both ship with the image and an examiner could cite either.
    //
    // The header is what Séance reads and therefore what is asserted, and the
    // difference is written down here rather than reconciled — a tool must
    // report what the evidence carries, not what a sidecar file says it should.
    assert_eq!(
        ewf.get("description").and_then(|v| v.as_str()),
        Some("Advanced ADS and File Systems"),
    );
}

/// The decoded stream is exactly as long as the acquisition says.
///
/// A decoder that returns a short stream and no error is the failure this
/// guards: every parser above it would then read a truncated disk as a small
/// one, and report what it found as everything there was.
#[test]
fn the_decoded_image_is_the_length_the_acquisition_recorded() {
    let Some(raw) = raw_evidence(Uuid::new_v4()) else {
        return;
    };
    let source = raw.data.as_ref().expect("checked in raw_evidence");
    assert_eq!(
        source.size(),
        SECTOR_COUNT * SECTOR_SIZE,
        "FTK recorded {SECTOR_COUNT} sectors of {SECTOR_SIZE} bytes"
    );
}

/// **The strong one:** the decoded bytes hash to what FTK Imager hashed.
///
/// Every other test in this workspace checks that Séance *understood* an image.
/// This checks that it *read* one — byte for byte against a digest computed by
/// a different tool, on a different machine, in 2023, before this decoder
/// existed. Nothing about the assertion depends on Séance being right about
/// anything else.
///
/// Both digests are checked in one pass, because a stream that matches on MD5
/// and not SHA-1 is a finding rather than a rounding error.
#[test]
fn the_decoded_bytes_hash_to_the_acquisition_digests() {
    // One import covers both: md-5 and sha1 re-export the same `digest::Digest`.
    use md5::Digest as _;

    let Some(raw) = raw_evidence(Uuid::new_v4()) else {
        return;
    };
    let source = raw.data.as_ref().expect("checked in raw_evidence");

    let total = source.size();
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut offset = 0u64;

    while offset < total {
        let want = std::cmp::min(buffer.len() as u64, total - offset) as usize;
        let read = source
            .read_at(offset, &mut buffer[..want])
            .expect("the decoded stream is readable to its stated end");
        assert!(
            read > 0,
            "read stalled at {offset} of {total} with bytes still to come, so \
             the stream ends before the acquisition says it does"
        );
        md5.update(&buffer[..read]);
        sha1.update(&buffer[..read]);
        offset += read as u64;
    }

    assert_eq!(
        format!("{:x}", md5.finalize()),
        ACQUIRED_MD5,
        "the decoded stream is not the stream FTK Imager acquired"
    );
    assert_eq!(
        format!("{:x}", sha1.finalize()),
        ACQUIRED_SHA1,
        "MD5 matched and SHA-1 did not, which is a finding rather than a \
         rounding error"
    );
}

/// **The free clusters of this volume become regions a carver can be pointed
/// at** (`ROADMAP` §5.4), on a real NTFS filesystem a third party acquired.
///
/// This image is an FTK *logical* acquisition — "Source Type: Logical" in the
/// log beside it — so the NTFS volume starts at byte 0 of the decoded stream
/// and the MFT parser can be handed it directly, with no partition table in
/// between.
///
/// The assertions are structural and independent of the code that produced the
/// regions: a region must lie inside the volume, regions must not overlap one
/// another, they must be in address order, and **cluster 0 must never be in
/// one** — it holds the boot sector, NTFS marks it allocated, and a free
/// region covering it would mean the bit convention is inverted. That last one
/// is the check that catches the error this route could make that would look
/// entirely ordinary.
#[test]
fn the_free_clusters_of_a_real_ntfs_volume_become_carvable_regions() {
    let Some(raw) = raw_evidence(Uuid::new_v4()) else {
        return;
    };
    let source = raw.data.clone().expect("the decoded stream");
    let volume = Artifact::new(
        raw.case_id,
        ArtifactType::FileSystem,
        Some(source),
        json!({"name": "NTFS volume", "filesystem_type": "NTFS"}),
    );
    let produced = seance_plugin_mft::MftParser::new()
        .process(&volume)
        .expect("the MFT parses");

    let map = produced
        .iter()
        .find(|a| a.metadata["type"] == "allocation_map")
        .expect("a real NTFS volume publishes its allocation map");
    let cluster_size = map.metadata["allocation_cluster_size"]
        .as_u64()
        .expect("the map states its cluster size");
    let total_clusters = map.metadata["allocation_total_clusters"]
        .as_u64()
        .expect("the map states the volume's extent");
    let volume_bytes = total_clusters * cluster_size;
    eprintln!("  volume: {total_clusters} clusters of {cluster_size} bytes = {volume_bytes} bytes");

    let regions: Vec<&Artifact> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .collect();
    eprintln!(
        "  free space: {} region(s), {} bytes, {} run(s) dropped, {} cluster(s) unassessed",
        map.metadata["free_regions_emitted"],
        map.metadata["free_bytes_emitted"],
        map.metadata["free_runs_dropped"],
        map.metadata["free_space_unassessed_clusters"],
    );
    assert!(
        !regions.is_empty(),
        "a 97 MB volume holding a handful of test files has free clusters; none was emitted"
    );
    assert_eq!(
        regions.len(),
        map.metadata["free_regions_emitted"].as_u64().unwrap() as usize,
        "the count on the map is the number of regions actually emitted"
    );

    let mut previous_end = 0u64;
    let mut emitted_bytes = 0u64;
    for region in &regions {
        let offset = region.metadata["offset_bytes"].as_u64().expect("offset");
        let size = region.metadata["size_bytes"].as_u64().expect("size");
        let first_cluster = region.metadata["first_cluster"].as_u64().expect("cluster");
        assert!(size > 0, "a zero-length region is not a region");
        assert!(
            offset >= previous_end,
            "regions overlap or are out of order: {offset} follows an end of {previous_end}"
        );
        assert!(
            offset + size <= volume_bytes,
            "a region at {offset}+{size} reaches past the volume's {volume_bytes} bytes"
        );
        assert_eq!(
            offset,
            first_cluster * cluster_size,
            "a region's offset must be its first cluster's own address"
        );
        assert!(
            first_cluster > 0,
            "cluster 0 holds the boot sector and NTFS marks it allocated; a free region \
             covering it means the bit convention is inverted"
        );
        assert_eq!(
            region.data.as_ref().map(|d| d.size()),
            Some(size),
            "the window is the length the record declares"
        );
        previous_end = offset + size;
        emitted_bytes += size;
    }
    assert_eq!(
        emitted_bytes,
        map.metadata["free_bytes_emitted"].as_u64().unwrap(),
        "the byte total on the map is the bytes the regions actually cover"
    );
    // Free space is a fraction of a volume, not all of it: a pass that called
    // the whole volume free would mean the bitmap was never read.
    assert!(
        emitted_bytes < volume_bytes,
        "every byte of the volume was called free, so the bitmap was not read"
    );

    // And the whole point: the automatic carver subscribes to this type, so a
    // region reaching it is what turns a bitmap into recovered files. Before
    // §5.4 the only regions in existence were the partition table's gaps, and
    // on a logical acquisition like this one there are none at all -- so
    // nothing was ever carved from this image automatically.
    use seance_core::module::ForensicsModule as _;
    let carver = seance_plugin_carver::UnallocatedCarver::new();
    assert!(
        carver
            .subscribes_to()
            .contains(&ArtifactType::UnallocatedSpace),
        "the carver must subscribe to the type this now produces"
    );
    let biggest = regions
        .iter()
        .max_by_key(|r| r.metadata["size_bytes"].as_u64().unwrap_or(0))
        .expect("at least one region");
    let carved = carver
        .process(biggest)
        .expect("the carver reads the region");
    let summary = carved
        .iter()
        .find(|a| a.metadata["type"] == "CarvingSummary")
        .expect("a region the carver read produces a summary, whatever it found");
    eprintln!(
        "  carver over the largest region: {} bytes scanned, {} file(s) carved",
        summary.metadata["scanned_bytes"], summary.metadata["total_carved"],
    );
    assert_eq!(
        summary.metadata["scanned_bytes"].as_u64(),
        biggest.metadata["size_bytes"].as_u64(),
        "the carver scanned the whole region the bitmap proved free"
    );
}
