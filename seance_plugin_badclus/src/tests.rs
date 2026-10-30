use super::*;
use uuid::Uuid;

// Build a $BadClus:$Bad-style artifact carrying the parsed runlist in
// `data_runs` metadata, exactly as the MFT parser emits it for the $Bad ADS.
fn badclus_artifact(metadata: serde_json::Value) -> Artifact {
    Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, None, metadata)
}

#[test]
fn test_recovers_bad_clusters_from_data_runs_metadata() {
    // Two non-sparse runs (bad clusters) interleaved with sparse runs (good
    // clusters). Only the non-sparse runs must be reported, at their exact byte
    // offsets, with cluster figures derived from the supplied cluster size.
    let artifact = badclus_artifact(serde_json::json!({
        "name": "$BadClus:$Bad",
        "stream_name": "$Bad",
        "is_ads": true,
        "cluster_size": 4096,
        "data_runs": [
            [null, 40960],     // 10 good clusters (sparse)
            [40960, 8192],     // bad: LCN 10, 2 clusters
            [null, 4096],      // 1 good cluster (sparse)
            [131072, 4096],    // bad: LCN 32, 1 cluster
        ],
    }));

    let parser = BadClusParser;
    let results = parser.process(&artifact).expect("parser failed");

    assert_eq!(
        results.len(),
        2,
        "only the two non-sparse runs are bad clusters"
    );

    let r0 = &results[0].metadata;
    assert_eq!(r0["record_type"], "badclus_range");
    assert_eq!(r0["stream"], "$BadClus:$Bad");
    assert_eq!(r0["volume_offset_bytes"], 40960);
    assert_eq!(r0["length_bytes"], 8192);
    assert_eq!(r0["cluster_start_lcn"], 10);
    assert_eq!(r0["cluster_end_lcn"], 11);
    assert_eq!(r0["cluster_count"], 2);
    // VCN is the byte position within $Bad (40960) / cluster size.
    assert_eq!(r0["vcn_start"], 10);
    assert_eq!(r0["vcn_end"], 11);

    let r1 = &results[1].metadata;
    assert_eq!(r1["volume_offset_bytes"], 131072);
    assert_eq!(r1["length_bytes"], 4096);
    assert_eq!(r1["cluster_start_lcn"], 32);
    assert_eq!(r1["cluster_count"], 1);
    assert_eq!(r1["cluster_end_lcn"], 32);
}

#[test]
fn test_matches_ads_via_name_key_not_file_name() {
    // The MFT $Bad ADS is keyed by "name" (not "file_name"). The parser must
    // still match it.
    let artifact = badclus_artifact(serde_json::json!({
        "name": "$BadClus:$Bad",
        "data_runs": [[40960, 4096]],
    }));

    let parser = BadClusParser;
    let results = parser.process(&artifact).expect("parser failed");
    assert_eq!(results.len(), 1);
}

#[test]
fn test_byte_offsets_exact_without_cluster_size() {
    // Without a cluster size, byte offsets are still exact; cluster/LCN fields
    // are reported null rather than derived from an assumed 4 KiB cluster.
    let artifact = badclus_artifact(serde_json::json!({
        "name": "$BadClus:$Bad",
        "data_runs": [[8_589_934_592u64, 65536]], // 8 GiB offset, non-4K-aligned volume
    }));

    let parser = BadClusParser;
    let results = parser.process(&artifact).expect("parser failed");
    assert_eq!(results.len(), 1);
    let m = &results[0].metadata;
    assert_eq!(m["volume_offset_bytes"], 8_589_934_592u64);
    assert_eq!(m["length_bytes"], 65536);
    assert!(m["cluster_start_lcn"].is_null());
    assert!(m["cluster_count"].is_null());
    assert!(m["cluster_size_bytes"].is_null());
}

#[test]
fn test_all_sparse_runs_yield_no_bad_clusters() {
    // A healthy volume: $Bad is one giant sparse run. No bad clusters.
    let artifact = badclus_artifact(serde_json::json!({
        "name": "$BadClus:$Bad",
        "cluster_size": 4096,
        "data_runs": [[null, 1_073_741_824u64]], // whole volume sparse
    }));

    let parser = BadClusParser;
    let results = parser.process(&artifact).expect("parser failed");
    assert_eq!(results.len(), 0, "sparse runs are good clusters, not bad");
}

/// Bad clusters live in the MFT run list; a `$BadClus:$Bad` artifact without
/// one (raw content only) must not fabricate ranges from content — and must
/// not answer "no bad clusters" either, because it could not look (HUNT-220).
#[test]
fn a_bad_cluster_stream_with_no_run_list_says_it_could_not_look() {
    let artifact = badclus_artifact(serde_json::json!({
        "name": "$BadClus:$Bad",
        "path": "/$BadClus:$Bad",
    }));

    let results = BadClusParser
        .process(&artifact)
        .expect("missing runlist must be handled, not error");
    assert!(
        results
            .iter()
            .all(|a| a.metadata["record_type"] != "badclus_range"),
        "no range may be invented from content: {results:?}"
    );
    let status = results
        .iter()
        .find(|a| a.metadata["record_type"] == "badclus_status")
        .expect("a stream with no run list must be published as unread, not as clean");
    assert_eq!(status.metadata["inventory_incomplete"], true);
    assert_eq!(
        status.metadata["inventory_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(status.metadata["ranges_reported"], 0);
    assert_eq!(status.metadata["run_list_absent"], true);
}

/// The gate was `contains("$Bad")`: any file whose name or path merely
/// contains `$Bad` was read as the volume's bad-cluster map, and its content
/// runs published as bad clusters (HUNT-220).
#[test]
fn a_file_whose_name_merely_contains_bad_is_not_read_as_the_bad_cluster_map() {
    for (name, path) in [
        ("$Badger.txt", "/Users/alice/$Badger.txt"),
        ("notes.txt", "/$BadClus_backup/notes.txt"),
        // The base record's unnamed stream is not the `$Bad` map.
        ("$BadClus", "/$BadClus"),
    ] {
        let artifact = badclus_artifact(serde_json::json!({
            "name": name,
            "path": path,
            "cluster_size": 4096,
            "data_runs": [[40960, 4096]],
        }));
        let out = BadClusParser.process(&artifact).expect("parse");
        assert!(out.is_empty(), "{path} is not $BadClus:$Bad: {out:?}");
    }
}

#[test]
fn test_non_badclus_artifact_skipped() {
    let artifact = badclus_artifact(serde_json::json!({
        "name": "notes.txt",
        "data_runs": [[40960, 4096]],
    }));

    let parser = BadClusParser;
    let results = parser.process(&artifact).expect("parser failed");
    assert_eq!(results.len(), 0);
}

#[test]
fn test_malformed_data_runs_error() {
    // A data_runs value that is not [offset, length] pairs is a hard parse
    // error, not a silent empty result.
    let artifact = badclus_artifact(serde_json::json!({
        "name": "$BadClus:$Bad",
        "data_runs": [[40960]], // wrong arity
    }));

    let parser = BadClusParser;
    assert!(parser.process(&artifact).is_err());
}

#[test]
fn test_matches_via_source_path_for_raw_evidence() {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        None,
        serde_json::json!({
            "source_path": "C:\\$Extend\\$BadClus:$Bad",
            "cluster_size": 4096,
            "data_runs": [[40960, 4096]],
        }),
    );

    let parser = BadClusParser;
    let results = parser.process(&artifact).expect("parser failed");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].metadata["cluster_start_lcn"], 10);
}

// --- Graded through the producer on a real volume (HUNT-155) -----------------

/// `reference/dfir_ntfs/test_data/ntfs_index.raw.gz`: a real 32 MiB NTFS volume
/// at sector 128 with 2,048-byte clusters. Its `$BadClus:$Bad` is what every
/// real volume has — one sparse run the length of the volume, `real_size`
/// 30,406,656 and `initialized_size` 0. Gitignored, so absent in CI.
fn load_real_volume() -> Option<Vec<u8>> {
    use std::io::Read;
    let path = std::path::Path::new("../reference/dfir_ntfs/test_data/ntfs_index.raw.gz");
    if !path.exists() {
        eprintln!("skipping: {path:?} not present (gitignored corpus, absent in CI)");
        return None;
    }
    let mut image = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).expect("open"))
        .read_to_end(&mut image)
        .expect("decompress");
    Some(image[128 * 512..].to_vec())
}

/// Byte offset of MFT record 8 (`$BadClus`) in the volume.
const BADCLUS_RECORD: usize = 4949 * 2048 + 8 * 1024;
/// Offset of the `$Bad` attribute within that record, and of its mapping pairs
/// within the attribute (read off the real record).
const BAD_ATTR: usize = 288;
const BAD_RUNS: usize = 72;

/// Mark clusters 1000 and 1001 bad the way CHKDSK does: split `$Bad`'s single
/// sparse run into sparse 1,000 / 2 clusters at LCN 1,000 / sparse remainder.
/// The mapping pairs grow from 4 bytes to 11, so the attribute grows by 8 and
/// the end marker and the record's used size move with it — the same edit
/// `chkdsk /r` makes. Only bytes below offset 510 change, so the record's
/// update-sequence placeholders are untouched.
fn mark_two_clusters_bad(volume: &mut [u8]) {
    let rec = BADCLUS_RECORD;
    let attr = rec + BAD_ATTR;
    assert_eq!(&volume[rec..rec + 4], b"FILE");
    assert_eq!(
        &volume[attr + BAD_RUNS..attr + BAD_RUNS + 4],
        &[0x02, 0xff, 0x39, 0x00],
        "the real volume's $Bad is one sparse run of 14,847 clusters"
    );
    let runs: [u8; 16] = [
        0x02, 0xe8, 0x03, // sparse, 1,000 clusters
        0x21, 0x02, 0xe8, 0x03, // 2 clusters at LCN 1,000
        0x02, 0x15, 0x36, // sparse, 13,845 clusters
        0x00, 0, 0, 0, 0, 0, // terminator, padding to 8
    ];
    volume[attr + BAD_RUNS..attr + BAD_RUNS + 16].copy_from_slice(&runs);
    volume[attr + 4..attr + 8].copy_from_slice(&88u32.to_le_bytes());
    // End-of-attributes marker, then the record's used size.
    volume[attr + 88..attr + 96].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
    volume[rec + 0x18..rec + 0x1c].copy_from_slice(&384u32.to_le_bytes());
}

fn bad_stream_from(volume: Vec<u8>) -> Artifact {
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(ByteSliceDataSource::new(volume))),
        serde_json::json!({ "filesystem_type": "NTFS" }),
    );
    seance_plugin_mft::MftParser::new()
        .process(&fs)
        .expect("the MFT parser reads the real volume")
        .into_iter()
        .find(|a| a.metadata["name"] == "$BadClus:$Bad")
        .expect("the MFT parser emits $BadClus:$Bad")
}

/// HUNT-155: the producer reduced `$Bad`'s runs to its logical extent against
/// `initialized_size` 0, discarding every bad-cluster run, so this module was
/// handed a single sparse run and reported nothing on any real volume.
#[test]
fn a_bad_cluster_marked_on_a_real_volume_is_reported() {
    let Some(mut volume) = load_real_volume() else {
        return;
    };
    mark_two_clusters_bad(&mut volume);
    let stream = bad_stream_from(volume);
    let out = BadClusParser.process(&stream).expect("parse");
    let ranges: Vec<&serde_json::Value> = out
        .iter()
        .map(|a| &a.metadata)
        .filter(|m| m["record_type"] == "badclus_range")
        .collect();
    assert_eq!(ranges.len(), 1, "one bad range: {out:?}");
    let r = ranges[0];
    assert_eq!(r["volume_offset_bytes"], 1000 * 2048);
    assert_eq!(r["length_bytes"], 2 * 2048);
    assert_eq!(r["cluster_size_bytes"], 2048);
    assert_eq!(r["cluster_start_lcn"], 1000);
    assert_eq!(r["cluster_end_lcn"], 1001);
    assert_eq!(r["vcn_start"], 1000);
}

/// The same real volume, unmodified: `$Bad` is all sparse, so there is no bad
/// cluster — and the module must have been handed the run list that says so,
/// not an absent one.
#[test]
fn a_real_volume_with_no_bad_clusters_reports_none_having_read_the_runs() {
    let Some(volume) = load_real_volume() else {
        return;
    };
    let stream = bad_stream_from(volume);
    assert_eq!(
        stream.metadata["bad_cluster_runs"],
        serde_json::json!([[null, 30_406_656u64]])
    );
    let out = BadClusParser.process(&stream).expect("parse");
    assert!(out
        .iter()
        .all(|a| a.metadata["record_type"] != "badclus_range"));
}

/// When the producer says it could not assemble all of `$Bad`'s runs, the
/// ranges reported are some of the bad clusters, and the listing says so.
#[test]
fn an_incomplete_bad_cluster_run_list_is_published_as_a_short_listing() {
    let artifact = badclus_artifact(serde_json::json!({
        "name": "$BadClus:$Bad",
        "stream_name": "$Bad",
        "is_ads": true,
        "record_number": 8,
        "cluster_size": 4096,
        "data_runs": [[null, 1_048_576]],
        "bad_cluster_runs": [[null, 40960], [40960, 4096], [null, 1_003_520]],
        "bad_cluster_runs_complete": false,
    }));
    let out = BadClusParser.process(&artifact).expect("parse");
    assert_eq!(
        out.iter()
            .filter(|a| a.metadata["record_type"] == "badclus_range")
            .count(),
        1
    );
    let status = out
        .iter()
        .find(|a| a.metadata["record_type"] == "badclus_status")
        .expect("an incomplete run list must be published");
    assert_eq!(status.metadata["inventory_incomplete"], true);
}
