use super::*;
use crate::data_source::ByteSliceDataSource;
use crate::free_space::{emit_free_regions, AllocationBitmap, BitMeaning, FreeSpaceLabels};

const CLUSTER: u64 = 4096;

fn summary_of(out: &[Artifact]) -> &serde_json::Value {
    &out.iter()
        .find(|a| a.metadata["subtype"] == "slack_space_summary")
        .expect("a summary is always emitted")
        .metadata
}

const LABELS: SlackLabels = SlackLabels {
    filesystem: "NTFS",
    offset_basis: "the start of this volume, not the start of the evidence",
};

fn fs_parent() -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        None,
        json!({"name": "volume"}),
    )
}

fn owner(id: Uuid, logical: u64) -> SlackOwner<'static> {
    SlackOwner {
        artifact_id: id,
        name: "file-n-4.dat",
        path: Some("/file-n-4.dat"),
        logical_size: logical,
    }
}

fn volume_with(bytes: usize, plant: &[(usize, &[u8])]) -> Arc<dyn DataSource> {
    let mut v = vec![0u8; bytes];
    for (at, data) in plant {
        v[*at..*at + data.len()].copy_from_slice(data);
    }
    Arc::new(ByteSliceDataSource::new(v))
}

#[test]
fn slack_window_from_allocation_runs_rounds_to_cluster_end() {
    // 1000 bytes in one cluster at byte 409600 of the volume.
    let w = slack_window(&[(Some(409_600), CLUSTER)], 1000, CLUSTER);
    assert_eq!(
        w,
        Some(SlackWindow {
            offset: 410_600,
            len: 3096
        })
    );
}

#[test]
fn slack_window_lands_in_the_run_holding_the_last_logical_byte() {
    // Two fragments: 2 clusters at 8192, then 1 cluster at 81920. A file of
    // 2*4096 + 10 bytes ends 10 bytes into the second fragment.
    let runs = [(Some(8192), 2 * CLUSTER), (Some(81_920), CLUSTER)];
    let w = slack_window(&runs, 2 * CLUSTER + 10, CLUSTER).unwrap();
    assert_eq!(w.offset, 81_930);
    assert_eq!(w.len, CLUSTER - 10);
}

#[test]
fn slack_window_does_not_assume_volume_aligned_clusters() {
    // FAT: the data region starts at an offset that is not a cluster
    // multiple of the volume, so a run's physical start is not either.
    let w = slack_window(&[(Some(17_408), CLUSTER)], 100, CLUSTER).unwrap();
    assert_eq!(w.offset, 17_508);
    assert_eq!(w.len, CLUSTER - 100);
}

#[test]
fn cluster_aligned_file_has_no_slack() {
    assert_eq!(
        slack_window(&[(Some(409_600), CLUSTER)], CLUSTER, CLUSTER),
        None
    );
    assert_eq!(slack_window(&[(Some(409_600), CLUSTER)], 0, CLUSTER), None);
}

#[test]
fn sparse_last_run_has_no_slack_window() {
    // The last logical byte is in a hole: no cluster, so no slack on disk,
    // and zeros are never offered as another tenant's bytes.
    let runs = [(Some(8192), CLUSTER), (None, CLUSTER)];
    assert_eq!(slack_window(&runs, CLUSTER + 100, CLUSTER), None);
}

#[test]
fn allocation_shorter_than_logical_has_no_slack_window() {
    assert_eq!(
        slack_window(&[(Some(8192), CLUSTER)], CLUSTER + 1, CLUSTER),
        None
    );
}

#[test]
fn zero_cluster_size_has_no_slack_window() {
    assert_eq!(slack_window(&[(Some(8192), CLUSTER)], 100, 0), None);
}

#[test]
fn all_zero_tail_emits_no_region_but_is_counted() {
    let parent = fs_parent();
    let vol = volume_with(512 * 1024, &[]);
    let mut c = SlackCollector::new(LABELS, CLUSTER);
    let w = slack_window(&[(Some(409_600), CLUSTER)], 1000, CLUSTER).unwrap();
    c.offer(&parent, &vol, owner(Uuid::new_v4(), 1000), w);
    let (out, outcome) = c.finish(&parent);
    assert!(out
        .iter()
        .all(|a| a.artifact_type != ArtifactType::SlackSpace));
    assert_eq!(outcome.files_offered, 1);
    assert_eq!(outcome.zero_tails, 1);
    assert_eq!(outcome.regions_emitted, 0);
}

#[test]
fn nonzero_tail_emits_region_with_file_slack_source() {
    let parent = fs_parent();
    let file_id = Uuid::new_v4();
    let vol = volume_with(512 * 1024, &[(409_600 + 1024, b"MZ")]);
    let mut c = SlackCollector::new(LABELS, CLUSTER);
    let w = slack_window(&[(Some(409_600), CLUSTER)], 1000, CLUSTER).unwrap();
    c.offer(&parent, &vol, owner(file_id, 1000), w);
    let (out, outcome) = c.finish(&parent);
    let regions: Vec<_> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .collect();
    assert_eq!(regions.len(), 1);
    let r = regions[0];
    assert_eq!(r.parent_id, Some(parent.id));
    let m = &r.metadata;
    assert_eq!(m["offset_bytes"], 410_600);
    assert_eq!(m["size_bytes"], 3096);
    assert_eq!(m["source"], "file_slack");
    assert_eq!(m["region_kind"], "slack");
    assert_eq!(m["parent_file"], "file-n-4.dat");
    assert_eq!(m["parent_path"], "/file-n-4.dat");
    assert_eq!(m["owner_artifact_id"], file_id.to_string());
    assert_eq!(m["logical_size"], 1000);
    assert_eq!(m["cluster_size"], CLUSTER);
    assert_eq!(m["filesystem"], "NTFS");
    assert!(m["offset_basis"].as_str().unwrap().contains("volume"));
    let means = m["slack_means"].as_str().unwrap();
    assert!(means.contains("NOT free space"), "{means}");
    // The region's bytes are the tail, not the file.
    let ds = r.data.as_ref().unwrap();
    assert_eq!(ds.size(), 3096);
    let mut two = [0u8; 2];
    ds.read_at(24, &mut two).unwrap();
    assert_eq!(&two, b"MZ");
    assert_eq!(outcome.regions_emitted, 1);
    assert_eq!(outcome.bytes_emitted, 3096);
}

#[test]
fn a_tail_that_reads_short_is_counted_as_not_examined() {
    let parent = fs_parent();
    // The volume ends 100 bytes into the slack window.
    let vol = volume_with(409_600 + 1100, &[(409_600 + 1050, b"x")]);
    let mut c = SlackCollector::new(LABELS, CLUSTER);
    let w = slack_window(&[(Some(409_600), CLUSTER)], 1000, CLUSTER).unwrap();
    c.offer(&parent, &vol, owner(Uuid::new_v4(), 1000), w);
    let (out, outcome) = c.finish(&parent);
    assert!(out
        .iter()
        .all(|a| a.artifact_type != ArtifactType::SlackSpace));
    assert_eq!(outcome.unreadable_tails, 1);
    assert_eq!(outcome.zero_tails, 0);
    let s = summary_of(&out);
    assert_eq!(s["content_incomplete"], true);
    assert_eq!(
        s["content_incomplete_reason"],
        crate::io::IncompleteReason::ShortRead.as_str()
    );
}

#[test]
fn summary_is_emitted_even_when_no_region_was() {
    let parent = fs_parent();
    let c = SlackCollector::new(LABELS, CLUSTER);
    let (out, _) = c.finish(&parent);
    let summaries: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["subtype"] == "slack_space_summary")
        .collect();
    assert_eq!(summaries.len(), 1);
    let s = &summaries[0].metadata;
    assert_eq!(s["artifact_kind"], "slack_space_summary");
    assert_eq!(s["regions_emitted"], 0);
    assert_eq!(s["max_slack_regions"], MAX_SLACK_REGIONS_PER_VOLUME);
    // Nothing was skipped, so the summary does not claim incompleteness.
    assert!(s.get("content_incomplete").is_none());
    assert!(s.get("content_incomplete_reason").is_none());
    assert!(s["statement"].as_str().unwrap().contains("slack"));
    assert_eq!(summaries[0].parent_id, Some(parent.id));
    assert_eq!(summaries[0].artifact_type, ArtifactType::ParsedRecord);
}

#[test]
fn files_past_the_ceiling_are_counted_not_read() {
    let parent = fs_parent();
    let vol = volume_with(64 * 1024, &[(4096 + 500, b"z")]);
    let mut c = SlackCollector::new(LABELS, CLUSTER).with_ceiling(1);
    let w = slack_window(&[(Some(4096), CLUSTER)], 100, CLUSTER).unwrap();
    c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), w);
    c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), w);
    let (out, outcome) = c.finish(&parent);
    assert_eq!(outcome.regions_emitted, 1);
    assert!(outcome.region_cap_reached);
    assert_eq!(outcome.files_not_examined_at_cap, 1);
    assert_eq!(outcome.files_offered, 2);
    let s = summary_of(&out);
    assert_eq!(s["content_incomplete"], true);
    assert_eq!(
        s["content_incomplete_reason"],
        crate::io::IncompleteReason::CapReached.as_str()
    );
}

/// Slack and free-space producers side by side: the regions differ in type and
/// the free total is the bitmap's alone. This shows only that the types differ;
/// the consumers that read `UnallocatedSpace` (the disk map, its free total and
/// the ad-hoc carve's targets) are pinned against slack in
/// `seance_db/tests/slack_is_not_free_space_test.rs`.
#[test]
fn slack_regions_are_never_unallocated_space() {
    let parent = fs_parent();
    let vol = volume_with(64 * 1024, &[(4096 + 500, b"z")]);
    // Clusters 0-7 free, 8-15 allocated, per the bitmap.
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
        &parent,
        &vol,
        &bitmap,
        FreeSpaceLabels {
            filesystem: "NTFS",
            offset_basis: "the volume",
        },
    );
    let mut c = SlackCollector::new(LABELS, CLUSTER);
    let w = slack_window(&[(Some(4096), CLUSTER)], 100, CLUSTER).unwrap();
    c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), w);
    let (slack, _) = c.finish(&parent);
    let mut all = free;
    all.extend(slack);
    let free_bytes: u64 = all
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .map(|a| a.metadata["size_bytes"].as_u64().unwrap())
        .sum();
    let slack_bytes: u64 = all
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .map(|a| a.metadata["size_bytes"].as_u64().unwrap())
        .sum();
    assert_eq!(slack_bytes, CLUSTER - 100);
    // The free total is the bitmap's eight clusters and not a byte more,
    // although the slack window sits inside cluster 1.
    assert_eq!(free_bytes, 8 * CLUSTER);
    assert_eq!(
        "SlackSpace".parse::<ArtifactType>().unwrap(),
        ArtifactType::SlackSpace
    );
    assert_eq!(ArtifactType::SlackSpace.to_string(), "SlackSpace");
}

/// Every offered window lands in exactly one bucket, so the summary's counts
/// add up. A zero-length window is not a window and is not offered.
#[test]
fn offered_windows_each_land_in_exactly_one_bucket() {
    let parent = fs_parent();
    let vol = volume_with(64 * 1024, &[(4096 + 500, b"z")]);
    let mut c = SlackCollector::new(LABELS, CLUSTER);
    c.offer(
        &parent,
        &vol,
        owner(Uuid::new_v4(), 100),
        SlackWindow {
            offset: 4096,
            len: 0,
        },
    );
    let w = slack_window(&[(Some(4096), CLUSTER)], 100, CLUSTER).unwrap();
    c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), w);
    let (_, o) = c.finish(&parent);
    assert_eq!(
        o.files_offered,
        o.regions_emitted + o.zero_tails + o.unreadable_tails + o.files_not_examined_at_cap,
        "offered must equal the sum of its buckets: {o:?}"
    );
    assert_eq!(o.files_offered, 1);
}

/// "No window" has two meanings, and only one of them is "nothing there".
#[test]
fn locate_slack_tells_no_tail_from_undescribed() {
    // Whole clusters: no tail.
    assert_eq!(
        locate_slack(&[(Some(4096), CLUSTER)], CLUSTER, CLUSTER),
        SlackLocation::NoTail
    );
    // Last logical byte in a sparse run: no cluster, no slack.
    assert_eq!(
        locate_slack(&[(Some(4096), CLUSTER), (None, CLUSTER)], 5000, CLUSTER),
        SlackLocation::NoTail
    );
    // Allocation shorter than the logical size: there is a tail, and the run
    // list does not say where.
    assert_eq!(
        locate_slack(&[(Some(4096), CLUSTER)], 5000, CLUSTER),
        SlackLocation::Undescribed
    );
    // A run that is not whole clusters would stretch the window: undescribed.
    assert_eq!(
        locate_slack(&[(Some(4096), 1500)], 1000, CLUSTER),
        SlackLocation::Undescribed
    );
    assert!(matches!(
        locate_slack(&[(Some(4096), CLUSTER)], 1000, CLUSTER),
        SlackLocation::Window(_)
    ));
}

/// A live file whose tail could not be located is counted on the summary as
/// not examined, so a volume of fragmented files is not read as one with no
/// slack-bearing files.
#[test]
fn files_whose_tail_could_not_be_located_are_counted_on_the_summary() {
    let parent = fs_parent();
    let mut c = SlackCollector::new(LABELS, CLUSTER);
    c.not_located();
    c.not_located();
    let (out, o) = c.finish(&parent);
    assert_eq!(o.files_not_located, 2);
    assert_eq!(o.files_offered, 0);
    let s = &out
        .iter()
        .find(|a| a.metadata["subtype"] == "slack_space_summary")
        .unwrap()
        .metadata;
    assert_eq!(s["files_not_located"], 2);
    assert_eq!(s["content_incomplete"], true);
    assert!(
        s["statement"].as_str().unwrap().contains("2 live file(s)"),
        "statement must give the number: {}",
        s["statement"]
    );
}

/// When a cap and a short read both occur, one reason is recorded and the cap
/// wins; the counters still carry both.
#[test]
fn cap_reached_takes_precedence_over_short_read_as_the_reason() {
    let parent = fs_parent();
    let vol = volume_with(64 * 1024, &[(4096 + 500, b"z")]);
    let mut c = SlackCollector::new(LABELS, CLUSTER).with_ceiling(1);
    let short = SlackWindow {
        offset: 64 * 1024 - 100,
        len: 4000,
    };
    let good = slack_window(&[(Some(4096), CLUSTER)], 100, CLUSTER).unwrap();
    c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), short);
    c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), good);
    c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), good);
    let (out, o) = c.finish(&parent);
    assert_eq!(o.unreadable_tails, 1);
    assert_eq!(o.files_not_examined_at_cap, 1);
    assert_eq!(
        summary_of(&out)["content_incomplete_reason"],
        crate::io::IncompleteReason::CapReached.as_str()
    );
}

/// The statement is quoted to examiners: each count must sit beside its own
/// wording, so a swapped format argument cannot pass.
#[test]
fn statement_puts_each_count_beside_its_own_claim() {
    let parent = fs_parent();
    let vol = volume_with(64 * 1024, &[(4096 + 500, b"z")]);
    let mut c = SlackCollector::new(LABELS, CLUSTER).with_ceiling(2);
    let zero = SlackWindow {
        offset: 8192,
        len: 100,
    };
    let short = SlackWindow {
        offset: 64 * 1024 - 100,
        len: 4000,
    };
    let good = slack_window(&[(Some(4096), CLUSTER)], 100, CLUSTER).unwrap();
    for _ in 0..3 {
        c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), zero);
    }
    for _ in 0..2 {
        c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), short);
    }
    for _ in 0..3 {
        c.offer(&parent, &vol, owner(Uuid::new_v4(), 100), good);
    }
    for _ in 0..4 {
        c.not_located();
    }
    let (out, _) = c.finish(&parent);
    let st = summary_of(&out)["statement"].as_str().unwrap().to_string();
    for fragment in [
        "8 file slack window(s)",
        "2 held non-zero bytes",
        "3 were read and held only zeros",
        "2 could not be read in full",
        "1 were not examined because the ceiling of 2 regions",
        "A further 4 live file(s)",
    ] {
        assert!(st.contains(fragment), "missing {fragment:?} in: {st}");
    }
}
