//! File slack as regions a carver, a scanner and a sweep can be pointed at
//! (HUNT-124).
//!
//! # What slack is, and what it is not
//!
//! A file system allocates whole clusters. A file whose logical size is not a
//! multiple of the cluster size leaves the tail of its last cluster unused:
//! the bytes from the file's logical end to the end of that cluster. That tail
//! is **file slack**. It is allocated to a live file — so it is not free space
//! and is never counted as free space — and it is not the file's content — so
//! it is never served, hashed or indexed as the file. What it may hold is
//! whatever the cluster held before this file was written into it: part of a
//! deleted file, or, on some systems, bytes from memory the writer padded the
//! last sector with. It may equally hold zeros.
//!
//! # Exactly which window
//!
//! One window per file: from the logical end to the end of the cluster that
//! holds the file's last logical byte. Clusters allocated to the file *past*
//! that one (a preallocated tail) are not covered by the window. The window is
//! computed from the file's allocation run list, never from its logical-content
//! run list, and not at all when:
//!
//! * the logical size is a multiple of the cluster size (no tail);
//! * the file's last logical byte lies in a sparse run (no cluster is
//!   allocated, so there is nothing on disk that could be slack);
//! * the allocation is shorter than the logical size (the run list does not
//!   describe where the tail is).
//!
//! # What the producer skips, and says it skipped
//!
//! A tail of all zeros is not emitted as a region — there is nothing in it to
//! carve, scan or find — and it is counted. A tail that cannot be read in full
//! is not emitted either, and is counted separately, because "could not look"
//! is not "nothing there". Past [`MAX_SLACK_REGIONS_PER_VOLUME`] regions the
//! producer stops reading tails at all and counts the files it did not
//! examine. A live file that has a tail the parser cannot locate (a run list or
//! chain that is incomplete, cut at a ceiling or shorter than the file, or a
//! compressed or encrypted allocation) is never offered, and is counted as
//! `files_not_located` through [`SlackCollector::not_located`]; see
//! [`locate_slack`] for the line between "no tail" and "could not locate it".
//! Every count lands on one `slack_space_summary` record per volume,
//! emitted even when no region was, so a volume whose slack was examined and
//! held nothing is distinguishable from one that was never examined.

use std::sync::Arc;

use serde_json::json;
use uuid::Uuid;

use crate::artifact::{Artifact, ArtifactType};
use crate::data_source::{DataSource, WindowSource};

/// Slack regions one volume may emit. Each is under one cluster, so this also
/// bounds the bytes a volume's slack regions can cover; files past it are
/// counted on the summary, not examined.
pub const MAX_SLACK_REGIONS_PER_VOLUME: usize = 250_000;

/// What every slack region says about itself, on the region, because it is the
/// artifact a carved file's provenance chain ends at.
pub const SLACK_MEANS: &str = "the bytes from this file's logical end to the end of the cluster \
    that holds its last byte. They are allocated to the live file named here, so they are NOT \
    free space, and they are NOT the file's content. They may hold what the cluster held before \
    this file was written into it (part of a deleted file), or padding the writing system put \
    there. Clusters allocated to the file past that last cluster are not covered by this region";

/// A file's slack window in the volume's coordinate space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlackWindow {
    /// First slack byte, as an offset into the volume source.
    pub offset: u64,
    /// Bytes from the logical end to the end of the last logical cluster.
    pub len: u64,
}

/// The slack window of a file, from its **allocation** run list.
///
/// `alloc_runs` are `(physical byte offset or None for sparse, byte length)`
/// in file order, each a whole number of clusters, as a filesystem parser
/// holds them before any trim to the logical size. `logical_size` is the size
/// the filesystem states; `cluster_size` the volume's.
pub fn slack_window(
    alloc_runs: &[(Option<u64>, u64)],
    logical_size: u64,
    cluster_size: u64,
) -> Option<SlackWindow> {
    match locate_slack(alloc_runs, logical_size, cluster_size) {
        SlackLocation::Window(w) => Some(w),
        SlackLocation::NoTail | SlackLocation::Undescribed => None,
    }
}

/// Where a file's slack is, or why the question has no window for an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlackLocation {
    /// The tail is on disk here.
    Window(SlackWindow),
    /// There is no slack on disk to look at: an empty file, a size that is a
    /// whole number of clusters, or a last logical byte in a sparse run.
    NoTail,
    /// There is a tail, but the run list does not say where it is: the
    /// allocation is shorter than the logical size, a run is not whole
    /// clusters, or the volume states no cluster size. This is "could not
    /// look", not "nothing there".
    Undescribed,
}

/// [`slack_window`], saying which of "no tail" and "could not locate the
/// tail" a missing window means. A parser counts the second on the summary
/// through [`SlackCollector::not_located`].
pub fn locate_slack(
    alloc_runs: &[(Option<u64>, u64)],
    logical_size: u64,
    cluster_size: u64,
) -> SlackLocation {
    if logical_size == 0 {
        return SlackLocation::NoTail;
    }
    if cluster_size == 0 {
        return SlackLocation::Undescribed;
    }
    let rem = logical_size % cluster_size;
    if rem == 0 {
        return SlackLocation::NoTail;
    }
    let len = cluster_size - rem;
    // The logical offset of the last logical byte, and the run that holds it.
    let last = logical_size - 1;
    let mut run_start = 0u64;
    for &(phys, run_len) in alloc_runs {
        let run_end = run_start.saturating_add(run_len);
        if last < run_end {
            // A hole holds no cluster, so there is no slack on disk.
            let Some(phys) = phys else {
                return SlackLocation::NoTail;
            };
            // Runs are whole clusters in file order, so the window ends at a
            // cluster boundary of the FILE, inside this run. Checked anyway: a
            // run list that is not whole clusters must not stretch the window
            // into a neighbour's bytes.
            match logical_size.checked_add(len) {
                Some(end) if end <= run_end => {}
                _ => return SlackLocation::Undescribed,
            }
            return match phys.checked_add(logical_size - run_start) {
                Some(offset) => SlackLocation::Window(SlackWindow { offset, len }),
                None => SlackLocation::Undescribed,
            };
        }
        run_start = run_end;
    }
    // The allocation ends before the logical size: nothing says where the
    // tail is.
    SlackLocation::Undescribed
}

/// Labels a filesystem parser supplies for its slack regions.
#[derive(Debug, Clone, Copy)]
pub struct SlackLabels {
    /// Which filesystem's allocation the windows came from ("NTFS", "FAT32").
    pub filesystem: &'static str,
    /// What `offset_bytes` is relative to, in words (see
    /// [`crate::free_space::FreeSpaceLabels::offset_basis`]).
    pub offset_basis: &'static str,
}

/// The live file a slack window belongs to.
#[derive(Debug, Clone, Copy)]
pub struct SlackOwner<'a> {
    /// The owning `FileEntry` artifact's id.
    pub artifact_id: Uuid,
    pub name: &'a str,
    pub path: Option<&'a str>,
    pub logical_size: u64,
}

/// What one volume's slack pass did, published on its summary record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlackOutcome {
    /// Files whose slack window was computed and offered.
    pub files_offered: u64,
    pub regions_emitted: u64,
    pub bytes_emitted: u64,
    /// Tails read in full and found to be all zero bytes: examined, not emitted.
    pub zero_tails: u64,
    /// Tails that could not be read in full: NOT examined.
    pub unreadable_tails: u64,
    /// Files offered after the region ceiling was reached: NOT examined.
    pub files_not_examined_at_cap: u64,
    pub region_cap_reached: bool,
    /// Live files with a tail whose location the parser could not state, so
    /// they were never offered: NOT examined.
    pub files_not_located: u64,
}

/// Collects one volume's slack regions under the ceiling.
pub struct SlackCollector {
    labels: SlackLabels,
    cluster_size: u64,
    max_regions: usize,
    regions: Vec<Artifact>,
    outcome: SlackOutcome,
}

impl SlackCollector {
    pub fn new(labels: SlackLabels, cluster_size: u64) -> Self {
        Self {
            labels,
            cluster_size,
            max_regions: MAX_SLACK_REGIONS_PER_VOLUME,
            regions: Vec::new(),
            outcome: SlackOutcome::default(),
        }
    }

    /// Lower the region ceiling (tests, and a caller that states its own).
    pub fn with_ceiling(mut self, max_regions: usize) -> Self {
        self.max_regions = max_regions;
        self
    }

    /// Offer one file's slack window. Reads the tail from `source` (the
    /// volume, in whose coordinate space `window` is) and emits a
    /// [`ArtifactType::SlackSpace`] region parented to `parent` (the volume's
    /// `FileSystem` artifact) when the tail holds any non-zero byte.
    pub fn offer(
        &mut self,
        parent: &Artifact,
        source: &Arc<dyn DataSource>,
        owner: SlackOwner<'_>,
        window: SlackWindow,
    ) {
        if window.len == 0 {
            // Not a window: nothing to offer, so nothing is counted as offered.
            return;
        }
        self.outcome.files_offered += 1;
        if self.regions.len() >= self.max_regions {
            // Not read: the ceiling bounds the ingest cost as well as the
            // artifact count, and what it skipped is counted, not guessed at.
            self.outcome.region_cap_reached = true;
            self.outcome.files_not_examined_at_cap += 1;
            return;
        }
        // A window is under one cluster, so this is at most one cluster read.
        let mut tail = vec![0u8; window.len as usize];
        let got = crate::io::read_full(source.as_ref(), window.offset, &mut tail);
        if (got as u64) < window.len {
            // Could not look at all of it: the unread part is not "zero".
            self.outcome.unreadable_tails += 1;
            return;
        }
        if tail.iter().all(|&b| b == 0) {
            self.outcome.zero_tails += 1;
            return;
        }
        let data: Arc<dyn DataSource> = Arc::new(WindowSource::new(
            Arc::clone(source),
            window.offset,
            window.len,
        ));
        let mut metadata = json!({
            "name": format!("Slack of {}", owner.name),
            // The two the content resolver requires of a region, in the
            // FileSystem parent's coordinate space.
            "offset_bytes": window.offset,
            "size_bytes": window.len,
            "offset_basis": self.labels.offset_basis,
            "filesystem": self.labels.filesystem,
            "source": "file_slack",
            "region_kind": "slack",
            "parent_file": owner.name,
            "owner_artifact_id": owner.artifact_id.to_string(),
            "logical_size": owner.logical_size,
            "cluster_size": self.cluster_size,
            "slack_means": SLACK_MEANS,
        });
        if let Some(path) = owner.path {
            metadata["parent_path"] = json!(path);
        }
        self.outcome.regions_emitted += 1;
        self.outcome.bytes_emitted = self.outcome.bytes_emitted.saturating_add(window.len);
        self.regions.push(
            Artifact::new(
                parent.case_id,
                ArtifactType::SlackSpace,
                Some(data),
                metadata,
            )
            .with_parent(parent.id),
        );
    }

    /// Count one live file with a tail the parser could not locate — a run
    /// list or cluster chain that is incomplete, cut at a ceiling or shorter
    /// than the logical size, or an allocation (compressed, encrypted) whose
    /// clusters are not the file's logical bytes. It is not offered, and is
    /// reported as not examined.
    pub fn not_located(&mut self) {
        self.outcome.files_not_located += 1;
    }

    /// What has been done so far.
    pub fn outcome(&self) -> &SlackOutcome {
        &self.outcome
    }

    /// The regions, followed by one `slack_space_summary` record parented to
    /// `parent` — emitted even when no region was, so a volume whose slack was
    /// examined and held nothing is distinguishable from one never examined.
    pub fn finish(self, parent: &Artifact) -> (Vec<Artifact>, SlackOutcome) {
        let o = &self.outcome;
        let not_examined = o.unreadable_tails + o.files_not_examined_at_cap + o.files_not_located;
        let statement = format!(
            "{} file slack window(s) on this {} volume were offered: {} held non-zero bytes and \
             were emitted as slack regions ({} bytes), {} were read and held only zeros, {} could \
             not be read in full, and {} were not examined because the ceiling of {} regions was \
             reached. A further {} live file(s) had a tail this parser could not locate (a run \
             list or cluster chain that is incomplete, cut at a ceiling or shorter than the file, \
             or a compressed or encrypted allocation) and were not examined. Slack is the tail of \
             a live file's last cluster: allocated, not free space, and not the file's content. \
             Resident, deleted and directory entries are not offered and not counted here.",
            o.files_offered,
            self.labels.filesystem,
            o.regions_emitted,
            o.bytes_emitted,
            o.zero_tails,
            o.unreadable_tails,
            o.files_not_examined_at_cap,
            self.max_regions,
            o.files_not_located,
        );
        let mut meta = json!({
            "type": "SlackSpaceSummary",
            "subtype": "slack_space_summary",
            "artifact_kind": "slack_space_summary",
            "name": format!("File slack ({} region(s))", o.regions_emitted),
            "filesystem": self.labels.filesystem,
            "files_offered": o.files_offered,
            "regions_emitted": o.regions_emitted,
            "bytes_emitted": o.bytes_emitted,
            "zero_tails": o.zero_tails,
            "unreadable_tails": o.unreadable_tails,
            "files_not_examined_at_cap": o.files_not_examined_at_cap,
            "region_cap_reached": o.region_cap_reached,
            "files_not_located": o.files_not_located,
            "max_slack_regions": self.max_regions,
            "statement": statement,
        });
        if not_examined > 0 {
            meta["content_incomplete"] = json!(true);
            meta["content_incomplete_reason"] = json!(if o.region_cap_reached {
                crate::io::IncompleteReason::CapReached.as_str()
            } else if o.unreadable_tails > 0 {
                crate::io::IncompleteReason::ShortRead.as_str()
            } else {
                crate::io::IncompleteReason::UnresolvedStructure.as_str()
            });
        }
        let summary = Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, meta)
            .with_parent(parent.id)
            .with_subtype("slack_space_summary");
        let mut out = self.regions;
        out.push(summary);
        (out, self.outcome)
    }
}

/// Offer one emitted `FileEntry`'s slack window to `collector` from the
/// metadata a filesystem parser persists on it (HUNT-124): `size`, `data_runs`
/// as `[offset | null, length]` pairs, `data_runs_complete`, and the
/// `is_directory`, `deleted` and `content_incomplete` flags.
///
/// Only a live, non-directory file whose persisted run list is whole clusters
/// and complete is offered: a deleted entry's run list is a guess, and one cut
/// short does not say where the tail is. A live file that has a tail but is
/// refused for one of those reasons — or because it carries any of
/// `not_located_flags`, the markers a parser sets when its run list is not the
/// file's allocation — is counted through [`SlackCollector::not_located`], so
/// the summary gives a number for "could not look" and never reads as "no
/// slack". A file with no tail is not counted at all.
pub fn offer_live_file(
    collector: &mut SlackCollector,
    fs: &Artifact,
    source: &Arc<dyn DataSource>,
    file: &Artifact,
    cluster_size: u64,
    not_located_flags: &[&str],
) {
    let md = &file.metadata;
    let flag = |key: &str| md.get(key).and_then(|v| v.as_bool()) == Some(true);
    if flag("is_directory") || flag("deleted") {
        return;
    }
    let Some(logical) = md.get("size").and_then(|v| v.as_u64()) else {
        // A live file with no stated size: whether it has a tail is unknown.
        collector.not_located();
        return;
    };
    if logical == 0 || cluster_size == 0 || logical % cluster_size == 0 {
        // No tail, whatever the run list says.
        return;
    }
    // From here the file has a tail; every refusal is "could not locate it".
    if flag("content_incomplete")
        || !flag("data_runs_complete")
        || not_located_flags.iter().any(|k| flag(k))
    {
        collector.not_located();
        return;
    }
    let Some(runs_json) = md.get("data_runs").and_then(|v| v.as_array()) else {
        collector.not_located();
        return;
    };
    let mut runs: Vec<(Option<u64>, u64)> = Vec::with_capacity(runs_json.len());
    for run in runs_json {
        let (Some(len), offset) = (run.get(1).and_then(|v| v.as_u64()), run.get(0)) else {
            collector.not_located();
            return;
        };
        runs.push((offset.and_then(|v| v.as_u64()), len));
    }
    let window = match locate_slack(&runs, logical, cluster_size) {
        SlackLocation::Window(w) => w,
        SlackLocation::NoTail => return,
        SlackLocation::Undescribed => {
            collector.not_located();
            return;
        }
    };
    let name = md.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
    collector.offer(
        fs,
        source,
        SlackOwner {
            artifact_id: file.id,
            name,
            path: md.get("path").and_then(|v| v.as_str()),
            logical_size: logical,
        },
        window,
    );
}

#[cfg(test)]
#[path = "slack_tests.rs"]
mod tests;
