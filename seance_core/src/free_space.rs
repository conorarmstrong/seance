//! Free clusters as regions a carver and a scanner can be pointed at
//! (`ROADMAP` §5.4).
//!
//! # What was missing
//!
//! Every filesystem parser here already reads its own allocation bitmap and
//! publishes a downsampled picture of it for the allocation view — and then
//! drops the bitmap. Nothing turned it into *work*. The one producer of
//! [`ArtifactType::UnallocatedSpace`] in the tree is the partition parser,
//! which emits the gaps an MBR or GPT table leaves **between** partitions, so
//! the automatic carver has never been pointed at the free clusters *inside* a
//! filesystem — which is where nearly everything an examiner carves for
//! actually is.
//!
//! This turns a bitmap into those regions. The carver already subscribes to
//! the type automatically, so it picks them up with no change, and it carves
//! the free space rather than the whole volume: less time, and no candidates
//! recovered out of the middle of live files.
//!
//! # "Free" is a claim about a bitmap, not about history
//!
//! Three things this deliberately does not say.
//!
//! A cluster the bitmap calls free is **not** a cluster nothing was ever
//! written to — that is the whole reason to carve it. Nor is it a cluster
//! nothing *is* in: a shadow copy can hold it, and `$BadClus` can own it.
//!
//! A cluster the bitmap calls allocated may still hold someone else's old
//! bytes in the tail of the file that owns it. That is **slack**, it is not
//! free space, and it is not emitted here.
//!
//! And a cluster the bitmap **could not speak for** is not free. This is the
//! trap the whole module is written around: a bitmap read short, or cut at a
//! cap, leaves a tail of zero bytes, and a zero bit means *free*. Emitting
//! those as free regions would carve them, find nothing in the holes of a
//! sparse image, and report unallocated space that was never assessed — so
//! [`FreeSpace::regions`] stops at the last cluster the held bytes cover, and
//! [`FreeSpaceOutcome`] publishes the clusters beyond it as unassessed. That
//! is `B5-004`'s rule applied a second time: the defect then was a bitmap that
//! "can cover only a prefix of the volume while presenting as complete", and a
//! region producer is the surface where that would have done the most harm.
//!
//! # What a cap costs is measured, not hidden
//!
//! A busy volume's free space is a few large runs and a great many
//! single-cluster holes, and one artifact per hole is millions of artifacts. So
//! the runs are ordered by size, the largest are kept, and the rest are
//! reported as a count and a **byte total** — which is the measure of what was
//! not carved. Regions are then emitted in offset order, because a record read
//! in address order is what an examiner expects.
//!
//! Both ceilings are defaults a lab can change ([`FreeSpaceLimits`],
//! `SEANCE_FREE_REGION_CAP` and `SEANCE_FREE_BYTE_CAP`, `CARVE-011`), and the
//! record publishes the ceilings the pass actually ran under. Sparse regions --
//! one artifact over many non-adjacent runs -- are deliberately not built: a
//! carve across a run boundary would join bytes that were never next to each
//! other on disk.
//!
//! The selection streams: the runs are never all held at once, only the
//! `max_regions` largest so far, so memory follows the cap and not the
//! fragmentation of a bitmap that is itself evidence.

use std::collections::BinaryHeap;
use std::sync::Arc;

use serde_json::json;

use crate::artifact::{Artifact, ArtifactType};
use crate::data_source::{DataSource, WindowSource};
use crate::io::IncompleteReason;

/// Free regions one filesystem may emit.
///
/// A used volume holds a few large free runs and many single-cluster holes.
/// Four thousand is more large runs than any real volume has, and the byte
/// total of what a cap drops is published beside it, so the cap costs a
/// measured quantity rather than an unknown one.
pub const MAX_FREE_REGIONS: usize = 4096;

/// Free bytes one volume may be carved for.
///
/// This route makes the automatic carver read free space it has never read
/// before, so it is also the route that can turn a short ingest into a long
/// one without anybody choosing it. 128 GiB is the figure the memory tier's
/// image-wide pattern ceiling already uses
/// (`seance_memory::patterns::MAX_TOTAL_BYTES`), it covers every volume in
/// this project's corpora whole, and what it declines is reported as a byte
/// total rather than quietly not carved.
///
/// The largest runs are kept first, so a volume past the ceiling is carved
/// where its free space actually is.
pub const MAX_FREE_BYTES_PER_VOLUME: u64 = 128 * 1024 * 1024 * 1024;

/// The smallest free run worth an artifact, in clusters.
///
/// One. A single free cluster holds a small file whole, and it is exactly what
/// a carver is for; nothing is dropped for size unless the region cap bites.
pub const MIN_FREE_RUN_CLUSTERS: u64 = 1;

/// The environment variable a lab sets to change [`MAX_FREE_REGIONS`] (CARVE-011).
pub const FREE_REGION_CAP_ENV: &str = "SEANCE_FREE_REGION_CAP";

/// The environment variable a lab sets to change [`MAX_FREE_BYTES_PER_VOLUME`].
pub const FREE_BYTE_CAP_ENV: &str = "SEANCE_FREE_BYTE_CAP";

/// The two ceilings one free-space pass runs under.
///
/// The defaults are [`MAX_FREE_REGIONS`] and [`MAX_FREE_BYTES_PER_VOLUME`]. A
/// lab that wants more of a fragmented volume carved raises them with
/// [`FREE_REGION_CAP_ENV`] and [`FREE_BYTE_CAP_ENV`] and wears the ingest time:
/// every region is an artifact, a database row and a carve pass of its own.
/// Whatever was applied is what the record publishes, so a raised ceiling is
/// never reported as the default one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeSpaceLimits {
    /// Regions one filesystem may emit.
    pub max_regions: usize,
    /// Free bytes one volume may be carved for.
    pub max_bytes: u64,
}

impl Default for FreeSpaceLimits {
    fn default() -> Self {
        Self {
            max_regions: MAX_FREE_REGIONS,
            max_bytes: MAX_FREE_BYTES_PER_VOLUME,
        }
    }
}

impl FreeSpaceLimits {
    /// The limits from two optional configured values.
    ///
    /// Read the way `SEANCE_WORKERS` is: a value that is absent, zero or does
    /// not parse as a whole number falls back to that ceiling's default. Zero
    /// is not "no ceiling" and not "no regions" -- both would be a surprise
    /// nobody chose.
    pub fn parse(max_regions: Option<&str>, max_bytes: Option<&str>) -> Self {
        let default = Self::default();
        Self {
            max_regions: max_regions
                .and_then(|v| v.trim().parse::<usize>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(default.max_regions),
            max_bytes: max_bytes
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(default.max_bytes),
        }
    }

    /// `"default"` or `"configured"` for the region ceiling, as the record
    /// publishes it.
    ///
    /// Decided by the **value applied**, not by whether the variable was set:
    /// a lab that sets [`FREE_REGION_CAP_ENV`] to the default figure ran under
    /// the default ceiling and is published as `"default"`. `"configured"`
    /// means the ceiling applied differs from the compiled default.
    pub fn region_cap_source(&self) -> &'static str {
        if self.max_regions == MAX_FREE_REGIONS {
            "default"
        } else {
            "configured"
        }
    }

    /// `"default"` or `"configured"` for the free-bytes ceiling, decided by
    /// the value applied in the same way as
    /// [`FreeSpaceLimits::region_cap_source`].
    pub fn byte_cap_source(&self) -> &'static str {
        if self.max_bytes == MAX_FREE_BYTES_PER_VOLUME {
            "default"
        } else {
            "configured"
        }
    }

    /// The limits from [`FREE_REGION_CAP_ENV`] and [`FREE_BYTE_CAP_ENV`].
    pub fn from_env() -> Self {
        let regions = std::env::var(FREE_REGION_CAP_ENV).ok();
        let bytes = std::env::var(FREE_BYTE_CAP_ENV).ok();
        Self::parse(regions.as_deref(), bytes.as_deref())
    }
}

/// Whether a set bit in an allocation bitmap means the cluster is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitMeaning {
    /// A set bit means allocated, a clear bit free — NTFS `$Bitmap` and
    /// exFAT's allocation bitmap.
    SetIsAllocated,
    /// A set bit means free — no filesystem here uses this, and it exists so
    /// that a caller must state the convention rather than inherit one.
    SetIsFree,
}

/// One filesystem's allocation bitmap, described by the parser that read it.
///
/// Every field is the caller's to state, because every one of them differs
/// between filesystems and a default would be wrong somewhere: NTFS's bitmap
/// starts at cluster 0 and exFAT's at cluster 2, and a byte offset derived from
/// the wrong base is a plausible address in the wrong place.
#[derive(Debug, Clone, Copy)]
pub struct AllocationBitmap<'a> {
    /// The bytes actually held, already truncated to what was read.
    pub bits: &'a [u8],
    /// The volume's real cluster count, from its own geometry rather than from
    /// the bitmap — a bitmap read short must never shrink a volume.
    pub total_clusters: u64,
    /// Bytes per cluster.
    pub cluster_size: u64,
    /// The cluster number the **first bit** describes: 0 for NTFS, 2 for
    /// exFAT and FAT, whose first two entries are reserved.
    pub first_cluster: u64,
    /// Byte offset, in the coordinate space of the data source the regions
    /// will be windowed out of, of the cluster [`AllocationBitmap::first_cluster`].
    pub first_cluster_offset: u64,
    /// What a set bit means.
    pub bit_meaning: BitMeaning,
}

impl AllocationBitmap<'_> {
    /// Clusters the held bytes can speak for.
    ///
    /// Eight per byte, and never past the volume's own cluster count: a bitmap
    /// longer than the volume describes clusters the volume does not have.
    pub fn covered_clusters(&self) -> u64 {
        let by_bits = (self.bits.len() as u64).saturating_mul(8);
        by_bits.min(self.total_clusters.saturating_sub(self.first_cluster))
    }

    /// Clusters the volume has that the held bytes cannot speak for.
    ///
    /// Not free, not allocated: unassessed. Published rather than carved.
    pub fn unassessed_clusters(&self) -> u64 {
        self.total_clusters
            .saturating_sub(self.first_cluster)
            .saturating_sub(self.covered_clusters())
    }

    /// Whether the cluster `index` bits into the map is free.
    ///
    /// `None` past what the held bytes cover — which is neither free nor
    /// allocated, and is why this is an `Option` rather than a `bool`.
    fn is_free(&self, index: u64) -> Option<bool> {
        if index >= self.covered_clusters() {
            return None;
        }
        let byte = self.bits.get((index / 8) as usize)?;
        let set = byte & (1u8 << (index % 8)) != 0;
        Some(match self.bit_meaning {
            BitMeaning::SetIsAllocated => !set,
            BitMeaning::SetIsFree => set,
        })
    }

    /// Every run of free clusters the held bytes prove, in cluster numbers.
    ///
    /// Stops at [`AllocationBitmap::covered_clusters`]. A run that reaches
    /// that boundary is **not** extended into the tail, because the tail's zero
    /// bytes are not evidence of anything.
    pub fn free_runs(&self) -> Vec<FreeRun> {
        let mut out: Vec<FreeRun> = Vec::new();
        self.for_each_free_run(|run| out.push(run));
        out
    }

    /// [`AllocationBitmap::free_runs`] without materialising them: `visit` is
    /// called once per run, in cluster order. A fragmented bitmap has one run
    /// per two clusters, so a caller that only needs the largest few must not
    /// be made to hold them all.
    pub fn for_each_free_run(&self, mut visit: impl FnMut(FreeRun)) {
        let covered = self.covered_clusters();
        let mut run: Option<(u64, u64)> = None;
        for index in 0..covered {
            match self.is_free(index) {
                Some(true) => match run.as_mut() {
                    Some((_, len)) => *len += 1,
                    None => run = Some((index, 1)),
                },
                _ => {
                    if let Some((start, len)) = run.take() {
                        visit(self.run(start, len));
                    }
                }
            }
        }
        if let Some((start, len)) = run.take() {
            visit(self.run(start, len));
        }
    }

    fn run(&self, index: u64, clusters: u64) -> FreeRun {
        FreeRun {
            first_cluster: self.first_cluster.saturating_add(index),
            clusters,
            offset: self
                .first_cluster_offset
                .saturating_add(index.saturating_mul(self.cluster_size)),
            bytes: clusters.saturating_mul(self.cluster_size),
        }
    }
}

/// One run of clusters the bitmap proves free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeRun {
    /// The volume's own number for the run's first cluster, so an examiner can
    /// check the answer against the bitmap by hand.
    pub first_cluster: u64,
    /// How many clusters.
    pub clusters: u64,
    /// Byte offset in the coordinate space the regions are windowed out of.
    pub offset: u64,
    /// Byte length.
    pub bytes: u64,
}

/// A [`FreeRun`] ordered so the run the caps would drop first is the greatest:
/// fewer bytes, then the higher offset (the reverse of the emission order of
/// "bytes descending, offset ascending"). A max-heap of these evicts the worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorstFirst(FreeRun);

impl Ord for WorstFirst {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .0
            .bytes
            .cmp(&self.0.bytes)
            .then(self.0.offset.cmp(&other.0.offset))
    }
}

impl PartialOrd for WorstFirst {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// What a free-space pass emitted, and what it did not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FreeSpaceOutcome {
    /// Free runs the bitmap proved.
    pub runs_found: usize,
    /// Regions emitted.
    pub regions_emitted: usize,
    /// Bytes those regions cover.
    pub bytes_emitted: u64,
    /// Runs the region cap dropped.
    pub runs_dropped: usize,
    /// Bytes those dropped runs cover — the measure of free space that was
    /// found and will not be carved.
    pub bytes_dropped: u64,
    /// Clusters the volume has that the held bitmap could not speak for.
    /// Neither free nor allocated.
    pub unassessed_clusters: u64,
    /// Bytes those clusters cover.
    pub unassessed_bytes: u64,
    /// Whether the region-count ceiling was reached.
    pub region_cap_reached: bool,
    /// Whether the free-bytes ceiling was reached.
    pub byte_cap_reached: bool,
    /// The ceilings this pass actually ran under.
    pub limits: FreeSpaceLimits,
    /// The bitmap's geometry could not be used (a cluster size of zero), so
    /// nothing was assessed. Distinct from "assessed, and none free".
    pub geometry_unusable: bool,
}

impl FreeSpaceOutcome {
    /// Whether every free run the bitmap proved was emitted, and the bitmap
    /// covered the whole volume.
    pub fn is_complete(&self) -> bool {
        self.runs_dropped == 0 && self.unassessed_clusters == 0 && !self.geometry_unusable
    }

    /// The vocabulary term a record should carry, or `None` where the pass was
    /// complete.
    pub fn reason(&self) -> Option<IncompleteReason> {
        if self.runs_dropped > 0 {
            Some(IncompleteReason::CapReached)
        } else if self.unassessed_clusters > 0 || self.geometry_unusable {
            Some(IncompleteReason::UnresolvedStructure)
        } else {
            None
        }
    }

    /// The sentence a record carries beside the numbers.
    pub fn statement(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.runs_dropped > 0 {
            let which = match (self.region_cap_reached, self.byte_cap_reached) {
                (true, true) => "the region ceiling and the free-bytes ceiling",
                (true, false) => "the region ceiling",
                (false, true) => "the free-bytes ceiling",
                (false, false) => "a ceiling",
            };
            parts.push(format!(
                "{} of {} free runs were emitted as regions and {} were not, covering {} bytes \
                 of free space that will not be carved -- {which} stopped it. The region \
                 ceiling keeps the largest runs; the free-bytes ceiling keeps the largest runs \
                 that fit the remaining byte budget and skips one that does not, so a single \
                 oversize run does not cost the smaller runs that would have fitted",
                self.regions_emitted, self.runs_found, self.runs_dropped, self.bytes_dropped
            ));
            parts.push(format!(
                "the ceilings applied were {} regions ({}) and {} bytes ({}); a lab that wants \
                 more of this volume carved sets {FREE_REGION_CAP_ENV} and {FREE_BYTE_CAP_ENV} \
                 and accepts the ingest time",
                self.limits.max_regions,
                self.limits.region_cap_source(),
                self.limits.max_bytes,
                self.limits.byte_cap_source(),
            ));
        }
        if self.geometry_unusable {
            parts.push(
                "the volume's cluster size is zero, so its allocation bitmap could not be \
                 interpreted and no cluster was assessed. This is NOT a finding that the volume \
                 has no free space"
                    .to_string(),
            );
        }
        if self.unassessed_clusters > 0 {
            parts.push(format!(
                "{} clusters ({} bytes) of this volume are beyond what the allocation bitmap \
                 this pass held could speak for. They are NOT free space and no region covers \
                 them: a bitmap read short leaves a tail of zero bytes, and a zero bit means \
                 free, so carving that tail would report unallocated space nobody assessed",
                self.unassessed_clusters, self.unassessed_bytes
            ));
        }
        (!parts.is_empty()).then(|| parts.join(". "))
    }

    /// The fields a record publishes.
    pub fn to_json(&self) -> serde_json::Value {
        let mut out = json!({
            "free_runs_found": self.runs_found,
            "free_regions_emitted": self.regions_emitted,
            "free_bytes_emitted": self.bytes_emitted,
            "free_runs_dropped": self.runs_dropped,
            "free_bytes_dropped": self.bytes_dropped,
            // The ceilings this pass ran under, not the compiled defaults: a
            // lab may have changed them (CARVE-011), and the record states
            // which were applied and whether each was the default.
            "free_region_cap": self.limits.max_regions,
            "free_region_cap_source": self.limits.region_cap_source(),
            "free_byte_cap": self.limits.max_bytes,
            "free_byte_cap_source": self.limits.byte_cap_source(),
            "free_region_cap_reached": self.region_cap_reached,
            "free_byte_cap_reached": self.byte_cap_reached,
            "free_space_unassessed_clusters": self.unassessed_clusters,
            "free_space_unassessed_bytes": self.unassessed_bytes,
            "free_space_geometry_unusable": self.geometry_unusable,
            "free_space_complete": self.is_complete(),
        });
        if let (Some(reason), Some(said), Some(map)) =
            (self.reason(), self.statement(), out.as_object_mut())
        {
            map.insert("free_space_incomplete".into(), json!(true));
            map.insert(
                "free_space_incomplete_reason".into(),
                json!(reason.as_str()),
            );
            map.insert("free_space_incomplete_detail".into(), json!(said));
        }
        out
    }
}

/// How a filesystem names itself on the regions it emits.
#[derive(Debug, Clone, Copy)]
pub struct FreeSpaceLabels {
    /// `"NTFS"`, `"exFAT"`, `"ext4"`, `"FAT32"` — what the examiner sees, and
    /// what says which bitmap the claim came from.
    pub filesystem: &'static str,
    /// What the offsets are relative to, in words.
    ///
    /// **Not** decoration: the carver adds a region's `offset_bytes` to a
    /// candidate's position and publishes the sum as
    /// `carving_offset_absolute`, so a region whose offsets are relative to a
    /// volume produces an "absolute" figure that is relative to that volume
    /// and not to the evidence. The partition parser's regions hang off the
    /// raw evidence and its figures really are evidence-absolute. Two
    /// coordinate spaces under one field name is the defect this names its way
    /// out of.
    pub offset_basis: &'static str,
}

/// Emit one [`ArtifactType::UnallocatedSpace`] artifact per free run.
///
/// `parent` is the artifact the regions hang off and whose coordinate space
/// `source` is in — for a filesystem, the `FileSystem` artifact and its own
/// volume window, so that `offset_bytes` resolves against it the way the
/// content resolver rebuilds every window: from the metadata, up the parent
/// chain.
///
/// Returns the regions in **offset order** and what the pass cost.
/// The ceilings are the configured ones ([`FreeSpaceLimits::from_env`]); use
/// [`emit_free_regions_with`] to state them.
pub fn emit_free_regions(
    parent: &Artifact,
    source: &Arc<dyn DataSource>,
    bitmap: &AllocationBitmap<'_>,
    labels: FreeSpaceLabels,
) -> (Vec<Artifact>, FreeSpaceOutcome) {
    emit_free_regions_with(parent, source, bitmap, labels, FreeSpaceLimits::from_env())
}

/// [`emit_free_regions`] under stated ceilings.
pub fn emit_free_regions_with(
    parent: &Artifact,
    source: &Arc<dyn DataSource>,
    bitmap: &AllocationBitmap<'_>,
    labels: FreeSpaceLabels,
    limits: FreeSpaceLimits,
) -> (Vec<Artifact>, FreeSpaceOutcome) {
    let mut outcome = FreeSpaceOutcome {
        limits,
        unassessed_clusters: bitmap.unassessed_clusters(),
        unassessed_bytes: bitmap
            .unassessed_clusters()
            .saturating_mul(bitmap.cluster_size),
        ..FreeSpaceOutcome::default()
    };
    if bitmap.cluster_size == 0 {
        outcome.geometry_unusable = true;
        return (Vec::new(), outcome);
    }
    // Stream the runs and keep only the `max_regions` largest, so memory is
    // bounded by the cap and not by how fragmented the (evidence-controlled)
    // bitmap is. Each run is clipped to the data source first: clusters the
    // geometry claims beyond its end were never assessed, so they are counted
    // as unassessed and never emitted.
    let source_size = source.size();
    let mut heap: BinaryHeap<WorstFirst> = BinaryHeap::new();
    bitmap.for_each_free_run(|run| {
        let usable =
            (source_size.saturating_sub(run.offset) / bitmap.cluster_size).min(run.clusters);
        let beyond = run.clusters - usable;
        if beyond > 0 {
            outcome.unassessed_clusters = outcome.unassessed_clusters.saturating_add(beyond);
            outcome.unassessed_bytes = outcome
                .unassessed_bytes
                .saturating_add(beyond.saturating_mul(bitmap.cluster_size));
        }
        let run = FreeRun {
            clusters: usable,
            bytes: usable.saturating_mul(bitmap.cluster_size),
            ..run
        };
        if run.clusters < MIN_FREE_RUN_CLUSTERS || run.bytes == 0 {
            return;
        }
        outcome.runs_found += 1;
        heap.push(WorstFirst(run));
        if heap.len() > limits.max_regions {
            if let Some(WorstFirst(evicted)) = heap.pop() {
                outcome.runs_dropped += 1;
                outcome.bytes_dropped = outcome.bytes_dropped.saturating_add(evicted.bytes);
                outcome.region_cap_reached = true;
            }
        }
    });
    // Largest first, so whichever ceiling bites drops the least free space it
    // can, and what it dropped is counted before the tail is discarded.
    let mut runs: Vec<FreeRun> = heap.into_iter().map(|w| w.0).collect();
    runs.sort_unstable_by(|a, b| b.bytes.cmp(&a.bytes).then(a.offset.cmp(&b.offset)));
    // A run that does not fit the remaining byte budget is skipped, not a
    // stopping point: smaller runs behind it may still fit.
    let mut kept = 0u64;
    runs.retain(|run| {
        let next = kept.saturating_add(run.bytes);
        if next > limits.max_bytes {
            outcome.runs_dropped += 1;
            outcome.bytes_dropped = outcome.bytes_dropped.saturating_add(run.bytes);
            outcome.byte_cap_reached = true;
            false
        } else {
            kept = next;
            true
        }
    });
    // Address order for the record, whatever order the selection used.
    runs.sort_unstable_by_key(|run| run.offset);

    let regions: Vec<Artifact> = runs
        .iter()
        .enumerate()
        .map(|(index, run)| {
            outcome.regions_emitted += 1;
            outcome.bytes_emitted = outcome.bytes_emitted.saturating_add(run.bytes);
            let window: Arc<dyn DataSource> =
                Arc::new(WindowSource::new(Arc::clone(source), run.offset, run.bytes));
            let mut metadata = json!({
                // The two the content resolver requires of this type, in the
                // parent's coordinate space.
                "offset_bytes": run.offset,
                "size_bytes": run.bytes,
                "filesystem": labels.filesystem,
                "offset_basis": labels.offset_basis,
                "free_region_index": index,
                "first_cluster": run.first_cluster,
                "clusters": run.clusters,
                "cluster_size": bitmap.cluster_size,
                "source": "allocation_bitmap",
                // What "free" is and is not, on the region itself, because
                // this is the artifact a carved file's provenance chain ends
                // at.
                "free_means": "the filesystem's own allocation bitmap marks these clusters as \
                               not in use. That is not a finding that nothing was ever written \
                               here -- which is the reason to carve it -- nor that nothing holds \
                               it now: a shadow copy may, and on NTFS $BadClus may. Clusters \
                               the bitmap marks IN USE are not covered by these regions, and \
                               the unused tail of a live file (slack) is not free space and is \
                               not here",
            });
            if let Some(map) = metadata.as_object_mut() {
                if let Some(reason) = outcome.reason() {
                    // The pass's own shortfall travels on every region it
                    // emitted, so a region read on its own still says the set
                    // it belongs to is not the whole set.
                    map.insert("free_space_incomplete".into(), json!(true));
                    map.insert(
                        "free_space_incomplete_reason".into(),
                        json!(reason.as_str()),
                    );
                }
            }
            Artifact::new(
                parent.case_id,
                ArtifactType::UnallocatedSpace,
                Some(window),
                metadata,
            )
            .with_parent(parent.id)
        })
        .collect();

    (regions, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_source::ByteSliceDataSource;
    use uuid::Uuid;

    const CLUSTER: u64 = 4096;

    fn parent() -> Artifact {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            None,
            json!({"name": "volume"}),
        )
    }

    /// A source that only claims a size, for geometries too large to allocate.
    #[derive(Debug)]
    struct SizedOnly(u64);

    impl DataSource for SizedOnly {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
        fn size(&self) -> u64 {
            self.0
        }
    }

    fn volume(bytes: usize) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(vec![0u8; bytes]))
    }

    /// The module's `emit_free_regions` reads `SEANCE_FREE_REGION_CAP` and
    /// `SEANCE_FREE_BYTE_CAP`. These tests assert on the default ceilings, so
    /// they must not depend on what a developer's or CI shell has exported:
    /// this local function shadows the glob-imported one and pins the
    /// defaults. The configured-ceiling tests call `emit_free_regions_with`
    /// directly.
    fn emit_free_regions(
        parent: &Artifact,
        source: &Arc<dyn DataSource>,
        bitmap: &AllocationBitmap<'_>,
        labels: FreeSpaceLabels,
    ) -> (Vec<Artifact>, FreeSpaceOutcome) {
        emit_free_regions_with(parent, source, bitmap, labels, FreeSpaceLimits::default())
    }

    fn ntfs<'a>(bits: &'a [u8], total_clusters: u64) -> AllocationBitmap<'a> {
        AllocationBitmap {
            bits,
            total_clusters,
            cluster_size: CLUSTER,
            first_cluster: 0,
            first_cluster_offset: 0,
            bit_meaning: BitMeaning::SetIsAllocated,
        }
    }

    /// A bitmap byte from a list of allocated cluster indices, LSB first —
    /// which is the convention NTFS and exFAT both use.
    fn allocated(indices: &[u64], clusters: u64) -> Vec<u8> {
        let mut bits = vec![0u8; clusters.div_ceil(8) as usize];
        for &i in indices {
            bits[(i / 8) as usize] |= 1u8 << (i % 8);
        }
        bits
    }

    #[test]
    fn a_free_run_becomes_a_region_at_the_bytes_that_run_occupies() {
        // Clusters 0 and 1 allocated, 2..5 free, 5 allocated, 6..8 free.
        let bits = allocated(&[0, 1, 5], 8);
        let map = ntfs(&bits, 8);
        let (regions, outcome) = emit_free_regions(
            &parent(),
            &volume(8 * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
        );
        assert_eq!(
            regions
                .iter()
                .map(|r| (
                    r.metadata["offset_bytes"].as_u64().unwrap(),
                    r.metadata["size_bytes"].as_u64().unwrap(),
                    r.metadata["first_cluster"].as_u64().unwrap(),
                    r.metadata["clusters"].as_u64().unwrap(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (2 * CLUSTER, 3 * CLUSTER, 2, 3),
                (6 * CLUSTER, 2 * CLUSTER, 6, 2),
            ],
            "two runs, at the byte offsets their clusters occupy"
        );
        assert!(outcome.is_complete(), "{outcome:?}");
        assert_eq!(outcome.runs_found, 2);
        assert_eq!(outcome.bytes_emitted, 5 * CLUSTER);
        // Every region carries what the content resolver requires of the type,
        // and its window is the length it declares.
        for region in &regions {
            assert_eq!(region.artifact_type, ArtifactType::UnallocatedSpace);
            assert_eq!(
                region.data.as_ref().map(|d| d.size()),
                Some(region.metadata["size_bytes"].as_u64().unwrap()),
                "size_bytes must equal the window's own length"
            );
        }
    }

    #[test]
    fn the_tail_a_short_bitmap_cannot_speak_for_is_never_emitted_as_free() {
        // The defect this whole module is written around, and B5-004's rule
        // applied a second time. A bitmap read short leaves zero bytes, a zero
        // bit means free, and emitting that tail would carve address space
        // nobody assessed and report it as unallocated.
        //
        // One byte of bitmap — eight clusters — against a volume of 1,000.
        let bits = allocated(&[0], 8);
        let map = ntfs(&bits, 1_000);
        assert_eq!(map.covered_clusters(), 8);
        assert_eq!(map.unassessed_clusters(), 992);

        let (regions, outcome) = emit_free_regions(
            &parent(),
            &volume(1_000 * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
        );
        // Clusters 1..8 are free and proved; nothing past cluster 8 is
        // emitted at all.
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].metadata["offset_bytes"], CLUSTER);
        assert_eq!(regions[0].metadata["size_bytes"], 7 * CLUSTER);
        assert_eq!(
            outcome.unassessed_clusters, 992,
            "and the rest is published as unassessed rather than carved"
        );
        assert_eq!(outcome.unassessed_bytes, 992 * CLUSTER);
        assert!(!outcome.is_complete());
        assert_eq!(
            outcome.reason(),
            Some(IncompleteReason::UnresolvedStructure)
        );
        let said = outcome.statement().expect("a sentence");
        assert!(said.contains("NOT free space"), "{said}");
        assert!(said.contains("zero bit means"), "{said}");
        // And every region says the set it belongs to is not the whole set.
        assert_eq!(regions[0].metadata["free_space_incomplete"], true);
    }

    #[test]
    fn a_run_that_reaches_the_edge_of_what_was_read_is_not_extended_past_it() {
        // Every bit the byte holds is free, so the run ends at the boundary
        // rather than running on into a tail that proves nothing.
        let bits = vec![0u8; 1];
        let map = ntfs(&bits, 100);
        let runs = map.free_runs();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].first_cluster, 0);
        assert_eq!(runs[0].clusters, 8, "eight, not one hundred");
    }

    #[test]
    fn a_bitmap_longer_than_the_volume_does_not_describe_clusters_the_volume_lacks() {
        // The opposite short read: 8 KiB of bitmap is 65,536 clusters, and the
        // volume has ten.
        let bits = vec![0u8; 8192];
        let map = ntfs(&bits, 10);
        assert_eq!(map.covered_clusters(), 10);
        assert_eq!(map.unassessed_clusters(), 0);
        let runs = map.free_runs();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].clusters, 10);
    }

    #[test]
    fn an_exfat_bitmap_starts_at_cluster_two_and_its_offsets_follow_from_that() {
        // exFAT's first two cluster numbers are reserved and its bitmap's
        // first bit is cluster 2, whose bytes are at the start of the data
        // region and not at the start of the volume. A base of zero here is a
        // plausible offset in the wrong place — which is why the caller states
        // it rather than inheriting a default.
        let data_region = 64 * CLUSTER;
        let bits = allocated(&[0], 4);
        let map = AllocationBitmap {
            bits: &bits,
            total_clusters: 66,
            cluster_size: CLUSTER,
            first_cluster: 2,
            first_cluster_offset: data_region,
            bit_meaning: BitMeaning::SetIsAllocated,
        };
        let (regions, outcome) = emit_free_regions(
            &parent(),
            &volume(130 * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "exFAT",
                offset_basis: "the volume",
            },
        );
        assert_eq!(regions.len(), 1);
        assert_eq!(
            regions[0].metadata["first_cluster"], 3,
            "cluster 3, the first free one"
        );
        assert_eq!(
            regions[0].metadata["offset_bytes"].as_u64().unwrap(),
            data_region + CLUSTER,
            "one cluster past the start of the data region"
        );
        assert_eq!(outcome.runs_found, 1);
    }

    #[test]
    fn the_region_ceiling_keeps_the_largest_runs_and_counts_the_bytes_it_dropped() {
        // A busy volume's free space is a few large runs and a great many
        // single-cluster holes. What a ceiling drops has to be the least space
        // it can, and the bytes it dropped are the measure of free space that
        // will not be carved.
        let clusters = (MAX_FREE_REGIONS as u64 + 200) * 2;
        // Alternate allocated/free so every free run is one cluster, then make
        // the last run long.
        let allocated_indices: Vec<u64> = (0..clusters).filter(|i| i % 2 == 0).collect();
        let mut bits = allocated(&allocated_indices, clusters);
        // A 40-cluster free run at the end: clear the allocated bits there.
        for i in (clusters - 40)..clusters {
            bits[(i / 8) as usize] &= !(1u8 << (i % 8));
        }
        let map = ntfs(&bits, clusters);
        let (regions, outcome) = emit_free_regions(
            &parent(),
            &volume(clusters as usize * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
        );
        assert_eq!(regions.len(), MAX_FREE_REGIONS);
        assert!(outcome.runs_dropped > 0);
        assert_eq!(outcome.reason(), Some(IncompleteReason::CapReached));
        assert_eq!(
            outcome.bytes_dropped,
            outcome.runs_dropped as u64 * CLUSTER,
            "every dropped run was one cluster, because the largest were kept"
        );
        // The long run at the end survived the cut. Its exact length is the
        // fixture's business -- the cluster before the cleared range was
        // already free, so it is 41 and not 40 -- and what is under test is
        // that the LARGEST run is the one a ceiling must not drop.
        let longest = map
            .free_runs()
            .iter()
            .map(|r| r.clusters)
            .max()
            .expect("some free run");
        assert!(longest > 1, "the fixture has one long run: {longest}");
        assert!(
            regions
                .iter()
                .any(|r| r.metadata["clusters"].as_u64() == Some(longest)),
            "the longest run ({longest} clusters) must survive the ceiling"
        );
        // And the regions are in address order however the selection ordered
        // them.
        let offsets: Vec<u64> = regions
            .iter()
            .map(|r| r.metadata["offset_bytes"].as_u64().unwrap())
            .collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted, "a record is read in address order");
        let said = outcome.statement().expect("a sentence");
        assert!(said.contains("will not be carved"), "{said}");
    }

    #[test]
    fn the_free_bytes_ceiling_says_which_ceiling_stopped_it_and_what_that_cost() {
        // This route makes the automatic carver read free space it never read
        // before, so it is the route that can turn a short ingest into a long
        // one without anybody choosing it. The ceiling exists for that, and
        // what it declines has to be a byte total rather than silence.
        //
        // Clusters big enough that three free runs exceed the ceiling.
        let huge = MAX_FREE_BYTES_PER_VOLUME / 2;
        let bits = allocated(&[1, 3], 6);
        let map = AllocationBitmap {
            bits: &bits,
            total_clusters: 6,
            cluster_size: huge,
            first_cluster: 0,
            first_cluster_offset: 0,
            bit_meaning: BitMeaning::SetIsAllocated,
        };
        // Free runs: cluster 0, cluster 2, clusters 4-5. Largest first is the
        // two-cluster run (one whole ceiling), then one of the singles.
        let (regions, outcome) = emit_free_regions(
            &parent(),
            &(Arc::new(SizedOnly(6 * huge)) as Arc<dyn DataSource>),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
        );
        assert_eq!(outcome.runs_found, 3);
        assert_eq!(regions.len(), 1, "the two-cluster run fills the ceiling");
        assert_eq!(outcome.bytes_emitted, huge * 2);
        assert_eq!(outcome.runs_dropped, 2);
        assert_eq!(outcome.bytes_dropped, huge * 2);
        assert!(outcome.byte_cap_reached);
        assert!(!outcome.region_cap_reached);
        assert_eq!(outcome.reason(), Some(IncompleteReason::CapReached));
        let said = outcome.statement().expect("a sentence");
        assert!(
            said.contains("free-bytes ceiling stopped it"),
            "the record says WHICH ceiling: {said}"
        );
        // And the largest run is the one that was kept.
        assert_eq!(regions[0].metadata["clusters"], 2);
    }

    /// 300 one-cluster free runs: clusters alternate allocated/free.
    fn three_hundred_runs() -> (Vec<u8>, u64) {
        let clusters = 600u64;
        let indices: Vec<u64> = (0..clusters).filter(|i| i % 2 == 0).collect();
        (allocated(&indices, clusters), clusters)
    }

    #[test]
    fn a_configured_region_ceiling_is_the_one_applied_and_the_one_published() {
        // CARVE-011: a lab may change the ceiling, and the record must then
        // state the ceiling that was applied. Publishing the constant beside a
        // raised or lowered one would be a false statement on the record.
        let (bits, clusters) = three_hundred_runs();
        let map = ntfs(&bits, clusters);
        let (regions, outcome) = emit_free_regions_with(
            &parent(),
            &volume(clusters as usize * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
            FreeSpaceLimits {
                max_regions: 100,
                max_bytes: MAX_FREE_BYTES_PER_VOLUME,
            },
        );
        assert_eq!(outcome.runs_found, 300);
        assert_eq!(regions.len(), 100, "the configured ceiling is applied");
        assert_eq!(outcome.runs_dropped, 200);
        assert_eq!(outcome.bytes_dropped, 200 * CLUSTER);
        assert!(outcome.region_cap_reached);
        let json = outcome.to_json();
        assert_eq!(json["free_region_cap"], 100, "{json}");
        assert_eq!(json["free_region_cap_source"], "configured", "{json}");
        assert_eq!(json["free_byte_cap"], MAX_FREE_BYTES_PER_VOLUME);
        assert_eq!(json["free_byte_cap_source"], "default", "{json}");
        assert_eq!(json["free_space_incomplete"], true);
        let said = outcome.statement().expect("a sentence");
        assert!(
            said.contains("100 regions (configured)") && said.contains(FREE_REGION_CAP_ENV),
            "the sentence names the ceiling applied and how to change it: {said}"
        );
    }

    #[test]
    fn a_ceiling_above_the_run_count_drops_nothing_and_says_complete() {
        // The known answer for "a lab that asks for the whole volume gets it".
        let (bits, clusters) = three_hundred_runs();
        let map = ntfs(&bits, clusters);
        let (regions, outcome) = emit_free_regions_with(
            &parent(),
            &volume(clusters as usize * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
            FreeSpaceLimits {
                max_regions: 10_000,
                max_bytes: MAX_FREE_BYTES_PER_VOLUME,
            },
        );
        assert_eq!(regions.len(), 300);
        assert_eq!(outcome.runs_dropped, 0);
        let json = outcome.to_json();
        assert_eq!(json["free_space_complete"], true, "{json}");
        assert!(json.get("free_space_incomplete").is_none(), "{json}");
        assert_eq!(json["free_region_cap"], 10_000);
        assert_eq!(json["free_region_cap_source"], "configured");
    }

    #[test]
    fn a_configured_byte_ceiling_is_the_one_applied_and_the_one_published() {
        let (bits, clusters) = three_hundred_runs();
        let map = ntfs(&bits, clusters);
        let (regions, outcome) = emit_free_regions_with(
            &parent(),
            &volume(clusters as usize * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
            FreeSpaceLimits {
                max_regions: MAX_FREE_REGIONS,
                max_bytes: 10 * CLUSTER,
            },
        );
        assert_eq!(regions.len(), 10);
        assert!(outcome.byte_cap_reached);
        let json = outcome.to_json();
        assert_eq!(json["free_byte_cap"], 10 * CLUSTER, "{json}");
        assert_eq!(json["free_byte_cap_source"], "configured");
        assert_eq!(json["free_region_cap_source"], "default");
    }

    #[test]
    fn limits_from_env_values_fall_back_on_zero_or_garbage() {
        let default = FreeSpaceLimits::default();
        assert_eq!(FreeSpaceLimits::parse(None, None), default);
        assert_eq!(FreeSpaceLimits::parse(Some("0"), Some("0")), default);
        assert_eq!(FreeSpaceLimits::parse(Some("abc"), Some("-5")), default);
        assert_eq!(FreeSpaceLimits::parse(Some(""), Some(" ")), default);
        assert_eq!(
            FreeSpaceLimits::parse(Some("5000"), Some("1099511627776")),
            FreeSpaceLimits {
                max_regions: 5000,
                max_bytes: 1_099_511_627_776,
            }
        );
        assert_eq!(
            FreeSpaceLimits::parse(Some(" 5000 "), None),
            FreeSpaceLimits {
                max_regions: 5000,
                max_bytes: MAX_FREE_BYTES_PER_VOLUME,
            },
            "surrounding whitespace in an environment file is not garbage"
        );
    }

    #[test]
    fn the_default_ceilings_are_published_as_the_default() {
        let json = FreeSpaceOutcome::default().to_json();
        assert_eq!(json["free_region_cap"], MAX_FREE_REGIONS);
        assert_eq!(json["free_region_cap_source"], "default");
        assert_eq!(json["free_byte_cap"], MAX_FREE_BYTES_PER_VOLUME);
        assert_eq!(json["free_byte_cap_source"], "default");
    }

    #[test]
    fn a_fully_allocated_volume_emits_nothing_and_says_it_is_complete() {
        // No free space is a real answer, and it is not the same as a bitmap
        // that could not be read.
        let bits = allocated(&(0..64).collect::<Vec<_>>(), 64);
        let map = ntfs(&bits, 64);
        let (regions, outcome) = emit_free_regions(
            &parent(),
            &volume(64 * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
        );
        assert!(regions.is_empty());
        assert_eq!(outcome.runs_found, 0);
        assert!(outcome.is_complete());
        assert_eq!(outcome.reason(), None);
        assert_eq!(outcome.statement(), None);
    }

    #[test]
    fn an_empty_bitmap_claims_nothing_about_a_volume_that_has_clusters() {
        let map = ntfs(&[], 1_000);
        assert_eq!(map.covered_clusters(), 0);
        assert_eq!(map.unassessed_clusters(), 1_000);
        let (regions, outcome) = emit_free_regions(
            &parent(),
            &volume(CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
        );
        assert!(regions.is_empty(), "not one region: nothing was assessed");
        assert!(!outcome.is_complete());
        assert_eq!(outcome.unassessed_clusters, 1_000);
    }

    #[test]
    fn a_zero_cluster_size_produces_nothing_rather_than_dividing_by_it() {
        let bits = vec![0u8; 8];
        let map = AllocationBitmap {
            bits: &bits,
            total_clusters: 64,
            cluster_size: 0,
            first_cluster: 0,
            first_cluster_offset: 0,
            bit_meaning: BitMeaning::SetIsAllocated,
        };
        let (regions, outcome) = emit_free_regions(
            &parent(),
            &volume(64),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
        );
        assert!(regions.is_empty());
        assert_eq!(outcome.regions_emitted, 0);
        // Nothing was examined: that is "could not look", never "none free".
        assert!(!outcome.is_complete());
        assert_eq!(
            outcome.reason(),
            Some(IncompleteReason::UnresolvedStructure)
        );
        assert!(outcome.statement().is_some());
        assert_eq!(outcome.to_json()["free_space_complete"], json!(false));
        assert_eq!(
            outcome.to_json()["free_space_geometry_unusable"],
            json!(true)
        );
    }

    fn labels() -> FreeSpaceLabels {
        FreeSpaceLabels {
            filesystem: "NTFS",
            offset_basis: "the volume",
        }
    }

    #[test]
    fn a_run_over_the_byte_ceiling_does_not_cost_the_smaller_runs_that_fit() {
        // One 200-cluster run, then three single-cluster holes; a 10-cluster
        // byte ceiling declines the big run and must still keep the holes.
        let bits = allocated(&[200, 202, 204, 206], 207);
        let map = ntfs(&bits, 207);
        let limits = FreeSpaceLimits {
            max_regions: 4096,
            max_bytes: 10 * CLUSTER,
        };
        let (regions, outcome) = emit_free_regions_with(
            &parent(),
            &volume(207 * CLUSTER as usize),
            &map,
            labels(),
            limits,
        );
        assert!(outcome.byte_cap_reached);
        assert_eq!(regions.len(), 3, "the three holes that fit must be emitted");
        assert_eq!(outcome.bytes_emitted, 3 * CLUSTER);
        assert_eq!(
            outcome.runs_found,
            outcome.regions_emitted + outcome.runs_dropped
        );
        assert_eq!(outcome.bytes_dropped, 200 * CLUSTER);
    }

    /// The pre-streaming selection: materialise, sort, split at the region
    /// cap, then scan the byte budget.
    fn reference(
        map: &AllocationBitmap<'_>,
        limits: FreeSpaceLimits,
    ) -> (Vec<FreeRun>, usize, u64) {
        let mut runs = map.free_runs();
        runs.sort_unstable_by(|a, b| b.bytes.cmp(&a.bytes).then(a.offset.cmp(&b.offset)));
        let (mut dropped, mut dropped_bytes) = (0usize, 0u64);
        if runs.len() > limits.max_regions {
            let tail = runs.split_off(limits.max_regions);
            dropped += tail.len();
            dropped_bytes += tail.iter().map(|r| r.bytes).sum::<u64>();
        }
        let mut kept = 0u64;
        runs.retain(|r| {
            if kept + r.bytes > limits.max_bytes {
                dropped += 1;
                dropped_bytes += r.bytes;
                false
            } else {
                kept += r.bytes;
                true
            }
        });
        runs.sort_unstable_by_key(|r| r.offset);
        (runs, dropped, dropped_bytes)
    }

    #[test]
    fn streaming_selection_matches_sort_and_split_on_random_bitmaps() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..40 {
            let len = 1 + (next() % 200) as usize;
            let bits: Vec<u8> = (0..len)
                .map(|_| match round % 3 {
                    0 => next() as u8,
                    1 => (next() as u8) & (next() as u8),
                    _ => 0xAA,
                })
                .collect();
            let clusters = len as u64 * 8;
            let map = ntfs(&bits, clusters);
            let limits = FreeSpaceLimits {
                max_regions: 1 + (next() % 30) as usize,
                max_bytes: (1 + next() % 400) * CLUSTER,
            };
            let (regions, outcome) = emit_free_regions_with(
                &parent(),
                &volume((clusters * CLUSTER) as usize),
                &map,
                labels(),
                limits,
            );
            let (expected, dropped, dropped_bytes) = reference(&map, limits);
            let got: Vec<(u64, u64)> = regions
                .iter()
                .map(|r| {
                    (
                        r.metadata["offset_bytes"].as_u64().unwrap(),
                        r.metadata["size_bytes"].as_u64().unwrap(),
                    )
                })
                .collect();
            let want: Vec<(u64, u64)> = expected.iter().map(|r| (r.offset, r.bytes)).collect();
            assert_eq!(got, want, "round {round}");
            assert_eq!(outcome.runs_dropped, dropped, "round {round}");
            assert_eq!(outcome.bytes_dropped, dropped_bytes, "round {round}");
        }
    }

    #[test]
    fn free_clusters_past_the_end_of_the_source_are_unassessed_not_emitted() {
        // Geometry claims 16 clusters, all free; the image holds only 10.
        let bits = vec![0u8; 2];
        let map = ntfs(&bits, 16);
        let (regions, outcome) =
            emit_free_regions(&parent(), &volume(10 * CLUSTER as usize), &map, labels());
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].metadata["size_bytes"], json!(10 * CLUSTER));
        assert_eq!(outcome.unassessed_clusters, 6);
        assert_eq!(outcome.unassessed_bytes, 6 * CLUSTER);
        assert!(!outcome.is_complete());
    }

    #[test]
    fn every_region_states_what_free_does_and_does_not_mean() {
        // The region is where a carved file's provenance chain ends, so the
        // sentence has to be on it rather than only in a document.
        let bits = allocated(&[0], 8);
        let map = ntfs(&bits, 8);
        let (regions, _) = emit_free_regions(
            &parent(),
            &volume(8 * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume, not the evidence",
            },
        );
        let m = &regions[0].metadata;
        assert_eq!(m["filesystem"], "NTFS");
        assert_eq!(m["offset_basis"], "the volume, not the evidence");
        assert_eq!(m["source"], "allocation_bitmap");
        let means = m["free_means"].as_str().unwrap();
        assert!(
            means.contains("not a finding that nothing was ever written"),
            "{means}"
        );
        assert!(means.contains("shadow copy"), "{means}");
        assert!(means.contains("slack"), "{means}");
    }

    #[test]
    fn the_bit_convention_is_the_callers_to_state() {
        // No filesystem here uses set-is-free, and the variant exists so that
        // a caller cannot inherit the wrong convention by omission. Inverted,
        // the same bytes describe the complement.
        let bits = allocated(&[0, 1], 8);
        let allocated_map = ntfs(&bits, 8);
        let free_map = AllocationBitmap {
            bit_meaning: BitMeaning::SetIsFree,
            ..allocated_map
        };
        assert_eq!(
            allocated_map
                .free_runs()
                .iter()
                .map(|r| r.clusters)
                .sum::<u64>(),
            6
        );
        assert_eq!(
            free_map.free_runs().iter().map(|r| r.clusters).sum::<u64>(),
            2
        );
    }

    #[test]
    fn the_outcome_record_publishes_every_number_a_reader_needs() {
        let bits = allocated(&[0], 8);
        let map = ntfs(&bits, 1_000);
        let (_, outcome) = emit_free_regions(
            &parent(),
            &volume(1_000 * CLUSTER as usize),
            &map,
            FreeSpaceLabels {
                filesystem: "NTFS",
                offset_basis: "the volume",
            },
        );
        let json = outcome.to_json();
        assert_eq!(json["free_runs_found"], 1);
        assert_eq!(json["free_regions_emitted"], 1);
        assert_eq!(json["free_bytes_emitted"], 7 * CLUSTER);
        assert_eq!(json["free_runs_dropped"], 0);
        assert_eq!(json["free_space_unassessed_clusters"], 992);
        assert_eq!(json["free_space_complete"], false);
        assert_eq!(json["free_space_incomplete"], true);
        assert_eq!(json["free_space_incomplete_reason"], "unresolved_structure");
        assert!(json["free_space_incomplete_detail"].is_string());
    }
}
