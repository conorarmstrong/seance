#![forbid(unsafe_code)]
use seance_carving::engine::{CarvedFile, CarvingDataSource, CarvingEngine};
use seance_carving::ext2_indirect::{self, CarveSize, Ext2Reconstruction, RebuiltEnd};
use seance_carving::formats;
use seance_carving::registry::SignatureRegistry;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{BufferedDataSource, DataSource, RunListDataSource, SourceCursor, WindowSource},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
    orchestrator::{CancellationHandle, ProgressReporter},
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Adapter bridging seance_core::DataSource to CarvingDataSource.
struct DataSourceAdapter {
    inner: Arc<dyn DataSource>,
}

impl CarvingDataSource for DataSourceAdapter {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// Maximum number of carved files per artifact to prevent runaway carving.
const MAX_CARVED_FILES: usize = 50_000;

/// Minimum file size to consider valid (skip tiny false positives).
const MIN_CARVED_SIZE: u64 = 16;

/// Build a carved FileEntry artifact from an engine [`CarvedFile`].
///
/// `source` is the data source the carved bytes live in; the artifact gets a
/// [`WindowSource`] over `[carved.offset, carved.offset + carved.size)`.
/// `carving_offset` is the offset reported relative to the scanned input, while
/// `carving_offset_absolute`, when set, is the position in the parent evidence.
/// Any `extra` metadata keys (e.g. `carving_source`) are merged last. The
/// carved bytes are hashed (md5 + sha256) through the window for chain of
/// custody.
///
/// `layout`, when set, is the carve rebuilt without the ext2 pointer blocks
/// in line with it (DFTT #12): the artifact then reads, hashes and records
/// that run list — `data_runs` in the same coordinates as `carving_offset`, so
/// the content resolver serves exactly the bytes hashed here — and `size` is
/// the rebuilt file's length.
#[allow(clippy::too_many_arguments)]
fn build_carved_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    source: &Arc<dyn DataSource>,
    carved: &CarvedFile,
    carving_offset: u64,
    carving_offset_absolute: Option<u64>,
    extra: &[(&str, Value)],
    layout: Option<&Ext2Reconstruction>,
) -> Artifact {
    let (window, size): (Arc<dyn DataSource>, u64) = match layout {
        Some(l) => (
            Arc::new(RunListDataSource::from_allocation(
                source.clone(),
                l.runs.iter().map(|&(o, len)| (Some(o), len)).collect(),
            )),
            l.logical_size,
        ),
        None => (
            Arc::new(WindowSource::new(
                source.clone(),
                carved.offset,
                carved.size,
            )),
            carved.size,
        ),
    };

    let mut metadata = json!({
        "name": format!("carved_{:08x}.{}", carving_offset, carved.extension),
        "size": size,
        "carved": true,
        "carving_signature": carved.signature_name,
        "carving_offset": carving_offset,
        "carving_size": size,
    });
    if let Some(l) = layout {
        // `carving_offset` is `carved.offset` shifted into the reporting
        // coordinates; the runs are shifted the same way.
        let shift = carving_offset - carved.offset;
        let runs: Vec<Value> = l
            .runs
            .iter()
            .map(|&(o, len)| json!([o + shift, len]))
            .collect();
        metadata["data_runs"] = json!(runs);
        metadata["data_runs_complete"] = json!(true);
        metadata["carving_reconstruction"] = json!("ext2_indirect");
        metadata["carving_pointer_blocks_skipped"] = json!(l.pointer_blocks.len());
        metadata["carving_fs_block_size"] = json!(l.block_size);
        metadata["carving_extent_bytes"] = json!(l.physical_end() - carved.offset);
    }

    if let Some(abs) = carving_offset_absolute {
        metadata["carving_offset_absolute"] = json!(abs);
    }
    // A carve sized again through the layout ends where that scan ended; the
    // raw carve's flag describes a different end and is not published.
    let validated = match layout.map(|l| l.end) {
        Some(RebuiltEnd::Resized { validated }) => validated,
        _ => carved.validated,
    };
    if let Some(validated) = validated {
        metadata["carving_validated"] = json!(validated);
    }
    for (key, value) in extra {
        metadata[*key] = value.clone();
    }

    let hash_src: Arc<dyn DataSource> = window.clone();
    let mut bytes_hashed = 0u64;
    let hashed = seance_core::hashing::compute_hashes_streaming_with_progress(
        &mut SourceCursor::new(hash_src),
        1024 * 1024,
        |done| bytes_hashed = done,
    );
    match hashed {
        // Only digests that cover the WHOLE declared window are chain-of-custody
        // evidence. If the window ran past the end of the backing source (or an
        // I/O error cut it short) the digests describe a prefix; publishing them
        // under the declared `size` would let a partial read verify as the carved
        // file. Record the shortfall instead, mirroring the file hasher's
        // `hash_skipped: short_read` (BUG-267).
        Ok(hashes) if bytes_hashed == size => {
            metadata["md5"] = json!(hashes.md5);
            metadata["sha256"] = json!(hashes.sha256);
        }
        Ok(_) => {
            warn!(
                "Carved file at offset 0x{:x} declares {} bytes but only {} could be read; digests withheld",
                carved.offset, size, bytes_hashed
            );
            metadata["hash_skipped"] = json!("short_read");
            metadata["bytes_hashed"] = json!(bytes_hashed);
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] =
                json!(seance_core::io::IncompleteReason::ShortRead.as_str());
        }
        Err(e) => {
            warn!(
                "Failed to hash carved file at offset 0x{:x} ({} bytes): {}",
                carved.offset, size, e
            );
            metadata["hash_skipped"] = json!("io_error");
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] =
                json!(seance_core::io::IncompleteReason::ShortRead.as_str());
        }
    }

    Artifact::new(case_id, ArtifactType::FileEntry, Some(window), metadata).with_parent(parent_id)
}

/// Stamp the carving summary with why the carved corpus may not be everything
/// that was recoverable.
///
/// Forensic meaning: `total_carved` is what this run emitted. A file cap or a
/// cancellation means further recoverable objects were left in the region.
/// Without this marker the carved corpus reads as the complete set of
/// recoverable files, and "nothing else was there" is exactly the conclusion an
/// examiner draws from a summary that never says otherwise (B2-085). A run that
/// finished must carry no marker, so an honest complete carve is distinguishable
/// from a truncated one.
///
/// A scan that stopped before the region's end without being cancelled — the
/// source delivered fewer bytes than it declared — is `short_read`: the bytes
/// past `scanned_bytes` were never examined.
fn stamp_carve_incompleteness(
    meta: &mut Value,
    file_cap_reached: bool,
    cancelled: bool,
    read_short: bool,
) {
    if !file_cap_reached && !cancelled && !read_short {
        return;
    }
    meta["content_incomplete"] = json!(true);
    meta["content_incomplete_reason"] = json!(if file_cap_reached {
        seance_core::io::IncompleteReason::CapReached.as_str()
    } else if cancelled {
        seance_core::io::IncompleteReason::UnresolvedStructure.as_str()
    } else {
        seance_core::io::IncompleteReason::ShortRead.as_str()
    });
}

/// Shared scan-and-emit core for the region carvers (whole-region [`FileCarver`]
/// and automatic [`UnallocatedCarver`]).
///
/// Scans `artifact`'s data source with the carving engine, deduplicates
/// overlapping candidates (largest match wins), and emits one carved FileEntry
/// per survivor plus a CarvingSummary ParsedRecord. Respects the supplied
/// cancellation handle and progress reporter. `who` is used only for logging.
/// Alignment a header carved out of file slack is looked for on.
///
/// No file can begin in slack: a file system starts a file at a cluster
/// boundary, and the start of the cluster that holds the slack is the live
/// owner's own content. So an object whose header lies in slack is either part
/// of a former file's content (an executable embedded in an archive or an
/// installer, say) or bytes written there deliberately. Such an object is
/// looked for at each 512-byte boundary past the owner's logical end — the
/// granularity the carving engine scans at and a sector write can place bytes
/// on — and nothing before the first of them, which lies in the owner's own
/// last sector.
const SLACK_SECTOR: u64 = 512;

/// How a region's carves are attributed, read off the region itself.
struct RegionProvenance {
    /// Bytes at the start of the region not scanned: for file slack, up to the
    /// first 512-byte boundary past the owner's logical end (see
    /// [`SLACK_SECTOR`]). The scan never reads past the region, so a carve from
    /// slack ends, at the latest, at the end of the owner's last cluster.
    skip: u64,
    /// Keys every carve from the region carries (`carving_source` et al.).
    extra: Vec<(&'static str, Value)>,
    /// Whether a scan that recovered nothing still gets its own summary.
    summary_when_empty: bool,
}

fn provenance_of(artifact: &Artifact) -> RegionProvenance {
    if artifact.artifact_type != ArtifactType::SlackSpace {
        return RegionProvenance {
            skip: 0,
            extra: Vec::new(),
            summary_when_empty: true,
        };
    }
    let md = &artifact.metadata;
    let start = md.get("offset_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
    let mut extra: Vec<(&'static str, Value)> = vec![("carving_source", json!("slack"))];
    for (from, to) in [
        ("parent_file", "parent_file"),
        ("parent_path", "parent_path"),
        ("owner_artifact_id", "slack_owner_artifact_id"),
    ] {
        if let Some(v) = md.get(from) {
            extra.push((to, v.clone()));
        }
    }
    RegionProvenance {
        skip: (SLACK_SECTOR - start % SLACK_SECTOR) % SLACK_SECTOR,
        extra,
        // One slack region per live file with a non-zero tail: a "0 recovered"
        // record for each would bury the case. The volume's
        // `slack_space_summary` is the record that they were produced, and
        // this carver is automatic, so every one it receives is scanned.
        summary_when_empty: false,
    }
}

fn region_carve(
    registry: &Arc<SignatureRegistry>,
    who: &str,
    artifact: &Artifact,
    cancel: &Option<CancellationHandle>,
    progress: &Option<ProgressReporter>,
) -> Vec<Artifact> {
    let region_source = match artifact.data.as_ref() {
        Some(ds) => ds,
        None => return Vec::new(),
    };

    let provenance = provenance_of(artifact);
    let region_size = region_source.size();
    if region_size <= provenance.skip {
        return Vec::new();
    }
    // The bytes actually scanned; offsets the engine reports are into this.
    let scanned: Arc<dyn DataSource> = if provenance.skip == 0 {
        region_source.clone()
    } else {
        Arc::new(WindowSource::new(
            region_source.clone(),
            provenance.skip,
            region_size - provenance.skip,
        ))
    };
    let data_source = &scanned;
    let total_size = data_source.size();
    if total_size == 0 {
        return Vec::new();
    }

    info!(
        "{} scanning {} bytes from artifact {} (type: {:?})",
        who, total_size, artifact.id, artifact.artifact_type
    );

    // Buffer the source: the engine scans in 512-byte blocks, so an unbuffered
    // source (an E01 IPC round-trip or a file syscall per block) would pay one
    // backing read per 512 bytes. A 1 MiB read-through buffer collapses the
    // sequential scan to ~one backing read per megabyte.
    let buffered: Arc<dyn DataSource> =
        Arc::new(BufferedDataSource::new(data_source.clone(), 1024 * 1024));
    let adapter = DataSourceAdapter { inner: buffered };

    // Position of this artifact's data within the parent evidence, used to
    // compute absolute offsets for carved files.
    let input_offset = artifact
        .metadata
        .get("offset_bytes")
        .and_then(|v| v.as_u64());

    let engine = CarvingEngine::new(registry.clone());

    let reporter = progress.clone();
    let artifact_id = artifact.id;
    let case_id = artifact.case_id;
    let mut progress_cb = |bytes_scanned: u64, bytes_total: u64| {
        if let Some(r) = &reporter {
            r.report_for_case(
                case_id,
                artifact_id,
                bytes_scanned,
                Some(bytes_total),
                "bytes",
            );
        }
    };
    let cancel_cb: Option<Box<dyn Fn() -> bool>> = cancel
        .clone()
        .map(|h| Box::new(move || h.is_cancelled(case_id)) as Box<dyn Fn() -> bool>);

    let scan = engine.scan_with_progress(
        &adapter,
        total_size,
        Some(&mut progress_cb),
        cancel_cb.as_deref(),
    );
    let carved_files = scan.files;
    let mut below_minimum = scan.below_minimum;
    if let Some(r) = progress {
        r.report_now_for_case(
            artifact.case_id,
            artifact_id,
            scan.bytes_scanned,
            Some(total_size),
            "bytes",
        );
    }
    if scan.cancelled {
        warn!(
            "{} cancelled after {} of {} bytes on artifact {}; emitting partial results",
            who, scan.bytes_scanned, total_size, artifact.id
        );
    }

    info!(
        "{} found {} raw candidates in artifact {}",
        who,
        carved_files.len(),
        artifact.id
    );

    // Deduplicate: remove overlapping carved files, keeping the largest match at each offset.
    // Sort by offset, then by size descending so larger files win ties.
    let mut sorted_files = carved_files;
    sorted_files.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.size.cmp(&a.size)));

    let mut artifacts = Vec::new();
    let mut last_end: u64 = 0;
    let mut stats: HashMap<String, (usize, u64)> = HashMap::new(); // sig_name -> (count, total_bytes)
    let mut skipped_overlap = 0usize;
    let mut skipped_tiny = 0usize;

    let mut file_cap_reached = false;
    // The windows of the files published below, in offset order and disjoint,
    // so a below-minimum candidate can be tested against them.
    let mut recorded: Vec<(u64, u64)> = Vec::new();
    for carved in &sorted_files {
        // Skip tiny false positives
        if carved.size < MIN_CARVED_SIZE {
            skipped_tiny += 1;
            continue;
        }

        // Skip overlapping regions (keep the first/largest match)
        if carved.offset < last_end {
            skipped_overlap += 1;
            debug!(
                "Skipping overlapping carved file {} at 0x{:x} (overlaps with previous ending at 0x{:x})",
                carved.signature_name, carved.offset, last_end
            );
            continue;
        }

        // Enforce limit
        if artifacts.len() >= MAX_CARVED_FILES {
            warn!(
                "{} hit {} file limit, stopping carving for artifact {}",
                who, MAX_CARVED_FILES, artifact.id
            );
            file_cap_reached = true;
            break;
        }

        // A carve that runs across ext2 pointer blocks in line with it is
        // rebuilt without them (DFTT #12). A size taken from the file's own
        // header is its logical length; any other is the span it covered.
        // Done only for a carve that will be published: the overlap and cap
        // checks above need nothing from the rebuild.
        let kind = if carved.validated.is_none() {
            CarveSize::Logical
        } else {
            CarveSize::Physical
        };
        let layout = ext2_indirect::reconstruct(&adapter, carved.offset, carved.size, kind)
            .or_else(|| ext2_indirect::resize_through_layout(&engine, &adapter, carved));
        last_end = layout
            .as_ref()
            .map(|l| l.physical_end())
            .unwrap_or(carved.offset + carved.size);
        let size = layout
            .as_ref()
            .map(|l| l.logical_size)
            .unwrap_or(carved.size);

        recorded.push((carved.offset, last_end));

        // Track stats
        let entry = stats.entry(carved.signature_name.clone()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += size;

        // Reported relative to the region, and absolutely as the region's
        // own offset plus that.
        let in_region = provenance.skip + carved.offset;
        let absolute = input_offset.map(|base| base + in_region);
        let file_artifact = build_carved_artifact(
            artifact.case_id,
            artifact.id,
            data_source,
            carved,
            in_region,
            absolute,
            &provenance.extra,
            layout.as_ref(),
        );

        debug!(
            "Carved {} at offset 0x{:x} ({} bytes)",
            carved.signature_name, carved.offset, carved.size
        );

        artifacts.push(file_artifact);
    }

    // Carves that matched a header and ended short of their signature's
    // minimum size (CARVE-018). The engine returns them instead of dropping
    // them; each is published as a file entry marked `carving_below_minimum`,
    // never as a recovered file, and counted apart from `total_carved`. One
    // that is tiny, or overlaps a published file or an earlier candidate, is
    // counted and not published.
    below_minimum.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.size.cmp(&a.size)));
    let mut below_artifacts: Vec<Artifact> = Vec::new();
    let mut below_stats: HashMap<String, usize> = HashMap::new();
    let mut skipped_tiny_below_minimum = 0usize;
    let mut last_below_end: u64 = 0;
    for carved in &below_minimum {
        if carved.size < MIN_CARVED_SIZE {
            skipped_tiny_below_minimum += 1;
            continue;
        }
        let end = carved.offset + carved.size;
        let at = recorded.partition_point(|&(start, _)| start < end);
        let overlaps_recorded = recorded[..at]
            .last()
            .is_some_and(|&(_, e)| e > carved.offset);
        if overlaps_recorded || carved.offset < last_below_end {
            skipped_overlap += 1;
            continue;
        }
        if artifacts.len() + below_artifacts.len() >= MAX_CARVED_FILES {
            file_cap_reached = true;
            break;
        }
        last_below_end = end;
        *below_stats
            .entry(carved.signature_name.clone())
            .or_insert(0) += 1;
        let in_region = provenance.skip + carved.offset;
        let absolute = input_offset.map(|base| base + in_region);
        let mut extra = provenance.extra.clone();
        extra.push(("carving_below_minimum", json!(true)));
        below_artifacts.push(build_carved_artifact(
            artifact.case_id,
            artifact.id,
            data_source,
            carved,
            in_region,
            absolute,
            &extra,
            None,
        ));
    }
    let total_below_minimum = below_artifacts.len();
    artifacts.extend(below_artifacts);

    // Emit a summary record whenever bytes were actually read.
    //
    // It used to be emitted only when something was carved or skipped, so a
    // region that was scanned and held nothing produced NOTHING — no record
    // that it had been looked at. "Examined and empty" and "never examined"
    // were the same absence in the case, which is the one thing this project
    // does not allow, and §5.4 made it the common case rather than a corner:
    // the free space of a clean volume is exactly a region that is carved and
    // holds no file. A region with no data source, or one of zero length,
    // still produces nothing at all — there is no scan to report.
    //
    // A region whose empty summary is suppressed (file slack) still gets one
    // when its scan was not clean and complete: a cancellation or a short
    // read part-way through must leave a `content_incomplete` record, or
    // "scanned and empty" and "stopped part-way" are the same absence.
    let read_short = !scan.cancelled && scan.bytes_scanned < total_size;
    let worth_a_summary = if provenance.summary_when_empty {
        scan.bytes_scanned > 0
    } else {
        scan.cancelled || read_short
    };
    if worth_a_summary
        || !artifacts.is_empty()
        || skipped_overlap > 0
        || skipped_tiny > 0
        || skipped_tiny_below_minimum > 0
    {
        let type_breakdown: Vec<serde_json::Value> = stats
            .iter()
            .map(|(sig, (count, bytes))| {
                json!({
                    "signature": sig,
                    "count": count,
                    "total_bytes": bytes,
                })
            })
            .collect();

        let below_minimum_breakdown: Vec<serde_json::Value> = below_stats
            .iter()
            .map(|(sig, count)| json!({ "signature": sig, "count": count }))
            .collect();

        let mut meta = json!({
            "type": "CarvingSummary",
            "subtype": "carving_summary",
            "name": format!("Carving Summary ({} files recovered)", artifacts.len() - total_below_minimum),
            "total_carved": artifacts.len() - total_below_minimum,
            // Candidates that ended short of their signature's minimum size,
            // published marked `carving_below_minimum`; not recovered files.
            "total_below_minimum": total_below_minimum,
            "below_minimum_breakdown": below_minimum_breakdown,
            "skipped_tiny_below_minimum": skipped_tiny_below_minimum,
            "total_candidates": sorted_files.len(),
            "skipped_overlap": skipped_overlap,
            "skipped_tiny": skipped_tiny,
            "scanned_bytes": scan.bytes_scanned,
            "cancelled": scan.cancelled,
            "type_breakdown": type_breakdown,
            // `total_carved` is what this run emitted, not what the region holds.
            "file_cap_reached": file_cap_reached,
            "max_carved_files": MAX_CARVED_FILES,
        });
        stamp_carve_incompleteness(&mut meta, file_cap_reached, scan.cancelled, read_short);

        let summary = Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
            .with_parent(artifact.id)
            .with_subtype("carving_summary");

        artifacts.push(summary);
    }

    info!(
        "{}: {} files recovered, {} overlaps skipped, {} tiny skipped from artifact {}",
        who,
        artifacts.len().saturating_sub(1), // -1 for the summary record
        skipped_overlap,
        skipped_tiny,
        artifact.id
    );

    artifacts
}

/// File carving ForensicsModule that wraps the seance_carving engine.
///
/// TODO(orchestrator-context): `ForensicsModule::process()` has no context
/// parameter, so the orchestrator cannot inject a per-run ProgressReporter or
/// CancellationHandle at dispatch time. Until the module trait grows a
/// context, callers that construct the carver directly (CLI, API wiring)
/// should attach them via `with_progress` / `with_cancellation` using
/// `Orchestrator::progress_reporter()` and `Orchestrator::cancellation_handle()`.
pub struct FileCarver {
    registry: Arc<SignatureRegistry>,
    cancel: Option<CancellationHandle>,
    progress: Option<ProgressReporter>,
}

impl FileCarver {
    pub fn new() -> Self {
        let mut registry = SignatureRegistry::new();
        formats::register_all(&mut registry);
        Self {
            registry: Arc::new(registry),
            cancel: None,
            progress: None,
        }
    }

    /// Like [`new`](Self::new), plus user-defined carving signatures parsed from
    /// a JSON custom-defs document. Returns an error string if it is malformed,
    /// so a bad definition fails loudly rather than silently reducing coverage.
    pub fn with_custom_defs(defs: &str) -> Result<Self, String> {
        let mut registry = SignatureRegistry::new();
        formats::register_all(&mut registry);
        let n = seance_carving::register_custom_signatures(&mut registry, defs)?;
        tracing::info!("Registered {n} custom carving signature(s)");
        Ok(Self {
            registry: Arc::new(registry),
            cancel: None,
            progress: None,
        })
    }

    /// Attach a cancellation handle; the scan stops cooperatively when it
    /// fires and emits the files carved so far (summary gets `cancelled: true`).
    pub fn with_cancellation(mut self, handle: CancellationHandle) -> Self {
        self.cancel = Some(handle);
        self
    }

    /// Attach a progress reporter; the scan emits ModuleProgress events in
    /// bytes (rate-limited by the reporter, at most ~1/sec).
    pub fn with_progress(mut self, reporter: ProgressReporter) -> Self {
        self.progress = Some(reporter);
        self
    }

    /// Opt-in file-slack carving for a single file.
    ///
    /// Slack is the space between a file's logical end and the end of its last
    /// allocated cluster. Automatic processing does not come through here: the
    /// NTFS, FAT, exFAT, ext4, HFS+ and APFS parsers emit one `SlackSpace` region per live file
    /// whose tail holds anything (`seance_core::slack`, HUNT-124), and
    /// [`UnallocatedCarver`] carves those regions with the same provenance
    /// keys. This remains for a caller that holds the geometry itself: it
    /// extracts `data_runs` + logical size + cluster size from a FileEntry and
    /// computes `allocation_end_absolute` (the absolute byte offset of the end
    /// of the last allocated cluster) before calling this.
    ///
    /// `volume` is the partition/filesystem data source the file lives in (slack
    /// bytes are past the FileEntry's own logical window, so the enclosing
    /// volume must be supplied). Recovered content is emitted as carved
    /// FileEntry artifacts tagged `carving_source = "slack"`, parented to
    /// `parent`, with absolute offsets and md5/sha256 hashes. Returns an empty
    /// vec when there is no slack or nothing is recoverable.
    pub fn carve_slack_for_file(
        &self,
        volume: Arc<dyn DataSource>,
        parent: &Artifact,
        logical_size: u64,
        cluster_size: u64,
        allocation_end_absolute: u64,
    ) -> Vec<Artifact> {
        let (slack_offset, slack_len) = match CarvingEngine::slack_region(
            logical_size,
            cluster_size,
            allocation_end_absolute,
        ) {
            Some(region) => region,
            None => return Vec::new(),
        };

        // Buffer the volume so the engine's 512-byte block reads don't each hit
        // the underlying source (see the region-carving path).
        let buffered: Arc<dyn DataSource> =
            Arc::new(BufferedDataSource::new(volume.clone(), 1024 * 1024));
        let adapter = DataSourceAdapter { inner: buffered };
        let engine = CarvingEngine::new(self.registry.clone());
        let mut finds = engine.carve_slack(&adapter, slack_offset, slack_len, cluster_size);

        // Deduplicate overlaps (largest match wins), mirroring region carving.
        finds.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.size.cmp(&a.size)));

        let parent_name = parent.metadata.get("name").cloned();
        let mut out = Vec::new();
        let mut last_end: u64 = 0;
        for carved in &finds {
            if carved.offset < last_end {
                continue;
            }
            last_end = carved.offset + carved.size;

            // carve_slack returns absolute offsets in `volume`; report the
            // position within the slack window plus the absolute offset.
            let relative = carved.offset - slack_offset;
            let mut extra: Vec<(&str, Value)> = vec![("carving_source", json!("slack"))];
            if let Some(name) = &parent_name {
                extra.push(("parent_file", name.clone()));
            }
            let art = build_carved_artifact(
                parent.case_id,
                parent.id,
                &volume,
                carved,
                relative,
                Some(carved.offset),
                &extra,
                None,
            );
            out.push(art);
        }

        info!(
            "Slack carving recovered {} artifact(s) from file {} (slack [{}, {}))",
            out.len(),
            parent.id,
            slack_offset,
            slack_offset + slack_len
        );

        out
    }
}

impl Default for FileCarver {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for FileCarver {
    fn id(&self) -> &str {
        "plugin.recovery.file_carver"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileSystem, ArtifactType::UnallocatedSpace]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::OptIn
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Whole-region carving: shared core with UnallocatedCarver.
        Ok(region_carve(
            &self.registry,
            self.id(),
            artifact,
            &self.cancel,
            &self.progress,
        ))
    }
}

/// Automatic unallocated-space carver.
///
/// Runs during normal ingest (`ExecutionMode::Automatic`) but subscribes ONLY
/// to [`ArtifactType::UnallocatedSpace`] -- carving entire live filesystems
/// automatically is too expensive, whereas unallocated space is the bounded,
/// forensically important target commercial triage tools carve by default.
///
/// It shares the exact scan-and-emit core ([`region_carve`]) with the on-demand
/// [`FileCarver`], emitting the same carved FileEntry artifacts (absolute
/// offsets from the region's `offset_bytes`, md5 + sha256, validation flag) plus
/// a CarvingSummary.
///
/// Cancellation / progress: like [`FileCarver`], `ForensicsModule::process()`
/// has no context parameter, so wiring that constructs this module directly
/// should attach a per-run handle/reporter via `with_cancellation` /
/// `with_progress` using `Orchestrator::cancellation_handle()` /
/// `Orchestrator::progress_reporter()`.
pub struct UnallocatedCarver {
    registry: Arc<SignatureRegistry>,
    cancel: Option<CancellationHandle>,
    progress: Option<ProgressReporter>,
}

impl UnallocatedCarver {
    pub fn new() -> Self {
        let mut registry = SignatureRegistry::new();
        formats::register_all(&mut registry);
        Self {
            registry: Arc::new(registry),
            cancel: None,
            progress: None,
        }
    }

    /// Like [`new`](Self::new), plus user-defined carving signatures from a JSON
    /// custom-defs document. Returns an error string if it is malformed.
    pub fn with_custom_defs(defs: &str) -> Result<Self, String> {
        let mut registry = SignatureRegistry::new();
        formats::register_all(&mut registry);
        let n = seance_carving::register_custom_signatures(&mut registry, defs)?;
        tracing::info!("Registered {n} custom carving signature(s)");
        Ok(Self {
            registry: Arc::new(registry),
            cancel: None,
            progress: None,
        })
    }

    /// Attach a cancellation handle (see [`FileCarver::with_cancellation`]).
    pub fn with_cancellation(mut self, handle: CancellationHandle) -> Self {
        self.cancel = Some(handle);
        self
    }

    /// Attach a progress reporter (see [`FileCarver::with_progress`]).
    pub fn with_progress(mut self, reporter: ProgressReporter) -> Self {
        self.progress = Some(reporter);
        self
    }
}

impl Default for UnallocatedCarver {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for UnallocatedCarver {
    fn id(&self) -> &str {
        "plugin.recovery.unallocated_carver"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // File slack (HUNT-124) is bounded the same way free space is — one
        // region per live file whose tail holds anything, under a per-volume
        // ceiling — and is where a file hidden in an allocated cluster is.
        vec![ArtifactType::UnallocatedSpace, ArtifactType::SlackSpace]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(region_carve(
            &self.registry,
            self.id(),
            artifact,
            &self.cancel,
            &self.progress,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::module::{ExecutionMode, ForensicsModule, InputCapability};
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Helper: create an Artifact with the given type, data source, and metadata.
    fn make_artifact(
        artifact_type: ArtifactType,
        data: Option<Arc<dyn DataSource>>,
        metadata: serde_json::Value,
    ) -> Artifact {
        Artifact::new(Uuid::new_v4(), artifact_type, data, metadata)
    }

    /// Helper: build a valid BMP blob.
    /// BMP is the simplest format for testing because the carving engine reads
    /// the file size directly from bytes 2..6 (LE u32) and emits a CarvedFile
    /// with `calculated_file_size` -- no data_check loop required.
    fn make_bmp(file_size: u32) -> Vec<u8> {
        let mut bmp = vec![0u8; file_size as usize];
        // Magic bytes "BM"
        bmp[0] = b'B';
        bmp[1] = b'M';
        // File size at bytes 2..6 (LE)
        bmp[2..6].copy_from_slice(&file_size.to_le_bytes());
        // A real header: pixel data at 54, a 40-byte DIB header (the signature
        // rejects a bare "BM" plus size).
        bmp[10..14].copy_from_slice(&54u32.to_le_bytes());
        bmp[14..18].copy_from_slice(&40u32.to_le_bytes());
        bmp
    }

    /// Helper: build a minimal PNG (header + padding + IEND chunk with CRC).
    fn make_png(total_size: usize) -> Vec<u8> {
        assert!(total_size >= 29, "PNG test data must be >= 29 bytes");
        let mut png = vec![0u8; total_size];
        // 8-byte PNG header
        png[0..8].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        // Place IEND chunk near the end:
        // IEND chunk = 4 bytes length (0) + 4 bytes "IEND" + 4 bytes CRC = 12 bytes
        let iend_type_offset = total_size - 8; // "IEND" starts here
        png[iend_type_offset..iend_type_offset + 4].copy_from_slice(b"IEND");
        // 4-byte CRC follows IEND (leave as zeros, fine for carving)
        png
    }

    // -----------------------------------------------------------------------
    // 1. Module metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_id() {
        let carver = FileCarver::new();
        assert_eq!(carver.id(), "plugin.recovery.file_carver");
    }

    #[test]
    fn test_module_version() {
        let carver = FileCarver::new();
        assert_eq!(carver.version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_module_subscribes_to() {
        let carver = FileCarver::new();
        let subs = carver.subscribes_to();
        assert!(subs.contains(&ArtifactType::FileSystem));
        assert!(subs.contains(&ArtifactType::UnallocatedSpace));
        assert_eq!(subs.len(), 2);
    }

    #[test]
    fn test_module_execution_mode_is_optin() {
        let carver = FileCarver::new();
        assert_eq!(carver.execution_mode(), ExecutionMode::OptIn);
    }

    #[test]
    fn test_module_input_capability_is_random_access() {
        let carver = FileCarver::new();
        assert_eq!(carver.input_capability(), InputCapability::RandomAccess);
    }

    #[test]
    fn test_default_trait() {
        // FileCarver implements Default via Default::default() -> new()
        let carver = FileCarver::default();
        assert_eq!(carver.id(), "plugin.recovery.file_carver");
    }

    // -----------------------------------------------------------------------
    // 2. Artifact with no data source returns empty vec
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_data_source_returns_empty() {
        let carver = FileCarver::new();
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, None, json!({}));
        let result = carver.process(&artifact).unwrap();
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 3. Empty data source returns empty vec
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_data_source_returns_empty() {
        let carver = FileCarver::new();
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![]));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let result = carver.process(&artifact).unwrap();
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 3b. Carving reads are buffered, not one syscall/IPC per 512-byte block
    // -----------------------------------------------------------------------

    /// A DataSource that counts read_at calls, wrapping an in-memory blob.
    #[derive(Debug)]
    struct CountingSource {
        data: Vec<u8>,
        reads: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl DataSource for CountingSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let off = offset as usize;
            if off >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    #[test]
    fn carving_reads_are_buffered() {
        use std::sync::atomic::Ordering;
        // A valid BMP at offset 0, then filler out to 512 KiB. Unbuffered, the
        // engine reads 512 bytes at a time -> ~1024 reads of the source; buffered
        // it should be a small handful.
        let mut data = make_bmp(4096);
        data.resize(512 * 1024, 0);
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let src: Arc<dyn DataSource> = Arc::new(CountingSource {
            data,
            reads: reads.clone(),
        });
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(src), json!({}));

        let out = FileCarver::new().process(&artifact).unwrap();
        assert!(!out.is_empty(), "the BMP must still be carved");

        let n = reads.load(Ordering::Relaxed);
        assert!(
            n < 64,
            "expected buffered reads of the source, got {n} (unbuffered would be ~1024)"
        );
    }

    // -----------------------------------------------------------------------
    // 4. Random garbage data yields no carved files (only noise)
    // -----------------------------------------------------------------------

    #[test]
    fn a_region_that_was_carved_and_held_nothing_says_so_rather_than_saying_nothing() {
        // This asserted an empty result, which was the defect: a region read
        // in full and holding no file produced no record that it had been
        // read, so "examined and empty" and "never examined" were the same
        // absence in the case. §5.4 makes that the common case — the free
        // space of a clean volume is exactly this — so the summary is now
        // emitted whenever bytes were scanned.
        let carver = FileCarver::new();
        // 2 KB of 0xAA -- unlikely to match any signature header
        let garbage = vec![0xAA; 2048];
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(garbage));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let result = carver.process(&artifact).unwrap();
        assert!(
            result
                .iter()
                .all(|a| a.artifact_type != ArtifactType::FileEntry),
            "no file is carved out of 2 KB of one repeated byte"
        );
        let summary = result
            .iter()
            .find(|a| a.metadata["type"] == "CarvingSummary")
            .expect("the region was scanned, so the case records that it was");
        assert_eq!(summary.metadata["total_carved"], 0);
        assert_eq!(summary.metadata["total_candidates"], 0);
        assert_eq!(
            summary.metadata["scanned_bytes"], 2048,
            "and how much was read, which is what makes the empty answer mean something"
        );
    }

    #[test]
    fn a_region_with_nothing_to_scan_still_produces_nothing() {
        // The other half of the same rule: where there was no scan there is
        // nothing to report, and a summary claiming a scan of zero bytes
        // would be a record of work nobody did.
        let carver = FileCarver::new();
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![]));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        assert!(carver.process(&artifact).unwrap().is_empty());
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, None, json!({}));
        assert!(carver.process(&artifact).unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // 5. DataSourceAdapter correctly wraps a core DataSource
    // -----------------------------------------------------------------------

    #[test]
    fn test_data_source_adapter_read_at() {
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data.clone()));
        let adapter = DataSourceAdapter {
            inner: inner.clone(),
        };

        // Read the full buffer
        let mut buf = [0u8; 5];
        let n = adapter.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, &data[..]);

        // Read from an offset
        let mut buf2 = [0u8; 2];
        let n = adapter.read_at(3, &mut buf2).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf2, &[0x40, 0x50]);
    }

    #[test]
    fn test_data_source_adapter_size() {
        let data = vec![0u8; 999];
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let adapter = DataSourceAdapter {
            inner: inner.clone(),
        };
        assert_eq!(adapter.size(), 999);
    }

    #[test]
    fn test_data_source_adapter_read_at_past_end() {
        let data = vec![0u8; 10];
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let adapter = DataSourceAdapter { inner };
        let mut buf = [0u8; 4];
        let n = adapter.read_at(10, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    // -----------------------------------------------------------------------
    // 6. Process data containing a BMP signature -- carved FileEntry produced
    // -----------------------------------------------------------------------

    #[test]
    fn test_carve_single_bmp() {
        let carver = FileCarver::new();

        // Embed a 256-byte BMP in a 1024-byte image (at offset 0)
        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(256);
        data[..256].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        // Expect exactly 1 FileEntry (BMP) + 1 CarvingSummary (ParsedRecord)
        assert_eq!(
            results.len(),
            2,
            "Expected exactly 2 artifacts (1 BMP + 1 summary), got {}",
            results.len()
        );

        let file_entries: Vec<_> = results
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert!(!file_entries.is_empty(), "Expected at least one FileEntry");

        let bmp_entry = file_entries
            .iter()
            .find(|a| a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("BMP"))
            .expect("Expected a BMP FileEntry");

        // Verify metadata fields
        assert_eq!(bmp_entry.metadata["carved"], json!(true));
        assert_eq!(bmp_entry.metadata["carving_size"], json!(256));
        assert_eq!(bmp_entry.metadata["carving_offset"], json!(0));
        assert_eq!(bmp_entry.metadata["size"], json!(256));

        // Verify parent_id is set
        assert_eq!(bmp_entry.parent_id, Some(artifact.id));
    }

    #[test]
    fn test_carve_custom_signature_end_to_end() {
        // A user-defined signature carves a file the built-in set doesn't know.
        let defs = r#"{ "signatures": [
            { "name": "AcmeLog", "extension": "acmelog",
              "header": "AC4D454C4F47", "footer": "0A454F46", "max_size": 65536 } ] }"#;
        let carver = FileCarver::with_custom_defs(defs).expect("valid custom defs");

        // header (6) + body (13) + footer (4) = 23 bytes, embedded in a buffer.
        let mut file = vec![0xAC, 0x4D, 0x45, 0x4C, 0x4F, 0x47];
        file.extend_from_slice(b"acme log body");
        file.extend_from_slice(&[0x0A, 0x45, 0x4F, 0x46]);
        let file_len = file.len() as u64;
        let mut data = vec![0u8; 2048];
        data[..file.len()].copy_from_slice(&file);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let entry = results
            .iter()
            .find(|a| {
                a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("AcmeLog")
            })
            .expect("custom AcmeLog signature should carve a file");
        assert_eq!(entry.metadata["carved"], json!(true));
        assert_eq!(entry.metadata["carving_offset"], json!(0));
        assert_eq!(entry.metadata["carving_size"], json!(file_len));
        assert_eq!(entry.metadata["name"], json!("carved_00000000.acmelog"));
    }

    // -----------------------------------------------------------------------
    // 7. Verify carved FileEntry has a WindowSource data source
    // -----------------------------------------------------------------------

    #[test]
    fn test_carved_file_has_readable_data() {
        let carver = FileCarver::new();

        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(128);
        data[..128].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let file_entry = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("Expected a FileEntry");

        // The carved artifact should have a data source (WindowSource)
        let carved_ds = file_entry
            .data
            .as_ref()
            .expect("FileEntry should have data source");
        assert_eq!(carved_ds.size(), 128);

        // Read the first two bytes via the window -- should be "BM"
        let mut buf = [0u8; 2];
        carved_ds.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"BM");
    }

    // -----------------------------------------------------------------------
    // 8. Verify CarvingSummary ParsedRecord is generated with correct stats
    // -----------------------------------------------------------------------

    #[test]
    fn test_carving_summary_record() {
        let carver = FileCarver::new();

        let mut data = vec![0u8; 2048];
        // Place a 256-byte BMP at offset 0
        let bmp = make_bmp(256);
        data[..256].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let summary = results
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::ParsedRecord
                    && a.metadata.get("type").and_then(|v| v.as_str()) == Some("CarvingSummary")
            })
            .expect("Expected a CarvingSummary ParsedRecord");

        // Check summary fields
        assert_eq!(summary.metadata["subtype"], json!("carving_summary"));
        assert_eq!(summary.metadata["scanned_bytes"], json!(2048));
        assert!(summary.metadata["total_carved"].as_u64().unwrap() >= 1);
        assert!(summary.metadata["total_candidates"].as_u64().unwrap() >= 1);
        assert!(summary.metadata["type_breakdown"].is_array());

        // parent_id should be set
        assert_eq!(summary.parent_id, Some(artifact.id));

        // subtype should be set via with_subtype
        assert_eq!(summary.subtype(), Some("carving_summary"));
    }

    /// A carve that ran to completion must not claim recoverable files were left
    /// behind — an incomplete flag on a complete run is as misleading as no flag
    /// on a truncated one.
    #[test]
    fn a_complete_carve_summary_is_not_marked_incomplete() {
        let carver = FileCarver::new();
        let mut data = vec![0u8; 2048];
        data[..256].copy_from_slice(&make_bmp(256));
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let summary = results
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("CarvingSummary"))
            .expect("summary record");
        assert_eq!(summary.metadata["file_cap_reached"], json!(false));
        assert_eq!(
            summary.metadata["max_carved_files"],
            json!(MAX_CARVED_FILES)
        );
        assert!(summary.metadata.get("content_incomplete").is_none());
    }

    /// Hitting the carved-file cap must mark the summary incomplete: the region
    /// still held recoverable objects the run never emitted.
    #[test]
    fn a_carve_stopped_by_the_file_cap_is_marked_incomplete() {
        let mut meta = json!({ "type": "CarvingSummary" });
        stamp_carve_incompleteness(&mut meta, true, false, false);
        assert_eq!(meta["content_incomplete"], json!(true));
        assert_eq!(meta["content_incomplete_reason"], json!("cap_reached"));
    }

    /// A cancelled carve scanned only part of the region; the corpus it emitted
    /// is not "all that was recoverable".
    #[test]
    fn a_cancelled_carve_is_marked_incomplete() {
        let mut meta = json!({ "type": "CarvingSummary" });
        stamp_carve_incompleteness(&mut meta, false, true, false);
        assert_eq!(meta["content_incomplete"], json!(true));
        assert_eq!(
            meta["content_incomplete_reason"],
            json!("unresolved_structure")
        );
    }

    /// A run that finished must not be stamped incomplete.
    #[test]
    fn a_finished_carve_is_not_stamped_incomplete() {
        let mut meta = json!({ "type": "CarvingSummary" });
        stamp_carve_incompleteness(&mut meta, false, false, false);
        assert!(meta.get("content_incomplete").is_none());
    }

    // -----------------------------------------------------------------------
    // 9. Verify small files < MIN_CARVED_SIZE (16 bytes) are filtered
    // -----------------------------------------------------------------------

    #[test]
    fn test_tiny_files_filtered() {
        let carver = FileCarver::new();

        // Build a BMP whose header claims a file size of 54 bytes (BMP minimum).
        // BMP minimum accepted by the signature is 54, and MIN_CARVED_SIZE is 16.
        // 54 >= 16, so it should NOT be filtered. Let's verify the boundary:
        // We need a BMP that the engine would produce with size < 16 to be filtered.
        // BMP min_filesize is 54, so the engine itself won't produce < 54.
        // Instead, test via the skipped_tiny counter in the summary.
        //
        // The filtering happens in process() on carved.size < 16.
        // Since BMP min is 54, this path is hard to trigger with real signatures.
        // We'll verify the filter indirectly by checking the skipped_tiny stat
        // is reported, and test that our BMP with size=54 IS included.
        let mut data = vec![0u8; 1024];
        // 64 bytes: the signature wants pixel data (at 54) inside the file.
        let bmp = make_bmp(64);
        data[..64].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        // The 54-byte BMP (>= 16 byte minimum) should be carved
        let file_entries: Vec<_> = results
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert!(
            !file_entries.is_empty(),
            "54-byte BMP should not be filtered (>= MIN_CARVED_SIZE)"
        );
    }

    #[test]
    fn test_min_carved_size_constant() {
        // Verify the constant has the expected value
        assert_eq!(MIN_CARVED_SIZE, 16);
    }

    #[test]
    fn test_max_carved_files_constant() {
        assert_eq!(MAX_CARVED_FILES, 50_000);
    }

    // -----------------------------------------------------------------------
    // 10. Overlap deduplication: two overlapping files keep only the first
    // -----------------------------------------------------------------------

    #[test]
    fn test_overlap_deduplication() {
        let carver = FileCarver::new();

        // The carving engine scans at 512-byte block boundaries, so both files
        // must start on a block boundary to be detected.
        // BMP1 at offset 0, size 1024 (extends past block 1)
        // BMP2 at offset 512, size 1024 (starts at block 1, overlaps with BMP1)
        let mut data = vec![0u8; 2048];
        let bmp1 = make_bmp(1024);
        data[..1024].copy_from_slice(&bmp1);
        let bmp2 = make_bmp(1024);
        data[512..1536].copy_from_slice(&bmp2);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let bmp_entries: Vec<_> = results
            .iter()
            .filter(|a| {
                a.artifact_type == ArtifactType::FileEntry
                    && a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("BMP")
            })
            .collect();

        // Due to overlap dedup (sorted by offset then size desc), only BMP at
        // offset 0 should survive because its range [0..1024) covers offset 512.
        assert_eq!(
            bmp_entries.len(),
            1,
            "Overlapping BMP should be deduplicated to 1, got {}",
            bmp_entries.len()
        );
        assert_eq!(bmp_entries[0].metadata["carving_offset"], json!(0));

        // Summary should record skipped_overlap > 0
        let summary = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .expect("Expected CarvingSummary");
        assert_eq!(
            summary.metadata["skipped_overlap"].as_u64().unwrap(),
            1,
            "Expected exactly 1 skipped overlap"
        );
    }

    // -----------------------------------------------------------------------
    // 11. Multiple non-overlapping files are all carved
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_non_overlapping_files() {
        let carver = FileCarver::new();

        // Place two non-overlapping BMPs with a gap between them.
        // BMP1 at offset 0, size 256
        // BMP2 at offset 512, size 256
        let mut data = vec![0u8; 1024];
        let bmp1 = make_bmp(256);
        data[..256].copy_from_slice(&bmp1);
        let bmp2 = make_bmp(256);
        data[512..768].copy_from_slice(&bmp2);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let bmp_entries: Vec<_> = results
            .iter()
            .filter(|a| {
                a.artifact_type == ArtifactType::FileEntry
                    && a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("BMP")
            })
            .collect();

        assert_eq!(
            bmp_entries.len(),
            2,
            "Expected 2 non-overlapping BMPs, got {}",
            bmp_entries.len()
        );

        let offsets: Vec<u64> = bmp_entries
            .iter()
            .map(|a| a.metadata["carving_offset"].as_u64().unwrap())
            .collect();
        assert!(offsets.contains(&0));
        assert!(offsets.contains(&512));
    }

    // -----------------------------------------------------------------------
    // 12. Carved file name includes hex offset and extension
    // -----------------------------------------------------------------------

    #[test]
    fn test_carved_file_name_format() {
        let carver = FileCarver::new();

        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(128);
        data[512..640].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let bmp_entry = results
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::FileEntry
                    && a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("BMP")
            })
            .expect("Expected a BMP FileEntry");

        let name = bmp_entry.metadata["name"].as_str().unwrap();
        // Offset 512 = 0x200, so name should be "carved_00000200.bmp"
        assert_eq!(name, "carved_00000200.bmp");
    }

    // -----------------------------------------------------------------------
    // 13. Process with FileSystem artifact type also works
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_filesystem_artifact() {
        let carver = FileCarver::new();

        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(128);
        data[..128].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::FileSystem, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        // Should still produce results (process doesn't check artifact_type filter)
        let file_entries: Vec<_> = results
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert!(!file_entries.is_empty());
    }

    // -----------------------------------------------------------------------
    // 14. PNG carving via header + IEND footer detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_carve_png_with_iend() {
        let carver = FileCarver::new();

        // Build data: 512 bytes of zeros, then a PNG, then more zeros.
        let png_size = 256;
        let png = make_png(png_size);
        let total = 2048;
        let mut data = vec![0u8; total];
        data[..png_size].copy_from_slice(&png);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let png_entries: Vec<_> = results
            .iter()
            .filter(|a| {
                a.artifact_type == ArtifactType::FileEntry
                    && a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("PNG")
            })
            .collect();
        assert!(
            !png_entries.is_empty(),
            "Expected at least one PNG FileEntry"
        );

        let png_entry = &png_entries[0];
        assert_eq!(png_entry.metadata["carved"], json!(true));
        assert_eq!(png_entry.metadata["carving_offset"], json!(0));

        // The carved PNG should have a readable data source containing the PNG header
        let carved_ds = png_entry
            .data
            .as_ref()
            .expect("PNG FileEntry needs data source");
        let mut header = [0u8; 8];
        carved_ds.read_at(0, &mut header).unwrap();
        assert_eq!(header, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    }

    // -----------------------------------------------------------------------
    // 15. CarvingSummary type_breakdown contains per-signature stats
    // -----------------------------------------------------------------------

    #[test]
    fn test_summary_type_breakdown() {
        let carver = FileCarver::new();

        let mut data = vec![0u8; 2048];
        // BMP at offset 0
        let bmp = make_bmp(128);
        data[..128].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let summary = results
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::ParsedRecord
                    && a.metadata.get("type").and_then(|v| v.as_str()) == Some("CarvingSummary")
            })
            .expect("Expected CarvingSummary");

        let breakdown = summary.metadata["type_breakdown"].as_array().unwrap();
        assert!(!breakdown.is_empty(), "type_breakdown should not be empty");

        // Find the BMP entry in the breakdown
        let bmp_stat = breakdown
            .iter()
            .find(|v| v["signature"].as_str() == Some("BMP"))
            .expect("Expected BMP in type_breakdown");
        assert!(bmp_stat["count"].as_u64().unwrap() >= 1);
        assert!(bmp_stat["total_bytes"].as_u64().unwrap() >= 128);
    }

    // -----------------------------------------------------------------------
    // 16. Summary name includes the count of recovered files
    // -----------------------------------------------------------------------

    #[test]
    fn test_summary_name_format() {
        let carver = FileCarver::new();

        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(128);
        data[..128].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let summary = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .unwrap();

        let name = summary.metadata["name"].as_str().unwrap();
        // The name should be "Carving Summary (N files recovered)"
        assert!(
            name.starts_with("Carving Summary ("),
            "Summary name should start with 'Carving Summary (', got: {}",
            name
        );
        assert!(
            name.ends_with(" files recovered)"),
            "Summary name should end with ' files recovered)', got: {}",
            name
        );
    }

    // -----------------------------------------------------------------------
    // 17. BMP at a non-zero offset is carved correctly
    // -----------------------------------------------------------------------

    #[test]
    fn test_bmp_at_non_zero_offset() {
        let carver = FileCarver::new();

        // 4096-byte image, BMP at offset 1024 (aligned to block boundary)
        let mut data = vec![0u8; 4096];
        let bmp = make_bmp(256);
        data[1024..1280].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let bmp_entry = results.iter().find(|a| {
            a.artifact_type == ArtifactType::FileEntry
                && a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("BMP")
        });

        assert!(bmp_entry.is_some(), "BMP at offset 1024 should be carved");
        let entry = bmp_entry.unwrap();
        assert_eq!(entry.metadata["carving_offset"], json!(1024));
        assert_eq!(entry.metadata["carving_size"], json!(256));
    }

    // -----------------------------------------------------------------------
    // 18. All carved FileEntry artifacts share the same case_id as the input
    // -----------------------------------------------------------------------

    #[test]
    fn test_carved_artifacts_inherit_case_id() {
        let carver = FileCarver::new();
        let case_id = Uuid::new_v4();

        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(128);
        data[..128].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = Artifact::new(case_id, ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        for result in &results {
            assert_eq!(
                result.case_id, case_id,
                "All produced artifacts should share the input case_id"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 19. All produced artifacts have unique IDs
    // -----------------------------------------------------------------------

    #[test]
    fn test_produced_artifacts_have_unique_ids() {
        let carver = FileCarver::new();

        let mut data = vec![0u8; 2048];
        let bmp1 = make_bmp(256);
        data[..256].copy_from_slice(&bmp1);
        let bmp2 = make_bmp(256);
        data[512..768].copy_from_slice(&bmp2);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let mut ids: Vec<Uuid> = results.iter().map(|a| a.id).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "All artifact IDs must be unique");
    }

    // -----------------------------------------------------------------------
    // 20. carving_offset_absolute from the input artifact's offset_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_carving_offset_absolute_with_input_offset() {
        let carver = FileCarver::new();

        // BMP at offset 512 inside an artifact positioned at 4096 in the parent
        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(128);
        data[512..640].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(
            ArtifactType::UnallocatedSpace,
            Some(ds),
            json!({"offset_bytes": 4096}),
        );
        let results = carver.process(&artifact).unwrap();

        let bmp_entry = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("Expected a FileEntry");
        assert_eq!(bmp_entry.metadata["carving_offset"], json!(512));
        assert_eq!(
            bmp_entry.metadata["carving_offset_absolute"],
            json!(4096 + 512)
        );
    }

    #[test]
    fn test_carving_offset_absolute_omitted_without_input_offset() {
        let carver = FileCarver::new();

        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(128);
        data[..128].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let bmp_entry = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("Expected a FileEntry");
        assert!(
            bmp_entry.metadata.get("carving_offset_absolute").is_none(),
            "no offset_bytes on the input => no absolute offset"
        );
    }

    // -----------------------------------------------------------------------
    // 21. Carved files are hashed (md5 + sha256 of the carved bytes)
    // -----------------------------------------------------------------------

    #[test]
    fn test_carved_file_hashes_match_content() {
        let carver = FileCarver::new();

        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(256);
        data[..256].copy_from_slice(&bmp);

        let expected = seance_core::hashing::compute_hashes(&data[..256]);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let bmp_entry = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("Expected a FileEntry");
        assert_eq!(bmp_entry.metadata["md5"].as_str().unwrap(), expected.md5);
        assert_eq!(
            bmp_entry.metadata["sha256"].as_str().unwrap(),
            expected.sha256
        );
    }

    #[test]
    fn test_digests_withheld_when_the_carved_window_reads_short() {
        // BUG-267: the window declares 256 bytes but only 64 exist. Publishing
        // md5/sha256 here would make a 64-byte prefix verify as the 256-byte
        // carved file, so the digests are withheld and the shortfall recorded.
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xABu8; 64]));
        let carved = CarvedFile {
            offset: 0,
            size: 256,
            extension: "bin".to_string(),
            signature_name: "Test".to_string(),
            validated: None,
        };
        let art = build_carved_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &src,
            &carved,
            0,
            None,
            &[],
            None,
        );

        assert!(art.metadata.get("md5").is_none(), "no digest for a prefix");
        assert!(art.metadata.get("sha256").is_none());
        assert_eq!(art.metadata["hash_skipped"], json!("short_read"));
        assert_eq!(art.metadata["bytes_hashed"], json!(64));
        assert_eq!(art.metadata["content_incomplete"], json!(true));
        assert_eq!(
            art.metadata["content_incomplete_reason"],
            json!("short_read")
        );
    }

    #[test]
    fn test_bmp_header_overrunning_eof_is_carved_to_the_readable_bytes() {
        // A BMP header near the end of unallocated space declaring far more
        // bytes than exist: the carve is clamped, so its digests still cover
        // the whole declared size.
        let carver = FileCarver::new();
        let mut data = vec![0u8; 128];
        data[0] = b'B';
        data[1] = b'M';
        data[2..6].copy_from_slice(&4096u32.to_le_bytes());
        data[10..14].copy_from_slice(&54u32.to_le_bytes());
        data[14..18].copy_from_slice(&40u32.to_le_bytes());
        let expected = seance_core::hashing::compute_hashes(&data);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let bmp_entry = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("Expected a FileEntry");
        assert_eq!(bmp_entry.metadata["size"], json!(128));
        assert!(bmp_entry.metadata.get("hash_skipped").is_none());
        assert_eq!(bmp_entry.metadata["md5"].as_str().unwrap(), expected.md5);
    }

    // -----------------------------------------------------------------------
    // 22. carving_validated persisted from the engine's validation result
    // -----------------------------------------------------------------------

    #[test]
    fn test_carving_validated_true_for_footer_confirmed_png() {
        let carver = FileCarver::new();

        // PNG end is confirmed via the IEND footer (data_check Stop + file_check)
        let png = make_png(256);
        let mut data = vec![0u8; 2048];
        data[..256].copy_from_slice(&png);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let png_entry = results
            .iter()
            .find(|a| a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("PNG"))
            .expect("Expected a PNG FileEntry");
        assert_eq!(png_entry.metadata["carving_validated"], json!(true));
    }

    #[test]
    fn test_carving_validated_absent_for_header_sized_bmp() {
        let carver = FileCarver::new();

        // BMP size comes straight from the header; no validation is performed
        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(128);
        data[..128].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let bmp_entry = results
            .iter()
            .find(|a| a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("BMP"))
            .expect("Expected a BMP FileEntry");
        assert!(
            bmp_entry.metadata.get("carving_validated").is_none(),
            "header-sized carve has no validation result"
        );
    }

    // -----------------------------------------------------------------------
    // CARVE-018: a carve that ended short of its signature's minimum size is
    // published, marked, and counted. SYNTHETIC buffer: a Clip Studio header
    // declaring 1 MiB in a 3,000-byte source.
    // -----------------------------------------------------------------------

    #[test]
    fn a_carve_below_its_minimum_is_published_marked_and_counted() {
        let carver = FileCarver::new();
        let mut data = b"CSFCHUNK".to_vec();
        data.extend_from_slice(&0x10_0000u64.to_be_bytes());
        data.resize(3000, 0x41);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let entry = results
            .iter()
            .find(|a| {
                a.metadata.get("carving_signature").and_then(|v| v.as_str())
                    == Some("Clip Studio Paint")
            })
            .expect("the truncated clip file is published");
        assert_eq!(entry.metadata["carving_below_minimum"], json!(true));
        assert_eq!(entry.metadata["carving_validated"], json!(false));
        assert_eq!(entry.metadata["carving_size"], json!(3000));
        assert!(
            entry.metadata.get("sha256").is_some(),
            "hashed over its window"
        );

        let summary = results
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("CarvingSummary"))
            .expect("summary");
        assert_eq!(summary.metadata["total_below_minimum"], json!(1));
        assert_eq!(summary.metadata["total_carved"], json!(0));
        let breakdown = summary.metadata["below_minimum_breakdown"]
            .as_array()
            .unwrap();
        assert_eq!(breakdown.len(), 1);
        assert_eq!(breakdown[0]["signature"], json!("Clip Studio Paint"));
        assert_eq!(breakdown[0]["count"], json!(1));
    }

    #[test]
    fn a_whole_carve_has_no_below_minimum_mark() {
        let carver = FileCarver::new();
        let mut data = vec![0u8; 2048];
        data[..256].copy_from_slice(&make_png(256));
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();
        let png = results
            .iter()
            .find(|a| a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("PNG"))
            .unwrap();
        assert!(png.metadata.get("carving_below_minimum").is_none());
        let summary = results
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("CarvingSummary"))
            .unwrap();
        assert_eq!(summary.metadata["total_below_minimum"], json!(0));
    }

    // -----------------------------------------------------------------------
    // 23. Cancellation stops the scan cleanly
    // -----------------------------------------------------------------------

    #[test]
    fn test_pre_cancelled_carver_returns_no_results() {
        use seance_core::orchestrator::CancellationHandle;

        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(256);
        data[..256].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));

        // Cancel *this artifact's case* (not a global shutdown): the carver must
        // still stop, proving per-case cancellation reaches the scan loop.
        let handle = CancellationHandle::new();
        handle.cancel_case(artifact.case_id);
        let carver = FileCarver::new().with_cancellation(handle);

        let results = carver.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "a per-case cancel must return cleanly with no carved files"
        );
    }

    // -----------------------------------------------------------------------
    // 24. Progress reporter receives scan progress events
    // -----------------------------------------------------------------------

    #[test]
    fn test_progress_reporter_receives_events() {
        use seance_core::orchestrator::{OrchestratorEvent, ProgressReporter};

        let (tx, mut rx) = tokio::sync::broadcast::channel(64);
        let reporter = ProgressReporter::new(tx, "plugin.recovery.file_carver");
        let carver = FileCarver::new().with_progress(reporter);

        let mut data = vec![0u8; 1024];
        let bmp = make_bmp(256);
        data[..256].copy_from_slice(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let artifact_id = artifact.id;
        carver.process(&artifact).unwrap();

        // The final report_now always fires with the full byte count
        let mut saw_final = false;
        while let Ok(event) = rx.try_recv() {
            if let OrchestratorEvent::ModuleProgress {
                module_id,
                artifact_id: reported_id,
                units_done,
                units_total,
                unit,
                ..
            } = event
            {
                assert_eq!(module_id, "plugin.recovery.file_carver");
                assert_eq!(reported_id, artifact_id);
                assert_eq!(unit, "bytes");
                assert_eq!(units_total, Some(1024));
                if units_done == 1024 {
                    saw_final = true;
                }
            }
        }
        assert!(
            saw_final,
            "expected a final ModuleProgress with all bytes scanned"
        );
    }

    // -----------------------------------------------------------------------
    // 25. A summary IS emitted when nothing is found, because the scan
    //     happened
    // -----------------------------------------------------------------------

    /// This test asserted the opposite, and the assertion was the defect.
    ///
    /// A region read in full and holding no file produced no record at all,
    /// so a case could not distinguish free space that was carved and was
    /// empty from free space nobody carved. Both read as nothing on the
    /// screen, and the second is the one an examiner has to know about.
    /// `ROADMAP` §5.4 turned that from a corner into the ordinary case: the
    /// free space of a clean volume is exactly a region that is carved and
    /// holds nothing.
    #[test]
    fn a_summary_is_emitted_when_a_scan_happened_and_found_nothing() {
        let carver = FileCarver::new();
        let garbage = vec![0xAA; 2048];
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(garbage));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = carver.process(&artifact).unwrap();

        let summaries: Vec<_> = results
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .collect();
        assert_eq!(
            summaries.len(),
            1,
            "one summary, saying the region was scanned and held nothing"
        );
        assert_eq!(summaries[0].metadata["total_carved"], 0);
        assert_eq!(summaries[0].metadata["scanned_bytes"], 2048);
    }

    // -----------------------------------------------------------------------
    // 26. UnallocatedCarver: automatic, subscribes ONLY to UnallocatedSpace
    // -----------------------------------------------------------------------

    #[test]
    fn test_unallocated_carver_metadata() {
        let carver = UnallocatedCarver::new();
        assert_eq!(carver.id(), "plugin.recovery.unallocated_carver");
        assert_eq!(carver.execution_mode(), ExecutionMode::Automatic);
        assert_eq!(carver.input_capability(), InputCapability::RandomAccess);

        let subs = carver.subscribes_to();
        // Free space and, since HUNT-124, file slack: both bounded regions.
        assert_eq!(
            subs,
            vec![ArtifactType::UnallocatedSpace, ArtifactType::SlackSpace]
        );
        assert!(
            !subs.contains(&ArtifactType::FileSystem),
            "automatic carver must NOT subscribe to whole filesystems"
        );
    }

    #[test]
    fn test_unallocated_carver_default_matches_new() {
        let carver = UnallocatedCarver::default();
        assert_eq!(carver.id(), "plugin.recovery.unallocated_carver");
    }

    // -----------------------------------------------------------------------
    // 27. UnallocatedCarver emits carved artifacts from an UnallocatedSpace input
    // -----------------------------------------------------------------------

    #[test]
    fn test_unallocated_carver_recovers_bmp_with_absolute_offset() {
        let carver = UnallocatedCarver::new();

        // BMP at offset 512 in an unallocated region positioned at 8192 in the
        // parent evidence.
        let mut data = vec![0u8; 2048];
        let bmp = make_bmp(256);
        data[512..768].copy_from_slice(&bmp);
        let expected = seance_core::hashing::compute_hashes(&data[512..768]);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(
            ArtifactType::UnallocatedSpace,
            Some(ds),
            json!({"offset_bytes": 8192}),
        );
        let results = carver.process(&artifact).unwrap();

        let bmp_entry = results
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::FileEntry
                    && a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("BMP")
            })
            .expect("UnallocatedCarver should recover the BMP");

        assert_eq!(bmp_entry.metadata["carving_offset"], json!(512));
        assert_eq!(
            bmp_entry.metadata["carving_offset_absolute"],
            json!(8192 + 512)
        );
        assert_eq!(bmp_entry.metadata["carving_size"], json!(256));
        assert_eq!(bmp_entry.metadata["md5"].as_str().unwrap(), expected.md5);
        assert_eq!(
            bmp_entry.metadata["sha256"].as_str().unwrap(),
            expected.sha256
        );
        assert_eq!(bmp_entry.parent_id, Some(artifact.id));

        // A CarvingSummary is still produced.
        assert!(results
            .iter()
            .any(|a| a.artifact_type == ArtifactType::ParsedRecord));
    }

    // -----------------------------------------------------------------------
    // 28. File-slack carving via FileCarver::carve_slack_for_file (opt-in)
    // -----------------------------------------------------------------------

    #[test]
    fn test_carve_slack_for_file_recovers_signature() {
        let carver = FileCarver::new();

        // Volume geometry: 512-byte clusters, file occupies [0, 1024) but its
        // logical size is 700, leaving slack [700, 1024). Plant a 128-byte BMP
        // at the start of the slack.
        let cluster_size = 512u64;
        let logical_size = 700u64;
        let allocation_end = 1024u64;

        let mut volume = vec![0u8; 4096];
        let bmp = make_bmp(128);
        volume[700..828].copy_from_slice(&bmp);
        let expected = seance_core::hashing::compute_hashes(&volume[700..828]);

        let vol: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(volume));
        let parent = make_artifact(ArtifactType::FileEntry, None, json!({"name": "secret.doc"}));

        let results =
            carver.carve_slack_for_file(vol, &parent, logical_size, cluster_size, allocation_end);

        let bmp_entry = results
            .iter()
            .find(|a| a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("BMP"))
            .expect("slack carving should recover the BMP");

        assert_eq!(bmp_entry.artifact_type, ArtifactType::FileEntry);
        assert_eq!(bmp_entry.metadata["carving_source"], json!("slack"));
        assert_eq!(bmp_entry.metadata["parent_file"], json!("secret.doc"));
        assert_eq!(bmp_entry.metadata["carving_offset_absolute"], json!(700));
        assert_eq!(bmp_entry.metadata["carving_offset"], json!(0)); // relative to slack start
        assert_eq!(bmp_entry.metadata["carving_size"], json!(128));
        assert_eq!(bmp_entry.metadata["md5"].as_str().unwrap(), expected.md5);
        assert_eq!(
            bmp_entry.metadata["sha256"].as_str().unwrap(),
            expected.sha256
        );
        assert_eq!(bmp_entry.parent_id, Some(parent.id));

        // The carved window reads the BMP bytes back.
        let carved_ds = bmp_entry
            .data
            .as_ref()
            .expect("slack find needs data source");
        assert_eq!(carved_ds.size(), 128);
        let mut magic = [0u8; 2];
        carved_ds.read_at(0, &mut magic).unwrap();
        assert_eq!(&magic, b"BM");
    }

    #[test]
    fn test_carve_slack_for_file_no_slack_returns_empty() {
        let carver = FileCarver::new();
        // logical size is a whole number of clusters => no slack.
        let vol: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 2048]));
        let parent = make_artifact(ArtifactType::FileEntry, None, json!({"name": "a.bin"}));
        let results = carver.carve_slack_for_file(vol, &parent, 1024, 512, 1024);
        assert!(results.is_empty(), "cluster-aligned file has no slack");
    }

    #[test]
    fn test_carve_slack_for_file_zero_filled_returns_empty() {
        let carver = FileCarver::new();
        // Slack exists geometrically but is all zeros => nothing recoverable.
        let vol: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 4096]));
        let parent = make_artifact(ArtifactType::FileEntry, None, json!({"name": "b.bin"}));
        let results = carver.carve_slack_for_file(vol, &parent, 700, 512, 1024);
        assert!(
            results.is_empty(),
            "zero-filled slack must not fabricate artifacts"
        );
    }

    // -----------------------------------------------------------------------
    // HUNT-124: file slack regions from the enumerator are carved automatically
    // and every carve says it came from slack.
    // -----------------------------------------------------------------------

    /// A 64 KiB volume holding a 1000-byte live file in the cluster at 4096,
    /// with `plant` written into its slack, turned into a slack region by the
    /// same builder the filesystem parsers use.
    fn slack_region_with(plant_at: usize, plant: &[u8]) -> Artifact {
        use seance_core::slack::{slack_window, SlackCollector, SlackLabels, SlackOwner};
        let mut vol = vec![0u8; 64 * 1024];
        vol[4096..5096].fill(b'f');
        vol[plant_at..plant_at + plant.len()].copy_from_slice(plant);
        let vol: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vol));
        let fs = make_artifact(ArtifactType::FileSystem, Some(vol.clone()), json!({}));
        let mut c = SlackCollector::new(
            SlackLabels {
                filesystem: "NTFS",
                offset_basis: "the start of this volume, not the start of the evidence",
            },
            4096,
        );
        let w = slack_window(&[(Some(4096), 4096)], 1000, 4096).unwrap();
        c.offer(
            &fs,
            &vol,
            SlackOwner {
                artifact_id: Uuid::new_v4(),
                name: "host.doc",
                path: Some("/docs/host.doc"),
                logical_size: 1000,
            },
            w,
        );
        let (out, _) = c.finish(&fs);
        out.into_iter()
            .find(|a| a.artifact_type == ArtifactType::SlackSpace)
            .expect("slack region")
    }

    #[test]
    fn the_automatic_carver_subscribes_to_slack_regions() {
        let subs = UnallocatedCarver::new().subscribes_to();
        assert!(subs.contains(&ArtifactType::SlackSpace));
        assert!(subs.contains(&ArtifactType::UnallocatedSpace));
    }

    #[test]
    fn region_carve_of_file_slack_region_stamps_carving_source_slack() {
        // Slack runs from 5096 to 8192; the first 512-byte boundary in it is
        // 5120, the first place the carver looks for a header. No file can
        // start there (files start on cluster boundaries); a header there is
        // part of a former file's content or was placed there.
        let region = slack_region_with(5120, &make_bmp(1000));
        let out = UnallocatedCarver::new().process(&region).unwrap();
        let carved: Vec<_> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(carved.len(), 1, "the BMP at the sector boundary is carved");
        let m = &carved[0].metadata;
        assert_eq!(m["carving_source"], "slack");
        assert_eq!(m["parent_file"], "host.doc");
        assert_eq!(m["parent_path"], "/docs/host.doc");
        assert_eq!(m["carving_offset"], 24, "offset within the slack region");
        assert_eq!(m["carving_offset_absolute"], 5120, "offset in the volume");
        assert_eq!(carved[0].parent_id, Some(region.id));
        let mut bm = [0u8; 2];
        carved[0]
            .data
            .as_ref()
            .unwrap()
            .read_at(0, &mut bm)
            .unwrap();
        assert_eq!(&bm, b"BM");
    }

    #[test]
    fn a_slack_region_that_holds_no_file_adds_no_per_region_summary() {
        // Tens of thousands of slack regions each with its own "0 recovered"
        // summary would bury the case; the volume's slack_space_summary is
        // the record that they were produced for carving.
        let region = slack_region_with(6000, b"not a header");
        let out = UnallocatedCarver::new().process(&region).unwrap();
        assert!(out.is_empty(), "{out:?}");
    }

    use seance_core::test_support::TruncatedSource;

    fn only_summary(out: &[Artifact]) -> &Artifact {
        let summaries: Vec<_> = out
            .iter()
            .filter(|a| {
                a.metadata.get("subtype").and_then(|v| v.as_str()) == Some("carving_summary")
            })
            .collect();
        assert_eq!(summaries.len(), 1, "exactly one carving summary: {out:?}");
        summaries[0]
    }

    #[test]
    fn a_slack_region_whose_scan_was_cancelled_says_so() {
        // Suppressing the empty per-region summary is for a clean, complete
        // scan only: a cancelled one must leave a `content_incomplete` record,
        // or "scanned, held nothing" and "stopped part-way" read the same.
        use seance_core::orchestrator::CancellationHandle;
        let region = slack_region_with(6000, b"not a header");
        let handle = CancellationHandle::new();
        handle.cancel_case(region.case_id);
        let out = UnallocatedCarver::new()
            .with_cancellation(handle)
            .process(&region)
            .unwrap();
        let s = only_summary(&out);
        assert_eq!(s.metadata["cancelled"], json!(true));
        assert_eq!(s.metadata["content_incomplete"], json!(true));
    }

    #[test]
    fn a_slack_region_that_read_short_says_so() {
        // The region declares its whole slack window but the source delivers
        // only the first 1024 bytes of it: the scan stops short and must say
        // so rather than leave no record.
        let mut region = slack_region_with(6000, b"not a header");
        let declared = region.data.as_ref().unwrap().size();
        region.data = Some(Arc::new(TruncatedSource::new(vec![0xAA; 1024], declared)));
        let out = UnallocatedCarver::new().process(&region).unwrap();
        let s = only_summary(&out);
        assert_eq!(s.metadata["cancelled"], json!(false));
        assert_eq!(s.metadata["content_incomplete"], json!(true));
        assert_eq!(s.metadata["content_incomplete_reason"], json!("short_read"));
    }

    #[test]
    fn an_unallocated_region_that_read_short_is_stamped_short_read() {
        // Same shortfall on free space: a summary was already emitted, but it
        // did not say the scan stopped before the region's end.
        let region = make_artifact(
            ArtifactType::UnallocatedSpace,
            Some(Arc::new(TruncatedSource::new(vec![0xAA; 2048], 8192))),
            json!({}),
        );
        let out = UnallocatedCarver::new().process(&region).unwrap();
        let s = only_summary(&out);
        assert_eq!(s.metadata["scanned_bytes"], json!(2048));
        assert_eq!(s.metadata["content_incomplete"], json!(true));
        assert_eq!(s.metadata["content_incomplete_reason"], json!("short_read"));
    }

    /// A BMP laid out the way the ext2 allocator writes a 20-block file in
    /// free space at 1 KiB blocks: 12 content blocks, the indirect block, 8
    /// more. Synthetic: it pins the mechanism; the real known answer is DFTT
    /// #12 (`seance_tests::carving_dftt_tests`).
    fn ext2_laid_out_bmp(first_block: u32) -> (Vec<u8>, Vec<u8>) {
        let bs = 1024usize;
        let mut bmp = make_bmp((20 * bs - 100) as u32);
        for (i, b) in bmp.iter_mut().enumerate().skip(64) {
            *b = (i % 97) as u8 | 0x40;
        }
        let mut disk = bmp[..12 * bs].to_vec();
        let own = first_block + 12;
        let mut ind = vec![0u8; bs];
        for k in 0..8u32 {
            ind[k as usize * 4..k as usize * 4 + 4].copy_from_slice(&(own + 1 + k).to_le_bytes());
        }
        disk.extend_from_slice(&ind);
        disk.extend_from_slice(&bmp[12 * bs..]);
        disk.resize(disk.len().div_ceil(bs) * bs, 0);
        (bmp, disk)
    }

    #[test]
    fn a_carve_across_an_ext2_indirect_block_hashes_and_serves_the_file_without_it() {
        let (bmp, laid_out) = ext2_laid_out_bmp(4000);
        let mut region = vec![0u8; 2048];
        region.extend_from_slice(&laid_out);
        region.extend(vec![0u8; 4096]);
        let expected = seance_core::hashing::compute_hashes(&bmp);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(region));
        let artifact = make_artifact(
            ArtifactType::UnallocatedSpace,
            Some(ds),
            json!({"offset_bytes": 1_048_576}),
        );
        let results = FileCarver::new().process(&artifact).unwrap();
        let entry = results
            .iter()
            .find(|a| a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("BMP"))
            .expect("the BMP is carved");

        assert_eq!(entry.metadata["md5"].as_str(), Some(expected.md5.as_str()));
        assert_eq!(entry.metadata["size"], json!(bmp.len()));
        assert_eq!(
            entry.metadata["carving_reconstruction"],
            json!("ext2_indirect")
        );
        assert_eq!(entry.metadata["carving_pointer_blocks_skipped"], json!(1));
        assert_eq!(entry.metadata["carving_fs_block_size"], json!(1024));
        // The run list the content resolver serves, relative to the region.
        assert_eq!(
            entry.metadata["data_runs"],
            json!([[2048, 12 * 1024], [2048 + 13 * 1024, bmp.len() - 12 * 1024]])
        );
        assert_eq!(entry.metadata["data_runs_complete"], json!(true));
        // The data source the artifact carries is the rebuilt file.
        let data = entry.data.as_ref().expect("data");
        let mut served = vec![0u8; data.size() as usize];
        data.read_at(0, &mut served).unwrap();
        assert_eq!(served, bmp);
    }

    /// A GIF laid out across an in-line ext2 IND block at 1 KiB blocks: its
    /// block walk reads the IND as image data and ends as an error, so the
    /// raw carve is not validated; the rebuild walks the file without the IND
    /// to its own trailer. Synthetic: it pins that the published
    /// `carving_validated` describes the rebuilt end, not the raw one (the
    /// real case is DFTT #12's `blogo.gif`).
    #[test]
    fn a_carve_resized_through_the_layout_is_validated_by_the_rebuilt_end() {
        let bs = 1024usize;
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0]);
        gif.extend_from_slice(&[0, 0, 0, 0xFF, 0xFF, 0xFF]);
        gif.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0]);
        gif.push(2);
        while gif.len() < 18 * bs {
            gif.push(255);
            gif.extend((0..255u32).map(|i| (i % 251) as u8 | 1));
        }
        gif.push(0);
        gif.push(0x3B);
        let nb = gif.len().div_ceil(bs);
        let first_block = 4000u32;
        let mut disk = gif[..12 * bs].to_vec();
        let own = first_block + 12;
        let mut ind = vec![0u8; bs];
        for k in 0..(nb - 12) as u32 {
            ind[k as usize * 4..k as usize * 4 + 4].copy_from_slice(&(own + 1 + k).to_le_bytes());
        }
        disk.extend_from_slice(&ind);
        disk.extend_from_slice(&gif[12 * bs..]);
        disk.resize(disk.len().div_ceil(bs) * bs, 0);
        let mut region = vec![0u8; 2048];
        region.extend_from_slice(&disk);
        region.extend(vec![0u8; 4096]);
        let expected = seance_core::hashing::compute_hashes(&gif);

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(region));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = FileCarver::new().process(&artifact).unwrap();
        let entry = results
            .iter()
            .find(|a| a.metadata.get("carving_signature").and_then(|v| v.as_str()) == Some("GIF"))
            .expect("the GIF is carved");
        assert_eq!(
            entry.metadata["carving_reconstruction"],
            json!("ext2_indirect")
        );
        assert_eq!(entry.metadata["md5"].as_str(), Some(expected.md5.as_str()));
        assert_eq!(
            entry.metadata["carving_validated"],
            json!(true),
            "the flag describes the end the rebuilt file was sized to"
        );
    }

    #[test]
    fn a_carve_with_no_pointer_block_in_line_keeps_its_plain_window() {
        let mut data = vec![0u8; 1024];
        data[..256].copy_from_slice(&make_bmp(256));
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
        let artifact = make_artifact(ArtifactType::UnallocatedSpace, Some(ds), json!({}));
        let results = FileCarver::new().process(&artifact).unwrap();
        let entry = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("carved");
        assert!(entry.metadata.get("data_runs").is_none());
        assert!(entry.metadata.get("carving_reconstruction").is_none());
    }
}
