#![forbid(unsafe_code)]
//! Pipeline modules that surface the `seance_bulk` feature-extraction algorithms.
//!
//! `seance_bulk` is pure algorithms; this crate wraps them as [`ForensicsModule`]s
//! so their results become artifacts an examiner sees. Because every output is a
//! `ParsedRecord` (or, for a carved pcap, a `FileEntry`), it flows into the
//! existing analysis, search, timeline and file-grid UIs with no bespoke wiring.
//!
//! | Module | Runs on | Emits | Mode |
//! |---|---|---|---|
//! | [`AesKeyScanner`] | memory images, raw evidence | `RecoveredKey` records | opt-in |
//! | [`BulkFeatureScanner`] | unallocated space, memory | `Feature` records + summary + histogram | automatic |
//! | [`NetworkPacketCarver`] | memory images, raw evidence | pcap `FileEntry` + summary | opt-in |
//! | [`DecodeRescan`] | file content | decoded child buffers | opt-in |
//!
//! The three opt-in modules are the ones that would otherwise add noise or cost
//! on every ingest: the AES key scanner sweeps up to 8 GiB byte-by-byte for key
//! schedules, packet carving writes a file, and decode-and-rescan multiplies the
//! pipeline's work. They are triggered per-artifact from the modules UI/API.

use seance_bulk::{
    aes, decode, features::FeatureScanner, histogram::MAX_DISTINCT_VALUES, net, FeatureHistogram,
};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    io::read_full,
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use tracing::debug;

/// Window read at once when streaming a large source.
const CHUNK: usize = 8 * 1024 * 1024;
/// Cap on total bytes any one scan will read, so a multi-gigabyte memory image
/// cannot make ingestion run unbounded. Stated in the summary when hit.
const SCAN_CAP: u64 = 8 * 1024 * 1024 * 1024;

/// Is this artifact a decoded memory image (the record `seance_memory` emits)?
fn is_memory_image(artifact: &Artifact) -> bool {
    artifact.metadata.get("subtype").and_then(|v| v.as_str()) == Some("memory_image")
}

/// The step at which an unreadable stretch is probed for its far edge. Memory
/// is acquired in pages, so a gap in a memory image starts and ends on a page
/// boundary; both edges are then refined to the byte (see [`next_readable`]).
const PROBE_GRAIN: u64 = 4096;
/// Unreadable ranges listed by offset on a summary. Past this many they are
/// still counted and their bytes still totalled; only the list stops.
const MAX_UNREADABLE_LISTED: usize = 1024;

/// What one windowed sweep covered, for the summary that reports it.
#[derive(Debug, Clone)]
struct Coverage {
    /// Bytes the sweep actually covered — the sum of every `owned` range
    /// handed to the caller. Never the limit it meant to reach.
    scanned: u64,
    /// The source is larger than [`SCAN_CAP`]; the tail was never meant to be read.
    capped: bool,
    /// Each stretch below the limit the source would not deliver (an error or
    /// a zero-length read), as `(offset, length)`, in source order; at most
    /// [`MAX_UNREADABLE_LISTED`] of them.
    unreadable: Vec<(u64, u64)>,
    /// How many unreadable stretches there were, listed or not.
    unreadable_count: u64,
    /// Their total length in bytes.
    unreadable_bytes: u64,
    /// The size the source declared.
    source_size: u64,
    /// The offset the sweep meant to reach: the source size, or the module's
    /// read cap when the source is larger.
    limit: u64,
}

impl Coverage {
    /// Some byte below the limit could not be read: the sweep is short of it
    /// for a reason that is not this build's choice.
    fn short_read(&self) -> bool {
        self.unreadable_bytes > 0
    }

    /// Stamp the coverage onto a summary's fields. An unreadable stretch is
    /// published as `content_incomplete` with the `short_read` reason and by
    /// its exact range, so the bytes the sweep never saw are not read as bytes
    /// that held nothing.
    fn stamp(&self, fields: &mut serde_json::Value) {
        fields["bytes_scanned"] = json!(self.scanned);
        fields["scan_capped"] = json!(self.capped);
        fields["short_read"] = json!(self.short_read());
        fields["source_size"] = json!(self.source_size);
        fields["unreadable_ranges"] = json!(self
            .unreadable
            .iter()
            .map(|(offset, length)| json!({ "offset": offset, "length": length }))
            .collect::<Vec<_>>());
        fields["unreadable_range_count"] = json!(self.unreadable_count);
        fields["unreadable_ranges_listed_all"] =
            json!(self.unreadable_count <= MAX_UNREADABLE_LISTED as u64);
        fields["unreadable_bytes"] = json!(self.unreadable_bytes);
        if self.short_read() {
            fields["content_incomplete"] = json!(true);
            fields["content_incomplete_reason"] =
                json!(seance_core::io::IncompleteReason::ShortRead.as_str());
            fields["content_incomplete_detail"] = json!(format!(
                "{} byte(s) in {} range(s) of the {} this scan meant to read could not be \
                 read and were not examined (listed in unreadable_ranges); the {} readable \
                 byte(s) around them were scanned",
                self.unreadable_bytes, self.unreadable_count, self.limit, self.scanned
            ));
        }
    }

    fn record_unreadable(&mut self, offset: u64, length: u64) {
        if length == 0 {
            return;
        }
        self.unreadable_count += 1;
        self.unreadable_bytes += length;
        if self.unreadable.len() < MAX_UNREADABLE_LISTED {
            self.unreadable.push((offset, length));
        }
    }
}

/// Fill `buf` from `data` at `base` and return how many leading bytes are
/// readable, exactly.
///
/// A memory layer refuses a read that touches a gap *whole* — an `Err` with no
/// count, even for the bytes before the gap — so one failed window read says
/// nothing about where the gap starts. The window is then re-read a
/// [`PROBE_GRAIN`] at a time up to the first piece that fails, and that piece
/// is bisected. On return `buf[..n]` holds bytes the source actually
/// delivered, and the byte at `base + n` (if `n < buf.len()`) would not read.
fn readable_prefix(data: &dyn DataSource, base: u64, buf: &mut [u8]) -> usize {
    let mut got = read_full(data, base, buf);
    while got < buf.len() {
        let at = base + got as u64;
        let grain_end = (at / PROBE_GRAIN + 1) * PROBE_GRAIN;
        let piece = ((grain_end - at) as usize).min(buf.len() - got);
        let k = read_full(data, at, &mut buf[got..got + piece]);
        if k == piece {
            got += piece;
            continue;
        }
        // A partial count is bytes delivered; the rest of the piece is bisected
        // for the longest run that reads whole.
        got += k;
        let at = base + got as u64;
        let (mut ok, mut bad) = (0usize, piece - k);
        while bad - ok > 1 {
            let mid = ok + (bad - ok) / 2;
            if read_full(data, at, &mut buf[got..got + mid]) == mid {
                ok = mid;
            } else {
                bad = mid;
            }
        }
        // A failed probe may have scribbled on the buffer; re-read what stands.
        if ok > 0 {
            got += read_full(data, at, &mut buf[got..got + ok]);
        }
        return got;
    }
    got
}

/// The first offset at or after `gap_start` from which the source reads
/// again, or `limit` if none does below it. `gap_start` is known unreadable.
///
/// Probes one byte on each [`PROBE_GRAIN`] boundary (and the last byte below
/// `limit`), then bisects the grain before the first probe that reads for the
/// byte where the readable run begins. The only thing this can miss is a
/// readable run shorter than one grain that lies wholly between two
/// unreadable probes; such bytes are counted as unreadable, never as scanned.
fn next_readable(data: &dyn DataSource, gap_start: u64, limit: u64) -> u64 {
    let mut probe = [0u8; 1];
    let mut scratch = vec![0u8; PROBE_GRAIN as usize + 1];
    let reads_whole = |from: u64, to_inclusive: u64, scratch: &mut [u8]| {
        let len = (to_inclusive - from + 1) as usize;
        read_full(data, from, &mut scratch[..len]) == len
    };
    let mut lo = gap_start;
    loop {
        let q = ((lo / PROBE_GRAIN + 1) * PROBE_GRAIN).min(limit.saturating_sub(1));
        if q <= lo {
            return limit;
        }
        if read_full(data, q, &mut probe) == 1 {
            // `lo` fails, `q` reads: the smallest `s` in (lo, q] from which
            // every byte up to `q` reads.
            let (mut bad, mut good) = (lo, q);
            while good - bad > 1 {
                let mid = bad + (good - bad) / 2;
                if reads_whole(mid, q, &mut scratch) {
                    good = mid;
                } else {
                    bad = mid;
                }
            }
            return good;
        }
        lo = q;
    }
}

/// Read `data` in overlapping windows, calling `f(absolute_offset, &window, owned)`.
///
/// Consecutive windows overlap by `overlap` bytes on each side, and `owned` is
/// the range of *start* offsets within the window that this window is
/// responsible for. Every readable start offset in the source falls in exactly
/// one window's `owned` range, and a match starting there has at least
/// `overlap` bytes of context after it (and before it, unless the source or a
/// readable run begins there), so a match no longer than `overlap` is seen
/// whole by its owning window. A caller must report only hits whose start is
/// in `owned`: a hit outside it is either a duplicate of the neighbouring
/// window's or — the reason the rule exists — a match the window edge cut
/// short, which would otherwise surface as a shorter value at a wrong offset.
///
/// A stretch the source will not deliver (a gap in a memory image, a bad
/// sector) is recorded by its exact range and stepped over; the sweep resumes
/// on its far side. A window never spans a gap, so bytes either side of one
/// are never presented as contiguous. Returns what the sweep covered — the
/// bytes it actually read, never the limit it meant to reach.
fn for_each_window(
    data: &Arc<dyn DataSource>,
    overlap: usize,
    mut f: impl FnMut(u64, &[u8], Range<usize>),
) -> Coverage {
    let size = data.size();
    let limit = size.min(SCAN_CAP);
    let mut cov = Coverage {
        scanned: 0,
        capped: size > SCAN_CAP,
        unreadable: Vec::new(),
        unreadable_count: 0,
        unreadable_bytes: 0,
        source_size: size,
        limit,
    };
    let mut owned_start: u64 = 0;
    // No window reaches back past this: the source's start, or the far edge
    // of the last gap — bytes across a gap are never context.
    let mut floor: u64 = 0;
    let mut buf = vec![0u8; CHUNK + 2 * overlap];
    while owned_start < limit {
        let base = owned_start.saturating_sub(overlap as u64).max(floor);
        let want = ((limit - base) as usize).min(buf.len());
        let got = readable_prefix(&**data, base, &mut buf[..want]);
        let lead = (owned_start - base) as usize;
        if got < lead {
            // The lead was read once already and now will not read; retry
            // this window without it rather than stall.
            floor = owned_start;
            continue;
        }
        let reached_end = base + got as u64 >= limit;
        let cut = got < want;
        // A window that ends at the limit or at a gap has nothing after it to
        // share, so it owns everything it holds.
        let owned_end = if reached_end || cut {
            got
        } else {
            got.saturating_sub(overlap)
        };
        if owned_end > lead {
            f(base, &buf[..got], lead..owned_end);
            cov.scanned += (owned_end - lead) as u64;
            owned_start = base + owned_end as u64;
        }
        if reached_end {
            break;
        }
        if cut {
            let gap_start = base + got as u64;
            let resume = next_readable(&**data, gap_start, limit);
            cov.record_unreadable(gap_start, resume - gap_start);
            owned_start = resume;
            floor = resume;
        }
    }
    cov
}

/// Read every readable byte of `data` below `limit`, as separate runs.
///
/// Each run is `(offset, bytes)`; a stretch the source will not deliver is
/// recorded on the returned [`Coverage`] by its exact range and stepped over
/// (HUNT-228), exactly as [`for_each_window`] does. Runs are never joined, so
/// bytes either side of a gap are never presented as contiguous. For a
/// consumer that needs whole buffers rather than windows: decode-and-rescan.
fn readable_runs(data: &dyn DataSource, limit: u64) -> (Vec<(u64, Vec<u8>)>, Coverage) {
    let size = data.size();
    let mut cov = Coverage {
        scanned: 0,
        capped: size > limit,
        unreadable: Vec::new(),
        unreadable_count: 0,
        unreadable_bytes: 0,
        source_size: size,
        limit,
    };
    let mut runs = Vec::new();
    let mut at = 0u64;
    while at < limit {
        let mut buf = vec![0u8; (limit - at) as usize];
        let got = readable_prefix(data, at, &mut buf);
        if got > 0 {
            buf.truncate(got);
            runs.push((at, buf));
            cov.scanned += got as u64;
        }
        let gap_start = at + got as u64;
        if gap_start >= limit {
            break;
        }
        let resume = next_readable(data, gap_start, limit);
        cov.record_unreadable(gap_start, resume - gap_start);
        at = resume;
    }
    (runs, cov)
}

// ---------------------------------------------------------------------------
// AES key recovery
// ---------------------------------------------------------------------------

/// Recovers AES keys by their key schedules from a decoded memory image OR a raw
/// capture, feeding the decryption plugins a key when no password is known.
///
/// **Opt-in.** A byte-by-byte key-schedule sweep over up to 8 GiB is worth its
/// cost when an examiner wants keys, but running it automatically on every raw
/// disk would add large, usually-pointless latency to the ingest hot path. So it
/// does not run on its own; it is triggered per artifact. It accepts both the
/// decoded memory-image record (the usual target) and raw evidence directly — a
/// raw RAM/hibernation/swap capture whose OS profile the memory module cannot
/// decode is still scannable, because key schedules are found in the raw bytes.
pub struct AesKeyScanner;

impl ForensicsModule for AesKeyScanner {
    fn id(&self) -> &str {
        "plugin.bulk.aes_keys"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::ParsedRecord, ArtifactType::RawEvidence]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::OptIn
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // A ParsedRecord is only relevant when it is a decoded memory image;
        // RawEvidence is scanned directly. Anything else is not ours.
        if artifact.artifact_type == ArtifactType::ParsedRecord && !is_memory_image(artifact) {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        // Overlap must cover the largest schedule so a key at a window boundary
        // is not split.
        let coverage = for_each_window(
            data,
            aes::AesBits::Aes256.schedule_len(),
            |base, win, owned| {
                for key in aes::scan_for_keys(win, 1) {
                    if !owned.contains(&key.offset) {
                        continue;
                    }
                    let abs = base + key.offset as u64;
                    out.push(
                    Artifact::new(
                        artifact.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        json!({
                            "type": "RecoveredKey",
                            "subtype": "aes_key",
                            "algorithm": format!("AES-{}", key.bits.bits()),
                            "bits": key.bits.bits(),
                            "device_offset": abs,
                            "key_hex": hex(&key.key),
                            "evidence_grade": "scanned",
                            "note": "Key schedule verified in memory. Confirming it against a \
                                     volume header is the decryptor's job; only then is it Validated.",
                        }),
                    )
                    .with_parent(artifact.id),
                );
                }
            },
        );
        debug!(
            "aes_keys: scanned {} bytes, {} keys",
            coverage.scanned,
            out.len()
        );
        if !out.is_empty() || coverage.capped || coverage.short_read() {
            let mut fields = json!({ "keys_found": out.len() });
            coverage.stamp(&mut fields);
            out.push(summary(artifact, "RecoveredKeySummary", fields));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Feature selectors over unallocated space and memory
// ---------------------------------------------------------------------------

/// Cap on individual feature records emitted per artifact, so scanning a large
/// unallocated region cannot flood the case; the summary states the true total.
const MAX_FEATURE_RECORDS: usize = 20_000;
/// How many most-common entries the `FeatureHistogramSummary` carries. The
/// record states the full distinct count beside them, so a table longer than
/// this is disclosed as truncated rather than read as complete.
const HISTOGRAM_TOP_N: usize = 100;

/// Sweeps unallocated space and memory for selectors (email, URL, card, SSN,
/// IBAN, VIN, GPS, …) that file-oriented parsers never reach, each with the
/// device offset it was found at.
pub struct BulkFeatureScanner;

impl ForensicsModule for BulkFeatureScanner {
    fn id(&self) -> &str {
        "plugin.bulk.features"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::UnallocatedSpace, ArtifactType::ParsedRecord]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if artifact.artifact_type == ArtifactType::ParsedRecord && !is_memory_image(artifact) {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let scanner = FeatureScanner::new();
        let mut out = Vec::new();
        // Every hit goes into the histogram as it streams past, so the counts
        // are complete even once the per-occurrence records are capped; the
        // histogram bounds its own memory by distinct value.
        let mut histogram = FeatureHistogram::new();
        // Overlap covers the longest plausible selector (a URL) without splitting.
        let coverage = for_each_window(data, 1024, |base, win, owned| {
            for hit in scanner.scan(win) {
                if !owned.contains(&hit.offset) {
                    continue;
                }
                let abs = base + hit.offset as u64;
                histogram.record(&hit);
                if out.len() < MAX_FEATURE_RECORDS {
                    out.push(
                        Artifact::new(
                            artifact.case_id,
                            ArtifactType::ParsedRecord,
                            None,
                            json!({
                                "type": "Feature",
                                "subtype": hit.kind,
                                "kind": hit.kind,
                                "value": hit.value,
                                "device_offset": abs,
                            }),
                        )
                        .with_parent(artifact.id),
                    );
                }
            }
        });
        let total = histogram.total_hits();
        debug!("features: scanned {} bytes, {total} hits", coverage.scanned);
        if total > 0 || coverage.capped || coverage.short_read() {
            let by_kind = histogram.by_kind();
            let mut fields = json!({
                "features_found": total,
                "records_emitted": out.len(),
                "by_kind": by_kind
                    .iter()
                    .map(|(kind, t)| (*kind, t.hits))
                    .collect::<BTreeMap<_, _>>(),
                "records_capped": total > MAX_FEATURE_RECORDS as u64,
            });
            coverage.stamp(&mut fields);
            out.push(summary(artifact, "FeatureSummary", fields));
        }
        if total > 0 {
            out.push(histogram_summary(artifact, &histogram, &coverage));
        }
        Ok(out)
    }
}

/// The one `FeatureHistogramSummary` a scan publishes: which values recurred
/// and how often, most-common first, with every ceiling it ran into stated on
/// the record itself.
fn histogram_summary(
    artifact: &Artifact,
    histogram: &FeatureHistogram,
    coverage: &Coverage,
) -> Artifact {
    let top = histogram.top(HISTOGRAM_TOP_N);
    let distinct = histogram.distinct_values();
    let note = if histogram.is_capped() {
        format!(
            "Capped: the histogram tracks at most {MAX_DISTINCT_VALUES} distinct values, and \
             {} hits for values beyond that were not tallied. Counts for the tracked values \
             are exact; the distinct-value total is a floor, not the number the scan contained.",
            histogram.hits_dropped()
        )
    } else {
        format!(
            "Every distinct value the scan found is tracked ({distinct} of at most \
             {MAX_DISTINCT_VALUES}); counts are exact."
        )
    };
    let mut fields = json!({
            "total_hits": histogram.total_hits(),
            "distinct_values": distinct,
            "hits_dropped": histogram.hits_dropped(),
            "capped": histogram.is_capped(),
            "max_distinct_values": MAX_DISTINCT_VALUES,
            "top_n": HISTOGRAM_TOP_N,
            "top_omitted": distinct.saturating_sub(top.len()),
            "top": top
                .iter()
                .map(|e| json!({ "kind": e.kind, "value": e.value, "count": e.count }))
                .collect::<Vec<_>>(),
            "by_kind": histogram
                .by_kind()
                .iter()
                .map(|(kind, t)| {
                    (
                        *kind,
                        json!({ "hits": t.hits, "distinct_values": t.distinct_values }),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            "note": note,
    });
    coverage.stamp(&mut fields);
    summary(artifact, "FeatureHistogramSummary", fields)
}

// ---------------------------------------------------------------------------
// Network packet carving to pcap
// ---------------------------------------------------------------------------

/// Carves IP packets from a memory image (or raw evidence) and reassembles a
/// pcap — recovering historical traffic the live memory `netscan` cannot see.
pub struct NetworkPacketCarver;

impl ForensicsModule for NetworkPacketCarver {
    fn id(&self) -> &str {
        "plugin.bulk.net_carve"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::ParsedRecord, ArtifactType::RawEvidence]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::OptIn
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if artifact.artifact_type == ArtifactType::ParsedRecord && !is_memory_image(artifact) {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        // A packet's total length fits in 16 bits, so a 64 KiB overlap guarantees
        // a packet whose header lands near a window boundary is carved whole;
        // the packets are collected across windows and the pcap assembled once
        // at the end.
        let mut packets: Vec<net::CarvedPacket> = Vec::new();
        let mut packet_bytes: Vec<Vec<u8>> = Vec::new();
        let coverage = for_each_window(data, 64 * 1024, |base, win, owned| {
            for p in net::carve_packets(win) {
                if !owned.contains(&p.offset) {
                    continue;
                }
                let abs = base + p.offset as u64;
                let end = (p.offset + p.total_len).min(win.len());
                packet_bytes.push(win[p.offset..end].to_vec());
                packets.push(net::CarvedPacket {
                    offset: abs as usize,
                    ..p
                });
            }
        });
        if packets.is_empty() {
            // No packets in bytes that were all read is a result; no packets in
            // a sweep that stopped short or capped is not, so it is said.
            if coverage.short_read() || coverage.capped {
                let mut fields = json!({ "packet_count": 0, "endpoints": [] });
                coverage.stamp(&mut fields);
                return Ok(vec![summary(artifact, "NetworkCarveSummary", fields)]);
            }
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        // Assemble one valid pcap from the unique packets. A contiguous buffer of
        // all packet bytes lets `write_pcap` copy each at its buffer offset; the
        // CarvedPacket offsets are rewritten to point into that buffer.
        let mut flat = Vec::new();
        let mut flat_pkts = Vec::new();
        for (p, bytes) in packets.iter().zip(&packet_bytes) {
            flat_pkts.push(net::CarvedPacket {
                offset: flat.len(),
                ..p.clone()
            });
            flat.extend_from_slice(bytes);
        }
        let pcap_bytes = net::write_pcap(&flat_pkts, &flat);
        // The reassembled pcap as a FileEntry, so it appears in the file grid and
        // can be exported and re-carved.
        let pcap_src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(pcap_bytes.clone()));
        out.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::FileEntry,
                Some(pcap_src),
                json!({
                    "type": "CarvedPcap",
                    "name": "carved_packets.pcap",
                    "subtype": "pcap",
                    "packet_count": packets.len(),
                    "byte_size": pcap_bytes.len(),
                    "note": "Packets carved from memory/evidence. Capture timestamps are unknown \
                             and recorded as zero.",
                }),
            )
            .with_parent(artifact.id),
        );
        let mut fields = json!({
            "packet_count": packets.len(),
            "endpoints": packets
                .iter()
                .take(200)
                .map(|p| json!({"src": p.src_str(), "dst": p.dst_str(), "proto": p.protocol, "offset": p.offset}))
                .collect::<Vec<_>>(),
        });
        coverage.stamp(&mut fields);
        out.push(summary(artifact, "NetworkCarveSummary", fields));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Decode-and-rescan substrate
// ---------------------------------------------------------------------------

/// Lifts base64/gzip/xor-obfuscated spans out of file content into child
/// buffers, which the orchestrator re-queues through the whole parser/carver set.
///
/// base64 and gzip announce themselves, so their spans are decoded wherever they
/// appear. XOR does not: every key "succeeds" on every byte, so a guessed key
/// would bury the case under a buffer of noise per file. A whole-buffer XOR child
/// is therefore only produced for a key the bytes themselves prove — see
/// [`detect_xor_keys`].
pub struct DecodeRescan;

/// Plaintext signatures used as proof that a buffer is single-byte XOR obfuscated.
///
/// Each is at least six bytes, so a chance match under a wrong key is about one
/// in 2^40 per position — negligible against the ~2^26 positions of a capped
/// buffer. A shorter magic would make false keys routine, and a false key costs a
/// whole-buffer child of noise.
const XOR_WITNESSES: &[(&str, &[u8])] = &[
    ("PE/DOS header", b"MZ\x90\x00\x03\x00"),
    ("PE DOS stub", b"This program cannot be run in DOS mode"),
    ("ZIP local header", b"PK\x03\x04\x14\x00"),
    ("PDF header", b"%PDF-1."),
    ("PNG header", b"\x89PNG\r\n\x1a\n"),
    ("GIF header", b"GIF89a"),
    ("SQLite header", b"SQLite format 3\x00"),
    ("OLE2 header", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("ELF32 header", b"\x7fELF\x01\x01"),
    ("ELF64 header", b"\x7fELF\x02\x01"),
    ("HTTP URL", b"http://"),
];

/// Recover the single-byte XOR keys a buffer proves it was obfuscated with.
///
/// XOR preserves the byte-to-byte deltas of whatever it hides, so one pass over
/// the buffer comparing each adjacent pair's delta against the witnesses' own
/// first delta finds candidates for every key at once; a candidate is confirmed
/// by XORing the full witness back out. Returns each key with the witness that
/// proved it, so the child artifact can carry its justification.
///
/// A key of zero is rejected: that is the buffer already in the clear, which the
/// other decoders and the parsers handle. That rejection is also what stops an
/// emitted child from being XORed back and forth forever when the orchestrator
/// re-queues it.
fn detect_xor_keys(buf: &[u8]) -> Vec<(u8, &'static str)> {
    // Pre-filter: a witness can only begin here if the first delta is one of
    // theirs, which rejects almost every position with a single array lookup and
    // keeps the sweep to one cheap pass over a buffer up to MAX_INPUT.
    let mut delta_seen = [false; 256];
    for (_, w) in XOR_WITNESSES {
        delta_seen[(w[0] ^ w[1]) as usize] = true;
    }
    let mut found: Vec<(u8, &'static str)> = Vec::new();
    for (pos, pair) in buf.windows(2).enumerate() {
        if !delta_seen[(pair[0] ^ pair[1]) as usize] {
            continue;
        }
        for (label, w) in XOR_WITNESSES {
            if pos + w.len() > buf.len() {
                continue;
            }
            let key = pair[0] ^ w[0];
            if key == 0 || found.iter().any(|(k, _)| *k == key) {
                continue;
            }
            if w.iter().zip(&buf[pos..]).all(|(b, c)| (c ^ key) == *b) {
                found.push((key, *label));
            }
        }
    }
    found
}

impl ForensicsModule for DecodeRescan {
    fn id(&self) -> &str {
        "plugin.bulk.decode_rescan"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileContent, ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::OptIn
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        // Bound the recursion HERE: the orchestrator re-queues our children back
        // into this module with no depth tracking, so a nested/compounding
        // encoding (a gzip whose output is more gzip, …) would never terminate.
        // Each child carries its generation; stop when it reaches the cap.
        const MAX_DECODE_DEPTH: u64 = 8;
        const MAX_CHILDREN: usize = 256;
        // Cap on whole-buffer XOR children: each is a full copy of the input, so
        // the memory cost is per key. Two proven keys in one buffer is already
        // unusual; any beyond the cap are disclosed as dropped, never dropped
        // silently.
        const MAX_XOR_KEYS: usize = 2;
        let generation = artifact
            .metadata
            .get("decode_generation")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if generation >= MAX_DECODE_DEPTH {
            return Ok(Vec::new());
        }

        // Bounded: decode-and-rescan reads the whole buffer, so cap it. A source
        // larger than this has its tail left unscanned; that is disclosed in the
        // summary below rather than passing silently as "nothing more was there".
        const MAX_INPUT: u64 = 64 * 1024 * 1024;
        let input_capped = data.size() > MAX_INPUT;
        // Every readable run below the cap, each decoded on its own: a bad
        // sector or a gap is named on the summary and stepped over, never
        // read as the end of the buffer (HUNT-228), and no encoded span is
        // spliced together across one.
        let (runs, coverage) = readable_runs(&**data, data.size().min(MAX_INPUT));

        // XOR children come first so the MAX_CHILDREN cap can never drop a proven
        // deobfuscation in favour of the 256th base64 span. Each pairs its Decoded
        // with the key and witness that justify it; the span decoders need no such
        // justification, because their encodings are self-announcing. Offsets
        // are made absolute (the run's own offset added) before anything is named.
        let mut decoded = Vec::new();
        let mut xor_keys_found = 0usize;
        let mut xor_emitted = 0usize;
        for (run_base, run) in &runs {
            let keys = detect_xor_keys(run);
            xor_keys_found += keys.len();
            for (key, witness) in keys {
                if xor_emitted >= MAX_XOR_KEYS {
                    break;
                }
                if let Some(mut d) = decode::decode_xor(run, key) {
                    d.offset += *run_base as usize;
                    decoded.push((d, Some((key, witness, *run_base))));
                    xor_emitted += 1;
                }
            }
        }
        // Spans the decoder's ceilings left undecoded are found and not emitted;
        // they are counted into `children_found` below so the summary says so.
        let mut base64_not_decoded = 0usize;
        let mut base64_capped = false;
        for (run_base, run) in &runs {
            let base64 = decode::decode_base64_spans(run, 24);
            base64_not_decoded += base64.spans_not_decoded;
            base64_capped |= base64.cap_reached;
            for mut d in base64.decoded {
                d.offset += *run_base as usize;
                decoded.push((d, None));
            }
        }
        for (run_base, run) in &runs {
            for mut d in decode::decode_gzip_members(run) {
                d.offset += *run_base as usize;
                decoded.push((d, None));
            }
        }
        // A key proved but not materialised (over the cap, or a buffer too short
        // for the decoder) is still something the buffer held, so it counts as
        // found and the cap arithmetic below discloses it.
        let decoded_found = decoded.len() + (xor_keys_found - xor_emitted) + base64_not_decoded;
        let mut out = Vec::new();
        for (d, xor) in decoded.into_iter().take(MAX_CHILDREN) {
            let child: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(d.data.clone()));
            let mut meta = json!({
                "type": "DecodedBuffer",
                "name": format!("decoded_{}_{}", d.method, d.offset),
                "decode_method": d.method,
                "parent_offset": d.offset,
                "byte_size": d.data.len(),
                // The child's generation, so a re-queue into this module stops at
                // MAX_DECODE_DEPTH rather than recursing forever.
                "decode_generation": generation + 1,
            });
            // A decoder that hit its output cap produced a partial buffer; say so
            // rather than let a downstream parser treat it as a whole file.
            if d.truncated {
                meta["content_incomplete"] = json!(true);
                meta["truncated_reason"] = json!("decode output cap reached");
            }
            // Record the key and the plaintext that proved it, so the examiner can
            // check the deobfuscation rather than take the child on trust. The name
            // carries the key too: two keys must not produce two children whose
            // names both say "offset 0".
            if let Some((key, witness, run_base)) = xor {
                // A run past a gap is a separate buffer; its offset keeps two
                // children under one key apart.
                meta["name"] = if run_base == 0 {
                    json!(format!("decoded_xor_{key:02x}"))
                } else {
                    json!(format!("decoded_xor_{key:02x}_{run_base}"))
                };
                meta["xor_key"] = json!(format!("0x{key:02x}"));
                meta["xor_evidence"] = json!(witness);
            }
            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::FileContent,
                    Some(child),
                    meta,
                )
                .with_parent(artifact.id),
            );
        }
        // Disclose either cap: an input truncated to MAX_INPUT, or more decodable
        // spans than we emitted. Silence here would read as "the whole buffer was
        // scanned and these are all the children", which would not be true.
        let children_dropped = decoded_found.saturating_sub(out.len());
        if input_capped || children_dropped > 0 || base64_capped || coverage.short_read() {
            let mut fields = json!({
                    "children_found": decoded_found,
                    "children_emitted": out.len(),
                    "children_dropped": children_dropped,
                    "input_capped": input_capped,
                    "xor_keys_found": xor_keys_found,
                    "xor_keys_emitted": xor_emitted,
                    // The base64 decoder's own ceilings (span count, total
                    // decoded bytes): spans past them were found, not decoded.
                    "base64_decode_capped": base64_capped,
                    "base64_spans_not_decoded": base64_not_decoded,
                    "base64_span_cap": decode::MAX_BASE64_SPANS,
                    "base64_output_cap": decode::MAX_BASE64_TOTAL_OUT,
            });
            // bytes_scanned, source_size and — on a short read — the
            // content_incomplete/short_read pair with every unreadable range.
            coverage.stamp(&mut fields);
            out.push(summary(artifact, "DecodeRescanSummary", fields));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Build a summary ParsedRecord of the given type carrying `fields`.
fn summary(parent: &Artifact, ty: &str, fields: serde_json::Value) -> Artifact {
    let mut m = json!({ "type": ty, "subtype": "summary" });
    if let (Some(obj), Some(src)) = (m.as_object_mut(), fields.as_object()) {
        for (k, v) in src {
            obj.insert(k.clone(), v.clone());
        }
    }
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, m).with_parent(parent.id)
}

/// Lower-case hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests;
