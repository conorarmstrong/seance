//! Prior versions of files, from a shadow copy's `$MFT` (HUNT-154, option B).
//!
//! # What this does
//!
//! Each rebuilt shadow copy is a whole NTFS volume as it stood when the
//! snapshot was taken. Walking every one of them as a file system (option A)
//! costs a full ingest per snapshot. This does the part an examiner asks
//! first — *what did this volume hold then that it does not hold now?* — at a
//! fraction of that: it parses the snapshot's `$MFT` and the live volume's with
//! the MFT module's own parser ([`seance_plugin_mft::volume_mft`]), and
//! publishes only the snapshot records that **differ** from the live record at
//! the same record number.
//!
//! # What a published record is
//!
//! A `ParsedRecord` of type `VssPriorVersion`, parented to its `VssSnapshot`
//! record, never a `FileEntry`: a `FileEntry` joins the file tree and the
//! timeline as a file of the live volume, and a prior version read as the live
//! file is the most dangerous mistake this module could invite. Its content
//! (`data_runs`, or `resident_data_b64`) is the **snapshot** record's, and the
//! runs are offsets in the snapshot volume — the content resolver applies the
//! parent `VssSnapshot` step first, which rebuilds the snapshot stream, so the
//! runs resolve against the snapshot and never against the live volume.
//!
//! # What it does not do
//!
//! It does not walk the snapshot's directories, `$I30`, `$UsnJrnl`,
//! `$LogFile` or unallocated space, and publishes nothing for a record that is
//! identical in the snapshot and the live volume — the live `FileEntry`
//! already shows it. The full per-snapshot walk stays open as an opt-in.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource, RunListDataSource, WindowSource};
use seance_core::io::IncompleteReason;
use seance_plugin_mft::volume_mft::{locate_volume_mft, parse_bare_mft_each, runs_from_metadata};
use serde_json::{json, Map, Value};
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::Arc;

/// Records of one `$MFT` compared (live or snapshot): 1,048,576, i.e. a
/// 1 GiB `$MFT` at 1 KiB records. Records past it are not compared, and the
/// snapshot record says so.
pub const MAX_MFT_RECORDS_COMPARED: u64 = 1 << 20;

/// Prior versions published per snapshot. Past it the snapshot record says
/// how many differing records were not published.
pub const MAX_PRIOR_VERSIONS_PER_SNAPSHOT: usize = 10_000;

/// The fields compared, in the order a difference list reports them.
///
/// `in_use` is derived from the MFT module's `deleted` flag; `parent_path` is
/// the directory path the MFT module reconstructed within the same `$MFT`, so
/// a renamed or moved parent shows as a difference too.
pub const COMPARED_FIELDS: [&str; 13] = [
    "sequence_number",
    "in_use",
    "name",
    "parent_path",
    "size",
    "created",
    "modified",
    "mft_modified",
    "accessed",
    "fn_created",
    "fn_modified",
    "fn_mft_modified",
    "fn_accessed",
];

/// One side's value for a compared field.
fn field(md: &Map<String, Value>, key: &str) -> Value {
    if key == "in_use" {
        return json!(md.get("deleted").and_then(Value::as_bool) != Some(true));
    }
    md.get(key).cloned().unwrap_or(Value::Null)
}

/// The fields of a snapshot record that differ from the live record at the
/// same record number, each as `{field, live, snapshot}`. A record the live
/// `$MFT` does not publish at all is one difference, field `record`.
pub fn differences(live: Option<&Map<String, Value>>, snapshot: &Map<String, Value>) -> Vec<Value> {
    let Some(live) = live else {
        return vec![json!({
            "field": "record",
            "live": Value::Null,
            "snapshot": "present",
        })];
    };
    COMPARED_FIELDS
        .iter()
        .filter_map(|&k| {
            let (l, s) = (field(live, k), field(snapshot, k));
            (l != s).then(|| json!({ "field": k, "live": l, "snapshot": s }))
        })
        .collect()
}

/// The live volume's `$MFT`, keyed by record number, and how much of it was
/// read.
///
/// Each record is kept as the JSON of only the fields a comparison or a
/// published record reads from the live side ([`live_keys`]), in one string,
/// not as the full metadata document the MFT module builds. The full documents
/// for a volume of 147,712 records were 3.9 GB before a snapshot had been
/// looked at, and a comparison holds the live side for the whole of every
/// snapshot's walk (HUNT-125).
pub struct ParsedMft {
    records: HashMap<u64, Box<str>>,
    /// Record slots in the `$MFT` (its size over the record size).
    pub record_slots: u64,
    /// True when [`MAX_MFT_RECORDS_COMPARED`] cut the parse short.
    pub capped: bool,
    /// False when the `$MFT`'s own run list is known to be short.
    pub runs_complete: bool,
}

impl ParsedMft {
    /// The live record at `number`, reduced to the fields read from it.
    pub fn record(&self, number: u64) -> Option<Map<String, Value>> {
        let json = self.records.get(&number)?;
        match serde_json::from_str::<Value>(json).ok()? {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    /// How many live records are held.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when no live record is held.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// The keys of a live record that anything reads: the compared fields, the
/// `deleted` flag `in_use` is derived from, and the path a published record
/// quotes.
fn live_keys() -> impl Iterator<Item = &'static str> {
    COMPARED_FIELDS.iter().copied().chain(["deleted", "path"])
}

/// What walking one `$MFT` learned about its extent.
struct MftExtent {
    record_slots: u64,
    capped: bool,
    runs_complete: bool,
}

/// Locate the `$MFT` of the NTFS volume `volume` serves and call `each` with
/// every base record, in table order, as it is parsed.
fn walk_volume_mft(
    volume: &Arc<dyn DataSource>,
    each: &mut dyn FnMut(u64, Map<String, Value>),
) -> Result<MftExtent, String> {
    let loc = locate_volume_mft(volume)
        .ok_or_else(|| "no NTFS boot sector, or its $MFT record 0 did not parse".to_string())?;
    let record_slots = loc.size / loc.record_size;
    let capped = record_slots > MAX_MFT_RECORDS_COMPARED;
    let window = loc.size.min(MAX_MFT_RECORDS_COMPARED * loc.record_size);
    let mft: Arc<dyn DataSource> = Arc::new(WindowSource::new(
        Arc::new(RunListDataSource::with_logical_size(
            volume.clone(),
            loc.runs.clone(),
            loc.size,
        )),
        0,
        window,
    ));
    parse_bare_mft_each(mft, loc.cluster_size, loc.record_size, &mut |md| {
        if let Some(n) = md.get("record_number").and_then(Value::as_u64) {
            each(n, md);
        }
    })?;
    Ok(MftExtent {
        record_slots,
        capped,
        runs_complete: loc.runs_complete,
    })
}

/// Locate and parse the `$MFT` of the NTFS volume `volume` serves, keeping the
/// compared fields of each record. The first record with a given number wins.
pub fn read_volume_mft(volume: &Arc<dyn DataSource>) -> Result<ParsedMft, String> {
    let mut records: HashMap<u64, Box<str>> = HashMap::new();
    let extent = walk_volume_mft(volume, &mut |n, md| {
        records.entry(n).or_insert_with(|| {
            let mut kept = Map::new();
            for k in live_keys() {
                if let Some(v) = md.get(k) {
                    kept.insert(k.to_string(), v.clone());
                }
            }
            Value::Object(kept).to_string().into_boxed_str()
        });
    })?;
    Ok(ParsedMft {
        records,
        record_slots: extent.record_slots,
        capped: extent.capped,
        runs_complete: extent.runs_complete,
    })
}

/// The snapshot a prior version was read from.
pub struct SnapshotRef<'a> {
    pub artifact: &'a Artifact,
    pub snapshot_id: &'a str,
    pub creation_time: &'a str,
    pub stack_position: u64,
    /// The rebuilt snapshot stream: the only source a prior version's runs
    /// are applied to.
    pub stream: Arc<dyn DataSource>,
    /// The snapshot's own `content_incomplete_reason`, if its bytes are not
    /// the whole snapshot.
    pub content_incomplete_reason: Option<&'a str>,
}

/// What the comparison of one snapshot found, for the snapshot record.
pub struct DiffOutcome {
    pub prior_versions: Vec<Artifact>,
    pub summary: Value,
    /// Set when a cap left differing records unpublished or records
    /// uncompared.
    pub inventory_incomplete_detail: Option<String>,
}

/// The `cap` items with the lowest numbers out of a stream, held without
/// holding the stream. The publication cap has always kept the differing
/// records with the lowest record numbers; a sort of the whole set did that,
/// and this does it from a walk, holding at most `cap` items.
struct LowestN<T> {
    cap: usize,
    heap: BinaryHeap<Entry<T>>,
}

struct Entry<T>(u64, T);
impl<T> PartialEq for Entry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<T> Eq for Entry<T> {}
impl<T> PartialOrd for Entry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Entry<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T> LowestN<T> {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            heap: BinaryHeap::new(),
        }
    }

    fn offer(&mut self, number: u64, item: T) {
        if self.heap.len() < self.cap {
            self.heap.push(Entry(number, item));
        } else if self.heap.peek().is_some_and(|worst| number < worst.0) {
            self.heap.pop();
            self.heap.push(Entry(number, item));
        }
    }

    /// The kept items, lowest number first.
    fn into_sorted(self) -> Vec<(u64, T)> {
        self.heap
            .into_sorted_vec()
            .into_iter()
            .map(|Entry(n, t)| (n, t))
            .collect()
    }
}

/// Compare one snapshot's `$MFT` with the live one and build the prior-version
/// records for what differs.
pub fn diff_snapshot(live: &ParsedMft, snap: &SnapshotRef<'_>) -> Result<DiffOutcome, String> {
    let mut seen: HashSet<u64> = HashSet::new();
    let mut differing = 0usize;
    let mut kept: LowestN<(Map<String, Value>, Vec<Value>)> =
        LowestN::new(MAX_PRIOR_VERSIONS_PER_SNAPSHOT);
    let extent = walk_volume_mft(&snap.stream, &mut |n, md| {
        // The first record with a given number wins, as it does for the live side.
        if !seen.insert(n) {
            return;
        }
        let diffs = differences(live.record(n).as_ref(), &md);
        if diffs.is_empty() {
            return;
        }
        differing += 1;
        kept.offer(n, (md, diffs));
    })?;
    let records_compared = seen.len();
    let parsed = extent;

    let kept = kept.into_sorted();
    let mut prior_versions = Vec::with_capacity(kept.len());
    for (number, (md, diffs)) in kept {
        prior_versions.push(prior_version_artifact(
            snap,
            live.record(number).as_ref(),
            &md,
            diffs,
        ));
    }

    let unpublished = differing - prior_versions.len();
    let mut detail = Vec::new();
    if unpublished > 0 {
        detail.push(format!(
            "{unpublished} differing record(s) past the {MAX_PRIOR_VERSIONS_PER_SNAPSHOT}-record \
             publication cap were not published"
        ));
    }
    if parsed.capped || live.capped {
        detail.push(format!(
            "records past the first {MAX_MFT_RECORDS_COMPARED} of the $MFT were not compared"
        ));
    }
    if !parsed.runs_complete || !live.runs_complete {
        detail.push(
            "a $MFT's own run list is incomplete, so records past its known extent were not \
             compared"
                .to_string(),
        );
    }
    let summary = json!({
        "status": "compared",
        "records_compared": records_compared,
        "snapshot_mft_record_slots": parsed.record_slots,
        "live_mft_record_slots": live.record_slots,
        "records_differing": differing,
        "prior_versions_published": prior_versions.len(),
        "prior_versions_unpublished": unpublished,
        "max_records_compared": MAX_MFT_RECORDS_COMPARED,
        "max_prior_versions_published": MAX_PRIOR_VERSIONS_PER_SNAPSHOT,
    });
    Ok(DiffOutcome {
        prior_versions,
        summary,
        inventory_incomplete_detail: (!detail.is_empty()).then(|| detail.join("; ")),
    })
}

/// Keys copied from the snapshot record as the record's content description.
const CONTENT_KEYS: [&str; 9] = [
    "data_runs",
    "data_runs_complete",
    "resident_data_b64",
    "compression",
    "compression_unit_bytes",
    "compressed",
    "efs_encrypted",
    "content_ciphertext",
    "ads_names",
];

fn prior_version_artifact(
    snap: &SnapshotRef<'_>,
    live: Option<&Map<String, Value>>,
    md: &Map<String, Value>,
    diffs: Vec<Value>,
) -> Artifact {
    let file_name = md.get("name").and_then(Value::as_str).unwrap_or("Unknown");
    let in_use = md.get("deleted").and_then(Value::as_bool) != Some(true);
    let changed: Vec<Value> = diffs.iter().map(|d| d["field"].clone()).collect();
    let label = format!(
        "SHADOW COPY VERSION, not the live volume: from snapshot {} created {} (stack position {})",
        snap.snapshot_id, snap.creation_time, snap.stack_position
    );

    let mut out = json!({
        "type": "VssPriorVersion",
        "subtype": "vss_prior_version",
        "name": format!("{file_name} [shadow copy {}]", snap.creation_time),
        "file_name": file_name,
        "provenance": "vss_snapshot",
        "is_snapshot_version": true,
        "snapshot_label": label,
        "vss_snapshot_id": snap.snapshot_id,
        "vss_creation_time": snap.creation_time,
        "vss_stack_position": snap.stack_position,
        "record_number": md.get("record_number"),
        "sequence_number": md.get("sequence_number"),
        "live_sequence_number": live.and_then(|l| l.get("sequence_number")),
        "absent_from_live": live.is_none(),
        "in_use_in_snapshot": in_use,
        "snapshot_path": md.get("path"),
        "live_path": live.and_then(|l| l.get("path")),
        "snapshot_is_directory": md.get("is_directory").and_then(Value::as_bool).unwrap_or(false),
        "differences": diffs,
        "changed_fields": changed,
        "snapshot_times": {
            "created": md.get("created"),
            "modified": md.get("modified"),
            "mft_modified": md.get("mft_modified"),
            "accessed": md.get("accessed"),
            "fn_created": md.get("fn_created"),
            "fn_modified": md.get("fn_modified"),
            "fn_mft_modified": md.get("fn_mft_modified"),
            "fn_accessed": md.get("fn_accessed"),
        },
        "source": "VssEnumerator",
    });
    let map = out.as_object_mut().expect("object");
    if let Some(size) = md.get("size") {
        map.insert("size".into(), size.clone());
    }
    for k in CONTENT_KEYS {
        if let Some(v) = md.get(k) {
            map.insert(k.into(), v.clone());
        }
    }
    stamp_content(map, md, snap);

    let data = ingest_source(map, &snap.stream);
    Artifact::new(snap.artifact.case_id, ArtifactType::ParsedRecord, data, out)
        .with_parent(snap.artifact.id)
}

/// Re-derive the incompleteness pair for a record whose runs now have a
/// volume behind them.
///
/// The bare parse stamped every non-resident stream `volume_not_in_evidence`
/// (true of a bare `$MFT`, false here: the rebuilt snapshot is that volume),
/// overwriting any more specific reason. What remains true is re-stated: EFS
/// ciphertext, a record deleted in the snapshot (its clusters may have been
/// reused before the snapshot was taken), a run list known short, and a
/// snapshot whose own bytes are not the whole snapshot.
fn stamp_content(map: &mut Map<String, Value>, md: &Map<String, Value>, snap: &SnapshotRef<'_>) {
    let bool_of = |k: &str| md.get(k).and_then(Value::as_bool) == Some(true);
    let (reason, detail): (Option<&str>, Option<String>) = if bool_of("efs_encrypted") {
        (Some(IncompleteReason::Encrypted.as_str()), None)
    } else if let Some(r) = snap.content_incomplete_reason {
        (
            Some(r),
            Some(format!(
                "The snapshot this version was read from is itself incomplete ({r}), so part of \
                 its content may be dated to another moment"
            )),
        )
    } else if bool_of("deleted") {
        map.insert(
            "deleted_content_caveat".into(),
            json!("clusters_may_be_reallocated"),
        );
        (
            Some(IncompleteReason::UnresolvedStructure.as_str()),
            Some(
                "The record was not in use in the snapshot: its clusters may have been \
                 reallocated before the snapshot was taken"
                    .to_string(),
            ),
        )
    } else if md.get("data_runs_complete").and_then(Value::as_bool) == Some(false) {
        (Some(IncompleteReason::UnresolvedStructure.as_str()), None)
    } else if md.get("compression_unsupported").is_some() && md.get("compression").is_none() {
        (Some(IncompleteReason::Compressed.as_str()), None)
    } else {
        (None, None)
    };
    if let Some(r) = reason {
        map.insert("content_incomplete".into(), json!(true));
        map.insert("content_incomplete_reason".into(), json!(r));
        if let Some(d) = detail {
            map.insert("content_incomplete_detail".into(), json!(d));
        }
    }
}

/// The ingest-time content: the snapshot record's plain runs over the rebuilt
/// snapshot stream, or its resident bytes. Compressed and encrypted content is
/// left to the resolver, which decompresses or refuses on demand.
fn ingest_source(
    map: &Map<String, Value>,
    stream: &Arc<dyn DataSource>,
) -> Option<Arc<dyn DataSource>> {
    if map.get("compression").is_some() || map.get("efs_encrypted").is_some() {
        return None;
    }
    if map.get("data_runs_complete").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    if let Some(b64) = map.get("resident_data_b64").and_then(Value::as_str) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        return STANDARD
            .decode(b64)
            .ok()
            .map(|b| Arc::new(ByteSliceDataSource::new(b)) as Arc<dyn DataSource>);
    }
    let runs = runs_from_metadata(map.get("data_runs")?)?;
    let size = map.get("size").and_then(Value::as_u64).unwrap_or(0);
    Some(Arc::new(RunListDataSource::with_logical_size(
        stream.clone(),
        runs,
        size,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn the_publication_cap_keeps_the_lowest_record_numbers_from_a_stream() {
        let mut kept = LowestN::new(3);
        for n in [40u64, 7, 91, 3, 55, 12, 3000, 8] {
            kept.offer(n, n * 2);
        }
        assert_eq!(kept.into_sorted(), vec![(3, 6), (7, 14), (8, 16)]);
        // Fewer than the cap: all are kept.
        let mut few = LowestN::new(10);
        few.offer(5, ());
        few.offer(1, ());
        assert_eq!(few.into_sorted(), vec![(1, ()), (5, ())]);
    }

    #[test]
    fn a_live_record_is_kept_as_only_the_fields_that_are_read_from_it() {
        let mut m = ParsedMft {
            records: HashMap::new(),
            record_slots: 1,
            capped: false,
            runs_complete: true,
        };
        let full = json!({
            "sequence_number": 2, "deleted": true, "name": "a.txt", "path": "/x/a.txt",
            "size": 9, "modified": "2019-06-05T00:00:00+00:00",
            "data_runs": [[1, 2]], "resident_data_b64": "AAAA", "ads_names": ["x"],
        });
        let mut kept = Map::new();
        for k in live_keys() {
            if let Some(v) = full.get(k) {
                kept.insert(k.to_string(), v.clone());
            }
        }
        m.records
            .insert(9, Value::Object(kept).to_string().into_boxed_str());
        let got = m.record(9).expect("held");
        assert_eq!(got["name"], "a.txt");
        assert_eq!(got["path"], "/x/a.txt");
        assert_eq!(got["sequence_number"], 2);
        assert!(got.get("data_runs").is_none(), "content keys are not held");
        assert!(got.get("resident_data_b64").is_none());
        assert!(m.record(10).is_none());
        // What a comparison reads is the same as from the full record.
        let snap = rec(json!({ "sequence_number": 1, "name": "a.txt", "size": 9 }));
        assert_eq!(
            differences(m.record(9).as_ref(), &snap),
            differences(full.as_object(), &snap)
        );
    }

    #[test]
    fn an_identical_record_is_not_a_prior_version() {
        let r = rec(json!({ "sequence_number": 3, "name": "a.txt", "size": 5 }));
        assert!(differences(Some(&r), &r).is_empty());
    }

    #[test]
    fn each_differing_field_is_listed_with_both_values() {
        let live = rec(json!({
            "sequence_number": 2, "deleted": true, "name": "a.txt",
            "modified": "2019-06-05T00:00:00+00:00",
        }));
        let snap = rec(json!({
            "sequence_number": 1, "name": "a.txt",
            "modified": "2019-06-04T00:00:00+00:00",
        }));
        assert_eq!(
            differences(Some(&live), &snap),
            vec![
                json!({ "field": "sequence_number", "live": 2, "snapshot": 1 }),
                json!({ "field": "in_use", "live": false, "snapshot": true }),
                json!({
                    "field": "modified",
                    "live": "2019-06-05T00:00:00+00:00",
                    "snapshot": "2019-06-04T00:00:00+00:00",
                }),
            ]
        );
    }

    #[test]
    fn a_record_the_live_mft_does_not_hold_is_one_difference() {
        let snap = rec(json!({ "sequence_number": 1, "name": "gone.txt" }));
        assert_eq!(
            differences(None, &snap),
            vec![json!({ "field": "record", "live": null, "snapshot": "present" })]
        );
    }

    #[test]
    fn the_bare_parse_volume_stamp_is_replaced_by_what_is_still_true() {
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({}),
        );
        let stream: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"abcdefgh".to_vec()));
        let snap = SnapshotRef {
            artifact: &artifact,
            snapshot_id: "s",
            creation_time: "t",
            stack_position: 1,
            stream,
            content_incomplete_reason: None,
        };
        // What the MFT module publishes for a live, plain file read from a
        // bare $MFT: runs, plus the volume-not-in-evidence stamp.
        let md = rec(json!({
            "record_number": 40, "sequence_number": 1, "name": "f.txt", "size": 4,
            "data_runs": [[2, 4]], "data_runs_complete": true,
            "content_incomplete": true, "content_incomplete_reason": "unresolved_structure",
            "volume_not_in_evidence": true,
        }));
        let a = prior_version_artifact(&snap, None, &md, differences(None, &md));
        assert!(a.metadata.get("volume_not_in_evidence").is_none());
        assert!(a.metadata.get("content_incomplete").is_none());
        assert_eq!(a.parent_id, Some(artifact.id));
        let ds = a.data.expect("served from the snapshot stream");
        let mut buf = [0u8; 4];
        seance_core::io::read_exact_or_fail(ds.as_ref(), 0, &mut buf, "t").unwrap();
        assert_eq!(&buf, b"cdef");

        // Deleted in the snapshot: the caveat stays.
        let mut deleted = md.clone();
        deleted.insert("deleted".into(), json!(true));
        let a = prior_version_artifact(&snap, None, &deleted, differences(None, &deleted));
        assert_eq!(
            a.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert_eq!(
            a.metadata["deleted_content_caveat"],
            "clusters_may_be_reallocated"
        );
    }
}
