#![forbid(unsafe_code)]
use crate::mft_structs::{
    apply_fixups, parse_attribute_header, parse_attribute_list, parse_data_runs_checked,
    parse_header, AttributeListEntry, MftRecordHeader, ATTR_TYPE_ATTRIBUTE_LIST, ATTR_TYPE_DATA,
    ATTR_TYPE_END, ATTR_TYPE_FILE_NAME, ATTR_TYPE_INDEX_ALLOCATION, ATTR_TYPE_INDEX_ROOT,
    ATTR_TYPE_LOGGED_UTILITY_STREAM, ATTR_TYPE_STANDARD_INFORMATION, FILE_SIGNATURE,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use byteorder::{ByteOrder, LittleEndian};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{byte_runs_to_metadata, ByteSliceDataSource, DataSource, RunListDataSource},
    file_detection::{try_detect_file_type, DetectedFileType},
    free_space::{emit_free_regions, AllocationBitmap, BitMeaning, FreeSpaceLabels},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
    orchestrator::{CancellationHandle, ProgressReporter},
    slack::{locate_slack, SlackCollector, SlackLabels, SlackLocation, SlackOwner},
    spilled_source::{spill_or_hold, SPILL_THRESHOLD_BYTES},
};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod mft_structs;
pub mod volume_mft;

#[cfg(test)]
mod boot_tests;
#[cfg(test)]
mod tests;

/// MFT record number of the root directory
const ROOT_RECORD: u64 = 5;
/// MFT record number of $Bitmap (volume allocation bitmap)
const BITMAP_RECORD: u64 = 6;
/// $FILE_NAME namespace value for DOS 8.3 alias names
const FILE_NAMESPACE_DOS: u8 = 2;
/// Limit attribute iterations to prevent infinite loops on corrupted records.
/// MFT records rarely have more than 10-20 attributes.
const MAX_ATTRIBUTES: usize = 100;
/// Cap on extension MFT records chased per file via $ATTRIBUTE_LIST. A
/// pathologically fragmented file referencing more records than this has its
/// remaining extents skipped and its runs flagged incomplete.
const MAX_EXTENSION_RECORDS: usize = 64;
/// Maximum buckets in a downsampled allocation bitmap (contract with the API layer)
const MAX_ALLOCATION_BUCKETS: u64 = 65536;
/// Safety cap when reading the $Bitmap contents into memory
const MAX_BITMAP_BYTES: u64 = 64 * 1024 * 1024;

/// Info about an Alternate Data Stream found in an MFT record
struct AdsEntry {
    name: String,
    size: u64,
    /// `$DATA` initialized size: the length of the prefix the filesystem has
    /// actually written. Bytes from here to `size` read as zeros on Windows.
    initialized_size: u64,
    runs: Option<Vec<(Option<u64>, u64)>>,
    resident_data: Option<Vec<u8>>,
    /// Start VCN of a non-resident stream's first extent; used to order merged
    /// $ATTRIBUTE_LIST fragments. 0 for resident streams (unused there).
    start_vcn: u64,
    /// `compression_unit` from the non-resident attribute header: log2 of the
    /// clusters per LZNT1 compression unit, 0 when the stream is stored raw.
    /// Without this a compressed ADS was served and hashed as its on-disk
    /// compressed cluster image (B6-004).
    compression_unit: u16,
}

/// One byte run of an attribute: (byte offset in the filesystem window, length).
/// A `None` offset is a sparse hole that reads as zeros.
type VcnRun = (Option<u64>, u64);

/// One extent of a fragmented non-resident attribute: (lowest_vcn, byte runs).
type VcnFragment = (u64, Vec<VcnRun>);

/// Extract the UTF-16LE attribute name from the MFT record buffer.
/// Returns None for unnamed attributes (name_length == 0).
fn extract_attr_name(
    record_buf: &[u8],
    attr_start: u64,
    attr_header: &mft_structs::AttributeHeader,
) -> Option<String> {
    if attr_header.name_length == 0 {
        return None;
    }
    let name_start = attr_start as usize + attr_header.name_offset as usize;
    let name_byte_len = attr_header.name_length as usize * 2;
    if name_start + name_byte_len > record_buf.len() {
        return None;
    }
    let name_bytes = &record_buf[name_start..name_start + name_byte_len];
    let u16_vec: Vec<u16> = name_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| LittleEndian::read_u16(c))
        .collect();
    String::from_utf16(&u16_vec).ok()
}

mod boot;

use boot::NtfsBootSector;

/// Bytes in one LZNT1 compression unit: `2^exp` clusters.
///
/// `exp` is the `compression_unit` field of a non-resident attribute header,
/// which is attacker-controllable in a hostile or truncated MFT. A shift of 64
/// or more is a panic under `overflow-checks`, and `2^exp * cluster_size` can
/// overflow a `u64` well before that. A single corrupt field must not bring the
/// whole MFT parse down — a panic here unwinds `process()` and the orchestrator
/// swallows it, losing every file in the table, not just the bad record — so
/// this returns `None` on an out-of-range exponent and the caller records the
/// compression descriptor as corrupt rather than fabricating a size.
fn compression_unit_bytes(exp: u16, cluster_size: u64) -> Option<u64> {
    // Overflow is not the only way this field is hostile. NTFS writes 4 here
    // (a 16-cluster unit) and nothing larger has ever been observed; an
    // exponent of 30 does not overflow a u64 and yet names a 4 TiB unit, and
    // that size flowed on into the decompressor's `vec![0u8; unit]` — an
    // allocation the allocator refuses, which is a process ABORT rather than a
    // panic, so the orchestrator's `catch_unwind` could not contain it. One
    // crafted record ended the whole ingest. The bound is what the format
    // emits, with headroom, and a value past it is the same corrupt descriptor
    // as an overflowing one.
    if exp > MAX_COMPRESSION_UNIT_EXPONENT {
        return None;
    }
    1u64.checked_shl(exp as u32)?.checked_mul(cluster_size)
}

/// The largest compression-unit exponent accepted from a record.
///
/// NTFS uses 4 (16 clusters, 64 KiB at the default cluster size). 6 leaves
/// room for a filesystem that grew the unit and stops well short of a size any
/// reader could honour: at 6 and a 64 KiB cluster the unit is 4 MiB.
const MAX_COMPRESSION_UNIT_EXPONENT: u16 = 6;

/// Parse the NTFS boot sector / BPB at offset 0 of the input window.
///
/// `None` when the window does not start with a valid NTFS boot sector — a bare
/// `$MFT` extracted from a volume, for instance, which starts with `FILE`.
///
/// A thin wrapper over [`boot::NtfsBootSector::parse`], which is the crate's
/// one decoder for this structure. There used to be two: this, and
/// `mft_scan_phase` hand-decoding the same three fields. Two decoders for one
/// structure is how they come to disagree, and these already had.
fn parse_ntfs_boot_sector(source: &dyn DataSource) -> Option<NtfsBootSector> {
    let mut buf = [0u8; boot::BOOT_SECTOR_BYTES];
    let n = source.read_at(0, &mut buf).ok()?;
    if n < boot::BOOT_SECTOR_BYTES {
        return None;
    }
    NtfsBootSector::parse(&buf)
}

/// First-pass record info used to reconstruct full paths.
struct NameMapEntry {
    name: String,
    parent: u64,
    /// The sequence number the `$FILE_NAME` parent reference names. Zero means
    /// the reference carried none, which NTFS never writes for an allocated
    /// record and which the test fixtures do; it is treated as "not stated".
    parent_sequence: u16,
    /// This record's own sequence number, from its header.
    sequence: u16,
    /// Whether this record is a directory (header flag or `$INDEX_ROOT`).
    is_directory: bool,
    namespace: u8,
}

/// A `$FILE_NAME` parent reference: the record number and the sequence number
/// that record had when the name was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParentRef {
    record: u64,
    sequence: u16,
}

/// Why a record's path could not be built, when it could not.
///
/// An MFT reference is a record number *and* a sequence number, and the
/// sequence is the half that says whether the record still holds what the
/// reference meant. Following the number alone grafted a deleted file whose
/// directory's slot had been reused under whatever now lives there — on the
/// NIST Data Leakage image, 1,419 entries under a `.lnk` (HUNT-065). Each
/// reason is stamped on the record as `orphan_reason`, because "the directory
/// is gone" and "the directory's slot now holds a file" call for different
/// follow-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OrphanReason {
    /// No record at all at the referenced number.
    ParentMissing,
    /// A record is there, at a different sequence: the directory was deleted
    /// and the slot reused.
    ParentRecordReused,
    /// A record is there at the right sequence and it is not a directory.
    ParentNotADirectory,
    /// The chain loops or is absurdly deep.
    Cycle,
}

impl OrphanReason {
    fn as_str(self) -> &'static str {
        match self {
            OrphanReason::ParentMissing => "parent_record_missing",
            OrphanReason::ParentRecordReused => "parent_record_reused",
            OrphanReason::ParentNotADirectory => "parent_not_a_directory",
            OrphanReason::Cycle => "parent_chain_cycle",
        }
    }
}

/// Extract (name, parent reference, namespace) from resident $FILE_NAME content.
fn parse_file_name_attr(content: &[u8]) -> Option<(String, ParentRef, u8)> {
    if content.len() <= 66 {
        return None;
    }
    // Parent reference: low 48 bits are the record number, high 16 the
    // sequence number that record had when this name was written.
    let raw = LittleEndian::read_u64(&content[0..8]);
    let parent = ParentRef {
        record: raw & 0x0000_FFFF_FFFF_FFFF,
        sequence: (raw >> 48) as u16,
    };
    let name_len = content[64] as usize;
    let namespace = content[65];
    let name_bytes_len = name_len * 2;
    if 66 + name_bytes_len > content.len() {
        return None;
    }
    let u16_vec: Vec<u16> = content[66..66 + name_bytes_len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| LittleEndian::read_u16(c))
        .collect();
    let name = String::from_utf16(&u16_vec).ok()?;
    Some((name, parent, namespace))
}

/// First pass over the MFT: build a record number -> (name, parent) map from
/// $FILE_NAME attributes so full paths can be reconstructed. Win32/POSIX
/// names are preferred over DOS 8.3 aliases.
///
/// `table` is the `$MFT` itself, record 0 at offset 0 — on a volume, the
/// table read through its own runs ([`volume_mft::VolumeMft::table`]), never
/// the volume window, so a stray `FILE` block elsewhere on the volume cannot
/// put a name under a record number it does not hold (HUNT-251). When
/// `slot_numbered`, a record's number is its slot in the table, which is what
/// a file reference indexes; otherwise it is the number in its header.
/// How many record slots pass between two `report_retention` lines.
const RETENTION_REPORT_EVERY: u64 = 10_000;

/// Log what the artifacts published so far are holding, beside the process's
/// own anonymous resident set, so a memory profile of one `$MFT` pass can say
/// which retention grows (HUNT-125). Metadata size is a 1-in-64 sample of the
/// serialised JSON, extrapolated; the count per artifact type is exact.
fn report_retention(records: u64, produced: &[Artifact], decompressed_bytes: u64) {
    let mut by_type: std::collections::BTreeMap<String, u64> = Default::default();
    // Sampled in-memory size (not serialised size: a `serde_json::Value` tree
    // costs several times its JSON text), per artifact type.
    let mut heap_sampled: std::collections::BTreeMap<String, (u64, u64)> = Default::default();
    let mut sampled_bytes: u64 = 0;
    let mut sampled: u64 = 0;
    for (i, a) in produced.iter().enumerate() {
        let kind = format!("{:?}", a.artifact_type);
        *by_type.entry(kind.clone()).or_default() += 1;
        if i % 64 == 0 {
            sampled_bytes += a.metadata.to_string().len() as u64;
            sampled += 1;
            let e = heap_sampled.entry(kind).or_default();
            e.0 += value_heap_bytes(&a.metadata) as u64 + std::mem::size_of::<Artifact>() as u64;
            e.1 += 1;
        }
    }
    let est_metadata = (sampled_bytes * produced.len() as u64)
        .checked_div(sampled)
        .unwrap_or(0);
    let est_heap_by_type: std::collections::BTreeMap<String, u64> = heap_sampled
        .into_iter()
        .map(|(k, (bytes, n))| {
            let total = by_type.get(&k).copied().unwrap_or(0);
            (k, (bytes * total).checked_div(n).unwrap_or(0))
        })
        .collect();
    let anon_kb = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("RssAnon:").map(|v| v.trim().to_string()))
        })
        .unwrap_or_else(|| "n/a".to_string());
    info!(
        "mft retention: records={} artifacts={} by_type={:?} est_metadata_bytes={} \
         est_heap_bytes_by_type={:?} decompressed_content_bytes={} process_rss_anon={}",
        records,
        produced.len(),
        by_type,
        est_metadata,
        est_heap_by_type,
        decompressed_bytes,
        anon_kb
    );
}

/// Approximate heap bytes held by a JSON value tree (strings, map and array
/// storage), for the retention report. Deliberately a rough lower bound: it
/// counts payload plus one `Value` slot per node and ignores allocator slack.
fn value_heap_bytes(v: &serde_json::Value) -> usize {
    use serde_json::Value;
    let slot = std::mem::size_of::<Value>();
    match v {
        Value::String(s) => s.capacity(),
        Value::Array(a) => a.capacity() * slot + a.iter().map(value_heap_bytes).sum::<usize>(),
        Value::Object(m) => m
            .iter()
            .map(|(k, x)| k.capacity() + 24 + slot + value_heap_bytes(x))
            .sum::<usize>(),
        _ => 0,
    }
}

fn build_name_map(
    data_source: &dyn DataSource,
    mft_record_size: u64,
    slot_numbered: bool,
) -> HashMap<u64, NameMapEntry> {
    let mut map: HashMap<u64, NameMapEntry> = HashMap::new();
    let mut offset: u64 = 0;
    // Reused across records so the first pass doesn't allocate a fresh 1KB buffer
    // per MFT record (millions on a large volume). read_at fully overwrites it
    // each iteration before any parsing runs, so no stale bytes leak.
    let mut record_buf = vec![0; mft_record_size as usize];

    while offset < data_source.size() {
        let bytes_read = match data_source.read_at(offset, &mut record_buf) {
            // A mid-volume read failure must not abort the whole first pass:
            // that would drop the names/parents of every later record and
            // silently corrupt path reconstruction. Skip this slot instead.
            Err(_) => {
                offset += mft_record_size;
                continue;
            }
            Ok(0) => break, // genuine end of data
            Ok(n) => n,
        };
        if bytes_read < mft_record_size as usize {
            // Short read. If a full record still fits in the volume here it is
            // an unreadable region, not the end: skip and continue. Otherwise
            // it is the final partial slot at the tail: stop.
            if offset + mft_record_size > data_source.size() {
                break;
            }
            offset += mft_record_size;
            continue;
        }
        let slot = offset / mft_record_size;
        offset += mft_record_size;

        if record_buf[0..4] != *FILE_SIGNATURE {
            continue;
        }

        let mut cursor = Cursor::new(&record_buf[..]);
        let header = match parse_header(&mut cursor) {
            Ok(h) => h,
            Err(_) => continue,
        };
        // A 3.0 header has no number of its own (HUNT-256): the slot is the
        // only number the record has, on bare input as on a located table.
        let record = if slot_numbered {
            slot
        } else {
            header.record_number.map_or(slot, u64::from)
        };
        // A failed USA fixup means the record is torn: the last two bytes of
        // each sector still hold the update-sequence placeholder rather than
        // the record's own bytes. Names and parent references read out of such
        // a buffer are fabricated, and a fabricated name here becomes a
        // fabricated PATH for every file under it. Skip the record (B6-002).
        if apply_fixups(
            &mut record_buf,
            header.update_seq_array_offset as usize,
            header.update_seq_array_size as usize,
        )
        .is_err()
        {
            continue;
        }

        let mut cursor = Cursor::new(&record_buf[..]);
        cursor.set_position(header.first_attribute_offset as u64);
        let mut attr_count = 0;
        let mut saw_index_root = false;

        loop {
            attr_count += 1;
            if attr_count > MAX_ATTRIBUTES {
                break;
            }
            let attr_start = cursor.position();
            let attr_header = match parse_attribute_header(&mut cursor) {
                Ok(h) => h,
                Err(_) => break,
            };
            if attr_header.attribute_type == ATTR_TYPE_END {
                break;
            }
            if attr_header.length < 16 {
                break;
            }

            // A directory is one by its header flag or by carrying an
            // `$INDEX_ROOT`; the path builder refuses to walk through a record
            // that is neither, whatever its name.
            if attr_header.attribute_type == ATTR_TYPE_INDEX_ROOT {
                if let Some(entry) = map.get_mut(&record) {
                    entry.is_directory = true;
                }
                saw_index_root = true;
            }

            if attr_header.attribute_type == ATTR_TYPE_FILE_NAME && !attr_header.non_resident {
                let start = attr_start + attr_header.content_offset as u64;
                let end = start + attr_header.content_size as u64;
                if end <= record_buf.len() as u64 {
                    if let Some((name, parent, namespace)) =
                        parse_file_name_attr(&record_buf[start as usize..end as usize])
                    {
                        let replace = match map.get(&record) {
                            None => true,
                            Some(existing) => {
                                existing.namespace == FILE_NAMESPACE_DOS
                                    && namespace != FILE_NAMESPACE_DOS
                            }
                        };
                        if replace {
                            let is_directory = header.flags & 0x0002 != 0
                                || saw_index_root
                                || map.get(&record).is_some_and(|e| e.is_directory);
                            map.insert(
                                record,
                                NameMapEntry {
                                    name,
                                    parent: parent.record,
                                    parent_sequence: parent.sequence,
                                    sequence: header.sequence_number,
                                    is_directory,
                                    namespace,
                                },
                            );
                        }
                    }
                }
            }

            cursor.set_position(attr_start + attr_header.length as u64);
        }
    }

    map
}

/// Resolve the absolute path of a directory by following parent references
/// up to the root (record 5).
///
/// Each hop is checked three ways before it is trusted: the record must
/// exist, it must hold the sequence number the reference names (a reference
/// with sequence 0 states none and is not checked — NTFS never writes 0 for
/// an allocated record), and it must be a directory. A hop that fails any of
/// them ends the walk with the reason, and the caller files the record under
/// `$OrphanFiles` with that reason. Following the record number alone put a
/// deleted file under whatever file had since taken its directory's slot
/// (HUNT-065).
fn resolve_dir_path(
    map: &HashMap<u64, NameMapEntry>,
    parent: ParentRef,
) -> Result<String, OrphanReason> {
    let mut parts: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut hop = parent;
    while hop.record != ROOT_RECORD {
        if !seen.insert(hop.record) || parts.len() > 255 {
            return Err(OrphanReason::Cycle);
        }
        let entry = map.get(&hop.record).ok_or(OrphanReason::ParentMissing)?;
        if hop.sequence != 0 && entry.sequence != hop.sequence {
            return Err(OrphanReason::ParentRecordReused);
        }
        if !entry.is_directory {
            return Err(OrphanReason::ParentNotADirectory);
        }
        parts.push(entry.name.clone());
        hop = ParentRef {
            record: entry.parent,
            sequence: entry.parent_sequence,
        };
    }
    parts.reverse();
    Ok(format!("/{}", parts.join("/")))
}

/// Compressed $DATA up to this size is decompressed in memory at ingest so the
/// search index sees real content; larger files index their raw runs. Re-serving
/// is size-independent (the resolver decompresses via the compression descriptor).
const NTFS_DECOMPRESS_CAP: u64 = 256 * 1024 * 1024;

/// Reduce an allocated run list to the attribute's logical content extent.
///
/// NTFS allocates whole clusters, so the last run of a non-resident attribute
/// normally runs past `real_size` into cluster slack: bytes that belong to
/// whatever previously occupied that cluster, not to this file. NTFS
/// separately records `initialized_size`, the length of the prefix the
/// filesystem has actually written; the range `[initialized_size, real_size)`
/// has never been written and Windows reads it as zeros even though the
/// clusters backing it still hold the previous tenant's data.
///
/// Forensic meaning: what an examiner hashes, previews, or exports must be
/// exactly the file's logical bytes. A wrong answer here is not obviously
/// wrong — it looks like a normal file whose MD5/SHA never matches the same
/// file acquired with any other tool, and whose tail shows recognisable
/// fragments of an unrelated deleted file attributed to this one.
///
/// Runs past the logical extent are dropped; the never-written tail (and any
/// range the run list stopped short of) becomes a sparse hole, matching the
/// zero-fill the API content resolver applies when re-serving.
fn logical_extent_runs(
    byte_runs: &[(Option<u64>, u64)],
    initialized_size: u64,
    real_size: u64,
) -> Vec<(Option<u64>, u64)> {
    if real_size == 0 {
        // A genuinely empty file is resident, so a non-resident attribute
        // claiming size 0 is a header this parser cannot trust (typically an
        // extension extent, which records zero for all three sizes). Return the
        // allocated runs unchanged rather than blanking recoverable data.
        return byte_runs.to_vec();
    }
    // A written prefix longer than the file itself is a corrupt header; the
    // file can never expose more than real_size bytes either way.
    let valid = initialized_size.min(real_size);
    let mut out: Vec<(Option<u64>, u64)> = Vec::with_capacity(byte_runs.len() + 1);
    let mut covered: u64 = 0;
    for &(offset, len) in byte_runs {
        if covered >= valid {
            break;
        }
        let take = len.min(valid - covered);
        if take > 0 {
            out.push((offset, take));
            covered = covered.saturating_add(take);
        }
    }
    if real_size > covered {
        out.push((None, real_size - covered));
    }
    out
}

/// Assemble the extents of one non-resident attribute into a single logical
/// run list, keyed on each extent's starting VCN.
///
/// Concatenating extents in VCN order is only correct when they tile the
/// attribute without gaps. When an extent is missing — an unreadable extension
/// MFT record, a torn `$ATTRIBUTE_LIST`, a first extent that does not start at
/// VCN 0 — plain concatenation pulls every later extent leftward, so byte N of
/// the file is served from a cluster that belongs to some entirely different
/// offset. That failure is silent and produces plausible-looking content.
///
/// Gaps are therefore padded with sparse holes so surviving extents stay at
/// their true logical offsets, and the caller is told the attribute is
/// incomplete so the emitted runs are never presented as a whole file.
/// Returns the merged runs and whether any gap or overlap was found.
fn merge_vcn_fragments(mut frags: Vec<VcnFragment>, cluster_size: u64) -> (Vec<VcnRun>, bool) {
    if cluster_size == 0 {
        // Without a cluster size a VCN cannot be converted to a byte offset;
        // report the merge as incomplete rather than guessing an alignment.
        let gapped = frags.len() > 1 || frags.first().is_some_and(|(vcn, _)| *vcn != 0);
        return (
            frags.into_iter().flat_map(|(_, runs)| runs).collect(),
            gapped,
        );
    }
    frags.sort_by_key(|(vcn, _)| *vcn);
    let mut out: Vec<VcnRun> = Vec::new();
    let mut expected_vcn: u64 = 0;
    let mut gapped = false;
    for (vcn, runs) in frags {
        if vcn > expected_vcn {
            // Missing extent: hold the following extents at their true offsets.
            let hole = vcn
                .saturating_sub(expected_vcn)
                .saturating_mul(cluster_size);
            out.push((None, hole));
            gapped = true;
        } else if vcn < expected_vcn {
            // Overlapping extents: the list disagrees with itself. Dropping the
            // overlap keeps later extents aligned; flag it either way.
            gapped = true;
            continue;
        }
        let span: u64 = runs.iter().fold(0u64, |acc, (_, l)| acc.saturating_add(*l));
        out.extend(runs);
        // NTFS allocates whole clusters, so a span that is not a multiple of the
        // cluster size still consumes the cluster it partially fills. Truncating
        // division under-counted the VCNs this extent covers, so the next extent
        // looked like it started too late: a hole was invented ahead of it and
        // every later extent was pushed off its true logical offset (B5-027).
        expected_vcn = expected_vcn.saturating_add(span.div_ceil(cluster_size));
    }
    (out, gapped)
}

/// Stamp the standard incompleteness pair when a run list is short of the
/// attribute it describes.
///
/// `data_runs_complete` is read only by the API content resolver (which refuses
/// to serve). The incompleteness census, the report and the artifact UI read
/// `content_incomplete` / `content_incomplete_reason`, so a file whose runs were
/// capped or whose attribute walk aborted was otherwise displayed as an ordinary
/// whole file (B6-007).
/// Stamp a non-resident stream read from a bare `$MFT` (HUNT-161).
///
/// Its run list is published — where the stream lived is evidence — but no
/// data source is attached, because the clusters it names are on a volume
/// that was not supplied. Applied against the `$MFT` file itself the same
/// offsets land on other MFT records, which is what was served before. A
/// zero-length stream has no content to be missing and is not stamped.
fn stamp_volume_not_in_evidence(
    metadata: &mut serde_json::Map<String, serde_json::Value>,
    logical_size: u64,
) {
    if logical_size == 0 {
        return;
    }
    metadata.insert("content_incomplete".to_string(), json!(true));
    metadata.insert(
        "content_incomplete_reason".to_string(),
        json!(IncompleteReason::UnresolvedStructure.as_str()),
    );
    metadata.insert("volume_not_in_evidence".to_string(), json!(true));
    metadata.insert(
        "content_incomplete_detail".to_string(),
        json!(
            "This stream is stored outside its MFT record, and the volume its cluster \
             runs address was not supplied — only the $MFT was. Its content is not \
             available from this evidence; the run list records where it was"
        ),
    );
}

fn stamp_runs_incompleteness(
    metadata: &mut serde_json::Map<String, serde_json::Value>,
    runs_fit_metadata_cap: bool,
    attr_list_incomplete: bool,
) {
    let reason = if !runs_fit_metadata_cap {
        IncompleteReason::CapReached
    } else if attr_list_incomplete {
        IncompleteReason::UnresolvedStructure
    } else {
        return;
    };
    // A more specific reason already recorded (encryption, compression) is the
    // better answer; never overwrite it with a structural one.
    if metadata.contains_key("content_incomplete_reason") {
        return;
    }
    metadata.insert("content_incomplete".to_string(), json!(true));
    metadata.insert(
        "content_incomplete_reason".to_string(),
        json!(reason.as_str()),
    );
}

/// A non-resident $DATA attribute recovered from an extension MFT record.
struct ExtDataAttr {
    /// `$DATA` or `$INDEX_ALLOCATION`.
    attribute_type: u32,
    attribute_id: u16,
    name: Option<String>,
    byte_runs: Vec<(Option<u64>, u64)>,
    real_size: u64,
    /// Written prefix of the attribute; only the VCN-0 extent carries a
    /// meaningful value (later extents record zero).
    initialized_size: u64,
    /// The run list hit the per-attribute run cap and was truncated; the file's
    /// data runs must be flagged incomplete.
    truncated: bool,
    /// LZNT1 compression unit (log2 clusters), 0 when stored raw.
    compression_unit: u16,
}

/// One fragment of a non-resident attribute, matched to an $ATTRIBUTE_LIST
/// entry in an extension record.
struct ResolvedFragment {
    name: Option<String>,
    lowest_vcn: u64,
    byte_runs: Vec<(Option<u64>, u64)>,
    real_size: u64,
    initialized_size: u64,
    /// LZNT1 compression unit (log2 clusters), 0 when stored raw.
    compression_unit: u16,
}

/// Outcome of resolving the extension records referenced by an $ATTRIBUTE_LIST.
struct ExtensionResolution {
    /// `$DATA` extents (unnamed and named streams).
    fragments: Vec<ResolvedFragment>,
    /// `$INDEX_ALLOCATION:$I30` extents of a directory's index.
    i30_fragments: Vec<ResolvedFragment>,
    /// The list names at least one `$I30` index-allocation extent held in an
    /// extension record, so the directory has an index allocation even when
    /// none of it could be recovered.
    i30_listed: bool,
    /// A listed `$I30` extent could not be recovered.
    i30_incomplete: bool,
    /// True when any referenced record or extent could not be recovered. The
    /// caller must flag the file's emitted data runs as incomplete: presenting
    /// a partial run list as complete would fabricate truncated evidence.
    incomplete: bool,
}

/// Read the MFT record at `record_num` from the `$MFT` table and apply fixups.
/// Returns None when the record cannot be trusted: out of range, short/failed
/// read, missing FILE signature, a header record number that is not the slot,
/// a base reference that does not name `base_record`, or bad fixups. Mirrors
/// the read path of the main scan loop (same phase alignment).
fn read_extension_record(
    data_source: &dyn DataSource,
    mft_record_size: u64,
    record_num: u64,
    base_record: u64,
) -> Option<(MftRecordHeader, Vec<u8>)> {
    let offset = record_num.checked_mul(mft_record_size)?;
    // Range-check first so an out-of-range reference is reported, not read.
    if offset.checked_add(mft_record_size)? > data_source.size() {
        return None;
    }
    let mut buf = vec![0u8; mft_record_size as usize];
    match data_source.read_at(offset, &mut buf) {
        Ok(n) if n as u64 == mft_record_size => {}
        _ => return None,
    }
    if buf[0..4] != *FILE_SIGNATURE {
        return None;
    }
    let mut cursor = Cursor::new(&buf[..]);
    let header = parse_header(&mut cursor).ok()?;
    // A 3.1 header's own record number must match the slot we addressed;
    // otherwise the MFT window is not laid out as assumed and this record
    // cannot be trusted to be the referenced one. A 3.0 header carries no
    // number (HUNT-256), so there is nothing to compare.
    if header
        .record_number
        .is_some_and(|n| u64::from(n) != record_num)
    {
        return None;
    }
    // On both versions an extension record names the base record that owns
    // it (the low 48 bits of its base reference). One that names another
    // file, or none, is not this file's extent: on 3.0 this is the only link.
    if header.base_record_reference & 0xFFFF_FFFF_FFFF != base_record {
        return None;
    }
    apply_fixups(
        &mut buf,
        header.update_seq_array_offset as usize,
        header.update_seq_array_size as usize,
    )
    .ok()?;
    Some((header, buf))
}

/// Collect the non-resident $DATA attributes (unnamed and named) of an
/// extension MFT record, with runs converted to byte offsets. Bounded by
/// MAX_ATTRIBUTES like the main attribute loop.
fn collect_extension_data_attrs(
    record_buf: &[u8],
    header: &MftRecordHeader,
    cluster_size: u64,
) -> Vec<ExtDataAttr> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(record_buf);
    cursor.set_position(header.first_attribute_offset as u64);
    let mut attr_count = 0;

    loop {
        attr_count += 1;
        if attr_count > MAX_ATTRIBUTES {
            break;
        }
        let attr_start = cursor.position();
        let attr_header = match parse_attribute_header(&mut cursor) {
            Ok(h) => h,
            Err(_) => break,
        };
        if attr_header.attribute_type == ATTR_TYPE_END {
            break;
        }
        if attr_header.length < 16 {
            break;
        }

        if matches!(
            attr_header.attribute_type,
            ATTR_TYPE_DATA | ATTR_TYPE_INDEX_ALLOCATION
        ) && attr_header.non_resident
        {
            let runs_offset_abs = attr_start + attr_header.data_runs_offset as u64;
            // Bound the run list to this attribute, not to the end of the
            // record: an unterminated list would otherwise decode the following
            // attribute's bytes as extents (B6-003).
            let attr_end = (attr_start + attr_header.length as u64).min(record_buf.len() as u64);
            if runs_offset_abs < attr_end {
                let (raw_runs, runs_truncated) = parse_data_runs_checked(
                    &record_buf[runs_offset_abs as usize..attr_end as usize],
                );
                let byte_runs: Vec<(Option<u64>, u64)> = raw_runs
                    .into_iter()
                    .map(|(lcn, len)| {
                        // Same saturation contract as the main attribute loop.
                        (
                            lcn.map(|l| l.saturating_mul(cluster_size)),
                            len.saturating_mul(cluster_size),
                        )
                    })
                    .collect();
                out.push(ExtDataAttr {
                    attribute_type: attr_header.attribute_type,
                    attribute_id: attr_header.attribute_id,
                    name: extract_attr_name(record_buf, attr_start, &attr_header),
                    byte_runs,
                    real_size: attr_header.real_size,
                    initialized_size: attr_header.initialized_size,
                    truncated: runs_truncated,
                    compression_unit: attr_header.compression_unit,
                });
            }
        }

        cursor.set_position(attr_start + attr_header.length as u64);
    }

    out
}

/// Resolve the extension MFT records referenced by a file's $ATTRIBUTE_LIST
/// and match each $DATA extent entry to the attribute living there. Matching
/// is by attribute type + name + attribute id, per the list entry. $DATA
/// extents and a directory's `$INDEX_ALLOCATION:$I30` extents are merged
/// (HUNT-256: a directory whose index allocation lived wholly in an extension
/// record was published with no `$I30` stream). Other attribute types in
/// extension records are not parsed by this module from a base record
/// either, so skipping them changes nothing.
fn resolve_extension_records(
    data_source: &dyn DataSource,
    mft_record_size: u64,
    cluster_size: u64,
    self_record: u64,
    entries: &[AttributeListEntry],
) -> ExtensionResolution {
    let mut fragments = Vec::new();
    let mut i30_fragments = Vec::new();
    let mut incomplete = false;
    let mut i30_incomplete = false;
    let is_i30 = |e: &AttributeListEntry| {
        e.attribute_type == ATTR_TYPE_INDEX_ALLOCATION && e.name.as_deref() == Some("$I30")
    };
    let i30_listed = entries
        .iter()
        .any(|e| is_i30(e) && e.base_record_number != self_record);

    // Distinct extension record numbers, ascending for deterministic output.
    let mut record_nums: Vec<u64> = entries
        .iter()
        .map(|e| e.base_record_number)
        .filter(|&n| n != self_record)
        .collect();
    record_nums.sort_unstable();
    record_nums.dedup();
    if record_nums.len() > MAX_EXTENSION_RECORDS {
        debug!(
            "Record #{}: $ATTRIBUTE_LIST references {} extension records (cap {}); \
             extents past the cap are skipped and the runs flagged incomplete",
            self_record,
            record_nums.len(),
            MAX_EXTENSION_RECORDS
        );
        incomplete = true;
        i30_incomplete |= i30_listed;
        record_nums.truncate(MAX_EXTENSION_RECORDS);
    }

    let mut seen_extents: HashSet<(u64, u16)> = HashSet::new();

    for record_num in record_nums {
        let (ext_header, ext_buf) =
            match read_extension_record(data_source, mft_record_size, record_num, self_record) {
                Some(v) => v,
                None => {
                    debug!(
                        "Record #{}: extension MFT record #{} referenced by $ATTRIBUTE_LIST \
                     is unreadable or untrustworthy; runs flagged incomplete",
                        self_record, record_num
                    );
                    incomplete = true;
                    i30_incomplete |= entries
                        .iter()
                        .any(|e| e.base_record_number == record_num && is_i30(e));
                    continue;
                }
            };

        let ext_attrs = collect_extension_data_attrs(&ext_buf, &ext_header, cluster_size);

        for entry in entries
            .iter()
            .filter(|e| e.base_record_number == record_num)
        {
            let index = is_i30(entry);
            if entry.attribute_type != ATTR_TYPE_DATA && !index {
                continue;
            }
            // An $I30 extent that cannot be recovered marks the index, not the
            // file's data, as incomplete.
            let flag_missing = |incomplete: &mut bool, i30_incomplete: &mut bool| {
                if index {
                    *i30_incomplete = true;
                } else {
                    *incomplete = true;
                }
            };
            // A nonzero sequence that disagrees with the record means the slot
            // was reused after the list was written: the extent is gone.
            if entry.base_record_sequence != 0
                && entry.base_record_sequence != ext_header.sequence_number
            {
                debug!(
                    "Record #{}: sequence mismatch for extension record #{} \
                     (list expects {}, record has {}); extent skipped",
                    self_record, record_num, entry.base_record_sequence, ext_header.sequence_number
                );
                flag_missing(&mut incomplete, &mut i30_incomplete);
                continue;
            }
            if !seen_extents.insert((record_num, entry.attribute_id)) {
                continue; // duplicate list entry; already merged
            }
            match ext_attrs.iter().find(|a| {
                a.attribute_type == entry.attribute_type
                    && a.attribute_id == entry.attribute_id
                    && a.name == entry.name
            }) {
                Some(attr) => {
                    // A truncated extension run list means the file's data is
                    // not fully described: flag it so data_runs_complete=false.
                    if attr.truncated {
                        flag_missing(&mut incomplete, &mut i30_incomplete);
                    }
                    let target = if index {
                        &mut i30_fragments
                    } else {
                        &mut fragments
                    };
                    target.push(ResolvedFragment {
                        name: entry.name.clone(),
                        lowest_vcn: entry.lowest_vcn,
                        byte_runs: attr.byte_runs.clone(),
                        real_size: attr.real_size,
                        initialized_size: attr.initialized_size,
                        compression_unit: attr.compression_unit,
                    });
                }
                None => {
                    debug!(
                        "Record #{}: extension record #{} holds no $DATA extent matching \
                         (name={:?}, id={}); runs flagged incomplete",
                        self_record, record_num, entry.name, entry.attribute_id
                    );
                    flag_missing(&mut incomplete, &mut i30_incomplete);
                }
            }
        }
    }

    ExtensionResolution {
        fragments,
        i30_fragments,
        i30_listed,
        i30_incomplete,
        incomplete,
    }
}

/// Downsample a raw allocation bitmap (1 bit per cluster, LSB-first within
/// each byte) into at most MAX_ALLOCATION_BUCKETS byte-sized buckets where
/// each byte is the allocated fraction scaled to 0-255.
fn downsample_allocation_bitmap(bitmap: &[u8], total_clusters: u64) -> (Vec<u8>, u64) {
    let clusters_per_bucket = total_clusters.div_ceil(MAX_ALLOCATION_BUCKETS).max(1);
    let bucket_count = total_clusters.div_ceil(clusters_per_bucket);
    let mut buckets = Vec::with_capacity(bucket_count as usize);
    let mut cluster: u64 = 0;
    while cluster < total_clusters {
        let in_bucket = clusters_per_bucket.min(total_clusters - cluster);
        let mut allocated: u64 = 0;
        for i in cluster..cluster + in_bucket {
            let byte = bitmap.get((i / 8) as usize).copied().unwrap_or(0);
            if byte & (1 << (i % 8)) != 0 {
                allocated += 1;
            }
        }
        buckets.push(((allocated * 255) / in_bucket) as u8);
        cluster += in_bucket;
    }
    (buckets, clusters_per_bucket)
}

pub use seance_core::ntfs_timestamps::{
    detect_timestomp_indicators, filetime_seconds, filetime_subsec, TimestompIndicator,
};

#[derive(Default)]
pub struct MftParser {
    progress: Option<ProgressReporter>,
    cancellation: Option<CancellationHandle>,
}

impl MftParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a progress reporter; the record-parse loop emits ModuleProgress
    /// events in "records" (rate-limited by the reporter to ~1/sec).
    pub fn with_progress(mut self, reporter: ProgressReporter) -> Self {
        self.progress = Some(reporter);
        self
    }

    /// Attach a cancellation handle; the record-parse loop stops cooperatively
    /// when it fires and returns the artifacts parsed so far.
    pub fn with_cancellation(mut self, handle: CancellationHandle) -> Self {
        self.cancellation = Some(handle);
        self
    }
}

impl ForensicsModule for MftParser {
    fn id(&self) -> &str {
        "plugin.ntfs.mft_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileSystem,
            ArtifactType::FileEntry,
            ArtifactType::RawEvidence,
            ArtifactType::SystemArtifact,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        self.process_records(artifact, None, EVENT_FLUSH_BATCH, false)
    }

    /// Timeline events are handed over in bounded batches while the table is
    /// walked. They are 8 of every 9 artifacts this module makes and the bulk
    /// of its memory (HUNT-125), and nothing later in the pass reads them.
    fn process_streaming(
        &self,
        artifact: &Artifact,
        sink: &mut dyn FnMut(Vec<Artifact>),
    ) -> Result<Vec<Artifact>, ModuleError> {
        self.process_records(artifact, Some(sink), EVENT_FLUSH_BATCH, false)
    }
}

/// How many timeline events are held before being handed to the streaming
/// sink. 8 events per file, about 2.5 KB of heap each: 16,384 of them is ~40 MB.
const EVENT_FLUSH_BATCH: usize = 16_384;

impl MftParser {
    /// The whole `$MFT` pass. With a `sink`, timeline events leave in batches
    /// as they are made and are not in the returned `Vec`; without one they are
    /// returned with everything else, as `process` always did.
    ///
    /// `stream_all` (with a `sink`) sends the file entries and the rest out in
    /// batches too. It is for a caller that wants each record once and keeps
    /// none of them, [`volume_mft::parse_bare_mft_each`]; the set-wide step
    /// that pairs a file with its `-wal` or `.LOG1` sidecar (BUG-257) is not run
    /// on a stream, and a bare `$MFT` has no content to pair.
    fn process_records(
        &self,
        artifact: &Artifact,
        mut sink: Option<&mut dyn FnMut(Vec<Artifact>)>,
        flush_at: usize,
        stream_all: bool,
    ) -> Result<Vec<Artifact>, ModuleError> {
        debug!("MftParser processing artifact ID: {}", artifact.id);
        let mut produced_artifacts = Vec::new();
        // Timeline events awaiting the next flush to `sink`.
        let mut event_batch: Vec<Artifact> = Vec::new();

        // Handle two cases:
        // 1. FileSystem artifact with NTFS filesystem_type metadata
        // 2. FileEntry artifact - use content detection to check if it's an MFT file

        let is_filesystem = artifact.artifact_type == ArtifactType::FileSystem;
        // Only a FileSystem artifact is the volume a run list addresses. A
        // FileEntry, RawEvidence or SystemArtifact that passes the $MFT content
        // check is a bare $MFT: its records are real, but every cluster run in
        // them points into a volume that is not in evidence (HUNT-161).
        let volume_in_evidence = is_filesystem;
        let is_file_entry = artifact.artifact_type == ArtifactType::FileEntry;
        let is_raw_evidence = artifact.artifact_type == ArtifactType::RawEvidence;
        let is_system_artifact = artifact.artifact_type == ArtifactType::SystemArtifact;

        if is_filesystem {
            // Fast path: check subtype first
            if let Some(subtype) = artifact.subtype() {
                if subtype != "ntfs" {
                    return Ok(Vec::new()); // Early exit - not NTFS
                }
            }

            // Fallback: check filesystem_type metadata
            let fs_type = artifact
                .metadata
                .get("filesystem_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if !fs_type.is_empty() && fs_type != "NTFS" {
                debug!("Skipping non-NTFS filesystem ({})", fs_type);
                return Ok(produced_artifacts);
            }
        } else if is_file_entry || is_raw_evidence || is_system_artifact {
            // Recursion guard: an entry this parser published (its own `$MFT`
            // among them) carries the record number it was read from. The
            // name alone is not the test — an examiner's exported `$MFT`,
            // ingested under that name, carries none and is parsed (HUNT-230).
            if artifact.metadata.get("record_number").is_some() {
                debug!(
                    "Skipping artifact {} as it was produced by MFT parser (has record_number)",
                    artifact.id
                );
                return Ok(produced_artifacts);
            }

            // Use content-based detection instead of filename
            if let Some(data_source) = artifact.data.as_ref() {
                // An unreadable header is "could not look", not "not an MFT" (CR-047).
                let detected_type =
                    try_detect_file_type(data_source.as_ref()).map_err(ModuleError::IoError)?;
                if detected_type != DetectedFileType::NtfsMft {
                    // Not an MFT file, skip silently
                    return Ok(produced_artifacts);
                }
                debug!(
                    "Detected MFT file via content analysis (artifact ID: {})",
                    artifact.id
                );
            } else {
                // No data source, cannot be an MFT file
                return Ok(produced_artifacts);
            }
        } else {
            return Ok(produced_artifacts);
        }

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("MFT parser requires a data source".to_string())
        })?;

        // We need an Arc to the datasource to share it with children
        // artifact.data is already Arc<dyn DataSource>, validated above
        let fs_source = Arc::clone(data_source);

        // Cluster size for converting run lists to byte offsets. Prefer the
        // real value from the NTFS boot sector when the input window includes
        // one (FileSystem artifacts). Bare $MFT inputs (e.g. an extracted
        // $MFT file such as the ntfs_frag_mft.bin fixture) carry no boot
        // sector, so fall back to metadata or the common 4096 default.
        let boot_info = if is_filesystem {
            parse_ntfs_boot_sector(data_source.as_ref())
        } else {
            None
        };
        let cluster_size = boot_info
            .as_ref()
            .map(|b| b.cluster_size())
            .or_else(|| {
                artifact
                    .metadata
                    .get("cluster_size")
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(4096);

        // The volume's own record size, from BPB 0x40 -- not a constant.
        //
        // This was hardcoded to 1024, which is what NTFS writes on every
        // volume anyone has measured, and is still a guess: a volume formatted
        // with a different record size would have had every record read at the
        // wrong stride and the whole table come back empty or garbled, with
        // nothing to say why. 4,096-byte records are what a 4K-native disk
        // gets. The fallback stays 1024 for a bare $MFT, where there is no
        // boot sector to ask.
        let mft_record_size: u64 = boot_info
            .as_ref()
            .and_then(|b| b.mft_record_size())
            .or_else(|| {
                artifact
                    .metadata
                    .get("mft_record_size")
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(1024);

        // The table the records are read from. On a volume it is the `$MFT`
        // read through its own runs, from record 0 (or, when that is torn, its
        // `$MFTMirr` copy) — never the volume window. Stepping the window a
        // record at a time published every slot that began `FILE`: the
        // mirror's copies of records 0-3, and on a volume with shadow copies
        // the older records a diff area preserves, each as a live file under
        // the number in its header, so a deleted record came back in use and
        // the name map took whichever copy was read last (HUNT-251).
        //
        // A FileSystem window with no NTFS boot sector that begins with a
        // `FILE` record is read as the table itself (record 0 at offset 0);
        // one with neither is not a volume whose `$MFT` can be found, and the
        // refusal is published rather than a scan for signatures.
        let located = if is_filesystem && boot_info.is_some() {
            volume_mft::locate_volume_mft(data_source)
        } else {
            None
        };
        let mut table_refusal: Option<&'static str> = None;
        let claims_ntfs = artifact.subtype() == Some("ntfs")
            || artifact
                .metadata
                .get("filesystem_type")
                .and_then(|v| v.as_str())
                == Some("NTFS");
        let table: Arc<dyn DataSource> = match &located {
            Some(loc) => loc.table(data_source),
            None if is_filesystem => {
                let mut sig = [0u8; 4];
                let starts_with_record =
                    data_source.read_at(0, &mut sig).ok() == Some(4) && sig == *FILE_SIGNATURE;
                if boot_info.is_some() {
                    table_refusal = Some(
                        "the boot sector names an $MFT whose record 0 does not parse, and \
                         neither does its $MFTMirr copy; the table's runs are unknown, so no \
                         record was read",
                    );
                    Arc::new(ByteSliceDataSource::new(Vec::new()))
                } else if starts_with_record {
                    Arc::clone(data_source)
                } else if !claims_ntfs {
                    // Nothing says this window is NTFS and nothing in it looks
                    // like it: not this module's input.
                    return Ok(produced_artifacts);
                } else {
                    table_refusal = Some(
                        "the window has no NTFS boot sector and does not begin with an MFT \
                         record; the $MFT cannot be located, so no record was read",
                    );
                    Arc::new(ByteSliceDataSource::new(Vec::new()))
                }
            }
            None => Arc::clone(data_source),
        };
        // On the located table a record's number is its slot: that is what a
        // file reference indexes.
        let slot_numbered = located.is_some();

        // First pass: map record number -> (name, parent) for path reconstruction
        let name_map = build_name_map(table.as_ref(), mft_record_size, slot_numbered);

        // $Bitmap (record 6) run list and size, captured during the main pass
        let mut bitmap_runs: Option<Vec<(Option<u64>, u64)>> = None;
        // File slack (HUNT-124): only a FileSystem input is the volume the
        // run lists address, so only there can a tail be read.
        let mut slack = is_filesystem.then(|| {
            SlackCollector::new(
                SlackLabels {
                    filesystem: "NTFS",
                    offset_basis: "the start of this volume, not the start of the evidence",
                },
                cluster_size,
            )
        });
        let mut bitmap_size: Option<u64> = None;

        // Honest denominator for progress: the number of record-sized slots in
        // the table. Each main-loop iteration advances one slot.
        let total_records = table.size() / mft_record_size;

        let mut offset: u64 = 0;

        // Records on the located table whose header names a record number
        // other than their slot. Published under the slot, with the header's
        // number beside it.
        let mut records_misnumbered: u64 = 0;

        // Count of record slots that could not be read (I/O error or short read
        // over a region large enough to hold a full record). These are unreadable
        // holes in the volume, not the end of data; enumeration continues past
        // them and the total is surfaced so partial extraction is never reported
        // as complete.
        let mut records_skipped: u64 = 0;

        // Count of record slots whose Update Sequence Array fixup failed. Such a
        // record is torn: the tail of every sector still holds the USA
        // placeholder instead of the record's own bytes, so names, timestamps
        // and data runs decoded from it are fabricated. They are skipped, and
        // the total is published so their absence is visible (B6-002).
        let mut records_fixup_failed: u64 = 0;

        // Reused across records so the main pass doesn't allocate a fresh 1KB
        // buffer per record. read_at fully overwrites it before any parsing, and
        // record_buf is only ever borrowed below (never moved), so reuse is safe.
        let mut record_buf = vec![0; mft_record_size as usize];

        // Bytes of decompressed LZNT1 content held in memory by the artifacts
        // published so far, reported by `report_retention` (HUNT-125).
        let mut retained_decompressed_bytes: u64 = 0;

        while offset < table.size() {
            // Hand a full batch of timeline events on before making more.
            if event_batch.len() >= flush_at {
                if let Some(sink) = sink.as_mut() {
                    sink(std::mem::take(&mut event_batch));
                }
            }
            if stream_all && produced_artifacts.len() >= flush_at {
                if let Some(sink) = sink.as_mut() {
                    sink(std::mem::take(&mut produced_artifacts));
                }
            }
            if offset > 0 && (offset / mft_record_size).is_multiple_of(RETENTION_REPORT_EVERY) {
                report_retention(
                    offset / mft_record_size,
                    &produced_artifacts,
                    retained_decompressed_bytes,
                );
            }
            // Cooperative cancellation: stop and return what we have so far.
            if let Some(cancel) = &self.cancellation {
                if cancel.is_cancelled(artifact.case_id) {
                    break;
                }
            }
            // Per-record progress (rate-limited internally to ~1/sec).
            if let Some(reporter) = &self.progress {
                reporter.report_for_case(
                    artifact.case_id,
                    artifact.id,
                    offset / mft_record_size,
                    Some(total_records),
                    "records",
                );
            }

            let bytes_read = match table.read_at(offset, &mut record_buf) {
                // A single unreadable region must not abort enumeration: doing so
                // silently drops every later record (files, deleted entries,
                // timestamps) while the output still looks complete. Skip the bad
                // slot and continue; always advance the offset so we cannot loop.
                Err(e) => {
                    debug!(
                        "MFT read error at offset 0x{:X}: {}; skipping record",
                        offset, e
                    );
                    records_skipped += 1;
                    offset += mft_record_size;
                    continue;
                }
                Ok(0) => break, // genuine end of data
                Ok(n) => n,
            };

            if bytes_read < mft_record_size as usize {
                // Short read. When a full record still fits in the volume here it
                // is an unreadable hole, not the end: count it, skip, and keep
                // scanning later records. Only the final partial slot at the tail
                // (no room for a full record) is a genuine end.
                if offset + mft_record_size > table.size() {
                    break;
                }
                debug!(
                    "Short read ({} < {}) at offset 0x{:X}; skipping unreadable MFT record",
                    bytes_read, mft_record_size, offset
                );
                records_skipped += 1;
                offset += mft_record_size;
                continue;
            }

            if record_buf[0..4] == *FILE_SIGNATURE {
                // 1. Parse Header First to get Fixup offsets
                let mut cursor = Cursor::new(&record_buf[..]);
                let header = match parse_header(&mut cursor) {
                    Ok(h) => h,
                    Err(e) => {
                        debug!(
                            "Failed to parse MFT header at offset 0x{:X}: {} (first 16 bytes: {:02X?})",
                            offset, e, &record_buf[..16.min(record_buf.len())]
                        );
                        offset += mft_record_size;
                        continue;
                    }
                };

                // On the located table the slot is the record number; a
                // header that says otherwise is kept beside it, not believed.
                let slot = offset / mft_record_size;
                let header_mismatch =
                    slot_numbered && header.record_number.is_some_and(|n| u64::from(n) != slot);
                // Bare input is numbered by the headers, except where a header
                // has no number: an NTFS 3.0 record's 0x2C is inside its update
                // sequence array (HUNT-256). That record is numbered by its
                // slot, and says so with `record_number_source: "slot"`.
                let numbered_by_slot = !slot_numbered && header.record_number.is_none();
                let record_num: u32 = match header.record_number {
                    Some(n) if !slot_numbered => n,
                    _ => u32::try_from(slot).unwrap_or(u32::MAX),
                };
                // Where the record sits: on the located table, the volume byte
                // offset its run maps the slot to; otherwise the window offset.
                let record_offset = located
                    .as_ref()
                    .and_then(|l| l.volume_offset(offset))
                    .unwrap_or(offset);
                if header_mismatch {
                    records_misnumbered += 1;
                }

                // 2. Apply Fixups. A failure is fatal to the record: the last
                // two bytes of each 512-byte sector still hold the update
                // sequence placeholder rather than the record's real bytes, so
                // attribute headers, $FILE_NAME content and data runs decoded
                // from this buffer are partly invented. Parsing on would
                // publish plausible-looking names, MACB times and cluster runs
                // for a torn record. Skip it and count it (B6-002); the
                // extension-record path already fails closed the same way.
                if let Err(e) = apply_fixups(
                    &mut record_buf,
                    header.update_seq_array_offset as usize,
                    header.update_seq_array_size as usize,
                ) {
                    debug!(
                        "Fixup failed for record #{} at offset 0x{:X}: {} (USA offset={}, size={}); \
                         record skipped as untrustworthy",
                        record_num,
                        offset,
                        e,
                        header.update_seq_array_offset,
                        header.update_seq_array_size
                    );
                    records_fixup_failed += 1;
                    offset += mft_record_size;
                    continue;
                }

                // 3. Parse Attributes
                let mut cursor = Cursor::new(&record_buf[..]);
                cursor.set_position(header.first_attribute_offset as u64);

                let mut standard_info_metadata = serde_json::Map::new();
                let mut filename_metadata = serde_json::Map::new();
                let mut has_filename = false;
                let mut filename_parent: Option<ParentRef> = None;
                let mut filename_namespace: u8 = 0;
                let mut has_index_root = false;
                let mut index_allocation_runs: Option<Vec<(Option<u64>, u64)>> = None;
                let mut index_allocation_start_vcn: u64 = 0;
                // The $I30 index allocation is listed in an extension record
                // but could not be (wholly) recovered from it (HUNT-256).
                let mut i30_incomplete = false;
                let mut primary_data_runs: Option<Vec<(Option<u64>, u64)>> = None;
                let mut primary_data_size: Option<u64> = None;
                // Written prefix of the unnamed $DATA. Paired with
                // primary_data_size: both come from the VCN-0 extent header.
                let mut primary_data_initialized: Option<u64> = None;
                let mut primary_data_start_vcn: u64 = 0;
                let mut primary_resident_data: Option<Vec<u8>> = None;
                let mut primary_data_compressed = false;
                let mut primary_compression_unit: u16 = 0;
                let mut alternate_data_streams: Vec<AdsEntry> = Vec::new();
                let mut has_efs = false;

                // $ATTRIBUTE_LIST state: entries parsed from the resident list,
                // plus the honesty flag set whenever any extent or the list
                // itself could not be fully resolved. When the flag is set the
                // emitted data runs are marked data_runs_complete = false so a
                // partial run list is never presented as whole.
                let mut attr_list_entries: Vec<AttributeListEntry> = Vec::new();
                let mut attr_list_incomplete = false;
                let mut attr_list_nonresident = false;

                // Raw Windows FILETIMEs retained for timestomp analysis.
                // None means absent/invalid (never epoch), matching the
                // filetime_to_datetime contract.
                let mut si_created_raw: Option<u64> = None;
                let mut si_modified_raw: Option<u64> = None;
                let mut si_mft_raw: Option<u64> = None;
                let mut si_accessed_raw: Option<u64> = None;
                let mut fn_created_raw: Option<u64> = None;

                let mut attr_count = 0;

                loop {
                    // Guard against infinite loops on corrupted data
                    attr_count += 1;
                    if attr_count > MAX_ATTRIBUTES {
                        debug!(
                            "Record #{}: Stopping attribute parsing after {} iterations (likely corrupted)",
                            record_num, MAX_ATTRIBUTES
                        );
                        // Attributes past the cap were never examined, so any
                        // $DATA extent among them is missing from the run list
                        // assembled below. The file's runs must not be
                        // presented as a complete description of its content.
                        attr_list_incomplete = true;
                        break;
                    }

                    let attr_header_start = cursor.position();
                    let attr_header = match parse_attribute_header(&mut cursor) {
                        Ok(h) => h,
                        Err(e) => {
                            debug!(
                                "Record #{}: Failed to parse attribute header at offset {}: {}; \
                                 remaining attributes not examined",
                                record_num, attr_header_start, e
                            );
                            // Attributes after the damage were never read, so
                            // any $DATA / ADS / $STANDARD_INFORMATION among them
                            // is missing from what we publish. Only the clean
                            // 0xFFFFFFFF terminator ends this walk completely
                            // (B6-007).
                            attr_list_incomplete = true;
                            break;
                        }
                    };

                    if attr_header.attribute_type == ATTR_TYPE_END {
                        break;
                    }

                    // Guard against infinite loop: if length is 0 or too small, skip
                    if attr_header.length < 16 {
                        debug!(
                            "Record #{}: Malformed attribute at offset {}: type=0x{:X}, length={} (minimum 16); \
                             remaining attributes not examined",
                            record_num, attr_header_start, attr_header.attribute_type, attr_header.length
                        );
                        // A bogus length makes the next attribute unlocatable:
                        // everything past here is lost, not absent (B6-007).
                        attr_list_incomplete = true;
                        break;
                    }

                    let content_abs_offset = attr_header_start + attr_header.content_offset as u64;

                    if !attr_header.non_resident {
                        // Resident
                        if content_abs_offset + attr_header.content_size as u64
                            <= record_buf.len() as u64
                        {
                            let content_slice = &record_buf[content_abs_offset as usize
                                ..(content_abs_offset + attr_header.content_size as u64) as usize];

                            match attr_header.attribute_type {
                                ATTR_TYPE_STANDARD_INFORMATION => {
                                    if content_slice.len() >= 32 {
                                        let c_time = LittleEndian::read_u64(&content_slice[0..8]);
                                        let m_time = LittleEndian::read_u64(&content_slice[8..16]);
                                        let mft_time =
                                            LittleEndian::read_u64(&content_slice[16..24]);
                                        let a_time = LittleEndian::read_u64(&content_slice[24..32]);

                                        // Zero/out-of-range FILETIMEs (timestomping indicator) stay absent
                                        if let Some(dt) =
                                            seance_core::time::filetime_to_datetime(c_time)
                                        {
                                            standard_info_metadata.insert(
                                                "created".to_string(),
                                                json!(dt.to_rfc3339()),
                                            );
                                            si_created_raw = Some(c_time);
                                        }
                                        if let Some(dt) =
                                            seance_core::time::filetime_to_datetime(m_time)
                                        {
                                            standard_info_metadata.insert(
                                                "modified".to_string(),
                                                json!(dt.to_rfc3339()),
                                            );
                                            si_modified_raw = Some(m_time);
                                        }
                                        if let Some(dt) =
                                            seance_core::time::filetime_to_datetime(mft_time)
                                        {
                                            standard_info_metadata.insert(
                                                "mft_modified".to_string(),
                                                json!(dt.to_rfc3339()),
                                            );
                                            si_mft_raw = Some(mft_time);
                                        }
                                        if let Some(dt) =
                                            seance_core::time::filetime_to_datetime(a_time)
                                        {
                                            standard_info_metadata.insert(
                                                "accessed".to_string(),
                                                json!(dt.to_rfc3339()),
                                            );
                                            si_accessed_raw = Some(a_time);
                                        }
                                    }
                                    // NTFS 3.x (the 72-byte form): the key into
                                    // `$Secure:$SDS`, where this file's owner,
                                    // DACL and SACL live. Published raw so the
                                    // descriptor records (keyed by the same id)
                                    // and the USN journal (which carries it on
                                    // every V2/V3 record) can be joined to the
                                    // file (HUNT-178). A 48-byte NTFS 1.2
                                    // attribute has no such field; none is
                                    // invented.
                                    if content_slice.len() >= 0x38 {
                                        standard_info_metadata.insert(
                                            "security_id".to_string(),
                                            json!(LittleEndian::read_u32(
                                                &content_slice[0x34..0x38]
                                            )),
                                        );
                                    }
                                }
                                ATTR_TYPE_FILE_NAME => {
                                    if let Some((name_str, parent, namespace)) =
                                        parse_file_name_attr(content_slice)
                                    {
                                        // Prefer Win32/POSIX names over DOS 8.3 aliases
                                        let replace = !has_filename
                                            || (filename_namespace == FILE_NAMESPACE_DOS
                                                && namespace != FILE_NAMESPACE_DOS);
                                        if replace {
                                            filename_metadata
                                                .insert("name".to_string(), json!(name_str));
                                            // $FILE_NAME MACB: Created 0x08, Modified 0x10,
                                            // MFT-Changed 0x18, Accessed 0x20 (FILETIME each).
                                            // Zero/invalid values stay absent (never epoch),
                                            // mirroring the SI set. Clear any stale values from
                                            // a previously seen (e.g. DOS 8.3) $FILE_NAME first.
                                            for k in [
                                                "fn_created",
                                                "fn_modified",
                                                "fn_mft_modified",
                                                "fn_accessed",
                                            ] {
                                                filename_metadata.remove(k);
                                            }
                                            fn_created_raw = None;
                                            let fn_c =
                                                LittleEndian::read_u64(&content_slice[8..16]);
                                            if let Some(dt) =
                                                seance_core::time::filetime_to_datetime(fn_c)
                                            {
                                                filename_metadata.insert(
                                                    "fn_created".to_string(),
                                                    json!(dt.to_rfc3339()),
                                                );
                                                fn_created_raw = Some(fn_c);
                                            }
                                            let fn_m =
                                                LittleEndian::read_u64(&content_slice[16..24]);
                                            if let Some(dt) =
                                                seance_core::time::filetime_to_datetime(fn_m)
                                            {
                                                filename_metadata.insert(
                                                    "fn_modified".to_string(),
                                                    json!(dt.to_rfc3339()),
                                                );
                                            }
                                            let fn_mft =
                                                LittleEndian::read_u64(&content_slice[24..32]);
                                            if let Some(dt) =
                                                seance_core::time::filetime_to_datetime(fn_mft)
                                            {
                                                filename_metadata.insert(
                                                    "fn_mft_modified".to_string(),
                                                    json!(dt.to_rfc3339()),
                                                );
                                            }
                                            let fn_a =
                                                LittleEndian::read_u64(&content_slice[32..40]);
                                            if let Some(dt) =
                                                seance_core::time::filetime_to_datetime(fn_a)
                                            {
                                                filename_metadata.insert(
                                                    "fn_accessed".to_string(),
                                                    json!(dt.to_rfc3339()),
                                                );
                                            }
                                            filename_parent = Some(parent);
                                            filename_namespace = namespace;
                                            has_filename = true;
                                        }
                                    }
                                }
                                ATTR_TYPE_INDEX_ROOT => {
                                    has_index_root = true;
                                }
                                ATTR_TYPE_ATTRIBUTE_LIST => {
                                    let parsed = parse_attribute_list(content_slice);
                                    if parsed.truncated {
                                        debug!(
                                            "Record #{}: $ATTRIBUTE_LIST is torn/corrupt; \
                                             extents past the damage are unrecoverable",
                                            record_num
                                        );
                                        attr_list_incomplete = true;
                                    }
                                    attr_list_entries.extend(parsed.entries);
                                }
                                ATTR_TYPE_DATA => {
                                    if let Some(stream_name) = extract_attr_name(
                                        &record_buf,
                                        attr_header_start,
                                        &attr_header,
                                    ) {
                                        alternate_data_streams.push(AdsEntry {
                                            name: stream_name,
                                            size: content_slice.len() as u64,
                                            // A resident stream is stored in the
                                            // record: every byte of it is written.
                                            initialized_size: content_slice.len() as u64,
                                            runs: None,
                                            resident_data: Some(content_slice.to_vec()),
                                            start_vcn: 0,
                                            // Resident content is stored
                                            // verbatim; NTFS never compresses it.
                                            compression_unit: 0,
                                        });
                                    } else {
                                        // Unnamed resident $DATA: file content lives in the record itself
                                        primary_resident_data = Some(content_slice.to_vec());
                                    }
                                }
                                ATTR_TYPE_LOGGED_UTILITY_STREAM => {
                                    // $LOGGED_UTILITY_STREAM with name "$EFS" indicates EFS encryption
                                    if let Some(ref stream_name) = extract_attr_name(
                                        &record_buf,
                                        attr_header_start,
                                        &attr_header,
                                    ) {
                                        if stream_name == "$EFS" {
                                            has_efs = true;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    } else {
                        // Non-Resident
                        let runs_offset_abs =
                            attr_header_start + attr_header.data_runs_offset as u64;
                        // The run list lives INSIDE this attribute. Slicing to
                        // the end of the record instead lets a run list with no
                        // 0x00 terminator keep decoding the next attribute's
                        // header bytes as runs, fabricating LCNs and lengths for
                        // this file while `data_runs_complete` still reads true
                        // (B6-003).
                        let attr_end = (attr_header_start + attr_header.length as u64)
                            .min(record_buf.len() as u64);
                        if runs_offset_abs < attr_end {
                            let runs_slice =
                                &record_buf[runs_offset_abs as usize..attr_end as usize];
                            let (raw_runs, runs_truncated) = parse_data_runs_checked(runs_slice);
                            // Hitting the run cap means this attribute's runs were
                            // dropped past the cap; flag the file's data as
                            // incomplete so it is never presented as whole.
                            if runs_truncated {
                                attr_list_incomplete = true;
                            }

                            // Convert runs to byte offsets
                            let byte_runs: Vec<(Option<u64>, u64)> = raw_runs
                                .into_iter()
                                .map(|(lcn, len)| {
                                    // Cluster values come from an attacker-controlled runlist;
                                    // saturate rather than overflow. Reads through the run list
                                    // are bounded by the data source and the resolver's cap.
                                    let byte_offset = lcn.map(|l| l.saturating_mul(cluster_size));
                                    let byte_len = len.saturating_mul(cluster_size);
                                    (byte_offset, byte_len)
                                })
                                .collect();

                            match attr_header.attribute_type {
                                ATTR_TYPE_INDEX_ALLOCATION => {
                                    index_allocation_start_vcn = attr_header.start_vcn;
                                    index_allocation_runs = Some(byte_runs);
                                }
                                ATTR_TYPE_ATTRIBUTE_LIST => {
                                    // A non-resident $ATTRIBUTE_LIST means the list
                                    // itself is spread across clusters described by
                                    // its own run list. Resolving that (reading the
                                    // list's runs, then the records it names) is
                                    // DEFERRED: it is rare (thousands of extents)
                                    // and needs a second chase level. What must NOT
                                    // happen is silent truncation, so flag the
                                    // file's runs as incomplete.
                                    attr_list_nonresident = true;
                                }
                                ATTR_TYPE_DATA => {
                                    if let Some(stream_name) = extract_attr_name(
                                        &record_buf,
                                        attr_header_start,
                                        &attr_header,
                                    ) {
                                        alternate_data_streams.push(AdsEntry {
                                            name: stream_name,
                                            size: attr_header.real_size,
                                            initialized_size: attr_header.initialized_size,
                                            runs: Some(byte_runs),
                                            resident_data: None,
                                            start_vcn: attr_header.start_vcn,
                                            compression_unit: attr_header.compression_unit,
                                        });
                                    } else {
                                        primary_data_runs = Some(byte_runs);
                                        primary_data_size = Some(attr_header.real_size);
                                        primary_data_initialized =
                                            Some(attr_header.initialized_size);
                                        primary_data_start_vcn = attr_header.start_vcn;
                                        // compression_unit != 0 marks an LZNT1-compressed $DATA;
                                        // the field is log2 of clusters per unit.
                                        primary_data_compressed = attr_header.compression_unit != 0;
                                        primary_compression_unit = attr_header.compression_unit;
                                    }
                                }
                                ATTR_TYPE_LOGGED_UTILITY_STREAM => {
                                    if let Some(ref stream_name) = extract_attr_name(
                                        &record_buf,
                                        attr_header_start,
                                        &attr_header,
                                    ) {
                                        if stream_name == "$EFS" {
                                            has_efs = true;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        } else {
                            // data_runs_offset points past the end of this
                            // attribute (or of the MFT record): its extents are
                            // unreadable. Silently emitting no runs would
                            // present a non-resident file as having no content
                            // rather than as content we could not locate.
                            debug!(
                                "Record {}: non-resident attribute 0x{:X} data_runs_offset {} \
                                 past end of attribute/record ({} bytes); runs unreadable",
                                record_num,
                                attr_header.attribute_type,
                                runs_offset_abs,
                                record_buf.len()
                            );
                            attr_list_incomplete = true;
                        }
                    }

                    // Advance to next attribute
                    cursor.set_position(attr_header_start + attr_header.length as u64);
                }

                // --- $ATTRIBUTE_LIST resolution -----------------------------
                // Attributes of this file may continue in extension MFT
                // records. Merge the recovered fragments into the run lists
                // built above, ordered by each extent's lowest_vcn. Anything
                // unrecoverable sets attr_list_incomplete so the emitted runs
                // are flagged data_runs_complete = false, never silently
                // truncated.
                if attr_list_nonresident {
                    attr_list_incomplete = true;
                }
                if !attr_list_entries.is_empty() {
                    let resolution = resolve_extension_records(
                        table.as_ref(),
                        mft_record_size,
                        cluster_size,
                        record_num as u64,
                        &attr_list_entries,
                    );
                    attr_list_incomplete |= resolution.incomplete;

                    // The directory's $I30 index allocation: base extent (if
                    // any) plus extension fragments, in VCN order. A listed
                    // extent that could not be recovered, or a gap between
                    // extents, marks the index incomplete (HUNT-256).
                    i30_incomplete |= resolution.i30_incomplete;
                    if !resolution.i30_fragments.is_empty() {
                        let mut frags: Vec<VcnFragment> = Vec::new();
                        if let Some(runs) = index_allocation_runs.take() {
                            frags.push((index_allocation_start_vcn, runs));
                        }
                        for f in &resolution.i30_fragments {
                            frags.push((f.lowest_vcn, f.byte_runs.clone()));
                        }
                        let (merged, gapped) = merge_vcn_fragments(frags, cluster_size);
                        i30_incomplete |= gapped;
                        index_allocation_runs = Some(merged);
                    } else if resolution.i30_listed && index_allocation_runs.is_none() {
                        // Listed, but nothing recovered: publish the stream as
                        // known to exist and unreadable, not drop it.
                        index_allocation_runs = Some(Vec::new());
                    }

                    // Unnamed primary $DATA: base extent plus extension fragments.
                    if resolution.fragments.iter().any(|f| f.name.is_none()) {
                        let mut frags: Vec<VcnFragment> = Vec::new();
                        if let Some(runs) = primary_data_runs.take() {
                            frags.push((primary_data_start_vcn, runs));
                        }
                        for f in resolution.fragments.iter().filter(|f| f.name.is_none()) {
                            frags.push((f.lowest_vcn, f.byte_runs.clone()));
                        }
                        let (merged, gapped) = merge_vcn_fragments(frags, cluster_size);
                        attr_list_incomplete |= gapped;
                        primary_data_runs = Some(merged);
                        if primary_data_size.is_none() {
                            primary_data_size = resolution
                                .fragments
                                .iter()
                                .filter(|f| f.name.is_none())
                                .map(|f| f.real_size)
                                .max();
                        }
                        if primary_data_initialized.is_none() {
                            primary_data_initialized = resolution
                                .fragments
                                .iter()
                                .filter(|f| f.name.is_none())
                                .map(|f| f.initialized_size)
                                .max();
                        }
                        // An unnamed $DATA that lives only in extension records
                        // carries its compression unit there. Missing it would
                        // hand the compressed cluster image to the hasher as
                        // plaintext (B6-004).
                        if primary_compression_unit == 0 {
                            primary_compression_unit = resolution
                                .fragments
                                .iter()
                                .filter(|f| f.name.is_none())
                                .map(|f| f.compression_unit)
                                .max()
                                .unwrap_or(0);
                            primary_data_compressed =
                                primary_data_compressed || primary_compression_unit != 0;
                        }
                    }

                    // Named streams (ADS), grouped by stream name. A stream
                    // resident in the base record has no run list to merge
                    // into; leave it untouched.
                    let mut stream_names: Vec<&str> = resolution
                        .fragments
                        .iter()
                        .filter_map(|f| f.name.as_deref())
                        .collect();
                    stream_names.sort_unstable();
                    stream_names.dedup();
                    for stream_name in stream_names {
                        let mut frags: Vec<VcnFragment> = Vec::new();
                        let mut size: u64 = 0;
                        let mut initialized: u64 = 0;
                        let mut compression_unit: u16 = 0;
                        for f in resolution
                            .fragments
                            .iter()
                            .filter(|f| f.name.as_deref() == Some(stream_name))
                        {
                            frags.push((f.lowest_vcn, f.byte_runs.clone()));
                            size = size.max(f.real_size);
                            initialized = initialized.max(f.initialized_size);
                            compression_unit = compression_unit.max(f.compression_unit);
                        }
                        if let Some(ads) = alternate_data_streams
                            .iter_mut()
                            .find(|a| a.name == stream_name)
                        {
                            if ads.runs.is_none() {
                                continue; // resident stream: nothing to merge into
                            }
                            frags.push((ads.start_vcn, ads.runs.take().unwrap_or_default()));
                            size = size.max(ads.size);
                            initialized = initialized.max(ads.initialized_size);
                            compression_unit = compression_unit.max(ads.compression_unit);
                            let (merged, gapped) = merge_vcn_fragments(frags, cluster_size);
                            attr_list_incomplete |= gapped;
                            ads.runs = Some(merged);
                            ads.size = size;
                            ads.initialized_size = initialized;
                            ads.compression_unit = compression_unit;
                        } else {
                            let (merged, gapped) = merge_vcn_fragments(frags, cluster_size);
                            attr_list_incomplete |= gapped;
                            alternate_data_streams.push(AdsEntry {
                                name: stream_name.to_string(),
                                size,
                                initialized_size: initialized,
                                runs: Some(merged),
                                resident_data: None,
                                start_vcn: 0,
                                compression_unit,
                            });
                        }
                    }
                }

                if has_filename {
                    // Combine metadata
                    for (k, v) in standard_info_metadata.clone() {
                        filename_metadata.insert(k, v);
                    }
                    filename_metadata.insert("record_number".to_string(), json!(record_num));
                    // The sequence number, which is what separates this file
                    // from the next one to occupy the record. NTFS frees a
                    // record on delete and increments the sequence when it is
                    // reused, so a reference naming record 4,712 means nothing
                    // without it — every structure that points at a file by
                    // reference (the USN journal, an $ATTRIBUTE_LIST base
                    // reference, a directory index entry) carries both halves,
                    // and the reader published only one. Without it a journal
                    // delete for a record this MFT still holds cannot be told
                    // apart from the record having been recycled, which is the
                    // ordinary case (§2.2 detection 6).
                    filename_metadata
                        .insert("sequence_number".to_string(), json!(header.sequence_number));
                    filename_metadata.insert("mft_offset".to_string(), json!(record_offset));
                    if let (true, Some(n)) = (header_mismatch, header.record_number) {
                        filename_metadata.insert("header_record_number".to_string(), json!(n));
                    }
                    if numbered_by_slot {
                        filename_metadata.insert("record_number_source".to_string(), json!("slot"));
                    }

                    // This parser emits its own TimelineEvent for EVERY
                    // timestamp it writes onto this entry -- both the $SI and
                    // the $FN set, each labelled with the attribute it came
                    // from and carrying the timestomping verdict. Say so, or
                    // the storage layer's generic FileEntry projection would
                    // report every NTFS file a second time at the same instant.
                    filename_metadata.insert(
                        seance_core::artifact::FILE_TIMELINE_SELF_EMITTED_KEY.to_string(),
                        json!(true),
                    );

                    // Full path reconstruction from the first-pass name map.
                    // Records whose parent chain is broken or cyclic land in
                    // the synthetic /$OrphanFiles directory.
                    let record_ref = record_num as u64;
                    let entry_name = filename_metadata
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    let mut orphan_reason: Option<OrphanReason> = None;
                    let (path, parent_path) = if record_ref == ROOT_RECORD {
                        ("/".to_string(), "/".to_string())
                    } else {
                        let resolved = match filename_parent {
                            Some(p) => resolve_dir_path(&name_map, p),
                            None => Err(OrphanReason::ParentMissing),
                        };
                        match resolved {
                            Ok(pp) => {
                                let full = if pp == "/" {
                                    format!("/{}", entry_name)
                                } else {
                                    format!("{}/{}", pp, entry_name)
                                };
                                (full, pp)
                            }
                            Err(reason) => {
                                orphan_reason = Some(reason);
                                (
                                    format!("/$OrphanFiles/{}", entry_name),
                                    "/$OrphanFiles".to_string(),
                                )
                            }
                        }
                    };
                    filename_metadata.insert("path".to_string(), json!(path.clone()));
                    filename_metadata.insert("parent_path".to_string(), json!(parent_path.clone()));
                    if let Some(reason) = orphan_reason {
                        // The path above is a placeholder, and the record says
                        // why: an examiner reading `$OrphanFiles` needs to know
                        // whether the directory is gone or merely reused.
                        filename_metadata
                            .insert("orphan_reason".to_string(), json!(reason.as_str()));
                    }

                    // The unnamed $DATA reduced to the file's logical content:
                    // cluster slack past real_size dropped, the never-written
                    // range [initialized_size, real_size) turned into zeros.
                    // Everything downstream (metadata runs, ingest hashing,
                    // search indexing) must see the file, not the clusters.
                    // Compressed $DATA is excluded: its runs describe the
                    // on-disk compressed image, whose length is unrelated to
                    // real_size, and the resolver decompresses them as-is.
                    let primary_content_runs: Option<Vec<VcnRun>> = match (
                        primary_data_runs.as_ref(),
                        primary_data_size,
                        primary_data_compressed,
                    ) {
                        (Some(runs), Some(real), false) => Some(logical_extent_runs(
                            runs,
                            // An absent initialized_size (extension-only $DATA)
                            // must not blank the file: assume fully written.
                            primary_data_initialized.unwrap_or(real),
                            real,
                        )),
                        _ => primary_data_runs.clone(),
                    };

                    // Persist data location per the metadata contract: cluster
                    // runs (byte offsets within the filesystem window) for
                    // non-resident files, inline base64 content for resident.
                    if !has_index_root {
                        if primary_data_compressed && primary_compression_unit > 0 {
                            // Compressed $DATA: persist the on-disk (compressed)
                            // runs plus a compression descriptor. The content
                            // resolver decompresses on demand (no size cap, no
                            // inlined bytes in the DB).
                            if let Some(ref runs) = primary_data_runs {
                                let (runs_json, complete) = byte_runs_to_metadata(runs);
                                filename_metadata.insert("data_runs".to_string(), runs_json);
                                filename_metadata.insert(
                                    "data_runs_complete".to_string(),
                                    json!(complete && !attr_list_incomplete),
                                );
                                stamp_runs_incompleteness(
                                    &mut filename_metadata,
                                    complete,
                                    attr_list_incomplete,
                                );
                                filename_metadata
                                    .insert("compression".to_string(), json!("ntfs_lznt1"));
                                match compression_unit_bytes(primary_compression_unit, cluster_size)
                                {
                                    Some(unit_size) => {
                                        filename_metadata.insert(
                                            "compression_unit_bytes".to_string(),
                                            json!(unit_size),
                                        );
                                    }
                                    None => {
                                        // The exponent is out of range: the field is
                                        // corrupt. Say so rather than invent a size.
                                        filename_metadata.insert(
                                            "compression_unit_invalid".to_string(),
                                            json!(true),
                                        );
                                        filename_metadata.insert(
                                            "compression_unit_exponent".to_string(),
                                            json!(primary_compression_unit),
                                        );
                                    }
                                }
                            }
                        } else if let Some(ref runs) = primary_content_runs {
                            let (runs_json, complete) = byte_runs_to_metadata(runs);
                            filename_metadata.insert("data_runs".to_string(), runs_json);
                            filename_metadata.insert(
                                "data_runs_complete".to_string(),
                                json!(complete && !attr_list_incomplete),
                            );
                            stamp_runs_incompleteness(
                                &mut filename_metadata,
                                complete,
                                attr_list_incomplete,
                            );
                        } else if let Some(ref data) = primary_resident_data {
                            filename_metadata.insert(
                                "resident_data_b64".to_string(),
                                json!(BASE64.encode(data)),
                            );
                        }

                        // Logical file size (the $DATA real_size, or the
                        // resident content length). Without it the file grid
                        // shows no size and the content resolver cannot trim
                        // cluster slack from served/downloaded content.
                        let logical_size = primary_data_size
                            .or_else(|| primary_resident_data.as_ref().map(|d| d.len() as u64));
                        if let Some(sz) = logical_size {
                            filename_metadata.insert("size".to_string(), json!(sz));
                        }
                    }

                    // Directory-ness has two independent signals: a resident
                    // $INDEX_ROOT, and bit 1 of the MFT record header flags.
                    // Reading only the first meant a record whose $INDEX_ROOT
                    // was lost (torn attribute walk, deleted directory whose
                    // index was reused) was published as a FILE (B6-033).
                    let header_says_directory = header.flags & 0x0002 != 0;
                    if has_index_root || header_says_directory {
                        filename_metadata.insert("is_directory".to_string(), json!(true));
                        if !has_index_root {
                            // The index itself was not recovered, so this
                            // directory's children are not enumerated from here.
                            filename_metadata.insert(
                                "is_directory_source".to_string(),
                                json!("mft_record_flag"),
                            );
                        }
                    }

                    if has_efs {
                        filename_metadata.insert("efs_encrypted".to_string(), json!(true));
                        // The $DATA runs of an EFS file address ciphertext this
                        // parser does not decrypt. Without this marker the
                        // served bytes and the stored hash look like ordinary
                        // plaintext file content, and an examiner comparing
                        // them against a known-file hash set would report a
                        // non-match as if the file itself differed. Mirrors the
                        // ext4/F2FS fscrypt markers.
                        filename_metadata
                            .insert("content_ciphertext".to_string(), json!("ntfs_efs"));
                        // `content_incomplete` is the flag the API, export and
                        // integrity-verify paths read; `content_ciphertext` is
                        // for display. Without it EFS ciphertext travels the
                        // same path as plaintext and its digest is recorded as
                        // the digest of the file's actual bytes. Mirrors the
                        // ext4/F2FS fscrypt markers.
                        filename_metadata.insert("content_incomplete".to_string(), json!(true));
                        filename_metadata.insert(
                            "content_incomplete_reason".to_string(),
                            json!(IncompleteReason::Encrypted.as_str()),
                        );
                    }

                    if primary_data_compressed {
                        // Informational: the $DATA is LZNT1-compressed. It is
                        // decompressed when the file source is built below;
                        // "compression_unsupported" is set only if that path
                        // cannot handle it (oversized file).
                        filename_metadata.insert("compressed".to_string(), json!(true));
                    }

                    // Check IN_USE flag (bit 0) to detect deleted files
                    if header.flags & 0x0001 == 0 {
                        filename_metadata.insert("deleted".to_string(), json!(true));
                        filename_metadata
                            .insert("deleted_recovery_source".to_string(), json!("mft"));
                        // The runs are right about WHERE the file was; nothing
                        // says the bytes there are still its own. NTFS frees
                        // the clusters on deletion, so any of them may since
                        // have been reallocated to another file — and the
                        // content served would then be that file's, under this
                        // name, with this file's size and timestamps beside it.
                        //
                        // `content_incomplete` is the flag the API, export and
                        // integrity-verify paths read. Without it a digest of
                        // whatever now occupies those clusters is recorded as
                        // the digest of this file's bytes, which is how a
                        // hash-set comparison reports a non-match as though the
                        // file itself differed. The FAT reader already marks its
                        // own deleted recoveries for the same reason (B2-160);
                        // this is the same claim, unqualified until now.
                        filename_metadata.insert(
                            "deleted_content_caveat".to_string(),
                            json!("clusters_may_be_reallocated"),
                        );
                        if !filename_metadata.contains_key("content_incomplete") {
                            filename_metadata.insert("content_incomplete".to_string(), json!(true));
                            filename_metadata.insert(
                                "content_incomplete_reason".to_string(),
                                json!(IncompleteReason::UnresolvedStructure.as_str()),
                            );
                        }
                    }

                    // Timestamp indicators from the SI/FN comparison. Always
                    // stamped so downstream consumers get a stable shape.
                    //
                    // `timestomp_suspected` is the VERDICT and is true only for
                    // a strong indicator — one no ordinary copy, move or rename
                    // produces. The weak indicators are still reported, each
                    // with the ordinary operation that explains it, because an
                    // examiner may want to see them; what they must not do is
                    // put a tampering verdict on a sixth of a stock Windows
                    // install (HUNT-051).
                    let indicators = detect_timestomp_indicators(
                        si_created_raw,
                        si_modified_raw,
                        si_mft_raw,
                        si_accessed_raw,
                        fn_created_raw,
                    );
                    let strong = indicators.iter().any(|i| i.strong);
                    let timestomp_reasons: Vec<String> = indicators
                        .iter()
                        .filter(|i| i.strong)
                        .map(|i| i.reason.clone())
                        .collect();
                    filename_metadata.insert("timestomp_suspected".to_string(), json!(strong));
                    // Kept for consumers that read it: the reasons BEHIND the
                    // verdict, so a reader of this key alone is never handed a
                    // benign copy's fingerprint as grounds for one.
                    filename_metadata
                        .insert("timestomp_reasons".to_string(), json!(timestomp_reasons));
                    if !indicators.is_empty() {
                        filename_metadata.insert(
                            "timestamp_indicators".to_string(),
                            json!(indicators
                                .iter()
                                .map(|i| json!({
                                    "reason": i.reason,
                                    "strength": if i.strong { "strong" } else { "weak" },
                                    "also_produced_by": i.benign_explanation,
                                }))
                                .collect::<Vec<_>>()),
                        );
                    }

                    // Capture the $Bitmap run list for the allocation map,
                    // emitted after the scan completes.
                    if record_ref == BITMAP_RECORD && entry_name == "$Bitmap" {
                        bitmap_runs = primary_data_runs.clone();
                        bitmap_size = primary_data_size;
                    }

                    // Construct artifact with DATA if we found $DATA runs
                    // Note: Currently MFT parser emits FileEntry which is metadata only usually.
                    // But for BadClus, we want data attached.
                    let mut file_data_source = None;
                    if !volume_in_evidence && primary_data_runs.is_some() {
                        // A bare $MFT: the runs address a volume that is not
                        // here, and applied against this file they "read" other
                        // MFT records (HUNT-161). Nothing is served — neither
                        // the raw runs nor an LZNT1 reconstruction from them;
                        // the run list is still published below.
                        stamp_volume_not_in_evidence(
                            &mut filename_metadata,
                            primary_data_size.unwrap_or(0),
                        );
                    } else if primary_data_compressed && primary_compression_unit > 0 {
                        let logical = primary_data_size.unwrap_or(0);
                        let unit_size =
                            compression_unit_bytes(primary_compression_unit, cluster_size);
                        // Each way a compressed $DATA can fail to resolve gets
                        // its OWN reason code — the same four-way split the ADS
                        // path below makes, and for the same reason. This path
                        // kept the old shape after the ADS one was fixed, so a
                        // corrupt compression exponent on a stream that was also
                        // empty or over the cap fell through to
                        // "ntfs_lznt1_oversize" on a record already stamped
                        // `compression_unit_invalid` — the self-contradiction the
                        // ADS comment says was removed — and a zero-length stream
                        // was marked `content_incomplete` when there was never
                        // any content to be missing (CR-033 #6). The reason code
                        // is what an examiner reads to decide whether to pursue
                        // the data another way, so a wrong one costs real work.
                        match (primary_data_runs.as_ref(), unit_size) {
                            (Some(runs), Some(unit))
                                if logical > 0 && logical <= NTFS_DECOMPRESS_CAP =>
                            {
                                // LZNT1-compressed: reconstruct the logical content in
                                // memory for ingest indexing. Re-serving is handled by
                                // the resolver via the compression descriptor above.
                                match seance_core::compression::decompress_ntfs_data(
                                    &fs_source, runs, unit, logical,
                                ) {
                                    Ok(data) => {
                                        // Anything large goes to a temp file, not
                                        // the heap: held in memory this was the
                                        // sum of every compressed file on the
                                        // volume (HUNT-125).
                                        if data.len() < SPILL_THRESHOLD_BYTES {
                                            retained_decompressed_bytes += data.len() as u64;
                                        }
                                        file_data_source = Some(spill_or_hold(data));
                                    }
                                    Err(e) => {
                                        // Truncated/corrupt compressed $DATA: do not
                                        // fabricate zero-padded content for the index.
                                        // The artifact is still recorded from metadata;
                                        // content resolution errors honestly (BUG-046).
                                        // It must also SAY so: a sized FileEntry with
                                        // no content and no incompleteness flag is
                                        // indistinguishable from an empty file.
                                        filename_metadata
                                            .insert("content_incomplete".to_string(), json!(true));
                                        filename_metadata.insert(
                                            "content_incomplete_reason".to_string(),
                                            json!(IncompleteReason::Compressed.as_str()),
                                        );
                                        filename_metadata.insert(
                                            "compression_unsupported".to_string(),
                                            json!("ntfs_lznt1_decompress_failed"),
                                        );
                                        debug!(
                                            "Compressed $DATA reconstruction failed; \
                                             leaving content unavailable: {}",
                                            e
                                        );
                                    }
                                }
                            }
                            (_, None) => {
                                // The exponent did not yield a unit size, so there
                                // is no way to walk the compressed runs at all.
                                // Named as what it is; the exponent itself was
                                // recorded with `compression_unit_invalid` above.
                                filename_metadata.insert(
                                    "compression_unsupported".to_string(),
                                    json!("ntfs_lznt1_invalid_compression_unit"),
                                );
                                filename_metadata
                                    .insert("content_incomplete".to_string(), json!(true));
                                filename_metadata.insert(
                                    "content_incomplete_reason".to_string(),
                                    json!(IncompleteReason::Compressed.as_str()),
                                );
                            }
                            (None, _) => {
                                // Compressed, with no run list to decompress from.
                                // Nothing describes where the bytes are.
                                filename_metadata.insert(
                                    "compression_unsupported".to_string(),
                                    json!("ntfs_lznt1_no_run_list"),
                                );
                                filename_metadata
                                    .insert("content_incomplete".to_string(), json!(true));
                                filename_metadata.insert(
                                    "content_incomplete_reason".to_string(),
                                    json!(IncompleteReason::Compressed.as_str()),
                                );
                            }
                            (Some(_), Some(_)) if logical == 0 => {
                                // A zero-length stream: there is no content to be
                                // missing, so this is NOT marked incomplete. Marking
                                // it so would have the report count a file as
                                // content that could not be read when there was
                                // never any content to read.
                                filename_metadata.insert(
                                    "compression_unsupported".to_string(),
                                    json!("ntfs_lznt1_zero_length"),
                                );
                            }
                            (Some(_), Some(_)) => {
                                // Too large to reconstruct in memory at ingest.
                                // The runs describe compressed clusters, so
                                // attaching them would hand the hash plugin and
                                // the search index the compressed image under
                                // this file's name — bytes that are not the
                                // file's content and whose digest matches
                                // nothing. Leave content unresolved at ingest
                                // and say so; the resolver still decompresses
                                // on demand when the file is served.
                                filename_metadata.insert(
                                    "compression_unsupported".to_string(),
                                    json!("ntfs_lznt1_oversize"),
                                );
                                filename_metadata
                                    .insert("content_incomplete".to_string(), json!(true));
                                filename_metadata.insert(
                                    "content_incomplete_reason".to_string(),
                                    json!(IncompleteReason::Compressed.as_str()),
                                );
                                debug!(
                                    "Record #{}: LZNT1 $DATA of {} bytes exceeds the \
                                     ingest decompression cap; content left unresolved",
                                    record_num, logical
                                );
                            }
                        }
                    } else if let Some(ref runs) = primary_content_runs {
                        // `primary_content_runs` is already reduced to the
                        // logical extent, so this is a no-op today. Stating the
                        // size keeps it one: a run list allocates whole
                        // clusters, and serving the trailing slack would put
                        // the previous occupant's bytes into this file's hex
                        // view, download, export and hash.
                        let source = RunListDataSource::with_logical_size(
                            fs_source.clone(),
                            runs.clone(),
                            primary_data_size.unwrap_or(0),
                        );
                        file_data_source = Some(Arc::new(source) as Arc<dyn DataSource>);
                    } else if let Some(ref data) = primary_resident_data {
                        file_data_source =
                            Some(Arc::new(ByteSliceDataSource::new(data.clone()))
                                as Arc<dyn DataSource>);
                    }

                    // Record ADS count on the parent FileEntry. This has to
                    // happen BEFORE the artifact is built: `json!` serialises a
                    // SNAPSHOT of the map, so the map stays usable afterwards
                    // (the ADS loop below still reads `name` out of it) and
                    // anything inserted after this point silently never reaches
                    // the record. A file with hidden streams then looks, on its
                    // own entry, exactly like a file with none.
                    if !alternate_data_streams.is_empty() {
                        filename_metadata
                            .insert("ads_count".to_string(), json!(alternate_data_streams.len()));
                        let ads_names: Vec<&str> = alternate_data_streams
                            .iter()
                            .map(|a| a.name.as_str())
                            .collect();
                        filename_metadata.insert("ads_names".to_string(), json!(ads_names));
                    }

                    let file_entry_artifact = Artifact::new(
                        artifact.case_id,
                        ArtifactType::FileEntry,
                        file_data_source,
                        json!(filename_metadata),
                    )
                    .with_parent(artifact.id);

                    let file_entry_id = file_entry_artifact.id;
                    produced_artifacts.push(file_entry_artifact);

                    // The unused tail of the file's last cluster, offered only
                    // when the allocation is fully described and is the
                    // file's own: a live, non-resident, uncompressed,
                    // unencrypted, non-directory primary $DATA whose run list
                    // is complete from VCN 0. A deleted file's clusters may
                    // belong to someone else now, and a compressed file's
                    // runs are not its logical bytes (HUNT-124). A live file
                    // with a tail that is refused on those grounds, or whose
                    // run list is shorter than its size, is counted on the
                    // summary as not located.
                    if let (Some(collector), Some(runs), Some(logical)) = (
                        slack.as_mut(),
                        primary_data_runs.as_ref(),
                        primary_data_size,
                    ) {
                        let live_file = header.flags & 0x0001 != 0
                            && header.flags & 0x0002 == 0
                            && !has_index_root;
                        let described = !primary_data_compressed
                            && !has_efs
                            && !attr_list_incomplete
                            && (primary_data_start_vcn == 0 || !attr_list_entries.is_empty());
                        let has_tail =
                            logical > 0 && cluster_size > 0 && logical % cluster_size != 0;
                        if live_file && has_tail && !described {
                            // A compressed or encrypted file's runs are not
                            // its logical bytes, and an incomplete run list
                            // may place the tail wrongly: the tail exists but
                            // could not be located. Counted, not dropped.
                            collector.not_located();
                        } else if live_file && has_tail {
                            match locate_slack(runs, logical, cluster_size) {
                                SlackLocation::Window(window) => {
                                    let name = filename_metadata
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Unknown");
                                    let path =
                                        filename_metadata.get("path").and_then(|v| v.as_str());
                                    collector.offer(
                                        artifact,
                                        &fs_source,
                                        SlackOwner {
                                            artifact_id: file_entry_id,
                                            name,
                                            path,
                                            logical_size: logical,
                                        },
                                        window,
                                    );
                                }
                                SlackLocation::Undescribed => collector.not_located(),
                                SlackLocation::NoTail => {}
                            }
                        }
                    }

                    // Emit child artifacts for each Alternate Data Stream
                    let parent_file_name = filename_metadata
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    for ads in &alternate_data_streams {
                        let ads_full_name = format!("{}:{}", parent_file_name, ads.name);
                        let ads_compressed = ads.compression_unit != 0;

                        // Same logical-extent reduction as the unnamed $DATA: a
                        // stream is hashed and served as its own bytes, not as
                        // the clusters that happen to hold it.
                        //
                        // A COMPRESSED stream is excluded from that reduction
                        // exactly as the unnamed $DATA is: its runs describe the
                        // on-disk compressed image, whose length has nothing to
                        // do with `size`, and trimming it to `size` would cut
                        // the compressed data mid-unit (B6-004).
                        let ads_content_runs: Option<Vec<VcnRun>> = if ads_compressed {
                            ads.runs.clone()
                        } else {
                            ads.runs.as_ref().map(|runs| {
                                logical_extent_runs(runs, ads.initialized_size, ads.size)
                            })
                        };

                        let mut ads_metadata = json!({
                            "name": ads_full_name,
                            "stream_name": ads.name,
                            "size": ads.size,
                            "is_ads": true,
                            "parent_file": parent_file_name,
                            "record_number": record_num,
                            // Both halves of the reference; see the unnamed
                            // $DATA path above for why one is not enough.
                            "sequence_number": header.sequence_number,
                            "path": format!("{}:{}", path, ads.name),
                            "parent_path": parent_path.clone(),
                        });
                        if numbered_by_slot {
                            ads_metadata["record_number_source"] = json!("slot");
                        }

                        // Serving/hashing the raw compressed clusters under the
                        // stream's name produces bytes that are not the stream's
                        // content and a digest that matches nothing. Reconstruct
                        // the plaintext for ingest exactly as the unnamed $DATA
                        // does, and publish the descriptor the content resolver
                        // needs to decompress on demand (B6-004).
                        let mut ads_decompressed: Option<Vec<u8>> = None;
                        // A bare $MFT: see the unnamed $DATA above (HUNT-161).
                        let ads_unservable = !volume_in_evidence && ads.runs.is_some();
                        if ads_unservable {
                            if let Some(map) = ads_metadata.as_object_mut() {
                                stamp_volume_not_in_evidence(map, ads.size);
                            }
                        }
                        if ads_compressed {
                            ads_metadata["compressed"] = json!(true);
                            ads_metadata["compression"] = json!("ntfs_lznt1");
                            // A corrupt exponent has no valid unit size; record that
                            // rather than a fabricated number or a panic.
                            let unit_size =
                                compression_unit_bytes(ads.compression_unit, cluster_size);
                            match unit_size {
                                Some(u) => ads_metadata["compression_unit_bytes"] = json!(u),
                                None => {
                                    ads_metadata["compression_unit_invalid"] = json!(true);
                                    ads_metadata["compression_unit_exponent"] =
                                        json!(ads.compression_unit);
                                }
                            }
                            // Each way this can fail gets its OWN reason code.
                            // Everything that was not decompressible used to fall
                            // through one arm stamped "ntfs_lznt1_oversize", which
                            // is a claim about the stream's SIZE: it tells the
                            // examiner the data is there and merely too large,
                            // which on this path also implies the resolver will
                            // decompress it on demand. For three of the four
                            // conditions that is false — a corrupt compression
                            // descriptor (already recorded as
                            // `compression_unit_invalid` two lines above, so the
                            // record contradicted itself), no run list at all, and
                            // a zero-length stream are none of them oversize, and
                            // no resolver will ever recover them. `content_
                            // incomplete_reason` is what an examiner reads to
                            // decide whether to pursue the data another way, so a
                            // wrong reason there costs real work.
                            match (ads.runs.as_ref(), unit_size) {
                                // Stamped above; nothing to decompress from.
                                _ if ads_unservable => {}
                                (Some(runs), Some(unit))
                                    if ads.size > 0 && ads.size <= NTFS_DECOMPRESS_CAP =>
                                {
                                    match seance_core::compression::decompress_ntfs_data(
                                        &fs_source, runs, unit, ads.size,
                                    ) {
                                        Ok(data) => {
                                            if data.len() < SPILL_THRESHOLD_BYTES {
                                                retained_decompressed_bytes += data.len() as u64;
                                            }
                                            ads_decompressed = Some(data)
                                        }
                                        Err(e) => {
                                            debug!(
                                                "Record #{}: LZNT1 ADS {} could not be \
                                                 reconstructed: {}",
                                                record_num, ads_full_name, e
                                            );
                                            ads_metadata["compression_unsupported"] =
                                                json!("ntfs_lznt1_decompress_failed");
                                            ads_metadata["content_incomplete"] = json!(true);
                                            ads_metadata["content_incomplete_reason"] =
                                                json!(IncompleteReason::Compressed.as_str());
                                        }
                                    }
                                }
                                (_, None) => {
                                    // The exponent did not yield a unit size, so
                                    // there is no way to walk the compressed runs
                                    // at all. Named as what it is; the exponent
                                    // itself is already recorded above.
                                    ads_metadata["compression_unsupported"] =
                                        json!("ntfs_lznt1_invalid_compression_unit");
                                    ads_metadata["content_incomplete"] = json!(true);
                                    ads_metadata["content_incomplete_reason"] =
                                        json!(IncompleteReason::Compressed.as_str());
                                }
                                (None, _) => {
                                    // Compressed, with no run list to decompress
                                    // from. Nothing describes where the bytes are.
                                    ads_metadata["compression_unsupported"] =
                                        json!("ntfs_lznt1_no_run_list");
                                    ads_metadata["content_incomplete"] = json!(true);
                                    ads_metadata["content_incomplete_reason"] =
                                        json!(IncompleteReason::Compressed.as_str());
                                }
                                (Some(_), Some(_)) if ads.size == 0 => {
                                    // A zero-length stream: there is no content to
                                    // be missing, so this is NOT marked incomplete.
                                    // Marking it so would have the report count a
                                    // stream as content that could not be read when
                                    // there was never any content to read.
                                    ads_metadata["compression_unsupported"] =
                                        json!("ntfs_lznt1_zero_length");
                                }
                                (Some(_), Some(_)) => {
                                    // The one case the old label actually described:
                                    // too large to reconstruct in memory at ingest.
                                    ads_metadata["compression_unsupported"] =
                                        json!("ntfs_lznt1_oversize");
                                    ads_metadata["content_incomplete"] = json!(true);
                                    ads_metadata["content_incomplete_reason"] =
                                        json!(IncompleteReason::Compressed.as_str());
                                }
                            }
                        }

                        let ads_data_source: Option<Arc<dyn DataSource>> =
                            if let Some(data) = ads_decompressed {
                                Some(spill_or_hold(data))
                            } else if ads_compressed || ads_unservable {
                                // Compressed and not reconstructed: attaching the
                                // compressed clusters here would index and hash
                                // them as the stream's bytes.
                                None
                            } else if let Some(ref runs) = ads_content_runs {
                                // Same reduction as the primary $DATA above:
                                // an ADS is a file's stream and has its own
                                // logical length.
                                Some(Arc::new(RunListDataSource::with_logical_size(
                                    fs_source.clone(),
                                    runs.clone(),
                                    ads.size,
                                )))
                            } else if let Some(ref data) = ads.resident_data {
                                Some(Arc::new(ByteSliceDataSource::new(data.clone())))
                            } else {
                                None
                            };

                        if let Some(ref runs) = ads_content_runs {
                            let (runs_json, complete) = byte_runs_to_metadata(runs);
                            ads_metadata["data_runs"] = runs_json;
                            ads_metadata["data_runs_complete"] =
                                json!(complete && !attr_list_incomplete);
                            if let Some(map) = ads_metadata.as_object_mut() {
                                stamp_runs_incompleteness(map, complete, attr_list_incomplete);
                            }
                        } else if let Some(ref data) = ads.resident_data {
                            ads_metadata["resident_data_b64"] = json!(BASE64.encode(data));
                        }

                        // `$BadClus:$Bad` (record 8) is a map, not content: its
                        // allocated runs ARE the bad clusters, and it carries
                        // `initialized_size` 0 on every real volume, so the
                        // logical-extent reduction above leaves one sparse run
                        // the length of the volume and discards every bad-cluster
                        // run (HUNT-155). The raw run list is published under its
                        // own key — `data_runs` keeps its contract, the stream's
                        // logical bytes, so no resolver serves never-written
                        // clusters as the stream's content — with the cluster
                        // size the bad-cluster reader needs to state LCNs.
                        if record_num == 8 && ads.name == "$Bad" && !ads_compressed {
                            if let Some(ref runs) = ads.runs {
                                let (runs_json, complete) = byte_runs_to_metadata(runs);
                                ads_metadata["bad_cluster_runs"] = runs_json;
                                ads_metadata["bad_cluster_runs_complete"] =
                                    json!(complete && !attr_list_incomplete);
                                ads_metadata["cluster_size"] = json!(cluster_size);
                            }
                        }

                        // A stream has no independent existence: if its base
                        // record is not in use, the stream is deleted too. Carry
                        // the flag so "deleted" filters surface recovered ADS.
                        if header.flags & 0x0001 == 0 {
                            ads_metadata["deleted"] = json!(true);
                            ads_metadata["deleted_recovery_source"] = json!("mft");
                        }

                        // Flat model: an ADS is parented to the FileSystem, not
                        // its base file. Its data_runs are filesystem-relative,
                        // so resolving content through the base file would apply
                        // them against the base's content instead of the FS
                        // window. The stream is linked to its base via the
                        // parent_file / path (basefile:stream) metadata.
                        let ads_artifact = Artifact::new(
                            artifact.case_id,
                            ArtifactType::FileEntry,
                            ads_data_source,
                            ads_metadata,
                        )
                        .with_parent(artifact.id);

                        produced_artifacts.push(ads_artifact);
                    }

                    // If we have Index Allocation, emit a specific artifact for it ($I30)
                    if let Some(runs) = index_allocation_runs {
                        // An index allocation IS its clusters — $INDEX_ALLOCATION
                        // has no logical length distinct from what it occupies,
                        // and the INDX record walk finds its own end.
                        //
                        // From a bare $MFT the index's clusters are not here:
                        // the stream is published without a data source and
                        // says why, rather than handing the $I30 reader the
                        // $MFT's own bytes at those offsets (HUNT-161).
                        let index_bytes: u64 = runs.iter().map(|(_, len)| *len).sum();
                        let index_source: Option<Arc<dyn DataSource>> = if runs.is_empty() {
                            // Listed in an extension record that could not be
                            // trusted: no clusters are known (HUNT-256).
                            None
                        } else if volume_in_evidence {
                            Some(Arc::new(RunListDataSource::from_allocation(
                                fs_source.clone(),
                                runs,
                            )))
                        } else {
                            None
                        };
                        let mut i30_metadata = serde_json::Map::new();
                        i30_metadata.insert("name".to_string(), json!("$I30"));
                        i30_metadata.insert("type".to_string(), json!("IndexAllocation"));
                        i30_metadata.insert(
                            "parent_file".to_string(),
                            json!(filename_metadata
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown")),
                        );
                        if i30_incomplete {
                            i30_metadata.insert("content_incomplete".to_string(), json!(true));
                            i30_metadata.insert(
                                "content_incomplete_reason".to_string(),
                                json!(IncompleteReason::UnresolvedStructure.as_str()),
                            );
                            i30_metadata.insert(
                                "content_incomplete_detail".to_string(),
                                json!(
                                    "Part or all of this directory index is held in an \
                                     extension MFT record named by its $ATTRIBUTE_LIST, and \
                                     that record could not be trusted or its extent was \
                                     missing; the stream holds only what was recovered"
                                ),
                            );
                        } else if index_source.is_none() {
                            stamp_volume_not_in_evidence(&mut i30_metadata, index_bytes);
                        }
                        let i30_artifact = Artifact::new(
                            artifact.case_id,
                            ArtifactType::SystemArtifact, // Specialized type
                            index_source,
                            serde_json::Value::Object(i30_metadata),
                        )
                        .with_parent(file_entry_id);

                        produced_artifacts.push(i30_artifact);
                    }

                    // Timeline Events - enriched with MFT metadata
                    let mut add_event =
                        |key: &str, desc: &str, timestamp_iso: &serde_json::Value| {
                            if let Some(ts_str) = timestamp_iso.as_str() {
                                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_str) {
                                    let timestamp = dt.timestamp();
                                    let name = filename_metadata
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Unknown");
                                    let is_dir = filename_metadata
                                        .get("is_directory")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);

                                    // Build enriched description
                                    let entry_type = if is_dir { "DIR" } else { "FILE" };
                                    let description =
                                        format!("{} {} (MFT: {})", entry_type, name, record_num);
                                    let path = filename_metadata
                                        .get("path")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or(name);

                                    // full_details is a JSON object so the timeline row
                                    // carries the SI/FN source (timestamp_type) and the
                                    // timestomping verdict through to the UI (only the
                                    // 5 timeline columns survive; extras must live here).
                                    let mut full_details = json!({
                                        "filename": name,
                                        "path": path,
                                        "mft_record": record_num,
                                        "desc": desc,
                                        "entry_type": entry_type,
                                        "timestamp_type": key,
                                    });
                                    if let Some(s) = filename_metadata.get("timestomp_suspected") {
                                        full_details["timestomp_suspected"] = s.clone();
                                    }
                                    if let Some(r) = filename_metadata.get("timestomp_reasons") {
                                        full_details["timestomp_reasons"] = r.clone();
                                    }

                                    let metadata = json!({
                                        "timestamp": timestamp,
                                        "timestamp_desc": desc,
                                        "source_module": "plugin.ntfs.mft_parser",
                                        "short_desc": description,
                                        "artifact_type": entry_type,
                                        "filename": name,
                                        "mft_record_number": record_num,
                                        "mft_offset": record_offset,
                                        "is_directory": is_dir,
                                        "timestamp_type": key,
                                        "full_details": full_details
                                    });

                                    let event_artifact = Artifact::new(
                                        artifact.case_id,
                                        ArtifactType::TimelineEvent,
                                        None,
                                        metadata,
                                    )
                                    .with_parent(file_entry_id);

                                    if sink.is_some() {
                                        event_batch.push(event_artifact);
                                    } else {
                                        produced_artifacts.push(event_artifact);
                                    }
                                }
                            }
                        };

                    if let Some(ts) = standard_info_metadata.get("created") {
                        add_event("SI_Created", "Created", ts);
                    }
                    if let Some(ts) = standard_info_metadata.get("modified") {
                        add_event("SI_Modified", "Modified", ts);
                    }
                    if let Some(ts) = standard_info_metadata.get("mft_modified") {
                        add_event("SI_MFT_Modified", "MFT Modified", ts);
                    }
                    if let Some(ts) = standard_info_metadata.get("accessed") {
                        add_event("SI_Accessed", "Accessed", ts);
                    }
                    if let Some(ts) = filename_metadata.get("fn_created") {
                        add_event("FN_Created", "Created (FN)", ts);
                    }
                    if let Some(ts) = filename_metadata.get("fn_modified") {
                        add_event("FN_Modified", "Modified (FN)", ts);
                    }
                    if let Some(ts) = filename_metadata.get("fn_mft_modified") {
                        add_event("FN_MftModified", "MFT Modified (FN)", ts);
                    }
                    if let Some(ts) = filename_metadata.get("fn_accessed") {
                        add_event("FN_Accessed", "Accessed (FN)", ts);
                    }
                }
            }

            offset += mft_record_size;
        }

        report_retention(
            offset / mft_record_size,
            &produced_artifacts,
            retained_decompressed_bytes,
        );

        // The last, part-filled batch. Flushed on a cancel too: what was found
        // is evidence whether or not the walk finished.
        if !event_batch.is_empty() {
            if let Some(sink) = sink.as_mut() {
                sink(std::mem::take(&mut event_batch));
            }
        }

        // Final progress update so the bar completes (or reflects the point of
        // cancellation).
        if let Some(reporter) = &self.progress {
            reporter.report_now_for_case(
                artifact.case_id,
                artifact.id,
                offset / mft_record_size,
                Some(total_records),
                "records",
            );
        }

        // Publish in-image sidecars (`.LOG1`/`.LOG2` beside a registry hive,
        // `-wal` beside a database) through `open_sibling`, so registry log
        // replay and WAL-aware SQLite spills work for evidence inside a disk
        // image and not only for loose files and ZIP entries (BUG-257).
        seance_core::data_source::attach_sibling_bundles(&mut produced_artifacts);

        // Surface any unreadable records so partial extraction is never presented
        // as complete. There is no dedicated filesystem-summary artifact, so emit
        // a ParsedRecord child of the parent carrying the count, and log it.
        //
        // On a volume the same record says how the table was found when that
        // is anything short of "record 0's own runs, whole": the `$MFTMirr`
        // copy standing in for a torn record 0, a run list known to be short
        // of the table (the unreached tail's records are not read, and are
        // counted), or no table at all (HUNT-251).
        let runs_short = located.as_ref().is_some_and(|l| !l.runs_complete);
        let from_mirror = located
            .as_ref()
            .is_some_and(|l| l.record0_source == volume_mft::Record0Source::MftMirr);
        if records_skipped > 0
            || records_fixup_failed > 0
            || table_refusal.is_some()
            || runs_short
            || from_mirror
            || records_misnumbered > 0
        {
            warn!(
                "MFT enumeration for artifact {}: {} unreadable, {} fixup-failed, {} misnumbered \
                 record(s); table {}",
                artifact.id,
                records_skipped,
                records_fixup_failed,
                records_misnumbered,
                table_refusal.unwrap_or(if runs_short {
                    "run list incomplete"
                } else {
                    "located"
                })
            );
            let incomplete = records_skipped > 0
                || records_fixup_failed > 0
                || table_refusal.is_some()
                || runs_short;
            let reason = if records_skipped > 0 {
                IncompleteReason::ShortRead
            } else {
                IncompleteReason::UnresolvedStructure
            };
            let mut summary = json!({
                "type": "mft_parse_summary",
                "unreadable_records": records_skipped,
                "records_skipped": records_skipped,
                "fixup_failed_records": records_fixup_failed,
                "total_record_slots": total_records,
            });
            if incomplete {
                // Standard pair: the file inventory this MFT produced is
                // short of the volume, and the shortfall must reach the
                // incompleteness census, not just the log.
                summary["inventory_incomplete"] = json!(true);
                summary["content_incomplete"] = json!(true);
                summary["content_incomplete_reason"] = json!(reason.as_str());
            }
            if records_misnumbered > 0 {
                summary["misnumbered_records"] = json!(records_misnumbered);
            }
            if let Some(refusal) = table_refusal {
                summary["mft_located"] = json!(false);
                summary["mft_not_located_detail"] = json!(refusal);
            }
            if let Some(loc) = located.as_ref() {
                summary["mft_located"] = json!(true);
                summary["mft_record0_source"] = json!(loc.record0_source.as_str());
                summary["mft_runs_complete"] = json!(loc.runs_complete);
                summary["mft_size"] = json!(loc.size);
                if !loc.runs_complete {
                    summary["mft_record_slots_unreached"] =
                        json!(loc.size.saturating_sub(loc.located_bytes()) / mft_record_size);
                }
            }
            produced_artifacts.push(
                Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, summary)
                    .with_parent(artifact.id),
            );
        }

        // The volume's slack regions and the one summary that says what the
        // pass examined, skipped and could not read (HUNT-124).
        if let Some(collector) = slack.take() {
            let (slack_artifacts, _) = collector.finish(artifact);
            produced_artifacts.extend(slack_artifacts);
        }

        // Emit an allocation map from $Bitmap (record 6) when parsing a full
        // filesystem window. Bare $MFT inputs have no volume to read the
        // bitmap clusters from, so the artifact is omitted, never fabricated.
        if is_filesystem {
            if let (Some(runs), Some(size)) = (bitmap_runs, bitmap_size) {
                if let Some((map_artifact, free_regions)) = build_allocation_map_artifact(
                    artifact,
                    &fs_source,
                    runs,
                    size,
                    cluster_size,
                    boot_info.as_ref().map(|b| b.total_clusters()),
                ) {
                    produced_artifacts.push(map_artifact);
                    // The free clusters as regions the automatic carver can be
                    // pointed at (ROADMAP §5.4). Until this landed the only
                    // producer of `UnallocatedSpace` in the tree was the
                    // partition parser's gaps BETWEEN partitions, so the free
                    // space inside a volume -- where nearly everything an
                    // examiner carves for is -- was never carved
                    // automatically at all.
                    produced_artifacts.extend(free_regions);
                }
            }

            // The volume's own account of its geometry, as a record (§1.7).
            // `documentation/WINDOWS_DESIGN.md` claimed `$Boot` was parsed and
            // nothing in the tree read a boot sector into an artifact.
            if let Some(boot) = boot_info.as_ref() {
                let mut primary = [0u8; boot::BOOT_SECTOR_BYTES];
                let read =
                    data_source.read_at(0, &mut primary).unwrap_or(0) == boot::BOOT_SECTOR_BYTES;
                let backup = if read {
                    boot::compare_backup(data_source.as_ref(), boot, &primary)
                } else {
                    boot::BackupComparison::NotReachable
                };
                produced_artifacts.push(
                    Artifact::new(
                        artifact.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        boot::boot_sector_metadata(boot, backup, None),
                    )
                    .with_parent(artifact.id),
                );
            }
        }

        Ok(produced_artifacts)
    }
}

/// Read the $Bitmap contents through its run list and emit the downsampled
/// allocation map as a ParsedRecord child of the FileSystem artifact.
/// Returns None when the bitmap cannot be read (the artifact is then omitted).
///
/// A bitmap that is read short must never shrink the volume. Clusters the
/// bitmap does not cover render as free space, and free space reads to an
/// examiner as "nothing was ever here" — so the volume keeps its real cluster
/// count from the boot sector and the shortfall is published as
/// `allocation_map_incomplete` plus the standard
/// `content_incomplete` / `content_incomplete_reason` pair (B5-004). This
/// mirrors the exFAT allocation-bitmap path, which already gathers with a
/// looping read and flags the same way.
#[allow(clippy::type_complexity)]
fn build_allocation_map_artifact(
    artifact: &Artifact,
    fs_source: &Arc<dyn DataSource>,
    runs: Vec<(Option<u64>, u64)>,
    bitmap_size: u64,
    cluster_size: u64,
    volume_clusters: Option<u64>,
) -> Option<(Artifact, Vec<Artifact>)> {
    // `from_allocation` deliberately. The read below is already bounded by
    // `bitmap_size`, so an over-long allocation cannot over-read — and fitting
    // to `bitmap_size` would *pad* a short run list with a sparse run, whose
    // zeros mean "free cluster". `bytes_read < bitmap_size` is how this
    // function detects that it holds less of the map than the volume has; a
    // pad would satisfy that check with fabricated free space.
    let source = RunListDataSource::from_allocation(fs_source.clone(), runs);
    // Cap and run-list length are tracked separately so the reason below can
    // say WHICH of them shortened the map.
    let capped_len = bitmap_size.min(MAX_BITMAP_BYTES);
    let read_len = capped_len.min(source.size());
    if read_len == 0 {
        return None;
    }
    let mut bitmap = vec![0u8; read_len as usize];
    // Loop over short reads: a single `read_at` may fill fewer bytes than
    // asked, and the zero tail is indistinguishable from genuinely free
    // clusters.
    let bytes_read = seance_core::io::read_full(&source, 0, &mut bitmap) as u64;
    if bytes_read == 0 {
        return None;
    }
    bitmap.truncate(bytes_read as usize);

    // Clusters the bytes we hold can actually speak for.
    let covered_clusters = bitmap.len() as u64 * 8;
    // The boot sector's cluster count is authoritative for the volume's extent.
    // Without a boot sector (a bare $MFT input) the bitmap's own coverage is
    // the only geometry available.
    let total_clusters = volume_clusters.unwrap_or(covered_clusters);
    if total_clusters == 0 {
        return None;
    }

    let incomplete_reason = if capped_len < bitmap_size {
        Some(IncompleteReason::CapReached)
    } else if bytes_read < bitmap_size {
        Some(IncompleteReason::ShortRead)
    } else if total_clusters > covered_clusters {
        Some(IncompleteReason::UnresolvedStructure)
    } else {
        None
    };

    let (buckets, clusters_per_bucket) = downsample_allocation_bitmap(&bitmap, total_clusters);

    let mut metadata = json!({
        "type": "allocation_map",
        "allocation_bitmap_b64": BASE64.encode(&buckets),
        "allocation_clusters_per_bucket": clusters_per_bucket,
        "allocation_total_clusters": total_clusters,
        "allocation_cluster_size": cluster_size,
    });
    if let Some(reason) = incomplete_reason {
        warn!(
            "$Bitmap for artifact {} covers {} of {} clusters ({} of {} bytes read, {}); \
             the uncovered range is NOT known to be free space",
            artifact.id,
            covered_clusters.min(total_clusters),
            total_clusters,
            bytes_read,
            bitmap_size,
            reason.as_str()
        );
        metadata["allocation_map_incomplete"] = json!(true);
        metadata["allocation_clusters_covered"] = json!(covered_clusters.min(total_clusters));
        metadata["allocation_bitmap_bytes_read"] = json!(bytes_read);
        metadata["allocation_bitmap_bytes_expected"] = json!(bitmap_size);
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!(reason.as_str());
    }

    // The same bytes, turned into regions rather than a picture (§5.4).
    //
    // `$Bitmap`'s first bit is LCN 0 and `fs_source` is the volume window, so
    // a cluster's byte offset in that window is its number times the cluster
    // size — no base to add, which is the one thing that makes NTFS the
    // simplest of the four. The emitter stops at the clusters the bytes above
    // can speak for and publishes the rest as unassessed, which is B5-004's
    // rule: a bitmap read short leaves a zero tail, and a zero bit is free.
    let bitmap_view = AllocationBitmap {
        bits: &bitmap,
        total_clusters,
        cluster_size,
        first_cluster: 0,
        first_cluster_offset: 0,
        bit_meaning: BitMeaning::SetIsAllocated,
    };
    let (free_regions, free_outcome) = emit_free_regions(
        artifact,
        fs_source,
        &bitmap_view,
        FreeSpaceLabels {
            filesystem: "NTFS",
            offset_basis: "the start of this volume, not the start of the evidence",
        },
    );
    if let (Some(map), Some(fields)) =
        (metadata.as_object_mut(), free_outcome.to_json().as_object())
    {
        for (key, value) in fields {
            map.insert(key.clone(), value.clone());
        }
    }
    if !free_outcome.is_complete() {
        // The allocation map is the record that already carries this volume's
        // free-space shortfall, so the region pass's own shortfall joins it
        // rather than starting a second place to look.
        metadata["content_incomplete"] = json!(true);
        if metadata.get("content_incomplete_reason").is_none() {
            if let Some(reason) = free_outcome.reason() {
                metadata["content_incomplete_reason"] = json!(reason.as_str());
            }
        }
    }
    info!(
        "$Bitmap for artifact {}: {} free region(s) covering {} bytes emitted for carving, \
         {} run(s) dropped at the region ceiling, {} cluster(s) unassessed",
        artifact.id,
        free_outcome.regions_emitted,
        free_outcome.bytes_emitted,
        free_outcome.runs_dropped,
        free_outcome.unassessed_clusters,
    );

    Some((
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id),
        free_regions,
    ))
}
