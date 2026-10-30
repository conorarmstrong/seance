#![forbid(unsafe_code)]
use byteorder::{ByteOrder, LittleEndian};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    codepage::decode_utf16le,
    file_detection::{detect_file_type, DetectedFileType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{debug, info, warn};

pub mod i30_structs;
use i30_structs::*;

#[cfg(test)]
mod tests;

pub struct I30Parser;

/// Is `s` (a name or a path) an NTFS `$I30` directory index stream?
///
/// Only the last path component counts, compared without case: `$I30`
/// itself, a stream reference `<dir>:$I30`, or the fully-typed
/// `<dir>:$I30:$INDEX_ALLOCATION`. A name that merely *contains* "i30"
/// (`vti30.dll`) is not one (HUNT-229).
fn is_i30_stream(s: &str) -> bool {
    let last = s.rsplit(['/', '\\']).next().unwrap_or("");
    let lower = last.to_ascii_lowercase();
    let stream = lower.strip_suffix(":$index_allocation").unwrap_or(&lower);
    stream == "$i30" || stream.ends_with(":$i30")
}

impl ForensicsModule for I30Parser {
    fn id(&self) -> &str {
        "plugin.ntfs.i30_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // Subscribe to SystemArtifacts which MftParser emits for Index Allocation streams
        // Also keep subscribing to FileEntry for legacy/manual usage
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
            ArtifactType::RawEvidence,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // info!("I30Parser processing artifact ID: {}", artifact.id);
        let mut produced_artifacts = Vec::new();

        let mut is_target = false;
        let mut source_name = String::new();

        // Check checks
        match artifact.artifact_type {
            ArtifactType::FileEntry => {
                // The MFT parser keys FileEntry names on `name` (and `path` for
                // alternate data streams); it never writes `file_name`. Reading
                // only `file_name` made this branch dead for everything the
                // pipeline actually produces (B6-035) — the SystemArtifact
                // branch below carried the whole workload.
                let file_name = artifact
                    .metadata
                    .get("name")
                    .or_else(|| artifact.metadata.get("file_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let path = artifact
                    .metadata
                    .get("path")
                    .or_else(|| artifact.metadata.get("source_path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if [file_name, path].iter().any(|s| is_i30_stream(s)) {
                    is_target = true;
                    source_name = if file_name.is_empty() {
                        path.to_string()
                    } else {
                        file_name.to_string()
                    };
                }
            }
            ArtifactType::SystemArtifact => {
                // Check if this is an IndexAllocation
                let type_val = artifact
                    .metadata
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if type_val == "IndexAllocation" {
                    let name = artifact
                        .metadata
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if name == "$I30" {
                        is_target = true;
                        source_name = "$I30 Stream".to_string();
                    }
                }
            }
            ArtifactType::RawEvidence => {
                // For RawEvidence, check content or filename
                if let Some(data) = &artifact.data {
                    // 1. Content Detection (Magic Bytes)
                    if detect_file_type(data.as_ref()) == DetectedFileType::NtfsIndx {
                        is_target = true;
                        source_name = artifact
                            .metadata
                            .get("source_path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Raw I30 File")
                            .to_string();
                    }
                }

                // 2. Fallback to filename check if magic bytes didn't match (though INDX should match)
                if !is_target {
                    let path = artifact
                        .metadata
                        .get("source_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if is_i30_stream(path) {
                        is_target = true;
                        source_name = path.to_string();
                    }
                }
            }
            _ => {}
        }

        if !is_target {
            return Ok(produced_artifacts);
        }

        // A selected stream with no bytes behind it is an index that was not
        // read, not a wrong input: `InvalidInputFormat` is folded into the
        // processing log's "skipped" row beside artifacts this module was never
        // for (HUNT-221, the pattern HUNT-178 fixed for `$SDS`). The stream the
        // MFT parser emits from a bare `$MFT` is the common case, and says so
        // with `volume_not_in_evidence`.
        let Some(data_source) = artifact.data.as_ref() else {
            let cause = if artifact
                .metadata
                .get("volume_not_in_evidence")
                .and_then(|v| v.as_bool())
                == Some(true)
            {
                "volume_not_in_evidence"
            } else {
                "no_data_source"
            };
            warn!(
                "$I30 {}: the index stream has no data source ({}); none of its entries can be read",
                source_name, cause
            );
            produced_artifacts.push(unread_index_record(artifact, &source_name, cause));
            return Ok(produced_artifacts);
        };

        info!("Processing $I30 index: {}", source_name);

        // Parse INDX buffers from the data source
        match parse_i30_buffers(data_source.as_ref()) {
            Ok(scan) => {
                let entries = &scan.entries;
                debug!("Extracted {} $I30 index entries", entries.len());
                if !scan.torn_buffers.is_empty() {
                    warn!(
                        "$I30 {}: {} INDX buffer(s) failed their update-sequence check; \
                         entries from them are flagged unverified",
                        source_name,
                        scan.torn_buffers.len()
                    );
                }

                // The live entries of this stream, for telling a stale copy of
                // an entry that still exists from the name of a deleted file
                // (HUNT-222). When NTFS shifts entries down a buffer, the old
                // positions stay in slack as whole copies of names that are
                // still live; both kinds were published alike.
                let live_refs: std::collections::HashSet<(&str, &str)> = entries
                    .iter()
                    .filter(|e| !e.from_slack && !e.file_reference.is_empty())
                    .map(|e| (e.file_reference.as_str(), e.file_name.as_str()))
                    .collect();
                let live_names: std::collections::HashSet<&str> = entries
                    .iter()
                    .filter(|e| !e.from_slack)
                    .map(|e| e.file_name.as_str())
                    .collect();

                // Create artifacts for each index entry
                for (i, entry) in entries.iter().enumerate() {
                    let mut metadata = json!({
                        "type": "NtfsIndexEntry",
                        "entry_number": i,
                        "file_name": entry.file_name,
                        "file_reference": entry.file_reference,
                        "parent_reference": entry.parent_reference,
                        "allocated_size": entry.allocated_size,
                        "real_size": entry.real_size,
                        "file_attributes": format!("0x{:08x}", entry.file_attributes),
                        "is_directory": entry.is_directory,
                        "namespace": entry.namespace_string(),
                        "entry_flags": entry.flag_strings(),
                        "created": entry.created_time(),
                        "modified": entry.modified_time(),
                        "mft_changed": entry.mft_changed_time(),
                        "accessed": entry.accessed_time(),
                        "from_slack": entry.from_slack,
                        "buffer_index": entry.buffer_index,
                        "entry_offset": entry.entry_offset,
                        "source": "$I30",
                    });

                    if entry.from_slack {
                        let (status, copy) = slack_status(entry, &live_refs, &live_names);
                        metadata["slack_status"] = json!(status);
                        metadata["stale_copy_of_live_entry"] =
                            copy.map_or(json!(null), |c| json!(c));
                    }

                    // An entry from a torn buffer is a recovered fragment, not a
                    // verified directory record: the fixup that proves the block
                    // was written whole did not hold.
                    let torn = scan.torn_buffers.contains(&entry.buffer_index);
                    metadata["fixup_verified"] = json!(!torn);
                    if torn {
                        metadata["content_incomplete"] = json!(true);
                        metadata["content_incomplete_reason"] = json!("indx_fixup_failed");
                    }

                    let i30_artifact =
                        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                            .with_parent(artifact.id);

                    produced_artifacts.push(i30_artifact);
                }

                // The scan itself did not cover the whole stream, or covered it
                // with torn blocks. Say so as a record: names missing from an
                // index are otherwise indistinguishable from files that never
                // existed in that directory.
                if scan.stopped.is_some()
                    || !scan.torn_buffers.is_empty()
                    || scan.buffers_unparsed > 0
                {
                    // The most serious cause names the record: a stop loses
                    // everything after it, an unparsed buffer loses one
                    // buffer, a torn one only qualifies what was decoded.
                    let reason = scan.stopped.unwrap_or(if scan.buffers_unparsed > 0 {
                        "indx_buffer_unparsable"
                    } else {
                        "indx_fixup_failed"
                    });
                    let detail = format!(
                        "Part of this $I30 index was unreadable, could not be parsed or failed \
                         its update-sequence check ({} torn buffer(s), {} unparsable buffer(s){}): \
                         names absent from these {} entries are not evidence that no such file \
                         existed in the directory",
                        scan.torn_buffers.len(),
                        scan.buffers_unparsed,
                        match scan.stopped {
                            Some(r) => format!(", scan stopped: {r}"),
                            None => String::new(),
                        },
                        entries.len(),
                    );
                    produced_artifacts.push(
                        Artifact::new(
                            artifact.case_id,
                            ArtifactType::ParsedRecord,
                            None,
                            json!({
                                "type": "I30ScanStatus",
                                "record_type": "i30_scan_status",
                                "name": format!("{} (partially recovered)", source_name),
                                "source": "$I30",
                                // The bytes of the stream were not all read or
                                // not all trustworthy...
                                "content_incomplete": true,
                                "content_incomplete_reason": reason,
                                "content_incomplete_detail": detail,
                                // ...and so the listing of names is short. This
                                // is the pair the frontend and the census read
                                // for "an absence here is not evidence".
                                "inventory_incomplete": true,
                                "inventory_incomplete_reason": reason,
                                "inventory_incomplete_detail": detail,
                                "torn_buffers": scan.torn_buffers.len(),
                                "buffers_unparsed": scan.buffers_unparsed,
                                "entries_recovered": entries.len(),
                                "message": detail,
                            }),
                        )
                        .with_parent(artifact.id),
                    );
                }
            }
            Err(e) => {
                warn!("Failed to parse $I30 index: {}", e);
            }
        }

        Ok(produced_artifacts)
    }
}

/// How a slack entry stands against the live entries of the same index.
///
/// * `copy_of_live_entry` — the same file reference and name are live: this is
///   a stale copy left when entries shifted, not a deleted file.
/// * `live_name_reference_unknown` — the reference was overwritten and the
///   name is live: most likely a copy, but a deleted file whose name was later
///   reused cannot be ruled out, so it is claimed as neither (`null`).
/// * `reference_live_under_other_name` — the same file reference is live in
///   this index under a different name: an old name of a file that still
///   exists (renamed, or its other namespace), not a deleted file.
/// * `no_live_entry` — nothing live in this stream matches: a candidate deleted
///   name. The comparison is against this stream's decoded entries only; the
///   directory's resident `$INDEX_ROOT` is not read, and entries in a buffer
///   that could not be read or walked are not known.
fn slack_status(
    entry: &IndexEntry,
    live_refs: &std::collections::HashSet<(&str, &str)>,
    live_names: &std::collections::HashSet<&str>,
) -> (&'static str, Option<bool>) {
    if !entry.file_reference.is_empty() {
        if live_refs.contains(&(entry.file_reference.as_str(), entry.file_name.as_str())) {
            return ("copy_of_live_entry", Some(true));
        }
        if live_refs
            .iter()
            .any(|(r, _)| *r == entry.file_reference.as_str())
        {
            // The same file is live here under another name: a rename (or
            // the other namespace's name), not a deletion.
            return ("reference_live_under_other_name", Some(false));
        }
        return ("no_live_entry", Some(false));
    }
    if live_names.contains(entry.file_name.as_str()) {
        ("live_name_reference_unknown", None)
    } else {
        ("no_live_entry", Some(false))
    }
}

/// The status record for a `$I30` stream that was identified and could not be
/// read at all: no entries, and a record that says why rather than an empty
/// result that reads as "this directory held no names".
fn unread_index_record(parent: &Artifact, source_name: &str, cause: &str) -> Artifact {
    const REASON: &str = "unresolved_structure";
    let directory = parent
        .metadata
        .get("parent_file")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let detail = format!(
        "This $I30 index stream{} was identified but has no readable content ({cause}), so none \
         of its entries or slack were read: the names this directory held, live or deleted, are \
         unknown to this case, not absent from it",
        if directory.is_empty() {
            String::new()
        } else {
            format!(" of directory {directory}")
        }
    );
    let mut m = json!({
        "type": "I30ScanStatus",
        "record_type": "i30_scan_status",
        "name": format!("{source_name} (not read)"),
        "source": "$I30",
        "read_incomplete": cause,
        "content_incomplete": true,
        "content_incomplete_reason": REASON,
        "content_incomplete_detail": detail,
        "inventory_incomplete": true,
        "inventory_incomplete_reason": REASON,
        "inventory_incomplete_detail": detail,
        "torn_buffers": 0,
        "buffers_unparsed": 0,
        "entries_recovered": 0,
        "message": detail,
    });
    if !directory.is_empty() {
        m["parent_file"] = json!(directory);
    }
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, m).with_parent(parent.id)
}

/// Outcome of scanning a `$I30` stream: the recovered index entries, plus the
/// buffers that could not be trusted and the reason the scan stopped early.
///
/// Forensic meaning: `$I30` entries are frequently the only surviving record of
/// a deleted file's name, size and timestamps. A buffer whose update-sequence
/// fixup failed is torn or half-overwritten, so the names and dates decoded
/// from it may be spliced from two different states of the directory. Those
/// entries are still worth recovering, but never as ordinary index entries.
struct I30Scan {
    entries: Vec<IndexEntry>,
    /// Indexes of INDX buffers whose USA fixup did not verify.
    torn_buffers: Vec<usize>,
    /// INDX buffers read whole whose node header could not be walked, so none
    /// of their entries were decoded.
    buffers_unparsed: usize,
    /// Why the scan ended before the end of the stream, when it did.
    stopped: Option<&'static str>,
}

/// Smallest and largest INDX record size this parser will accept.
///
/// The index record size is `$INDEX_ROOT`'s, and equals the cluster size when
/// that is >= 512 bytes: 4 KiB is the common case but 8 KiB / 16 KiB / 32 KiB
/// / 64 KiB volumes are ordinary, and 512/1024/2048 occur on small volumes.
const INDX_MIN_RECORD_SIZE: usize = 512;
const INDX_MAX_RECORD_SIZE: usize = 64 * 1024;

/// The update-sequence stride: NTFS protects the last two bytes of every 512
/// bytes of a multi-sector structure, on every volume, whatever the physical
/// sector size.
const USA_STRIDE: usize = 512;

/// The on-disk size of the INDX record starting at `head`, taken from the
/// record itself.
///
/// The index record size is whatever `$INDEX_ROOT` declared for the volume, so
/// it must be read, never assumed. Two fields state it:
///
/// * the update-sequence array, which protects the last two bytes of every
///   512-byte stride and carries one extra entry for the sequence number, so
///   `record_size = (usa_count - 1) * 512`. This is the authority. The stride
///   is NTFS's, not the disk's: a 4Kn volume's 4,096-byte records carry a USA
///   count of 9 (dfir_ntfs's `4k-large.mft`; its `UPDATE_SEQUENCE_STRIDE_INDEX`
///   is 512), so a 4,096-byte stride is never considered (HUNT-153).
/// * `INDEX_HEADER.allocated_size` at 0x20, measured from the node header at
///   0x18, used to choose between those and as the fallback when the USA count
///   is unusable (a corrupt or overwritten record header).
///
/// Returns `None` when the two fields cannot be reconciled. The caller must then
/// STOP rather than guess: assuming 4 KiB on an 8 KiB or 16 KiB volume lands the
/// next read in the middle of a record, and every buffer after it is decoded at
/// the wrong alignment — producing wrong names and timestamps, or silently none
/// at all.
fn indx_record_size(head: &[u8]) -> Option<usize> {
    if head.len() < 0x24 {
        return None;
    }
    let plausible = |size: usize| (INDX_MIN_RECORD_SIZE..=INDX_MAX_RECORD_SIZE).contains(&size);

    let usa_count = LittleEndian::read_u16(&head[0x06..0x08]) as usize;
    let protected_sectors = usa_count.checked_sub(1).filter(|n| *n > 0);
    let usa_sizes: Vec<usize> = protected_sectors
        .and_then(|sectors| sectors.checked_mul(USA_STRIDE))
        .filter(|s| plausible(*s))
        .into_iter()
        .collect();

    // INDEX_HEADER.allocated_size is relative to the node header at 0x18, and
    // a record is allocated in whole sectors.
    let from_alloc = 0x18usize
        .checked_add(LittleEndian::read_u32(&head[0x20..0x24]) as usize)
        .map(|end| end.next_multiple_of(512))
        .filter(|s| plausible(*s));

    match (usa_sizes.as_slice(), from_alloc) {
        // The two fields agree: this is the record size, whatever the volume's
        // sector size was.
        (sizes, Some(alloc)) if sizes.contains(&alloc) => Some(alloc),
        // Only the USA is usable, and it names exactly one size.
        ([only], None) => Some(*only),
        // The USA says the record is at least this big and allocated_size fits
        // inside it: trust the USA.
        (sizes, Some(alloc)) if sizes.iter().any(|s| *s >= alloc) => {
            sizes.iter().copied().filter(|s| *s >= alloc).min()
        }
        // No usable USA at all: the allocated size is all we have.
        ([], Some(alloc)) => Some(alloc),
        _ => None,
    }
}

/// Parse INDX buffers from a data source
fn parse_i30_buffers(
    data_source: &dyn seance_core::data_source::DataSource,
) -> Result<I30Scan, ModuleError> {
    const INDX_MAGIC: &[u8] = b"INDX";
    const SECTOR_SIZE: usize = 512;
    /// Bytes of record header needed to derive the record size.
    const INDX_HEAD_SIZE: usize = 0x24;

    let mut entries = Vec::new();
    let mut torn_buffers: Vec<usize> = Vec::new();
    let mut buffers_unparsed: usize = 0;
    let mut stopped: Option<&'static str> = None;
    let mut offset: u64 = 0;
    let file_size = data_source.size();
    let mut buffer_index = 0;

    // Scan for INDX buffers
    while offset < file_size {
        // Looped reads throughout: one short `read_at` from a chunked source is
        // not evidence the record ends there.
        let mut head = vec![0u8; INDX_HEAD_SIZE];
        let (bytes_read, failed) = read_reporting_failure(data_source, offset, &mut head);

        if failed {
            // A read that errored is not the end of the stream: what lies past
            // it was never looked at (HUNT-153).
            warn!("$I30 read failed at offset {}; stopping scan", offset);
            stopped = Some("indx_read_failed");
            break;
        }
        if bytes_read < 4 {
            // Fewer than 4 bytes where the stream says more remain is a short
            // read, not the end; a tail too small to hold a signature is.
            if file_size - offset >= 4 {
                stopped = Some("indx_buffer_short_read");
            }
            break;
        }

        // Check for INDX magic
        if head[..4] != *INDX_MAGIC {
            // Try aligning to next sector if magic mismatch?
            // Or simple scan
            offset += SECTOR_SIZE as u64;
            continue;
        }

        if bytes_read < INDX_HEAD_SIZE {
            warn!(
                "INDX header short read ({} of {} bytes) at offset {}; stopping scan",
                bytes_read, INDX_HEAD_SIZE, offset
            );
            stopped = Some("indx_buffer_short_read");
            break;
        }

        // Record size comes from the record, not from an assumption. A 4 KiB
        // guess on an 8/16/64 KiB volume misaligns every subsequent buffer.
        let indx_buffer_size = match indx_record_size(&head[..bytes_read]) {
            Some(size) => size,
            None => {
                warn!(
                    "INDX buffer at offset {}: record size not derivable from its \
                     update-sequence array / allocated size; stopping scan",
                    offset
                );
                stopped = Some("indx_record_size_unresolved");
                break;
            }
        };

        // Found an INDX buffer, read the whole record
        if offset + indx_buffer_size as u64 > file_size {
            warn!("INDX buffer truncated at offset {}", offset);
            stopped = Some("indx_buffer_truncated");
            break;
        }

        let mut buffer = vec![0u8; indx_buffer_size];
        // Fail closed on a short read: a zero-padded INDX buffer would parse
        // fabricated index entries. Stop scanning rather than trust the unread
        // tail (BUG-155).
        let (n, failed) = read_reporting_failure(data_source, offset, &mut buffer);
        if failed {
            warn!(
                "INDX buffer read failed after {} of {} bytes at offset {}; stopping scan",
                n, indx_buffer_size, offset
            );
            stopped = Some("indx_read_failed");
            break;
        }
        if n < indx_buffer_size {
            warn!(
                "INDX buffer short read ({} of {} bytes) at offset {}; stopping scan",
                n, indx_buffer_size, offset
            );
            stopped = Some("indx_buffer_short_read");
            break;
        }

        // Apply fixup array (in place) to restore sector-end bytes before
        // parsing. A per-sector USN mismatch means the INDX block is torn or
        // partially overwritten: surface it (warn) rather than silently
        // treating the block as clean. This mirrors the MFT fixup path, which
        // errors on mismatch; sectors before the mismatch are still corrected
        // so parsing proceeds best-effort on the recoverable portion.
        if let Err(e) = apply_fixup(&mut buffer) {
            warn!(
                "Fixup mismatch/failure for INDX buffer at offset {}: {} (torn or unverifiable block)",
                offset, e
            );
            // Remember which buffer it was: every entry decoded from it is
            // marked so a torn block's names and timestamps can never be read
            // as a verified directory entry.
            torn_buffers.push(buffer_index);
        }

        match parse_index_buffer(&buffer, buffer_index, offset as usize) {
            Ok(buffer_entries) => {
                entries.extend(buffer_entries);
            }
            Err(e) => {
                // Read whole, but its node header cannot be walked: its names
                // are missing from the listing, so it is counted and the
                // status record says so (HUNT-153).
                warn!("Failed to parse INDX buffer at offset {}: {}", offset, e);
                buffers_unparsed += 1;
            }
        }

        offset += indx_buffer_size as u64;
        buffer_index += 1;
    }

    Ok(I30Scan {
        entries,
        torn_buffers,
        buffers_unparsed,
        stopped,
    })
}

/// `read_full`, but saying whether the loop ended on an `Err` rather than a
/// zero-length read. `seance_core::io::read_full` folds the two together, and
/// here they mean different things: the end of the stream, or a region no one
/// looked at.
fn read_reporting_failure(
    ds: &dyn seance_core::data_source::DataSource,
    offset: u64,
    buf: &mut [u8],
) -> (usize, bool) {
    let mut off = 0usize;
    while off < buf.len() {
        match ds.read_at(offset + off as u64, &mut buf[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(_) => return (off, true),
        }
    }
    (off, false)
}

/// Apply the update-sequence-array (USA) fixup to an INDX buffer in place.
///
/// Each protected sector's trailing 2 bytes must equal the USN placeholder.
/// A mismatch means the block is torn or was partially overwritten: this
/// returns `Err` (fail closed / surface the tear) instead of silently leaving
/// the placeholder in place and reporting success, matching the MFT fixup path.
/// Sectors verified before the mismatch are still corrected in place, so the
/// caller can parse the recoverable portion best-effort.
fn apply_fixup(buffer: &mut [u8]) -> Result<(), ModuleError> {
    if buffer.len() < 0x30 {
        return Err(ModuleError::ParsingError(format!(
            "Buffer too small for fixup: {} bytes (minimum 48 required)",
            buffer.len()
        )));
    }

    let update_seq_offset = LittleEndian::read_u16(&buffer[4..6]) as usize;
    let update_seq_size = LittleEndian::read_u16(&buffer[6..8]) as usize;

    // update_seq_size must be >= 2 (1 fixup value + at least 1 sector entry)
    if update_seq_size < 2 {
        return Err(ModuleError::ParsingError(format!(
            "Invalid fixup array size: {} (minimum 2 required)",
            update_seq_size
        )));
    }

    if update_seq_offset + (update_seq_size * 2) > buffer.len() {
        return Err(ModuleError::ParsingError(format!(
            "Invalid fixup array bounds: offset={}, size={}, buffer_len={}",
            update_seq_offset,
            update_seq_size,
            buffer.len()
        )));
    }

    // Copy the USA out so `buffer` can be mutated without an outstanding borrow.
    let update_seq = buffer[update_seq_offset..update_seq_offset + (update_seq_size * 2)].to_vec();
    let fixup_value = LittleEndian::read_u16(&update_seq[0..2]);

    // Apply fixup to each sector, verifying the USN placeholder first.
    for i in 1..update_seq_size {
        let sector_end = i * USA_STRIDE - 2;
        if sector_end + 2 > buffer.len() {
            return Err(ModuleError::ParsingError(format!(
                "Sector {} end out of bounds during fixup: {} > {}",
                i,
                sector_end + 2,
                buffer.len()
            )));
        }
        // Verify the fixup signature: the trailing bytes of every protected
        // sector must hold the USN. A mismatch is a torn/overwritten block.
        let current = LittleEndian::read_u16(&buffer[sector_end..sector_end + 2]);
        if current != fixup_value {
            return Err(ModuleError::ParsingError(format!(
                "Fixup mismatch: sector {} end 0x{:04X} != USN 0x{:04X} (torn INDX block)",
                i, current, fixup_value
            )));
        }
        // Replace with actual data from the fixup array.
        let replacement = LittleEndian::read_u16(&update_seq[i * 2..(i * 2) + 2]);
        LittleEndian::write_u16(&mut buffer[sector_end..sector_end + 2], replacement);
    }

    Ok(())
}

/// Parse a single INDX buffer
fn parse_index_buffer(
    buffer: &[u8],
    buffer_index: usize,
    buffer_offset: usize,
) -> Result<Vec<IndexEntry>, ModuleError> {
    if buffer.len() < 0x30 {
        return Err(ModuleError::ParsingError(format!(
            "INDX buffer too small ({} bytes) for initial header",
            buffer.len()
        )));
    }

    debug!("Buffer length in parse_index_buffer: {}", buffer.len());
    debug!(
        "Buffer bytes around 0x18-0x24: {:02X?}",
        &buffer[0x10..0x28]
    );

    // Parse INDX header
    let entry_offset_relative_to_0x18 = LittleEndian::read_u32(&buffer[0x18..0x1C]) as usize;
    let total_size = LittleEndian::read_u32(&buffer[0x1C..0x20]) as usize;
    let alloc_size = LittleEndian::read_u32(&buffer[0x20..0x24]) as usize;

    debug!(
        "Parsed entry_offset_relative_to_0x18: {}, total_size: {}",
        entry_offset_relative_to_0x18, total_size
    );

    // Per the NTFS INDEX_HEADER spec, EntriesOffset (0x18) and IndexLength /
    // total_size (0x1C) are BOTH measured from the start of the node header at
    // 0x18, and IndexLength *includes* the header. The used-entries region is
    // therefore [0x18 + EntriesOffset, 0x18 + IndexLength). Computing
    // `entries_start + total_size` (as before) over-counted by EntriesOffset and,
    // for a nearly-full block, pushed entries_end past the buffer so the bounds
    // check dropped every entry.
    if entry_offset_relative_to_0x18 > total_size {
        return Err(ModuleError::ParsingError(format!(
            "INDX entries offset {entry_offset_relative_to_0x18} exceeds index length {total_size}"
        )));
    }
    let entries_start = 0x18 + entry_offset_relative_to_0x18;
    let entries_end = 0x18 + total_size;

    if entries_start > buffer.len() || entries_end > buffer.len() || entries_start > entries_end {
        return Err(ModuleError::ParsingError(format!(
            "Invalid entry bounds in INDX buffer: entries_start={}, entries_end={}, buffer_len={}",
            entries_start,
            entries_end,
            buffer.len()
        )));
    }

    let entry_data = &buffer[entries_start..entries_end];
    let mut entries = Vec::new();
    let mut offset = 0;

    // Parse index entries
    while offset + 16 <= entry_data.len() {
        let entry = &entry_data[offset..];
        debug!(
            "Parsing entry at offset {} (entry_data len: {})",
            offset,
            entry_data.len()
        );
        debug!("Current entry slice len: {}", entry.len());

        let entry_len = LittleEndian::read_u16(&entry[8..10]) as usize;
        let attr_len = LittleEndian::read_u16(&entry[10..12]) as usize;
        let flags = LittleEndian::read_u16(&entry[12..14]);

        if entry_len == 0 || entry_len > entry.len() {
            warn!(
                "Invalid entry_len: {} (entry slice len: {}). Breaking.",
                entry_len,
                entry.len()
            );
            break;
        }

        // Check if this is a valid file name attribute. Use `attr_len + 16 <=
        // entry_len` rather than `attr_len <= entry_len - 16`: entry_len is
        // attacker-controlled and can be < 16, which would underflow the usize
        // subtraction (debug/fuzz panic).
        if attr_len >= 0x42 && attr_len + 16 <= entry_len {
            debug!("Found potential valid FILE_NAME attribute (attr_len: {}, entry_len: {}) at offset {}", attr_len, entry_len, offset);
            if let Ok(index_entry) = parse_index_entry(
                &entry[..entry_len],
                attr_len,
                flags,
                buffer_index,
                buffer_offset + entries_start + offset,
                false, // Not from slack yet
            ) {
                entries.push(index_entry);
            }
        } else {
            debug!("Skipping entry at offset {} due to invalid attr_len ({} < 0x42 or too large) or invalid entry_len", offset, attr_len);
        }

        offset += entry_len;

        if flags & 0x2 != 0 {
            break;
        }
    }

    // The slack — where a deleted file's entry survives after NTFS shifts the
    // remaining entries down over it — is the record's free space: from the end
    // of the used region (`IndexLength`) to the end of the allocation
    // (`AllocatedSize`), both measured from the node header at 0x18. It is NOT
    // inside `entries_end`: bounding the slack pass there (as this did until
    // HUNT-153) handed it an empty slice after the last-entry marker, and it
    // recovered nothing on any real volume. dfir_ntfs's `get_slack` reads the
    // same range (`24 + first_free_byte ..`).
    let slack_start = entries_end;
    let slack_end = 0x18usize.saturating_add(alloc_size).min(buffer.len());
    if slack_start < slack_end {
        debug!(
            "Parsing slack space from {} to {} (relative to the INDX record)",
            slack_start, slack_end
        );
        entries.extend(parse_slack_space(
            &buffer[slack_start..slack_end],
            buffer_index,
            buffer_offset + slack_start,
        ));
    }

    Ok(entries)
}

/// Parse slack space for deleted entries
fn parse_slack_space(
    slack_data: &[u8],
    buffer_index: usize,
    slack_offset: usize,
) -> Vec<IndexEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    debug!(
        "Starting parse_slack_space from absolute offset {} (length {} of slack_data)",
        slack_offset,
        slack_data.len()
    );

    // Scan through slack space looking for potential file name attributes
    while offset + 0x42 + 2 <= slack_data.len() {
        debug!(
            "Trying to parse slack entry at relative offset {} (absolute {})",
            offset,
            slack_offset + offset
        );
        if let Some(mut entry) =
            try_parse_slack_entry(&slack_data[offset..], buffer_index, slack_offset + offset)
        {
            // A stale entry in slack is a whole index entry — 16 bytes of
            // header (file reference, entry length, attribute length, flags)
            // then the $FILE_NAME — so the deleted file's own reference is
            // usually still in front of the name. Read it only when that header
            // lies inside the slack and its lengths describe exactly this
            // $FILE_NAME; anything less is left unknown rather than guessed.
            if let Some(header) = offset.checked_sub(16).map(|h| &slack_data[h..offset]) {
                let name_len = slack_data[offset + 0x40] as usize;
                let attr_len = LittleEndian::read_u16(&header[10..12]) as usize;
                let entry_len = LittleEndian::read_u16(&header[8..10]) as usize;
                if attr_len == 0x42 + name_len * 2
                    && entry_len >= 16 + attr_len
                    && entry_len.is_multiple_of(8)
                {
                    entry.file_reference =
                        format_file_reference(LittleEndian::read_u64(&header[0..8]));
                }
            }
            debug!(
                "Found slack entry: {} (from slack: {})",
                entry.file_name, entry.from_slack
            );
            entries.push(entry);
            // Advance by the full size of the found FILE_NAME attribute
            // Fixed part (0x42) + actual name length (name_length * 2)
            let name_length = slack_data[offset + 0x40] as usize;
            offset += 0x42 + (name_length * 2);
            // Ensure offset is 8-byte aligned (FILE_NAME attributes usually are within INDX)
            while offset % 8 != 0 && offset < slack_data.len() {
                offset += 1;
            }
        } else {
            offset += 1; // Move forward byte by byte
        }
    }

    entries
}

/// 1980-01-01T00:00:00Z as a FILETIME: the earliest time a slack candidate's
/// `$FILE_NAME` timestamps may carry.
const SLACK_FILETIME_NOT_BEFORE: u64 = 119_600_064_000_000_000;
/// 2108-01-01T00:00:00Z as a FILETIME: the first time a slack candidate's
/// timestamps may not carry.
const SLACK_FILETIME_NOT_AFTER: u64 = 159_992_928_000_000_000;

/// Attempt to parse an entry from slack space
fn try_parse_slack_entry(
    data: &[u8],
    buffer_index: usize,
    entry_offset: usize,
) -> Option<IndexEntry> {
    debug!(
        "Attempting try_parse_slack_entry at absolute offset {}",
        entry_offset
    );
    if data.len() < 0x42 + 2 {
        debug!(
            "Slack data too small ({} bytes) for FILE_NAME attribute",
            data.len()
        );
        return None;
    }

    // Heuristic: check name_length and namespace for validity
    let name_length_byte = data[0x40];
    let namespace_byte = data[0x41];

    if name_length_byte == 0 {
        debug!(
            "Skipping slack entry at offset {} due to zero name length",
            entry_offset
        );
        return None;
    }
    if namespace_byte > 0x3 {
        debug!(
            "Skipping slack entry at offset {} due to invalid namespace (0x{:x})",
            entry_offset, namespace_byte
        );
        return None;
    }

    let name_length = name_length_byte as usize;
    let actual_name_bytes_len = name_length * 2;
    if 0x42 + actual_name_bytes_len > data.len() {
        debug!("Skipping slack entry at offset {} due to name string out of bounds (name_len={} * 2 + 0x42 = {} > data.len()={})", entry_offset, name_length, 0x42 + actual_name_bytes_len, data.len());
        return None;
    }
    debug!("Found potential slack entry: name_length_byte={}, namespace_byte=0x{:x}, actual_name_bytes_len={}", name_length_byte, namespace_byte, actual_name_bytes_len);

    // Attempt to parse the file name attribute directly from this slice
    let parent_ref = LittleEndian::read_u64(&data[0..8]);
    let created = LittleEndian::read_u64(&data[8..16]);
    let modified = LittleEndian::read_u64(&data[16..24]);
    let mft_changed = LittleEndian::read_u64(&data[24..32]);
    let accessed = LittleEndian::read_u64(&data[32..40]);
    let allocated_size = LittleEndian::read_u64(&data[0x28..0x30]);
    let real_size = LittleEndian::read_u64(&data[0x30..0x38]);
    let file_attributes = LittleEndian::read_u32(&data[0x38..0x3C]);

    // The slack pass tests every byte offset, so a shape test alone accepts
    // fragments of other structures as names (on the dfir_ntfs `ntfs_index`
    // volume, a one-character "h" with parent 1048576-2). A real $FILE_NAME
    // carries four FILETIMEs; all four must fall in the window below or the
    // candidate is not reported. The window is wider than dfir_ntfs's
    // 1997..2060 carve so a genuinely old or back-dated file still passes; a
    // stale entry whose times were set outside it (before 1980, or to zero) is
    // not recovered, and the method statement says so.
    if ![created, modified, mft_changed, accessed]
        .iter()
        .all(|t| (SLACK_FILETIME_NOT_BEFORE..SLACK_FILETIME_NOT_AFTER).contains(t))
    {
        debug!(
            "Skipping slack candidate at offset {} whose timestamps are implausible",
            entry_offset
        );
        return None;
    }

    let name_bytes_slice = &data[0x42..0x42 + actual_name_bytes_len];
    let file_name = decode_utf16le(name_bytes_slice);

    if file_name.is_empty() || file_name.contains(['/', '\0']) {
        debug!(
            "Skipping slack entry at offset {} because decoded filename is empty",
            entry_offset
        );
        return None;
    }

    let is_directory = (file_attributes & 0x10) != 0;

    Some(IndexEntry {
        // Unknown until the caller finds a consistent stale entry header in
        // front of this $FILE_NAME. Empty, as `format_file_reference` renders a
        // zero reference — never "0-0", which reads as MFT record 0 ($MFT).
        file_reference: String::new(),
        parent_reference: format_file_reference(parent_ref),
        file_name,
        created,
        modified,
        mft_changed,
        accessed,
        allocated_size,
        real_size,
        file_attributes,
        namespace: namespace_byte,
        flags: 0, // No specific INDX_ENTRY flags for slack entries
        is_directory,
        from_slack: true,
        buffer_index,
        entry_offset,
    })
}

/// Parse a single index entry
fn parse_index_entry(
    entry: &[u8],
    attr_len: usize,
    flags: u16,
    buffer_index: usize,
    entry_offset: usize,
    from_slack: bool,
) -> Result<IndexEntry, ModuleError> {
    if entry.len() < 16 + attr_len {
        return Err(ModuleError::ParsingError(format!(
            "Entry truncated at buffer_index={}, entry_offset={}: entry_len={}, required={}",
            buffer_index,
            entry_offset,
            entry.len(),
            16 + attr_len
        )));
    }

    let file_ref = LittleEndian::read_u64(&entry[0..8]);
    let file_name_data = &entry[16..16 + attr_len];

    if file_name_data.len() < 0x42 {
        return Err(ModuleError::ParsingError(format!(
            "File name attribute too small at buffer_index={}, entry_offset={}: {} bytes (minimum 66 required)",
            buffer_index, entry_offset, file_name_data.len()
        )));
    }

    let parent_ref = LittleEndian::read_u64(&file_name_data[0..8]);
    let created = LittleEndian::read_u64(&file_name_data[8..16]);
    let modified = LittleEndian::read_u64(&file_name_data[16..24]);
    let mft_changed = LittleEndian::read_u64(&file_name_data[24..32]);
    let accessed = LittleEndian::read_u64(&file_name_data[32..40]);
    let allocated_size = LittleEndian::read_u64(&file_name_data[40..48]);
    let real_size = LittleEndian::read_u64(&file_name_data[48..56]);
    let file_attributes = LittleEndian::read_u32(&file_name_data[56..60]);
    let name_length = file_name_data[64] as usize;
    let namespace = file_name_data[65];

    if name_length == 0 || 66 + name_length * 2 > file_name_data.len() {
        return Err(ModuleError::ParsingError(format!(
            "Invalid name length at buffer_index={}, entry_offset={}: name_length={}, available={}",
            buffer_index,
            entry_offset,
            name_length,
            file_name_data.len() - 66
        )));
    }

    // Decode UTF-16LE filename
    let name_bytes = &file_name_data[66..66 + name_length * 2];
    let file_name = decode_utf16le(name_bytes);

    let is_directory = (file_attributes & 0x10) != 0;

    Ok(IndexEntry {
        file_reference: format_file_reference(file_ref),
        parent_reference: format_file_reference(parent_ref),
        file_name,
        created,
        modified,
        mft_changed,
        accessed,
        allocated_size,
        real_size,
        file_attributes,
        namespace,
        flags,
        is_directory,
        from_slack,
        buffer_index,
        entry_offset,
    })
}

/// Format file reference as "record-sequence"
fn format_file_reference(frn: u64) -> String {
    if frn == 0 {
        return String::new();
    }
    let record = frn & 0x0000FFFFFFFFFFFF;
    let sequence = frn >> 48;
    format!("{}-{}", record, sequence)
}
