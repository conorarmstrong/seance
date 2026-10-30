#![forbid(unsafe_code)]
mod usnjrnl_structs;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{debug, info, warn};
use usnjrnl_structs::*;

#[cfg(test)]
mod tests;

pub struct UsnJrnlParser;

impl ForensicsModule for UsnJrnlParser {
    fn id(&self) -> &str {
        "plugin.ntfs.usnjrnl_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::RawEvidence,
            ArtifactType::SystemArtifact,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(file_name_str) = usn_journal_stream_label(artifact) else {
            return Ok(vec![]);
        };

        info!("Processing UsnJrnl file: {}", file_name_str);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("No data source available".to_string())
        })?;

        let (records, window) = parse_usn_journal(data_source.as_ref())?;

        info!(
            "Parsed {} USN records from {}",
            records.len(),
            file_name_str
        );

        let mut artifacts: Vec<Artifact> = Vec::new();

        // Over the cap only the most recent tail of `$UsnJrnl:$J` is read. The
        // rename/delete history before that window is absent from the case, so
        // it is stated outright instead of leaving the parse looking whole
        // (BUG-283).
        if let Some(reason) = window.incomplete_reason() {
            warn!(
                "USN journal {} is {} bytes; {} were parsed ({}): rename/delete \
                 history is missing from this case",
                file_name_str, window.journal_size, window.bytes_read, reason
            );
            artifacts.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "UsnJournalWindow",
                        "record_type": "usn_journal_status",
                        "name": format!("{} (partially parsed)", file_name_str),
                        "content_incomplete": true,
                        "content_incomplete_reason": reason,
                        "journal_size": window.journal_size,
                        "window_start_offset": window.window_start,
                        "bytes_parsed": window.bytes_read,
                        "records_parsed": records.len(),
                        "invalid_record_lengths": window.invalid_lengths,
                        "undecodable_records": window.undecodable_records,
                        "trailing_partial_record": window.trailing_partial_record,
                        "message": "Part of this journal was not parsed (cap, short read, or records that would not decode). A rename or delete absent from these entries is not evidence that it did not happen.",
                    }),
                )
                .with_parent(artifact.id),
            );
        }

        for record in records {
            let parsed_record = create_artifact_from_record(artifact.case_id, &record, artifact.id);
            let record_id = parsed_record.id;
            artifacts.push(parsed_record);

            // Emit TimelineEvent. Records with a zero/invalid FILETIME have
            // no timestamp and must not appear as 1970 timeline events.
            let Some(record_ts) = record.timestamp else {
                continue;
            };
            let reason_names = decode_reason_flags(record.reason_flags);
            let primary_op = primary_operation(record.reason_flags);
            let short_desc = format!("USN: {} on {}", primary_op, record.file_name);

            let event_metadata = json!({
                "timestamp": record_ts.timestamp(),
                "timestamp_desc": "USN Journal Entry",
                "source_module": "plugin.ntfs.usnjrnl_parser",
                "short_desc": short_desc,
                "full_details": json!({
                    "usn": record.usn,
                    "reasons": reason_names,
                    "filename": record.file_name,
                    "file_ref": format_file_reference(record.file_reference_number, record.file_reference_number_hi),
                    "attributes": record.file_attributes
                }).to_string()
            });

            let timeline_artifact = Artifact::new(
                artifact.case_id,
                ArtifactType::TimelineEvent,
                None,
                event_metadata,
            )
            .with_parent(record_id);

            artifacts.push(timeline_artifact);
        }

        Ok(artifacts)
    }
}

/// True when `s` names the `$J` change-journal stream rather than some other
/// part of `$UsnJrnl`.
///
/// Accepts the ADS spelling the MFT parser publishes (`$UsnJrnl:$J`), a bare
/// `$J`, and the path spellings tools use when the stream is exported as its
/// own file (`.../$Extend/$UsnJrnl/$J`, `.../$UsnJrnl_$J`).
fn names_the_j_stream(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let last = s
        .rsplit(['/', '\\', ':', '_'])
        .next()
        .unwrap_or("")
        .trim_end_matches(".bin");
    last == "$J" || (last == "J" && s.contains("UsnJrnl"))
}

/// Identify the `$UsnJrnl:$J` stream and return the label to report it under,
/// or `None` when this artifact is not the change journal.
///
/// The gate used to read only the `file_name` metadata key. The MFT parser
/// publishes alternate data streams with `name` ("$UsnJrnl:$J") and
/// `stream_name` ("$J") and never writes `file_name`, so on a normal NTFS
/// ingest this module matched nothing and the case simply had NO USN history —
/// while every unit test passed, because the tests hand-set `file_name`
/// (B6-001).
///
/// It must stay narrow in the other direction too. `$UsnJrnl` also carries a
/// `$Max` control stream and an unnamed `$DATA`; neither holds USN records, and
/// parsing them as records would either error the module or invent history.
fn usn_journal_stream_label(artifact: &Artifact) -> Option<String> {
    if !matches!(
        artifact.artifact_type,
        ArtifactType::FileEntry | ArtifactType::RawEvidence | ArtifactType::SystemArtifact
    ) {
        return None;
    }
    let field = |key: &str| {
        artifact
            .metadata
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
    };
    let stream_name = field("stream_name");
    let name = if field("name").is_empty() {
        field("file_name")
    } else {
        field("name")
    };
    let path = if field("source_path").is_empty() {
        field("path")
    } else {
        field("source_path")
    };

    // $Max records the journal's maximum size and allocation delta, not change
    // records. Never decode it as the record stream.
    if stream_name == "$Max" || name.ends_with(":$Max") || path.ends_with(":$Max") {
        return None;
    }

    let is_j = stream_name == "$J" || names_the_j_stream(name) || names_the_j_stream(path);
    // A loose file the examiner added by hand is often just called "UsnJrnl"
    // (the whole $J stream dumped to disk); accept that for standalone inputs,
    // where there is no $Max / base-record ambiguity to confuse it with.
    let is_loose_dump = artifact.artifact_type == ArtifactType::RawEvidence
        && (name.contains("UsnJrnl") || path.contains("UsnJrnl"));

    if !is_j && !is_loose_dump {
        return None;
    }
    let label = [name, path, stream_name]
        .into_iter()
        .find(|s| !s.is_empty())?;
    Some(label.to_string())
}

/// Cap on how much of the journal we buffer at once. `$UsnJrnl:$J` can report a
/// huge (usually mostly sparse) logical size; a `vec![0u8; size]` over that
/// would OOM the worker and lose the entire USN history. 512 MiB comfortably
/// holds the live tail of any real journal.
const MAX_USN_BYTES: u64 = 512 * 1024 * 1024;

/// What part of the journal was actually parsed.
///
/// The USN journal is the record of renames and deletes. History missing from
/// it is read as "this file was never renamed / never deleted", so every way
/// the parse can fall short of the stream has to be counted here and published
/// — not only the byte cap (B2-156).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JournalWindow {
    /// Logical size of the `$J` stream.
    pub journal_size: u64,
    /// Offset the parse started at (non-zero only when the cap applied).
    pub window_start: u64,
    /// Bytes actually read from that offset.
    pub bytes_read: u64,
    /// The stream ended before the window did: the rest was never read.
    pub short_read: bool,
    /// Records whose declared length was not a valid USN record length. The
    /// walk resyncs 8 bytes on, so an unknown span of the journal is skipped.
    pub invalid_lengths: usize,
    /// Records whose body would not decode.
    pub undecodable_records: usize,
    /// The window ended part-way through a record.
    pub trailing_partial_record: bool,
}

impl JournalWindow {
    /// True when older journal history exists before the parsed window (the
    /// byte cap applied). This is one of several ways the parse can fall short;
    /// see [`JournalWindow::incomplete_reason`].
    fn truncated(&self) -> bool {
        self.window_start > 0
    }

    /// Why the parsed journal is not the whole journal, if it is not.
    ///
    /// `None` means every byte of the stream was read and every record in it
    /// decoded — the only case where an absent rename is evidence that no
    /// rename happened.
    fn incomplete_reason(&self) -> Option<&'static str> {
        use seance_core::io::IncompleteReason;
        if self.truncated() {
            return Some(IncompleteReason::CapReached.as_str());
        }
        if self.short_read || self.trailing_partial_record {
            return Some(IncompleteReason::ShortRead.as_str());
        }
        if self.invalid_lengths > 0 || self.undecodable_records > 0 {
            return Some(IncompleteReason::UnresolvedStructure.as_str());
        }
        None
    }
}

/// Parse USN Journal binary data into records.
fn parse_usn_journal(
    data_source: &dyn seance_core::data_source::DataSource,
) -> Result<(Vec<UsnRecord>, JournalWindow), ModuleError> {
    parse_usn_journal_capped(data_source, MAX_USN_BYTES)
}

/// Parse the journal, buffering at most `cap` bytes.
///
/// `$UsnJrnl:$J` is a sparse stream: purged records at the head are deallocated
/// (read back as zeros) while live records accumulate at the tail. When the
/// journal exceeds `cap` we read the most-recent tail window rather than the
/// sparse head, and never allocate more than `cap`. Short reads are looped over
/// and a premature EOF truncates the buffer -- unread bytes are never treated as
/// zero records -- while a genuine I/O error fails closed.
///
/// The returned [`JournalWindow`] says which part of the stream this is: when
/// the cap applied, the records are only the most recent tail and the caller
/// must publish that fact (BUG-283).
fn parse_usn_journal_capped(
    data_source: &dyn seance_core::data_source::DataSource,
    cap: u64,
) -> Result<(Vec<UsnRecord>, JournalWindow), ModuleError> {
    let size = data_source.size();
    let start = size.saturating_sub(cap);
    let want = (size - start) as usize;

    let mut all_data = vec![0u8; want];
    let mut off = 0usize;
    while off < all_data.len() {
        match data_source.read_at(start + off as u64, &mut all_data[off..]) {
            Ok(0) => break, // premature EOF: keep only what we actually read
            Ok(n) => off += n,
            Err(e) => return Err(ModuleError::IoError(e)), // fail closed
        }
    }
    all_data.truncate(off);

    let mut window = JournalWindow {
        journal_size: size,
        window_start: start,
        bytes_read: off as u64,
        // The stream stopped short of the window we asked for: the bytes past
        // this point were never read, and are not known to hold no records.
        short_read: off < want,
        invalid_lengths: 0,
        undecodable_records: 0,
        trailing_partial_record: false,
    };

    let mut records = Vec::new();
    let mut offset: usize = 0;
    let data_len = all_data.len();

    while offset + 8 <= data_len {
        // Read record length (first 4 bytes)
        let record_length = u32::from_le_bytes([
            all_data[offset],
            all_data[offset + 1],
            all_data[offset + 2],
            all_data[offset + 3],
        ]);

        // Skip zero-length records (padding)
        if record_length == 0 {
            offset += 8;
            continue;
        }

        // Validate record length (must be 8-byte aligned and at least 60 bytes)
        if !record_length.is_multiple_of(8) || record_length < 60 {
            warn!(
                "Invalid record length {} at offset 0x{:X}, skipping",
                record_length, offset
            );
            // Resyncing 8 bytes on skips an unknown span of the journal: the
            // records inside it are missing from the case, not absent from the
            // volume's history.
            window.invalid_lengths += 1;
            offset += 8;
            continue;
        }

        // Check if we have enough data for the full record
        if offset + record_length as usize > data_len {
            debug!("Incomplete record at offset 0x{:X}, stopping", offset);
            window.trailing_partial_record = true;
            break;
        }

        // Parse the record
        let record_data = &all_data[offset..offset + record_length as usize];

        match parse_usn_record(record_data) {
            Ok(record) => {
                records.push(record);
            }
            Err(e) => {
                warn!("Failed to parse record at offset 0x{:X}: {}", offset, e);
                window.undecodable_records += 1;
            }
        }

        offset += record_length as usize;
    }

    Ok((records, window))
}

/// Parse a single USN record
fn parse_usn_record(data: &[u8]) -> Result<UsnRecord, ModuleError> {
    if data.len() < 8 {
        return Err(ModuleError::InvalidInputFormat(
            "Record too short".to_string(),
        ));
    }

    let record_length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let major_version = u16::from_le_bytes([data[4], data[5]]);
    let minor_version = u16::from_le_bytes([data[6], data[7]]);

    match major_version {
        2 | 3 => parse_usn_record_v2_v3(data, record_length, major_version, minor_version),
        4 => parse_usn_record_v4(data, record_length, minor_version),
        _ => Err(ModuleError::InvalidInputFormat(format!(
            "Unsupported USN version: {}.{}",
            major_version, minor_version
        ))),
    }
}

/// Parse a USN_RECORD_V2 or USN_RECORD_V3 (identical layouts; V3 widens the
/// file reference numbers to 128 bits).
fn parse_usn_record_v2_v3(
    data: &[u8],
    record_length: u32,
    major_version: u16,
    minor_version: u16,
) -> Result<UsnRecord, ModuleError> {
    if data.len() < 60 {
        return Err(ModuleError::InvalidInputFormat(
            "Record too short".to_string(),
        ));
    }

    // Determine offset increment based on version
    let offset_increment: usize = match major_version {
        2 => 0,
        3 => 16,
        _ => unreachable!(),
    };

    // Validate minimum record size for this version
    let min_size = 60 + offset_increment;
    if data.len() < min_size {
        return Err(ModuleError::InvalidInputFormat(format!(
            "Record too short for v{}",
            major_version
        )));
    }

    // Parse file reference numbers
    let (
        file_reference_number,
        file_reference_number_hi,
        parent_reference_number,
        parent_reference_number_hi,
    ) = match major_version {
        2 => {
            let file_ref = u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]);
            let parent_ref = u64::from_le_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]);
            (file_ref, 0u64, parent_ref, 0u64)
        }
        3 => {
            let file_ref_lo = u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]);
            let file_ref_hi = u64::from_le_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]);
            let parent_ref_lo = u64::from_le_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]);
            let parent_ref_hi = u64::from_le_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]);
            (file_ref_lo, file_ref_hi, parent_ref_lo, parent_ref_hi)
        }
        _ => unreachable!(),
    };

    // Parse record fields (with offset adjustment)
    let base_offset = 24 + offset_increment;

    let usn = u64::from_le_bytes([
        data[base_offset],
        data[base_offset + 1],
        data[base_offset + 2],
        data[base_offset + 3],
        data[base_offset + 4],
        data[base_offset + 5],
        data[base_offset + 6],
        data[base_offset + 7],
    ]);

    let raw_timestamp = u64::from_le_bytes([
        data[base_offset + 8],
        data[base_offset + 9],
        data[base_offset + 10],
        data[base_offset + 11],
        data[base_offset + 12],
        data[base_offset + 13],
        data[base_offset + 14],
        data[base_offset + 15],
    ]);

    let reason_flags = u32::from_le_bytes([
        data[base_offset + 16],
        data[base_offset + 17],
        data[base_offset + 18],
        data[base_offset + 19],
    ]);

    let source_info = u32::from_le_bytes([
        data[base_offset + 20],
        data[base_offset + 21],
        data[base_offset + 22],
        data[base_offset + 23],
    ]);

    let security_id = u32::from_le_bytes([
        data[base_offset + 24],
        data[base_offset + 25],
        data[base_offset + 26],
        data[base_offset + 27],
    ]);

    let file_attributes = u32::from_le_bytes([
        data[base_offset + 28],
        data[base_offset + 29],
        data[base_offset + 30],
        data[base_offset + 31],
    ]);

    let file_name_length = u16::from_le_bytes([data[base_offset + 32], data[base_offset + 33]]);

    let file_name_offset =
        u16::from_le_bytes([data[base_offset + 34], data[base_offset + 35]]) as usize;

    // Parse filename (UTF-16LE)
    let file_name = if file_name_length > 0 && file_name_offset < data.len() {
        let name_end = file_name_offset + file_name_length as usize;
        if name_end <= data.len() {
            decode_utf16le(&data[file_name_offset..name_end])
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    // Convert Windows FILETIME to DateTime
    let timestamp = seance_core::time::filetime_to_datetime(raw_timestamp);

    Ok(UsnRecord {
        record_length,
        major_version,
        minor_version,
        file_reference_number,
        file_reference_number_hi,
        parent_reference_number,
        parent_reference_number_hi,
        usn,
        timestamp,
        reason_flags,
        source_info,
        security_id,
        file_attributes,
        file_name,
        _file_name_length: file_name_length,
        extents: Vec::new(),
        remaining_extents: 0,
    })
}

/// Parse a USN_RECORD_V4 (range-tracking record, [MS-FSCC] 2.3.58):
///
/// ```text
/// 0x00 RecordLength u32        0x04 MajorVersion u16 (=4)  0x06 MinorVersion u16
/// 0x08 FileReferenceNumber (16 bytes, lo+hi)
/// 0x18 ParentFileReferenceNumber (16 bytes, lo+hi)
/// 0x28 Usn u64                 0x30 Reason u32             0x34 SourceInfo u32
/// 0x38 RemainingExtents u32    0x3C NumberOfExtents u16    0x3E ExtentSize u16
/// 0x40 Extents[NumberOfExtents], each ExtentSize bytes: Offset i64, Length i64
/// ```
///
/// V4 records carry NO timestamp, NO file name, no security id and no file
/// attributes; they report changed byte ranges and are paired with a later V3
/// close record for the name/time. Reading the V3 layout at these offsets
/// would fabricate a timestamp and filename out of extent data, so both are
/// left empty here (timestamp `None`, file_name `""`).
fn parse_usn_record_v4(
    data: &[u8],
    record_length: u32,
    minor_version: u16,
) -> Result<UsnRecord, ModuleError> {
    const V4_HEADER_LEN: usize = 0x40;

    if data.len() < V4_HEADER_LEN {
        return Err(ModuleError::InvalidInputFormat(
            "Record too short for v4".to_string(),
        ));
    }

    let file_reference_number = u64::from_le_bytes(data[0x08..0x10].try_into().unwrap());
    let file_reference_number_hi = u64::from_le_bytes(data[0x10..0x18].try_into().unwrap());
    let parent_reference_number = u64::from_le_bytes(data[0x18..0x20].try_into().unwrap());
    let parent_reference_number_hi = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap());
    let usn = u64::from_le_bytes(data[0x28..0x30].try_into().unwrap());
    let reason_flags = u32::from_le_bytes(data[0x30..0x34].try_into().unwrap());
    let source_info = u32::from_le_bytes(data[0x34..0x38].try_into().unwrap());
    let remaining_extents = u32::from_le_bytes(data[0x38..0x3C].try_into().unwrap());
    let number_of_extents = u16::from_le_bytes([data[0x3C], data[0x3D]]) as usize;
    let extent_size = u16::from_le_bytes([data[0x3E], data[0x3F]]) as usize;

    if number_of_extents > 0 && extent_size < 16 {
        return Err(ModuleError::InvalidInputFormat(format!(
            "v4 extent size {} too small to hold offset+length",
            extent_size
        )));
    }

    let extents_bytes = number_of_extents
        .checked_mul(extent_size)
        .ok_or_else(|| ModuleError::InvalidInputFormat("v4 extent array overflow".to_string()))?;
    if V4_HEADER_LEN + extents_bytes > data.len() {
        return Err(ModuleError::InvalidInputFormat(format!(
            "v4 record truncated: {} extents of {} bytes need {} bytes, have {}",
            number_of_extents,
            extent_size,
            V4_HEADER_LEN + extents_bytes,
            data.len()
        )));
    }

    let mut extents = Vec::with_capacity(number_of_extents);
    for i in 0..number_of_extents {
        let base = V4_HEADER_LEN + i * extent_size;
        let offset = i64::from_le_bytes(data[base..base + 8].try_into().unwrap());
        let length = i64::from_le_bytes(data[base + 8..base + 16].try_into().unwrap());
        extents.push(UsnExtent { offset, length });
    }

    Ok(UsnRecord {
        record_length,
        major_version: 4,
        minor_version,
        file_reference_number,
        file_reference_number_hi,
        parent_reference_number,
        parent_reference_number_hi,
        usn,
        timestamp: None,
        reason_flags,
        source_info,
        security_id: 0,
        file_attributes: 0,
        file_name: String::new(),
        _file_name_length: 0,
        extents,
        remaining_extents,
    })
}

/// Decode UTF-16LE string
fn decode_utf16le(data: &[u8]) -> String {
    if data.is_empty() || !data.len().is_multiple_of(2) {
        return String::new();
    }

    let u16_data: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    String::from_utf16_lossy(&u16_data)
}

/// Create an artifact from a USN record
fn create_artifact_from_record(
    case_id: uuid::Uuid,
    record: &UsnRecord,
    parent_id: uuid::Uuid,
) -> Artifact {
    let reason_names = decode_reason_flags(record.reason_flags);
    let file_reference = format_file_reference(
        record.file_reference_number,
        record.file_reference_number_hi,
    );
    let parent_reference = format_file_reference(
        record.parent_reference_number,
        record.parent_reference_number_hi,
    );
    let primary_op = primary_operation(record.reason_flags);

    let mut metadata = json!({
            "type": "UsnJournalEntry",
            "record_type": "usn_journal",
            "usn": record.usn.to_string(),
            "file_name": record.file_name,
            "file_reference": file_reference,
            "parent_reference": parent_reference,
            "reason_flags": format!("0x{:08X}", record.reason_flags),
            "reason_names": reason_names,
            "primary_operation": primary_op,
            "source_info": format!("0x{:08X}", record.source_info),
            "version": format!("{}.{}", record.major_version, record.minor_version),
            "record_length": record.record_length,
    });

    if record.major_version == 4 {
        // V4 carries no timestamp, file name, security id or file attributes;
        // report the changed byte ranges it actually contains instead.
        metadata["extents"] = json!(record
            .extents
            .iter()
            .map(|e| json!({ "offset": e.offset, "length": e.length }))
            .collect::<Vec<_>>());
        metadata["remaining_extents"] = json!(record.remaining_extents);
        // A nonzero remaining_extents means the ranges listed here are only part
        // of what changed for this USN; the rest are described by records
        // outside this one. Without saying so, the extent list reads as the
        // complete set of modified byte ranges for that change.
        if record.remaining_extents > 0 {
            metadata["extents_complete"] = json!(false);
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] = json!("v4_extents_continue_in_later_records");
        } else {
            metadata["extents_complete"] = json!(true);
        }
    } else {
        metadata["security_id"] = json!(record.security_id);
        metadata["file_attributes"] = json!(format!("0x{:08X}", record.file_attributes));
        // Absent for zero/out-of-range FILETIMEs rather than a fake epoch date
        if let Some(ts) = record.timestamp {
            metadata["timestamp"] = json!(ts.to_rfc3339());
        }
    }

    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
}
