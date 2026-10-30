#![forbid(unsafe_code)]
use seance_core::{
    artifact::{Artifact, ArtifactType},
    file_detection::{detect_file_type, DetectedFileType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{debug, info, warn};

pub mod logfile_structs;
use logfile_structs::*;

#[cfg(test)]
mod tests;

pub struct LogFileParser;

/// A record is worth an artifact when it is an NTFS client record with a
/// decoded operation whose redo or undo operation is not `Noop`. Pure `Noop`
/// records and LFS-internal records carry no forensic content.
fn is_significant(record: &LogRecord) -> bool {
    match &record.op {
        Some(op) => op.redo_operation != 0 || op.undo_operation != 0,
        None => false,
    }
}

impl ForensicsModule for LogFileParser {
    fn id(&self) -> &str {
        "plugin.ntfs.logfile_parser"
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
        debug!("LogFileParser processing artifact ID: {}", artifact.id);
        let mut produced_artifacts = Vec::new();
        // True once the BYTES have been identified as an NTFS transaction log,
        // which is a different claim from "an NTFS volume was handed to us".
        // Only the former makes a failed parse a shortfall worth recording; the
        // latter would put "the $LogFile could not be read" on every NTFS volume
        // in every case, and a disclosure that fires everywhere discloses
        // nothing.
        let mut content_confirmed = false;

        // Handle two cases:
        // 1. FileSystem artifact with NTFS filesystem_type metadata
        // 2. FileEntry artifact - use content detection to check if it's a $LogFile

        let is_filesystem = artifact.artifact_type == ArtifactType::FileSystem;
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
            // Use content-based detection instead of filename
            let data_source = match artifact.data.as_ref() {
                Some(ds) => ds,
                None => return Ok(produced_artifacts),
            };

            let detected_type = detect_file_type(data_source.as_ref());
            if detected_type != DetectedFileType::NtfsLogFile {
                // Not a LogFile, skip silently
                return Ok(produced_artifacts);
            }
            // The bytes ARE an NTFS transaction log. That is what makes silence
            // unacceptable if the parse then fails: see the `Err` arm below.
            content_confirmed = true;

            info!(
                "Detected $LogFile via content analysis (artifact ID: {})",
                artifact.id
            );
        } else {
            return Ok(produced_artifacts);
        }

        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(produced_artifacts),
        };

        match parse_logfile(data_source.as_ref()) {
            Ok(parsed) => {
                info!(
                    "Parsed $LogFile: {} records from {} pages (restart page {}, {} bytes)",
                    parsed.records.len(),
                    parsed.pages_scanned,
                    parsed.restart_page_used,
                    parsed.restart.file_size
                );

                // Honest skip-and-count: torn/corrupt pages failed their USA
                // fixup and were skipped rather than mis-parsed. Caps and short
                // reads stop the walk the same way. None of that is visible to
                // an examiner from the log records alone, so a status record is
                // emitted alongside them: a missing rename or delete must be
                // attributable either to "it did not happen" or to "this part of
                // the journal was never read", never ambiguously to both.
                if !parsed.complete() {
                    let reasons = parsed.incomplete_reasons();
                    warn!(
                        "$LogFile parse incomplete ({}): {} torn pages of {} scanned, {} records",
                        reasons.join(","),
                        parsed.torn_pages,
                        parsed.pages_scanned,
                        parsed.records.len()
                    );
                    const SHORT_PARSE_MESSAGE: &str =
                        "Part of the NTFS transaction log was not parsed: operations from the \
                         affected pages are absent from this case and their absence is not \
                         evidence they did not occur";
                    produced_artifacts.push(
                        Artifact::new(
                            artifact.case_id,
                            ArtifactType::ParsedRecord,
                            None,
                            json!({
                                "type": "LogFileParseStatus",
                                "record_type": "logfile_parse_status",
                                "name": "$LogFile (partially parsed)",
                                "source": "$LogFile",
                                "content_incomplete": true,
                                "content_incomplete_reason": reasons.join(","),
                                // The operations on the pages that were skipped
                                // are absent from the case, not merely truncated:
                                // that is an INVENTORY shortfall, and it is the
                                // inventory pair the completeness census and the
                                // report's "not recovered" section read.
                                "inventory_incomplete": true,
                                "inventory_incomplete_reason": reasons.join(","),
                                // The sentence has to land on the keys the
                                // examiner-facing reader shows
                                // (`frontend/src/lib/incompleteness.ts` keys off
                                // `<flag>_detail`). A bare `message` is read by
                                // nothing on that path, so the examiner was shown
                                // a reason code with nothing explaining it.
                                "content_incomplete_detail": SHORT_PARSE_MESSAGE,
                                "inventory_incomplete_detail": SHORT_PARSE_MESSAGE,
                                "torn_pages": parsed.torn_pages,
                                "pages_part_walked": parsed.pages_part_walked,
                                "pages_scanned": parsed.pages_scanned,
                                "records_parsed": parsed.records.len(),
                                "message": SHORT_PARSE_MESSAGE,
                            }),
                        )
                        .with_parent(artifact.id),
                    );
                }

                let significant: Vec<&LogRecord> = parsed
                    .records
                    .iter()
                    .filter(|r| is_significant(r))
                    .collect();
                info!(
                    "Found {} significant log records (out of {})",
                    significant.len(),
                    parsed.records.len()
                );

                for (i, log_record) in significant.iter().enumerate() {
                    let op = log_record
                        .op
                        .as_ref()
                        .expect("significant records have an op");

                    let mut metadata = json!({
                        // The category an examiner groups by. Without it these
                        // records fell through the record-type COALESCE onto
                        // their NUMERIC `record_type` below, so the largest
                        // class in an NTFS case showed up under a card and a
                        // viewer heading literally titled "1". The number is a
                        // property of one field of one record, never the name of
                        // the kind of record — that is what `type` is for.
                        "type": "NtfsLogFileRecord",
                        "record_number": i,
                        "lsn": format!("0x{:016x}", log_record.lsn),
                        "page_number": log_record.page_number,
                        "operation": ntfs_operation_name(op.redo_operation),
                        "target_attribute": op.target_attribute,
                        "undo_operation": op.undo_operation,
                        "redo_operation": op.redo_operation,
                        "undo_operation_name": ntfs_operation_name(op.undo_operation),
                        "redo_data_length": op.redo_length,
                        "undo_data_length": op.undo_length,
                        "target_vcn": op.target_vcn,
                        "target_lcn": op.target_lcn,
                        "transaction_id": log_record.transaction_id,
                        // The NTFS $LogFile record-type number (1 = a normal
                        // client record). Renamed off the bare `record_type`
                        // key, which the analysis grouping treats as a category
                        // NAME; a number there is not a name.
                        "ntfs_record_type": log_record.record_type,
                        "multi_page": log_record.multi_page,
                        "source": "$LogFile",
                    });

                    // A record whose client data spills into the next page was
                    // decoded from the first-page fragment only: the redo/undo
                    // payload behind these operation codes is incomplete.
                    // Without saying so, a partially-read operation reads as a
                    // fully-recovered one.
                    if log_record.multi_page {
                        metadata["content_incomplete"] = json!(true);
                        metadata["content_incomplete_reason"] =
                            json!("multi_page_record_not_reassembled");
                    }

                    let log_artifact = Artifact::new(
                        artifact.case_id,
                        ArtifactType::ParsedRecord,
                        None, // Log records don't have associated data
                        metadata,
                    )
                    .with_parent(artifact.id);

                    produced_artifacts.push(log_artifact);
                }

                info!(
                    "Created {} significant artifacts from $LogFile",
                    produced_artifacts.len()
                );
            }
            Err(e) => {
                warn!("Failed to parse $LogFile: {}", e);
                // Don't fail the entire pipeline — but don't answer with silence
                // either. When the bytes were identified as an NTFS transaction
                // log and the parse then failed, producing nothing makes "this
                // journal recorded no renames or deletes" and "this journal was
                // never read" the same answer. Only the content-confirmed path
                // says anything here: a FileSystem artifact was never
                // established to be a $LogFile, so a failure there is not a
                // shortfall this module can attest to.
                if content_confirmed {
                    let message = format!(
                        "This file was identified as an NTFS transaction log but could not be \
                         parsed ({e}): no journal operations from it are in this case, and that \
                         is not evidence that none occurred"
                    );
                    produced_artifacts.push(
                        Artifact::new(
                            artifact.case_id,
                            ArtifactType::ParsedRecord,
                            None,
                            json!({
                                "type": "LogFileParseStatus",
                                "record_type": "logfile_parse_status",
                                "name": "$LogFile (not parsed)",
                                "source": "$LogFile",
                                "content_incomplete": true,
                                "content_incomplete_reason":
                                    IncompleteReason::UnresolvedStructure.as_str(),
                                "inventory_incomplete": true,
                                "inventory_incomplete_reason":
                                    IncompleteReason::UnresolvedStructure.as_str(),
                                "content_incomplete_detail": message,
                                "inventory_incomplete_detail": message,
                                // Nothing was walked, and the counts say so
                                // rather than being omitted: a reader comparing
                                // status records must not have to guess whether
                                // an absent count means zero or unknown.
                                "torn_pages": 0,
                                "pages_part_walked": 0,
                                "pages_scanned": 0,
                                "records_parsed": 0,
                                "parse_error": e.to_string(),
                                "message": message,
                            }),
                        )
                        .with_parent(artifact.id),
                    );
                }
            }
        }

        Ok(produced_artifacts)
    }
}
