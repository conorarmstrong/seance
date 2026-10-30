#![forbid(unsafe_code)]
mod parser;
#[cfg(test)]
mod tests;

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    file_detection::{detect_file_type, DetectedFileType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{debug, info, warn};

pub(crate) use parser::parse_prefetch;

// Prefetch files are small (a few hundred KB; well under 1 MB even on Win10).
// Cap the input we accept, and cap the declared uncompressed size of a MAM blob
// before decompressing (see parser::parse_prefetch).
pub(crate) const MAX_PREFETCH_SIZE: usize = 16 * 1024 * 1024;

pub struct PrefetchParser;

impl ForensicsModule for PrefetchParser {
    fn id(&self) -> &str {
        "plugin.windows.prefetch_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl PrefetchParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        debug!("PrefetchParser processing artifact ID: {}", artifact.id);

        // Use content-based detection instead of filename.
        //
        // `detect_file_type` classifies a buffer as a prefetch file when it
        // begins with an uncompressed SCCA header (version 17/23/26/30/31 +
        // "SCCA" at offset 4) or with the `MAM\x04` Xpress-Huffman wrapper used
        // by Win10/11; the native parser below transparently decompresses MAM.
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(Vec::new()),
        };

        let detected_type = detect_file_type(data_source.as_ref());
        if detected_type != DetectedFileType::PrefetchFile {
            // Not a prefetch file, skip silently
            return Ok(Vec::new());
        }

        info!(
            "Detected Prefetch file via content analysis (artifact ID: {})",
            artifact.id
        );

        // Refuse oversized inputs before allocating: a hostile/mis-detected
        // source could declare a huge size and OOM the worker. Check the
        // declared size first, then cap the read so we never buffer more than
        // MAX_PREFETCH_SIZE regardless of what the source reports.
        if data_source.as_ref().size() > MAX_PREFETCH_SIZE as u64 {
            warn!(
                "Prefetch artifact {} exceeds size cap ({} bytes); skipping",
                artifact.id,
                data_source.as_ref().size()
            );
            return Ok(vec![parse_status_artifact(
                artifact,
                seance_core::io::IncompleteReason::CapReached,
                "size_cap_exceeded",
                &format!(
                    "This file was identified as a Windows prefetch file but is {} bytes, past the \
                     {} byte ceiling this parser accepts, so it was never read",
                    data_source.as_ref().size(),
                    MAX_PREFETCH_SIZE
                ),
            )]);
        }
        let declared = data_source.as_ref().size();
        let buffer = seance_core::io::read_capped(data_source.as_ref(), MAX_PREFETCH_SIZE as u64);
        // The declared size is under the cap (checked above), so fewer bytes
        // than declared means the source could not deliver them. SCCA sections
        // are offset-addressed, so a short buffer yields a run list or a loaded
        // file list that is a prefix presented as the whole (B6-016).
        let short_read = (buffer.len() as u64) < declared;

        // Parse with the native, fully bounds-checked parser. Any malformed
        // input (implausible counts, truncation, bad offsets) returns an Err
        // instead of allocating unbounded memory or panicking.
        let prefetch = match parse_prefetch(&buffer) {
            Ok(pf) => pf,
            Err(e) => {
                warn!(
                    "Failed to parse artifact {} as Prefetch file: {}",
                    artifact.id, e
                );
                // A file the source could not hand over in full failed to parse
                // for a different reason than a corrupt one, and the two point
                // at different follow-up (re-acquire vs. carve/repair).
                let (reason, failure) = if short_read {
                    (
                        seance_core::io::IncompleteReason::ShortRead,
                        "short_read_before_parse",
                    )
                } else {
                    (
                        seance_core::io::IncompleteReason::UnresolvedStructure,
                        "parse_failed",
                    )
                };
                return Ok(vec![parse_status_artifact(
                    artifact,
                    reason,
                    failure,
                    &format!(
                        "This file was identified as a Windows prefetch file but could not be \
                         decoded ({e}): the program it records was executed, and no execution \
                         time or loaded-file list from it is in this case"
                    ),
                )]);
            }
        };

        let volumes: Vec<serde_json::Value> = prefetch
            .volumes
            .iter()
            .map(|vol| {
                json!({
                    "device_path": vol.device_path,
                    // Raw Windows FILETIME -> RFC 3339 (null when unset/invalid),
                    // not a bare u64 that downstream would misread as Unix time.
                    "creation_time": seance_core::time::filetime_to_rfc3339(vol.creation_time),
                    "serial_number": vol.serial_number,
                })
            })
            .collect();

        let executable_name = prefetch.executable_name;
        let run_count = prefetch.run_count;
        let run_times = prefetch.run_times;
        let loaded_files = prefetch.loaded_files;
        let loaded_files_count = loaded_files.len();
        let short_desc = format!("{} (executed {} times)", executable_name, run_count);

        info!(
            "Successfully parsed prefetch file: {} with {} executions",
            executable_name, run_count
        );

        let prefetch_artifact = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "PrefetchEntry",
                "executable_name": executable_name.clone(),
                "run_count": run_count,
                // Raw Windows FILETIME -> RFC 3339 (null when unset/invalid).
                "last_execution_time": seance_core::time::filetime_to_rfc3339(prefetch.last_execution_time),
                "volumes": volumes,
                "loaded_files_count": loaded_files_count,
                "loaded_files": loaded_files,
                "version": prefetch.version_label,
                "short_desc": short_desc,
            }),
        )
        .with_parent(artifact.id);

        let mut produced = vec![prefetch_artifact];

        // Timeline events: one per recorded last-run time. Windows 8+ keeps up to
        // eight; older versions expose the single most-recent execution.
        let total_runs = run_times.len();
        for (idx, &filetime) in run_times.iter().enumerate() {
            let unix_secs = match seance_core::time::filetime_to_unix_secs(filetime) {
                Some(s) => s,
                None => continue,
            };
            let short_desc = if total_runs > 1 {
                format!(
                    "Program executed: {} (run count {}, execution {} of {})",
                    executable_name,
                    run_count,
                    idx + 1,
                    total_runs
                )
            } else {
                format!(
                    "Program executed: {} (run count {})",
                    executable_name, run_count
                )
            };
            let event = Artifact::new(
                artifact.case_id,
                ArtifactType::TimelineEvent,
                None,
                json!({
                    "timestamp": unix_secs,
                    "timestamp_desc": "Program Last Executed",
                    "source_module": "plugin.windows.prefetch_parser",
                    "short_desc": short_desc,
                    "executable_name": executable_name,
                    "run_count": run_count,
                }),
            )
            .with_parent(artifact.id);
            produced.push(event);
        }

        if short_read {
            warn!(
                "Prefetch artifact {}: only {} of {} declared bytes were readable; \
                 run times and loaded-file list may be short",
                artifact.id,
                buffer.len(),
                declared
            );
            stamp_short_read(&mut produced, buffer.len() as u64, declared);
        }

        Ok(produced)
    }
}

/// Mark every record built from a prefetch file the source could not deliver in
/// full.
///
/// The SCCA sections are addressed by offset, so a short buffer does not simply
/// stop at the last complete record: whichever sections lay past the shortfall
/// are absent, and the run count, run times and loaded-file list are all floors.
fn stamp_short_read(produced: &mut [Artifact], bytes_read: u64, declared: u64) {
    for a in produced.iter_mut() {
        let Some(map) = a.metadata.as_object_mut() else {
            continue;
        };
        map.insert("content_incomplete".into(), json!(true));
        map.insert(
            "content_incomplete_reason".into(),
            json!(seance_core::io::IncompleteReason::ShortRead.as_str()),
        );
        map.insert("inventory_incomplete".into(), json!(true));
        map.insert(
            "inventory_incomplete_reason".into(),
            json!(seance_core::io::IncompleteReason::ShortRead.as_str()),
        );
        map.insert("bytes_read".into(), json!(bytes_read));
        map.insert("declared_size".into(), json!(declared));
        map.insert(
            "incomplete_detail".into(),
            json!(
                "the prefetch file was not readable to its declared end; the run times and \
                 loaded-file list are a floor, not the whole record"
            ),
        );
    }
}

/// Build the examiner-facing record that says a file this parser identified as
/// Windows prefetch yielded no execution record.
///
/// Forensic meaning: a `.pf` file exists because Windows prepared that program
/// for execution. If the parser cannot read it, producing nothing makes the file
/// indistinguishable from a machine where the program was never run — and
/// "PREFETCH shows no trace of it" is exactly the conclusion an examiner would
/// draw. This record keeps the file's existence, and the failure to read it, in
/// the case (B2-165).
fn parse_status_artifact(
    source: &Artifact,
    reason: seance_core::io::IncompleteReason,
    failure: &str,
    message: &str,
) -> Artifact {
    let name = source
        .metadata
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("prefetch file");
    Artifact::new(
        source.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "PrefetchParseStatus",
            "record_type": "prefetch_parse_status",
            "name": format!("{} (not parsed)", name),
            "content_incomplete": true,
            "content_incomplete_reason": reason.as_str(),
            // Which of the two ways the file was lost: never read at all, or
            // read and undecodable. They point an examiner at different next
            // steps (re-acquire vs. carve/repair).
            "failure": failure,
            "message": message,
        }),
    )
    .with_parent(source.id)
}
