//! The module: a setupapi log on disk becomes records.
//!
//! # How a log is recognised
//!
//! **By its first line, never by its name.** All three real logs open with the
//! byte string `[Device Install Log]`; a file that does not produces nothing
//! at all — not a refusal, not an empty record. A file merely named
//! `setupapi.dev.log` is not one of these, and inventing a parse failure for
//! it would put a statement in the case about something that is not evidence.
//!
//! The name is used only to decide whether to *read* the first bytes, so that
//! a full disk's worth of files is not opened to check — and it then rides on
//! every record, because the first line does **not** tell `setupapi.dev.log`
//! from `setupapi.setup.log` and they hold different section vocabularies.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};

use crate::parse::{self, TIME_BASIS};

/// Bytes read to decide whether a file is one of these at all.
const SNIFF_BYTES: usize = 20;

/// The largest log this build will read whole.
///
/// The largest real one measured is 1.4 MiB. 256 MiB is two orders of
/// magnitude of headroom and finite.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

pub struct SetupApiParser;

/// Whether a name is worth opening. Deliberately loose: Windows writes
/// `setupapi.dev.log`, `setupapi.setup.log`, `setupapi.app.log`,
/// `setupapi.offline.log` and a dated `setupapi.offline.<stamp>.log`, and a
/// list of exact names would miss the next one.
fn worth_sniffing(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let base = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    base.starts_with("setupapi") && base.ends_with(".log")
}

impl ForensicsModule for SetupApiParser {
    fn id(&self) -> &str {
        "plugin.windows.setupapi_log"
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
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl SetupApiParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(source) = artifact.data.as_ref() else {
            return Ok(vec![]);
        };
        let name = seance_core::shadow_copy::original_name(artifact)
            .or_else(|| artifact.metadata.get("file_name").and_then(|v| v.as_str()))
            .unwrap_or("");
        let path = artifact
            .metadata
            .get("path")
            .or_else(|| artifact.metadata.get("source_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !worth_sniffing(name) && !worth_sniffing(path) {
            return Ok(vec![]);
        }

        let mut head = [0u8; SNIFF_BYTES];
        if source.read_at(0, &mut head).unwrap_or(0) < SNIFF_BYTES {
            return Ok(vec![]);
        }
        if !parse::is_device_install_log(&head) {
            // Named like one, and not one. Nothing is said about it.
            return Ok(vec![]);
        }

        let log_file = if name.is_empty() { path } else { name };
        let size = source.size();
        if size > MAX_FILE_BYTES {
            // Said rather than skipped: a log too large to read is not a log
            // that records no device installs.
            return Ok(vec![Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::json!({
                    "type": "DeviceInstallLogCoverage",
                    "name": format!("{log_file} not read"),
                    "log_file": log_file,
                    "content_incomplete": true,
                    "content_incomplete_reason":
                        seance_core::io::IncompleteReason::CapReached.as_str(),
                    "content_incomplete_detail": format!(
                        "This device-install log is {size} bytes, past this build's \
                         {MAX_FILE_BYTES}-byte ceiling, and was not read. Nothing about the \
                         device installs it records is established either way."
                    ),
                }),
            )
            .with_parent(artifact.id)]);
        }

        let mut bytes = vec![0u8; size as usize];
        let read = source.read_at(0, &mut bytes).unwrap_or(0);
        bytes.truncate(read);
        let short = (read as u64) < size;
        // Every one of the three real logs is pure ASCII with no NUL and no
        // non-ASCII byte. A lossy decode is still the right call for a carved
        // or damaged copy: losing the whole log over one bad byte would be
        // worse than reading the rest of it.
        let text = String::from_utf8_lossy(&bytes);
        let log = parse::parse(&text);

        let mut out = Vec::new();
        let hist = log.kind_histogram();
        let device_count = log.device_sections().count();
        let mut coverage = serde_json::json!({
            "type": "DeviceInstallLogCoverage",
            "name": format!("{log_file} — {} section(s)", log.sections.len()),
            "log_file": log_file,
            // Which installation this log describes. A `setupapi.offline.log`
            // declaring 6.3.9600 inside a 10.0.16299 machine describes the
            // deployment image's servicing, not this machine's device history.
            "log_os_version": log.header.get("OS Version"),
            "header": log.header,
            "header_keys_in_file_order": log.header_order,
            "begin_log_seen": log.begin_log_seen,
            "lines_read": log.lines_read,
            "sections_total": log.sections.len(),
            "sections_concerning_a_device": device_count,
            // Every kind with its count. On the largest real log the two
            // commonest kinds are driver-store housekeeping and account for
            // 154 of 194 sections; burying them would be as wrong as hiding
            // them, so the histogram is complete and the device count is
            // separate.
            "section_kinds": hist,
            "boot_sessions": log
                .boot_sessions
                .iter()
                .map(|b| serde_json::json!({ "local_time": b.local_time, "line": b.line }))
                .collect::<Vec<_>>(),
            "boot_sessions_order_basis":
                "Boot sessions are listed in FILE ORDER and are never sorted. On real evidence \
                 they are not in chronological order -- one measured log has a session 9 h 19 m \
                 earlier than the one before it -- and the file's order is the order the machine \
                 wrote them.",
            "sections_never_closed": log.unclosed_sections,
            "clock_anomalies": log.clock_anomalies,
            "time_basis": TIME_BASIS,
            "timeline_eligible": false,
        });
        if let Some(cap) = &log.cap_reached {
            if let Some(m) = coverage.as_object_mut() {
                m.insert("content_incomplete".into(), serde_json::json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    serde_json::json!(seance_core::io::IncompleteReason::CapReached.as_str()),
                );
                m.insert("content_incomplete_detail".into(), serde_json::json!(cap));
            }
        }
        if short {
            if let Some(m) = coverage.as_object_mut() {
                m.insert("content_incomplete".into(), serde_json::json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    serde_json::json!(seance_core::io::IncompleteReason::ShortRead.as_str()),
                );
                m.insert(
                    "short_read_detail".into(),
                    serde_json::json!(format!(
                        "{read} of {size} bytes were readable. The sections below are what those \
                         bytes held; what the unread bytes hold is not established, so this log \
                         may record device installs that are not reported here."
                    )),
                );
            }
        }
        out.push(
            Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, coverage)
                .with_parent(artifact.id),
        );

        // One record per section that concerns a device. The rest are in the
        // histogram above: emitting 154 driver-store housekeeping records
        // would bury the three device installs among them.
        for sec in log.device_sections() {
            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    sec.to_json(log_file, &log),
                )
                .with_parent(artifact.id),
            );
        }
        Ok(out)
    }
}
