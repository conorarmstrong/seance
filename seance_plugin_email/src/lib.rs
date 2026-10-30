#![forbid(unsafe_code)]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
mod detection;
mod eml;
mod emlx;
mod msg;
pub mod ost4k;
mod pst;
pub mod pst512;
/// The PST/OST entry point, public so the real-file tests can drive it.
pub use pst::parse_pst;
pub mod thread;

use detection::{detect_email_format, EmailFormat};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::SourceCursor,
    io::{read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::io::Read;
use tracing::{debug, warn};

/// A nameless `.emlx` is recognised by its whole wrapper: a decimal count
/// line and an XML plist starting exactly where the count says the message
/// ends. A real message is larger than the 1,024-byte probe, so the probe
/// alone cannot see the plist; this makes one bounded five-byte read at the
/// counted offset instead. Only the bytes `<?xml` there are accepted — a bare
/// number on a first line is common text and is not enough.
fn emlx_wrapper_at_counted_offset(
    ds: &dyn seance_core::data_source::DataSource,
    header: &[u8],
) -> bool {
    let Some((count, start)) = detection::emlx_count_line(header) else {
        return false;
    };
    let Some(end) = (start as u64).checked_add(count as u64) else {
        return false;
    };
    if end.saturating_add(5) > ds.size() {
        return false;
    }
    let mut probe = [0u8; 5];
    read_full(ds, end, &mut probe) == 5 && &probe == b"<?xml"
}

/// Maximum email file size to read into memory (512 MB)
const MAX_EMAIL_FILE_SIZE: u64 = 512 * 1024 * 1024;

pub struct EmailParser;

impl ForensicsModule for EmailParser {
    fn id(&self) -> &str {
        "plugin.email.parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::Container]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // Fast path: check subtype for MBOX containers
        if let Some(subtype) = artifact.subtype() {
            if subtype == "mbox" {
                return self.process_mbox(artifact, &name);
            }
            // OLE2 subtype could be a .msg file — check extension before skipping
            if subtype == "ole2" {
                if !name.to_lowercase().ends_with(".msg") {
                    return Ok(Vec::new());
                }
            } else if subtype != "eml" && subtype != "msg" {
                return Ok(Vec::new());
            }
        }

        // Check if this looks like an email file
        let lower_name = name.to_lowercase();
        let might_be_email = lower_name.ends_with(".eml")
            || lower_name.ends_with(".emlx")
            || lower_name.ends_with(".msg")
            || lower_name.ends_with(".mbox")
            || lower_name.ends_with(".mbx")
            || lower_name.ends_with(".pst")
            || lower_name.ends_with(".ost");

        if !might_be_email && artifact.subtype().is_none() {
            // No extension match and no subtype — do content detection
            let data_source = match artifact.data.as_ref() {
                Some(ds) => ds,
                None => return Ok(Vec::new()),
            };

            // Read header for detection. The read loops over short reads: a
            // windowed/chunked source may hand back a handful of bytes per call,
            // and a 40-byte "header" would fail the format gate and drop a
            // perfectly valid mail store (BUG B2-106).
            let mut header = vec![0u8; 1024];
            let bytes_read = read_full(data_source.as_ref(), 0, &mut header);
            if bytes_read == 0 {
                return Ok(Vec::new());
            }
            header.truncate(bytes_read);

            let format = detect_email_format(&header, &name);
            if format == EmailFormat::Unknown
                && !emlx_wrapper_at_counted_offset(data_source.as_ref(), &header)
            {
                return Ok(Vec::new());
            }
        }

        // Read the full content
        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("Email parser requires data source".to_string())
        })?;

        let file_size = data_source.size();
        if file_size > MAX_EMAIL_FILE_SIZE {
            warn!(
                "Email file {} too large ({} bytes, max {}), skipping",
                name, file_size, MAX_EMAIL_FILE_SIZE
            );
            return Ok(vec![not_parsed_marker(
                artifact,
                &name,
                "OverSizeCap",
                IncompleteReason::CapReached,
                "Mail store exceeds the parser's in-memory size cap; no messages were extracted",
                &[
                    ("declared_size", json!(file_size)),
                    ("max_size", json!(MAX_EMAIL_FILE_SIZE)),
                ],
            )]);
        }

        let mut cursor = SourceCursor::new(data_source.clone());
        let mut content = Vec::new();
        if let Err(e) = cursor.read_to_end(&mut content) {
            warn!("Failed to read email content for {}: {}", name, e);
            return Ok(vec![not_parsed_marker(
                artifact,
                &name,
                "ReadFailed",
                IncompleteReason::ShortRead,
                "Mail store could not be read; no messages were extracted",
                &[
                    ("declared_size", json!(file_size)),
                    ("error", json!(e.to_string())),
                ],
            )]);
        }

        if content.is_empty() {
            if file_size > 0 {
                return Ok(vec![short_read_marker(artifact, &name, 0, file_size)]);
            }
            return Ok(Vec::new());
        }

        // Detect format from content + name
        let format = detect_email_format(&content, &name);

        let mut produced = match format {
            EmailFormat::Eml => {
                debug!("EmailParser processing EML: {}", name);
                eml::parse_eml_message(&content, artifact.case_id, artifact.id, &name, None)
            }
            EmailFormat::Emlx => {
                debug!("EmailParser processing EMLX: {}", name);
                emlx::parse_emlx(
                    &content,
                    artifact.case_id,
                    artifact.id,
                    &name,
                    artifact.data.as_ref(),
                )
            }
            EmailFormat::Mbox => {
                debug!("EmailParser processing MBOX: {}", name);
                eml::parse_mbox(&content, artifact.case_id, artifact.id, &name)
            }
            EmailFormat::Msg => {
                debug!("EmailParser processing MSG: {}", name);
                msg::parse_msg(&content, artifact.case_id, artifact.id, &name)
            }
            EmailFormat::Pst => {
                debug!("EmailParser processing PST: {}", name);
                pst::parse_pst(&content, artifact.case_id, artifact.id, &name)
            }
            // Reaching here means the name or the container subtype already
            // said "this is mail" — a `.msg` whose bytes are not an OLE2
            // compound document, or an artifact a container labelled `eml` —
            // and the content matched no mail format this parser reads.
            // Returning an empty vec put that file in the same place as a
            // machine with no mail on it (same class as B8-046).
            EmailFormat::Unknown => vec![not_parsed_marker(
                artifact,
                &name,
                "FormatUnrecognised",
                IncompleteReason::UnresolvedStructure,
                "This file was identified as mail by its name or container, and its content \
                 matched no mail format this parser reads; no messages were extracted",
                &[("declared_size", json!(file_size))],
            )],
        };

        // A store this parser claimed and split into nothing must not read as a
        // machine with no mail on it — the B8-046 hole the EML and MSG paths
        // were closed for, which stayed open on mbox: a `Container` labelled
        // `mbox` holding text with no `From ` separator line yielded zero
        // artifacts, so an examiner saw the same case contents either way.
        if produced.is_empty() {
            produced.push(no_messages_marker(artifact, &name, file_size));
        }

        // The store was short of its declared size: whatever parsed is a prefix,
        // never the whole mailbox.
        if (content.len() as u64) < file_size {
            produced.push(short_read_marker(
                artifact,
                &name,
                content.len() as u64,
                file_size,
            ));
        }
        Ok(produced)
    }
}

/// A record stating that a file this parser claimed was read and held no
/// separable message.
///
/// A store that split into nothing used to produce nothing at all, which on the
/// case is indistinguishable from a machine with no mail on it — the B8-046
/// hole the EML and MSG paths were closed for, which stayed open on mbox: a
/// `Container` labelled `mbox` holding text with no `From ` separator line
/// yielded zero artifacts.
fn no_messages_marker(artifact: &Artifact, name: &str, declared_size: u64) -> Artifact {
    not_parsed_marker(
        artifact,
        name,
        "NoMessagesFound",
        IncompleteReason::UnresolvedStructure,
        concat!(
            "this file was identified as mail and read, and no message could be separated ",
            "out of it: for an mbox that means no `From ` separator line was found at the ",
            "start of a line anywhere in it. No message was recovered, and none is claimed"
        ),
        &[("declared_size", json!(declared_size))],
    )
}

/// A record stating that an email store was located but **not** parsed, and why.
///
/// Forensic meaning: the examiner learns that mail evidence existed at this path
/// and that this tool did not read it. Without the record, an over-cap or
/// unreadable multi-gigabyte PST/MBOX produces exactly the same case contents as
/// a machine that never had mail on it — an examiner could then testify that no
/// email was present when in fact none was ever examined.
fn not_parsed_marker(
    artifact: &Artifact,
    name: &str,
    status: &str,
    reason: IncompleteReason,
    message: &str,
    extra: &[(&str, serde_json::Value)],
) -> Artifact {
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("EmailParseStatus"));
    meta.insert("subtype".into(), json!("email_not_parsed"));
    meta.insert("status".into(), json!(status));
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert("content_incomplete_reason".into(), json!(reason.as_str()));
    meta.insert("file_name".into(), json!(name));
    meta.insert("message".into(), json!(message));
    meta.insert("name".into(), json!(format!("Email not parsed: {name}")));
    for (k, v) in extra {
        meta.insert((*k).to_string(), v.clone());
    }
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(artifact.id)
}

/// A record stating that only a prefix of the mail store was readable, so the
/// messages that *were* parsed are a partial recovery rather than the mailbox.
fn short_read_marker(artifact: &Artifact, name: &str, got: u64, declared: u64) -> Artifact {
    not_parsed_marker(
        artifact,
        name,
        "ShortRead",
        IncompleteReason::ShortRead,
        "Mail store ended before its declared size; parsed messages are a prefix of the mailbox",
        &[
            ("bytes_read", json!(got)),
            ("declared_size", json!(declared)),
            // `extra` is applied last, so this replaces the default display name.
            ("name", json!(format!("Email partially read: {name}"))),
        ],
    )
}

impl EmailParser {
    fn process_mbox(&self, artifact: &Artifact, name: &str) -> Result<Vec<Artifact>, ModuleError> {
        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("MBOX parser requires data source".to_string())
        })?;

        let file_size = data_source.size();
        if file_size > MAX_EMAIL_FILE_SIZE {
            warn!(
                "MBOX file {} too large ({} bytes, max {}), skipping",
                name, file_size, MAX_EMAIL_FILE_SIZE
            );
            return Ok(vec![not_parsed_marker(
                artifact,
                name,
                "OverSizeCap",
                IncompleteReason::CapReached,
                "MBOX exceeds the parser's in-memory size cap; no messages were extracted",
                &[
                    ("declared_size", json!(file_size)),
                    ("max_size", json!(MAX_EMAIL_FILE_SIZE)),
                ],
            )]);
        }

        let mut cursor = SourceCursor::new(data_source.clone());
        let mut content = Vec::new();
        if let Err(e) = cursor.read_to_end(&mut content) {
            warn!("Failed to read MBOX content for {}: {}", name, e);
            return Ok(vec![not_parsed_marker(
                artifact,
                name,
                "ReadFailed",
                IncompleteReason::ShortRead,
                "MBOX could not be read; no messages were extracted",
                &[
                    ("declared_size", json!(file_size)),
                    ("error", json!(e.to_string())),
                ],
            )]);
        }

        debug!("EmailParser processing MBOX container: {}", name);
        let mut produced = eml::parse_mbox(&content, artifact.case_id, artifact.id, name);
        if produced.is_empty() {
            produced.push(no_messages_marker(artifact, name, file_size));
        }
        if (content.len() as u64) < file_size {
            produced.push(short_read_marker(
                artifact,
                name,
                content.len() as u64,
                file_size,
            ));
        }
        Ok(produced)
    }
}

/// True when [`truncate_str`] would cut `s` at `max_bytes`.
///
/// Forensic meaning: callers stamp the result as `body_truncated` on the record.
/// The `...[truncated]` sentinel inside the text is prose — search, export and
/// the UI all treat the field as the message body, so without a structured flag a
/// cut-off body reads as the whole message an examiner may quote in a report.
pub(crate) fn is_truncated(s: &str, max_bytes: usize) -> bool {
    s.len() > max_bytes
}

/// Truncate a string to at most `max_bytes` bytes, respecting UTF-8 boundaries.
pub(crate) fn truncate_str(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        s.to_string()
    } else {
        let mut end = max_bytes;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...[truncated]", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::{
        artifact::{Artifact, ArtifactType},
        data_source::ByteSliceDataSource,
        module::ForensicsModule,
    };
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Minimal valid RFC 822 email with all standard headers and a body.
    const MINIMAL_EML: &[u8] = b"From: alice@example.com\r\n\
        To: bob@example.com\r\n\
        Subject: Test\r\n\
        Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
        \r\n\
        Hello World";

    /// EML without a Date header (should produce ParsedRecord but no TimelineEvent).
    const EML_NO_DATE: &[u8] = b"From: alice@example.com\r\n\
        To: bob@example.com\r\n\
        Subject: No date email\r\n\
        \r\n\
        Body without date";

    /// Build a FileEntry artifact backed by the given bytes, with optional name metadata.
    fn make_file_artifact(data: &[u8], name: &str) -> Artifact {
        let ds: Arc<dyn seance_core::data_source::DataSource> =
            Arc::new(ByteSliceDataSource::new(data.to_vec()));
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({"name": name}),
        )
    }

    /// Build a FileEntry artifact with no data source attached.
    fn make_artifact_no_data(name: &str) -> Artifact {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({"name": name}),
        )
    }

    // -----------------------------------------------------------------------
    // 1. Module metadata
    // -----------------------------------------------------------------------

    #[test]
    fn an_emlx_file_is_routed_to_the_emlx_reader_by_name() {
        // `From:` sits past line 10, so the content heuristic alone would
        // not call this mail: the name has to.
        let mut msg = String::new();
        for i in 0..12 {
            msg.push_str(&format!("X-Apple-Filler-{i}: x\n"));
        }
        msg.push_str("From: alice@example.com\nSubject: Routed\n\nhi\n");
        let mut data = format!("{:<10}\n", msg.len()).into_bytes();
        data.extend_from_slice(msg.as_bytes());
        data.extend_from_slice(
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
              <key>flags</key><integer>1</integer></dict></plist>\n",
        );
        let parser = EmailParser;
        let results = parser
            .process(&make_file_artifact(&data, "2.emlx"))
            .expect("process");
        let rec = results
            .iter()
            .find(|a| a.metadata["type"] == "EmailMessage")
            .expect("an EmailMessage from a .emlx");
        assert_eq!(rec.metadata["format"], "emlx");
        assert_eq!(rec.metadata["subject"], "Routed");
    }

    /// A nameless `.emlx` (carved, or renamed) larger than the 1,024-byte
    /// probe, with its identity headers past line 10 — the shape of Apple
    /// Mail's own files. The probe cannot see the plist, and the EML
    /// heuristic cannot see a `From:`; before the counted-offset read, this
    /// produced no record at all. Synthetic: pins the mechanism only.
    #[test]
    fn a_nameless_emlx_larger_than_the_probe_is_still_read_as_emlx() {
        let mut msg = String::new();
        for i in 0..12 {
            msg.push_str(&format!("X-Apple-Filler-{i}: x\n"));
        }
        msg.push_str("From: alice@example.com\nSubject: Nameless\n\n");
        msg.push_str(&"body text line\n".repeat(200));
        let mut data = format!("{:<10}\n", msg.len()).into_bytes();
        data.extend_from_slice(msg.as_bytes());
        data.extend_from_slice(
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
              <key>flags</key><integer>1</integer></dict></plist>\n",
        );
        assert!(data.len() > 2048);
        let results = EmailParser
            .process(&make_file_artifact(&data, "f0000123"))
            .expect("process");
        let rec = results
            .iter()
            .find(|a| a.metadata["type"] == "EmailMessage")
            .expect("an EmailMessage from a nameless .emlx");
        assert_eq!(rec.metadata["format"], "emlx");
        assert_eq!(rec.metadata["subject"], "Nameless");
        let body = rec.metadata["body_text"].as_str().unwrap_or_default();
        assert!(!body.contains("plist"), "the plist must not reach the body");
    }

    /// A text file whose first line is a bare number and which is not an
    /// `.emlx` stays unrecognised: the counted offset must hold `<?xml`.
    #[test]
    fn a_digits_first_line_without_a_plist_at_the_count_is_not_emlx() {
        let mut data = b"42\n".to_vec();
        data.extend_from_slice(&b"plain text, not mail\n".repeat(100));
        let results = EmailParser
            .process(&make_file_artifact(&data, "notes"))
            .expect("process");
        assert!(results.is_empty(), "got {results:?}");
    }

    #[test]
    fn module_id_is_correct() {
        let parser = EmailParser;
        assert_eq!(parser.id(), "plugin.email.parser");
    }

    #[test]
    fn module_version_is_semver() {
        let parser = EmailParser;
        let core = parser.version().split('-').next().unwrap_or_default();
        let parts: Vec<&str> = core.split('.').collect();
        assert_eq!(parts.len(), 3, "version should be MAJOR.MINOR.PATCH");
        for part in &parts {
            part.parse::<u32>()
                .expect("version component should be numeric");
        }
    }

    #[test]
    fn module_subscribes_to_file_entry_and_container() {
        let parser = EmailParser;
        let subs = parser.subscribes_to();
        assert!(subs.contains(&ArtifactType::FileEntry));
        assert!(subs.contains(&ArtifactType::Container));
        assert_eq!(subs.len(), 2);
    }

    #[test]
    fn module_input_capability_is_stream() {
        let parser = EmailParser;
        assert_eq!(
            parser.input_capability(),
            seance_core::module::InputCapability::Stream
        );
    }

    // -----------------------------------------------------------------------
    // 2. process() with a minimal valid EML via in-memory DataSource
    // -----------------------------------------------------------------------

    #[test]
    fn process_valid_eml_produces_parsed_record_and_timeline() {
        let parser = EmailParser;
        let artifact = make_file_artifact(MINIMAL_EML, "message.eml");

        let results = parser.process(&artifact).expect("process should succeed");

        // EML with a Date header should produce exactly 2 artifacts
        assert_eq!(results.len(), 2, "expected ParsedRecord + TimelineEvent");
        assert_eq!(results[0].artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(results[1].artifact_type, ArtifactType::TimelineEvent);
    }

    // -----------------------------------------------------------------------
    // 3. process() with artifact that has no data source
    // -----------------------------------------------------------------------

    #[test]
    fn process_no_data_source_returns_empty() {
        let parser = EmailParser;
        // .eml extension is recognised, but data source is None so it hits the
        // "requires data source" error path. The current implementation returns
        // an Err for this case, so we accept either Err or Ok(empty).
        let artifact = make_artifact_no_data("message.eml");
        let result = parser.process(&artifact);
        // Err (InvalidInputFormat) is acceptable; a successful parse must be empty.
        if let Ok(v) = result {
            assert!(v.is_empty(), "no data source should yield no artifacts");
        }
    }

    #[test]
    fn process_no_data_source_no_extension_returns_empty() {
        let parser = EmailParser;
        // No extension, no subtype, and no data source to sniff content from.
        let artifact = make_artifact_no_data("somefile");
        let results = parser
            .process(&artifact)
            .expect("should succeed with empty vec");
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // 4. .eml extension in metadata triggers format detection
    // -----------------------------------------------------------------------

    #[test]
    fn eml_extension_triggers_detection() {
        let parser = EmailParser;
        // The file name has .eml extension, so format detection picks EmailFormat::Eml
        // even though the content detection alone would also work.
        let artifact = make_file_artifact(MINIMAL_EML, "evidence.eml");
        let results = parser.process(&artifact).expect("process should succeed");
        assert!(
            !results.is_empty(),
            ".eml extension should cause the file to be parsed"
        );
        assert_eq!(results[0].artifact_type, ArtifactType::ParsedRecord);
    }

    #[test]
    fn eml_detected_by_content_without_extension() {
        let parser = EmailParser;
        // No .eml extension, but the content has RFC 822 headers so content
        // detection should still identify it as an EML.
        let artifact = make_file_artifact(MINIMAL_EML, "unknown_file");
        let results = parser.process(&artifact).expect("process should succeed");
        assert!(
            !results.is_empty(),
            "RFC 822 headers in content should trigger EML parsing"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Output artifact types: ParsedRecord for email, TimelineEvent for date
    // -----------------------------------------------------------------------

    #[test]
    fn output_types_with_date() {
        let parser = EmailParser;
        let artifact = make_file_artifact(MINIMAL_EML, "msg.eml");
        let results = parser.process(&artifact).unwrap();

        let types: Vec<&ArtifactType> = results.iter().map(|a| &a.artifact_type).collect();
        assert_eq!(
            types,
            vec![&ArtifactType::ParsedRecord, &ArtifactType::TimelineEvent]
        );
    }

    #[test]
    fn output_types_without_date() {
        let parser = EmailParser;
        let artifact = make_file_artifact(EML_NO_DATE, "nodate.eml");
        let results = parser.process(&artifact).unwrap();

        // No Date header means only ParsedRecord, no TimelineEvent
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].artifact_type, ArtifactType::ParsedRecord);
    }

    // -----------------------------------------------------------------------
    // 6. Email metadata fields are populated correctly
    // -----------------------------------------------------------------------

    #[test]
    fn parsed_record_metadata_fields() {
        let parser = EmailParser;
        let artifact = make_file_artifact(MINIMAL_EML, "test.eml");
        let results = parser.process(&artifact).unwrap();

        let record = &results[0];
        let meta = &record.metadata;

        assert_eq!(meta["from"], "alice@example.com");
        assert_eq!(meta["to"][0], "bob@example.com");
        assert_eq!(meta["subject"], "Test");
        assert_eq!(meta["analysis_type"], "email");
        assert_eq!(meta["subtype"], "email_message");
        assert_eq!(meta["has_attachments"], false);
        assert_eq!(meta["attachment_count"], 0);
        // body_text should contain the message body
        let body = meta["body_text"].as_str().unwrap_or("");
        assert!(
            body.contains("Hello World"),
            "body_text should contain message body"
        );
    }

    #[test]
    fn parsed_record_has_correct_case_and_parent_ids() {
        let parser = EmailParser;
        let artifact = make_file_artifact(MINIMAL_EML, "test.eml");
        let case_id = artifact.case_id;
        let parent_id = artifact.id;

        let results = parser.process(&artifact).unwrap();

        for result in &results {
            assert_eq!(result.case_id, case_id, "case_id should propagate");
            assert_eq!(
                result.parent_id,
                Some(parent_id),
                "parent_id should reference the input artifact"
            );
        }
    }

    #[test]
    fn timeline_event_metadata_fields() {
        let parser = EmailParser;
        let artifact = make_file_artifact(MINIMAL_EML, "test.eml");
        let results = parser.process(&artifact).unwrap();

        let timeline = &results[1];
        let meta = &timeline.metadata;

        assert_eq!(meta["timestamp_desc"], "Email Sent");
        assert_eq!(meta["source_module"], "plugin.email.parser");
        assert_eq!(meta["event_type"], "email_message");
        assert_eq!(meta["from"], "alice@example.com");
        assert_eq!(meta["subject"], "Test");
        // timestamp should be a non-empty ISO 8601 / RFC 3339 string
        let ts = meta["timestamp"].as_str().unwrap_or("");
        assert!(!ts.is_empty(), "timestamp should be populated");
        assert!(
            ts.contains("2024"),
            "timestamp should contain the year 2024"
        );
    }

    // -----------------------------------------------------------------------
    // Additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn process_empty_content_returns_empty() {
        let parser = EmailParser;
        let artifact = make_file_artifact(b"", "empty.eml");
        let results = parser.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "empty content should yield no artifacts"
        );
    }

    #[test]
    fn non_email_extension_with_non_email_content_skipped() {
        let parser = EmailParser;
        // Neither extension nor content match any email format
        let artifact = make_file_artifact(b"\x89PNG\r\n\x1a\n", "photo.png");
        let results = parser.process(&artifact).unwrap();
        assert!(results.is_empty(), "PNG should not be parsed as email");
    }

    #[test]
    fn subtype_eml_triggers_parsing() {
        let parser = EmailParser;
        let ds: Arc<dyn seance_core::data_source::DataSource> =
            Arc::new(ByteSliceDataSource::new(MINIMAL_EML.to_vec()));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({"name": "unknown", "subtype": "eml"}),
        );
        let results = parser.process(&artifact).unwrap();
        assert!(
            !results.is_empty(),
            "subtype 'eml' should trigger email parsing"
        );
    }

    #[test]
    fn unrecognised_subtype_skips_processing() {
        let parser = EmailParser;
        let ds: Arc<dyn seance_core::data_source::DataSource> =
            Arc::new(ByteSliceDataSource::new(MINIMAL_EML.to_vec()));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({"name": "data.bin", "subtype": "zip"}),
        );
        let results = parser.process(&artifact).unwrap();
        assert!(results.is_empty(), "unrecognised subtype should be skipped");
    }

    #[test]
    fn process_eml_with_cc_and_multiple_recipients() {
        let eml = b"From: sender@example.com\r\n\
            To: alice@example.com, bob@example.com\r\n\
            Cc: carol@example.com\r\n\
            Subject: Group email\r\n\
            Date: Tue, 02 Jan 2024 12:00:00 +0000\r\n\
            \r\n\
            Group message body";
        let parser = EmailParser;
        let artifact = make_file_artifact(eml, "group.eml");
        let results = parser.process(&artifact).unwrap();

        let record = &results[0];
        let to_list = record.metadata["to"]
            .as_array()
            .expect("to should be an array");
        assert_eq!(to_list.len(), 2);
        assert!(to_list.iter().any(|v| v == "alice@example.com"));
        assert!(to_list.iter().any(|v| v == "bob@example.com"));

        let cc_list = record.metadata["cc"]
            .as_array()
            .expect("cc should be an array");
        assert_eq!(cc_list.len(), 1);
        assert_eq!(cc_list[0], "carol@example.com");
    }

    // -----------------------------------------------------------------------
    // Evidence-dropped honesty (B2-101 / B2-106)
    // -----------------------------------------------------------------------

    use seance_core::test_support::TruncatedSource;

    fn artifact_over(ds: TruncatedSource, name: &str) -> Artifact {
        let ds: Arc<dyn seance_core::data_source::DataSource> = Arc::new(ds);
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": name }),
        )
    }

    #[test]
    fn a_mail_store_over_the_size_cap_leaves_a_record_saying_it_was_not_parsed() {
        let parser = EmailParser;
        let artifact = artifact_over(
            TruncatedSource::new(MINIMAL_EML.to_vec(), MAX_EMAIL_FILE_SIZE + 1),
            "huge.pst",
        );
        let results = parser.process(&artifact).unwrap();
        assert_eq!(
            results.len(),
            1,
            "an over-cap store must not vanish from the case"
        );
        let md = &results[0].metadata;
        assert_eq!(md["type"], "EmailParseStatus");
        assert_eq!(md["status"], "OverSizeCap");
        assert_eq!(md["content_incomplete"], json!(true));
        assert_eq!(md["content_incomplete_reason"], "cap_reached");
        assert_eq!(md["file_name"], "huge.pst");
        assert_eq!(md["declared_size"], json!(MAX_EMAIL_FILE_SIZE + 1));
    }

    #[test]
    fn a_mail_store_shorter_than_its_declared_size_is_flagged_as_a_prefix() {
        let parser = EmailParser;
        let artifact = artifact_over(
            TruncatedSource::new(MINIMAL_EML.to_vec(), MINIMAL_EML.len() as u64 + 4096),
            "truncated.eml",
        );
        let results = parser.process(&artifact).unwrap();
        let marker = results
            .iter()
            .find(|a| a.metadata["type"] == "EmailParseStatus")
            .expect("short read must leave an incomplete marker");
        assert_eq!(marker.metadata["status"], "ShortRead");
        assert_eq!(marker.metadata["content_incomplete_reason"], "short_read");
        assert_eq!(
            marker.metadata["bytes_read"],
            json!(MINIMAL_EML.len() as u64)
        );
        // The message that *did* parse is still emitted; it is just not the whole store.
        assert!(results.iter().any(|a| a.metadata["type"] == "EmailMessage"));
    }

    #[test]
    fn a_whole_mail_store_gets_no_incomplete_marker() {
        let parser = EmailParser;
        let artifact = make_file_artifact(MINIMAL_EML, "ok.eml");
        let results = parser.process(&artifact).unwrap();
        assert!(
            !results
                .iter()
                .any(|a| a.metadata["type"] == "EmailParseStatus"),
            "a complete parse must not claim to be incomplete"
        );
    }

    #[test]
    fn a_chunked_source_still_passes_the_content_detection_gate() {
        // A windowed source hands back one byte per call; the old single-shot
        // probe saw a 1-byte "header" and dropped the message (B2-106).
        #[derive(Debug)]
        struct OneBytePerCall(Vec<u8>);
        impl seance_core::data_source::DataSource for OneBytePerCall {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
                let off = offset as usize;
                if off >= self.0.len() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.0[off];
                Ok(1)
            }
            fn size(&self) -> u64 {
                self.0.len() as u64
            }
        }
        let ds: Arc<dyn seance_core::data_source::DataSource> =
            Arc::new(OneBytePerCall(MINIMAL_EML.to_vec()));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "no_extension" }),
        );
        let results = EmailParser.process(&artifact).unwrap();
        assert!(
            results.iter().any(|a| a.metadata["type"] == "EmailMessage"),
            "a chunked source must not be mis-rejected as a non-email"
        );
    }

    #[test]
    fn a_truncated_body_is_flagged_in_structured_metadata() {
        let mut eml = b"From: a@example.com\r\nSubject: Long\r\n\r\n".to_vec();
        eml.extend(std::iter::repeat_n(b'x', 70 * 1024));
        let artifact = make_file_artifact(&eml, "long.eml");
        let results = EmailParser.process(&artifact).unwrap();
        let record = results
            .iter()
            .find(|a| a.metadata["type"] == "EmailMessage")
            .expect("message record");
        assert_eq!(record.metadata["body_truncated"], json!(true));
        // B3-085: `body_truncated` is this parser's own key. The standard pair
        // is what export/API honesty reads; without it a clipped body exported
        // as the whole message.
        assert_eq!(record.metadata["content_incomplete"], json!(true));
        assert_eq!(
            record.metadata["content_incomplete_reason"],
            json!("cap_reached")
        );
    }

    /// **A real `.msg` reaches the MSG reader.** The OLE2 signature constant in
    /// `detection.rs` had two bytes transposed and a third wrong, and both
    /// tests guarding it carried the same wrong bytes, so every genuine
    /// Outlook message fell through to `FormatUnrecognised`: the product
    /// claimed MSG support on its site, in its README and in its online help,
    /// and parsed none. This test builds the compound document rather than
    /// asserting on a signature, so the format — not a copy of the constant —
    /// decides whether it passes.
    #[test]
    fn a_real_outlook_message_is_parsed_and_not_called_unrecognised() {
        use std::io::{Cursor, Write};
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        {
            // PidTagSubject, 0x0037, as Unicode (001F).
            let mut stream = comp.create_stream("/__substg1.0_0037001F").unwrap();
            let utf16: Vec<u8> = "Quarterly figures"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            stream.write_all(&utf16).unwrap();
        }
        let bytes = comp.into_inner().into_inner();
        assert_eq!(
            &bytes[0..8],
            &crate::detection::OLE2_SIGNATURE,
            "the fixture must be a real compound document"
        );

        let artifact = make_file_artifact(&bytes, "figures.msg");
        let results = EmailParser.process(&artifact).unwrap();
        assert!(
            results.iter().any(|a| a.metadata["type"] == "EmailMessage"),
            "a real .msg must produce a message, got {:?}",
            results
                .iter()
                .map(|a| a.metadata["type"].clone())
                .collect::<Vec<_>>()
        );
        let message = results
            .iter()
            .find(|a| a.metadata["type"] == "EmailMessage")
            .unwrap();
        assert_eq!(message.metadata["subject"], json!("Quarterly figures"));
    }

    /// **An mbox that splits into nothing must say so.** `split_mbox` returns
    /// an empty list for text with no `From ` separator line, and both callers
    /// pushed nothing: a `Container` labelled `mbox` then produced **zero**
    /// artifacts, which on the case is indistinguishable from a machine with
    /// no mail on it. That is the B8-046 hole the EML and MSG paths were
    /// closed for, still open on mbox.
    #[test]
    fn an_mbox_that_yields_no_message_says_so_rather_than_nothing() {
        let ds: Arc<dyn seance_core::data_source::DataSource> = Arc::new(ByteSliceDataSource::new(
            b"Just some text\nwithout an mbox separator\n".to_vec(),
        ));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(ds),
            json!({ "name": "inbox.mbox", "subtype": "mbox" }),
        );
        let out = EmailParser.process(&artifact).unwrap();
        assert_eq!(out.len(), 1, "the store must not vanish from the case");
        let m = &out[0].metadata;
        assert_eq!(m["type"], "EmailParseStatus");
        assert_eq!(m["status"], "NoMessagesFound");
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
        assert!(m["message"].as_str().unwrap_or_default().contains("From "));

        // The counterweight: a real mbox still produces its messages and no
        // marker, so the record continues to mean something.
        let mbox = b"From alice@example.com Mon Jan  1 00:00:00 2024\r\nFrom: alice@example.com\r\nSubject: One\r\n\r\nbody\r\n".to_vec();
        let ds: Arc<dyn seance_core::data_source::DataSource> =
            Arc::new(ByteSliceDataSource::new(mbox));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(ds),
            json!({ "name": "real.mbox", "subtype": "mbox" }),
        );
        let out = EmailParser.process(&artifact).unwrap();
        assert!(out.iter().any(|a| a.metadata["type"] == "EmailMessage"));
        assert!(
            !out.iter()
                .any(|a| a.metadata["status"] == "NoMessagesFound"),
            "a mailbox that parsed must carry no such marker"
        );
    }

    /// A file whose name says `.msg` and whose bytes are not an OLE2 compound
    /// document was identified as mail and parsed into nothing. It has to say
    /// so: silently returning no artifacts puts it in the same place as a
    /// machine that had no mail on it (same class as B8-046).
    ///
    /// The control for this is `non_email_extension_with_non_email_content_skipped`:
    /// a file nothing ever claimed was mail is still skipped in silence, so a
    /// status record continues to mean something.
    #[test]
    fn a_file_named_as_mail_whose_content_matches_no_format_says_it_was_not_parsed() {
        let artifact = make_file_artifact(b"not an OLE2 document at all", "letter.msg");
        let results = EmailParser.process(&artifact).unwrap();
        assert_eq!(results.len(), 1, "the file must not vanish from the case");
        let md = &results[0].metadata;
        assert_eq!(md["type"], "EmailParseStatus");
        assert_eq!(md["status"], "FormatUnrecognised");
        assert_eq!(md["content_incomplete"], json!(true));
        assert_eq!(md["content_incomplete_reason"], "unresolved_structure");
        assert_eq!(md["file_name"], "letter.msg");
    }

    /// B3-085 control: a whole message with no attachments carries no standard
    /// flag, so its absence still means "complete".
    #[test]
    fn a_complete_message_carries_no_standard_incompleteness_pair() {
        let eml = b"From: a@example.com\r\nSubject: Short\r\n\r\nhello\r\n".to_vec();
        let artifact = make_file_artifact(&eml, "short.eml");
        let results = EmailParser.process(&artifact).unwrap();
        let record = results
            .iter()
            .find(|a| a.metadata["type"] == "EmailMessage")
            .expect("message record");
        assert!(record.metadata.get("content_incomplete").is_none());
    }
}
