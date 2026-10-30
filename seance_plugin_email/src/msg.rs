use crate::{is_truncated, truncate_str};
use cfb::CompoundFile;
use chrono::{DateTime, Utc};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::io::IncompleteReason;
use serde_json::json;
use std::io::{Cursor, Read};
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

/// A record stating that a file identified as an Outlook message was **not**
/// parsed, and why.
///
/// Forensic meaning: without it, a truncated or corrupt `.msg` produces exactly
/// the same case contents as a file that was never mail. The examiner cannot
/// tell "this message could not be read" from "there was no message here".
fn parse_status(
    case_id: Uuid,
    parent_id: Uuid,
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
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
}

/// Property IDs for MSG file streams
/// Stream names follow pattern: __substg1.0_XXXX00YY where XXXX is property ID and YY is type
const PROP_SUBJECT: &str = "0037"; // PidTagSubject
const PROP_SENDER_NAME: &str = "0C1A"; // PidTagSenderName
const PROP_SENDER_EMAIL: &str = "0C1F"; // PidTagSenderEmailAddress
const PROP_SENDER_SMTP: &str = "5D01"; // PidTagSenderSmtpAddress
const PROP_SENT_REPRESENTING_NAME: &str = "0042"; // PidTagSentRepresentingName
const PROP_SENT_REPRESENTING_EMAIL: &str = "0065"; // PidTagSentRepresentingEmailAddress
const PROP_SENT_REPRESENTING_SMTP: &str = "5D02"; // PidTagSentRepresentingSmtpAddress
const PROP_DISPLAY_TO: &str = "0E04"; // PidTagDisplayTo
const PROP_DISPLAY_CC: &str = "0E03"; // PidTagDisplayCc
const PROP_DISPLAY_BCC: &str = "0E02"; // PidTagDisplayBcc
const PROP_BODY: &str = "1000"; // PidTagBody
const PROP_HTML_BODY: &str = "1013"; // PidTagHtml
const PROP_MESSAGE_ID: &str = "1035"; // PidTagInternetMessageId
const PROP_IN_REPLY_TO: &str = "1042"; // PidTagInReplyToId
                                       // PidTagInternetReferences: the RFC 5322 `References` header as Outlook stored
                                       // it, one space-separated list of ids. Never read until 2026-09-14, so a `.msg`
                                       // reply carried its parent but not its ancestry and threaded only two levels
                                       // deep (ROADMAP §5.14).
const PROP_REFERENCES: &str = "1039"; // PidTagInternetReferences

/// Cap on the body text stored on the record (64 KiB), matching the EML/PST paths.
const MAX_BODY_SIZE: usize = 64 * 1024;

/// Cap on attachment bytes promoted to a child `FileEntry`, matching the EML path.
const MAX_ATTACHMENT_BYTES: usize = 64 * 1024 * 1024;

/// One attachment sub-storage, inventoried and — where it fits the cap — read.
struct MsgAttachment {
    name: String,
    content_type: String,
    /// Declared size of the `PidTagAttachDataBinary` stream, when there is one.
    declared_size: Option<u64>,
    /// The bytes, when the stream existed, fitted the cap and read whole.
    bytes: Option<Vec<u8>>,
    /// Why the bytes are absent, when they are.
    unavailable: Option<String>,
    storage: String,
}

impl MsgAttachment {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "name": self.name,
            // The declared stream length, or null. Never 0 for "could not be
            // read": a zero-byte attachment and an unreadable one are different
            // findings.
            "size": self.declared_size,
            "content_type": self.content_type,
            "storage": self.storage,
            // Whether this attachment became a child FileEntry — which is
            // what decides whether it was hashed, detected, indexed, previewed
            // or exported. (Not carved: the carver takes file systems and
            // unallocated space, never a `FileEntry`.)
            "bytes_extracted": self.bytes.is_some(),
            "unavailable_reason": self.unavailable,
        })
    }
}

/// Parse an Outlook MSG file from OLE2 compound document
pub fn parse_msg(data: &[u8], case_id: Uuid, parent_id: Uuid, name: &str) -> Vec<Artifact> {
    let mut artifacts = Vec::new();

    let cursor = Cursor::new(data);
    let mut comp = match CompoundFile::open(cursor) {
        Ok(c) => c,
        Err(e) => {
            // The name or the magic already said this is an Outlook message.
            // Returning nothing here makes an unreadable `.msg` indistinguishable
            // from a file that was never mail, and the message it holds absent
            // from the case with nothing saying so (B5-034).
            warn!("Failed to open MSG file {}: {}", name, e);
            artifacts.push(parse_status(
                case_id,
                parent_id,
                name,
                "InvalidCompoundFile",
                IncompleteReason::UnresolvedStructure,
                "The file was identified as an Outlook message and its compound-file structure \
                 could not be opened; no message was extracted",
                &[
                    ("error", json!(e.to_string())),
                    ("declared_size", json!(data.len())),
                ],
            ));
            return artifacts;
        }
    };

    // Read string properties from __substg1.0_ streams
    let subject = read_string_property(&mut comp, PROP_SUBJECT);
    let sender_name = read_string_property(&mut comp, PROP_SENDER_NAME)
        .or_else(|| read_string_property(&mut comp, PROP_SENT_REPRESENTING_NAME))
        .unwrap_or_default();
    // Prefer the SMTP-address properties: for Exchange-originated messages the
    // legacy *EmailAddress properties hold an X.500 DN, not a usable address,
    // which surfaced as a missing/garbage sender. Fall back to the legacy
    // properties for plain SMTP messages that only set those.
    let sender_email = read_string_property(&mut comp, PROP_SENDER_SMTP)
        .or_else(|| read_string_property(&mut comp, PROP_SENT_REPRESENTING_SMTP))
        .or_else(|| read_string_property(&mut comp, PROP_SENDER_EMAIL))
        .or_else(|| read_string_property(&mut comp, PROP_SENT_REPRESENTING_EMAIL))
        .unwrap_or_default();
    let display_to = read_string_property(&mut comp, PROP_DISPLAY_TO).unwrap_or_default();
    let display_cc = read_string_property(&mut comp, PROP_DISPLAY_CC).unwrap_or_default();
    let display_bcc = read_string_property(&mut comp, PROP_DISPLAY_BCC).unwrap_or_default();
    let body_text = read_string_property(&mut comp, PROP_BODY).unwrap_or_default();
    let body_html = read_string_property(&mut comp, PROP_HTML_BODY).unwrap_or_default();
    let message_id = read_string_property(&mut comp, PROP_MESSAGE_ID).unwrap_or_default();
    let in_reply_to = read_string_property(&mut comp, PROP_IN_REPLY_TO).unwrap_or_default();
    // Outlook stores the `References` header as one string; the header's own
    // form is a whitespace-separated list of angle-bracketed ids.
    let references: Vec<String> = read_string_property(&mut comp, PROP_REFERENCES)
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();

    let subject_str = subject.unwrap_or_default();

    // Parse display recipients into lists
    let to: Vec<String> = parse_display_list(&display_to);
    let cc: Vec<String> = parse_display_list(&display_cc);
    let bcc: Vec<String> = parse_display_list(&display_bcc);

    // Enumerate the real attachment sub-storages (indices are not guaranteed to
    // run 0..count — see `attachment_storage_paths`).
    let attachment_paths = attachment_storage_paths(&comp);
    let attachment_count = attachment_paths.len();

    // Get attachment metadata
    let attachments = extract_attachment_metadata(&mut comp, &attachment_paths);

    // Extract date from binary FILETIME property (PidTagClientSubmitTime 0x0039, type 0x0040)
    // One walk for both fields — the string for display and the integer the
    // conversation views sort and page on (§5.14: an ISO 8601 string cast to an
    // integer is its year) — so the two always name the same instant read from
    // the same property. `PidTagCreationTime` is the fallback.
    let instant = read_filetime_instant(&mut comp, "0039")
        .or_else(|| read_filetime_instant(&mut comp, "3007"));
    let date_str = instant
        .as_ref()
        .map(|(text, _)| text.clone())
        .unwrap_or_default();
    let date_epoch = instant.as_ref().map(|(_, secs)| *secs);

    let body_truncated =
        is_truncated(&body_text, MAX_BODY_SIZE) || is_truncated(&body_html, MAX_BODY_SIZE);
    // An attachment whose bytes were not carried into the case is inventory
    // only: it is never hashed, detected, indexed, previewed or exported.
    let attachments_incomplete = attachments.iter().any(|att| att.bytes.is_none());

    let mut metadata = json!({
        "type": "EmailMessage",
        "analysis_type": "email",
        "subtype": "email_message",
        "format": "msg",
        "from": sender_email,
        "from_name": sender_name,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "subject": subject_str,
        "date": date_str,
        // Unix seconds beside the RFC 3339 string; see the eml reader for why.
        "date_epoch": date_epoch,
        "message_id": message_id,
        "in_reply_to": in_reply_to,
        "references": references,
        "body_text": truncate_str(&body_text, MAX_BODY_SIZE),
        "body_html": truncate_str(&body_html, MAX_BODY_SIZE),
        // Structured honesty: the `...[truncated]` sentinel inside the text is
        // prose that search/export/UI do not read (B2-105).
        "body_truncated": body_truncated,
        "attachment_count": attachment_count,
        "attachments": attachments.iter().map(MsgAttachment::to_json).collect::<Vec<_>>(),
        "attachments_incomplete": attachments_incomplete,
        "has_attachments": attachment_count > 0,
        "container": name,
    });

    // The thread the message belongs to, derived from the RFC 5322 headers by
    // the one writer in `crate::thread` so every format this crate reads
    // publishes the same keys with the same basis beside them (§5.14).
    if let Some(map) = metadata.as_object_mut() {
        crate::thread::stamp(map, &message_id, &in_reply_to, &references);
    }

    // `body_truncated` and `attachments_incomplete` are this parser's own keys;
    // the API, export and court-census honesty paths key on `content_incomplete`
    // and `content_incomplete_reason`. Without the standard pair a clipped body
    // or an attachment left out of the case exported as a complete recovery —
    // the same gap the EML path already closes (B3-085, B5-003). Both sets are
    // emitted; the bespoke keys stay for any existing consumer.
    if body_truncated || attachments_incomplete {
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!(IncompleteReason::CapReached.as_str());
    }

    let record =
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id);
    let record_id = record.id;

    artifacts.push(record);

    // Every attachment whose bytes were read becomes a child FileEntry, so the
    // hasher, the carver, the file analyser and the exporter all see it. An
    // attachment that stays inventory-only is listed on the record above with
    // `bytes_extracted: false` and its reason, and the record carries the
    // standard incompleteness pair.
    for att in &attachments {
        let Some(bytes) = att.bytes.as_ref() else {
            continue;
        };
        let att_meta = json!({
            "name": att.name,
            "size": bytes.len(),
            "content_type": att.content_type,
            "source": "email_attachment",
            "email_subject": subject_str,
            "email_message_id": message_id,
            "storage": att.storage,
        });
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.clone()));
        artifacts.push(
            Artifact::new(case_id, ArtifactType::FileEntry, Some(ds), att_meta)
                .with_parent(record_id),
        );
    }

    // Create timeline event if we have a date
    if !date_str.is_empty() {
        let description = if !sender_email.is_empty() {
            format!("Email from {} - {}", sender_email, subject_str)
        } else {
            format!("Email - {}", subject_str)
        };

        let timeline_metadata = json!({
            "timestamp": date_str,
            "timestamp_desc": "Email Sent",
            "source_module": "plugin.email.parser",
            "short_desc": description,
            "event_type": "email_message",
            "source": name,
            "from": sender_email,
            "to": to,
            "subject": subject_str,
        });

        let timeline = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            timeline_metadata,
        )
        .with_parent(parent_id);

        artifacts.push(timeline);
    }

    debug!("Parsed MSG file {}: subject={}", name, subject_str);

    artifacts
}

/// Read a string property from __substg1.0_XXXX streams
/// Tries Unicode (001F) first, then ANSI (001E)
fn read_string_property<R: Read + std::io::Seek>(
    comp: &mut CompoundFile<R>,
    prop_id: &str,
) -> Option<String> {
    // Try Unicode stream first (type 001F)
    let unicode_path = format!("/__substg1.0_{prop_id}001F");
    if let Ok(mut stream) = comp.open_stream(&unicode_path) {
        let mut buf = Vec::new();
        if stream.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            // UTF-16LE encoded — truncate to even length for safety
            let safe_len = buf.len() & !1;
            let chars: Vec<u16> = buf[..safe_len]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return Some(
                String::from_utf16_lossy(&chars)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }

    // Try ANSI stream (type 001E)
    let ansi_path = format!("/__substg1.0_{prop_id}001E");
    if let Ok(mut stream) = comp.open_stream(&ansi_path) {
        let mut buf = Vec::new();
        if stream.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            return Some(
                String::from_utf8_lossy(&buf)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }

    None
}

/// Parse a semicolon-separated display list into individual addresses
fn parse_display_list(display: &str) -> Vec<String> {
    if display.is_empty() {
        return Vec::new();
    }
    display
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The storage paths of every attachment sub-storage, in document order.
///
/// Forensic meaning: MSG attachment storages are named
/// `__attach_version1.0_#XXXXXXXX`, but the index is only *conventionally*
/// `0..count`. Outlook leaves gaps when an attachment is deleted, and some
/// producers start at 1. Enumerating `0..count` (the old behaviour) therefore
/// invented empty slots for indices that do not exist and skipped the real
/// storages past the gap, so a message with attachments `#0`, `#2` reported one
/// nameless `attachment_1` and never surfaced the second file (B2-104). Reading
/// the directory tells the truth for any numbering.
fn attachment_storage_paths<R: Read + std::io::Seek>(comp: &CompoundFile<R>) -> Vec<String> {
    let mut paths: Vec<String> = comp
        .walk()
        .filter(|entry| {
            entry.is_storage()
                && entry
                    .name()
                    .to_ascii_lowercase()
                    .starts_with("__attach_version1.0_")
        })
        .map(|entry| entry.path().to_string_lossy().to_string())
        .collect();
    // `walk` order is tree order; sort so the inventory is stable and matches the
    // stored attachment index.
    paths.sort();
    paths
}

/// Inventory every attachment sub-storage and read the bytes of those that fit
/// the cap.
///
/// Forensic meaning: an attachment that is only inventoried is a filename in a
/// table. It is never hashed, never detected, never previewed and never exported,
/// so it reads as recovered evidence that merely happens to be absent from the
/// case. Reading the bytes here is what lets the caller emit it as a child
/// `FileEntry`; where the bytes could not be read, the row says so instead of
/// looking the same as one that was (B5-003).
fn extract_attachment_metadata<R: Read + std::io::Seek>(
    comp: &mut CompoundFile<R>,
    paths: &[String],
) -> Vec<MsgAttachment> {
    let mut attachments = Vec::new();

    for (i, prefix) in paths.iter().enumerate() {
        // Try to read attachment filename
        let filename = read_substg_string(comp, prefix, "3707") // PidTagAttachLongFilename
            .or_else(|| read_substg_string(comp, prefix, "3704")) // PidTagAttachFilename
            .unwrap_or_else(|| format!("attachment_{}", i));

        // Try to read content type
        let content_type = read_substg_string(comp, prefix, "370E") // PidTagAttachMimeTag
            .unwrap_or_else(|| "application/octet-stream".to_string());

        // The data stream: its declared length, and its bytes when they fit.
        let data_path = format!("{prefix}/__substg1.0_37010102"); // PidTagAttachDataBinary
        let mut declared_size = None;
        let mut bytes = None;
        let mut unavailable = None;
        match comp.open_stream(&data_path) {
            Ok(mut stream) => {
                let len = stream.len();
                declared_size = Some(len);
                if len > MAX_ATTACHMENT_BYTES as u64 {
                    unavailable = Some(format!(
                        "the attachment is {len} bytes, over this parser's \
                         {MAX_ATTACHMENT_BYTES}-byte extraction cap, so its bytes were not \
                         carried into the case"
                    ));
                } else {
                    let mut buf = Vec::with_capacity(len as usize);
                    match stream.read_to_end(&mut buf) {
                        Ok(_) if buf.len() as u64 == len => bytes = Some(buf),
                        Ok(_) => {
                            unavailable = Some(format!(
                                "the attachment stream declares {len} bytes and {} were readable, \
                                 so no content was carried into the case",
                                buf.len()
                            ))
                        }
                        Err(e) => {
                            unavailable =
                                Some(format!("the attachment stream could not be read: {e}"))
                        }
                    }
                }
            }
            Err(e) => {
                unavailable = Some(format!(
                    "this attachment storage holds no readable data stream: {e}"
                ))
            }
        }

        attachments.push(MsgAttachment {
            name: filename,
            content_type,
            declared_size,
            bytes,
            unavailable,
            storage: prefix.clone(),
        });
    }

    attachments
}

/// Read a string property from within an attachment substorage
fn read_substg_string<R: Read + std::io::Seek>(
    comp: &mut CompoundFile<R>,
    prefix: &str,
    prop_id: &str,
) -> Option<String> {
    // Try Unicode first
    let path = format!("{prefix}/__substg1.0_{prop_id}001F");
    if let Ok(mut stream) = comp.open_stream(&path) {
        let mut buf = Vec::new();
        if stream.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            let safe_len = buf.len() & !1;
            let chars: Vec<u16> = buf[..safe_len]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return Some(
                String::from_utf16_lossy(&chars)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }

    // Try ANSI
    let path = format!("{prefix}/__substg1.0_{prop_id}001E");
    if let Ok(mut stream) = comp.open_stream(&path) {
        let mut buf = Vec::new();
        if stream.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            return Some(
                String::from_utf8_lossy(&buf)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }

    None
}

/// Read a FILETIME (8-byte binary) property from the MSG compound document.
/// FILETIME is 100-nanosecond intervals since 1601-01-01.
/// The same property as [`read_filetime_property`], in unix seconds.
/// One FILETIME property as **both** an RFC 3339 string and unix seconds,
/// accepted or refused once.
///
/// The string and the integer were read by two functions with different
/// acceptance rules: the string required `DateTime::from_timestamp` to succeed
/// (so an out-of-range value was refused) while the integer had no upper bound
/// at all, so a `0x7FFF…` "never" FILETIME produced a year-30828 `date_epoch`
/// beside an empty `date` and no timeline event. One decision, one pair.
fn read_filetime_instant<R: Read + std::io::Seek>(
    comp: &mut CompoundFile<R>,
    prop_id: &str,
) -> Option<(String, i64)> {
    const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;
    let path = format!("/__substg1.0_{prop_id}0040");
    let mut stream = comp.open_stream(&path).ok()?;
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).ok()?;
    let filetime = u64::from_le_bytes(buf);
    // At or below the epoch difference is what an unset FILETIME decodes to,
    // and 1601 is not a date a message was sent on.
    if filetime <= FILETIME_UNIX_DIFF {
        return None;
    }
    let unix_100ns = filetime - FILETIME_UNIX_DIFF;
    let secs = i64::try_from(unix_100ns / 10_000_000).ok()?;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    // The calendar conversion is the stricter of the two, so it decides for
    // both: a value it cannot place on a calendar is not a date.
    let dt = DateTime::<Utc>::from_timestamp(secs, nanos)?;
    Some((dt.to_rfc3339(), secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_display_list_empty() {
        assert!(parse_display_list("").is_empty());
    }

    #[test]
    fn test_parse_display_list_single() {
        let result = parse_display_list("alice@example.com");
        assert_eq!(result, vec!["alice@example.com"]);
    }

    #[test]
    fn test_parse_display_list_multiple() {
        let result = parse_display_list("alice@example.com; bob@example.com; charlie@example.com");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "alice@example.com");
        assert_eq!(result[1], "bob@example.com");
        assert_eq!(result[2], "charlie@example.com");
    }

    #[test]
    fn test_parse_display_list_with_whitespace() {
        let result = parse_display_list("  alice@example.com ;  bob@example.com  ");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "alice@example.com");
        assert_eq!(result[1], "bob@example.com");
    }

    #[test]
    fn test_parse_display_list_trailing_semicolons() {
        let result = parse_display_list("alice@example.com;;");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "alice@example.com");
    }

    #[test]
    fn test_truncate_str_msg() {
        assert_eq!(truncate_str("short", 100), "short");
        let result = truncate_str("a long string that exceeds limit", 10);
        assert!(result.contains("...[truncated]"));
    }

    /// Build a minimal OLE2 MSG in memory with the given unicode string
    /// properties (`prop_id` -> value), returning the raw bytes.
    fn build_msg(props: &[(&str, &str)]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        for (prop_id, value) in props {
            let path = format!("/__substg1.0_{prop_id}001F");
            let mut stream = comp.create_stream(&path).unwrap();
            let utf16: Vec<u8> = value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            stream.write_all(&utf16).unwrap();
        }
        comp.into_inner().into_inner()
    }

    #[test]
    fn msg_prefers_smtp_address_over_x500_dn() {
        // Exchange-style: legacy 0C1F holds an X.500 DN, 5D01 the real SMTP.
        let data = build_msg(&[
            ("0037", "Quarterly report"),
            ("0C1F", "/O=EXCHANGE/OU=EAG/CN=RECIPIENTS/CN=ALICE"),
            ("5D01", "alice@example.com"),
        ]);
        let out = parse_msg(&data, Uuid::new_v4(), Uuid::new_v4(), "x.msg");
        let rec = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .expect("record");
        assert_eq!(
            rec.metadata.get("from").and_then(|v| v.as_str()),
            Some("alice@example.com")
        );
    }

    #[test]
    fn msg_falls_back_to_legacy_email_without_smtp() {
        // Plain SMTP message: only the legacy property is set.
        let data = build_msg(&[("0037", "Hi"), ("0C1F", "bob@example.com")]);
        let out = parse_msg(&data, Uuid::new_v4(), Uuid::new_v4(), "y.msg");
        let rec = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .expect("record");
        assert_eq!(
            rec.metadata.get("from").and_then(|v| v.as_str()),
            Some("bob@example.com")
        );
    }

    /// The single status record a failed open must produce.
    fn only_status(artifacts: &[Artifact]) -> &Artifact {
        assert_eq!(artifacts.len(), 1, "{artifacts:?}");
        let status = &artifacts[0];
        assert_eq!(
            status.metadata.get("type").and_then(|v| v.as_str()),
            Some("EmailParseStatus")
        );
        assert_eq!(
            status.metadata.get("content_incomplete"),
            Some(&json!(true))
        );
        assert!(status
            .metadata
            .get("content_incomplete_reason")
            .and_then(|v| v.as_str())
            .is_some_and(|r| !r.is_empty()));
        status
    }

    #[test]
    fn test_parse_msg_invalid_data() {
        // Random bytes that the format detector called an Outlook message. The
        // file cannot be opened, and an empty result would be indistinguishable
        // from a file that was never mail (B5-034).
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let artifacts = parse_msg(&data, Uuid::new_v4(), Uuid::new_v4(), "bad.msg");
        let status = only_status(&artifacts);
        assert_eq!(
            status.metadata.get("status").and_then(|v| v.as_str()),
            Some("InvalidCompoundFile")
        );
        assert_eq!(
            status.metadata.get("file_name").and_then(|v| v.as_str()),
            Some("bad.msg")
        );
    }

    #[test]
    fn test_parse_msg_empty() {
        let artifacts = parse_msg(&[], Uuid::new_v4(), Uuid::new_v4(), "empty.msg");
        only_status(&artifacts);
    }

    #[test]
    fn test_parse_msg_truncated_ole2() {
        // Valid OLE2 magic but truncated: the strongest case of all, because the
        // magic itself said this was a compound file. The bytes are the real
        // signature, taken from one place — they were written by hand here and
        // were not the OLE2 signature at all, which is how the transposed
        // constant in `detection.rs` survived.
        let mut data = vec![0u8; 20];
        data[0..8].copy_from_slice(&crate::detection::OLE2_SIGNATURE);
        let artifacts = parse_msg(&data, Uuid::new_v4(), Uuid::new_v4(), "truncated.msg");
        only_status(&artifacts);
    }

    /// Build a minimal MSG carrying one attachment sub-storage with `bytes` in
    /// its `PidTagAttachDataBinary` stream.
    fn build_msg_with_attachment(filename: &str, bytes: &[u8]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        {
            let mut stream = comp.create_stream("/__substg1.0_0037001F").unwrap();
            let utf16: Vec<u8> = "With attachment"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            stream.write_all(&utf16).unwrap();
        }
        comp.create_storage("/__attach_version1.0_#00000000")
            .unwrap();
        {
            let mut stream = comp
                .create_stream("/__attach_version1.0_#00000000/__substg1.0_3707001F")
                .unwrap();
            let utf16: Vec<u8> = filename
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            stream.write_all(&utf16).unwrap();
        }
        {
            let mut stream = comp
                .create_stream("/__attach_version1.0_#00000000/__substg1.0_37010102")
                .unwrap();
            stream.write_all(bytes).unwrap();
        }
        comp.into_inner().into_inner()
    }

    /// An attachment must become a child `FileEntry` carrying its bytes.
    ///
    /// What an examiner learns: whether the file that came with this message is
    /// in the case. Inventory alone is a filename in a table — never hashed,
    /// never detected, never previewed, never exported — which reads as recovered
    /// evidence that merely happens to be absent (B5-003).
    #[test]
    fn a_msg_attachment_becomes_a_child_file_entry_with_its_bytes() {
        let payload = b"%PDF-1.4 not really a pdf";
        let data = build_msg_with_attachment("invoice.pdf", payload);
        let out = parse_msg(&data, Uuid::new_v4(), Uuid::new_v4(), "with_att.msg");

        let record = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .expect("the message record");
        assert_eq!(record.metadata["attachment_count"], json!(1));
        assert_eq!(
            record.metadata["attachments"][0]["name"],
            json!("invoice.pdf")
        );
        assert_eq!(
            record.metadata["attachments"][0]["bytes_extracted"],
            json!(true)
        );
        assert_eq!(record.metadata["attachments_incomplete"], json!(false));
        assert!(
            record.metadata.get("content_incomplete").is_none(),
            "a message whose attachment is in the case is not incomplete"
        );

        let child = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("the attachment must be a child FileEntry, not a table row");
        assert_eq!(child.parent_id, Some(record.id));
        assert_eq!(child.metadata["name"], json!("invoice.pdf"));
        let source = child.data.as_ref().expect("the child carries its bytes");
        assert_eq!(source.size(), payload.len() as u64);
    }

    /// An attachment whose bytes could not be carried must say so, and the
    /// record must carry the standard incompleteness pair.
    #[test]
    fn an_attachment_with_no_data_stream_marks_the_record_incomplete() {
        use std::io::{Cursor, Write};
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        {
            let mut stream = comp.create_stream("/__substg1.0_0037001F").unwrap();
            let utf16: Vec<u8> = "No data"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            stream.write_all(&utf16).unwrap();
        }
        comp.create_storage("/__attach_version1.0_#00000000")
            .unwrap();
        let data = comp.into_inner().into_inner();

        let out = parse_msg(&data, Uuid::new_v4(), Uuid::new_v4(), "no_data.msg");
        let record = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .expect("the message record");

        assert_eq!(record.metadata["attachment_count"], json!(1));
        assert_eq!(
            record.metadata["attachments"][0]["bytes_extracted"],
            json!(false)
        );
        assert!(record.metadata["attachments"][0]["unavailable_reason"].is_string());
        // Size is null, never 0: "zero bytes" and "could not be read" are
        // different findings.
        assert!(record.metadata["attachments"][0]["size"].is_null());
        assert_eq!(record.metadata["attachments_incomplete"], json!(true));
        assert_eq!(record.metadata["content_incomplete"], json!(true));
        assert!(record.metadata["content_incomplete_reason"].is_string());
        assert!(
            !out.iter()
                .any(|a| a.artifact_type == ArtifactType::FileEntry),
            "nothing may be promoted when there were no bytes to promote"
        );
    }

    /// A body clipped at the cap must carry the standard pair, not only the
    /// parser's own `body_truncated` key that no consumer reads (B5-003).
    #[test]
    fn a_clipped_msg_body_carries_the_standard_incompleteness_pair() {
        let long = "x".repeat(MAX_BODY_SIZE + 1024);
        let data = build_msg(&[("0037", "Long"), ("1000", &long)]);
        let out = parse_msg(&data, Uuid::new_v4(), Uuid::new_v4(), "long.msg");
        let record = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .expect("the message record");

        assert_eq!(record.metadata["body_truncated"], json!(true));
        assert_eq!(record.metadata["content_incomplete"], json!(true));
        assert!(record.metadata["content_incomplete_reason"].is_string());
    }
}
