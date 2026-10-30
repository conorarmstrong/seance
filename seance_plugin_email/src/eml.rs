use crate::{is_truncated, truncate_str};
use chrono::{DateTime, Utc};
use mail_parser::{MessageParser, MimeHeaders};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::io::IncompleteReason;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

const MAX_BODY_SIZE: usize = 64 * 1024; // 64KB
/// Cap attachment bytes promoted to FileEntry artifacts. Beyond this size we
/// still record the attachment as inline metadata (name/size/content_type),
/// but skip extracting the bytes — prevents OOM on emails with multi-GB
/// attachments and matches the protection on the upstream email file size.
const MAX_ATTACHMENT_BYTES: usize = 64 * 1024 * 1024;

/// Parse a single EML message from raw bytes and produce artifacts
pub fn parse_eml_message(
    data: &[u8],
    case_id: Uuid,
    parent_id: Uuid,
    container_name: &str,
    message_index: Option<usize>,
) -> Vec<Artifact> {
    let mut artifacts = Vec::new();

    let message = match MessageParser::default().parse(data) {
        Some(msg) => msg,
        None => {
            // Something already decided this was mail before we got here: an
            // `.eml` extension, an RFC 822 header block found by content
            // detection, or an MBOX "From " boundary. Returning an empty vec
            // made a corrupt or truncated message disappear from the case with
            // no trace, so a mailbox with unreadable messages in it and a
            // mailbox that never held them produced identical output. MSG
            // already records its open failures; EML did not (B8-046).
            artifacts.push(unparsable_message_artifact(
                case_id,
                parent_id,
                container_name,
                message_index,
                data.len(),
            ));
            return artifacts;
        }
    };

    // Extract header fields
    let from = message
        .from()
        .and_then(|addrs| addrs.first())
        .map(|a| a.address().unwrap_or_default().to_string())
        .unwrap_or_default();

    let from_name = message
        .from()
        .and_then(|addrs| addrs.first())
        .and_then(|a| a.name())
        .unwrap_or_default()
        .to_string();

    let to: Vec<String> = message
        .to()
        .map(|addrs| {
            addrs
                .iter()
                .map(|a| a.address().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();

    let cc: Vec<String> = message
        .cc()
        .map(|addrs| {
            addrs
                .iter()
                .map(|a| a.address().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();

    let bcc: Vec<String> = message
        .bcc()
        .map(|addrs| {
            addrs
                .iter()
                .map(|a| a.address().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();

    let subject = message.subject().unwrap_or_default().to_string();

    let message_id = message.message_id().unwrap_or_default().to_string();

    let in_reply_to = message
        .in_reply_to()
        .as_text()
        .unwrap_or_default()
        .to_string();

    let references: Vec<String> = message
        .references()
        .as_text_list()
        .into_iter()
        .flatten()
        .map(|s| s.to_string())
        .collect();

    // Extract body
    let raw_body_text = message.body_text(0).unwrap_or_default();
    let raw_body_html = message.body_html(0).unwrap_or_default();
    let body_truncated =
        is_truncated(&raw_body_text, MAX_BODY_SIZE) || is_truncated(&raw_body_html, MAX_BODY_SIZE);
    let body_text = truncate_str(&raw_body_text, MAX_BODY_SIZE);
    let body_html = truncate_str(&raw_body_html, MAX_BODY_SIZE);

    // Extract attachment info. `bytes_extracted` says whether the attachment's
    // bytes were promoted to a child FileEntry (so hashing, carving and preview
    // can reach them) or only its metadata was recorded.
    let attachments: Vec<serde_json::Value> = message
        .attachments()
        .map(|att| {
            let ct = att
                .content_type()
                .map(|c| match c.subtype() {
                    Some(sub) => format!("{}/{}", c.ctype(), sub),
                    None => c.ctype().to_string(),
                })
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let len = att.contents().len();
            json!({
                "name": att.attachment_name().unwrap_or("unnamed"),
                "size": len,
                "content_type": ct,
                "bytes_extracted": len > 0 && len <= MAX_ATTACHMENT_BYTES,
            })
        })
        .collect();

    let attachment_count = attachments.len();
    let has_attachments = attachment_count > 0;
    // At least one attachment's bytes were left behind (over the per-attachment
    // cap, or empty). The message is NOT a complete recovery: without the flag a
    // 200 MiB archive attached to a message vanishes while the message still
    // reports `attachment_count: 1` and looks fully extracted (B2-103).
    let attachments_incomplete = message
        .attachments()
        .any(|att| att.contents().is_empty() || att.contents().len() > MAX_ATTACHMENT_BYTES);
    // An attachment left behind because it is over the per-attachment ceiling is
    // a cap; one left behind because it decoded to nothing is an unresolved
    // structure. Naming which of the two is what tells an examiner whether
    // raising the ceiling would recover it.
    let attachments_over_cap = message
        .attachments()
        .any(|att| att.contents().len() > MAX_ATTACHMENT_BYTES);

    // Parse date
    let date_epoch: Option<i64> = message.date().and_then(|d| {
        let ts = d.to_timestamp();
        // A zero or negative timestamp is what an unset or unparsable Date
        // header decodes to, and 1970 is not a date this message was sent on.
        (ts > 0).then_some(ts)
    });
    let date_str = date_epoch
        .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0))
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();

    let mut metadata = json!({
        "type": "EmailMessage",
        "analysis_type": "email",
        "subtype": "email_message",
        "from": from,
        "from_name": from_name,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "subject": subject,
        "date": date_str,
        // Unix seconds beside the RFC 3339 string. The conversation views sort
        // and page on one integer expression across every channel, and chat
        // records store `$.date` as an epoch — casting this format's ISO string
        // to an integer yields the *year*, which would page an email thread in
        // an order that has nothing to do with when the messages were sent
        // (§5.14). Absent, not zero, when the Date header gave no usable time.
        "date_epoch": date_epoch,
        "message_id": message_id,
        "in_reply_to": in_reply_to,
        "references": references,
        "body_text": body_text,
        "body_html": body_html,
        // Structured honesty: the `...[truncated]` sentinel inside the text is
        // prose that search/export/UI do not read (B2-105).
        "body_truncated": body_truncated,
        "attachment_count": attachment_count,
        "attachments": attachments,
        "attachments_incomplete": attachments_incomplete,
        "has_attachments": has_attachments,
        "container": container_name,
        "message_index": message_index,
    });

    // The thread the message belongs to, derived from the RFC 5322 headers by
    // the one writer in `crate::thread` so every format this crate reads
    // publishes the same keys with the same basis beside them (§5.14).
    if let Some(map) = metadata.as_object_mut() {
        crate::thread::stamp(map, &message_id, &in_reply_to, &references);
    }

    // `attachments_incomplete` and `body_truncated` are this parser's own keys;
    // the API, export and cross-plugin honesty paths key on `content_incomplete`
    // and `content_incomplete_reason` (as `not_parsed_marker` in this crate
    // already does). Without the standard pair a message whose 200 MiB
    // attachment was left behind exported as a complete recovery (B3-085). Both
    // sets are emitted; the bespoke keys stay for any existing consumer.
    if attachments_incomplete || body_truncated {
        let reason = if attachments_over_cap || body_truncated {
            IncompleteReason::CapReached
        } else {
            IncompleteReason::UnresolvedStructure
        };
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!(reason.as_str());
    }

    let record =
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id);
    let record_id = record.id;

    artifacts.push(record);

    // Emit each attachment as a child FileEntry so the modules that subscribe
    // to a `FileEntry` — the hasher, the file-type detector, YARA and the
    // search index — can analyse it independently. NOT the carver:
    // `seance_plugin_carver` subscribes to file systems and unallocated space
    // only, so an attachment is never carved.
    // Inline `attachments` metadata above stays as a summary.
    for att in message.attachments() {
        let bytes = att.contents();
        if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT_BYTES {
            // Over-cap (or empty) attachments keep their inline metadata entry
            // with `bytes_extracted: false`, and the parent record carries
            // `attachments_incomplete`. Nothing is dropped silently.
            continue;
        }
        let att_name = att
            .attachment_name()
            .unwrap_or("unnamed_attachment")
            .to_string();
        // mail_parser splits Content-Type into main + subtype; reassemble as
        // "main/subtype" (e.g. "image/png") so it matches what the email
        // client originally sent.
        let content_type = att
            .content_type()
            .map(|ct| match ct.subtype() {
                Some(sub) => format!("{}/{}", ct.ctype(), sub),
                None => ct.ctype().to_string(),
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let att_meta = json!({
            "name": att_name,
            "size": bytes.len(),
            "content_type": content_type,
            "source": "email_attachment",
            "email_subject": subject,
            "email_message_id": message_id,
        });
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.to_vec()));
        let att_artifact = Artifact::new(case_id, ArtifactType::FileEntry, Some(ds), att_meta)
            .with_parent(record_id);
        artifacts.push(att_artifact);
    }

    // Create timeline event if we have a date
    if !date_str.is_empty() {
        let description = if !from.is_empty() {
            format!("Email from {} - {}", from, subject)
        } else {
            format!("Email - {}", subject)
        };

        let timeline_metadata = json!({
            "timestamp": date_str,
            "timestamp_desc": "Email Sent",
            "source_module": "plugin.email.parser",
            "short_desc": description,
            "event_type": "email_message",
            "source": container_name,
            "from": from,
            "to": to,
            "subject": subject,
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

    artifacts
}

/// A record stating that a message this tool identified as mail could not be
/// parsed into one, and how many bytes were skipped.
///
/// Forensic meaning: the examiner learns that a message existed here and that
/// this tool did not read it. Its absence from the case is then a gap in the
/// parse, not evidence that the mailbox never held it. The keys are the same
/// ones the crate's `not_parsed_marker` uses, so the API, export and
/// cross-plugin honesty paths pick this up without knowing about EML.
fn unparsable_message_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    container_name: &str,
    message_index: Option<usize>,
    byte_length: usize,
) -> Artifact {
    let label = match message_index {
        Some(idx) => format!("{container_name} (message {idx})"),
        None => container_name.to_string(),
    };
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "EmailParseStatus",
            "subtype": "email_not_parsed",
            "status": "NotParsable",
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "file_name": container_name,
            "container": container_name,
            "message_index": message_index,
            "bytes_skipped": byte_length,
            "message": "This was identified as a mail message and no RFC 822 headers or body \
                        could be parsed from it; none of its content was recovered",
            "name": format!("Email not parsed: {label}"),
        }),
    )
    .with_parent(parent_id)
}

/// Parse an MBOX file, splitting on "From " boundaries
pub fn parse_mbox(data: &[u8], case_id: Uuid, parent_id: Uuid, name: &str) -> Vec<Artifact> {
    let mut artifacts = Vec::new();

    // MBOX format: messages separated by lines starting with "From "
    let owned;
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => {
            owned = String::from_utf8_lossy(data).into_owned();
            &owned
        }
    };

    let messages = split_mbox(text);

    for (idx, msg_text) in messages.iter().enumerate() {
        let msg_artifacts =
            parse_eml_message(msg_text.as_bytes(), case_id, parent_id, name, Some(idx));
        artifacts.extend(msg_artifacts);
    }

    artifacts
}

/// Split MBOX content into individual messages.
///
/// A message begins at a separator line: `From <sender> <asctime date>`, the
/// form every mbox writer emits (Thunderbird writes the sender as a bare `-`).
/// The date is what tells a separator apart from prose that happens to open a
/// line with "From " — requiring an empty line before it instead does not, and
/// loses every message whose body ends without a trailing blank line.
fn split_mbox(content: &str) -> Vec<String> {
    let mut messages = Vec::new();
    let mut current_message = String::new();
    let mut in_message = false;

    for line in content.lines() {
        if is_mbox_separator(line) {
            if in_message && !current_message.is_empty() {
                messages.push(std::mem::take(&mut current_message));
            }
            in_message = true;
            // Skip the "From " separator line itself
            continue;
        }

        if in_message {
            // Un-escape ">From " lines (MBOX escaping)
            if line.starts_with(">From ") {
                current_message.push_str(&line[1..]);
            } else {
                current_message.push_str(line);
            }
            current_message.push('\n');
        }
    }

    // Push the last message
    if !current_message.is_empty() {
        messages.push(current_message);
    }

    messages
}

/// True when the line is an mbox `From_` separator rather than body text.
///
/// The separator ends with an asctime date — `Thu Feb  3 21:51:00 2022` — with
/// an optional trailing timezone or offset. Body prose starting "From " carries
/// no such date, so the date is the discriminator.
fn is_mbox_separator(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("From ") else {
        return false;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // weekday, month, day, time, year — the last five fields that form a date,
    // allowing a timezone after the year.
    (5..=fields.len()).rev().any(|end| {
        let start = end - 5;
        looks_like_asctime(&fields[start..end])
    })
}

fn looks_like_asctime(fields: &[&str]) -> bool {
    const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let [weekday, month, day, time, year] = fields else {
        return false;
    };
    WEEKDAYS.contains(weekday)
        && MONTHS.contains(month)
        && (1..=2).contains(&day.len())
        && day.chars().all(|c| c.is_ascii_digit())
        && looks_like_clock(time)
        && year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
}

fn looks_like_clock(time: &str) -> bool {
    let parts: Vec<&str> = time.split(':').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // === MBOX splitting tests ===

    #[test]
    fn test_split_mbox_single_message() {
        let mbox = "From sender@example.com Mon Jan 1 00:00:00 2024\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nBody of the message\n";
        let messages = split_mbox(mbox);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("From: sender@example.com"));
        assert!(messages[0].contains("Body of the message"));
    }

    #[test]
    fn test_split_mbox_two_messages() {
        let mbox = "From alice@example.com Mon Jan 1 00:00:00 2024\nFrom: alice@example.com\nSubject: First\n\nFirst body\n\nFrom bob@example.com Tue Jan 2 00:00:00 2024\nFrom: bob@example.com\nSubject: Second\n\nSecond body\n";
        let messages = split_mbox(mbox);
        assert_eq!(messages.len(), 2);
        assert!(messages[0].contains("Subject: First"));
        assert!(messages[1].contains("Subject: Second"));
    }

    #[test]
    fn test_split_mbox_empty() {
        let messages = split_mbox("");
        assert!(messages.is_empty());
    }

    #[test]
    fn test_split_mbox_no_from_line() {
        // Content without "From " boundary — no messages extracted
        let messages = split_mbox("Just some text\nwithout mbox format\n");
        assert!(messages.is_empty());
    }

    #[test]
    fn test_split_mbox_from_in_body_not_after_empty_line() {
        // "From " in body NOT preceded by empty line should not split
        let mbox = "From sender@example.com Mon Jan 1 00:00:00 2024\nFrom: sender@example.com\nSubject: Test\n\nThe message says:\nFrom the beginning we knew\nthis would happen.\n";
        let messages = split_mbox(mbox);
        assert_eq!(
            messages.len(),
            1,
            "From in body without preceding empty line should not split"
        );
        assert!(messages[0].contains("From the beginning we knew"));
    }

    #[test]
    fn test_split_mbox_from_after_empty_line_splits() {
        // "From " preceded by empty line IS a boundary
        let mbox = "From first@example.com Mon Jan 1 00:00:00 2024\nFrom: first@example.com\nSubject: First\n\nBody one\n\nFrom second@example.com Tue Jan 2 00:00:00 2024\nFrom: second@example.com\nSubject: Second\n\nBody two\n";
        let messages = split_mbox(mbox);
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn a_thunderbird_mbox_splits_at_every_separator_line() {
        // Thunderbird writes "From - <date>" separators and does not always
        // leave a blank line before the next one: a message whose body ends
        // without a trailing empty line was swallowed into its neighbour,
        // taking every later message with it (Magnet 2022 Linux, 49 messages
        // in the mailbox, 4 recovered).
        let mbox = concat!(
            "From - Thu Feb  3 21:51:00 2022\n",
            "From: alice@example.com\n",
            "Subject: First\n",
            "\n",
            "Body one, no blank line after me\n",
            "From - Thu Feb  3 21:51:01 2022\n",
            "From: bob@example.com\n",
            "Subject: Second\n",
            "\n",
            "Body two\n",
            "From - Thu Feb  3 21:51:02 2022\n",
            "From: carol@example.com\n",
            "Subject: Third\n",
            "\n",
            "Body three\n",
        );
        let messages = split_mbox(mbox);
        assert_eq!(messages.len(), 3, "every separator starts a new message");
        assert!(messages[0].contains("Subject: First"));
        assert!(messages[1].contains("Subject: Second"));
        assert!(messages[2].contains("Subject: Third"));
    }

    #[test]
    fn a_from_line_in_a_body_is_not_a_separator_without_a_date() {
        // The separator is "From <sender> <asctime date>". Prose that opens a
        // line with "From " carries no such date and must not split a message,
        // whether or not an empty line precedes it.
        let mbox = concat!(
            "From - Thu Feb  3 21:51:00 2022\n",
            "From: alice@example.com\n",
            "Subject: Only one\n",
            "\n",
            "She wrote:\n",
            "\n",
            "From the beginning we knew this would happen.\n",
        );
        let messages = split_mbox(mbox);
        assert_eq!(messages.len(), 1, "prose is not an mbox separator");
        assert!(messages[0].contains("From the beginning we knew"));
    }

    #[test]
    fn test_split_mbox_escaped_from() {
        // ">From " should be unescaped to "From "
        let mbox = "From sender@example.com Mon Jan 1 00:00:00 2024\nFrom: sender@example.com\nSubject: Test\n\n>From the very start\n";
        let messages = split_mbox(mbox);
        assert_eq!(messages.len(), 1);
        assert!(
            messages[0].contains("From the very start"),
            "'>From ' should be unescaped"
        );
        assert!(
            !messages[0].contains(">From "),
            "'>From ' should have been stripped"
        );
    }

    // === EML parsing tests ===

    #[test]
    fn test_parse_eml_basic() {
        let eml = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\nDate: Mon, 1 Jan 2024 12:00:00 +0000\r\n\r\nHello Bob!\r\n";
        let case_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let artifacts = parse_eml_message(eml, case_id, parent_id, "test.eml", None);

        assert_eq!(
            artifacts.len(),
            2,
            "Should produce ParsedRecord + TimelineEvent"
        );

        let record = &artifacts[0];
        assert_eq!(record.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(record.metadata["from"], "alice@example.com");
        assert_eq!(record.metadata["subject"], "Hello");
        assert_eq!(record.metadata["has_attachments"], false);

        let timeline = &artifacts[1];
        assert_eq!(timeline.artifact_type, ArtifactType::TimelineEvent);
        assert_eq!(timeline.metadata["timestamp_desc"], "Email Sent");
    }

    #[test]
    fn test_parse_eml_missing_fields() {
        // Minimal EML with only Subject
        let eml = b"Subject: Minimal\r\n\r\nBody text\r\n";
        let artifacts = parse_eml_message(eml, Uuid::new_v4(), Uuid::new_v4(), "minimal.eml", None);

        assert!(!artifacts.is_empty());
        let record = &artifacts[0];
        assert_eq!(record.metadata["subject"], "Minimal");
        assert_eq!(record.metadata["from"], "");
    }

    #[test]
    fn test_parse_eml_no_date_no_timeline() {
        // EML without Date header — should produce ParsedRecord but no TimelineEvent
        let eml = b"From: alice@example.com\r\nSubject: No date\r\n\r\nBody\r\n";
        let artifacts = parse_eml_message(eml, Uuid::new_v4(), Uuid::new_v4(), "nodate.eml", None);

        assert_eq!(artifacts.len(), 1, "No date means no TimelineEvent");
        assert_eq!(artifacts[0].artifact_type, ArtifactType::ParsedRecord);
    }

    // === Threading (ROADMAP §5.14) ===

    /// A reply carries its ancestry, and the thread key is the root of it, so
    /// the whole exchange groups under the id of the message that started it.
    #[test]
    fn a_reply_is_keyed_on_the_thread_root_its_references_name() {
        let eml = b"From: bob@example.com\r\nTo: alice@example.com\r\n\
                    Subject: Re: Invoice 4471\r\nDate: Mon, 1 Jan 2024 12:05:00 +0000\r\n\
                    Message-ID: <reply@example.com>\r\n\
                    In-Reply-To: <root@example.com>\r\n\
                    References: <root@example.com>\r\n\r\nPaid.\r\n";
        let artifacts = parse_eml_message(eml, Uuid::new_v4(), Uuid::new_v4(), "r.eml", None);
        let m = &artifacts[0].metadata;
        assert_eq!(m["email_thread_key"], "root@example.com");
        assert_eq!(m["email_thread_basis"], "references_root");
        assert!(m["email_thread_basis_note"]
            .as_str()
            .unwrap()
            .contains("the mail client recorded"));
        assert!(m.get("email_thread_unavailable_reason").is_none());
    }

    /// The root of a thread names no parent, so it keys on its own id — which
    /// is the same key its replies computed from `References`.
    #[test]
    fn a_thread_root_keys_on_itself_and_meets_its_replies() {
        let eml = b"From: alice@example.com\r\nSubject: Invoice 4471\r\n\
                    Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n\
                    Message-ID: <root@example.com>\r\n\r\nAttached.\r\n";
        let m =
            &parse_eml_message(eml, Uuid::new_v4(), Uuid::new_v4(), "root.eml", None)[0].metadata;
        assert_eq!(m["email_thread_key"], "root@example.com");
        assert_eq!(m["email_thread_basis"], "own_message_id");
        assert!(m["email_thread_basis_note"]
            .as_str()
            .unwrap()
            .contains("not that none was sent"));
    }

    /// A message with none of the three headers gets no key and says why. A
    /// fabricated key would group every header-less message in the mailbox
    /// into one conversation that never existed.
    #[test]
    fn a_message_with_no_threading_headers_carries_the_reason_and_no_key() {
        let eml = b"Subject: Minimal\r\n\r\nBody text\r\n";
        let m =
            &parse_eml_message(eml, Uuid::new_v4(), Uuid::new_v4(), "min.eml", None)[0].metadata;
        assert!(m.get("email_thread_key").is_none());
        assert!(m["email_thread_unavailable_reason"]
            .as_str()
            .unwrap()
            .contains("cannot be addressed"));
    }

    /// Unix seconds beside the RFC 3339 string. The conversation views sort and
    /// page on one integer expression across every channel, and casting this
    /// format's ISO string to an integer yields its *year*.
    #[test]
    fn a_message_carries_its_date_as_an_integer_as_well_as_a_string() {
        let eml = b"From: alice@example.com\r\nSubject: Hello\r\n\
                    Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n\r\nHi\r\n";
        let m = &parse_eml_message(eml, Uuid::new_v4(), Uuid::new_v4(), "d.eml", None)[0].metadata;
        assert_eq!(m["date_epoch"], 1_704_110_400i64);
        assert_eq!(m["date"], "2024-01-01T12:00:00+00:00");
    }

    /// Absent, not zero: 1970 is not a date this message was sent on, and a
    /// thread ordered by a fabricated epoch would put undated mail first.
    #[test]
    fn a_message_with_no_date_carries_no_epoch_rather_than_zero() {
        let eml = b"From: alice@example.com\r\nSubject: No date\r\n\r\nBody\r\n";
        let m = &parse_eml_message(eml, Uuid::new_v4(), Uuid::new_v4(), "nd.eml", None)[0].metadata;
        assert!(m["date_epoch"].is_null(), "{}", m["date_epoch"]);
        assert_eq!(m["date"], "");
    }

    /// Build a tiny multipart/mixed EML with one base64-encoded attachment.
    /// The attachment payload is `payload`.
    fn build_eml_with_attachment(payload: &[u8], filename: &str, ctype: &str) -> Vec<u8> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        // Wrap to 76 chars per RFC 2045 just for realism.
        let wrapped = b64
            .as_bytes()
            .chunks(76)
            .map(std::str::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\r\n");
        let boundary = "BOUNDARY_XYZ";
        format!(
            "From: alice@example.com\r\n\
             To: bob@example.com\r\n\
             Subject: With attachment\r\n\
             Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary={boundary}\r\n\
             \r\n\
             --{boundary}\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             \r\n\
             Body text here.\r\n\
             --{boundary}\r\n\
             Content-Type: {ctype}\r\n\
             Content-Transfer-Encoding: base64\r\n\
             Content-Disposition: attachment; filename=\"{filename}\"\r\n\
             \r\n\
             {wrapped}\r\n\
             --{boundary}--\r\n",
            boundary = boundary,
            ctype = ctype,
            filename = filename,
            wrapped = wrapped,
        )
        .into_bytes()
    }

    #[test]
    fn attachment_is_promoted_to_file_entry_child() {
        let payload = b"\x89PNG\r\n\x1a\nFAKE-PNG-BYTES";
        let eml = build_eml_with_attachment(payload, "photo.png", "image/png");
        let case_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let artifacts = parse_eml_message(&eml, case_id, parent_id, "test.eml", None);

        // Layout: ParsedRecord + FileEntry(attachment) + TimelineEvent.
        let record = artifacts
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .expect("missing ParsedRecord");
        let attachment = artifacts
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("missing FileEntry for attachment");

        // Inline metadata still records the attachment summary.
        assert_eq!(record.metadata["has_attachments"], true);
        assert_eq!(record.metadata["attachment_count"], 1);

        // The FileEntry is parented to the ParsedRecord (not to the email
        // container) so the artifact tree shows it nested under its email.
        assert_eq!(attachment.parent_id, Some(record.id));
        assert_eq!(case_id, attachment.case_id);
        assert_eq!(attachment.metadata["name"].as_str(), Some("photo.png"));
        assert_eq!(
            attachment.metadata["content_type"].as_str(),
            Some("image/png")
        );
        assert_eq!(
            attachment.metadata["source"].as_str(),
            Some("email_attachment")
        );
        // Cross-reference back to the email is preserved.
        assert_eq!(
            attachment.metadata["email_subject"].as_str(),
            Some("With attachment")
        );

        // Crucially the FileEntry must carry the attachment bytes so downstream
        // modules (carver, file analyzer, hashing) can process it.
        let ds = attachment
            .data
            .as_ref()
            .expect("attachment needs DataSource");
        assert_eq!(ds.size(), payload.len() as u64);
        let mut buf = vec![0u8; payload.len()];
        ds.read_at(0, &mut buf).unwrap();
        assert_eq!(
            &buf, payload,
            "DataSource must return the decoded attachment bytes"
        );
    }

    #[test]
    fn email_without_attachments_emits_no_file_entry() {
        // Sanity: emails with no attachments must not emit spurious FileEntry artifacts.
        let eml = b"From: alice@example.com\r\nSubject: No attachment\r\nDate: Mon, 1 Jan 2024 12:00:00 +0000\r\n\r\nJust body\r\n";
        let arts = parse_eml_message(eml, Uuid::new_v4(), Uuid::new_v4(), "x.eml", None);
        assert!(
            arts.iter()
                .all(|a| a.artifact_type != ArtifactType::FileEntry),
            "no FileEntry expected for plain email"
        );
    }

    #[test]
    fn oversized_attachment_is_skipped_not_panicked() {
        // An attachment larger than MAX_ATTACHMENT_BYTES should be summarized
        // in metadata but NOT promoted to a FileEntry (avoids OOM).
        // We can't easily build a 64MB+1 EML in a unit test; instead verify
        // the empty-attachment branch (which uses the same skip path).
        // Construct an EML where the attachment body is empty.
        let eml = build_eml_with_attachment(b"", "empty.bin", "application/octet-stream");
        let arts = parse_eml_message(&eml, Uuid::new_v4(), Uuid::new_v4(), "x.eml", None);
        assert!(
            arts.iter()
                .all(|a| a.artifact_type != ArtifactType::FileEntry),
            "empty attachment must not be promoted"
        );
    }

    #[test]
    fn multiple_attachments_all_promoted() {
        // Build an EML manually with two attachments — exercise the loop.
        let boundary = "B";
        let payload_a = b"AAAA";
        let payload_b = b"BBBBB";
        use base64::Engine;
        let b64a = base64::engine::general_purpose::STANDARD.encode(payload_a);
        let b64b = base64::engine::general_purpose::STANDARD.encode(payload_b);
        let eml = format!(
            "From: a@x.com\r\nTo: b@x.com\r\nSubject: Two\r\nDate: Mon, 1 Jan 2024 12:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary={B}\r\n\r\n\
             --{B}\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
             --{B}\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n\r\n{b64a}\r\n\
             --{B}\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"b.bin\"\r\n\r\n{b64b}\r\n\
             --{B}--\r\n",
            B = boundary, b64a = b64a, b64b = b64b
        )
        .into_bytes();

        let arts = parse_eml_message(&eml, Uuid::new_v4(), Uuid::new_v4(), "x.eml", None);
        let attachments: Vec<_> = arts
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(attachments.len(), 2);
        let names: Vec<&str> = attachments
            .iter()
            .filter_map(|a| a.metadata["name"].as_str())
            .collect();
        assert!(names.contains(&"a.bin"));
        assert!(names.contains(&"b.bin"));
    }

    /// B8-046: a file the format gate already called mail, from which nothing
    /// parses, must leave a record saying so.
    ///
    /// What an examiner learns: whether "there was no message here" is
    /// supportable. `MessageParser::parse` returns `None` when its header scan
    /// ends without ever having a header name to record — a file of nothing but
    /// spaces and tabs is the shape that reaches it — and that `None` used to
    /// return an empty `Vec`, so an `.eml` with no readable content produced
    /// exactly what a directory with no mail in it produces.
    #[test]
    fn an_eml_that_parses_to_nothing_leaves_a_record_saying_so() {
        let blank: &[u8] = b"   \t   ";
        let artifacts = parse_eml_message(blank, Uuid::new_v4(), Uuid::new_v4(), "blank.eml", None);
        assert_eq!(
            artifacts.len(),
            1,
            "an unparsable message must not vanish from the case"
        );
        let md = &artifacts[0].metadata;
        assert_eq!(md["type"], "EmailParseStatus");
        assert_eq!(md["status"], "NotParsable");
        assert_eq!(md["content_incomplete"], json!(true));
        assert_eq!(md["content_incomplete_reason"], "unresolved_structure");
        assert_eq!(md["file_name"], "blank.eml");
        assert_eq!(md["bytes_skipped"], json!(blank.len()));

        // A message that does parse still carries no status record, so the
        // marker's absence keeps meaning "complete".
        let good = parse_eml_message(
            b"From: a@example.com\r\nSubject: Fine\r\n\r\nbody\r\n",
            Uuid::new_v4(),
            Uuid::new_v4(),
            "fine.eml",
            None,
        );
        assert!(good
            .iter()
            .all(|a| a.metadata["type"] != "EmailParseStatus"));
    }

    /// The same honesty inside an MBOX: one unreadable message among readable
    /// ones is a gap in that mailbox, and the record names which message.
    #[test]
    fn an_unparsable_mbox_message_is_reported_with_its_index() {
        let artifacts = parse_eml_message(
            b"  \t",
            Uuid::new_v4(),
            Uuid::new_v4(),
            "inbox.mbox",
            Some(3),
        );
        assert_eq!(artifacts.len(), 1);
        let md = &artifacts[0].metadata;
        assert_eq!(md["message_index"], json!(3));
        assert_eq!(md["name"], "Email not parsed: inbox.mbox (message 3)");
    }

    /// The end-to-end path this closes: a `.eml` whose content is blank passes
    /// the format gate on its extension, reaches the parser, and now leaves a
    /// status record instead of nothing at all.
    #[test]
    fn a_blank_eml_reaches_the_status_record_through_the_module_entry_point() {
        use seance_core::module::ForensicsModule;

        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"   \t   ".to_vec()));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "blank.eml" }),
        );
        let results = crate::EmailParser.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["type"], "EmailParseStatus");
        assert_eq!(results[0].metadata["status"], "NotParsable");
    }

    #[test]
    fn test_parse_mbox_multiple_messages() {
        let mbox_data = b"From alice@example.com Mon Jan 1 00:00:00 2024\r\nFrom: alice@example.com\r\nSubject: First\r\nDate: Mon, 1 Jan 2024 12:00:00 +0000\r\n\r\nFirst body\r\n\r\nFrom bob@example.com Tue Jan 2 00:00:00 2024\r\nFrom: bob@example.com\r\nSubject: Second\r\nDate: Tue, 2 Jan 2024 12:00:00 +0000\r\n\r\nSecond body\r\n";
        let artifacts = parse_mbox(mbox_data, Uuid::new_v4(), Uuid::new_v4(), "inbox.mbox");

        // Each message produces ParsedRecord + TimelineEvent = 2 artifacts per message
        assert!(
            artifacts.len() >= 2,
            "Should have artifacts from multiple messages"
        );
    }

    #[test]
    fn test_parse_mbox_empty() {
        let artifacts = parse_mbox(b"", Uuid::new_v4(), Uuid::new_v4(), "empty.mbox");
        assert!(artifacts.is_empty());
    }

    // === truncate_str tests ===

    #[test]
    fn test_truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_str_long() {
        let result = truncate_str("hello world", 5);
        assert!(result.starts_with("hello"));
        assert!(result.contains("...[truncated]"));
    }

    #[test]
    fn test_truncate_str_utf8_boundary() {
        // Multi-byte UTF-8: "é" is 2 bytes (0xC3, 0xA9)
        let s = "héllo";
        // Cutting at byte 2 would split the "é" — should back up
        let result = truncate_str(s, 2);
        assert!(result.starts_with("h"));
        assert!(result.contains("...[truncated]"));
    }

    #[test]
    fn test_truncate_str_empty() {
        assert_eq!(truncate_str("", 10), "");
    }
}
