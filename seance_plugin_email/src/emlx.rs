//! Apple Mail `.emlx` and `.partial.emlx` (+ `.emlxpart`) reader.
//!
//! An `.emlx` is three things end to end, and only the middle one is mail:
//!
//! 1. a decimal byte count on its own line, space-padded (`701       `);
//! 2. exactly that many bytes of RFC 5322 message, handed to the same
//!    [`crate::eml::parse_eml_message`] every other format here uses;
//! 3. an XML property list Apple Mail keeps about the message
//!    (`date-received`, `date-last-viewed`, `flags`, `conversation-id`,
//!    `remote-id`, ...).
//!
//! Before this reader the whole file went to the EML path when a `From:`
//! happened to sit in its first ten lines, so the count line was read as the
//! first "header" and the plist as body text. The plist values are published
//! as `emlx_*` keys on the message record and never reach `body_text`.
//!
//! `flags` is reported as the raw integer and **not decoded** (owner decision
//! 2026-09-26, §3.10): its bit layout is Apple-private and the held corpus
//! cannot confirm any community description of it. The Envelope Index reader
//! (`seance_plugin_macos_artifacts::mail`) reports read/flagged/deleted state
//! for the rows of Mail's own index, but neither reader names the other's
//! record: joining an index row to an `.emlx` is the examiner's own search.
//!
//! A `.partial.emlx` reaches its `.emlxpart` files only through
//! [`DataSource::open_relative`], which a host directory and a ZIP entry
//! support and a file served out of an NTFS/APFS/HFS+/ext4 image does not.
//! On image-resident evidence every stub part is `source_cannot_look`.

use crate::detection::emlx_count_line;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::io::IncompleteReason;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use uuid::Uuid;

/// Parse one Apple Mail `.emlx` file.
///
/// `source` is the file's own data source; a `.partial.emlx` uses it to reach
/// its `.emlxpart` neighbours (see [`crate::emlx`] for the layout).
pub fn parse_emlx(
    data: &[u8],
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
    source: Option<&Arc<dyn DataSource>>,
) -> Vec<Artifact> {
    let Some((declared, start)) = emlx_count_line(data) else {
        return vec![not_parsed(
            case_id,
            parent_id,
            name,
            "EmlxNoByteCount",
            "This file is named or shaped as an Apple Mail .emlx and does not open with the \
             decimal byte-count line that bounds the message; the message was not separated \
             from its property list and nothing was extracted",
            data.len(),
        )];
    };

    let available = data.len() - start;
    let overruns = declared > available;
    let message_end = start + declared.min(available);
    let message = &data[start..message_end];
    let trailer = &data[message_end..];

    // A `.partial.emlx` holds the parts Apple Mail did not download as stubs
    // (headers + `X-Apple-Content-Length`, empty body); each part's bytes live
    // beside it as `<id>.<section>.emlxpart`. Reunite what can be reached
    // before parsing, so a reunited attachment is extracted like any other.
    let stubs = find_stubs(message);
    let mut parts = Vec::new();
    let mut absent_reasons = Vec::new();
    let mut part_incomplete: Option<IncompleteReason> = None;
    let mut inserts: Vec<(usize, Vec<u8>)> = Vec::new();
    for stub in &stubs {
        let file = part_file_name(name, &stub.section);
        let (status, bytes) = fetch_part(source, &file);
        let mut entry = Map::new();
        entry.insert("section".into(), json!(stub.section));
        entry.insert("file".into(), json!(file));
        entry.insert("status".into(), json!(status.as_str()));
        if let Some(d) = stub.declared_length {
            entry.insert("declared_length".into(), json!(d));
        }
        match bytes {
            Some(b) => {
                entry.insert("bytes".into(), json!(b.len()));
                if let Some(d) = stub.declared_length {
                    entry.insert("declared_length_agrees".into(), json!(crlf_length(&b) == d));
                }
                inserts.push((stub.insert_at, b));
            }
            None => {
                absent_reasons.push(format!(
                    "part {} ({file}): {}",
                    stub.section,
                    status.explain()
                ));
                let reason = status.incomplete_reason();
                if part_incomplete != Some(IncompleteReason::CapReached) {
                    part_incomplete = Some(reason);
                }
            }
        }
        parts.push(Value::Object(entry));
    }
    let stitched;
    let message = if inserts.is_empty() {
        message
    } else {
        stitched = splice(message, &mut inserts);
        &stitched[..]
    };

    let mut out = crate::eml::parse_eml_message(message, case_id, parent_id, name, None);

    let mut stamp = Map::new();
    let is_partial = name.to_ascii_lowercase().ends_with(".partial.emlx");
    if is_partial || !stubs.is_empty() {
        stamp.insert("emlx_partial".into(), json!(true));
        stamp.insert("emlx_parts".into(), Value::Array(parts));
    }
    if !absent_reasons.is_empty() {
        stamp.insert(
            "attachment_absent_reason".into(),
            json!(absent_reasons.join("; ")),
        );
    }
    stamp.insert("format".into(), json!("emlx"));
    stamp.insert("emlx_byte_count".into(), json!(declared));
    let mut incomplete: Option<IncompleteReason> = None;
    if overruns {
        // The count promises more message than the file holds: what parsed is
        // a prefix, and there is no plist to read.
        stamp.insert("emlx_bytes_available".into(), json!(available));
        incomplete = Some(IncompleteReason::ShortRead);
    }

    let plist_bytes = trim_ascii_start(trailer);
    if overruns {
        stamp.insert("emlx_plist_present".into(), json!(false));
    } else if plist_bytes.is_empty() {
        // Apple Mail always writes the property list; a file that ends where
        // the message does has lost it.
        stamp.insert("emlx_plist_present".into(), json!(false));
        stamp.insert("emlx_plist_parsed".into(), json!(false));
        incomplete.get_or_insert(IncompleteReason::UnresolvedStructure);
    } else {
        stamp.insert("emlx_plist_present".into(), json!(true));
        match plist::Value::from_reader_xml(std::io::Cursor::new(plist_bytes)) {
            Ok(value) => {
                stamp.insert("emlx_plist_parsed".into(), json!(true));
                stamp_plist(&mut stamp, &value);
            }
            Err(e) => {
                stamp.insert("emlx_plist_parsed".into(), json!(false));
                stamp.insert("emlx_plist_error".into(), json!(e.to_string()));
                incomplete.get_or_insert(IncompleteReason::UnresolvedStructure);
            }
        }
    }

    if incomplete.is_none() {
        incomplete = part_incomplete;
    }
    apply_to_record(&mut out, stamp, incomplete);
    out
}

/// Copy the plist keys this reader names onto the record. Any other keys are
/// listed by name in `emlx_plist_other_keys` so their presence is not lost.
fn stamp_plist(stamp: &mut Map<String, Value>, value: &plist::Value) {
    let Some(dict) = value.as_dictionary() else {
        stamp.insert("emlx_plist_parsed".into(), json!(false));
        stamp.insert(
            "emlx_plist_error".into(),
            json!("property list root is not a dictionary"),
        );
        return;
    };
    let mut other = Vec::new();
    for (key, v) in dict {
        let target = match key.as_str() {
            "date-received" => "emlx_date_received",
            "date-last-viewed" => "emlx_date_last_viewed",
            "date-sent" => "emlx_date_sent",
            // Raw, never decoded into read/deleted/flagged: see module docs.
            "flags" => "emlx_flags",
            "conversation-id" => "emlx_conversation_id",
            "remote-id" => "emlx_remote_id",
            "original-mailbox" => "emlx_original_mailbox",
            _ => {
                other.push(key.clone());
                continue;
            }
        };
        stamp.insert(target.into(), plist_to_json(v));
    }
    stamp.insert("emlx_flags_decoded".into(), json!(false));
    if !other.is_empty() {
        stamp.insert("emlx_plist_other_keys".into(), json!(other));
    }
}

fn plist_to_json(v: &plist::Value) -> Value {
    match v {
        plist::Value::Integer(i) => i
            .as_signed()
            .map(|n| json!(n))
            .or_else(|| i.as_unsigned().map(|n| json!(n)))
            .unwrap_or(Value::Null),
        plist::Value::String(s) => json!(s),
        plist::Value::Boolean(b) => json!(b),
        plist::Value::Real(r) => json!(r),
        other => json!(format!("{other:?}")),
    }
}

/// Merge the `.emlx` keys into the message record (or, when the message could
/// not be parsed, into its not-parsed record).
fn apply_to_record(
    out: &mut [Artifact],
    stamp: Map<String, Value>,
    incomplete: Option<IncompleteReason>,
) {
    let Some(rec) = out
        .iter_mut()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
    else {
        return;
    };
    let Some(map) = rec.metadata.as_object_mut() else {
        return;
    };
    for (k, v) in stamp {
        map.insert(k, v);
    }
    if let Some(reason) = incomplete {
        // A stronger reason already on the record (a cap) is kept; this one
        // only fills the gap.
        if map.get("content_incomplete") != Some(&json!(true)) {
            map.insert("content_incomplete".into(), json!(true));
            map.insert("content_incomplete_reason".into(), json!(reason.as_str()));
        }
    }
}

/// A MIME part Apple Mail left as a stub in a `.partial.emlx`.
#[derive(Debug, Clone, PartialEq)]
struct Stub {
    /// IMAP-style section number: `3`, or `2.1` inside a nested multipart.
    section: String,
    /// Offset in the message where the part's body belongs.
    insert_at: usize,
    /// `X-Apple-Content-Length`: the part's size on the server.
    declared_length: Option<u64>,
}

/// Deepest multipart nesting walked; deeper parts are not searched for stubs.
const MAX_MIME_DEPTH: usize = 16;

/// The largest `.emlxpart` read into memory.
const MAX_PART_BYTES: u64 = 64 * 1024 * 1024;

/// Walk the message's MIME tree and return every stub part: a leaf with an
/// `X-Apple-Content-Length` header and an empty body. The section number is
/// the part's position (1-based, dotted through nested multiparts), which is
/// the number Apple Mail puts in the `.emlxpart` file name. `message/rfc822`
/// parts are not descended into.
fn find_stubs(message: &[u8]) -> Vec<Stub> {
    let mut out = Vec::new();
    walk_entity(message, 0, "", 0, &mut out);
    out
}

fn walk_entity(entity: &[u8], base: usize, section: &str, depth: usize, out: &mut Vec<Stub>) {
    let (headers, body_start) = split_headers(entity);
    let content_type = header_value(&headers, "content-type").unwrap_or_default();
    if content_type.to_ascii_lowercase().starts_with("multipart/") {
        if depth >= MAX_MIME_DEPTH {
            return;
        }
        let Some(boundary) = boundary_param(&content_type) else {
            return;
        };
        for (k, (start, end)) in multipart_children(entity, body_start, &boundary)
            .into_iter()
            .enumerate()
        {
            let child = if section.is_empty() {
                format!("{}", k + 1)
            } else {
                format!("{section}.{}", k + 1)
            };
            walk_entity(&entity[start..end], base + start, &child, depth + 1, out);
        }
        return;
    }
    let Some(declared) = header_value(&headers, "x-apple-content-length") else {
        return;
    };
    let body = &entity[body_start.min(entity.len())..];
    if !body.iter().all(|b| b.is_ascii_whitespace()) {
        return;
    }
    out.push(Stub {
        // A single-part message's body is section 1.
        section: if section.is_empty() {
            "1".to_string()
        } else {
            section.to_string()
        },
        insert_at: base + body_start.min(entity.len()),
        declared_length: declared.trim().parse().ok(),
    });
}

/// Unfolded `(lower-case name, value)` headers and the body's offset.
fn split_headers(entity: &[u8]) -> (Vec<(String, String)>, usize) {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut pos = 0;
    while pos < entity.len() {
        let end = entity[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(entity.len());
        let line = &entity[pos..end];
        let text = String::from_utf8_lossy(line);
        let trimmed = text.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return (headers, end);
        }
        if trimmed.starts_with([' ', '\t']) {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(trimmed.trim());
            }
        } else if let Some((n, v)) = trimmed.split_once(':') {
            headers.push((n.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
        pos = end;
    }
    (headers, entity.len())
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
}

fn boundary_param(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    let at = lower.find("boundary=")? + "boundary=".len();
    let rest = &content_type[at..];
    let value = if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next()?
    } else {
        rest.split([';', ' ', '\t']).next()?
    };
    (!value.is_empty()).then(|| value.to_string())
}

/// The byte ranges of a multipart body's children, between `--boundary`
/// lines; the line end before a delimiter belongs to the delimiter.
fn multipart_children(entity: &[u8], body_start: usize, boundary: &str) -> Vec<(usize, usize)> {
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();
    let mut children = Vec::new();
    let mut open: Option<usize> = None;
    let mut pos = body_start;
    while pos < entity.len() {
        let end = entity[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(entity.len());
        let line = &entity[pos..end];
        if line.starts_with(delim) {
            if let Some(start) = open.take() {
                let mut stop = pos;
                if stop > start && entity[stop - 1] == b'\n' {
                    stop -= 1;
                    if stop > start && entity[stop - 1] == b'\r' {
                        stop -= 1;
                    }
                }
                children.push((start, stop.max(start)));
            }
            if line[delim.len()..].starts_with(b"--") {
                return children;
            }
            open = Some(end);
        }
        pos = end;
    }
    children
}

/// `1498.partial.emlx` + section `3` -> `1498.3.emlxpart`.
fn part_file_name(name: &str, section: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = base.to_ascii_lowercase();
    let stem = if lower.ends_with(".partial.emlx") {
        &base[..base.len() - ".partial.emlx".len()]
    } else if lower.ends_with(".emlx") {
        &base[..base.len() - ".emlx".len()]
    } else {
        base
    };
    format!("{stem}.{section}.emlxpart")
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PartStatus {
    Reunited,
    Absent,
    SourceCannotLook,
    OverCap,
    ReadFailed,
}

impl PartStatus {
    fn as_str(self) -> &'static str {
        match self {
            PartStatus::Reunited => "reunited",
            PartStatus::Absent => "absent",
            PartStatus::SourceCannotLook => "source_cannot_look",
            PartStatus::OverCap => "over_cap",
            PartStatus::ReadFailed => "read_failed",
        }
    }

    fn explain(self) -> &'static str {
        match self {
            PartStatus::Reunited => "reunited",
            PartStatus::Absent => "the part file is not present beside the message",
            PartStatus::SourceCannotLook => {
                "this tool could not look for files beside the message on this source, so \
                 whether the part file exists is unknown"
            }
            PartStatus::OverCap => "the part file is larger than the reader's in-memory cap",
            PartStatus::ReadFailed => "the part file could not be read in full",
        }
    }

    fn incomplete_reason(self) -> IncompleteReason {
        match self {
            PartStatus::OverCap => IncompleteReason::CapReached,
            PartStatus::ReadFailed => IncompleteReason::ShortRead,
            _ => IncompleteReason::UnresolvedStructure,
        }
    }
}

fn fetch_part(source: Option<&Arc<dyn DataSource>>, file: &str) -> (PartStatus, Option<Vec<u8>>) {
    let Some(src) = source.filter(|s| s.supports_siblings()) else {
        return (PartStatus::SourceCannotLook, None);
    };
    let Some(part) = src.open_relative(file) else {
        return (PartStatus::Absent, None);
    };
    let size = part.size();
    if size > MAX_PART_BYTES {
        return (PartStatus::OverCap, None);
    }
    let mut buf = vec![0u8; size as usize];
    let n = seance_core::io::read_full(part.as_ref(), 0, &mut buf);
    if n as u64 != size {
        return (PartStatus::ReadFailed, None);
    }
    (PartStatus::Reunited, Some(buf))
}

/// The length the part would have with CRLF line ends, which is what
/// `X-Apple-Content-Length` counts (checked on the hoover fixture: 75,521
/// bytes + 981 LF = 76,502).
fn crlf_length(b: &[u8]) -> u64 {
    let bare_lf = b
        .iter()
        .enumerate()
        .filter(|&(i, &c)| c == b'\n' && (i == 0 || b[i - 1] != b'\r'))
        .count();
    (b.len() + bare_lf) as u64
}

fn splice(message: &[u8], inserts: &mut [(usize, Vec<u8>)]) -> Vec<u8> {
    inserts.sort_by_key(|(at, _)| *at);
    let extra: usize = inserts.iter().map(|(_, b)| b.len()).sum();
    let mut out = Vec::with_capacity(message.len() + extra);
    let mut cursor = 0;
    for (at, bytes) in inserts.iter() {
        out.extend_from_slice(&message[cursor..*at]);
        out.extend_from_slice(bytes);
        cursor = *at;
    }
    out.extend_from_slice(&message[cursor..]);
    out
}

fn trim_ascii_start(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|c| c.is_ascii_whitespace()).count();
    &b[n..]
}

/// The not-parsed record, with the keys the crate's other not-parsed markers
/// carry so the API, export and honesty paths read it without knowing emlx.
fn not_parsed(
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
    status: &str,
    message: &str,
    size: usize,
) -> Artifact {
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "EmailParseStatus",
            "subtype": "email_not_parsed",
            "status": status,
            "format": "emlx",
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "file_name": name,
            "declared_size": size,
            "message": message,
            "name": format!("Email not parsed: {name}"),
        }),
    )
    .with_parent(parent_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::artifact::ArtifactType;

    const PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
\t<key>date-last-viewed</key>\n\t<integer>1698374611</integer>\n\
\t<key>date-received</key>\n\t<integer>1698374610</integer>\n\
\t<key>flags</key>\n\t<integer>8623685697</integer>\n\
\t<key>conversation-id</key>\n\t<integer>7</integer>\n\
\t<key>remote-id</key>\n\t<string>42</string>\n\
</dict>\n</plist>\n";

    /// A synthetic `.emlx` in the layout Apple Mail writes: the decimal count
    /// padded with spaces, exactly that many message bytes, then the plist.
    /// It pins the mechanism only; the real-file answers are in
    /// `tests/emlx_real_test.rs`.
    fn synthetic(message: &str, declared: Option<usize>) -> Vec<u8> {
        let n = declared.unwrap_or(message.len());
        let mut out = format!("{:<10}\n", n).into_bytes();
        out.extend_from_slice(message.as_bytes());
        out.extend_from_slice(PLIST.as_bytes());
        out
    }

    const MESSAGE: &str = "Subject: Hello\n\
X-Apple-Base-Url: x-msg://1/\n\
X-Universally-Unique-Identifier: 3803F081-61FB-4C24-8FCA-8C8FD5D302CE\n\
From: Alice <alice@example.com>\n\
Date: Thu, 26 Oct 2023 20:43:30 -0600\n\
To: bob@example.com\n\
Content-Type: text/plain\n\
\n\
Body line\n";

    fn record(out: &[Artifact]) -> &serde_json::Value {
        &out.iter()
            .find(|a| {
                a.artifact_type == ArtifactType::ParsedRecord
                    && a.metadata["type"] == "EmailMessage"
            })
            .expect("an EmailMessage record")
            .metadata
    }

    #[test]
    fn an_emlx_message_is_bounded_by_its_byte_count_and_the_plist_is_not_body() {
        let data = synthetic(MESSAGE, None);
        let out = parse_emlx(&data, Uuid::nil(), Uuid::nil(), "2.emlx", None);
        let m = record(&out);
        assert_eq!(m["from"], "alice@example.com");
        assert_eq!(m["subject"], "Hello");
        assert_eq!(m["date"], "2023-10-27T02:43:30+00:00");
        let body = m["body_text"].as_str().unwrap();
        assert!(!body.contains("<plist"), "plist leaked into body: {body}");
        assert!(body.contains("Body line"));
        assert_eq!(m["format"], "emlx");
        assert_eq!(m["emlx_byte_count"], MESSAGE.len());
        assert_eq!(m["emlx_date_received"], 1698374610_i64);
        assert_eq!(m["emlx_date_last_viewed"], 1698374611_i64);
        assert_eq!(m["emlx_conversation_id"], 7);
        assert_eq!(m["emlx_remote_id"], "42");
        assert_eq!(m.get("content_incomplete"), None);
    }

    #[test]
    fn an_emlx_whose_count_overruns_the_file_is_flagged_not_trusted() {
        let mut data = format!("{:<10}\n", 99_999).into_bytes();
        data.extend_from_slice(MESSAGE.as_bytes());
        let out = parse_emlx(&data, Uuid::nil(), Uuid::nil(), "3.emlx", None);
        let m = record(&out);
        assert_eq!(m["content_incomplete"], true);
        assert_eq!(m["content_incomplete_reason"], "short_read");
        assert_eq!(m["emlx_byte_count"], 99_999);
        assert_eq!(m["emlx_bytes_available"], MESSAGE.len());
    }

    #[test]
    fn an_emlx_without_a_count_line_is_a_not_parsed_record() {
        let out = parse_emlx(MESSAGE.as_bytes(), Uuid::nil(), Uuid::nil(), "4.emlx", None);
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["type"], "EmailParseStatus");
        assert_eq!(m["status"], "EmlxNoByteCount");
        assert_eq!(m["content_incomplete"], true);
    }

    #[test]
    fn an_emlx_whose_plist_will_not_parse_keeps_the_message_and_says_so() {
        let mut data = format!("{:<10}\n", MESSAGE.len()).into_bytes();
        data.extend_from_slice(MESSAGE.as_bytes());
        data.extend_from_slice(b"<?xml version=\"1.0\"?><plist><dict><key>flags</ke");
        let out = parse_emlx(&data, Uuid::nil(), Uuid::nil(), "5.emlx", None);
        let m = record(&out);
        assert_eq!(m["subject"], "Hello");
        assert_eq!(m["emlx_plist_parsed"], false);
        assert_eq!(m["content_incomplete"], true);
        assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
        assert!(!m["body_text"].as_str().unwrap().contains("plist"));
    }

    #[test]
    fn the_emlx_flags_integer_is_reported_raw_and_not_decoded() {
        let data = synthetic(MESSAGE, None);
        let out = parse_emlx(&data, Uuid::nil(), Uuid::nil(), "2.emlx", None);
        let m = record(&out);
        assert_eq!(m["emlx_flags"], 8623685697_u64);
        assert_eq!(m["emlx_flags_decoded"], false);
        for k in ["read", "deleted", "flagged", "is_read", "is_deleted"] {
            assert!(m.get(k).is_none(), "{k} must not be derived from flags");
        }
    }
}
