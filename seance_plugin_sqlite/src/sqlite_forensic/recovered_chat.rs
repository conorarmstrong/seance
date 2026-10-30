//! Reconstruct threaded conversations from RECOVERED (non-live) chat-app rows.
//!
//! The recovery engine returns individual non-live rows attributed to app
//! tables: deleted rows salvaged from freeblock and slack space on a
//! "cleared history" database, plus page versions replayed from an
//! uncheckpointed write-ahead log or a rollback journal. **Attribution is the
//! condition, not the recovery**: this module threads only rows carrying the
//! table they came from, so a row from an orphaned freelist page — where the
//! table is unknown and the columns are inferred by shape — is recovered and
//! published as a row and never threaded into a conversation. Journal rows
//! were in that position too until their pages were resolved through the
//! page-to-table map (2026-09-17). This module joins them back
//! into `chat_message` records that the conversation viewer renders — each
//! flagged as recovered so an examiner never mistakes a salvaged message for a
//! live one. It is deliberately conservative: only rows the recovery decoded into
//! named columns with a usable body are threaded; it never fabricates content.
//!
//! Supported schemas: iMessage (`chat.db`), WhatsApp iOS (`ChatStorage.sqlite`),
//! WhatsApp Android (`msgstore.db`), and Android SMS/MMS (`mmssms.db`).

use super::record::{is_likely_text, Value};
use super::{ExtractionResult, ForensicRecord};
use seance_core::time::{cocoa_secs_to_unix_nanos, cocoa_to_unix_nanos, unix_ns};
use serde_json::{json, Value as JsonValue};
use std::collections::{HashMap, HashSet};

/// True when `t` has the shape of an id, GUID or hex token rather than a word.
///
/// The distinguishing feature is not how few letters it has — plenty of real
/// messages are mostly digits — but that it is one unbroken run drawn from the
/// hex alphabet and carrying a digit or a separator. `deadbeef` and `cafe` are
/// words that happen to be spellable in hex, so they are not identifiers;
/// `11-74C` and `EF28-9A0B` are.
fn looks_like_identifier(t: &str) -> bool {
    if t.chars().any(char::is_whitespace) {
        return false;
    }
    let hexish = t
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, '-' | '{' | '}'));
    hexish
        && t.chars()
            .any(|c| c.is_ascii_digit() || matches!(c, '-' | '{' | '}'))
}

/// True when `t` is a bare link, which is a complete message on its own.
fn is_url_like(t: &str) -> bool {
    let lower = t.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("www.")
}

/// True when `s` reads like a human message body rather than an id/guid/hex/token
/// fragment. Requires a minimum length, some alphabetic content, and no control
/// bytes.
///
/// This used to demand that letters be at least half the body, which rejected
/// ordinary messages whose content is mostly a number or a link: `call me on
/// +15551234` is 8 letters in 20 characters, and `123 High St, Flat 4` fails the
/// same way. Those rows were dropped before reaching dedup or the conversation
/// view, so a recovered conversation silently lost exactly the messages an
/// examiner most wants — phone numbers, addresses, links (BUG-285).
///
/// The ratio is now the last resort rather than the first test. A body that
/// breaks into whitespace-separated tokens, or that is a bare URL, is a message;
/// a body shaped like an identifier is not; and only an unbroken run that is
/// neither still falls back to the letter ratio.
fn is_message_like(s: &str) -> bool {
    let t = s.trim();
    let n = t.chars().count();
    if n < 4 {
        return false;
    }
    if t.chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r')
    {
        return false;
    }
    if !is_likely_text(t) {
        return false;
    }
    let letters = t.chars().filter(|c| c.is_alphabetic()).count();
    if letters < 3 {
        return false;
    }
    if looks_like_identifier(t) {
        return false;
    }
    // Separate tokens mean prose, not a token: no id contains a space.
    if t.chars().any(char::is_whitespace) || is_url_like(t) {
        return true;
    }
    (letters as f64) / (n as f64) >= 0.5
}

/// Serialization scaffolding that shows up when a message body lives in an
/// `NSKeyedArchiver` `attributedBody` blob (modern iMessage): class names and
/// attribute keys, not message text. Rejecting these keeps a recovered
/// "conversation" from filling up with `NSMutableAttributedString` noise.
fn is_archiver_noise(s: &str) -> bool {
    let t = s.trim();
    (t.starts_with("NS") && !t.contains(' '))
        || t.starts_with("__kIM")
        || t.contains("AttributeName")
        || t.contains("MessagePart")
        || t == "onary" // NSDictionary fragment
}

/// Drop a leading GUID/hex id fragment glued to a recovered body (the previous
/// column bled in during a shifted decode), e.g.
/// `0DADA13A-38BD-...-659A147B0686Vazeny` → `Vazeny`. Only strips a run that is
/// clearly an id (contains a hyphen or is a long hex run), never a hex-looking
/// English word like `deadbeef`.
fn strip_id_prefix(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() && (chars[i].is_ascii_hexdigit() || chars[i] == '-') {
        i += 1;
    }
    if i >= 8 && i < chars.len() {
        let prefix: String = chars[..i].iter().collect();
        if prefix.contains('-') || i >= 16 {
            return chars[i..]
                .iter()
                .collect::<String>()
                .trim_start()
                .to_string();
        }
    }
    s.to_string()
}

/// Best-effort message body for a recovered row. Prefers a named `text`-style
/// column; when recovery shifted the columns (body landed in `ROWID` or a blob),
/// it falls back to the longest *multi-word* sentence in the row — the space
/// requirement plus the archiver-noise filter separate a real recovered message
/// from a class-name token or an id fragment.
fn best_message_text(rec: &ForensicRecord, named: &[&str]) -> Option<String> {
    for name in named {
        if let Some(t) = col_text(rec, name) {
            if is_message_like(&t) && !is_archiver_noise(&t) {
                return Some(strip_id_prefix(&t));
            }
        }
    }
    // Modern iMessage keeps the body in an `attributedBody` Apple typedstream blob.
    // Decode it before the generic heuristic so the real text wins over the
    // archiver class-name fragments that heuristic would otherwise surface.
    for v in &rec.values {
        if let Value::Blob(b) = v {
            if let Some(t) = seance_core::typedstream::extract_message_text(b) {
                let t = strip_id_prefix(t.trim());
                if !t.is_empty() {
                    return Some(t);
                }
            }
        }
    }
    let mut best: Option<String> = None;
    for v in &rec.values {
        let candidate = match v {
            Value::Text(s) => Some(s.clone()),
            Value::Blob(b) => std::str::from_utf8(b).ok().map(|s| s.to_string()),
            _ => None,
        };
        if let Some(c) = candidate {
            let c = c.trim().to_string();
            if c.contains(' ')
                && is_message_like(&c)
                && !is_archiver_noise(&c)
                && best.as_ref().is_none_or(|b| c.len() > b.len())
            {
                best = Some(c);
            }
        }
    }
    best.map(|s| strip_id_prefix(&s))
}

/// Tables that only a WhatsApp Android `msgstore.db` carries alongside its
/// `message`/`messages` table. A generic `message` table is not evidence of
/// WhatsApp — Signal, Messenger and many other stores have one — so at least one
/// of these must be present before rows are attributed to WhatsApp.
const WHATSAPP_ANDROID_MARKERS: &[&str] = &[
    "jid",
    "chat_list",
    "message_media",
    "message_thumbnails",
    "messages_quotes",
    "group_participants",
    "message_quoted",
    "receipt_user",
];

/// Tables that identify a Signal Android database. Signal has both a `message`
/// table and (on older versions) an `sms` table, so it must be recognised
/// explicitly and left unattributed rather than mislabelled as another app.
const SIGNAL_MARKERS: &[&str] = &["recipient", "thread", "identities", "sessions", "part"];

/// Detect the app from the recovered schema and reconstruct its deleted
/// conversation. Returns `chat_message` metadata objects (empty if the schema is
/// unrecognized or nothing usable was recovered).
///
/// Attribution is deliberately strict: a row that cannot be tied to a specific
/// app is better left as a generic recovered row than published under the wrong
/// service name, which would put an examiner's conclusion on the wrong app.
pub fn reconstruct(result: &ExtractionResult) -> Vec<JsonValue> {
    let tables: HashSet<&str> = result.summary.tables.iter().map(|s| s.as_str()).collect();
    let any = |names: &[&str]| names.iter().any(|n| tables.contains(*n));
    let is_signal = any(SIGNAL_MARKERS);

    let messages = if tables.contains("message") && tables.contains("handle") {
        reconstruct_imessage(result)
    } else if tables.contains("ZWAMESSAGE") {
        reconstruct_whatsapp_ios(result)
    } else if (tables.contains("messages") || tables.contains("message"))
        && any(WHATSAPP_ANDROID_MARKERS)
        && !is_signal
    {
        reconstruct_whatsapp_android(result)
    } else if tables.contains("sms") && !is_signal {
        reconstruct_android_sms(result)
    } else {
        Vec::new()
    };
    dedup_by_text(drop_wal_copies_of_live_rows(result, messages))
}

/// A WAL frame often holds a page version identical to one already live in the
/// main database. Promoting those would show the same message twice — once live,
/// once "recovered" — so drop a WAL-sourced reconstruction that is provably the
/// same row: **same table, same rowid, same body**.
///
/// The key has to be row identity, not the body on its own. Matching any live
/// text anywhere in the database deleted real uncheckpointed messages whenever
/// the body happened to equal some other string in the file — a common phrase
/// (`ok`, `yes`), another chat's message, or a live handle/JID/push name. A WAL
/// page version that keeps the rowid but carries a *different* body is a later
/// (or earlier) version of that row, which is evidence in its own right, so it
/// is kept. A recovered row with no rowid cannot be proven a duplicate and is
/// likewise kept: a visible, recovery-flagged duplicate is recoverable by an
/// examiner, a silently dropped message is not.
fn drop_wal_copies_of_live_rows(
    result: &ExtractionResult,
    messages: Vec<JsonValue>,
) -> Vec<JsonValue> {
    /// (source table, rowid) of a WAL-sourced reconstruction.
    fn wal_row_key(m: &JsonValue) -> Option<(&str, i64)> {
        if m.get("recovery_source").and_then(|v| v.as_str()) != Some("wal") {
            return None;
        }
        Some((
            m.get("source_table").and_then(|v| v.as_str())?,
            m.get("source_rowid").and_then(|v| v.as_i64())?,
        ))
    }

    // Only the live rows a WAL reconstruction actually claims to be a copy of
    // need indexing, which also keeps the typedstream decode below off every
    // blob in the database.
    let wanted: HashSet<(String, i64)> = messages
        .iter()
        .filter_map(wal_row_key)
        .map(|(t, r)| (t.to_string(), r))
        .collect();
    if wanted.is_empty() {
        return messages;
    }

    let mut live_row_text: HashMap<(String, i64), HashSet<String>> = HashMap::new();
    for r in result
        .records
        .iter()
        .filter(|r| !r.deleted && r.recovery_source.is_none())
    {
        let (Some(table), Some(rowid)) = (r.table.clone(), r.rowid) else {
            continue;
        };
        let key = (table, rowid);
        if !wanted.contains(&key) {
            continue;
        }
        let entry = live_row_text.entry(key).or_default();
        for v in &r.values {
            match v {
                Value::Text(s) => {
                    entry.insert(s.trim().to_string());
                }
                // Modern iMessage keeps the body in an `attributedBody`
                // typedstream blob, so the live copy of a WAL body lives there.
                Value::Blob(b) => {
                    if let Some(t) = seance_core::typedstream::extract_message_text(b) {
                        entry.insert(t.trim().to_string());
                    }
                }
                _ => {}
            }
        }
    }

    messages
        .into_iter()
        .filter(|m| {
            let Some((table, rowid)) = wal_row_key(m) else {
                return true;
            };
            let text = m
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim();
            !live_row_text
                .get(&(table.to_string(), rowid))
                .is_some_and(|texts| texts.contains(text))
        })
        .collect()
}

/// The same deleted message often survives in more than one place (a freelist
/// page *and* slack, or several near-identical carve offsets), so collapse
/// messages that share the same body and correspondent to one entry.
fn dedup_by_text(messages: Vec<JsonValue>) -> Vec<JsonValue> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(messages.len());
    for m in messages {
        let key = format!(
            "{}|{}",
            m.get("chat_identifier")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            m.get("text").and_then(|v| v.as_str()).unwrap_or("").trim()
        );
        if seen.insert(key) {
            out.push(m);
        }
    }
    out
}

/// Only reconstruct from *recovered* rows of a given table — live rows are
/// already handled by the app-specific parser.
///
/// "Recovered" is any row the extractor did not read from the live b-tree:
/// freeblock/freelist/slack carves (`deleted`) **and** page versions replayed
/// from the write-ahead log or rollback journal. WAL frames are not deleted, but
/// they are exactly where a seized phone keeps its most recent, uncheckpointed
/// messages; keying on `deleted` alone left those out of the conversation view.
fn recovered_rows<'a>(
    result: &'a ExtractionResult,
    table: &str,
) -> impl Iterator<Item = &'a ForensicRecord> + 'a {
    let table = table.to_string();
    result.records.iter().filter(move |r| {
        (r.deleted || r.recovery_source.is_some()) && r.table.as_deref() == Some(table.as_str())
    })
}

/// Every surviving row of a table, live or recovered. Lookup tables
/// (`handle`, `jid`, `chat`) are read this way: a cleared message history
/// usually leaves them intact, and they are what resolve a thread.
fn rows_of<'a>(
    result: &'a ExtractionResult,
    table: &str,
) -> impl Iterator<Item = &'a ForensicRecord> + 'a {
    let table = table.to_string();
    result
        .records
        .iter()
        .filter(move |r| r.table.as_deref() == Some(table.as_str()))
}

/// Primary key of a lookup row: the b-tree rowid when it survived, else the
/// decoded `INTEGER PRIMARY KEY` column (which SQLite stores as the rowid).
fn row_key(rec: &ForensicRecord, name: &str) -> Option<i64> {
    rec.rowid.or_else(|| col_int(rec, name))
}

fn col<'a>(rec: &'a ForensicRecord, name: &str) -> Option<&'a Value> {
    rec.columns
        .iter()
        .position(|c| c.eq_ignore_ascii_case(name))
        .and_then(|i| rec.values.get(i))
}

fn col_text(rec: &ForensicRecord, name: &str) -> Option<String> {
    match col(rec, name)? {
        Value::Text(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn col_int(rec: &ForensicRecord, name: &str) -> Option<i64> {
    match col(rec, name)? {
        Value::Int(n) => Some(*n),
        _ => None,
    }
}

/// An Apple/Core Data date column, decoded to `(Unix seconds, sub-second
/// nanos)`.
///
/// The column arrives in either encoding: Core Data (WhatsApp iOS) writes a
/// DOUBLE of seconds since 2001, iMessage writes an integer that is seconds on
/// older stores and nanoseconds on iOS 11+. Both are decoded through the shared
/// converters, which also reject the 0/negative "unset" sentinel so a cleared
/// date is never surfaced as 2001-01-01.
///
/// The fraction is kept rather than cast away: recovered rows are exactly the
/// ones with no other ordering signal — no live b-tree order, often no rowid —
/// so inside a second the sub-second part is all that says which message came
/// first.
fn col_apple_date(rec: &ForensicRecord, name: &str) -> Option<(i64, u32)> {
    match col(rec, name)? {
        Value::Int(n) => cocoa_to_unix_nanos(*n),
        Value::Float(f) => cocoa_secs_to_unix_nanos(*f),
        _ => None,
    }
}

/// A Unix-millisecond column (Android), decoded to `(Unix seconds, sub-second
/// nanos)`. Defensive about a value already in seconds, and the milliseconds
/// travel as nanos for the same ordering reason as [`col_apple_date`].
fn ms_to_unix_parts(ms: i64) -> (i64, u32) {
    if ms.abs() > 1_000_000_000_000 {
        (
            ms.div_euclid(1000),
            (ms.rem_euclid(1000) * 1_000_000) as u32,
        )
    } else {
        (ms, 0)
    }
}

fn preview(text: &Option<String>) -> String {
    text.as_deref()
        .unwrap_or("(no text recovered)")
        .chars()
        .take(60)
        .collect()
}

/// Common chat_message envelope shared by every app, so all recovered
/// conversations render through the same viewer with a consistent shape.
#[allow(clippy::too_many_arguments)]
fn chat_message(
    msg_type: &str,
    service: &str,
    text: Option<String>,
    date: Option<(i64, u32)>,
    chat_identifier: String,
    contact: Option<String>,
    is_from_me: Option<bool>,
    rec: &ForensicRecord,
) -> JsonValue {
    let direction = is_from_me.map(|m| if m { "sent" } else { "received" });
    // Order signal for bodies with no recovered timestamp (see mod.rs). Absent on
    // rows that did keep a date; present on raw attributedBody recoveries.
    let recovery_index = col_int(rec, "recovery_index");
    let mut message = json!({
        "type": msg_type,
        "subtype": "chat_message",
        "platform": "recovered",
        "service": service,
        "text": text,
        "date": date.map(|(secs, _)| secs),
        "recovery_index": recovery_index,
        "chat_identifier": chat_identifier,
        "conversation_id": chat_identifier,
        // Also expose the thread key under the field each viewer groups on, so a
        // recovered WhatsApp message threads on contact_jid rather than falling
        // back to "unknown".
        "contact_jid": chat_identifier,
        "contact": contact,
        "is_from_me": is_from_me,
        "direction": direction,
        // Provenance: this message was not read from the live b-tree. Carved
        // rows really are deleted; a WAL/journal replay is a page version that
        // was never checkpointed, so it must not be labelled deleted.
        "recovered": true,
        "deleted": rec.deleted,
        "recovery_source": rec.recovery_source.map(|s| s.as_str()),
        "confidence": rec.confidence,
        "source_table": rec.table,
        // Row identity of the source record. This is what makes a WAL page
        // version comparable to the live row it may be a copy of.
        "source_rowid": rec.rowid,
        "name": format!("{} (recovered): {}", direction.unwrap_or("message"), preview(&text)),
    });
    // Full-precision instant beside the whole seconds, in the `date_ns` shape
    // the live iMessage/WhatsApp parsers publish — it is the field
    // `seance_db::chat_timeline_row` reads to fill
    // `timeline_events.timestamp_subsec_nanos`, so a recovered conversation
    // sorts against the live ones at the same precision instead of collapsing
    // onto whole seconds. Absent when the source recorded no fraction.
    if let Some(ns) = date.and_then(|(secs, nanos)| unix_ns(secs, nanos)) {
        message["date_ns"] = json!(ns);
    }
    message
}

// --- iMessage (chat.db) ---------------------------------------------------

fn reconstruct_imessage(result: &ExtractionResult) -> Vec<JsonValue> {
    // handle.ROWID -> handle.id (phone/email). Built from ALL handle rows (live
    // and recovered): a cleared message history often leaves the handle/contact
    // table intact, so the correspondent can still be resolved.
    let mut handles: HashMap<i64, String> = HashMap::new();
    for h in result
        .records
        .iter()
        .filter(|r| r.table.as_deref() == Some("handle"))
    {
        if let (Some(rowid), Some(id)) = (h.rowid, col_text(h, "id")) {
            handles.insert(rowid, id);
        }
    }
    let mut out = Vec::new();
    for m in recovered_rows(result, "message") {
        // A body recovered straight from an attributedBody typedstream blob is
        // already validated — use it verbatim (it may be a short word or emoji
        // that the generic message-like filter would wrongly drop). Otherwise the
        // body may be in the `text` column or, when columns shifted, elsewhere.
        let from_attributed = m
            .notes
            .iter()
            .any(|n| n.contains("attributedBody typedstream"));
        let text = if from_attributed {
            col_text(m, "text")
        } else {
            best_message_text(m, &["text"])
        };
        let Some(text) = text else {
            continue;
        };
        // handle_id is only trustworthy as a small positive int; a shifted decode
        // can leave garbage there, so fall back to an undifferentiated thread.
        let handle_id = col_int(m, "handle_id").filter(|h| *h > 0 && *h < 1_000_000);
        let contact = handle_id.and_then(|h| handles.get(&h).cloned());
        let chat_id = contact
            .clone()
            .or_else(|| handle_id.map(|h| format!("handle {h}")))
            .unwrap_or_else(|| "recovered".to_string());
        let date = col_apple_date(m, "date");
        let is_from_me = col_int(m, "is_from_me")
            .filter(|v| *v == 0 || *v == 1)
            .map(|v| v != 0);
        out.push(chat_message(
            "iMessage",
            "iMessage (recovered)",
            Some(text),
            date,
            chat_id,
            contact,
            is_from_me,
            m,
        ));
    }
    out
}

// --- WhatsApp iOS (ChatStorage.sqlite, ZWAMESSAGE) ------------------------

fn reconstruct_whatsapp_ios(result: &ExtractionResult) -> Vec<JsonValue> {
    let mut out = Vec::new();
    for m in recovered_rows(result, "ZWAMESSAGE") {
        let Some(text) = best_message_text(m, &["ZTEXT"]) else {
            continue;
        };
        let text = Some(text);
        let jid = col_text(m, "ZFROMJID")
            .or_else(|| col_text(m, "ZTOJID"))
            .unwrap_or_else(|| "unknown".to_string());
        // The 0 sentinel (unset) is dropped by the converter so it is not
        // fabricated as a 2001 date, matching the recovered-iMessage path above.
        let date = col_apple_date(m, "ZMESSAGEDATE");
        let is_from_me = col_int(m, "ZISFROMME").map(|v| v != 0);
        out.push(chat_message(
            "WhatsApp",
            "WhatsApp iOS (recovered)",
            text,
            date,
            jid.clone(),
            Some(jid),
            is_from_me,
            m,
        ));
    }
    out
}

// --- WhatsApp Android (msgstore.db) ---------------------------------------

fn reconstruct_whatsapp_android(result: &ExtractionResult) -> Vec<JsonValue> {
    // Modern msgstore keeps no JID string on the message: it holds
    // `chat_row_id` -> `chat._id`, and `chat.jid_row_id` -> `jid._id`. Build
    // both lookups from every surviving row (live or recovered) — a cleared
    // message table usually leaves `chat`/`jid` intact, which is what turns a
    // recovered thread from "unknown" into a real correspondent.
    let mut jids: HashMap<i64, String> = HashMap::new();
    for j in rows_of(result, "jid") {
        if let (Some(id), Some(raw)) = (row_key(j, "_id"), col_text(j, "raw_string")) {
            jids.insert(id, raw);
        }
    }
    let mut chats: HashMap<i64, (Option<String>, Option<String>)> = HashMap::new();
    for c in rows_of(result, "chat") {
        if let Some(id) = row_key(c, "_id") {
            let jid = col_int(c, "jid_row_id").and_then(|r| jids.get(&r).cloned());
            chats.insert(id, (jid, col_text(c, "subject")));
        }
    }

    let mut out = Vec::new();
    for table in ["messages", "message"] {
        for m in recovered_rows(result, table) {
            // Legacy `messages`: `data` holds text; modern `message`: `text_data`.
            let Some(text) = best_message_text(m, &["data", "text_data"]) else {
                continue;
            };
            let text = Some(text);
            // Thread key, in order of directness: a string JID on the message
            // (legacy), the modern `chat_row_id` join, then a transitional
            // integer `key_remote_jid` that is really a `jid._id`.
            let chat_row = col_int(m, "chat_row_id").and_then(|c| chats.get(&c));
            let jid = col_text(m, "key_remote_jid")
                .or_else(|| col_text(m, "remote_jid"))
                .or_else(|| chat_row.and_then(|c| c.0.clone()))
                .or_else(|| col_int(m, "key_remote_jid").and_then(|r| jids.get(&r).cloned()))
                .unwrap_or_else(|| "unknown".to_string());
            // Group subject when the chat row survived, else the JID itself.
            let contact = chat_row
                .and_then(|c| c.1.clone())
                .unwrap_or_else(|| jid.clone());
            let date = col_int(m, "timestamp")
                .filter(|d| *d > 0)
                .map(ms_to_unix_parts);
            // `key_from_me` is the legacy name; modern msgstore calls it `from_me`.
            let is_from_me = col_int(m, "key_from_me")
                .or_else(|| col_int(m, "from_me"))
                .map(|v| v != 0);
            out.push(chat_message(
                "WhatsApp",
                "WhatsApp Android (recovered)",
                text,
                date,
                jid,
                Some(contact),
                is_from_me,
                m,
            ));
        }
    }
    out
}

// --- Android SMS/MMS (mmssms.db, sms table) -------------------------------

fn reconstruct_android_sms(result: &ExtractionResult) -> Vec<JsonValue> {
    let mut out = Vec::new();
    for m in recovered_rows(result, "sms") {
        let Some(text) = best_message_text(m, &["body"]) else {
            continue;
        };
        let text = Some(text);
        let address = col_text(m, "address").unwrap_or_else(|| "unknown".to_string());
        let date = col_int(m, "date").filter(|d| *d > 0).map(ms_to_unix_parts);
        // type: 1 = inbox (received), 2 = sent.
        let is_from_me = col_int(m, "type").map(|t| t == 2);
        out.push(chat_message(
            "AndroidSms",
            "Android SMS (recovered)",
            text,
            date,
            address.clone(),
            Some(address),
            is_from_me,
            m,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite_forensic::{DbSummary, RecoverySource};
    use seance_core::time::COCOA_EPOCH as APPLE_EPOCH;

    fn rec(table: &str, cols: &[(&str, Value)], rowid: Option<i64>) -> ForensicRecord {
        ForensicRecord {
            table: Some(table.to_string()),
            rowid,
            page_number: 1,
            deleted: true,
            recovery_source: Some(RecoverySource::Freelist),
            confidence: 60,
            columns: cols.iter().map(|(n, _)| n.to_string()).collect(),
            values: cols.iter().map(|(_, v)| v.clone()).collect(),
            notes: vec![],
        }
    }

    /// A row replayed from the write-ahead log: not deleted, but not live
    /// either — the state a seized, uncheckpointed database is in.
    fn wal_rec(table: &str, cols: &[(&str, Value)], rowid: Option<i64>) -> ForensicRecord {
        ForensicRecord {
            deleted: false,
            recovery_source: Some(RecoverySource::Wal),
            ..rec(table, cols, rowid)
        }
    }

    /// A row read straight from the live b-tree.
    fn live_rec(table: &str, cols: &[(&str, Value)], rowid: Option<i64>) -> ForensicRecord {
        ForensicRecord {
            deleted: false,
            recovery_source: None,
            ..rec(table, cols, rowid)
        }
    }

    fn result_with(tables: &[&str], records: Vec<ForensicRecord>) -> ExtractionResult {
        ExtractionResult {
            summary: DbSummary {
                page_size: 4096,
                page_count: 1,
                encoding: "UTF-8",
                magic_ok: true,
                base_offset: 0,
                tables: tables.iter().map(|s| s.to_string()).collect(),
                schema_objects: tables.len(),
                live_rows: 0,
                deleted_rows: records.len(),
                carved_rows: 0,
                wal_present: false,
                journal_present: false,
                wal_frames: 0,
                journal_frames: 0,
                freelist_pages: 0,
                warnings: vec![],
            },
            schema: vec![],
            records,
            records_truncated: false,
        }
    }

    #[test]
    fn imessage_threads_recovered_message_to_handle() {
        let result = result_with(
            &["message", "handle", "chat"],
            vec![
                rec(
                    "handle",
                    &[("id", Value::Text("+15551234".into()))],
                    Some(7),
                ),
                rec(
                    "message",
                    &[
                        ("text", Value::Text("meet at noon".into())),
                        ("handle_id", Value::Int(7)),
                        ("is_from_me", Value::Int(0)),
                        ("date", Value::Int(700_000_000)), // seconds since 2001
                    ],
                    Some(101),
                ),
            ],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        assert_eq!(m["type"], "iMessage");
        assert_eq!(m["text"], "meet at noon");
        assert_eq!(m["chat_identifier"], "+15551234"); // resolved via handle join
        assert_eq!(m["is_from_me"], false);
        assert_eq!(m["direction"], "received");
        assert_eq!(m["recovered"], true);
        assert_eq!(m["date"], 700_000_000 + APPLE_EPOCH);
    }

    #[test]
    fn imessage_falls_back_to_handle_id_when_join_missing() {
        let result = result_with(
            &["message", "handle", "chat"],
            vec![rec(
                "message",
                &[
                    ("text", Value::Text("call me back".into())),
                    ("handle_id", Value::Int(42)),
                ],
                None,
            )],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["chat_identifier"], "handle 42");
    }

    #[test]
    fn android_sms_maps_type_to_direction() {
        let result = result_with(
            &["sms"],
            vec![rec(
                "sms",
                &[
                    ("address", Value::Text("+15559999".into())),
                    ("body", Value::Text("secret".into())),
                    ("type", Value::Int(2)),
                    ("date", Value::Int(1_600_000_000_000)),
                ],
                Some(1),
            )],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["type"], "AndroidSms");
        assert_eq!(msgs[0]["is_from_me"], true);
        assert_eq!(msgs[0]["date"], 1_600_000_000); // ms -> s
    }

    #[test]
    fn unrecognized_schema_yields_nothing() {
        let result = result_with(&["widgets"], vec![]);
        assert!(reconstruct(&result).is_empty());
    }

    #[test]
    fn recovers_message_body_from_shifted_blob_column() {
        // A shifted decode put an id fragment in `text` and the real body in a
        // blob column (as raw UTF-8 bytes). best_message_text must find the body.
        let result = result_with(
            &["message", "handle"],
            vec![rec(
                "message",
                &[
                    (
                        "ROWID",
                        Value::Blob("meet me at the docks tonight".as_bytes().to_vec()),
                    ),
                    ("text", Value::Text("11-74C".into())), // id fragment, not a message
                    ("handle_id", Value::Int(3)),
                ],
                Some(9),
            )],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["text"], "meet me at the docks tonight");
    }

    #[test]
    fn strips_leading_guid_prefix_but_keeps_hex_words() {
        assert_eq!(
            strip_id_prefix("0DADA13A-38BD-42CB-7058-659A147B0686Vazeny zakazniku"),
            "Vazeny zakazniku"
        );
        // A hex-looking English word must be preserved (no hyphen, < 16 chars).
        assert_eq!(strip_id_prefix("deadbeef cafe"), "deadbeef cafe");
        assert_eq!(strip_id_prefix("lze odeslat, mate"), "lze odeslat, mate");
    }

    #[test]
    fn id_and_hex_fragments_are_not_treated_as_messages() {
        assert!(!is_message_like("11-74C"));
        assert!(!is_message_like("88-4AE"));
        assert!(!is_message_like("EF28592C-6B8A-4B74"));
        assert!(is_message_like("meet me at noon"));
        assert!(is_message_like("haha"));
    }

    #[test]
    fn a_body_that_is_mostly_digits_is_still_a_message() {
        // Each of these is under the old 50% letter ratio and was dropped
        // before it could reach the conversation view (BUG-285). They are
        // exactly the bodies an examiner cares most about recovering.
        assert!(is_message_like("call me on +15551234")); // 8 letters / 20
        assert!(is_message_like("123 High St, Flat 4"));
        assert!(is_message_like("acct 4123 9981 0022"));
        assert!(is_message_like("https://example.com/a/1234567890"));
        assert!(is_message_like("www.example.com/98765"));
    }

    #[test]
    fn a_word_spellable_in_hex_is_not_mistaken_for_an_identifier() {
        // The identifier test keys on shape, not on the hex alphabet alone:
        // an id carries a digit or a separator, a word does not.
        assert!(is_message_like("deadbeef"));
        assert!(is_message_like("added"));
        assert!(!is_message_like("cafe1234"));
        assert!(!is_message_like("{EF28592C-6B8A}"));
    }

    #[test]
    fn whatsapp_ios_reads_float_date_and_sets_thread_key() {
        // Core Data stores ZMESSAGEDATE as a DOUBLE (seconds since 2001).
        let result = result_with(
            &["ZWAMESSAGE"],
            vec![rec(
                "ZWAMESSAGE",
                &[
                    ("ZTEXT", Value::Text("see you soon".into())),
                    ("ZFROMJID", Value::Text("15551234@s.whatsapp.net".into())),
                    ("ZMESSAGEDATE", Value::Float(700_000_000.0)),
                    ("ZISFROMME", Value::Int(1)),
                ],
                Some(1),
            )],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        assert_eq!(m["type"], "WhatsApp");
        assert_eq!(m["date"], 700_000_000 + APPLE_EPOCH); // float date decoded
                                                          // The WhatsApp viewer threads on contact_jid, not chat_identifier.
        assert_eq!(m["contact_jid"], "15551234@s.whatsapp.net");
        assert_eq!(m["is_from_me"], true);
        // Written exactly on a second: nothing to add beyond the seconds field.
        assert!(m.get("date_ns").is_none());
    }

    #[test]
    fn recovered_whatsapp_keeps_the_sub_second_that_orders_two_messages() {
        // Two salvaged rows from inside the same second. A recovered row has no
        // live b-tree position to fall back on, so the ZMESSAGEDATE fraction is
        // the whole of what says which message came first — and it used to be
        // cast away with `f as i64`.
        let result = result_with(
            &["ZWAMESSAGE"],
            vec![
                rec(
                    "ZWAMESSAGE",
                    &[
                        ("ZTEXT", Value::Text("are you around".into())),
                        ("ZFROMJID", Value::Text("15551234@s.whatsapp.net".into())),
                        ("ZMESSAGEDATE", Value::Float(700_000_000.25)),
                        ("ZISFROMME", Value::Int(0)),
                    ],
                    Some(1),
                ),
                rec(
                    "ZWAMESSAGE",
                    &[
                        ("ZTEXT", Value::Text("yes just got in".into())),
                        ("ZFROMJID", Value::Text("15551234@s.whatsapp.net".into())),
                        ("ZMESSAGEDATE", Value::Float(700_000_000.75)),
                        ("ZISFROMME", Value::Int(1)),
                    ],
                    Some(2),
                ),
            ],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 2);
        let base = 700_000_000 + APPLE_EPOCH;
        assert_eq!(msgs[0]["date"], base);
        assert_eq!(msgs[1]["date"], base);
        let first_ns = msgs[0]["date_ns"].as_i64().unwrap();
        let reply_ns = msgs[1]["date_ns"].as_i64().unwrap();
        assert_eq!(first_ns, base * 1_000_000_000 + 250_000_000);
        assert_eq!(reply_ns, base * 1_000_000_000 + 750_000_000);
        assert!(
            first_ns < reply_ns,
            "the recovered reply must still sort after the message it answers"
        );
    }

    #[test]
    fn recovered_imessage_nanosecond_column_keeps_its_fraction() {
        // iOS 11+ writes `message.date` as nanoseconds since 2001. The whole
        // nanosecond value is the record's precision; publishing only its
        // seconds discarded it.
        let ns_since_2001 = 700_000_000i64 * 1_000_000_000 + 123_456_789;
        let result = result_with(
            &["message", "handle", "chat"],
            vec![rec(
                "message",
                &[
                    ("text", Value::Text("meet at noon".into())),
                    ("date", Value::Int(ns_since_2001)),
                    ("is_from_me", Value::Int(0)),
                ],
                Some(1),
            )],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        let base = 700_000_000 + APPLE_EPOCH;
        assert_eq!(msgs[0]["date"], base);
        assert_eq!(
            msgs[0]["date_ns"].as_i64(),
            Some(base * 1_000_000_000 + 123_456_789)
        );
    }

    #[test]
    fn whatsapp_ios_zero_date_is_undated_not_2001() {
        // A ZMESSAGEDATE of 0 is unset; it must be null, not 978307200 (2001).
        let result = result_with(
            &["ZWAMESSAGE"],
            vec![rec(
                "ZWAMESSAGE",
                &[
                    ("ZTEXT", Value::Text("no timestamp here".into())),
                    ("ZFROMJID", Value::Text("15551234@s.whatsapp.net".into())),
                    ("ZMESSAGEDATE", Value::Float(0.0)),
                    ("ZISFROMME", Value::Int(0)),
                ],
                Some(1),
            )],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        assert!(
            msgs[0]["date"].is_null(),
            "unset date must be null, not 2001"
        );
    }

    #[test]
    fn whatsapp_android_zero_timestamp_is_undated_not_1970() {
        let result = result_with(
            &["messages", "chat_list"],
            vec![rec(
                "messages",
                &[
                    ("data", Value::Text("hello".into())),
                    (
                        "key_remote_jid",
                        Value::Text("15551234@s.whatsapp.net".into()),
                    ),
                    ("timestamp", Value::Int(0)),
                    ("key_from_me", Value::Int(1)),
                ],
                Some(1),
            )],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        assert!(
            msgs[0]["date"].is_null(),
            "unset timestamp must be null, not 1970"
        );
    }

    #[test]
    fn signal_message_table_is_not_labelled_whatsapp() {
        // BUG-221: a bare `message` table is not evidence of WhatsApp. Signal's
        // deleted rows must not be published as "WhatsApp Android (recovered)".
        let result = result_with(
            &["message", "recipient", "thread", "part"],
            vec![rec(
                "message",
                &[
                    ("body", Value::Text("burner phone tomorrow".into())),
                    ("thread_id", Value::Int(4)),
                    ("date_sent", Value::Int(1_600_000_000_000)),
                ],
                Some(1),
            )],
        );
        assert!(
            reconstruct(&result).is_empty(),
            "Signal rows must not be attributed to another app"
        );
    }

    #[test]
    fn generic_message_table_without_whatsapp_markers_is_not_attributed() {
        // BUG-221: some unrelated store with a `messages` table (no jid /
        // chat_list / media tables) must stay unattributed.
        let result = result_with(
            &["messages", "threads"],
            vec![rec(
                "messages",
                &[
                    ("data", Value::Text("hello there friend".into())),
                    ("timestamp", Value::Int(1_600_000_000_000)),
                ],
                Some(1),
            )],
        );
        assert!(reconstruct(&result).is_empty());
    }

    #[test]
    fn whatsapp_android_modern_columns_resolve_direction_and_thread() {
        // BUG-222: modern msgstore has no JID string and no `key_from_me` on the
        // message: text_data / from_me / chat_row_id -> chat.jid_row_id -> jid.
        let result = result_with(
            &["message", "chat", "jid"],
            vec![
                rec(
                    "jid",
                    &[("raw_string", Value::Text("447700900999@g.us".into()))],
                    Some(9),
                ),
                rec(
                    "chat",
                    &[
                        ("jid_row_id", Value::Int(9)),
                        ("subject", Value::Text("Work Group".into())),
                    ],
                    Some(3),
                ),
                rec(
                    "message",
                    &[
                        ("chat_row_id", Value::Int(3)),
                        ("from_me", Value::Int(1)),
                        ("text_data", Value::Text("delete this later".into())),
                        ("timestamp", Value::Int(1_600_000_000_000)),
                    ],
                    Some(11),
                ),
            ],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        assert_eq!(m["text"], "delete this later");
        assert_eq!(
            m["chat_identifier"], "447700900999@g.us",
            "thread must resolve through chat_row_id, not collapse to unknown"
        );
        assert_eq!(m["contact"], "Work Group");
        assert_eq!(m["is_from_me"], true, "direction must come from `from_me`");
        assert_eq!(m["direction"], "sent");
    }

    #[test]
    fn wal_rows_become_recovered_chat_messages_but_are_not_called_deleted() {
        // BUG-228: an uncheckpointed WAL frame is where a seized phone keeps its
        // most recent messages. It must reach the conversation view, flagged as
        // recovered-from-wal and NOT as deleted.
        let result = result_with(
            &["message", "handle", "chat"],
            vec![
                live_rec(
                    "handle",
                    &[("id", Value::Text("+15551234".into()))],
                    Some(7),
                ),
                wal_rec(
                    "message",
                    &[
                        ("text", Value::Text("just landed, call me".into())),
                        ("handle_id", Value::Int(7)),
                        ("is_from_me", Value::Int(0)),
                        ("date", Value::Int(700_000_000)),
                    ],
                    Some(102),
                ),
            ],
        );
        let msgs = reconstruct(&result);
        assert_eq!(
            msgs.len(),
            1,
            "WAL frame must be promoted to a chat message"
        );
        let m = &msgs[0];
        assert_eq!(m["text"], "just landed, call me");
        assert_eq!(m["chat_identifier"], "+15551234");
        assert_eq!(m["recovered"], true);
        assert_eq!(m["recovery_source"], "wal");
        assert_eq!(
            m["deleted"], false,
            "an uncheckpointed page version is not a deleted row"
        );
    }

    #[test]
    fn wal_copy_of_a_live_row_is_not_duplicated() {
        // The same page version can sit in both the b-tree and the WAL; promoting
        // it would show one message twice.
        let result = result_with(
            &["message", "handle", "chat"],
            vec![
                live_rec(
                    "handle",
                    &[("id", Value::Text("+15551234".into()))],
                    Some(7),
                ),
                live_rec(
                    "message",
                    &[
                        ("text", Value::Text("already checkpointed".into())),
                        ("handle_id", Value::Int(7)),
                        ("is_from_me", Value::Int(0)),
                    ],
                    Some(50),
                ),
                wal_rec(
                    "message",
                    &[
                        ("text", Value::Text("already checkpointed".into())),
                        ("handle_id", Value::Int(7)),
                        ("is_from_me", Value::Int(0)),
                    ],
                    Some(50),
                ),
            ],
        );
        assert!(
            reconstruct(&result).is_empty(),
            "a WAL copy of a live message must not be re-emitted as recovered"
        );
    }

    #[test]
    fn wal_message_survives_a_live_text_collision_in_another_row() {
        // BUG-250: dedup must key on row identity (table + rowid + body), not on
        // "this body appears somewhere live". A short, common body — or one that
        // equals a live handle/JID — is not evidence of a duplicate.
        let result = result_with(
            &["message", "handle", "chat"],
            vec![
                live_rec(
                    "handle",
                    &[("id", Value::Text("+15551234".into()))],
                    Some(7),
                ),
                // A different live message that happens to say the same thing.
                live_rec(
                    "message",
                    &[
                        ("text", Value::Text("ok see you then".into())),
                        ("handle_id", Value::Int(7)),
                        ("is_from_me", Value::Int(0)),
                    ],
                    Some(50),
                ),
                // Genuinely uncheckpointed: a different row of the same table.
                wal_rec(
                    "message",
                    &[
                        ("text", Value::Text("ok see you then".into())),
                        ("handle_id", Value::Int(7)),
                        ("is_from_me", Value::Int(1)),
                        ("date", Value::Int(700_000_500)),
                    ],
                    Some(51),
                ),
            ],
        );
        let msgs = reconstruct(&result);
        assert_eq!(
            msgs.len(),
            1,
            "a WAL row with its own rowid is not a copy of another live row"
        );
        assert_eq!(msgs[0]["recovery_source"], "wal");
        assert_eq!(msgs[0]["source_rowid"], 51);
    }

    #[test]
    fn wal_row_that_collides_with_a_live_handle_string_is_kept() {
        // The old global text set contained every live text cell, including
        // handles and JIDs, so a message body that happened to equal one of them
        // vanished. iMessage handles are email addresses, and a message whose
        // body is just an address ("who should I contact?" -> "x@y.com") is
        // ordinary, so the collision is realistic rather than contrived.
        let addr = "john.smith@example.com";
        let result = result_with(
            &["message", "handle", "chat"],
            vec![
                live_rec("handle", &[("id", Value::Text(addr.into()))], Some(7)),
                wal_rec(
                    "message",
                    &[
                        ("text", Value::Text(addr.into())),
                        ("handle_id", Value::Int(7)),
                        ("is_from_me", Value::Int(0)),
                    ],
                    Some(99),
                ),
            ],
        );
        let msgs = reconstruct(&result);
        assert_eq!(
            msgs.len(),
            1,
            "a WAL body equal to a live handle string is a message, not a duplicate of that handle row"
        );
        assert_eq!(msgs[0]["text"], addr);
    }

    #[test]
    fn wal_version_of_a_live_row_with_a_different_body_is_kept() {
        // Same rowid, different body: the page version records a change to that
        // row, which is evidence rather than a duplicate.
        let result = result_with(
            &["message", "handle", "chat"],
            vec![
                live_rec(
                    "handle",
                    &[("id", Value::Text("+15551234".into()))],
                    Some(7),
                ),
                live_rec(
                    "message",
                    &[
                        ("text", Value::Text("already checkpointed".into())),
                        ("handle_id", Value::Int(7)),
                        ("is_from_me", Value::Int(0)),
                    ],
                    Some(50),
                ),
                wal_rec(
                    "message",
                    &[
                        ("text", Value::Text("edited after checkpoint".into())),
                        ("handle_id", Value::Int(7)),
                        ("is_from_me", Value::Int(0)),
                    ],
                    Some(50),
                ),
            ],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["text"], "edited after checkpoint");
    }

    #[test]
    fn android_sms_zero_date_is_undated_not_1970() {
        let result = result_with(
            &["sms"],
            vec![rec(
                "sms",
                &[
                    ("address", Value::Text("+15559999".into())),
                    ("body", Value::Text("secret".into())),
                    ("type", Value::Int(1)),
                    ("date", Value::Int(0)),
                ],
                Some(1),
            )],
        );
        let msgs = reconstruct(&result);
        assert_eq!(msgs.len(), 1);
        assert!(
            msgs[0]["date"].is_null(),
            "unset date must be null, not 1970"
        );
    }
}
