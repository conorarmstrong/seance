#![forbid(unsafe_code)]
//! Android SMS/MMS Parser Module
//!
//! Parses the Android telephony provider store (`mmssms.db`) extracting SMS
//! and MMS messages as forensic artifacts.
//!
//! ## Supported Database
//!
//! - `mmssms.db` — Android telephony store (`content://mms-sms`)
//!
//! ## Schema
//!
//! - `sms` — text messages (`_id, thread_id, address, date, type, body, ...`)
//! - `threads` / `canonical_addresses` — recipient resolution
//! - `pdu` / `part` / `addr` — MMS envelopes, body parts and addresses
//!
//! The authoritative claim check is the presence of the `sms` table. WhatsApp
//! (`msgstore.db`) and iMessage (`chat.db`) use `message`/`messages` and have no
//! `sms` table, so this module never double-parses those stores.
//!
//! ## Schema drift
//!
//! `PRAGMA user_version` is checked against the window observed on real
//! telephony stores (`SUPPORTED_SCHEMA`), and every column is resolved through
//! a field map. A store outside the window, or one whose columns no candidate
//! name matches, still parses and carries a `ParserStaleWarning` record naming
//! the version or the unresolved fields — never a silent shortfall.
//!
//! ## Timestamps
//!
//! SMS `date` is Unix epoch **milliseconds** and MMS `pdu.date` is Unix epoch
//! **seconds**, but a store recovered from a backup or a third-party SMS app
//! may hold either — or microseconds. The unit is therefore judged from the
//! magnitude by the one shared band table,
//! [`seance_sqlite_util::unix_seconds_from_magnitude`], rather than by a rule
//! local to this file. We surface both a Unix-seconds integer (`date`) and an
//! RFC3339 string (`date_rfc3339`); a column that recorded no instant surfaces
//! as neither.

#[cfg(test)]
mod schema_golden_tests;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
#[cfg(test)]
use seance_sqlite_util::adopt::inline_marker::field_drift_marker;
use seance_sqlite_util::adopt::inline_marker::{user_version_marker, TableFields as Fields};
#[cfg(test)]
use seance_sqlite_util::FieldMap;
use seance_sqlite_util::{probe_table, unix_seconds_from_magnitude, Presence, SupportedRange};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Maximum number of messages to extract per database.
const MAX_MESSAGE_ENTRIES: usize = 50_000;

/// Maximum on-disk database size we will spill and open.
const MAX_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The parser identity a schema warning is filed under.
const SCHEMA_APP: &str = "android-sms";

/// The `PRAGMA user_version` window this parser was validated against, on real
/// telephony stores only — never widened by guesswork. Observed: 57 in plaso's
/// `test_data/mmssms.db`, 67 in the Magnet 2022 CTF Pixel 3
/// (`com.android.providers.telephony/databases/mmssms.db`). A store outside
/// it still parses; it also carries a `ParserStaleWarning`.
const SUPPORTED_SCHEMA: SupportedRange = SupportedRange {
    min: 57,
    max: Some(67),
};

/// The real stores each endpoint of [`SUPPORTED_SCHEMA`] was read out of,
/// written on every schema record as `validated_against`.
const SCHEMA_EVIDENCE: &str = "plaso test_data/mmssms.db (user_version 57); Magnet 2022 CTF \
     Pixel 3 com.android.providers.telephony/databases/mmssms.db (user_version 67)";

/// The logical fields each table is read through, with the physical column
/// names that have carried them in the real stores above. A rename in a newer
/// telephony provider is then one more candidate here, not a code path — and
/// until it is added, the field is reported as unresolved rather than read as
/// empty.
const SMS_FIELDS: &[(&str, &[&str])] = &[
    ("id", &["_id"]),
    ("thread_id", &["thread_id"]),
    ("address", &["address"]),
    ("date", &["date"]),
    ("read", &["read"]),
    ("status", &["status"]),
    ("type", &["type"]),
    ("body", &["body"]),
    ("subject", &["subject"]),
];
const PDU_FIELDS: &[(&str, &[&str])] = &[
    ("id", &["_id"]),
    ("thread_id", &["thread_id"]),
    ("date", &["date"]),
    ("msg_box", &["msg_box"]),
    ("read", &["read"]),
    ("subject", &["sub"]),
    ("status", &["st"]),
];
const PART_FIELDS: &[(&str, &[&str])] = &[
    ("message_id", &["mid"]),
    ("content_type", &["ct"]),
    ("text", &["text"]),
    ("name", &["name"]),
    ("content_location", &["cl"]),
    ("file_name", &["fn"]),
];
const ADDR_FIELDS: &[(&str, &[&str])] = &[
    ("message_id", &["msg_id"]),
    ("address", &["address"]),
    ("type", &["type"]),
];
const THREAD_FIELDS: &[(&str, &[&str])] =
    &[("id", &["_id"]), ("recipient_ids", &["recipient_ids"])];
const CANONICAL_FIELDS: &[(&str, &[&str])] = &[("id", &["_id"]), ("address", &["address"])];

/// The marker for this store's `PRAGMA user_version` against the validated
/// window, if any.
fn schema_version_marker(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Option<Artifact> {
    user_version_marker(
        conn,
        case_id,
        parent_id,
        SCHEMA_APP,
        &SUPPORTED_SCHEMA,
        SCHEMA_EVIDENCE,
    )
}

pub struct AndroidSmsParser;

/// Permissive filename pre-filter (only decides whether to open the file). The
/// authoritative check is the `sms`-table schema (`has_android_sms_schema`) run
/// after opening, which rejects any false positive. Matching on suffix/substring
/// means renamed or path-prefixed copies are still parsed.
/// Address book for a message walk: contact id to display name, contact id to
/// its known numbers, how many rows the lookup itself could not decode, and the
/// schema-drift marker for the lookup table when a column did not resolve.
///
/// The third element is the one that must not be dropped: a name resolved from
/// a partial address book is still a name, but the count says how partial.
type ContactIndex = (
    HashMap<i64, String>,
    HashMap<i64, Vec<String>>,
    usize,
    Option<Artifact>,
);

fn identify_android_sms_db(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("mmssms.db") || n.contains("mmssms")
}

/// True if a table with the given name exists.
///
/// Returns `Err` when the catalogue itself could not be read. A corrupt database
/// answers that query with an error, and reporting it as "table absent" turned
/// an unreadable telephony store into a phone that had exchanged no messages:
/// "no such table" and "could not tell" must never render the same.
fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    // Delegates so views count as present; see the note in the `bool` form of
    // this helper elsewhere in the tree. `Undetermined` stays an error here,
    // because a catalogue that would not read is not an absent table.
    match probe_table(conn, table) {
        Presence::Present => Ok(true),
        Presence::Absent => Ok(false),
        Presence::Undetermined(why) => Err(anyhow::anyhow!(
            "Failed to read the schema catalogue looking for '{table}': {why}"
        )),
    }
}

/// True if the staged copy begins with the SQLite file magic.
///
/// Used to tell "not our database" from "a telephony store that would not
/// open": the first must stay silent, the second must be reported.
fn staged_looks_like_sqlite(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && seance_core::io::is_sqlite_header(&head)
}

/// Authoritative schema check: the Android telephony `sms` table. This is what
/// distinguishes `mmssms.db` from WhatsApp (`msgstore.db`) and iMessage
/// (`chat.db`), neither of which has an `sms` table.
fn has_android_sms_schema(conn: &Connection) -> Result<bool> {
    table_exists(conn, "sms")
}

/// Map an Android `sms.type` code to (direction, is_from_me). `None` (a NULL
/// column) and any code the platform does not define both yield `(None, None)`:
/// the direction was not established, and neither key is written.
///
/// The keys are OMITTED rather than set to a literal `"unknown"` because that is
/// what every consumer already treats as undetermined — the messaging viewer
/// prints "Direction (Sent/Received) Not Determinable" for an absent `direction`
/// but renders the string `"unknown"` on the received side with no note at all,
/// so the honest-looking literal published exactly the fabricated attribution it
/// was meant to prevent. Signal/Telegram/iMessage omit it for the same reason.
///
/// Android Sms.Type: 1=inbox(received), 2=sent, 3=draft, 4=outbox, 5=failed,
/// 6=queued. Only "sent" is actually delivered; drafts, outbox, failed and
/// queued are outgoing but NOT sent, so they must not be labeled "sent".
/// `is_from_me` is true for every outgoing state (the user authored it);
/// `direction` carries the precise state so filters/comms graphs are not misled.
fn sms_direction(sms_type: Option<i64>) -> (Option<&'static str>, Option<bool>) {
    match sms_type {
        Some(1) => (Some("received"), Some(false)),
        Some(2) => (Some("sent"), Some(true)),
        Some(3) => (Some("draft"), Some(true)),
        Some(4) => (Some("outbox"), Some(true)),
        Some(5) => (Some("failed"), Some(true)),
        Some(6) => (Some("queued"), Some(true)),
        _ => (None, None),
    }
}

/// Map an Android MMS `pdu.msg_box` code to (direction, is_from_me). Same
/// contract as [`sms_direction`]: 1=inbox(received), 2=sent, 3=draft, 4=outbox.
fn mms_direction(msg_box: Option<i64>) -> (Option<&'static str>, Option<bool>) {
    match msg_box {
        Some(1) => (Some("received"), Some(false)),
        Some(2) => (Some("sent"), Some(true)),
        Some(3) => (Some("draft"), Some(true)),
        Some(4) => (Some("outbox"), Some(true)),
        _ => (None, None),
    }
}

/// Convert a raw Android telephony epoch value to whole Unix seconds, or `None`
/// where the column recorded no instant.
///
/// This is [`unix_seconds_from_magnitude`] and nothing else. It used to be a
/// local two-branch rule — below 10^11 seconds, at or above it milliseconds —
/// which is right for the two units Android itself writes and wrong for the
/// third unit this corpus contains: a 16-digit microsecond value was divided by
/// a thousand and dated the message to the year 55840. The shared normaliser
/// judges microseconds, milliseconds and seconds by one band table, and
/// `chat.rs` documents `date` as whole seconds on the strength of it.
///
/// Two behaviours changed with it, both deliberately:
///
/// * A `date` of `0` no longer becomes a literal `date: 0`. Zero is a column
///   the store never set, not midnight on 1970-01-01. The viewers already skip
///   a `0` (their first-key-that-passes rule fails the band test on it), so
///   that state was invisible in the browser while a server-side `COALESCE`
///   over the same record took it as non-NULL and placed the message fifty
///   years early — the same record, fifty years apart, depending on who read
///   it. It is not silently discarded either: the caller writes it back under
///   `date_unusable` / `date_raw`, so the fact that the store held a value
///   survives without being offered as a time.
/// * A negative `date` is treated the same way. No SMS predates 1992, so a
///   negative telephony epoch is a corrupt or unset column rather than an old
///   message, and it must not anchor a timeline entry in the 1960s.
fn normalize_epoch_secs(raw: i64) -> Option<i64> {
    unix_seconds_from_magnitude(raw)
}

/// RFC3339 string for a Unix-seconds value. None if out of range.
fn to_rfc3339(secs: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339())
}

/// Build a best-effort `thread_id -> recipient address` map by joining
/// `threads.recipient_ids` (space-separated canonical ids) to
/// `canonical_addresses.address`. Empty when those tables are absent.
///
/// The returned count is the number of rows that would not decode: a lost
/// `canonical_addresses` or `threads` row silently renames a correspondent to a
/// thread id, so it is tallied rather than dropped.
///
/// The markers are for the two lookup tables' columns: a renamed
/// `recipient_ids` would otherwise silently rename every correspondent to a
/// thread id.
fn build_thread_address_map(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
) -> Result<(HashMap<i64, String>, usize, Vec<Artifact>)> {
    let mut map = HashMap::new();
    let mut dropped = 0usize;
    if !table_exists(conn, "threads")? || !table_exists(conn, "canonical_addresses")? {
        return Ok((map, dropped, Vec::new()));
    }

    let canonical = Fields::resolve(conn, SCHEMA_APP, "canonical_addresses", CANONICAL_FIELDS)?;
    let threads = Fields::resolve(conn, SCHEMA_APP, "threads", THREAD_FIELDS)?;
    let mut markers = Vec::new();
    markers.extend(canonical.drift_marker(case_id, parent_id, 0));
    markers.extend(threads.drift_marker(case_id, parent_id, 0));

    let mut canon: HashMap<i64, String> = HashMap::new();
    let select = format!(
        "SELECT {}, {} FROM canonical_addresses",
        canonical.col_or("id", "rowid"),
        canonical.col("address")
    );
    if let Ok(mut stmt) = conn.prepare(&select) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
        }) {
            for row in rows {
                let (id, addr) = match row {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("Skipping malformed canonical_addresses row: {}", e);
                        dropped += 1;
                        continue;
                    }
                };
                if let Some(a) = addr.filter(|s| !s.is_empty()) {
                    canon.insert(id, a);
                }
            }
        }
    }

    let select = format!(
        "SELECT {}, {} FROM threads",
        threads.col_or("id", "rowid"),
        threads.col("recipient_ids")
    );
    if let Ok(mut stmt) = conn.prepare(&select) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
        }) {
            for row in rows {
                let (tid, recipient_ids) = match row {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("Skipping malformed threads row: {}", e);
                        dropped += 1;
                        continue;
                    }
                };
                if let Some(ids) = recipient_ids {
                    let addrs: Vec<String> = ids
                        .split_whitespace()
                        .filter_map(|s| s.parse::<i64>().ok())
                        .filter_map(|id| canon.get(&id).cloned())
                        .collect();
                    if !addrs.is_empty() {
                        map.insert(tid, addrs.join(", "));
                    }
                }
            }
        }
    }

    Ok((map, dropped, markers))
}

/// Resolve the recipient/contact strings for a message given its explicit
/// address (may be None) and thread id. Returns (contact, chat_identifier,
/// chat_display_name).
fn resolve_contact(
    address: Option<String>,
    thread_id: Option<i64>,
    thread_addr: &HashMap<i64, String>,
) -> (String, String, String) {
    let addr = address
        .filter(|s| !s.is_empty())
        .or_else(|| thread_id.and_then(|t| thread_addr.get(&t).cloned()));

    let chat_identifier = addr.clone().unwrap_or_else(|| {
        thread_id
            .map(|t| t.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });
    let contact = addr.clone().unwrap_or_else(|| chat_identifier.clone());
    let chat_display_name = addr
        .clone()
        .unwrap_or_else(|| format!("Thread {}", chat_identifier));

    (contact, chat_identifier, chat_display_name)
}

/// Parse SMS and MMS messages plus a trailing summary record.
fn parse_android_sms(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Result<Vec<Artifact>> {
    parse_android_sms_capped(conn, case_id, parent_id, file_name, MAX_MESSAGE_ENTRIES)
}

/// [`parse_android_sms`] with the row budget supplied, so the cap-reached path
/// is reachable in a test without seeding fifty thousand messages.
fn parse_android_sms_capped(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    // Schema-drift defence: the store's version against the validated window,
    // then every table's columns against the names the parser knows. Both are
    // findings filed beside the records, never reasons to stop the walk.
    let mut markers = Vec::new();
    markers.extend(schema_version_marker(conn, case_id, parent_id));
    let (thread_addr, mut dropped_rows, lookup_markers) =
        build_thread_address_map(conn, case_id, parent_id)?;
    markers.extend(lookup_markers);

    let mut thread_ids: HashSet<i64> = HashSet::new();
    let mut sms_count = 0usize;
    let mut mms_count = 0usize;
    let mut truncated = false;

    // --- SMS ---
    {
        let sms = Fields::resolve(conn, SCHEMA_APP, "sms", SMS_FIELDS)?;
        let select = format!(
            "SELECT {id}, {thread}, {address}, {date}, {read}, {status}, {kind}, {body}, {subject}
             FROM sms ORDER BY {date} DESC",
            id = sms.col_or("id", "rowid"),
            thread = sms.col("thread_id"),
            address = sms.col("address"),
            date = sms.col("date"),
            read = sms.col("read"),
            status = sms.col("status"),
            kind = sms.col("type"),
            body = sms.col("body"),
            subject = sms.col("subject"),
        );
        let mut stmt = conn
            .prepare(&select)
            .context("Failed to prepare sms query")?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,            // _id
                    row.get::<_, Option<i64>>(1)?,    // thread_id
                    row.get::<_, Option<String>>(2)?, // address
                    row.get::<_, Option<i64>>(3)?,    // date (millis)
                    row.get::<_, Option<i64>>(4)?,    // read
                    row.get::<_, Option<i64>>(5)?,    // status
                    row.get::<_, Option<i64>>(6)?,    // type
                    row.get::<_, Option<String>>(7)?, // body
                    row.get::<_, Option<String>>(8)?, // subject
                ))
            })
            .context("Failed to query sms rows")?;

        for row in rows {
            if artifacts.len() >= max_entries {
                truncated = true;
                break;
            }
            let (id, thread_id, address, date, read, status, sms_type, body, subject) = match row {
                Ok(r) => r,
                Err(e) => {
                    debug!("Skipping malformed sms row: {}", e);
                    dropped_rows += 1;
                    continue;
                }
            };

            // A NULL `type` never recorded the direction. It must not become
            // "received" / `is_from_me: false`: that is an affirmative statement
            // that the other party wrote the message.
            let (direction, is_from_me) = sms_direction(sms_type);

            let (contact, chat_identifier, chat_display_name) =
                resolve_contact(address, thread_id, &thread_addr);
            if let Some(t) = thread_id {
                thread_ids.insert(t);
            }

            let mut meta = serde_json::Map::new();
            meta.insert("type".into(), json!("AndroidSms"));
            meta.insert("service".into(), json!("SMS"));
            // Absent, not false: an undetermined author must never read as the
            // correspondent having written the message, and an absent key is
            // what the viewers already render as "not determinable".
            if let Some(from_me) = is_from_me {
                meta.insert("is_from_me".into(), json!(from_me));
            }
            if let Some(d) = direction {
                meta.insert("direction".into(), json!(d));
            }
            // The column as stored, null included — not a substituted 1. This is
            // what distinguishes "the type column was NULL" from "the row was
            // never examined".
            meta.insert("sms_type".into(), json!(sms_type));
            meta.insert("contact".into(), json!(contact));
            meta.insert("chat_identifier".into(), json!(chat_identifier));
            meta.insert("chat_display_name".into(), json!(chat_display_name));
            meta.insert("rowid".into(), json!(id));
            if let Some(t) = thread_id {
                meta.insert("thread_id".into(), json!(t));
            }
            if let Some(b) = &body {
                meta.insert("text".into(), json!(b));
            }
            if let Some(s) = subject.filter(|s| !s.is_empty()) {
                meta.insert("subject".into(), json!(s));
            }
            match date.and_then(normalize_epoch_secs) {
                Some(secs) => {
                    meta.insert("date".into(), json!(secs));
                    if let Some(r) = to_rfc3339(secs) {
                        meta.insert("date_rfc3339".into(), json!(r));
                    }
                }
                // The column held a value and no reading of it is an instant.
                // That the store wrote a literal 0 (or a negative) is an
                // observation worth keeping, so it is kept — under a key no
                // consumer can mistake for a time, and beside the flag the
                // utmp parser already uses for the same situation. Neither
                // `date` nor `date_rfc3339` is written, because a
                // "1970-01-01T00:00:00+00:00" string standing next to an
                // omitted `date` is the same false claim in another field.
                None => {
                    if let Some(raw) = date {
                        meta.insert("date_unusable".into(), json!(true));
                        meta.insert("date_raw".into(), json!(raw));
                    }
                }
            }
            if let Some(r) = read {
                meta.insert("read".into(), json!(r != 0));
            }
            if let Some(st) = status {
                meta.insert("status".into(), json!(st));
            }

            let preview = body
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(80)
                .collect::<String>();
            meta.insert(
                "name".into(),
                json!(format!(
                    "{}: {} — {}",
                    direction.unwrap_or("message"),
                    contact,
                    if preview.is_empty() {
                        "(no text)"
                    } else {
                        &preview
                    }
                )),
            );

            let artifact = Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                Value::Object(meta),
            )
            .with_parent(parent_id)
            .with_subtype("chat_message");
            artifacts.push(artifact);
            sms_count += 1;
        }
        markers.extend(sms.drift_marker(case_id, parent_id, sms_count));
    }

    // --- MMS (best-effort) ---
    if table_exists(conn, "pdu")? {
        let (part_text, part_atts, part_dropped, part_marker) =
            load_mms_parts(conn, case_id, parent_id)?;
        let (addr_from, addr_to, addr_dropped, addr_marker) =
            load_mms_addresses(conn, case_id, parent_id)?;
        dropped_rows += part_dropped + addr_dropped;
        markers.extend(part_marker);
        markers.extend(addr_marker);

        let pdu = Fields::resolve(conn, SCHEMA_APP, "pdu", PDU_FIELDS)?;
        let select = format!(
            "SELECT {id}, {thread}, {date}, {msg_box}, {read}, {subject}, {status}
             FROM pdu ORDER BY {date} DESC",
            id = pdu.col_or("id", "rowid"),
            thread = pdu.col("thread_id"),
            date = pdu.col("date"),
            msg_box = pdu.col("msg_box"),
            read = pdu.col("read"),
            subject = pdu.col("subject"),
            status = pdu.col("status"),
        );
        let mut stmt = conn
            .prepare(&select)
            .context("Failed to prepare pdu query")?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,            // _id
                    row.get::<_, Option<i64>>(1)?,    // thread_id
                    row.get::<_, Option<i64>>(2)?,    // date (seconds)
                    row.get::<_, Option<i64>>(3)?,    // msg_box
                    row.get::<_, Option<i64>>(4)?,    // read
                    row.get::<_, Option<String>>(5)?, // sub (subject)
                    row.get::<_, Option<i64>>(6)?,    // st (status)
                ))
            })
            .context("Failed to query pdu rows")?;

        for row in rows {
            if artifacts.len() >= max_entries {
                truncated = true;
                break;
            }
            let (id, thread_id, date, msg_box, read, sub, st) = match row {
                Ok(r) => r,
                Err(e) => {
                    debug!("Skipping malformed pdu row: {}", e);
                    dropped_rows += 1;
                    continue;
                }
            };

            // A NULL `msg_box` never recorded the direction, and on MMS the
            // direction also decides which `addr` row is the correspondent — so
            // defaulting it to "received" both invented the attribution and
            // pointed the peer at the wrong address row.
            let (direction, is_from_me) = mms_direction(msg_box);

            // Received: the peer is addr type 137 (from). Outgoing (sent, draft,
            // outbox): the peer is type 151 (to). On an outgoing PDU the `from`
            // row is the device owner, so it is never a fallback for the peer —
            // with no `to` row the address stays absent and `resolve_contact`
            // falls back to the thread's own address. With the direction
            // undetermined neither side can be chosen, so no addr row is used
            // and the thread's own address stands in.
            let address = match is_from_me {
                Some(true) => addr_to.get(&id).and_then(|v| v.first().cloned()),
                Some(false) => addr_from.get(&id).cloned(),
                None => None,
            };

            let (contact, chat_identifier, chat_display_name) =
                resolve_contact(address, thread_id, &thread_addr);
            if let Some(t) = thread_id {
                thread_ids.insert(t);
            }

            let atts = part_atts.get(&id).cloned().unwrap_or_default();
            let has_attachments = !atts.is_empty();

            let mut meta = serde_json::Map::new();
            meta.insert("type".into(), json!("AndroidSms"));
            meta.insert("service".into(), json!("MMS"));
            // Absent, not false: an undetermined author must never read as the
            // correspondent having sent the MMS.
            if let Some(from_me) = is_from_me {
                meta.insert("is_from_me".into(), json!(from_me));
            }
            if let Some(d) = direction {
                meta.insert("direction".into(), json!(d));
            }
            // The column as stored, null included — not a substituted 1.
            meta.insert("msg_box".into(), json!(msg_box));
            if is_from_me.is_none() {
                // The peer could not be selected from the `addr` rows because
                // the direction that selects them was never recorded.
                meta.insert("peer_undetermined".into(), json!(true));
            }
            meta.insert("contact".into(), json!(contact));
            meta.insert("chat_identifier".into(), json!(chat_identifier));
            meta.insert("chat_display_name".into(), json!(chat_display_name));
            meta.insert("has_attachments".into(), json!(has_attachments));
            meta.insert("rowid".into(), json!(id));
            if has_attachments {
                meta.insert("attachment_names".into(), json!(atts));
            }
            if let Some(t) = thread_id {
                meta.insert("thread_id".into(), json!(t));
            }
            if let Some(t) = part_text.get(&id) {
                meta.insert("text".into(), json!(t));
            }
            if let Some(s) = sub.filter(|s| !s.is_empty()) {
                meta.insert("subject".into(), json!(s));
            }
            match date.and_then(normalize_epoch_secs) {
                Some(secs) => {
                    meta.insert("date".into(), json!(secs));
                    if let Some(r) = to_rfc3339(secs) {
                        meta.insert("date_rfc3339".into(), json!(r));
                    }
                }
                // The column held a value and no reading of it is an instant.
                // That the store wrote a literal 0 (or a negative) is an
                // observation worth keeping, so it is kept — under a key no
                // consumer can mistake for a time, and beside the flag the
                // utmp parser already uses for the same situation. Neither
                // `date` nor `date_rfc3339` is written, because a
                // "1970-01-01T00:00:00+00:00" string standing next to an
                // omitted `date` is the same false claim in another field.
                None => {
                    if let Some(raw) = date {
                        meta.insert("date_unusable".into(), json!(true));
                        meta.insert("date_raw".into(), json!(raw));
                    }
                }
            }
            if let Some(r) = read {
                meta.insert("read".into(), json!(r != 0));
            }
            if let Some(st) = st {
                meta.insert("status".into(), json!(st));
            }

            let preview = part_text
                .get(&id)
                .map(|s| s.chars().take(80).collect::<String>())
                .unwrap_or_default();
            meta.insert(
                "name".into(),
                json!(format!(
                    "{}: {} — {}",
                    direction.unwrap_or("message"),
                    contact,
                    if preview.is_empty() {
                        "(MMS attachment)"
                    } else {
                        &preview
                    }
                )),
            );

            let artifact = Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                Value::Object(meta),
            )
            .with_parent(parent_id)
            .with_subtype("chat_message");
            artifacts.push(artifact);
            mms_count += 1;
        }
        markers.extend(pdu.drift_marker(case_id, parent_id, mms_count));
    }

    // The schema findings sit between the records and the summary, so a reader
    // walking the list meets them before the totals they qualify.
    artifacts.extend(markers);

    // --- Summary ---
    let message_count = sms_count + mms_count;
    let thread_count = thread_ids.len();
    let mut summary = serde_json::Map::new();
    summary.insert("type".into(), json!("AndroidSmsSummary"));
    summary.insert("message_count".into(), json!(message_count));
    summary.insert("thread_count".into(), json!(thread_count));
    summary.insert("sms_count".into(), json!(sms_count));
    summary.insert("mms_count".into(), json!(mms_count));
    summary.insert("file_name".into(), json!(file_name));
    // Both walks are `ORDER BY date DESC`, so the cap drops the OLDEST
    // messages. `truncated` alone is easy for a consumer to miss; the
    // `content_incomplete` pair is the field every other parser in this tree
    // sets, and it is what stops "N messages" from reading as the whole store.
    if truncated {
        summary.insert("truncated".into(), json!(true));
        summary.insert("content_incomplete".into(), json!(true));
        summary.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::CapReached.as_str()),
        );
        // The budget this walk actually ran under, not the module constant: the
        // two differ whenever a caller supplies its own cap, and an examiner
        // reading "stopped at 50000" against a walk that stopped at 3 would be
        // reading a number that never governed anything.
        summary.insert("max_entries".into(), json!(max_entries));
        summary.insert(
            "message".into(),
            json!("Message walk stopped at the parser cap; the oldest messages were not extracted"),
        );
    }
    if dropped_rows > 0 {
        // Rows that were in the store and would not decode — messages, MMS body
        // parts, addresses or thread recipients. Without this the counts above
        // read as the exact size of the conversation, and an examiner could
        // testify that a message was never sent when in fact its row could not
        // be read.
        summary.insert("rows_dropped".into(), json!(dropped_rows));
        summary.insert("inventory_incomplete".into(), json!(true));
        summary.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
        summary.insert("content_incomplete".into(), json!(true));
        // A cap is the coarser statement; do not overwrite it.
        summary
            .entry("content_incomplete_reason")
            .or_insert_with(|| json!(IncompleteReason::UnresolvedStructure.as_str()));
    }
    summary.insert(
        "name".into(),
        json!(format!(
            "Android SMS/MMS: {} messages across {} threads",
            message_count, thread_count
        )),
    );
    artifacts.push(
        Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            Value::Object(summary),
        )
        .with_parent(parent_id)
        .with_subtype("summary"),
    );

    Ok(artifacts)
}

/// Load MMS body parts keyed by pdu id: (text-part map, attachment-name map,
/// undecodable row count).
/// `text/plain` parts are concatenated into the text; other parts (except SMIL
/// layout) contribute an attachment name. A part row that will not decode is a
/// message body or attachment this tool did not recover, so it is counted
/// rather than dropped in silence.
fn load_mms_parts(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Result<ContactIndex> {
    let mut part_text: HashMap<i64, String> = HashMap::new();
    let mut part_atts: HashMap<i64, Vec<String>> = HashMap::new();
    let mut dropped = 0usize;

    if !table_exists(conn, "part")? {
        return Ok((part_text, part_atts, dropped, None));
    }

    let part = Fields::resolve(conn, SCHEMA_APP, "part", PART_FIELDS)?;
    let select = format!(
        "SELECT {}, {}, {}, {}, {}, {} FROM part",
        part.col("message_id"),
        part.col("content_type"),
        part.col("text"),
        part.col("name"),
        part.col("content_location"),
        part.col("file_name"),
    );
    if let Ok(mut stmt) = conn.prepare(&select) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<i64>>(0)?,    // mid
                r.get::<_, Option<String>>(1)?, // ct
                r.get::<_, Option<String>>(2)?, // text
                r.get::<_, Option<String>>(3)?, // name
                r.get::<_, Option<String>>(4)?, // cl
                r.get::<_, Option<String>>(5)?, // fn
            ))
        }) {
            for row in rows {
                let (mid, ct, text, name, cl, fnm) = match row {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("Skipping malformed part row: {}", e);
                        dropped += 1;
                        continue;
                    }
                };
                let mid = match mid {
                    Some(m) => m,
                    None => continue,
                };
                let ct_l = ct.as_deref().unwrap_or("").to_ascii_lowercase();
                if ct_l == "text/plain" {
                    if let Some(t) = text.filter(|s| !s.is_empty()) {
                        let e = part_text.entry(mid).or_default();
                        if !e.is_empty() {
                            e.push('\n');
                        }
                        e.push_str(&t);
                    }
                } else if !ct_l.is_empty() && ct_l != "application/smil" {
                    let label = name.or(cl).or(fnm).unwrap_or_else(|| ct_l.clone());
                    part_atts.entry(mid).or_default().push(label);
                }
            }
        }
    }

    let marker = part.drift_marker(case_id, parent_id, part_text.len() + part_atts.len());
    Ok((part_text, part_atts, dropped, marker))
}

/// Load MMS addresses keyed by pdu id: (from-address map [type 137], to-address
/// list map [type 151], undecodable row count). A lost `addr` row changes which
/// number is reported as the correspondent, so it is counted.
fn load_mms_addresses(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Result<ContactIndex> {
    let mut addr_from: HashMap<i64, String> = HashMap::new();
    let mut addr_to: HashMap<i64, Vec<String>> = HashMap::new();
    let mut dropped = 0usize;

    if !table_exists(conn, "addr")? {
        return Ok((addr_from, addr_to, dropped, None));
    }

    let addr = Fields::resolve(conn, SCHEMA_APP, "addr", ADDR_FIELDS)?;
    let select = format!(
        "SELECT {}, {}, {} FROM addr",
        addr.col("message_id"),
        addr.col("address"),
        addr.col("type"),
    );
    if let Ok(mut stmt) = conn.prepare(&select) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<i64>>(0)?,    // msg_id
                r.get::<_, Option<String>>(1)?, // address
                r.get::<_, Option<i64>>(2)?,    // type
            ))
        }) {
            for row in rows {
                let (msg_id, address, atype) = match row {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("Skipping malformed addr row: {}", e);
                        dropped += 1;
                        continue;
                    }
                };
                let (msg_id, address) = match (msg_id, address) {
                    (Some(m), Some(a)) if !a.is_empty() && a != "insert-address-token" => (m, a),
                    _ => continue,
                };
                match atype {
                    Some(137) => {
                        addr_from.entry(msg_id).or_insert(address);
                    }
                    Some(151) => {
                        addr_to.entry(msg_id).or_default().push(address);
                    }
                    _ => {}
                }
            }
        }
    }

    let marker = addr.drift_marker(case_id, parent_id, addr_from.len() + addr_to.len());
    Ok((addr_from, addr_to, dropped, marker))
}

impl ForensicsModule for AndroidSmsParser {
    fn id(&self) -> &str {
        "plugin.messaging.android_sms"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::SystemArtifact]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if !identify_android_sms_db(name) {
            return Ok(Vec::new());
        }

        info!("AndroidSmsParser processing: {}", name);

        // A directory entry that carries the store's name is not a store, and
        // is not declared as one (ROADMAP §5.11: the shared entry gate).
        if seance_sqlite_util::is_directory_entry(artifact) {
            return Ok(Vec::new());
        }
        if artifact.data.is_none() {
            info!(
                "No data source for {}, producing identification artifact only",
                name
            );
            let metadata = json!({
                "type": "AndroidSms",
                "file_name": name,
                "status": "Identified",
                "name": format!("Android SMS/MMS Database (not parsed - no data): {}", name),
            });
            let id_artifact =
                Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(artifact.id);
            return Ok(vec![id_artifact]);
        }

        // Through the shared gate: a header that did not arrive in full is the
        // stager's record of a short read, never a finding about the file.
        let temp =
            match seance_sqlite_util::stage_named_store(artifact, "android_sms", MAX_DB_BYTES) {
                Ok(Ok(temp)) => temp,
                Ok(Err(records)) => return Ok(records),
                Err(e) => {
                    return Err(ModuleError::ParsingError(format!(
                        "Failed to extract DB: {}",
                        e
                    )))
                }
            };

        let result = (|| -> Result<Vec<Artifact>> {
            // A file with no SQLite header is not our database, and silence is
            // the right answer. A file that DOES carry the header and then
            // fails is a telephony store this tool could not read: from here on
            // every failure is reported, because zero artifacts would make a
            // corrupt store indistinguishable from a phone that exchanged no
            // messages.
            if !staged_looks_like_sqlite(temp.path()) {
                debug!("{} carries no SQLite header, skipping", name);
                return Ok(Vec::new());
            }

            let conn = temp
                .open()
                .context("Failed to open the Android telephony database")?;

            // `?`, not `unwrap_or(false)`: a database whose catalogue cannot be
            // read takes the parse-failure path (which carries the
            // incompleteness pair) rather than being filed as "not a telephony
            // store".
            if !has_android_sms_schema(&conn)? {
                info!("{} lacks Android telephony 'sms' schema, skipping", name);
                return Ok(Vec::new());
            }

            parse_android_sms(&conn, artifact.case_id, artifact.id, name)
        })();

        match result {
            Ok(mut artifacts) => {
                // A telephony store staged short still opens and answers
                // queries from the pages it can reach, so the rows that
                // survived would otherwise read as the whole message store.
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                info!(
                    "AndroidSmsParser extracted {} records from {}",
                    artifacts.len(),
                    name
                );
                Ok(artifacts)
            }
            Err(e) => {
                warn!("Failed to parse Android SMS database ({}): {}", name, e);
                let metadata = json!({
                    "type": "AndroidSms",
                    "file_name": name,
                    "status": "ParseFailed",
                    "error": e.to_string(),
                    // The standard pair, not just a status string: the API,
                    // export and reporting paths key on these, and without them
                    // a failed parse exports as a store that held no messages.
                    "content_incomplete": true,
                    "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    "name": format!("Android SMS/MMS Database (parse failed): {}", name),
                });
                let id_artifact =
                    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(artifact.id);
                Ok(vec![id_artifact])
            }
        }
    }
}

/// The magnitude contract: what this parser writes into `date` must be a whole
/// Unix second an examiner could read as a date, whichever of the three units
/// the Android store happened to record.
///
/// This lives beside the parser rather than in `tests.rs` because it is a
/// statement about the record this file emits, and it is the guard that stops a
/// future edit reintroducing a two-branch `raw < 10^11 ? raw : raw / 1000`
/// normaliser — which reads a 16-digit microsecond value as milliseconds and
/// dates the message to the year 55840.
#[cfg(test)]
mod magnitude_contract {
    use super::*;
    use seance_sqlite_util::chat::is_plausible_instant_secs;

    /// 2023-11-14T22:13:20Z — the one instant every row below claims, written
    /// in each unit this corpus is known to contain.
    const INSTANT_SECS: i64 = 1_700_000_000;
    const SAME_INSTANT_IN_EVERY_UNIT: [(&str, i64); 3] = [
        ("seconds", 1_700_000_000),
        ("milliseconds", 1_700_000_000_123),
        ("microseconds", 1_700_000_000_123_456),
    ];

    /// An `sms` table holding one row per supplied `date`, with everything else
    /// a message needs held constant.
    fn sms_db(dates: &[i64]) -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE sms (
                 _id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER,
                 read INTEGER, status INTEGER, type INTEGER, body TEXT, subject TEXT
             );",
        )
        .expect("create sms");
        for (i, date) in dates.iter().enumerate() {
            conn.execute(
                "INSERT INTO sms (_id, thread_id, address, date, read, status, type, body)
                 VALUES (?1, 1, '+15550100', ?2, 1, 0, 1, 'hi')",
                rusqlite::params![i as i64 + 1, date],
            )
            .expect("insert sms");
        }
        conn
    }

    fn messages(artifacts: &[Artifact]) -> Vec<&Artifact> {
        artifacts
            .iter()
            .filter(|a| a.metadata.get("subtype").and_then(|s| s.as_str()) == Some("chat_message"))
            .collect()
    }

    fn parse(conn: &Connection) -> Vec<Artifact> {
        parse_android_sms(conn, Uuid::new_v4(), Uuid::new_v4(), "mmssms.db").expect("parse")
    }

    #[test]
    fn every_unit_of_one_instant_is_written_as_the_same_plausible_second() {
        let dates: Vec<i64> = SAME_INSTANT_IN_EVERY_UNIT.iter().map(|(_, v)| *v).collect();
        let artifacts = parse(&sms_db(&dates));
        let msgs = messages(&artifacts);
        assert_eq!(msgs.len(), dates.len());

        for (unit, raw) in SAME_INSTANT_IN_EVERY_UNIT {
            let msg = msgs
                .iter()
                .find(|a| a.metadata["rowid"].as_i64() == Some(row_of(&dates, raw)))
                .unwrap_or_else(|| panic!("no record for the {unit} row"));
            let secs = msg.metadata["date"]
                .as_i64()
                .unwrap_or_else(|| panic!("the {unit} row wrote a non-integer date"));
            assert!(
                is_plausible_instant_secs(secs),
                "{unit} value {raw} was written as {secs}, which is not a date a \
                 message could carry"
            );
            assert_eq!(
                secs, INSTANT_SECS,
                "{unit} value {raw} names a different instant than the other units"
            );
        }
    }

    /// The row number a given raw date was inserted as, so a record can be
    /// matched back to the unit it was written in.
    fn row_of(dates: &[i64], raw: i64) -> i64 {
        dates.iter().position(|d| *d == raw).expect("inserted") as i64 + 1
    }

    #[test]
    fn an_unset_date_is_absent_rather_than_written_as_the_epoch() {
        let artifacts = parse(&sms_db(&[0]));
        let msgs = messages(&artifacts);
        assert_eq!(msgs.len(), 1);
        // Not `0`, and not 1970-01-01: a `date` column of 0 is a column the
        // store never set. Written literally it survives every non-null test on
        // the server side and dates the message to the epoch.
        assert!(
            msgs[0].metadata.get("date").is_none(),
            "an unset date was written as {:?}",
            msgs[0].metadata.get("date")
        );
        // And no fabricated instant beside the omitted key: a
        // "1970-01-01T00:00:00+00:00" string next to an absent `date` would be
        // the same false claim in a different field.
        assert!(msgs[0].metadata.get("date_rfc3339").is_none());
        // The observation itself survives, under keys that cannot be read as a
        // time: the store did write something, and that is a fact about the
        // store.
        assert_eq!(msgs[0].metadata["date_unusable"], true);
        assert_eq!(msgs[0].metadata["date_raw"], 0);
    }

    #[test]
    fn a_placeable_date_carries_no_unusable_marks() {
        let artifacts = parse(&sms_db(&[INSTANT_SECS]));
        let msgs = messages(&artifacts);
        assert_eq!(msgs[0].metadata["date"], INSTANT_SECS);
        assert!(msgs[0].metadata.get("date_unusable").is_none());
        assert!(msgs[0].metadata.get("date_raw").is_none());
    }

    #[test]
    fn a_message_with_no_date_column_at_all_carries_no_marks() {
        // Absent is not the same as unusable: with `date` NULL there is no raw
        // value to show, and a `date_unusable` flag would claim the store held
        // something it did not. Signal and the call log draw the same line.
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE sms (
                 _id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER,
                 read INTEGER, status INTEGER, type INTEGER, body TEXT, subject TEXT
             );
             INSERT INTO sms (_id, thread_id, address, date, read, status, type, body)
             VALUES (1, 1, '+15550100', NULL, 1, 0, 1, 'hi');",
        )
        .expect("create sms");
        let artifacts = parse(&conn);
        let msgs = messages(&artifacts);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].metadata.get("date").is_none());
        assert!(msgs[0].metadata.get("date_unusable").is_none());
        assert!(msgs[0].metadata.get("date_raw").is_none());
    }

    /// The MMS walk builds its own copy of the timestamp block, so the contract
    /// has to be asserted through `pdu` as well as through `sms`. The two
    /// copies are exactly how this defect spread in the first place.
    #[test]
    fn the_mms_walk_honours_the_same_contract_as_the_sms_walk() {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE sms (
                 _id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER,
                 read INTEGER, status INTEGER, type INTEGER, body TEXT, subject TEXT
             );
             CREATE TABLE pdu (
                 _id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER,
                 msg_box INTEGER, read INTEGER, sub TEXT, st INTEGER
             );
             INSERT INTO pdu VALUES (1, 1, 1700000000123456, 1, 1, NULL, NULL);
             INSERT INTO pdu VALUES (2, 1, 0, 1, 1, NULL, NULL);",
        )
        .expect("create pdu");
        let artifacts = parse(&conn);
        let msgs = messages(&artifacts);

        let placed = msgs
            .iter()
            .find(|a| a.metadata["rowid"] == 1)
            .expect("the microsecond PDU");
        assert_eq!(placed.metadata["date"], INSTANT_SECS);
        assert!(is_plausible_instant_secs(
            placed.metadata["date"].as_i64().expect("an integer date")
        ));

        let unplaced = msgs
            .iter()
            .find(|a| a.metadata["rowid"] == 2)
            .expect("the unset PDU");
        assert!(unplaced.metadata.get("date").is_none());
        assert_eq!(unplaced.metadata["date_unusable"], true);
        assert_eq!(unplaced.metadata["date_raw"], 0);
    }
}
